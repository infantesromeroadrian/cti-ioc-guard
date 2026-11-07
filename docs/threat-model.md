# Modelo de amenazas

Alcance: la extracción de indicadores de compromiso (IOC) con un LLM a partir de texto de
inteligencia de amenazas (descripciones de NVD, pulses de AlienVault OTX, informes). Este
documento describe lo que el código **hace hoy**; lo que no está implementado figura en
«Riesgos residuales». Las cifras de eficacia no se citan aquí: están en `metrics.json`
(véase el README).

Referencia: OWASP Top 10 for LLM Applications, edición **2025**
(<https://genai.owasp.org/llm-top-10/>, consultada el 2026-11-07; es la versión vigente en la
fuente primaria a esa fecha). Las categorías citadas son las de esa edición: LLM01 Prompt
Injection, LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06
Excessive Agency, LLM09 Misinformation y LLM10 Unbounded Consumption.

## 1. Activos y límites de confianza

| Elemento | Confianza | Nota |
|---|---|---|
| Texto de feeds (NVD, OTX, informes) | **No fiable** | Lo escribe un tercero, incluido un atacante. Es el vector de inyección indirecta. |
| Prompt de sistema y esquemas | Fiable | Versionados en el repositorio. |
| Salida del LLM | **No fiable** | Es una *propuesta*; nunca una decisión. |
| Verificador determinista, política de severidad | Fiable | Código sin LLM (`src/cti_guard/security/`). |
| Base de datos y API | Fiable, sin autenticación | Prototipo: solo para `127.0.0.1`. |

Flujo (la frontera de confianza queda a la izquierda del verificador):

```
feed no fiable ─► heurísticas de inyección ─► ¿cuarentena? ──sí──► nada se emite
                        │ no
                        ▼
       LLM extractor (sin herramientas, prompt con spotlighting, salida JSON con esquema)
                        │ candidatos (tipo, valor)
                        ▼
   verificador: lista blanca de tipos · sintaxis · aparece literalmente en el texto ·
                no cae en un tramo marcado como inyección  ─► IOC con procedencia (offsets)
                        ▼
   severidad = max(LLM, suelo por evidencia) · alertas solo desde IOC verificados
```

## 2. Amenazas y controles

### T1. Inyección indirecta de prompts (LLM01)

El atacante controla parte del texto del feed e intenta que el extractor (a) reporte un IOC
falso, (b) omita IOC reales o (c) rebaje la severidad.

Controles implementados, en orden de ejecución:

1. **Cuarentena por heurísticas** (`security/injection.py`). Reglas por categoría
   (anulación de instrucciones, directivas sobre la salida, marcadores de rol o de plantilla de
   chat, caracteres invisibles / etiquetas Unicode). Un documento que dispara cualquier regla
   no llega al LLM y no emite IOC. Es un cable de tropiezo, no una garantía: las heurísticas
   fallan con paráfrasis, otros idiomas o codificaciones, y pueden saltar con prosa legítima.
   Su tasa de detección y su tasa de falsos positivos sobre el corpus real se miden y se
   publican en `metrics.json` (`robustness._quarantine`).
2. **Contenido tratado como datos** (`security/spotlight.py`, `infrastructure/adapters/llm/prompts.py`).
   El documento va entre delimitadores con nonce aleatorio por llamada, con *datamarking*
   (cada hueco en blanco se sustituye por `ˆ`) y un prompt que lo declara dato no fiable.
   Reduce la obediencia del modelo; no la elimina.
3. **LLM sin herramientas ni efectos** (`infrastructure/adapters/llm/proposer.py`). Función
   pura: texto en, JSON fuera. No hay llamadas a herramientas, ni red, ni escritura, ni
   memoria entre documentos. Privilegio mínimo: un secuestro total del modelo solo puede
   producir una propuesta equivocada.
4. **Esquema y lista blanca de tipos** (`llm/schemas.py`). Salida validada con pydantic
   (`extra="forbid"`, tipos en enumeración, longitudes acotadas). Si no valida, se descarta el
   fragmento (fallo cerrado) en lugar de reparar o ejecutar nada.
5. **Verificación determinista** (`security/verifier.py`). Cada candidato debe (i) tener un
   tipo permitido (IP, dominio, URL, MD5, SHA-1, SHA-256, CVE), (ii) ser sintácticamente
   válido, (iii) aparecer **literalmente** en el texto fuente (tras deshacer el *defanging*
   `hxxp`, `[.]`), con frontera de token, y (iv) **no estar solo dentro de un tramo marcado
   como inyección**. El apartado (iv) es necesario porque (iii) por sí solo no basta: un
   atacante puede incluir el IOC falso dentro del propio texto de la instrucción, y entonces sí
   «aparece literalmente». El resultado lleva la procedencia (`start`, `end` sobre el texto
   original).
6. **Suelo de severidad por evidencia** (`security/policy.py`). La severidad final es
   `max(LLM, suelo)`; un documento con al menos un IOC verificado no puede quedar por debajo
   de `medium` por obra de la salida del modelo. No impide una rebaja parcial (de `critical` a
   `medium`); esa limitación se mide, no se oculta.
7. **Ninguna alerta solo desde el LLM** (`domain/services/alert_service.py`).
   `should_alert_for_ioc` exige `ioc.verified`. Un IOC sin verificar (p. ej. creado por la API)
   nunca dispara una alerta.

### T2. Alucinación y datos erróneos (LLM09, LLM05)

El LLM puede inventar o «corregir» valores. El verificador (control 5) descarta todo lo que no
sea literal en la fuente. Esto elimina las alucinaciones de valor, no los errores de
*atribución* (marcar como malicioso un dominio legítimo citado en el informe): ese error de
precisión se mide en `metrics.json`.

La salida del LLM no se interpreta nunca como código ni se concatena en consultas: las
persistencias usan SQLAlchemy con parámetros (LLM05).

### T3. Agencia excesiva (LLM06)

No hay agentes ni herramientas (véase el control 3). Fuera de alcance por diseño.

### T4. Divulgación de información sensible (LLM02)

- Las claves (`OLLAMA_API_KEY`, `NVD_API_KEY`, `OTX_API_KEY`, `LLM_API_KEY`) solo se leen del
  entorno, se tipan como `SecretStr` (no salen en `repr` ni en `model_dump`) y `.env.example`
  no contiene valores. `.env` está en `.gitignore`.
- El texto de los feeds se envía al proveedor LLM configurado. Con Ollama local no sale de la
  máquina; con Ollama Cloud o un servicio compatible con OpenAI sí. No usar estos adaptadores
  con documentos confidenciales sin evaluar al proveedor.

### T5. Consumo no acotado (LLM10)

Documento troceado en fragmentos de tamaño fijo; `num_predict` / `max_tokens` acotado por
llamada (se usa el cliente nativo de Ollama porque `max_completion_tokens`, el parámetro que envía
langchain-openai, **no se aplica en Ollama**: comprobado el 2026-11-07 contra Ollama 0.40.13 con
`gpt-oss:120b-cloud`, 491 tokens generados con el límite en 30, mientras que `max_tokens` y
`num_predict` sí cortan; no se ha comprobado en otros proveedores. El cliente compatible con
OpenAI envía `max_tokens`); tiempo de espera por llamada; lista de indicadores limitada a 500 por fragmento.
No hay límite de tamaño del documento ni de tasa global (riesgo residual).

### T6. Envenenamiento de la memoria / del almacén

No hay memoria del modelo entre documentos. La base de datos guarda procedencia y la marca
`verified`; un IOC no verificado puede existir (p. ej. por `POST /api/iocs`) pero no genera
alertas.

## 3. Riesgos residuales (conocidos y no mitigados)

- **Ataques que evaden las heurísticas** (paráfrasis, idiomas, texto partido). Dependen de los
  controles 2 a 6; la tasa de éxito medida con y sin defensas está en `metrics.json`.
- **Omisión de IOC reales.** El verificador filtra lo que se añade, no lo que falta. Una
  instrucción que consiga que el modelo calle indicadores solo la frenan la cuarentena y el
  spotlighting. Se mide como «retención de IOC».
- **Rebaja de severidad parcial** por encima del suelo (véase control 6).
- **Falsos positivos de la cuarentena** sobre informes legítimos que hablan de inyección de
  prompts: el documento se queda sin extracción automática (fallo seguro, con coste de
  disponibilidad). Se mide su tasa.
- **API sin autenticación ni autorización** y con CORS limitado a `localhost`. No exponer.
- **Un único anotador** para el corpus de evaluación (sin acuerdo entre anotadores) y sesgo de
  *pooling*: ver README, apartado de limitaciones.
- **Dependencias**: sin SBOM ni escaneo de vulnerabilidades en CI (solo Dependabot mensual).

## 4. Marcos de referencia

OWASP Top 10 for LLM Applications 2025 (arriba). El patrón «el LLM propone, un verificador
determinista decide» y el spotlighting siguen la literatura sobre defensa frente a inyección
indirecta (Hines et al., 2024, *Defending Against Indirect Prompt Injection Attacks With
Spotlighting*). No se declara conformidad con ningún estándar.
