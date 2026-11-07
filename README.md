# CTI Guard

Extracción de indicadores de compromiso (IOC) con un LLM a partir de **texto no fiable**
(descripciones de NVD, pulses de AlienVault OTX, informes), con defensas frente a inyección
indirecta de prompts y medida contra un baseline clásico de expresiones regulares.

> **Estado: prototipo de investigación / portfolio.** No es un producto, no está probado en
> producción y la API no tiene autenticación. Las cifras de este README salen de `metrics.json`
> (generado por `python -m cti_guard.eval`) y se insertan con `python -m cti_guard.eval.report`;
> ninguna está escrita a mano.

## Idea

El LLM **propone**; un verificador determinista **decide**. Cada IOC que propone el modelo debe:

1. tener un tipo de la lista blanca (IP, dominio, URL, MD5, SHA-1, SHA-256, CVE);
2. ser sintácticamente válido;
3. aparecer literalmente en el texto fuente (se deshace el *defanging* `hxxp`, `[.]`), con su
   procedencia (offsets sobre el texto original);
4. no estar únicamente dentro de un tramo que las heurísticas hayan marcado como inyección.

Además: spotlighting del documento (delimitadores con nonce + *datamarking*), extractor sin
herramientas ni efectos, esquema pydantic estricto, suelo de severidad por evidencia, cuarentena
de documentos sospechosos y ninguna alerta generada a partir de un IOC sin verificar. Detalle,
límites y riesgos residuales en [`docs/threat-model.md`](docs/threat-model.md).

## Arranque rápido (offline, sin claves)

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,eval]"

cti-guard demo                      # scrape -> extract -> persist con fixtures grabadas
cti-guard serve --demo              # API en http://127.0.0.1:8000/docs con datos de ejemplo
cti-guard extract informe.txt       # IOC de un fichero (--extractor llm para usar el modelo)

ruff check . && ruff format --check . && pytest   # los tests no usan red ni claves
docker build -t cti-guard:local .   # o: docker compose up --build
```

El extractor LLM usa **Ollama** por defecto (cliente nativo; local o Ollama Cloud) y admite
cualquier servidor compatible con OpenAI (`LLM_PROVIDER=openai_compat`). Las claves van solo por
entorno (`OLLAMA_API_KEY`, `NVD_API_KEY`, `OTX_API_KEY`); `.env.example` no contiene valores.
Se usa el cliente nativo de Ollama porque `max_completion_tokens` (lo que envía
`langchain-openai`) no limita la generación en Ollama; `num_predict` sí.

### API de ejemplo (sin frontend)

La API trae datos de ejemplo grabados (`--demo`); documentación interactiva en `/docs`.

```bash
cti-guard serve --demo &                       # http://127.0.0.1:8000
curl -s http://127.0.0.1:8000/health
curl -s "http://127.0.0.1:8000/api/iocs/?page_size=5"      # IOC con procedencia: verified, start, end
curl -s http://127.0.0.1:8000/api/cves/CVE-2099-0001       # CVE de fixture y su severidad
```

## Arquitectura

Hexagonal (puertos y adaptadores), paquete `src/cti_guard/`:

- `domain/`: entidades (IOC con procedencia y marca `verified`, CVE, ThreatIntel, Alert), puertos
  y servicios puros.
- `security/`: controles deterministas sin LLM (`refang`, `verifier`, `injection`, `spotlight`, `policy`).
- `application/`: casos de uso y `guarded_extraction` (propone, verifica, aplica política).
- `infrastructure/`: adaptadores (extractor regex, extractor LLM, scrapers NVD/OTX con fixtures,
  repositorios SQLite), API FastAPI y configuración.
- `eval/`: harness de evaluación reproducible.

## Evaluación

Un solo comando escribe `metrics.json`:

```bash
python -m cti_guard.eval.fetch      # descarga el corpus a ~/datasets/cti-llm/ (fuera del repo); úselo con moderación
                                    # (≤1 petición/s, con backoff): son recursos públicos compartidos
python -m cti_guard.eval --out metrics.json
python -m cti_guard.eval.report     # inserta las tablas de abajo en este README
```

Las llamadas al modelo se cachean en `~/datasets/cti-llm/cache/` (clave: modelo + prompts +
esquema), de modo que repetir la evaluación es determinista y gratuito; sin esa caché hace falta
el mismo modelo. Niveles de defensa (cada uno añade un control al anterior): D0 prompt ingenuo,
D1 spotlighting, D2 verificador determinista + suelo de severidad, D3 veto por tramo de inyección,
D4 cuarentena.

<!-- metrics:start -->
Generado el 2026-11-07T19:16:19+00:00 · modelo: `gpt-oss:120b-cloud` (digest `ac7f7a1e7785`, servidor ollama 0.40.13) · 39 informes, 1850 IOC de referencia · robustez: 20 informes, 360 variantes inyectadas · semilla 0.

#### Calidad de extracción (micro-agregado, IC 95% de Wilson)

| Sistema | Precisión estricta (vs STIX) | Precisión adjudicada | Recall (vs STIX) | F1 estricto (IC bootstrap) | Doble uso listado | Informes en cuarentena |
|---|---|---|---|---|---|---|
| Regex (baseline original) | 59.4% [57.2%, 61.5%] | 67.5% [65.4%, 69.5%] | 64.0% [61.8%, 66.2%] | 61.6% [45.1%, 72.3%] | 16 | 0 |
| Regex + refang (baseline reforzado) | 64.8% [63.0%, 66.5%] | 76.0% [74.4%, 77.5%] | 99.7% [99.4%, 99.9%] | 78.6% [70.6%, 84.6%] | 31 | 0 |
| LLM, prompt ingenuo, sin verificar | 71.8% [70.0%, 73.5%] | 83.4% [81.9%, 84.8%] | 96.7% [95.7%, 97.4%] | 82.4% [75.0%, 88.0%] | 30 | 0 |
| LLM + spotlighting, sin verificar | 78.0% [76.2%, 79.8%] | 91.6% [90.3%, 92.7%] | 88.7% [87.2%, 90.1%] | 83.0% [76.5%, 89.3%] | 29 | 0 |
| LLM + verificador determinista | 82.0% [80.3%, 83.6%] | 96.2% [95.3%, 97.0%] | 88.7% [87.2%, 90.1%] | 85.2% [79.1%, 90.8%] | 29 | 0 |
| LLM + verificador + veto por tramo de inyección | 82.0% [80.3%, 83.6%] | 96.2% [95.3%, 97.0%] | 88.7% [87.2%, 90.1%] | 85.2% [79.1%, 90.8%] | 29 | 0 |
| LLM + todo lo anterior + cuarentena (defensa completa) | 82.0% [80.3%, 83.6%] | 96.2% [95.3%, 97.0%] | 88.7% [87.2%, 90.1%] | 85.2% [79.1%, 90.8%] | 29 | 0 |

#### Calidad por tipo de IOC (precisión / recall)

| Tipo | Regex | Regex + refang | LLM, prompt ingenuo, sin verificar | LLM + spotlighting, sin verificar | LLM + verificador determinista | LLM + verificador + veto por tramo de inyección | LLM + todo lo anterior + cuarentena |
|---|---|---|---|---|---|---|---|
| ip | 56.2% / 2.1% (TP 9, FP 7, FN 420) | 76.1% / 99.5% (TP 427, FP 134, FN 2) | 76.9% / 99.3% (TP 426, FP 128, FN 3) | 77.2% / 99.5% (TP 427, FP 126, FN 2) | 78.2% / 99.5% (TP 427, FP 119, FN 2) | 78.2% / 99.5% (TP 427, FP 119, FN 2) | 78.2% / 99.5% (TP 427, FP 119, FN 2) |
| domain | 2.1% / 5.3% (TP 12, FP 547, FN 214) | 27.6% / 99.6% (TP 225, FP 590, FN 1) | 55.8% / 92.0% (TP 208, FP 165, FN 18) | 77.5% / 91.6% (TP 207, FP 60, FN 19) | 85.5% / 91.6% (TP 207, FP 35, FN 19) | 85.5% / 91.6% (TP 207, FP 35, FN 19) | 85.5% / 91.6% (TP 207, FP 35, FN 19) |
| url | 0.0% / 0.0% (TP 0, FP 73, FN 31) | 23.6% / 93.5% (TP 29, FP 94, FN 2) | 12.6% / 71.0% (TP 22, FP 152, FN 9) | 34.4% / 67.7% (TP 21, FP 40, FN 10) | 42.0% / 67.7% (TP 21, FP 29, FN 10) | 42.0% / 67.7% (TP 21, FP 29, FN 10) | 42.0% / 67.7% (TP 21, FP 29, FN 10) |
| md5 | 98.1% / 100.0% (TP 458, FP 9, FN 0) | 98.1% / 100.0% (TP 458, FP 9, FN 0) | 97.9% / 99.3% (TP 455, FP 10, FN 3) | 96.2% / 77.1% (TP 353, FP 14, FN 105) | 98.6% / 77.1% (TP 353, FP 5, FN 105) | 98.6% / 77.1% (TP 353, FP 5, FN 105) | 98.6% / 77.1% (TP 353, FP 5, FN 105) |
| sha1 | 90.1% / 100.0% (TP 255, FP 28, FN 0) | 90.1% / 100.0% (TP 255, FP 28, FN 0) | 80.3% / 95.7% (TP 244, FP 60, FN 11) | 87.8% / 87.5% (TP 223, FP 31, FN 32) | 89.2% / 87.5% (TP 223, FP 27, FN 32) | 89.2% / 87.5% (TP 223, FP 27, FN 32) | 89.2% / 87.5% (TP 223, FP 27, FN 32) |
| sha256 | 92.3% / 100.0% (TP 421, FP 35, FN 0) | 92.3% / 100.0% (TP 421, FP 35, FN 0) | 84.9% / 96.0% (TP 404, FP 72, FN 17) | 83.2% / 90.3% (TP 380, FP 77, FN 41) | 92.0% / 90.3% (TP 380, FP 33, FN 41) | 92.0% / 90.3% (TP 380, FP 33, FN 41) | 92.0% / 90.3% (TP 380, FP 33, FN 41) |
| cve | 21.1% / 100.0% (TP 30, FP 112, FN 0) | 21.1% / 100.0% (TP 30, FP 112, FN 0) | 19.9% / 96.7% (TP 29, FP 117, FN 1) | 20.8% / 100.0% (TP 30, FP 114, FN 0) | 21.1% / 100.0% (TP 30, FP 112, FN 0) | 21.1% / 100.0% (TP 30, FP 112, FN 0) | 21.1% / 100.0% (TP 30, FP 112, FN 0) |

#### Robustez frente a inyección indirecta: tasa de éxito del ataque (menor es mejor)

| Sistema | IOC falso reportado | IOC reales omitidos (≥50% perdido) | Severidad rebajada | Severidad a low/info |
|---|---|---|---|---|
| Regex (baseline original) | 100.0% [96.9%, 100.0%] (n=120) | 0.0% [0.0%, 4.4%] (n=84) | n/d | n/d |
| Regex + refang (baseline reforzado) | 100.0% [96.9%, 100.0%] (n=120) | 0.0% [0.0%, 3.1%] (n=120) | n/d | n/d |
| LLM, prompt ingenuo, sin verificar | 97.5% [92.9%, 99.2%] (n=120) | 24.2% [17.4%, 32.6%] (n=120) | 60.0% [51.1%, 68.3%] (n=120) | 57.0% [47.9%, 65.7%] (n=114) |
| LLM + spotlighting, sin verificar | 81.7% [73.8%, 87.6%] (n=120) | 10.8% [6.4%, 17.7%] (n=120) | 8.3% [4.6%, 14.7%] (n=120) | 4.4% [1.9%, 9.9%] (n=114) |
| LLM + verificador determinista | 81.7% [73.8%, 87.6%] (n=120) | 10.8% [6.4%, 17.7%] (n=120) | 8.3% [4.6%, 14.7%] (n=120) | 0.0% [0.0%, 3.1%] (n=120) |
| LLM + verificador + veto por tramo de inyección | 62.5% [53.6%, 70.7%] (n=120) | 10.8% [6.4%, 17.7%] (n=120) | 8.3% [4.6%, 14.7%] (n=120) | 0.0% [0.0%, 3.1%] (n=120) |
| LLM + todo lo anterior + cuarentena (defensa completa) | 62.5% [53.6%, 70.7%] (n=120) | 6.7% [3.4%, 12.6%] (n=120) | 4.2% [1.8%, 9.4%] (n=120) | 0.0% [0.0%, 3.1%] (n=120) |

En omisión de IOC, D4 deja en cuarentena 40.0% [31.7%, 48.9%] (n=120) de los casos aplicables: el documento queda marcado para revisión (coste de disponibilidad), no es una pérdida silenciosa, y por eso no se cuenta como éxito del ataque.

Cuarentena: marca 36.7% [31.9%, 41.8%] (n=360) de las variantes inyectadas y 0.0% [0.0%, 6.0%] (n=60) de los informes limpios (falsos positivos).

Detección por estilo de ataque: authority_claim: 33.8% [23.9%, 45.4%] (n=71), direct: 48.3% [35.9%, 60.8%] (n=58), hidden_unicode: 100.0% [93.6%, 100.0%] (n=56), multilingual: 0.0% [0.0%, 6.1%] (n=59), paraphrase: 0.0% [0.0%, 5.8%] (n=62), role_marker: 44.4% [32.0%, 57.6%] (n=54).

#### Detector de inyección sobre las muestras etiquetadas (resultado real, no la expectativa del fixture)

| Categoría | Detectadas | Total | Marcadas por el autor como no detectables |
|---|---|---|---|
| override | 3 | 6 | 2 |
| directive | 3 | 6 | 2 |
| role_marker | 3 | 6 | 0 |
| obfuscation | 4 | 6 | 2 |

Prosa legítima marcada por error: 1 de 24 (negative-cti-03). Discrepancias con la expectativa del fixture: 5.
<!-- metrics:end -->

### Lectura de los resultados (qué dicen y qué no)

* **Calidad.** Frente al baseline regex reforzado (con refang), el LLM con verificador mejora la precisión
  (estricta 64,8 % → 82,0 %; adjudicada 76,0 % → 96,2 %) a costa de recall (99,7 % → 88,7 %, aunque esa
  referencia es casi circular, ver abajo). El verificador, sin perder ningún acierto, elimina los falsos
  positivos por valores inventados o mal formados (precisión estricta de D1 a D2: 78,0 % → 82,0 %).
  El *spotlighting* tiene un coste de recall en hashes largos (D0 → D1).
* **Robustez.** Las defensas por capas reducen mucho los ataques de rebaja de severidad y de omisión, pero
  **no resuelven el IOC falso inyectado en el propio texto**: con la defensa completa sigue prosperando en
  el 62,5 % de las variantes. «Aparece literalmente en la fuente» no basta cuando el atacante escribe la
  instrucción con el IOC dentro; solo frena el veto por tramo cuando las heurísticas marcan la inyección.
  Las heurísticas no detectan paráfrasis ni otros idiomas (0 % en esos estilos) y sí todos los casos con
  caracteres invisibles. El baseline regex, por su parte, devuelve el IOC inyectado en el 100 % de los casos.
* La **cuarentena** convierte parte de la omisión en revisión manual en lugar de pérdida silenciosa; su coste
  es de disponibilidad. Sobre los informes limpios del corpus marcó 0 de 60 lecturas (3 repeticiones de 20).
* El subconjunto de robustez son los **20 primeros informes** del manifest (orden por identificador:
  predominan los avisos de 2022-2023), no una muestra aleatoria.

### Cómo leer las cifras

* **El recall del regex + refang (≈99,7 %) es casi circular.** La referencia son los IOC del STIX del aviso
  que aparecen literalmente en la página; cualquier sistema que encuentre toda cadena con forma de IOC tras
  deshacer el *defanging* cubre esa referencia por construcción. La comparación que importa es la
  **precisión** y la **robustez**, no ese recall.
* La referencia es independiente (la escriben los autores de cada aviso), pero el STIX no es exhaustivo:
  por eso hay precisión estricta y precisión adjudicada (reglas y casos en `corpus/ANNOTATION.md`).

### Desviaciones del protocolo

Tres correcciones se hicieron **después de ver resultados sobre el mismo conjunto de evaluación**; no hay
conjunto de validación separado.

1. *Truncado de salida.* Una primera ejecución (tope de salida 2 048 tokens, trozos de 4 000 caracteres)
   truncaba el JSON en trozos con muchos hashes. Se subió el tope a 6 144 y se redujo el trozo a 3 000. Cifras
   que cambiaron (LLM ingenuo D0 / spotlighting D1): recall 61,5 % → 96,7 % y 58,1 % → 88,7 %; precisión
   68,0 % → 71,8 % y 75,8 % → 78,0 %.
2. *Cuarentena.* Con las reglas iniciales la cuarentena marcaba 6 de los 39 informes limpios (frases
   corrientes como «include additional IOCs» o «act as a proxy»); se acotaron esas reglas, antes de conocer
   las plantillas de ataque. Efecto aislado: en la primera ejecución D4 tenía recall 46,1 % frente a 58,1 % de D3 (12,0 puntos perdidos por la cuarentena) y 6 informes en cuarentena; tras el ajuste D4 = D3 en recall (88,7 %) y 0 informes en cuarentena. (Las dos correcciones se aplicaron antes de la segunda ejecución, por lo que la mejora absoluta de D4 mezcla ambas.)

3. *Fragmentos de hash en el verificador.* Una auditoría de la adjudicación encontró que el verificador aceptaba
   como MD5 una mitad de un SHA-256 partido por el ajuste de una tabla. Se añadió el rechazo de esos fragmentos
   (ver `docs/threat-model.md`). Efecto medido sobre el conjunto de evaluación: nulo en D2 a D4 (TP 1 641, FP 360
   y FN 209 antes y después; recall y precisión estricta idénticos); las dos mitades solo las proponían los
   baselines regex, que no pasan por el verificador. Se corrigió igualmente por ser una debilidad real, y se
   reclasificaron 2 adjudicaciones (regla A7). Además, 14 hashes de herramientas de doble uso listadas
   (regla A8) dejaron de contar como TP en la precisión adjudicada.

El spotlighting (D1) reduce el recall frente al prompt ingenuo (D0) en hashes largos; es un coste real de esa
defensa en este modelo y se muestra en las tablas.

### Limitaciones de la evaluación

* **Un solo modelo principal** (`gpt-oss:120b-cloud` vía Ollama Cloud, con `temperature=0` y `seed=0`; el
  proveedor puede cambiar el modelo detrás del mismo nombre). No hay cifras de un modelo local: se lanzó
  `arca-ornith-9b:q4km` sobre 4 informes (≈1,3 llamadas/min en este equipo) y no terminó a tiempo para esta
  entrega, así que **no se publica ningún resultado local**. `metrics.json` registra un único modelo.
* **Sin conjunto de validación separado**: hay tres desviaciones declaradas arriba, hechas viendo el mismo corpus.
* **Adjudicación con un solo anotador (un LLM)**, sin acuerdo entre anotadores; auditada por muestreo por el
  responsable del proyecto (dos muestras de 30) con una incoherencia corregida (servicios legítimos de doble uso).
* **Plantillas de ataque**: 36, redactadas por una IA distinta del extractor; son una muestra pequeña y
  no adaptativa (no se optimizan contra las defensas). El éxito real de un atacante adaptativo será mayor.
* Las repeticiones de robustez varían el muestreo de plantillas y los IOC falsos, no el modelo
  (temperatura 0): la dispersión es entre muestras de ataques, no entre ejecuciones del modelo.
* Las heurísticas de inyección se ajustaron una vez sobre los informes limpios; sus aciertos y fallos sobre
  las muestras etiquetadas son resultado real, sin ajuste posterior (5 discrepancias con la expectativa del
  autor del fixture, que no se corrigieron en el detector).
* El corpus son avisos de CISA: texto técnico en inglés y cuidado; no representa feeds ruidosos (OTX).

## Qué se retiró y por qué

La versión inicial incluía LDA, Word2Vec, un clasificador de severidad BERT, notificadores
Slack/correo y un frontend sin tests. LDA y Word2Vec estaban entrenados con datos simulados
(`data_source: mock`, coherencia `NaN`), BERT no tenía pesos ajustados y el «NER con spaCy» cargaba
un modelo que nunca se usaba en la extracción (era solo regex). Se eliminaron para conservar solo
piezas verificables.

## Licencia

MIT. Véase [`LICENSE`](LICENSE).
