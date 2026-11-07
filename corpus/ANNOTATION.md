# Corpus de evaluación: origen, etiquetas y reglas de adjudicación

## Contenido del directorio

| Fichero | Qué es |
|---|---|
| `candidates.txt` | URLs de avisos de ciberseguridad de CISA (`aaYY-NNNx`, 2022 a 2026) descubiertas mediante el índice CDX de la Internet Archive. |
| `manifest.jsonl` | Los informes seleccionados: URL, URL del snapshot inmutable de la Internet Archive, ficheros STIX usados (con sha256), nº de IOC de referencia y alcanzables, y **sha256 del texto normalizado**. |
| `gold.jsonl` | IOC de referencia por informe: tipo, valor canónico y offsets en el texto normalizado. |
| `adjudication.jsonl` | Veredicto sobre cada indicador extraído que no está en el STIX (ver abajo). |

El texto de los informes **no** se redistribuye. `python -m cti_guard.eval.fetch` lo descarga a
`~/datasets/cti-llm/corpus/` (fuera del repo) y verifica el sha256. Licencia: son obras de una agencia
federal de EE. UU. (17 U.S.C. §105), pero los avisos conjuntos pueden incorporar material de agencias
extranjeras y no se ha podido confirmar la política de reutilización de cisa.gov en fuente primaria,
de modo que el diseño es conservador: solo se publican manifest, valores y offsets.

## Cómo se obtuvo la referencia (independiente de ambos sistemas)

Cada aviso seleccionado enlaza un fichero STIX (2.1 JSON o, en avisos anteriores a 2023, STIX 1.x XML)
**escrito por sus autores**. Las etiquetas de referencia son los IOC de ese STIX (tipos: IP, dominio, URL,
MD5, SHA-1, SHA-256, CVE), canonicalizados con las mismas reglas que usan los sistemas evaluados.
Ni el anotador ni ninguno de los extractores comparados decide qué es un IOC de referencia.

* Criterio de selección: aviso con STIX descargable y **al menos 5 IOC alcanzables**.
* **Alcanzable**: el IOC del STIX aparece literalmente en el cuerpo HTML normalizado (tras deshacer el
  *defanging* `hxxp`, `[.]`, `[:]`). Un IOC que está solo en el STIX y no en la página no se puede exigir a
  un extractor de texto; se cuenta en `stix_total` y se excluye de `reachable`.
* Estratificación por año con semilla fija (`20261107`) sobre los candidatos válidos.
* La entrada a los extractores es el cuerpo HTML normalizado (`eval/fetch.py:html_to_text`).

Consecuencia que conviene tener presente: como la referencia se define como «STIX ∩ literalmente presente»,
un extractor que encuentre cualquier cadena con forma de IOC tras deshacer el defanging tendrá recall
cercano al 100 % por construcción. El recall mide por tanto la **cobertura de lo que el autor del aviso
decidió publicar**, no la capacidad de decidir qué es malicioso. Esa segunda capacidad es la precisión.

## Adjudicación (para la precisión)

El STIX no es exhaustivo: un extractor puede devolver indicadores reales que el STIX no lista. La precisión
se publica por eso de dos formas: **estricta** (solo cuenta como acierto lo que está en el STIX; cota
inferior) y **adjudicada** (suma los aciertos adjudicados a mano). El recall siempre es contra el STIX.

Se adjudica el conjunto de indicadores extraídos por **cualquiera** de los 7 sistemas y ausentes del STIX
(1 321 casos). Cada caso queda registrado en `adjudication.jsonl` con su regla o motivo.

Reglas automáticas (deterministas, sin LLM):

* **A1** el dominio o IP es el host de una URL de referencia: `TP`.
* **A2** dominio o URL de una autoridad o de un proveedor (`.gov`, `.mil`, `.edu`, `cisa.gov`, `microsoft.com`,
  `github.com`, …): `FP`. Citar al propio organismo no es un IOC.
* **A3** nombre de fichero con forma de dominio (`secretsdump.py`, `ntds.dit`): `FP`.
* **A4** dirección no global (privada, loopback, reservada): `FP`.
* **A5** valor no válido sintácticamente o no canónico para su tipo: `FP`.
* **A6** el valor no aparece literalmente en el texto fuente (alucinación o valor mal formado): `FP`.
* **A7** un MD5/SHA-1 que es un fragmento: cadena hex que, unida a la cadena hex vecina (separada solo por
  espacios; también por saltos de línea si va tras una etiqueta SHA-256), forma 64 hex. Las tablas rompen
  un SHA-256 en dos mitades. `FP`. El verificador aplica la misma regla y rechaza esos fragmentos.
* **A8** servicio o herramienta legítima de doble uso que el aviso lista como IOC y el STIX no incluye
  (proveedores de correo anónimo o cifrado, túneles como ngrok, alojamiento de ficheros, pastebin/discord,
  soporte remoto como Zoho Assist o FixMe.IT, y hashes de PsExec, PuTTY, WinSCP, escáneres, ScreenConnect…):
  **no cuenta como TP** en la precisión adjudicada y se informa aparte (`dual_use_listed`). Se aplica el mismo
  trato a todos los casos listados en tablas de IOC; las menciones narrativas (p. ej. «exfiltraron con MEGA»)
  siguen siendo `FP`. Las subredes o cuentas concretas del atacante (instancias de ScreenConnect,
  cuentas de blob storage) siguen siendo `TP`.

Criterio manual para el resto (723 casos, `rule: manual`), aplicado por un único anotador (un LLM, Claude):

* Hash: `TP` si el informe lo lista o describe como hash de fichero o de certificado asociado a la actividad;
  `FP` si no es un hash de fichero (imphash, BuildID, id de gist, clave pública TOX, identificadores de cartera).
* IP: `TP` si se presenta como infraestructura del adversario; `FP` si es una versión (`20.10.0.0`) o una
  dirección de prueba benigna (`8.8.8.8`).
* CVE: `TP` si el aviso lo presenta como explotado, atacado, investigado por el actor o parte del conjunto
  de vulnerabilidades de la campaña; `FP` si solo se cita como vulnerabilidad conocida del producto o como
  referencia a un boletín del fabricante.
* Dominio / URL: `TP` si el informe lo lista o describe como infraestructura del adversario (incluidos dominios
  de correo anónimo usados por el actor y servicios legítimos solo cuando el aviso los lista como IOC);
  `FP` si es un nombre de fichero, un identificador de código, la parte local de un correo, una referencia
  bibliográfica, un sitio benigno o un marcador de posición.

## Limitaciones declaradas

* **Un solo anotador para la adjudicación** (un LLM, no independiente de la familia de modelos evaluada) y sin
  acuerdo entre anotadores. Por eso se publica también la precisión estricta contra STIX, que no depende de él.
  Se prepara una muestra de 30 casos para auditoría humana.
* **Sesgo de *pooling***: solo se adjudica lo que algún sistema extrajo; un IOC real que ninguno encontró ni
  figura en el STIX no se cuenta.
* El criterio sobre qué es «infraestructura del adversario» es discutible en los casos límite (CVE citados,
  servicios legítimos abusados). Todos los casos están registrados para poder reasignarlos.
* 13 de los 39 informes usan STIX 1.x XML (los de 2022 y algunos posteriores); su análisis es propio y menos probado
  que el de STIX 2.1 JSON.
