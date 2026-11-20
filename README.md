# C2-DECT — Investigación

Repositorio de **contenido y resultados** de investigación sobre C2-DECT, una
plataforma de emulación de adversarios con C2 integrado para laboratorios de
Red Team y validación de detección.

> **Este repositorio no contiene código fuente de C2-DECT.** Contiene
> documentación, planes, auditorías, resultados medibles y **prototipos
> pequeños y originales** de cada línea de investigación (sin dependencias del
> framework). El código del framework permanece en su repositorio de desarrollo.

## Prototipos propios (verificables)

Cada repo de línea incluye un prototipo independiente con tests, fixtures
sintéticas, `results.json` (con hashes SHA256) y CI que ejecuta las pruebas:

| Repo | Prototipo |
|---|---|
| `c2dect-soc-validation` | `tt_calculator.py` — TTD/TTC, IC95%, comparación de brazos |
| `c2dect-hardening` | `hardening_scan.py` — 7 reglas, severidades y ratchet de baseline |
| `c2dect-unicorn-fuzzing` | `crash_triage.py` — dedupe, minimización, cobertura y reproducibilidad |
| `c2dect-telemetry-dataset` | `dataset_tools.py` — sanitización, etiquetas, split y datasheet |

Aquí, `verify_manifest.py` comprueba la integridad de todo el contenido:

```powershell
python -m unittest discover -v
python verify_manifest.py
python verify_manifest.py generate
```

## Ámbito y uso autorizado

Toda la investigación se realiza en **laboratorio aislado, con alcance declarado
y RoE (Rules of Engagement) firmada**, contra activos propios o bajo contrato de
pruebas de seguridad autorizadas. El uso contra activos de terceros sin
autorización es ilegal. Los hallazgos no se cierran automáticamente (G3): el
cierre exige retest con evidencia.

## Líneas de investigación

| Línea | Repo | Resultado |
|---|---|---|
| 4 — Validación de SOC con grupo de control | `c2dect-soc-validation` | Estudio de caso |
| 5 — Hardening del propio C2 | `c2dect-hardening` | Harness + metodología |
| 6 — Fuzzing/emulación con Unicorn | `c2dect-unicorn-fuzzing` | Benchmark + paper |
| 7 — Dataset de telemetría etiquetado | `c2dect-telemetry-dataset` | Dataset + datasheet |

## Documentos incluidos

- `PLANES_INVESTIGACION_4-7.md` — planes con hipótesis, métricas, experimentos y entregables.
- `AUDITORIA_OFENSIVA_c2-dect_2026.md` — auditoría ofensiva estática (2026-10-30).
- `AUDITORIA_OFENSIVA_c2-dect.md` — auditoría ofensiva previa (2025).
- `AUDITORIA_DEFENSIVA_OFENSIVA.md` — auditoría defensiva/ofensiva.
- `AUDITORIA_PROFUNDA_c2dect_vs_SentryGuard.md` — análisis comparativo.

## Idea central

El diferenciable de C2-DECT no es la weaponización, sino el **contrato de verdad**
(`truth.Outcome`): ninguna capacidad se declara "ejecutada" sin evidencia. La
investigación busca formalizar y medir esa propiedad, no añadir capacidades
ofensivas opacas.
