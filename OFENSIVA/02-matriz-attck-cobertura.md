# 02 — Matriz ATT&CK y cobertura de detección

## Estado medido

La matriz de cobertura de la campaña (`c2dect-telemetry-dataset`) muestra
**44 TTPs sin ejecutar**, todos los hits a 0 y veredictos `sin-registro /
sin-probar`. Es decir: hoy no hay evidencia de cobertura real. Publicar una
matriz «rellena» sería falso; el dataset v1 debe construirse ejecutando la
campaña bajo RoE firmada.

## Estructura de la matriz (contrato)

Cada fila lleva: `tecnica ATT&CK`, `regla Sigma`, `táctica`, `hits`,
`veredicto`, `estado`, `evidencia (hash/ruta sanitizada)`.

| Táctica | Tecnica (ej.) | Sensor primario | Veredicto possible |
|---|---|---|---|
| Reconocimiento | T1595 | pcap / DNS | landed / sin-registro |
| Acceso inicial | T1566, T1189 | correo / proxy | landed / sin-registro |
| Ejecución | T1059 | Sysmon 1 / ETW | caught / landed |
| Persistencia | T1547 | registro / tareas | caught / caught |
| Evasión | T1055 | ETW-TI | needs_tuning |
| C2 | T1071.001 | pcap / JA3 | caught |
| Lateral | T1021 | 4624 / 5140 | sin-probar |

## Brechas prioritarias (hipótesis)

1. **Evasión (T1055, T1629)** — indicadores estructurales requieren ETW-TI;
   sin ese sensor la cobertura cae a cero.
2. **Beaconing (T1071.001)** — reglas de periodicidad existen pero no hay
   tráfico etiquetado que las valide.
3. **Acceso inicial** — las reglas están declaradas pero la campaña no ejecutó
   esas técnicas.

## Entregable

Capa de Navigator con la cobertura **medida** (no declarada), generada desde
`results.json` del repo de dataset.
