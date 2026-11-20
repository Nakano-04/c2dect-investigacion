# 06 — Hipótesis de brechas falsables

Cada hipótesis se formula para poder ser refutada con datos.

| ID | Hipótesis | Métrica de refutación | Estado |
|---|---|---|---|
| H1 | La evasión sin ETW-TI es indetectable | recall > 0 sin ese sensor | Sin probar |
| H2 | El beaconing periódico es detectable con pcap | precision > 0.8 sobre corpus benigno | Sin probar |
| H3 | El acceso inicial deja rastro en proceso | TTD < 60 s en ≥ 80% de repeticiones | Sin probar |
| H4 | La mayor brecha está en memoria, no en red | gap_priority(memoria) > gap_priority(red) | Sin probar |
| H5 | El ruido de lab no predice el de producción | FP/h real ≠ FP/h estimado | Sin probar |

## Protocolo de cierre (G3)

Ningún hallazgo se cierra automáticamente. Cierre requiere retest con
evidencia sanitizada: hash de la técnica, hash del sensor, veredicto y
`DetectionRecord` con `RuleID` y `Source`.

## Uso de estas hipótesis

Sirven para diseñar el experimento del Plan 7 (dataset) y el Plan 4 (SOC).
Sin hipótesis pre-registradas, la medición se convierte en una búsqueda de
resultados favorables.
