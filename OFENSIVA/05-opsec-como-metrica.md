# 05 - OPSEC como métrica de huella

## Idea

La seguridad operativa puede expresarse como un vector de **observabilidad**
por técnica: qué sensores la ven y cuánta señal generan. Ese vector se agrega
en una puntuación que cuantifica la huella.

> Uso defendido: priorizar detección. Una técnica con alta puntuación de
> observabilidad es un buen candidato para regla Sigma; una con baja puntuación
> indica un sensor faltante.

## Modelo

Cada técnica declara `artifacts`: señales observables por sensor con un peso
(0–3) según la riqueza de la señal.

| Sensor | Señal ejemplo | Peso típico |
|---|---|---|
| `process` | Sysmon 1, línea de comandos | 2 |
| `network` | pcap, JA3, periodicidad | 2 |
| `memory` | ETW-TI, RX sobre PEB | 3 |
| `registry` | claves de persistencia | 2 |
| `file` | escritura de artefacto | 1 |

## Puntuación

```
observabilidad = Σ(pesos de señales) / Σ(pesos máximos posibles)
gap_priority   = 1 - cobertura_de_reglas_de_la_tecnica
```

- `observabilidad` alta → la técnica deja mucho rastro.
- `gap_priority` alta → hay poco sensor/regla, conviene invertir ahí.

El prototipo `opsec_score.py` implementa este modelo con datos sintéticos y
produce un informe por técnica y un ranking de brechas.

## Límites

La puntuación depende de los sensores desplegados: no es una propiedad
intrínseca de la técnica, sino del **par técnica-entorno**. Por eso se publica
junta la lista de sensores asumida.
