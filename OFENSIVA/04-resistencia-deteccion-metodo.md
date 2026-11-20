# 04 - Resistencia a detección como propiedad medible

## Tesis

La detectabilidad de una técnica es una **propiedad medible**, no una opinion.
Se mide con tres componentes: cuándo se detecta, con qué precisión y con cuánta
incertidumbre.

## Definiciones operativas

- **TTD (time to detect)**: `t_alerta - t_ejecucion`.
- **TTC (time to contain)**: `t_contencion - t_ejecucion`.
- **Recall**: detectadas / ejecutadas.
- **Precisión**: verdaderos positivos / alertas.
- **FP/h**: falsos positivos por hora de telemetría benigna.
- **Observabilidad**: probabilidad de que al menos un sensor registre la técnica.

## Protocolo

1. Ejecutar la técnica en aislado, con marca de tiempo de inicio.
2. Capturar sensores (ETW-TI, Sysmon, pcap, logs de aplicación).
3. Correlacionar por host + PID +_image + ventana temporal.
4. Corregir contra corpus benigno para estimar falsos positivos.
5. Repetir N veces; bootstrap para IC95%.
6. Publicar con hashes de fixture y semilla determinista.

## Criterios de honestidad

- Un crash de emulación se reporta como **crash de emulación**, nunca como RCE.
- Una técnica no ejecutada se marca `no-ejecutada`, nunca se rellena.
- El resultado se reporta con su intervalo de confianza y su muestra.

## Qué NO es este método

No es una guía para evadir detección. Es un protocolo para que el equipo azul
sepa qué puede ver y con cuánto retraso. La misma medición que dice «esta
técnica es poco observable» es la que permite priorizar una regla nueva.
