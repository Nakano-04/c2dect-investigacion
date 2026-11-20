# 07 - Bypass auditable como técnica de medición

## Planteamiento

Un "bypass" sólo es publicable y verificable cuando se convierte en **objeto de
medición**: el laboratorio intenta una técnica de evasión y el resultado
auditado es *si el sensor la detectó*, nunca el código que la ejecutó.

Esto invierte la lógica del armamento. En lugar de entregar una capacidad que
evade, se entrega un **protocolo para medir cuánto evade** y un registro que
demuestra lo que ocurrió.

## Principios

1. **Contrato, no código.** Cada técnica se describe por su *indicador duro*
   (qué cambia en el sistema), no por su implementación.
2. **Verdicto con evidencia.** El resultado es `observed / not-observed /
   no-ejecutada`, siempre con hash de la telemetría y del sensor.
3. **Sensor declarado.** Se publica qué sensores se asumieron. Sin esa lista,
   "no detectado" no significa nada.
4. **Sin secretos.** Rutas y hashes sanitizados (G8); ningún hallazgo se cierra
   automáticamente (G3).

## Catálogo de técnicas "semi-nuevas" (nivel indicador)

| ID | Técnica | Indicador duro | Sensor requerido |
|---|---|---|---|
| B-01 | Parcheo de ETW en usuario | Cambio de permisos/bytes en sección de ETW | ETW-TI |
| B-02 | Bypass de AMSI | Modificación de la función de escaneo | ETW / hook de biblioteca |
| B-03 | Inyección en PEB (P³) | RX sobre MEM_PRIVATE del PEB | ETW-TI (`NtProtectVirtualMemory`) |
| B-04 | Hijack de hilo | RIP fuera de imagen válida | ETW-TI (`NtSetContextThread`) |
| B-05 | Sleep obfuscation | Gap temporal con cambios de protección de memoria | ETW + correlación temporal |
| B-06 | Llamadas directas a syscall | Transición sin entrada en ntdll | ETW-TI |

> Estas técnicas están documentadas públicamente (MITRE ATT&CK T1055, T1622,
> T1564). Aquí sólo se registra su **huella**, no se implementan.

## Métrica de "bypass observado"

```
bypass_observado = 1 - recall_del_sensor_para_la_tecnica
```

si el sensor detectó la técnica en todas las repeticiones → bypass = 0.
si no la detectó en ninguna → bypass = 1, pero con IC95% y `n` declarados.

Un bypass con `n=1` no es evidencia; es un anécdota.

## Entregable

- Catálogo `fixtures/bypass_catalog.json` (contrato de indicadores).
- Prototipo `bypass_audit.py` / `bypass_audit_zig`: calcula el índice de bypass
  observado a partir de repeticiones con veredicto, con bootstrap.
- Registro de auditoría: hash del catálogo + hash de la telemetría + sensor
  declarado + semilla.

## Límite

No se incluye código que parchee ETW/AMSI, realice inyección, ofusque memoria
o invoque syscalls directos. El bypass se estudia como **hipótesis medible**,
no como herramienta.
