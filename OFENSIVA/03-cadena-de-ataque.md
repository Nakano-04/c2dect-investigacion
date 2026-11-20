# 03 - Cadena de ataque y puntos de observación

La plataforma organiza la emulación en siete fases. Para cada fase se lista el
punto de observación más temprano y el criterio de verdad que la valida.

| Fase | Componente | Punto de observación | Criterio de verdad |
|---|---|---|---|
| 1. Acceso inicial | `delivery/` | Correo/proxy, creación de proceso | Entrega con artifact y ack |
| 2. Reconocimiento | `cmd/recon-module/` | DNS, escaneo, pcap | Salida correlacionada con CVE |
| 3. Explotación | `exploits/` | Crash de emulación (Unicorn) | `Outcome.executed` + evidencia |
| 4. Post-explotación | `cmd/agent_go/` | Sysmon 1/10, ETW | Tarea con resultado real |
| 5. Escalada/lateral | `modules/lateral-rust/` | 4624/5140, DCOM | RoE firmada + evidence |
| 6. Beaconing/C2 | `server/` + `c2-protocol/` | pcap, JA3, periodicidad | Check-in cifrado verificado |
| 7. Impacto (simulado) | simuladores | cifrar/descifrar round-trip | RoE + marcador de simulación |

## Gobernanza como parte de la cadena

Cada transición está sujeta a: killswitch, kill-date, escala, techo de tiempo y
acuse del operador. Las capacidades STUB/WIP/CHECK-ONLY se declaran como tales:
nunca se presentan como ejecutadas.

## Lección de investigación

La cadena completa no es necesaria para medir detección. A menudo el mayor
valor está en las fases 1, 4 y 6, que son las que producen telemetría más rica
y más barata de instrumentar.
