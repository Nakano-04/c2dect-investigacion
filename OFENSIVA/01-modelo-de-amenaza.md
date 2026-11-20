# 01 — Modelo de amenaza del adversario emulado

## Activos en el laboratorio

| Activo | Valor | Amenaza principal |
|---|---|---|
| Consola del operador | Alta | Robo de sesión, suplantación |
| Servidor C2 (API + DB) | Alta | Extracción de tareas/loot, envenenamiento de telemetría |
| Canal de beaconing | Alta | Intercepción, replay de beacon, falsificación de tareas |
| Agente en el host objetivo | Media | Captura, ingeniería inversa, extracción de claves de sesión |
| Host objetivo | Alta | Movimiento lateral, persistencia, impacto simulado |

## Adversario

Perfil emulado: actor con acceso inicial limitado, capacidades de post-explotación
y un objetivo de reconocimiento/impacto. Se modelan tres niveles:

1. **Oportunista** — acceso inicial, descubrimiento básico, beaconing.
2. **Organizado** — post-explotación, movimiento lateral, persistencia.
3. **APT (laboratorio)** — cadenas completas con gobernanza (RoE, kill-date,
   techo de tiempo, escala).

## Supuestos

- El adversario conoce el entorno de laboratorio y sus sensores.
- La telemetría es producida por sensores reales (ETW-TI, Sysmon, pcap), no
  por el propio aserto del agente.
- Ninguna capacidad se acepta como ejecutada sin `truth.Outcome` con evidencia.

## Superficie de ataque del propio C2

La auditoría ofensiva del framework identifica cinco vectores: API/tenant,
inyección de argumentos, capacidades del agente, transporte TLS/mTLS y backup.
Todos están remediados por defecto; quedan los *escape hatches* de laboratorio
como riesgo residual (ver `c2dect-hardening/AUDITORIA_OFENSIVA_c2-dect_2026.md`).

## Preguntas de investigación derivadas

- ¿Qué partially observable events delatan cada fase antes del impacto?
- ¿Qué supuestos del adversario se validan o se rompen con telemetría real?
- ¿Dónde está el punto de observación más temprano y menos costoso?
