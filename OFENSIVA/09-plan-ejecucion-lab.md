# 09 - Plan de ejecucion en laboratorio (6 tecnicas reales)

Este documento convierte el marco en evidencia empirica. No anade codigo:
define como ejecutar un subconjunto pequeno y como cerrar hallazgos con datos.

## Objetivo

Pasar de 44 TTPs `sin-probar` a **6 tecnicas ejecutadas** con telemetria real,
veredictos `caught / landed / needs_tuning`, TTD medido e IC95%.

## Alcance y gobernanza (obligatorio antes de ejecutar)

1. VM aislada con snapshot limpio (`clean-v1`), sin acceso a Internet.
2. RoE firmada generada con `tools/gate/make_lab_roe.py`:
   `python tools/gate/make_lab_roe.py --out lab/roe.json --tenant lab-tenant --modules atomic-lab`
   Semilla por defecto es PUBLICA de test: solo laboratorio.
3. Killswitch, kill-date, techo de tiempo y escala declarados.
4. Ningun activo de terceros. Sin excepciones.

## Las 6 tecnicas

| # | Tecnica | ATT&CK | Sensor primario | Hipotesis (doc 06) |
|---|---|---|---|---|
| 1 | Ejecucion via shell | T1059 | Sysmon 1 / ETW process | H3: TTD < 60s en >=80% |
| 2 | Beaconing periodico | T1071.001 | pcap / JA3 | H2: precision > 0.8 |
| 3 | Inyeccion P3 (PEB RX) | T1055 | ETW-TI | H1: sin ETW-TI es indetectable |
| 4 | Hijack de hilo | T1055 | ETW-TI `NtSetContextThread` | H1 |
| 5 | Persistencia por registro | T1547 | Sysmon 12/13 | cobertura declarada |
| 6 | Descubrimiento local | T1082 | Sysmon 1 (command line) | ruido benigno |

Criterio de seleccion: las 6 producen telemetria rica, son repetibles y
cubren los tres sensores del marco (proceso, red, memoria).

## Formato de telemetria (contrato p3.telemetry.v1)

Cada evento lleva `schema`, `event_type`, `host`, `pid`, `image`, `t` y campos
propios. El detector **recalcula** los indicadores desde campos crudos; no
confia en un `p3_indicator` precalculado.

```json
{"schema":"p3.telemetry.v1","event_type":"memory_protect",
 "host":"lab-w1","pid":4321,"image":"lab.exe","t":12.34,
 "region":"peb","new_protect":"RX","image_backed":false}
```

Tipos usados: `process_create`, `memory_protect`, `thread_context`,
`process_access`, `network_connect`.

## Procedimiento por tecnica (5 pasos)

1. restaurar snapshot `clean-v1`; arrancar sensores y confirmar latencia 0;
2. ejecutar la tecnica N veces (objetivo `n=10`), registrando `t0` real;
3. capturar eventos crudos y convertirlos al contrato con el adaptador;
4. correlacionar por `host + pid + image` en ventana de 60s;
5. escribir un `DetectionRecord` con `RuleID`, `Source`, veredicto y hash de
   la telemetria. Sin `RuleID`, el hallazgo NO se cierra (G1/G3).

## Criterios de cierre (G1/G3/G8)

- **G1**: todo TTP ejecutado tiene `DetectionRecord` con `RuleID` y `Source`.
- **G3**: ningun hallazgo se cierra automaticamente; cierre = retest con
  evidencia sanitizada.
- **G8**: rutas y hashes sanitizados; sin secretos ni identificadores reales.
- Si una tecnica no se ejecuta: `no-ejecutada`, nunca telemetria sintetica.

## Medicion con las herramientas del repo

```powershell
# 1. huella real de la tecnica (debe coincidir con footprint.py)
.\zig-out\bin\footprint_zig.exe telemetry\events.json

# 2. correlacion de la cadena P3
.\zig-out\bin\correlate_zig.exe telemetry\p3_events.json 60

# 3. bypass observado = 1 - recall del sensor (sensor declarado)
python bypass_audit.py telemetry\registro_bypass.json
```

## Entregable final

- `telemetry/lab-v1/` con 6 carpetas, una por tecnica, cada una con:
  `events.jsonl`, `DetectionRecord.json`, `t0.json` y `sha256.txt`.
- `results.json` con TTD/TTC por tecnica, recall, precision, FP/h e IC95%.
- Matriz de cobertura ACTUALIZADA: 6 filas medidas + 38 `sin-probar`.
- Un veredicto H1/H2/H3 cambiado de `Sin probar` a medido (o refutado).

## Criterio de exito del plan

No es "que todo se detecte". Es que **al menos una hipotesis quede refutada o
confirmada con datos reales** y que otro investigador pueda repetir la medicion
con la RoE, la semilla y los hashes publicados.
