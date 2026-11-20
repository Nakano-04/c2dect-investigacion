# AUDITORÍA DE PROFUNDIDAD - `c2-dect` vs `SentryGuard-0.0.1`

**Fecha:** 2026-11-10 · **Método:** revisión estática + verificación ejecutable (8 agentes de auditoría en paralelo + pruebas empíricas propias con los binarios reales de ambos proyectos).

**Alcance:**
- Ofensivo: `C:\Users\USER1\Desktop\test\cs2\c2-dect`
- Defensivo: `C:\Users\USER1\Desktop\test\cs2\SentryGuard-0.0.1`

**No se modificó ningún fichero de ninguno de los dos proyectos.** (Las únicas escrituras fueron en `%TEMP%\opencode\`. Se limpiaron los `obj2/` accidentales creados dentro del repo de SentryGuard y se re-verificó el build: `0 errores`.)

---

## 0. VEREDICTO EJECUTIVO

| | c2-dect (ofensivo) | SentryGuard-0.0.1 (defensivo) |
|---|---|---|
| **Compila** | ✅ `go build ./cmd/server/` y `./cmd/agent_go/` OK · `go vet` limpio | ✅ `dotnet build` 0 errores, 6 warnings · `cargo check` OK (34 warnings) |
| **Tests** | parciales (216 capacidades auto-sondeadas; 100 `real-ejecutada`, 30 `simulada`, 53 `no-disponible`) | ✅ 69/69 pasan - pero **no cubren ninguna detección** (ver §3.7) |
| **Es real** | **Sí, a medias.** El agente Go es un arsenal real. El servidor es un simulador grande. | **No.** El motor de reglas es real; la *plataforma* que lo alimenta no existe. |
| **¿Puede defenderse?** | - | **NO.** Tres bloqueos independientes, cada uno suficiente. |

### La respuesta a «¿puede SentryGuard defender?»

**No, y no por falta de reglas.** SentryGuard tiene 3.085 reglas Sigma + 5.934 YARA y las evalúa. El problema es que **no hay nada que evalúe** y **nada que hacer con el resultado**:

1. **No hay telemetría.** El agente .NET genera escenarios sintéticos (`EventCollector.cs:14-31`); el agente Go en Windows no recolecta nada (`proc_other.go:19-21`); el driver kernel (16 ficheros C, 13 IOCTLs) no tiene sistema de build y su cliente .NET no lo referencia ningún binario. `EventSourceFactory` sólo conoce `"simulated"` y `"jsonl"`.
2. **No hay respuesta.** `NetworkIsolator` es un `HashSet` en memoria que devuelve `Success=true` (`NetworkIsolator.cs:46-62`). La API del servidor tiene **cero endpoints de respuesta**. `checkin` devuelve `tasks: []` y ambos agentes lo ignoran.
3. **El motor tiene bugs que anulan la cobertura.** El operador Sigma `|re` degrada a «el campo existe» (`EvaluationEngine.cs:236`) → 61 reglas matchean cualquier valor. El `RuleIndex` colapsa 3.085 reglas en 8 logsources (`RuleIndex.cs:224`, primer `data_source` gana) y aplica *todas* las reglas del logsource ignorando el `event_id` (`RuleIndex.cs:128-136`). 210 reglas vienen con `"enabled": false`. 640 reglas con nodos `selection_list` no deserializan.

**Peor aún: donde sí hay telemetría, el motor produce falsos positivos和非 detections.**

---

## 1. VERIFICACIONES EJECUTABLES (primeras manos)

| Verificación | Resultado |
|---|---|
| `dotnet build SentryGuard.sln -c Release` | ✅ 0 errores, 6 warnings |
| `dotnet test SentryGuard.sln -c Release` | ✅ **69/69** (12 Server + 57 Rules), 1m10s |
| `cargo check --release` en `src/core` | ✅ compila, **34 warnings**, **0 tests** |
| `go build ./cmd/server/` (c2-dect) | ✅ EXIT=0 |
| `go build ./cmd/agent_go/` (c2-dect) | ✅ EXIT=0 (binario 16.6 MB) |
| `go vet ./...` en `c2-dect/server` | ✅ EXIT=0 |
| **YARA de SentryGuard sobre el binario real del agente c2-dect** | ⚠️ **55 matches en 328.008 ms** (5,5 min para un solo fichero de 16 MB) |
| **Purple-team benigno** (`notepad.exe notes.txt`, `WINWORD.EXE document.docx`) | 🔴 **14 detecciones, 2× CRITICAL score=650** por abrir un bloc de notas |
| **Purple-team c2-dect real** (11 eventos con artefactos reales del agente) | 🟡 36 detecciones - acierta en persistencia/servicio, **falla en registro, fichero, red y DNS** |
| **Regla `T1547_New_RUN_Key_Pointing_to_Suspicious_Folder`** (la que debería cazar la persistencia de c2-dect) | 🔴 **Cargada, aplicable bajo canal `Security`, pero `"enabled": false` → nunca dispara.** Aislando cada hoja: **ambas hojas sí matchean**. Es la闸门 la que está cerrada. |

### 1.1 Purple-team: dos eventos benignos, 14 detecciones

```
[DETECT] [LOW]  T1016 (?)  rule=T1016_Suspicious_Network_Command
[DETECT] [HIGH] T1027 (?)  rule=T1027_Invoke_Obfuscation_STDIN__Launcher
[DETECT] [HIGH] T1027 (?)  rule=T1027_Invoke_Obfuscation_VAR__Launcher
[DETECT] [HIGH] T1027 (?)  rule=T1027_Invoke_Obfuscation_Via_Stdin
[DETECT] [HIGH] T1027 (?)  rule=T1027_Invoke_Obfuscation_Via_Use_Clip
[DETECT] [MEDIUM] T1119 (?) rule=T1119_Automated_Collection_Command_Prompt
[DETECT] [HIGH] T1055 (?)  rule=T1055_Network_Connection_Initiated_Via_Notepad_EXE
[DETECT] [HIGH] T1036 (?)  rule=T1036_Suspicious_DumpMinitool_Execution
[CORR]   CRITICAL score=650
```

Causa raíz de los 4 `T1027` fantasma: la familia «Invoke-Obfuscation» usa el operador Sigma `|re`, que el motor **no implementa** → `BuildFieldCondition` cae en `return containsKey` (`EvaluationEngine.cs:236`) → *la regla dispara si el campo existe*. Las 4 aparecen en **todos** los eventos, incluidos `notepad.exe`.

`T1036_Suspicious_DumpMinitool_Execution` dispara porque una de sus ramas OR es `CommandLine contains ".txt"` → `notes.txt` casa.

### 1.2 Purple-team: artefactos REALES de c2-dect

Eventos sintetizados desde los artefactos literales del agente (`cmd/agent_go/`): servicio `WinDefendUpdate`, `svchost.exe` en `%APPDATA%\c2-dect\data`, `HKCU\...\Run`, `ms-settings\Shell\Open\command` (fodhelper), `ffmpeg -f dshow audio="Microphone"`, `keylogs\keylog.txt`, `downloads\payload.exe`, conexión `203.0.113.77:443`, DNS `*.tun.cdn-sync.net`.

| Artefacto de c2-dect | ¿Detectado por SentryGuard? | Detalle |
|---|---|---|
| `sc create WinDefendUpdate` | ✅ | `T1543 New Service Creation Using Sc.EXE` (LOW) |
| `svchost.exe` desde AppData | ✅ | `T1036 Suspicious Process Masquerading As SvcHost.EXE` (HIGH) + `Uncommon Svchost Parent Process` + `Suspicious Parent Directory` |
| `fodhelper.exe` + `ms-settings` | ⚠️ | Sólo un match YARA genérico (`T1134 Meterpreter/CobaltStrike`) |
| **`HKCU\...\Run` → `%APPDATA%\c2-dect\data\svchost.exe`** | 🔴 **NO** | La regla que lo cubre está `enabled=false`; el resto no mira `HKCU` |
| **`c2-dect\data\keylogs\keylog.txt` (creación de fichero)** | 🔴 **NO** | Sin cobertura de Sysmon EID 11 |
| **`c2-dect\data\downloads\payload.exe`** | 🔴 **NO** | Ídem |
| **Conexión a `203.0.113.77:443`** | 🔴 **NO** | Sin telemetría de red |
| **DNS `a8f3c2e1b9d4.tun.cdn-sync.net`** | 🔴 **NO** | Sin telemetría DNS |
| **Captura de audio con `ffmpeg -f dshow`** | 🔴 **NO** | Sin regla |
| **Nombre de servicio `WinDefendUpdate` (suplanta Defender)** | 🔴 **NO** | Sin regla específica |
| **Ruta `c2-dect` (×107 en el binario)** | 🔴 **NO** | Sin regla |

**Detección real: 3 de 11.** Las 3 son coincidencia de patrón genérico, no cobertura diseñada.

### 1.3 YARA contra el binario real de c2-dect - y el problema de rendimiento

El motor YARA **sí** encuentra cosas en el binario real del agente (55 matches: `Rubeus Credentials`, `Sharphound Credentials`, `Mal Zip Socgholish`, `Expl Keepass`, `Powershell In Word Doc`…). Pero:

- **328 segundos** para un fichero de 16 MB → **techo ≈ 1,4 ficheros/hora/host**. Un EDR real no puede con esto.
- El motor es un **emulador escrito a mano**, no libyara. `YaraNativePool` (P/Invoke real) es **código muerto**.
- El emulador **descarta las guardas**: si la condición contiene `any of them` / `all of them`, se evalúa **sólo** el atajo y se ignoran `uint16(0)`, `filesize`, `pe.exports()`. Medido: **5.490 de 5.934 reglas (92,5 %)** pierden sus guardas. Por eso `Rubeus Credentials` matchea un binario Go: las cadenas están, pero la condición PE no se comprobó.
- `MatchTextEncoding` con `nocase` **aloca una copia en minúsculas del buffer completo por cada cadena** → O(cadenas × buffer) de asignaciones. De ahí el coste.

---

## 2. c2-dect - AUDITORÍA OFENSIVA

### 2.1 Lo que es real (agente Go `cmd/agent_go/`)

**Credenciales / AD:** Kerberoast completo (`kerberoast.go`: login Kerberos + LDAP + AS-REQ/AS-REP, devuelve hashes TGS), DCSync nativo (`dcsync_native.go`), Golden/Silver ticket, LSASS dump (`comsvcs.dll!MiniDump`), SAM/SYSTEM dump, DPAPI (`CryptUnprotectData`), Chrome master key, WiFi PSK.

**Movimiento lateral:** WMI remoto (COM/WBEM), PsExec, WinRM (`winrs.exe`), DCOM (MMC20), BITS (incluido `SetNotifyCmdLine`, patrón UBoatRAT), RDP (`tscon` hijack, `mstsc /shadow:`), **SMB relay NTLM honesto** (no falsifica el challenge).

**Persistencia:** Run key HKCU, scheduled task, servicio Windows (`sc create`), WMI Event Subscription, COM hijack, DLL side-loading (`%TEMP%\c2sl-<pid>-<nanos>\`), worm como servicio `WinDefendUpdate`.

**Elevación:** UAC bypass por 6 vías (fodhelper, eventvwr, cmstp, computerdefaults, slui, SilentCleanup), token steal/impersonation.

**Evasión:** unhooking per-export de ntdll comparando disco vs. memoria, blob de syscalls indirectas con tabla cifrada y validación contra `\KnownDlls`, Hell's/Halo's Gate, sleepmask ChaCha20-Poly1305 + `PAGE_NOACCESS` + custodia DPAPI, detección de VM/sandbox (15 checks), patch de AMSI y ETW.

**C2:** AES-256-GCM + ECDH P-256 + HKDF, perfiles malleable estilo Cobalt Strike, JA3/JA4 diversificado por conexión, ECH, 3 distribuciones de jitter (la default `activity` está diseñada contra el «Jitter-Trap» de Varonis), rotación de clave cada 500 beacons, cifrado de strings XOR por build.

**El repositorio se auto-mide:** `tools/probe_capabilities.py` sondea 206 capacidades contra la API en vivo y publica el veredicto (100 `real-ejecutada`, 30 `simulada`, 53 `no-disponible`, 22 `no-verificable`). Es una práctica honesta y poco común.

### 2.2 Lo que es simulación - y lo que **finge** ser real

🔴 **Cinco superficies devuelven éxito falso.** Este es el riesgo mayor del proyecto ofensivo: un operador que confíe en esos retornos creerá haber tirado credenciales cuando no ha pasado nada.

| Ubicación | Qué devuelve |
|---|---|
| `orchestration/orchestrator_tool.py:328-346` | `_exec_plugin` imprime `[+] Plugin 'X' executed`, `exit_code: 0` para los 12 plugins ofensivos (`cred_dump`, `kerberoast`, `golden_ticket`, `silver_ticket`, `pass_the_ticket`, `proc_inject`…) **sin ejecutar nada**. `_exec_dotnet:311-326` **inventa** `"Assembly loaded in memory"`. `inject_process:348-395` abre el handle y **miente**: `"Memory allocated at 0x10000000"`, `"Thread created: 0x12345678"` |
| `modules/privesc-auto/privesc_auto.py:134` | `{"ok": True, "simulated": True, "from": "USER", "to": "SYSTEM"}` **sin escalar** |
| `modules/socks-proxy/socks_proxy.py:130` | `double_pivot_via_agent()` → `{"ok": True, ...}` sin pivotear |
| `modules/phishingstrike/control-plane/infra-svc/cmd/server/destroy.go:86-95,113-131` | `/destroy` responde `{"status":"killed"}` - `ExecTerraformDestroy.Destroy` y `CloudflareSinkhole.RotateToSinkhole` hacen `return nil` **sin destruir nada**. Un kill-switch que dice «killed» y no mata es peor que no tener kill-switch |
| `modules/lateral-rust/src/lateral/pth.rs:16-33` | Pass-the-hash computa la respuesta NTLMv2 contra un `server_challenge = [0u8;8]` **inventado**, ignora la respuesta (`let _response =`) y devuelve `Ok(true)`. `exec_command` devuelve `"Command executed on {target}"` sin ejecutar |
| `modules/lateral-rust/src/credential/lsass.rs:192-204`, `sam.rs:43-44` | Devuelven **credenciales de prueba fijas** (`Password123`/`testuser`/`TESTDOMAIN`) como si fueran las extraídas del dump |

🔴 **El catálogo miente sobre `webexploits`.** `module_catalog.go:376,378` afirma: *«las 26 funciones hacen peticiones HTTP REALES al objetivo»*. La realidad: **4** hacen HTTP de ataque (`ssi`, `ssrf`, `ssrf.IMDS`, `ssti`), **1** es stub (`xxe.Exploit` → `"xxe exploit not executed (compat stub)"`, etiquetada **"REAL"** en `webexploits_modules.go:478`), y **21** son heurística de strings (`sqli.ErrorBasedCheck` marca éxito con **cualquier HTTP 500**; `UnionCheck` con **cualquier 200**; `BlindCheck` con cualquier respuesta >1,5 s; `authbypass.JWTCheck` cuenta 3 puntos → acepta `alg:none`).

🔴 **El gusano no propaga el payload.** `modules/lateral-rust/src/propagation/deployer.rs:44-92` (`try_wmi_deploy`/`try_psexec_deploy`/`try_dcom_deploy`) ejecuta **`"echo test"`**. El motor "propaga" sin propagar. Tampoco hay beacon de reporting: `HttpsBeacon` existe pero `propagation/worm.rs` nunca lo invoca - el C2 es unidireccional (operador → gusano), no hay retorno de infectados.

🔴 **El worm del agente Go ignora los flags que le pasa el servidor.** `/api/worm/deploy` calcula `--max-depth`, `--threshold`, `--scope` (`handlers.go:2044-2050`) pero `worm_deploy.go:78` lanza el binario **sin argumentos**. El propio catálogo lo admite (`module_catalog.go:1576`).

### 2.3 El plano del servidor C2

| Canal | Estado |
|---|---|
| **HTTP/HTTPS (Gin)** | ✅ **Único canal funcional**. `/agent/checkin`, `/agent/task/pending`, `/agent/task/result`, `/agent/key/exchange` |
| DNS (`server/v3/dns`) | 🔴 **Código muerto** - `NewDNSListener` nunca se invoca. Sin cifrar, TXT fijo `id=%s;sleep=10;jitter=30` |
| SOCKS (`server/v3/socks`) | 🔴 **Código muerto** en servidor; en el agente el comando `socks` sólo imprime *«SOCKS5 proxy simulado lab-only - dry-run»*. El SOCKS5 real es el inverso de `cmd/agent_go/socks.go` |
| WebSocket (`server/v3/websocket`) | 🔴 **Código muerto**. `CheckOrigin: return true` → CSWSH total si se cablea |
| Armory / BOF | 🔴 **Código muerto**. `bof.Execute` dice literalmente *«In a real implementation, this would: 1. Allocate executable memory…»* y luego `// Simulated execution` |

**Debilidad de seguridad propia del C2 (crítica):** el plano del agente opera **sin autenticación real** en el único modo funcional. El primer beacon no tiene clave AES, así que requiere `C2_ALLOW_CLEARTEXT_AGENT=1` - y en ese modo el `session_id` (elegido por el cliente, formato `<hostname>_<8 hex>`) es el único token. Consecuencia: **secuestro de sesión** (UPSERT sobrescribe hostname/IP del cliente en la DB y en la GUI del operador), **robo de tareas pendientes** (`GET /agent/task/pending?session_id=`), **inyección de resultados falsos**.

**Claves de sesión reales en claro en disco:** verificado en `build/c2-dect.db` (19 MB) - claves privadas ECDH y claves AES-256 de implantes en texto plano, porque `SQLCIPHER_KEY` es **opcional** y el KDF es `SHA-256(passphrase)` sin salt.

**El despliegue «de producción» desactiva la seguridad:** `docker-compose.prod.yml:109-122` → `--http`, `C2_ALLOW_HTTP=1`, `C2_ALLOW_NO_MTLS=1`, `C2_ALLOW_SELF_SIGNED=1`, admin con la password del `.env` publicada, puerto 8443 publicado sin TLS. `build/Dockerfile` deja `C2DECT_LAB=1` en la imagen final.

### 2.4 Lo que le falta a c2-dect ofensivamente - lista priorizada

| # | Ausencia | Verificación |
|---|---|---|
| 1 | **Sin BOF real** | `server/v3/bof/bof.go:163-190` - simulado + el paquete no lo importa nadie |
| 2 | **Sin process hollowing expuesto** | `cmd/agent_go/process_hollowing.go:236` implementa `HollowProcess` **completo y real** (`NtUnmapViewOfSection`, `NtAllocateVirtualMemory`, parseo PE64) pero **no hay `case "hollow"` en el switch** y nadie lo llama. Mismo caso `InjectReflectiveDLL` |
| 3 | **Sin ADS** (Alternate Data Streams) | grep de `AlternateDataStream`/`NTFS_ALTERNATE` → 0 |
| 4 | **Sin pivoting SMB por named pipes** | El pivote real es SOCKS5 inverso. `modules/lateral/` es **una cabecera de 169 líneas sin `.cpp`** |
| 5 | **Sin exfiltración real** | `DeadDropInstruction::Exfiltrate` (`command/executor.rs:45-48`) sólo registra el nº de bytes |
| 6 | **Sin persistencia Startup folder / IFEO / AppInit_DLLs** | Sólo Run key, tarea, servicio, WMI, COM, side-load |
| 7 | **Sin Kerberoast en `lateral-rust`** | El `kerberoast.go` del agente Go es de otro árbol; el plugin del orquestador es metadato |
| 8 | **Sin DCSync en ningún árbol** | Sólo descripción textual |
| 9 | **Sin SSH como vector lateral** | El puerto 22 sólo aparece para scanning |
| 10 | **Sin canales C2 no-HTTP** | `DECTP_SPEC.md:78` declara `{http,dns,smb,websocket}`; sólo existe HTTP |
| 11 | **Sin drenaje de ruido (noise/drain)** | Verificado: no hay generación de tráfico de fondo. El perfil malleable puede cambiar ruta/UA/método, pero el **prefijo `/agent` es constante e inseparable** (`handlers.go:1745`) y el cuerpo/respuesta JSON tienen forma fija (`{"session_id","data"}` / `{"encrypted":true,"data":...}`) |
| 12 | **PhishingStrike desconectado del C2** | grep de `phishingstrike`/`phishcore` en `server/` → **0**. El cloaking avanzado (GeoIP/ASN/JA4) **solo se llama en sus propios tests**; el hot path es un bloque Lua de nginx que mira 9 User-Agents. El kill-switch del dataplane se `mod`-declara y **nunca se instancia**. El broadcast del kill no se invoca. ACME DNS-01 es placeholder. El insert a ClickHouse es `TODO(prod)` |
| 13 | **`ultra/` (C++) no compila** | 6 errores en CI; `restore_amsi`/`restore_etw` devuelven `true` sin restaurar |
| 14 | **`pic-asm` / `signature-evasion` no compilan** | Sin `CMakeLists.txt` válido; el `README.md` documenta `core/src/evasion_core.c`, **fichero que no existe** |

### 2.5 Lo que le falta a c2-dect **en control de alcance** (responsabilidad)

🔴 **Asimetría grave:** el módulo que puede más daño (`ddos-dect`, con cuotas duras + allowlist + política firmada Ed25519) está **bien gateado**. Los que pueden ejecutar RCE/SSRF contra terceros **no**:

| Endpoint | Gate de impacto | Allowlist de objetivo |
|---|---|---|
| `/api/modules/ddos-dect` | ✅ política firmada `lab-only` | ✅ host+puerto, fail-closed a loopback |
| `/api/modules/{ransomware,worm,kernel,lateral,privesc,adversary}-sim` | ✅ política firmada | ✅ lab contenido (`.lab-allow`) |
| **`/api/modules/webexploits`** | 🔴 **ninguno** | 🔴 **ninguna** → el C2 envía payloads de ejecución de comando y SSRF a **cualquier URL http(s)** |
| **`/api/modules/discovery`** | 🔴 ninguno | 🔴 ninguna → `nmap -sn <cidr>` y `Invoke-BloodHound` contra cualquier destino |
| **`/api/modules/collection`** | 🔴 ninguno | - opera sobre el host del C2: lectura/cifrado arbitrario de ficheros (`paths`/`path` sin sanear → `os.ReadFile` directo) |
| **`/api/modules/creds`** | 🔴 ninguno | - roba tokens del host del C2 |

Otros problemas: `AGENT-EXEC` es una **constante estática replayable** (`agent_command_gate.go:45`), no ligada a tarea/operador; los `args` de las tareas no se validan (`_ = args`, línea 201); `requireOffensiveLicense` está **muerta** (`jwt_claims` nunca se setea, `Claims` no tiene `tier`) → toda operación ofensiva de tools devuelve 401 y el modelo de licencias no existe de facto.

**Conclusión de responsabilidad:** es defendible como **plataforma de laboratorio / emulación de Red Team** (tiene gates firmados, allowlists, marcadores `.lab-allow`, dry-run por defecto, auditoría encadenada SHA-384). **No es defendible como producto comercial** mientras `webexploits` y `discovery` salgan a la red sin allowlist, mientras el token de confirmación sea una constante replayable, y mientras el cifrado en reposo dependa de una variable de entorno opcional sin guard fail-closed.

### 2.6 Huellas forenses de c2-dect (IOCs verificados en el binario real)

Extraídos con `strings` sobre el binario recién compilado (16.6 MB):

| Cadena | Ocurrencias | Dónde |
|---|---|---|
| `c2-dect` | **107** | Ruta de datos `<dir>\c2-dect\data\{screenshots,downloads,keylogs,streams,uploads}` |
| `WinDefendUpdate` | 2 | Servicio que suplanta a Windows Defender (`worm_deploy.go:92`) |
| `kerberoast` | 8 | `kerberoast.go` |
| `fodhelper` | 5 | UAC bypass (`capabilities.go:606`) |
| `EtwEventWrite` | 3 | Patch de ETW (`etw_patch.go`) |
| `AmsiScanBuffer` | 1 | Patch de AMSI (`amsi_bypass.go`) |
| `Chrome/126` | 1 | UA hardcodeado (`main.go:39`) - coincide con la regla propia `c2lab-v3-agent-checkin-path.yml` |
| `svchost.exe` | 1 | Nombre del worm |
| `mimikatz` | 1 | En la ruta de Kerberoast |

Además, en el repo: **35 reglas Sigma propias** en `infra/phase0/sigma/rules/` que detectan al propio agente (sleepmask NOACCESS, DPAPI key custody, check-in path, jitter uniforme, Run key a directorio escribible, DNS tunneling, lateral, kerberoast, LSASS). Su `baseline-report-real.md` declara OPSEC **70/100 - «C (ruidoso)»** y EDR **0/3 detecciones**.

**Ironía arquitectónica:** c2-dect trae un detector de sí mismo mejor calibrado que el EDR que se supone que lo detecta.

---

## 3. SentryGuard-0.0.1 - AUDITORÍA DEFENSIVA

### 3.1 Telemetría: **no existe en el camino de producción**

| Fuente | Estado |
|---|---|
| Driver kernel (WDM) | 16 ficheros C, 13 IOCTLs, **pero sin `.vcxproj`/`.inf`/Makefile** → **no compila desde el repo**; `SgNetworkInitialize`, `SgMinifilterInitialize`, `SgInjectionDetect*`, `SgSecurityMonitorPrivilege`, `SgGetUserName`, `SgHashBuffer` tienen **0 call-sites**; `NetworkEnable=FALSE`, `MemoryEnable=FALSE`; **8 de 22** tipos de evento alcanzables; ~17 bugs funcionales (timestamp epoch-1601 con error de 369 años, ACL inexistente en el device object, `PsReferencePrimaryToken` a IRQL incorrecto, offset fijo `EPROCESS+0x5A8`, `RtlInitializeCriticalSection` sobre una `LIST_ENTRY`, `RegNtPreOpenKey` reportado como CREATE_KEY…) |
| Cliente .NET del driver | `SentryGuardIoctls.cs` (26 KB) - **código muerto**: `SentryGuard.Sources.Windows` no lo referencia ningún `.csproj` de producto. Además el protocolo está roto en 3 puntos (offset inicial 16 vs 24, stride fijo 5816 vs `header.Size`, skips de struct 24/28 vs 32/60/30) |
| ETW | 🔴 Inexistente (0 coincidencias de `TraceEvent`/`EventSource`/`EventPipe`) |
| Windows Event Log | 🔴 Inexistente como fuente (sólo un consumidor puntual en `ADCSCertificateDetector`) |
| Sysmon | 🔴 No se consume. Sólo se **falsa la forma** del evento (`channel: Microsoft-Windows-Sysmon/Operational`, `source: Sysmon`) |
| WFP (red) | 🔴 `network.c` escrito pero con **0 call-sites**; sólo capa V4; **nunca lee payload**, ni SNI, ni IP en texto (`remote_address` siempre vacío) |
| pcap | 🔴 Inexistente (0 coincidencias de `pcap`/`Npcap`/`WinDivert`) |
| WMI | ⚠️ Sólo auto-protección, no telemetría de seguridad |
| `/proc` (Linux) | ✅ Real pero rudimentario: polling de PIDs nuevos cada 5 s |
| Agente .NET | 🔴 `EventCollector.cs:14-31` → `ScenarioCatalog.All` → **12 escenarios sintéticos**. `AgentOptions.Source` existe pero **nunca se lee** |
| Agente Go en Windows | 🔴 `proc_other.go:19-21` → `proc` es un stub que hace `<-ctx.Done()`. El instalador pone `SENTRYGUARD_COLLECTOR=proc` (`Install-User.ps1:67`) ⇒ **en Windows el agente instalado no envía ni un evento** |

**ElPipeline no tiene fuente de red.** Un beacon C2 por HTTPS es **completamente invisible** para SentryGuard, y lo seguiría siendo con el driver compilado, firmado y conectado (la capa `ALE_AUTH_CONNECT_V4` sólo ve IP y puerto del socket).

### 3.2 Telemetría de proceso: el desajuste de esquema

- Las 3.085 reglas Sigma están escritas contra el esquema **Sysmon** (`CommandLine`, `Image`, `ParentImage`, `TargetObject`, `TargetFilename`, `DestinationIp`, `QueryName`…). `Connect.md:282-287` documenta el mapeo Sysmon→Sigma.
- El driver produce **otro** esquema: `command_line`, `image_name`, `parent_image_name`, `key_name`, `remote_address`…
- **No existe `FieldMapper` driver→Sigma** (`FieldMapper.cs` no existe, pese a que el README lo documenta). Aunque el driver compilase, cargase y el cliente se conectase, **las reglas no casarían** (0 reglas evaluadas, 0 detecciones).

### 3.3 Respuesta: **cero capacidad**

| Capacidad | Estado |
|---|---|
| **Aislar host** | 🔴 `NetworkIsolator` = `HashSet<string>` en memoria + un `Logger.Warning`. Los 4 campos de `IsolationConfig` (`Duration`, `AllowedServerIps`, `DisableShares`, `BlockOutbound`) **se declaran y nunca se leen**. No hay regla de firewall, ni `netsh`, ni WFP, ni expiración, ni reversión real. Además sólo lo usa `WormDetector`, en un proyecto **huérfano**, y el `ResponseAction "isolate_host"` **ni siquiera parsea** (el enum es `IsolateHost`, sin guion → `Enum.TryParse` falla en silencio) |
| **Matar proceso** | 🔴 No existe (sólo `Process.Kill` del sandbox analyser) |
| **Cuarentena de fichero** | 🔴 No existe (sólo un `File.Move(x, x+".quarantine")` del sandbox) |
| **Bloquear IP/dominio** | 🔴 `ResponseAction.BlockIP` es un miembro de enum sin ejecutor |
| **Matar sesión / revocar tokens** | 🔴 No existe |
| **Canal servidor→agente** | 🔴 `checkin` devuelve `tasks: Array.Empty<object>()`; el agente Go sólo parsea `nowUtc`; el .NET **descarta el cuerpo**. No hay cola de comandos en BD, ni endpoint de pull, ni procesamiento de `tasks` |
| **IoC en el endpoint** | 🔴 Sin gestión de reglas de firewall, sin sinkhole DNS, sin enforcement de hosts, sin integración AMSI, sin gestión de Sysmon, sin bloqueo BYOVD |

**Código muerto peligroso:**
- `CanaryRollback.cs` - nunca instanciado. Si se conectara: `ComputeSHA3` **es SHA-256**, `HealthCheckLoop:447-478` **revierte todos los canaries** (lsass.exe, sam, SYSTEM, bootmgr) si el health score < 0.7 (que baja si Defender no corre o el host está saturado), y `RevertRegistryKey:292-327` restaura con nombres inventados `Value0`, `Value1` → **corrompe el registro que dice restaurar**.
- `SelfProtectionHardening.cs` - nunca instanciado. Stubs vacíos (`SetProcessIntegrityLevel`, `RemoveTokenPrivileges`, `SetProcessDEP`, `SetProcessASLR`), `NtSetInformationProcess(0x1D)` no es la marca de proceso crítico (→ BSOD si se conecta), `ProtectCriticalFiles` puede **autobloquear** el servicio (Deny+herencia protegida sin ACE para el SID del servicio), `ProtectServices` escribe un valor `FailureActions` que **no es un valor de registro** (es un binario bajo `...\Config`).
- `SandboxAnalyzer.cs:240-289` **ejecuta la muestra en el host del EDR** (`Process.Start`), dos veces. Riesgo de auto-infección.

### 3.4 Autenticación y autorización

- **RBAC: no existe.** 0 resultados de `RequireRole|AddPolicy|Roles =` en todo `src/`. El `Role` se emite como claim y se devuelve en `/me`, pero **nunca se evalúa**. `docs/COMPLIANCE.md:7` afirma «Acceso basado en roles» y `docs/API.md:86` documenta un `403 rol insuficiente`. **Ambas afirmaciones son falsas.**
- **RLS inoperante.** Las políticas se crean (`DbInitializer.cs:19-40`) pero: falta `FORCE ROW LEVEL SECURITY` (en PostgreSQL el owner ignora RLS), `app.tenant_id` **nunca se fija** por request, `TenantId` **nunca se propaga** a Events/Detections, `Indicators` queda fuera del perímetro, y el despliegue documentado conecta con el owner de la BD.
- **Secretos por defecto que pasan el guard fail-fast.** El guard (`Program.cs:72-78`) exige ≥32 bytes y rechaza la cadena literal `dev-only-signing-key-change-me`. Pero `.env.example:11` trae `sentryguard-prod-change-me-64chars-…` y `deployment/docker-compose.yml:64` trae `sentryguard-production-change-me-…` - **ambos pasan el check de producción**. También `Seed__AdminPassword=SentryGuard2026!` y `Seed__EnableTotp=false`. Con la `Jwt:Key` por defecto **se forja un token admin**.
- **`Agents__RegistrationKey=change-me-registration-key-32chars`** pasa el check de ≥8 chars → **cualquier agente puede auto-registrarse**. Y el re-registro por hostname **secuestra** cualquier host ya registrado (`AgentEndpoints.cs:25-42`) emitiendo un token nuevo a quien presente la key.
- **`/api/agents/{id}/checkin` sin autenticación** (`AgentEndpoints.cs:72-98`) → cualquiera puede marcar agentes como Online, sobrescribir `Os`/`Arch`/`AgentVersion` e **inflar `EventsSent`**.
- **Hub SignalR abierto** (`Program.cs:185`, sin `[Authorize]`) → fuga hostnames y estados de detección.
- **Sin TLS en el plano de control**: `appsettings.json:2` → `http://0.0.0.0:5137`. Sin `UseHttpsRedirection`, sin `UseHsts`, sin validación de certificado de cliente ⇒ **mTLS no es implementable**, pese a lo que afirma `docs/COMPLIANCE.md:19`. Los bearer tokens circulan en claro.
- **Rate limit global sin particionar**: 5/min en auth **global** ⇒ 5 peticiones agotan el presupuesto de toda la flota (DoS de autenticación). `ingest` 5000/min también global ⇒ un agente ruidoso starvea a todos. `/api/agents/register` **sin límite**.
- **PBKDF2 100k iteraciones** (por debajo de la recomendación OWASP 600k), sin lockout de cuenta, sin política de contraseña. **TOTP implementado y testeado contra vectores RFC** pero **el secreto se genera y nunca se entrega** ⇒ activar `EnableTotp=true` **bloquea el único admin**.
- **Refresh token sin detección de reuso de familia** (`ReplacedByTokenHash` se escribe pero nunca se lee). `docs/API.md:10` promete lo contrario.
- **RLS + TLS + RBAC + mTLS**: las cuatro afirmaciones del documento de compliance son falsas.

### 3.5 Observabilidad: el SLO nunca puede breachar

- El servidor **nunca alimenta el `ThreatPulse`**: las únicas llamadas a `RecordDetection` están en la CLI. `MetricsEndpoints.cs:24` crea un `ThreatPulse` **nuevo en cada petición**.
- `SloMonitor.cs:21` exige `events > 100` con `events = pulse.events_total = 0` ⇒ **nunca se dispara**.
- ⇒ **`GET /api/metrics/slo` devuelve siempre «OK»**. Es el peor fallo de monitorización posible en un EDR: un panel verde que no puede volverse rojo.
- Prometheus: versión hardcodeada, histogramas **no estándar** (`{name}{quantile=…}` en vez de `_bucket{le=…}` ⇒ p95 no calculable), métricas sólo en proceso (multi-réplica ⇒ cada pod expone las suyas), `/metrics` anónimo.
- OpenTelemetry: **sólo `AddConsoleExporter()`** ⇒ la instrucción de apuntar `OTEL_EXPORTER_OTLP_ENDPOINT` no hace nada.
- Logs: sólo consola; la sección `"Serilog"` de `appsettings.json` es **inerte** (falta `ReadFrom.Configuration()`). `RequestLoggingMiddleware` **sólo registra ≥400** ⇒ no hay auditoría de acciones privilegiadas.

### 3.6 El motor de reglas - bugs con impacto medido

| # | Bug | Impacto medido |
|---|---|---|
| 1 | **Operador `\|re` no implementado** → `return containsKey` (`EvaluationEngine.cs:236`) | 61 reglas matchean **cualquier** valor del campo. Los 4 `T1027 Invoke-Obfuscation` fantasma salen de aquí |
| 2 | **`RuleIndex` colapsa a 8 logsources** (`RuleIndex.cs:224`: el primer `data_source` gana; casi todas las reglas SigmaHQ listan Sysmon) | `sysmon` 1.531 · `security` 667 · `unknown` 393 · `audit` 209 · `powershell` 162 · `osquery` 67 · `aws cloudtrail` 55 · `wmi` 1. **385,6 reglas por logsource**. 515 reglas (16,7 %) son de plataformas no-Windows → nunca se evalúan |
| 3 | **El fallback por logsource ignora el `event_id`** (`RuleIndex.cs:128-136`) | Un evento Sysmon EID 22 (DNS) se evalúa contra las 1.531 reglas Sysmon, incluidas las de EID 1/3/7/8/10/11/13 |
| 4 | **210 reglas con `"enabled": false`** en el corpus (6,8 %) | Incluye `T1547_New_RUN_Key_Pointing_to_Suspicious_Folder` (la que caza la persistencia de c2-dect), `T1003_*` LSASS, `T1053_*`, `T1070_*`, `T1218_*` |
| 5 | **640 reglas con nodos `selection_list`** no deserializan (el mapa Sigma crudo `"Image\|endswith": [...]` no tiene propiedad) → `Field=null` → `Expression.Constant(false)` | Muertas silenciosamente |
| 6 | **144 reglas con `negation`** usan la clave `"item"` (singular); `RuleReader` sólo lee `"items"` → rama negada descartada → `AND false` | Muertas silenciosamente |
| 7 | **Unión: 958 / 3.085 = 31,1 % de reglas Sigma permanentemente muertas** (210 disabled + 640 selection_list + 144 negation + 176 árbol vacío). Sin un solo log | Cobertura real ≈ 2.127 |
| 8 | **MITRE enrichment: 19 técnicas hardcodeadas** (`MitreEnricher.cs:147-292`) - no existe `mitre_map.json` | El CLI imprime `(?)` en la mayoría de las detecciones |
| 9 | **IDs de sub-técnica con guion** (`T1003-001`) en vez de punto (`T1003.001`) | **14 de 404** IDs resuelven (3,5 %). 234 reglas usan el formato inválido |
| 10 | **`AlertFactory` no parsea `"isolate_host"`** (enum `IsolateHost`) | Se pierde **exactamente** la acción de aislamiento más importante |
| 11 | **`CorrelationEngine` no tiene estado** (`Correlate()` sólo ve el evento actual) | Las 7 correlaciones son intra-evento. **La cadena «proceso → persistencia → beacon» no es detectable.** `CORR_003` (T1570) y `CORR_004` (T1059.001) **nunca pueden dispararse** (IDs inexistentes en el catálogo) |
| 12 | **`RuleDeduplicator` revienta** con `InvalidOperationException` sobre el catálogo real (muta `group.Value` mientras la enumera, línea 57-72) | Y además es código muerto |
| 13 | **YARA: 5.490 / 5.934 (92,5 %) pierden sus guardas** (`uint16(0)`, `filesize`, `pe.exports()`) por el atajo `any of them` | Falsos positivos sistemáticos. 376 reglas nunca pueden ser verdaderas; 1.199 sin cadenas |
| 14 | **`YaraNativePool` (libyara real) es código muerto** | Todo el YARA en producción es emulado |
| 15 | **`case`/`endswith` con `string.Contains` es case-SENSITIVE** en la ruta compilada, mientras el path interpretado usa `OrdinalIgnoreCase` | Falsos negativos en las 1.181 ocurrencias de `endswith` |

### 3.7 Tests: pasan, pero no prueban detección

69/69 verdes. Pero:
- **`GoldenDatasetTests.cs` no es un golden dataset**: sin fixtures, sin corpus etiquetado, sin salida esperada. Construye un PE sintético y comprueba un método privado por reflexión. **1 control negativo, 0 detecciones positivas.**
- **`PipelineGateTests.F31_Channel_Backpressure_10k` asserta `10_000 == 10_000`** (tautología). **`F31_Yara_Confidence_Gate_085` no toca el gate real** (`Program.cs:483`).
- **`YaraNativeTests.F22` asserta `n > 5000` sobre el contador del *fallback JSON*** ⇒ **pasa igual con o sin libyara**. La integración nativa no se prueba en absoluto.
- **Ningún test end-to-end «evento malicioso ⇒ detección ⇒ técnica MITRE»**. Por eso el 31 % de reglas muertas, los FP por `re`, el crash del deduplicador y el crash de `ResponseAction` pasan CI en silencio.
- El core Rust: **0 tests, 0 benchmarks** (`cargo test -- --list` → «0 tests»).
- El agente Go: `internal/client` tiene tests; el resto «no test files».

### 3.8 Todo el "detection testing" es contra datos fabricados

| Artefacto | Volumen |
|---|---|
| `src/SentryGuard.Sources/scenarios.json` | 12 escenarios (9 ataque + 3 benigno), **todos fabricados**, todos con `channel: Microsoft-Windows-Sysmon/Operational`, `source: Sysmon` |
| `events.jsonl` | 12 líneas (9 plantillas repetidas) |
| `events-scan.jsonl` | 60 líneas (las mismas 12 plantillas) |
| `c2-dect-test.jsonl` | **5 líneas** - el «test contra c2-dect» del proyecto entero |
| `agents/go/internal/collector/demo.go` | generador `demo-collector-N` |

**77 líneas de JSONL escritas a mano. Cero eventos capturados de un sistema real.** El `winlog.channel` y el `winlog.event_id` que dirigen la detección los elige **el simulador**, no el sistema operativo (`ScenarioCatalog.cs:29-30` → `DetectionRunner.cs:35-37`).

Las 5 líneas de `c2-dect-test.jsonl` son 5Ian greys genéricos (PowerShell download cradle, `mimikatz.exe`, `reg add .../Run`, `rundll32 javascript:`, ScriptBlock 4104) - **no reflejan los artefactos reales del agente c2-dect** (`WinDefendUpdate`, `svchost.exe` en AppData, `c2-dect\data`, AES-GCM, UA Chrome/126).

---

## 4. MATRIZ DE COBERTURA: c2-dect → SentryGuard

| Técnica c2-dect | Implementación real | SentryGuard (código) | SentryGuard (producción) | Veredicto |
|---|---|---|---|---|
| **T1071.001 Beacon HTTP/HTTPS** | ✅ AES-GCM + ECDH, jitter `activity`, ECH, UA rotativa | `NetworkThreatDetector.DetectC2Communication` (umbral `variance < avg*0.1`) | 🔴 **Sin telemetría de red** | ❌ **Evadido por diseño**: el umbral sólo se cumple si `T < 0,3/j²`. Con jitter 20 % y T=60 s → invisible. Y sin telemetría de red, moot |
| **T1071.004 DNS C2** | ✅ `dead_drop/dns.rs` TXT + DoH + GitHub | `DetectDNSTunneling` (longitud >50, entropía >4, >50 TXT/5 min) | 🔴 Sin ETW DNS | ❌ La regla existe pero nunca se evalúa |
| **T1547.001 Run key HKCU → AppData** | ✅ `worm_deploy.go:126` | `MITRE99.CheckBootAutostartSubs` (**sólo HKLM**) | 🔴 La regla Sigma que lo cubre está `enabled=false` | ❌ **Fallo verificado empíricamente** |
| **T1543.003 Servicio `WinDefendUpdate`** | ✅ `sc create` | `T1543_New_Service_Creation_Using_Sc_EXE` | ⚠️ Detecta la creación, no el nombre malicioso | ⚠️ Parcial |
| **T1036.005 `svchost.exe` en AppData** | ✅ masquerading | `T1036_Suspicious_Process_Masquerading_As_SvcHost_EXE` | ✅ | ✅ **Detectado** |
| **T1548.002 UAC bypass fodhelper** | ✅ `ms-settings\Shell\Open\command` | `LivingOffTheLand` (strings) | 🔴 Sin cobertura de HKCU Classes | ❌ |
| **T1003.001 LSASS dump** | ✅ `comsvcs.dll!MiniDump` | `MITRE99` por nombre de proceso; `LivingOffTheLand` | 🔴 Reglas `T1003_*` de LSASS están **disabled** | ❌ |
| **T1558.003 Kerberoast** | ✅ `kerberoast.go` | `KerberosAdvancedDetector` (real, con estado) | 🔴 Proyecto `SentryGuard.Detection` **huérfano** | ❌ |
| **T1562.001 AMSI/ETW bypass** | ✅ patch en memoria | `AntiREDetector.CheckETWHooking` (sólo su propio proceso); `MITRE99` lee `amsi.dll` **en disco** (el byte 0 de una DLL es `0x4D` ⇒ imposible) | ❌ | ❌ **Estructuralmente incapaz** |
| **T1106 Syscalls directos** | ✅ blob Go con tabla cifrada | `APIUnhookingDetector` = switch sobre `evt.EventType` que nadie produce | ❌ | ❌ |
| **T1055.012 Process hollowing** | ✅ `ultra/hollowing` (real, aunque con args mal ordenados) | `FilelessMalwareDetector.DetectProcessHollowing` = tabla de 4 pares padre→hijo | ❌ | ❌ |
| **T1027 Sleep masking (ChaCha+NOACCESS)** | ✅ `sleepmask.go` | ❌ Ninguna regla Sigma lo cubre | ❌ | ❌ |
| **T1113 Captura de pantalla** | ✅ `screenshot.go` | - | ❌ | ❌ |
| **T1056 / T1115 Keylogger** | ✅ hilo `GetAsyncKeyState` → `c2-dect\data\keylogs\keylog.txt` | - | 🔴 Sin telemetría de ficheros | ❌ |
| **T1486 Ransomware** | ✅ AES-256-GCM real (lab-gated) | Sigma T1486 (18) + YARA T1486 (28) | ✅ **la mejor cobertura relativa** | ✅ *(relativo)* |
| **T1490 Shadow copy deletion** | ⚠️ No implementado en c2-dect | `ImpairDefensesDetector` - grep `vssadmin`/`shadowcopy` → **0** | ❌ | ❌ |
| **T1562.004 Firewall disable** | - | `ImpairDefensesDetector` sólo matchea el literal exacto `netsh advfirewall set allprofiles state off` | ⚠️ | ⚠️ Literal, no semántico |
| **T1570 / T1021 Movimiento lateral** | ✅ WMI/PsExec/WinRM/DCOM/BITS/RDP/SMB relay | `LivingOffTheLand.DetectLateralMovement` (el mejor) | ⚠️ | ⚠️ |
| **T1583 / T1071 Red infra** | ✅ redirector con cloaking JA4/GeoIP/ASN | `NetworkThreatDetector` (sin JA3/JA4, sin SNI, sin cert) | 🔴 | ❌ |
| **T1555 DPAPI key custody** | ✅ `CryptProtectData` | - | ❌ | ❌ |

**Resultado agregado: de 20 técnicas representativas, SentryGuard detecta 1 de forma fiable, 4 parcialmente, y 0 en producción.**

---

## 5. PLAN DE ACCIÓN

### 5.1 SentryGuard - P0 (sin esto no hay EDR) - ~2 semanas

| # | Acción | Esfuerzo |
|---|---|---|
| 1 | **Fuente ETW en user-mode** (`Microsoft-Windows-Kernel-Process`, `-File`, `-Network`, `-PowerShell`, `-DNS-Client`) + fuente Sysmon/Event Log. Registrarla en `EventSourceFactory`. **Resuelve de golpe el 80 % de las brechas de telemetría sin firmar un driver** | M |
| 2 | **Cablear los detectores al pipeline** (`DetectionRunner.Run` → despachar a `SentryGuard.Detection`) **o borrarlos**. Hoy son 15.500 líneas que nunca se ejecutan y dan falsa impresión de cobertura | M |
| 3 | **Arreglar los 5 bugs del motor**: `\|re`/`cidr`/`fieldref` → error explícito por regla (no degradar a «el campo existe»); `selection_list` y `negation.item` en el modelo; `RuleIndex` por `event_id` sin el fallback por logsource; `enabled=false` → reevaluar el corpus; normalizar IDs MITRE a `.` y generar `mitre_map.json` real | M |
| 4 | **Conectar `YaraNativePool` + `YaraCache`** (o borrar el emulador). Salto de 1,4 ev/s a decenas. Y corregir las guardas descartadas (92,5 %) | M |
| 5 | **Canal de respuesta servidor→agente**: tabla de tareas + `tasks` reales en `checkin` + agente que las ejecute | M |
| 6 | **Ejecutores de respuesta reales**: firewall de Windows para aislamiento, kill por PID, cuarentena con hash, bloqueo de IP/dominio. Y arreglar `AlertFactory` para que `isolate_host` parsee | M |
| 7 | **Secretos**: eliminar los defaults que pasan el guard fail-closed (`.env.example`, `docker-compose.yml`), exigir `Agents__RegistrationKey` aleatorio, `Seed__EnableTotp=true` por defecto con entrega del secreto TOTP, y **RBAC de verdad** (`RequireRole` en las acciones sensibles) | S |
| 8 | **TLS en el plano de control** + `RequireAuthorization()` en `checkin` + `FORCE ROW LEVEL SECURITY` + `SET LOCAL app.tenant_id` por request | S |

### 5.2 SentryGuard - P1 (operación y honestidad) - ~1 mes

- **Capturar telemetría real** de un Windows de pruebas con Sysmon/ETW y sustituir `events-scan.jsonl` por una captura auténtica. Es el cambio con mayor retorno de credibilidad por hora de trabajo.
- **Etiquetar el modo demo** (`IsSynthetic = true`) y propagarlo al payload de ingestión: hoy un `mimikatz.exe` simulado es indistinguible de uno real en la BD.
- **SLO real**: alimentar el `ThreatPulse` desde el servidor; corregir el formato de histogramas Prometheus; añadir OTLP.
- **Spool a disco** en ambos agentes (pérdida total de telemetría si el servidor cae 30 s).
- **Golden dataset real**: ≥200 eventos etiquetados (benignos + c2-dect real) con alertas esperadas + test que detecte reglas muertas.
- **Métricas de motor**: `rules_loaded`, `rules_dead`, `rules_skipped`, `matches_by_category`, `yara_scan_ms`; que toda regla muerta sea visible al arrancar.
- **Driver**: crear `.vcxproj`/`.inf` + paso WDK en CI + corregir los 3 bugs de protocolo, o **moverlo a `experimental/`**. Mantenerlo como está (aparentando capacidad) es la peor de las dos opciones.
- **Limpiar el catálogo**: borrar `Rules/JSON` (duplicado obsoleto) y `Rules/yara_json.bak-*` (5.934 reglas viejas), y validar `RulesBasePath` al arrancar (hoy `--rules ...\Rules` cargaría 11.868 YARA, la mitad obsoleta, + 5.934 JSON-YARA reinterpretados como Sigma en silencio).
- **Arreglar o declarar muerto `CanaryRollback`** (si se conecta hoy, corrompe el sistema) y **`SelfProtectionHardening`**.
- **Deploy**: el `Dockerfile` está roto (falta `SentryGuard.Metrics` en el contexto de build ⇒ `dotnet restore` falla) y el chart Helm no arranca (sin `Jwt__Key`/`Agents__RegistrationKey`, Secret de Postgres inexistente). CI sin SAST/dependencias/secretos/firma/SBOM.
- **Corregir la documentación**: ≥20 afirmaciones materiales en `docs/` son falsas (RBAC, mTLS, OTLP, SLO, threat-intel scoring, `health/ready`, refresh-reuse, filtros de `status`).

### 5.3 c2-dect - P0 (credibilidad y responsabilidad) - ~1 mes

| # | Acción |
|---|---|
| 1 | **Tipar todos los "éxitos" simulados**: `orchestrator_tool` (3 sitios), `privesc_auto`, `socks_proxy.double_pivot`, `infra-svc /destroy`, `pth.rs`, `lsass`/`sam` creds. Devolver `simulated: true` / `not_implemented` y verificarlo en CI. **Es el mayor riesgo del proyecto**: un operador cree que ha tirado credenciales. |
| 2 | **Cerrar `webexploits` y `discovery` con la misma política firmada Ed25519 + allowlist de objetivo que `ddos-dect`**. La asimetría actual (el módulo más peligroso está gateado, el que ejecuta RCE/SSRF contra terceros no) es indefendible |
| 3 | **Sustituir el secreto TCP hardcodeado** `c2-dect-dev-secret-change-me` y hacer `SQLCIPHER_KEY` **obligatoria fail-closed** (como ya se hace con `C2_MTLS_CA`) con KDF Argon2id + salt. Hoy hay claves ECDH/AES de implantes reales en claro en `build/c2-dect.db` |
| 4 | **Mover el token JWT del WebSocket** de la query string a cookie `HttpOnly; Secure; SameSite=Strict` (hoy se filtra a `gin.log`) |
| 5 | **Autenticar el primer beacon**: hoy el único modo funcional es cleartext sin auth. Handshake con token pre-compartido o pubkey ECDSA del agente |
| 6 | **Implementar el despliegue real del payload del gusano** (`propagation/deployer.rs` ejecuta `"echo test"`) y su **beacon de reporting** (`propagation/worm.rs` nunca invoca `HttpsBeacon`) |
| 7 | **Cablear `killswitch.rs` (dataplane) y `Broadcaster.Broadcast`**, y reemplazar ACME DNS-01 y el insert a ClickHouse por implementaciones reales |
| 8 | **Mover `cloaking::eval` al hot path** del redirector (hoy la sophistication de GeoIP/ASN/JA4 es publicidad, no capacidad) |
| 9 | **Cifrar/TTL los reportes de recon** y **purgar los 2 reportes reales commiteados** (`recon_DESKTOP-S4SRNHT_*.json`, `scan_log.txt` con hostname `UCATEPALC101_14` y la ruta de otro operador) |
| 10 | **Unificar los dos kill-switch** (`tools/gate/kill_switch.py` con Postgres/Redis y `tools/gate/impact_policy.py` con Ed25519) en un único interruptor que cubra también la capa de cifrado |
| 11 | **Hacer obligatorio el `.lab-allow`** en `lateral-emu` (ahora se lo salta: *«en modo simulación no exigimos el marcador»*) y mover la auditoría fuera del lab (hoy `audit.jsonl` vive junto a la acción) |
| 12 | **Rotar el `AGENT-EXEC`** a token de un solo uso ligado a tarea/operador/sesión, y validar `args` |
| 13 | **Corregir el catálogo**: `Grade: "real"` en 9 familias de `webexploits` que son heurística/stub; `xxe.Exploit` etiquetado «REAL» cuando devuelve «compat stub»; «las 26 funciones hacen peticiones HTTP REALES» cuando son 4 |

### 5.4 c2-dect - P1 (madurez ofensiva) - ~3 meses

- Implementar BOF real (o borrarlo del árbol); exponer `HollowProcess` y `InjectReflectiveDLL` en el switch del agente; ADS; pivoting SMB por named pipes; exfiltración real por canal; Startup folder / IFEO / AppInit_DLLs; Kerberoast + DCSync en `lateral-rust`; SSH lateral; canales C2 no-HTTP (DNS/WS/SMB); drenaje de ruido y prefijo de ruta configurable.
- Compilar `ultra/` y `pic-asm/` o moverlos a `experimental/` (hoy `signature-evasion/README.md` documenta un `core/src/evasion_core.c` **que no existe**).
- Fijar `go vet`/`golangci-lint` y `cargo clippy` en CI para los árboles hoy rotos.
- Retirar el prefijo `/agent` fijo de las rutas (o hacerlo configurable) y añadir UA/JA3 versiones actualizadas.
- Compilar el implante con `-s -w` (hoy no se.strip-ean los símbolos Go ⇒ firma trivial de compilador) y dejar de hornear `-X main.defaultServer=<C2>` **en claro** en el binario.

---

## 6. RESUMEN EJECUTIVO FINAL

**c2-dect** es dos proyectos superpuestos: (1) un **arsenal ofensivo real** en `cmd/agent_go/` y `modules/lateral-rust/` -Kerberoast, DCSync, forja de tickets, WMI/PsExec/WinRM/DCOM/BITS/RDP, SMB relay, LSASS/SAM/DPAPI, UAC bypass, AMSI/ETW/unhooking, sleepmask, pivot SOCKS5, ransomware- y (2) un **simulador defensivo maduro y criptográficamente serio** (ransomware-sim, worm-sim, phishingstrike en su parte de gobernanza, reconocimiento-c2). Su riesgo principal no es lo que hace sino **lo que dice que hace**: 5 superficies devuelven éxito falso y 2 devuelven credenciales de prueba.

**SentryGuard-0.0.1** tiene un motor de reglas real (3.085 Sigma + 5.934 YARA, correlación, enriquecimiento MITRE, telemetría, métricas) pero **no tiene plataforma**: la telemetría es sintética, el driver no compila y no está cableado, el protocolo IOCTL está roto, los 26 ficheros de detectores avanzados son código muerto, la correlación no tiene estado, la acción de aislamiento no parsea, el SLO nunca puede breachar, no hay RBAC, no hay TLS, los secretos por defecto pasan el guard fail-closed, y el 31 % de las reglas Sigma está muerta en silencio. **Contra un c2-dect real: no lo vería, y si lo viera no podría hacer nada.** El panel que se observa está lleno con las 350 detecciones que el propio servidor siembra (`DbInitializer.cs:92-117`) - lo que además crea una **falsa sensación de cobertura**.

**Los dos proyectos miden honestamente lo que no hacen** (c2-dect con `probe_capabilities.py`; SentryGuard con `scorer.py` que se niega a fabricar un 100). El problema es que esa honestidad es **por componentes**, no **por producto**: cada componente sabe lo que es, pero el ensamblaje afirma capacidades que ningún camino de ejecución sostiene.

---

*Fin del informe. Ningún fichero de `c2-dect` ni de `SentryGuard-0.0.1` fue modificado.*
