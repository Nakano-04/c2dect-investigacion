# Auditoria Ofensiva - c2-dect (actualizacion 2026-10-30)

**Objetivo:** `C:\Users\USER1\Desktop\test\cs2\c2-dect` (framework C2 / simulacion de adversarios Red Team).
**Metodo:** revision estatica de codigo fuente (Go, Rust, C#, Python). No se ejecutaron payloads, no se lanzo fuzzing contra objetivos vivos y no se modifico codigo fuente.
**Referencia previa:** `AUDITORIA_OFENSIVA_c2-dect.md` (2025-01-18, 5 vectores) y `AUDIT_REPORT.md` (auditoria defensiva de codigo).
**Estado del codigo al analisis:** post-remediacion del changelog 2026-10-18 (7 puntos críticos) y release v3.5.1-beta / v3.6.0.

---

## 1. Resumen ejecutivo

C2-DECT es una plataforma de simulacion de adversarios de extremo a extremo (acceso inicial, exploits, post-explotacion, movimiento lateral, beaconing C2) para laboratorios de Red Team y equipos azules. El propio README declara que **ningun modulo es PRODUCTION-READY** y clasifica componentes como STUB / WIP / CHECK-ONLY / SIMULADO.

**Hallazgo principal:** los hallazgos CRITICOS y ALTOS de la auditoria ofensiva previa (2025) estan **remediados en su mayor parte** en el codigo actual:

| Hallazgo previo (2025) | Estado actual | Evidencia en codigo |
|---|---|---|
| IDOR / tenant bypass en sesiones, workspaces, file download | Remediado | `server/api/handlers.go:1070-1496` (`requireSessionAccess` en todas las mutaciones de sesion); `server/api/workspace.go:72` |
| Borrado global de sesiones sin rol admin | Remediado | `handlers.go:158` (`requireRole("admin")` en `DELETE /api/sessions`) |
| Inyeccion de argumentos en modulos Python (`strings.Fields`) | Remediado | `server/api/exploits_handlers.go:405-458` (`runPythonModuleArgs` argv + `validCVEID`/`validFilePath`/`validKeyword`) |
| Scripts Lua/WASM sin firma por defecto | Remediado | `cmd/agent_go/scripting_sign.go:67-107` (`rejectOpenLab`/`verifyScriptSource`, `C2_SCRIPT_ALLOW_UNSIGNED=1` para lab) |
| File manager sin sandbox (traversal) | Remediado | `cmd/agent_go/filemanager.go:11-175` (`validatePath` en todas las operaciones FS) |
| mTLS allowlist vacia / cualquier cert CA | Remediado | `server/cmd/mtls.go:54-55,81` (fail-closed si allowlist vacia; `C2_ALLOW_NO_MTLS_ALLOWLIST=1` solo lab) |
| Puerto C2 expuesto en `0.0.0.0` | Remediado | `server/cmd/main.go:30` (`defaultAddr = "127.0.0.1:8443"`) |
| HTTP plano (`--http`) por defecto | Remediado | `server/cmd/main.go:175-177` (requiere `C2_ALLOW_HTTP=1`) |
| Cert autofirmado por defecto sin restriccion | Remediado | `server/cmd/main.go:238-242` (requiere `C2_ALLOW_SELF_SIGNED=1`) |
| Backup expone claves de sesion | Remediado | `server/db/backup.go:32-34` (claves ECDH/AES excluidas); passphrase minima 20 (`backup.go:58-59`) |
| Secrets hardcodeados | Parcial | `cmd/server/main.go:29-31` lee `C2_FRAME_SECRET` con fallback dev-explícito |

**Riesgo residual principal:** el framework conserva "escape hatches" de modo laboratorio (variables de entorno que desactivan controles de seguridad) y modulos ofensivos clasificados como STUB / CHECK-ONLY que, si se activan fuera del ambito de laboratorio, constituyen superficie ofensiva real.

---

## 2. Vectores de ataque revisados (estado actual)

### Vector 1 - Server API: IDOR, tenant bypass y mutation de sesiones
**Estado: controlado (bajo riesgo en scope declarado; medio si se desactiva TenancyEnforced).**

- `requireSessionAccess()` se aplica a tag, sleep, file download, workspace, loot, campaign y activity (`handlers.go:1072,1127,1136,1166,1213,1269,1333,1347,1364,1417,1437,1496`). Sesiones de otro tenant responden 404 (no oracular).
- `callerTenantID()` retorna `0` (no `1`) cuando falta tenant; el fallback legacy a tenant 1 se elimino.
- `allow_impact_modules` por tenant con default `FALSE` (fail-checked): worm deploy, worm beacon, worm task, worm result responden 403 `capability_denied` sin el flag (`handlers.go:1818-1825,1969-1971,2006-2008,2037-2039`).
- Kill-all global requiere approval single-use (`killswitch.go:39`, `handlers.go:161`).

**Residual:** `GET /api/tenants` solo requiere autenticacion (inventario de tenants visible a operadores autenticados); `TenancyEnforced()` default 1 pero desactivable para modo lab legacy.

### Vector 2 - Inyeccion de comandos/argumentos (modulos Python)
**Estado: remediado (bajo riesgo).**

- `runPythonModuleArgs(module, args...)` ejecuta con `exec.Command` argv separado, sin `strings.Fields` sobre entrada de usuario (`exploits_handlers.go:405`).
- Validacion estricta aplicada en `/exploits/generate`, `/validate`, `/search`, `/analyze`: `validCVEID` (`CVE-YYYY-NNNN`), `validFilePath` (relativo, sin traversal, sin metacaracteres shell), `validKeyword` (alfanumerico + `- . _` espacios) (`exploits_handlers.go:413-470`).

### Vector 3 - Agente: RCE, file manager, persistencia, scripting
**Estado: controles presentes; superficie intencionalmente ofensiva (capacidades de agente).**

- Ejecucion directa `shell`/`exec` (`cmd.exe /C`, `sh -c`) sigue siendo una capacidad declarada del agente (`main.go:1509`, Fase 2 scripting). Es funcional por diseno en C2; el riesgo se gestiona con alcance de laboratorio y kill-date.
- File manager con `validatePath()` jaula `readFile/writeFile/copyFile/deleteFile/moveFile/getFileInfo/createDirectory/listFiles/searchFiles` dentro de `getDataDir()` y bloquea `..` (`filemanager.go:11-175`).
- Scripting Lua/WASM: firmas Ed25519 fail-closed; `c2.exec`, `c2.fs.*`, `c2.download/upload` solo en modo estricto con `C2_SCRIPT_PUBKEY`; `C2_SCRIPT_ALLOW_UNSIGNED=1` abre modo lab (`scripting_sign.go:63-74`, `scripting_lua.go:273-352`).
- Persistencia (servicio, registro, tarea programada), UAC bypass (fodhelper), self-delete, steal de tokens: capacidades ofensivas del agente, sin cambios estructurales desde la auditoria previa.

### Vector 4 - Transporte: TLS / mTLS / listener
**Estado: remediado por defecto; escape hatches de laboratorio.**

- Listener por defecto `127.0.0.1:8443` (`server/cmd/main.go:30`). Antes era `0.0.0.0:8443` (server antiguo) / `0.0.0.0:443` (`cmd/server/main.go:20` - revisar: este mantiene `0.0.0.0:443`, ver nota abajo).
- `--http` (TLS deshabilitado) requiere `C2_ALLOW_HTTP=1` (`main.go:175-177`).
- Cert autofirmado solo con `C2_ALLOW_SELF_SIGNED=1` (`main.go:238-242`).
- mTLS cliente fail-closed: cert+key o ninguno (`cmd/agent_go/mtls.go:11`); servidor rechaza allowlist vacia salvo `C2_ALLOW_NO_MTLS_ALLOWLIST=1` (`server/cmd/mtls.go:54-55`).
- TLS 1.3 minimo en servidor y agente.

**Nota:** `cmd/server/main.go:20` mantiene `defaultAddr = "0.0.0.0:443"` (binario servidor legado distinto de `server/cmd/main.go`). Verificar cual se despliega en produccion.

### Vector 5 - Backup, JWT y extraccion de claves
**Estado: remediado (medio-residual).**

- Backup AES-256-GCM + HKDF, passphrase minima 20 caracteres (`backup.go:58-59`).
- `backupOperator` sin `PassHash`; `backupSession` excluye key material de sesion; SQL excluye columnas privadas/AES (`backup.go:23-34,167-181` previas, ahora excluidas por diseno).
- JWT: HS256, access 15 min, refresh 24h, key version enforcement, audience validation. `C2_FRAME_SECRET` por env var con fallback dev `"c2-dect-dev-secret-change-me"` (`cmd/server/main.go:29-31`).

---

## 3. Escape hatches de modo laboratorio (residuos de endurecimiento)

Las siguientes variables/flags desactivan controles de seguridad y están documentadas como "lab only", pero siguen presentes en codigo:

| Escape hatch | Efecto | Archivo |
|---|---|---|
| `C2_ALLOW_HTTP=1` | Habilita listener HTTP plano (sin TLS) | `server/cmd/main.go:175-177` |
| `C2_ALLOW_SELF_SIGNED=1` | Permite cert autofirmado sin pinning | `server/cmd/main.go:238-242` |
| `C2_ALLOW_NO_MTLS_ALLOWLIST=1` | Desactiva allowlist mTLS (cualquier cert CA) | `server/cmd/mtls.go:54` |
| `C2_ALLOW_NO_MTLS=1` | Desactiva mTLS por completo | `server/cmd/main.go:153` |
| `C2_SCRIPT_ALLOW_UNSIGNED=1` | Acepta scripts Lua/WASM sin firma Ed25519 | `cmd/agent_go/scripting_sign.go:71` |
| `C2_FRAME_SECRET` fallback | `"c2-dect-dev-secret-change-me"` si no se define env | `cmd/server/main.go:30-31` |
| Claves privadas commiteadas | `build/server.key`, `server/server.key` (test) | disco del repositorio |

**Impacto:** un operador que despliegue con estas variables expone el C2 a interceptacion, suplantacion de beacon y ejecucion de scripts no firmados.

---

## 4. Cadenas de ataque minimas (estaticas, teoricas)

1. **Cadena servidor (tenant):** operador autenticado -> `TenancyEnforced` desactivado o tenant 1 legacy -> mutacion/borrado cross-tenant de sesiones -> plantado de payload via modulo. (Controlado: `requireSessionAccess` + `callerTenantID=0`.)
2. **Cadena agente (scripting):** tarea del operador -> script Lua/WASM sin firma si `C2_SCRIPT_ALLOW_UNSIGNED=1` -> `c2.exec`/`c2.fs.*` arbitrario -> persistencia (servicio/registro) -> relaunch con privilegios. (Controlado: firmas fail-closed por defecto.)
3. **Cadena MITM (transporte):** `--http` o cert autofirmado sin pinning -> interception/modificacion del beacon y bootstrapping ECDH. (Controlado por defecto: TLS 1.3 + `127.0.0.1` + mTLS fail-closed.)
4. **Cadena backup:** robo de `.env`/backup + passphrase -> descifrado de backup -> extracción de metadatos de operador/sesion. (Controlado: passphrase minima 20, claves de sesion excluidas; residual: sin firma digital del backup, solo hash chain.)

---

## 5. Inventario de modulos ofensivos y su madurez

Según `modules/offensive_modules.go`, `server/api/module_catalog.go` y `MODULOS_INVENTARIO.json`, los modulos ofensivos declarados incluyen: discovery, collection, creds, webexploits (9 subpaquetes, 26 funciones), ddos-dect, dect-sql, lateral-rust (15× STUB), privesc-auto, ransomware-sim, worm-sim, kernel-real/sim, adversary-sim, socks-proxy, trust, delivery, phishingstrike.

- **Exploits reales:** CHECK-ONLY / SIMULADO; sin RCE validado en lab (Fase 6).
- **Movimiento lateral:** 15× STUB en `modules/lateral-rust/` (Fase 7).
- **Evasión de firmas:** WIP, sin validación AV citada (Fase 11).
- **Polimorfismo/hollowing/ETW/AMSI:** STUB (Fases 4, 12, 29-36).

**Implicación ofensiva:** la mayoría de capacidades "reales" no existen como tal; sin embargo, el framework integra agentes con capacidades de shell, file system, persistencia y scripting que sí son operables en entorno de laboratorio.

---

## 6. Recomendaciones de hardening (priorizadas)

### Alta
1. Eliminar fallback hardcodeado `c2-dect-dev-secret-change-me`; fallar si `C2_FRAME_SECRET` no está definida en producción.
2. Rotar y eliminar del repositorio (y del historial de Git) cualquier certificado/clave privada commiteada (`build/server.key`, `server/server.key`, `c2-dect.db`).
3. Revisar `cmd/server/main.go:20` (`0.0.0.0:443`) vs `server/cmd/main.go:30` (`127.0.0.1:8443`): unificar el bind por defecto a loopback en binarios de servidor.
4. Hacer los escape hatches de laboratorio opt-in explícitos en tiempo de arranque (mensaje de advertencia visible, no solo variable de entorno silenciosa).

### Media
5. Añadir firma digital (Ed25519) al payload de backup, no solo hash chain.
6. Tests cross-tenant en CI automática (actualmente solo en `ci-interactive.yml`, manual/acotado).
7. CI completa para C/C++, Go de raiz y Android (hoy 0 % en `ci.yml`).
8. SBOM por release y `govulncheck` en pipeline automático.

### Baja
9. Documentar `kill-date`, sleep obfuscation y syscall indirectos en README (pendiente desde AUDIT_REPORT.md).
10. Migrar `Newtonsoft.Json` a `System.Text.Json` en GUI; añadir `Flask` a `requirements.txt` de exploits Python.

---

## 7. Limitaciones y uso autorizado

- Este informe es una **revisión estática de código**; no sustituye pruebas dinámicas, fuzzing ni pruebas de intrusión contra objetivos autorizados.
- C2-DECT debe usarse **únicamente en laboratorio con alcance declarado y autorización escrita vigente**, contra activos propios o bajo contrato de pruebas de seguridad. El uso contra activos de terceros sin autorización es ilegal.
- El proyecto declara explícitamente que no es production-ready; ninguna capacidad STUB/WIP/CHECK-ONLY debe considerarse operativa fuera del laboratorio.

---

**Archivos de consulta en el repositorio:** `README.md`, `ROADMAP.md`, `TECH_DEBT.md`, `THREAT_MODEL.md`, `docs/AUDITORIA-CODIGO.md`, `docs/CODIGO-FUENTE.md`, `server/api/exploits_handlers.go`, `server/cmd/main.go`, `server/cmd/mtls.go`, `cmd/agent_go/filemanager.go`, `cmd/agent_go/scripting_sign.go`, `server/db/backup.go`.

**Fin del informe.**
