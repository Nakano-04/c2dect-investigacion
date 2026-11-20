# Auditoria Ofensiva - c2-dect

Alcance: analisis estatico de servidor Go, agente Go, scripting, TLS/backup y configuracion. No se ejecutaron payloads destructivos ni se modifico codigo fuente.

## Vector 1 - Server API / IDOR y tenant bypass
- Cross-tenant mutacion de sesiones: `server/api/handlers.go:998-1012` (`handleTagSession`) no ejecuta `requireSessionAccess`; `handlers.go:1070-1083` (`handleSetSleep`) cambia `sleep` antes del chequeo tenant; `handlers.go:1241-1255` (`handleFileDownload`) encarga descarga para cualquier session id; `server/api/workspace.go:70-93` (`handleSetWorkspace`) sobreescribe workspace sin owner check.
- Exterminio global de sesiones: `handlers.go:1342-1349`; no requiere rol admin.
- Tenant inventory disclosure: `server/api/multitenancy.go:41,85-88`; `GET /api/tenants` solo auth.
- Audit log cross-tenant leak: `handlers.go:1390-1410`.
- Creacion/modificacion de users sin ownership: `multitenancy.go:345-362,375-379`; `handleTOTPDisable` permite desactivar MFA de cualquier usuario.
- Legacy JWT fallback: `handlers.go:906-923` defaultea tenant 1 cuando falta `tid`.

## Vector 2 - Command/argument injection
- `exploits_handlers.go:168-173,193,271`; `runPythonModuleRaw` en `exploits_handlers.go:287-291` usa `strings.Fields`, por lo que `req.CVEID`, `req.FilePath`, `req.Start`, `req.TargetSubnet` pueden inyectar banderas/args del modulo Python (`handlers.go:1466-1470,1529-1535`).

## Vector 3 - Agent RCE y file chaining
- Ejecucion directa:
  - `shell`/`exec`: `cmd.exe /C`, `sh -c`: `main.go:643-655`, `main.go:1050-1055`, `evasion.go:93-112`.
- File manager sin sandbox:
  - `readFile`, `writeFile`, `copyFile` rutas arbitrarias: `filemanager.go:61-125`, `main.go:751-792`.
  - `upload` y `download` permiten plantar y exfiltrar: `main.go:730-768`.
  - Lua/WASM replica FS y `c2.exec`: `scripting_lua.go:646-687`, `scripting_wasmrt.go:241-263,394-408`, `scripting_lua.go:576-602`.
- Persistence:
  - `installservice` `binPath` arbitrario: `main.go:1118-1131`, `capabilities.go:613-617`.
  - `persistreg`, `persisttask`, `worm`: `worm_deploy.go:91-142`.
- Privilege escalation:
  - MSI / UAC / token theft: `privesc.go:20,24,64-73,247-304`, `capabilities.go:647-733`.
- `wormDeploy` escribe binario recibido como `System32\svchost.exe` e instala servicio `WinDefendUpdate`.
- Unsigned modules accepted by default: `scripting_sign.go:51-71`, `scripting_lua.go:271-288`.

## Vector 4 - Transporte / TLS / mTLS
- Self-signed default cert sin trust pinning y `--http`: `main.go:211-218,332-389`.
- Private key por defecto commiteada en disco: `build/server.key`, `server/server.key`.
- mTLS allowlist vacia => cualquier cert firmado por CA: `mtls.go:53-55`, `main.go:293-307`.

## Vector 5 - Backup y JWT/key extraction
- Backups usan AES-256-GCM + HKDF rapido con min 12 chars e incluyen claves privadas/AES y hashes operador: `backup.go:68-93,167-181`, `crypto.go:59-77`.
- Legacy JWT aceptado (`KeyVersion==0`, audiencia solo si presente); secrets debiles en `.env` (JWT_SECRET/WEAPONIZE_TOKEN).
- Checkin sin auth: `handlers.go:565-637`; beacons default tenant 1.

## Minimal chains
Chain server: JWT valido de operador -> omision tenant -> mutacion o borrado cross-tenant -> plantado/XOR de payload via modulo.
Chain agent: operator envia tarea -> si pubkey unset, Lua unsigned -> `c2.exec` -> FS arbitrary -> service/worm persistence -> relaunch SYSTEM.
Chain MITM: cert default/self-signed + `--http` permiten interceptar y capturar o modificar beacon/bootstrapping ECDH.
Chain backup: roba `.env`/backup + passphrase -> deriva keys -> descifra backup y restores -> extrae claves privadas de sesion.

## Hardening
- Añadir `requireSessionAccess` y checks admin/tenant de forma central en agent-plane y API.
- Eliminar default secrets; reject tokens sin `tid`/key_version.
- Pasar argumentos como argv slices + validacion estricta.
- Path sandbox real para file manager y bridges (root + `filepath.Clean` + allowlist).
- Forzar firmas de scripts, `C2_SCRIPT_STRICT=1`, verifier real.
- TLS 1.3 obligatorio, sin `--http`, cert pinning/CA allowlist nonempty.
- Backups con passphrase min 20 + Argon2id y cifrado/restauracion gobernada.
- Rate limiting real con IP spoof protections (no wildcard TrustedProxies).

No se modifico codigo fuente.
