# Auditoria Defensiva y Ofensiva - Two Projects

Proyectos:
- SentryGuard-curado (defensivo)
- c2-dect (ofensivo C2 + herramientas)

Metodo: revision estatica de codigo fuente, grep de secretos/patrones peligrosos, y analisis de configuracion. No se modifico codigo fuente.

## SentryGuard-curado (defensivo) - hallazgos

### Criticos
1. Cluster auth bypass por header: `src/SentryGuard.Server/api/clusterhandler.go:39-44`; `X-Forwarded-By` omite validacion del secreto cluster.
2. SAML sin verificacion de firma XML-DSig: `src/SentryGuard.Server/auth/saml.go:197-222`; aserciones forjadas aceptadas.
3. Secreto cluster por query string: `src/SentryGuard.Server/api/clusterhandler.go:36-38`; fuga en logs/historiales.

### Altos
4. Operador password en texto plano en implementacion generica DB: `src/SentryGuard.Server/db/database.go:129-135`.
5. Fallback a API key conocida `devkey`: `src/SentryGuard.Orchestrator/Program.cs:19`, `src/SentryGuard.V3.Listener/Program.cs:11`.
6. Command injection en NetworkIsolator: `src/SentryGuard.Modules/Responder/NetworkIsolator.cs:422-439` ejecuta `cmd.exe /c {command}` sin sanitizar.

### Medios / Bajos
7. Downgrade silencioso a HTTP si faltan certs TLS: `src/SentryGuard.Server/cmd/main.go:315-318`.
8. SignalR hubs sin `[Authorize]`: `src/SentryGuard.API/Hubs/MetricsHub.cs:6` (y similares).
9. CSP debilitado con `unsafe-inline`/`unsafe-eval`: `src/SentryGuard.Server/api/middleware.go:168`.
10. RNG predecible por timestamp: `src/SentryGuard.Server/api/middleware.go:348-351`.
11. WebSocket acepta cualquier Origin: `src/SentryGuard.ExecutiveDashboard/main.go:116`.

## c2-dect (ofensivo) - hallazgos

### Criticos
1. Secretos reales/produccion en `.env`: `REDIS_PASSWORD`, `JWT_SECRET`, `WEAPONIZE_TOKEN` committed en disco y no ignorados operativamente por despliegue local.

### Altos
2. Agente acepta scripts sin firma por defecto: `cmd/agent_go/scripting_lua.go:104-111`, `cmd/agent_go/scripting_sign.go:19-21`.
3. Gaps de aislamiento multi-tenant: `server/api/handlers.go:998`, `server/api/handlers.go:1070-1082`, `server/api/workspace.go:70`, fallback tenant 1 en `server/api/handlers.go:909-922`.

### Medios
4. TLS/mTLS debiles: `--http`, cert autofirmado por defecto, allowlist vacio: `server/cmd/main.go:164`, `server/cmd/mtls.go:53-55`.
5. Ejecucion de modulos Python con args combinados: `server/api/exploits_handlers.go:287`, entrada `req.Start` en `server/api/handlers.go:1466-1471`.
6. Backup expone material de claves de sesion en payload descifrable/backup: `server/db/backup.go:167-177`.
7. File manager del agente sin contencion de ruta: `cmd/agent_go/filemanager.go:61-96`.

### Bajos
8. Allowlist mTLS por defecto vacio (legado); endurecer por defecto.

## Recomendaciones prioritarias
- Rotar inmediatamente cualquier secreto expuesto y eliminarlos de repo + historial.
- Implementar verificacion criptografica SAML/XML-DSig y secret rotation.
- Endurecer cluster auth: secreto obligatorio, no query string, no bypass por X-Forwarded-By.
- Enforce tenant access antes de mutaciones; token siempre con tenant.
- Ejecucion de agentes/scripts solo firmados y en modo estricto.
- TLS 1.3 obligatorio, mTLS con allowlist no vacia, no HTTP legacy.
- Contencion de rutas del file manager y validacion de argumentos en modulos.
- Backups con KDF fuerte, passphrase minima elevada y gobernanza de restore.

## Nota
Los agentes no modificaron archivos. El alcance es estatico; se recomienda seguir con pruebas dinamicas/fuzzing e inventario de dependencias.
