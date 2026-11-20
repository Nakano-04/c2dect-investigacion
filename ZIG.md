# Ejecutable Zig — `verify_manifest_zig`

Verificador de integridad del contenido del repo, escrito en Zig 0.17.1 sin
dependencias externas. Comprueba los SHA256 declarados en `artifacts.sha256`.

```powershell
zig build
zig build test
.\zig-out\bin\verify_manifest_zig.exe artifacts.sha256
```

El binario es independiente y no necesita Python. La versión Python
(`verify_manifest.py`) queda como referencia legible; ambas implementan el
mismo contrato.

## Segundo ejecutable: `opsec_zig`

Puntuación de observabilidad por técnica (capa ofensiva medida):

```powershell
.\zig-out\bin\opsec_zig.exe fixtures\tecnicas.json
```

Lee el mismo `fixtures/tecnicas.json` que `opsec_score.py` y emite una tabla
de observabilidad por técnica. Es una herramienta de priorización defensiva,
no de evasión.
