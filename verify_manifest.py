"""Prototipo extendido: verificacion de integridad del contenido del repo.

No depende de C2-DECT. Comprueba los hashes declarados en `artifacts.sha256`,
informa de archivos faltantes o modificados y puede regenerar el manifiesto.
Permite a cualquier lector verificar que documentacion y resultados no fueron
alterados desde su publicacion.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

DEFAULT_MANIFEST = "artifacts.sha256"
EXCLUDED = {".git", "__pycache__", ".zig-cache", "zig-out", DEFAULT_MANIFEST}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest(root: str | Path, exclude: set[str] | None = None) -> list[str]:
    root = Path(root)
    excluded = EXCLUDED | (exclude or set())
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in excluded for part in path.parts):
            continue
        rel = path.relative_to(root).as_posix()
        lines.append(f"{sha256_file(path)}  {rel}")
    return lines


def verify(manifest: str | Path, root: str | Path) -> dict:
    root = Path(root)
    checked = missing = 0
    changed: list[dict] = []
    absent: list[str] = []

    for line in Path(manifest).read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        expected, rel = line.split(None, 1)
        rel = rel.strip()
        target = root / rel
        checked += 1
        if not target.exists():
            missing += 1
            absent.append(rel)
            continue
        actual = sha256_file(target)
        if actual != expected:
            changed.append({"path": rel, "expected": expected, "actual": actual})

    return {
        "checked": checked,
        "missing": absent,
        "changed": changed,
        "ok": not absent and not changed,
    }


def render_report(result: dict) -> str:
    lines = [
        "# Verificacion de artefactos",
        "",
        f"- Archivos comprobados: {result['checked']}",
        f"- Ausentes: {len(result['missing'])}",
        f"- Modificados: {len(result['changed'])}",
        f"- Resultado: {'OK' if result['ok'] else 'FAIL'}",
    ]
    for rel in result["missing"]:
        lines.append(f"- FALTA: {rel}")
    for change in result["changed"]:
        lines.append(f"- CAMBIO: {change['path']} ({change['expected']} -> {change['actual']})")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="verify", choices=["verify", "generate"])
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    if args.command == "generate":
        lines = build_manifest(args.root)
        Path(args.manifest).write_text("# sha256  path\n" + "\n".join(lines) + "\n", encoding="utf-8")
        print(f"manifiesto generado: {args.manifest} ({len(lines)} archivos)")
        return

    result = verify(args.manifest, args.root)
    print(render_report(result))
    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
