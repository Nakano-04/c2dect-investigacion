"""Prototipo: puntuacion de observabilidad de tecnicas (datos sinteticos).

No depende de C2-DECT. Es una herramienta de PRIORIZACION DEFENSIVA: dada una
lista de tecnicas y las senales que produce cada una en distintos sensores,
calcula que tan observable es cada tecnica y donde hay brechas de cobertura.

No disena evasion: solo cuantifica huella para decidir donde invertir deteccion.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

MAX_PESO = 3


def load(path: str | Path) -> list[dict]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def observabilidad(tecnica: dict) -> float:
    """Suma de pesos de senales / maximo posible segun sensores declarados."""
    senales = tecnica.get("signals", {})
    sensores = tecnica.get("sensors_assumed", list(senales))
    if not sensores:
        return 0.0
    total = sum(min(MAX_PESO, max(0, int(senales.get(s, 0)))) for s in sensores)
    return round(total / (MAX_PESO * len(sensores)), 4)


def gap_priority(tecnica: dict) -> float:
    """1 - cobertura de reglas declaradas para la tecnica."""
    cobertura = tecnica.get("rule_coverage", 0)
    cobertura = min(1.0, max(0.0, float(cobertura)))
    return round(1 - cobertura, 4)


def score(tecnicas: list[dict]) -> dict:
    rows = []
    for t in tecnicas:
        rows.append({
            "technique": t["id"],
            "tactic": t.get("tactic", ""),
            "observabilidad": observabilidad(t),
            "gap_priority": gap_priority(t),
            "sensores": t.get("sensors_assumed", []),
        })
    return {
        "sensores_auditados": sorted({s for t in tecnicas for s in t.get("sensors_assumed", [])}),
        "tecnicas": len(rows),
        "ranking_observabilidad": sorted(rows, key=lambda r: -r["observabilidad"]),
        "ranking_brechas": sorted(rows, key=lambda r: -r["gap_priority"]),
    }


def render_markdown(result: dict) -> str:
    lines = [
        "# Informe OPSEC — observabilidad por tecnica",
        "",
        f"Sensores asumidos: {', '.join(result['sensores_auditados'])}",
        "",
        "| Tecnica | Tactica | Observabilidad | Gap |",
        "|---|---|---:|---:|",
    ]
    for r in result["ranking_observabilidad"]:
        lines.append(
            f"| {r['technique']} | {r['tactic']} | {r['observabilidad']} | {r['gap_priority']} |"
        )
    lines += ["", "## Prioridad de brechas (donde invertir deteccion)", ""]
    for r in result["ranking_brechas"][:5]:
        lines.append(f"- {r['technique']}: gap {r['gap_priority']}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tecnicas")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    result = score(load(args.tecnicas))
    print(render_markdown(result) if args.markdown else json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
