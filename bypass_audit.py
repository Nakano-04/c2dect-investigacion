"""Bypass auditable: indice de evasion OBSERVADO, no capacidad entregada.

No implementa ninguna tecnica de evasion. Consume registros de repeticiones
de laboratorio donde un sensor dijo si vio o no el indicador duro de una
tecnica, y calcula 1 - recall con intervalo de confianza bootstrap.

Contrato de entrada (JSON):
{
  "sensor": "ETW-TI",
  "catalog_sha256": "...",
  "repeticiones": [
    {"tecnica": "B-03", "visto": true},
    {"tecnica": "B-03", "visto": false}
  ]
}

Salida: indice de bypass observado por tecnica con IC95%, n y semilla.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from pathlib import Path


def bootstrap_mean(values: list[float], seed: int, n: int = 2000) -> dict:
    if not values:
        return {"mean": None, "ci95": [None, None], "n": 0}
    rng = random.Random(seed)
    means = sorted(statistics.mean(rng.choice(values) for _ in values) for _ in range(n))
    return {
        "mean": round(statistics.mean(values), 4),
        "ci95": [round(means[int(0.025 * n)], 4), round(means[int(0.975 * n) - 1], 4)],
        "n": len(values),
    }


def audit(registro: dict, seed: int = 7) -> dict:
    sensor = registro.get("sensor")
    if not sensor:
        raise ValueError("sensor declarado es obligatorio (G8)")

    por_tecnica: dict[str, list[int]] = {}
    for rep in registro.get("repeticiones", []):
        tecnica = rep.get("tecnica")
        visto = rep.get("visto")
        if not tecnica or not isinstance(visto, bool):
            continue
        por_tecnica.setdefault(tecnica, []).append(0 if visto else 1)

    resultados = {}
    for tecnica, observaciones in sorted(por_tecnica.items()):
        stats = bootstrap_mean([float(v) for v in observaciones], seed)
        resultados[tecnica] = {
            "bypass_observado": stats["mean"],
            "ic95": stats["ci95"],
            "repeticiones": stats["n"],
            "visto": observaciones.count(0),
            "no_visto": observaciones.count(1),
        }

    return {
        "sensor": sensor,
        "catalog_sha256": registro.get("catalog_sha256"),
        "semilla": seed,
        "tecnicas": len(resultados),
        "resultados": resultados,
        "nota": "bypass_observado = 1 - recall del sensor. No es una capacidad, es una medicion.",
    }


def sha256_file(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("registro")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    registro = json.loads(Path(args.registro).read_text(encoding="utf-8"))
    print(json.dumps(audit(registro, args.seed), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
