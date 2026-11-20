"""Huella conductual determinista (referencia legible en Python).

NO mide el compilador: mide eventos de comportamiento (tipo de evento +
tecnica). Un binario Python y uno Zig con la MISMA conducta producen el MISMO
hash. Esa es la evidencia de que el lenguaje no altera la huella conductual.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def canonical(events: list[dict]) -> str:
    pairs = sorted(
        f"{e['event_type']}:{e['technique']}" for e in events
    )
    return "\n".join(pairs) + "\n"


def fingerprint(events: list[dict]) -> str:
    return hashlib.sha256(canonical(events).encode("utf-8")).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events")
    args = parser.parse_args()
    events = json.loads(Path(args.events).read_text(encoding="utf-8"))
    print(fingerprint(events))


if __name__ == "__main__":
    main()
