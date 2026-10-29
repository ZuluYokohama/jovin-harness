"""``python -m jovin_harness.cumulant --out DIR [--synthetic-target nongaussian|gaussian]``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m jovin_harness.cumulant",
                                 description="Synthetic-only O4 vs O2 gate suite (canaries first)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--synthetic-target", choices=["nongaussian", "gaussian", "blowup"])
    ap.add_argument("--threads", type=int, default=2)
    a = ap.parse_args(argv)
    from .runner import run

    res = run(a.out, synthetic_target=a.synthetic_target, threads=a.threads)
    json.dump(res, sys.stdout, indent=1, sort_keys=True)
    print()
    return 0 if res["canaries_all_pass"] and res["journal_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
