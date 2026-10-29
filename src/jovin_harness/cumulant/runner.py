"""Synthetic-only suite runner: freeze prereg, calibrate band, canaries, optional synthetic target.

Real data is out of scope here. A real run needs a frozen prereg that binds the data hash and an
owner go reference (``chain.assert_real_run_authorized``), see ``docs/cumulant/PREREG_TEMPLATE.md``.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

import torch

from . import VERDICTS
from .chain import Journal, freeze, verify_chain
from .gates import Prereg, _stream, calibrate_band, decide, run_canaries, run_gates


def _summ(g: dict | None) -> dict | None:
    if not g:
        return g
    keys = ("mean_defect_O2", "mean_defect_O4", "diff_O2_minus_O4", "diff_ci", "rel_diff", "rel_diff_ci",
            "rel_diff_ci_superiority", "n_starts", "long_rollout_bounded")
    return {k: g["result"][k] for k in keys} | {k: g[k] for k in ("o4_superior", "equivalent", "ci_excludes_zero")}


def summarize_gates(g: dict) -> dict:
    out = {"gate1": _summ(g.get("gate1")),
           "gate3": g["gate3"]["checks"] | {"pass": g["gate3"]["pass"]}}
    if g.get("gate2"):
        out["gate2"] = {k: {"rel_diff_ci": v["rel_diff_ci"], "equivalent": g["gate2"]["null_equivalent"][k]}
                        for k, v in g["gate2"]["nulls"].items()} | {"band": g["gate2"]["band"]}
    return out


def run(out: Path, prereg: Prereg | None = None, synthetic_target: str | None = None, threads: int = 2,
        frozen_by: str = "agent (synthetic canary run)",
        approval_ref: str = "synthetic-only; no owner go needed") -> dict:
    torch.set_num_threads(threads)
    pr = prereg or Prereg()
    if pr.data_source != "synthetic":
        raise PermissionError("runner is synthetic-only")
    out = Path(out)
    if (out / "SCORED").exists():
        raise PermissionError(f"{out} already scored once; use a new output directory")
    doc = freeze(pr.as_dict(), out / "PREREG_FROZEN.json", frozen_by, approval_ref)
    j = Journal(out / "journal.jsonl")
    j.append("PREREG_FROZEN", {"prereg_sha256": doc["prereg_sha256"], "torch": torch.__version__,
                               "python": platform.python_version(), "threads": threads})
    cal = calibrate_band(pr)
    j.append("BAND_CALIBRATED", cal)
    can = run_canaries(pr, cal["band"])
    canary_summary = {}
    for k, v in can.items():
        if not k.startswith("C"):
            continue
        s = {"expect": v["expect"], "pass": v["pass"]}
        if "gates" in v:
            s |= summarize_gates(v["gates"])
        else:
            g3 = v["gate3"]
            s |= {"gate3": g3["checks"] | {"pass": g3["pass"], "max_kurt": g3["details"]["max_kurt"],
                                           "kurt_growth": g3["details"]["kurt_growth"]}}
        canary_summary[k] = s
        j.append(f"CANARY_{k}", s)
    result = {"prereg_sha256": doc["prereg_sha256"], "band": cal["band"], "canaries": canary_summary,
              "canaries_all_pass": can["all_pass"]}
    if synthetic_target:
        (out / "SCORED").write_text("synthetic target scored once\n")
        if not can["all_pass"]:
            verdict, target = "UNKNOWN", None
        else:
            st = _stream(pr, synthetic_target, pr.seed)
            g = run_gates(pr, st, cal["band"])
            verdict, target = decide(True, g), summarize_gates(g)
        assert verdict in VERDICTS and verdict != "OPEN"
        result |= {"synthetic_target": synthetic_target, "target": target, "verdict": verdict,
                   "note": "synthetic demonstration only; not a scientific result; OPEN is owner-stamped"}
        j.append("VERDICT", {"synthetic_target": synthetic_target, "verdict": verdict, "target": target})
    ok, head = verify_chain(out / "journal.jsonl")
    result |= {"journal_ok": ok, "journal_head": head}
    (out / "RESULT.json").write_text(json.dumps(result, indent=1, sort_keys=True))
    return result
