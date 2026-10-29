import json
import re
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from jovin_harness.cumulant import VERDICTS  # noqa: E402
from jovin_harness.cumulant.chain import verify_chain  # noqa: E402
from jovin_harness.cumulant.gates import Prereg, _stream, compare, decide, gate3, realizability, superior  # noqa: E402
from jovin_harness.cumulant.runner import run  # noqa: E402


def g(o4_superior=False, equivalent=False, nulls_eq=True, g3=True):
    return {"gate1": {"o4_superior": o4_superior, "equivalent": equivalent},
            "gate2": {"all_nulls_equivalent": nulls_eq, "band": 0.1}, "gate3": {"pass": g3}}


def test_decision_table_fails_closed():
    assert decide(False, g(o4_superior=True)) == "UNKNOWN"
    assert decide(True, g(o4_superior=True, g3=False)) == "STOP"
    assert decide(True, g(o4_superior=True, nulls_eq=False)) == "STOP"
    assert decide(True, {"gate1": None, "gate2": None, "gate3": None}) == "STOP"
    assert decide(True, g(o4_superior=True)) == "MEASURE"
    assert decide(True, g(equivalent=True)) == "OPEN_NULL"
    assert decide(True, g()) == "RESIDUE"
    assert "OPEN" not in VERDICTS


def test_code_never_emits_open():
    src = Path(__file__).parents[2] / "src" / "jovin_harness" / "cumulant"
    for f in src.glob("*.py"):
        assert not re.search(r"""return\s+["']OPEN["']""", f.read_text()), f


def test_superiority_needs_margin_beyond_band():
    r = {"o4_strictly_better": True, "rel_diff_ci_superiority": [0.05, 0.2]}
    assert superior(r, 0.04) and not superior(r, 0.1)
    assert not superior(r | {"o4_strictly_better": False}, 0.0)


def test_gate3_fails_blowup_and_passes_stationary():
    pr = Prereg(steps=600)
    assert not gate3(pr, _stream(pr, "blowup", 5), None)["pass"]
    assert gate3(pr, _stream(pr, "nongaussian", 5), None)["pass"]


def test_gate3_fails_closed_on_nonfinite_and_zero_power():
    pr = Prereg(steps=50)
    st = _stream(pr, "gaussian", 1)
    bad = st["field"].clone()
    bad[3, 7] = float("nan")
    assert not realizability(pr, bad)["finite"]
    flat = torch.zeros_like(st["field"])
    assert not realizability(pr, flat)["positive_spectral_density"]
    unbounded = {"result": {"long_rollout_bounded": {"O2": True, "O4": False}}}
    assert not gate3(pr, st, unbounded)["pass"]


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    out = {}
    for target in ("nongaussian", "gaussian"):
        d = tmp_path_factory.mktemp(target)
        out[target] = (d, run(d, synthetic_target=target))
    return out


def test_canaries_pass_and_synthetic_verdicts(runs):
    for d, res in runs.values():
        assert res["canaries_all_pass"], json.dumps(res["canaries"], indent=1)
        assert res["journal_ok"] and verify_chain(d / "journal.jsonl")[0]
        assert res["verdict"] in VERDICTS
        kinds = [json.loads(x)["kind"] for x in (d / "journal.jsonl").read_text().splitlines()]
        assert kinds[0] == "PREREG_FROZEN" and kinds[1] == "BAND_CALIBRATED" and kinds[-1] == "VERDICT"
        assert kinds.index("BAND_CALIBRATED") < min(i for i, k in enumerate(kinds) if k.startswith("CANARY_"))
    assert runs["nongaussian"][1]["verdict"] == "MEASURE"
    assert runs["gaussian"][1]["verdict"] == "OPEN_NULL"


def test_score_once(runs):
    d, res = runs["nongaussian"]
    with pytest.raises(PermissionError):
        run(d, synthetic_target="nongaussian")
    assert json.loads((d / "RESULT.json").read_text())["prereg_sha256"] == res["prereg_sha256"]


def test_compare_is_deterministic():
    pr = Prereg(steps=400, train_steps=100, bootstrap_reps=200)
    st = _stream(pr, "nongaussian", 9)
    a = compare(pr, st["field"], st["coarse"])
    b = compare(pr, st["field"], st["coarse"])
    assert a == b


def test_runner_refuses_real_data(tmp_path):
    with pytest.raises(PermissionError):
        run(tmp_path, prereg=Prereg(data_source="kansas"))
