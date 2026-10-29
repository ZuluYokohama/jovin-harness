"""Gates 1-3, equivalence-band calibration, canaries and the verdict rule.

Verdicts come from ``{OPEN_NULL, RESIDUE, STOP, MEASURE, UNKNOWN}``. ``OPEN`` is never emitted;
a ``MEASURE`` result is only eligible for an owner stamp.

Decision rule for a target stream, applied in order (fail closed):

1. any canary failed -> ``UNKNOWN``;
2. gate 3 failed (realizability, positivity, bounded rollout) -> ``STOP``;
3. any null not equivalent within the calibrated band -> ``STOP`` (an O4 "advantage" that survives a
   Gaussianizing or alignment-destroying null is an artifact, not fourth-order information);
4. O4 strictly better on the true stream: the bootstrap CI of ``mean(e_O2 - e_O4)`` excludes 0
   AND the CI of the relative difference lies above the calibrated band -> ``MEASURE``;
5. true stream equivalent within the band -> ``OPEN_NULL``;
6. otherwise (inconclusive, or O2 better) -> ``RESIDUE``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import torch

from .bands import band_decompose, band_masks, band_moments
from .closure import block_bootstrap_ci, build_pair, rollout_defect, train
from .operators import matched_pair
from .surrogates import column_shuffle, iaaft, phase_randomize
from .synthetic import StreamSpec, generate


@dataclass(frozen=True)
class Prereg:
    seed: int = 20261029
    data_source: str = "synthetic"
    n: int = 512
    steps: int = 1200
    edges: tuple[int, ...] = (1, 4, 8, 16, 32, 64, 128, 256)
    coarse_modes: int = 3
    standardized: bool = True
    hidden: int = 8
    train_frac: float = 2 / 3
    train_steps: int = 600
    lr: float = 0.02
    horizon: int = 8
    long_horizon_mult: int = 4
    bootstrap_reps: int = 2000
    ci_level: float = 0.95
    equivalence_ci_level: float = 0.90
    calibration_seeds: tuple[int, ...] = (101, 102, 103, 104, 105, 106)
    band_multiplier: float = 1.25
    band_floor: float = 0.01
    iaaft_iterations: int = 50
    pearson_tol: float = 1e-9
    kurt_cap: float = 30.0
    kurt_growth_max: float = 2.0
    rollout_bound: float = 3.0
    canary_seeds: dict = field(default_factory=lambda: {"nongaussian": 201, "gaussian": 202, "blowup": 203})
    owner_go_ref: str = ""
    data_sha256: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["edges"] = list(self.edges)
        d["calibration_seeds"] = list(self.calibration_seeds)
        return d


def _stream(pr: Prereg, mode: str, seed: int) -> dict:
    return generate(StreamSpec(mode=mode, n=pr.n, steps=pr.steps, seed=seed, coarse_modes=pr.coarse_modes,
                               edges=tuple(pr.edges)))


def _split(pr: Prereg, steps: int) -> tuple[int, torch.Tensor]:
    cut = int(steps * pr.train_frac)
    long_h = pr.horizon * pr.long_horizon_mult
    starts = torch.arange(cut, steps - long_h - 1)
    if len(starts) < 4 * pr.horizon:
        raise ValueError("held-out segment too short for the horizon")
    return cut, starts


def compare(pr: Prereg, field_: torch.Tensor, coarse: torch.Tensor, feature_field: torch.Tensor | None = None,
            shuffle_seed: int | None = None, seed_offset: int = 0) -> dict:
    """Train matched O2/O4 closures and compare rollout defects on the held-out segment.

    ``feature_field`` replaces the field the operators see (a surrogate), while the coarse targets
    stay the true ones. ``shuffle_seed`` permutes the feature rows in time (column shuffle null).
    """
    o2, o4 = matched_pair((pr.n,), list(pr.edges), pr.standardized)
    src = field_ if feature_field is None else feature_field
    raw2, raw4 = o2.raw(src).detach(), o4.raw(src).detach()
    if shuffle_seed is not None:
        raw2, raw4 = column_shuffle(raw2, shuffle_seed), column_shuffle(raw4, shuffle_seed)
    m2, m4 = build_pair(o2, o4, coarse.shape[-1], pr.hidden, pr.seed + seed_offset)
    cut, starts = _split(pr, coarse.shape[0])
    for m, raw in ((m2, raw2), (m4, raw4)):
        train(m, coarse[:cut + 1], raw[:cut + 1], pr.train_steps, pr.lr)
    e2, t2 = rollout_defect(m2, coarse, raw2, starts, pr.horizon)
    e4, t4 = rollout_defect(m4, coarse, raw4, starts, pr.horizon)
    long_h = pr.horizon * pr.long_horizon_mult
    l2, _ = rollout_defect(m2, coarse, raw2, starts, long_h)
    l4, lt4 = rollout_defect(m4, coarse, raw4, starts, long_h)
    _, lt2 = rollout_defect(m2, coarse, raw2, starts, long_h)
    s2, s4 = e2.mean(1), e4.mean(1)
    d = s2 - s4
    bs = dict(block=pr.horizon, reps=pr.bootstrap_reps, seed=pr.seed + 7 + seed_offset)
    est, lo, hi = block_bootstrap_ci(d, level=pr.ci_level, **bs)
    rel, rlo, rhi = block_bootstrap_ci(d, level=pr.equivalence_ci_level, ratio_den=s2, **bs)
    _, slo, shi = block_bootstrap_ci(d, level=pr.ci_level, ratio_den=s2, **bs)
    true_scale = coarse[cut:].norm(dim=-1).max()
    bounded = {name: bool(torch.isfinite(t).all() and t.norm(dim=-1).max() <= pr.rollout_bound * true_scale)
               for name, t in (("O2", lt2), ("O4", lt4))}
    return {"defect_O2_by_t": e2.mean(0).tolist(), "defect_O4_by_t": e4.mean(0).tolist(),
            "mean_defect_O2": float(s2.mean()), "mean_defect_O4": float(s4.mean()),
            "diff_O2_minus_O4": est, "diff_ci": [lo, hi], "ci_level": pr.ci_level,
            "rel_diff": rel, "rel_diff_ci": [rlo, rhi], "equivalence_ci_level": pr.equivalence_ci_level,
            "rel_diff_ci_superiority": [slo, shi],
            "o4_strictly_better": lo > 0, "n_starts": int(len(starts)),
            "long_rollout_bounded": bounded, "long_defect_O2": float(l2.mean()), "long_defect_O4": float(l4.mean())}


def superior(result: dict, band: float) -> bool:
    """O4 strictly better: the absolute-difference CI excludes 0 AND the relative-difference CI
    (at ``ci_level``) lies above the calibrated band, so a systematic O2 handicap of the size seen on
    Gaussian calibration streams cannot pass as fourth-order information."""
    return bool(result["o4_strictly_better"] and result["rel_diff_ci_superiority"][0] > band)


def equivalent(result: dict, band: float) -> bool:
    lo, hi = result["rel_diff_ci"]
    return max(abs(lo), abs(hi)) <= band


def calibrate_band(pr: Prereg) -> dict:
    """Pre-calibrated equivalence band from Gaussian streams with dedicated seeds.

    For each calibration seed the matched pair is compared on a Gaussian stream (no fourth-order
    information exists), and the largest |end| of the equivalence CI of the relative defect
    difference is recorded. Band = ``max(floor, multiplier * max over seeds)``.
    """
    per_seed = []
    for s in pr.calibration_seeds:
        st = _stream(pr, "gaussian", s)
        r = compare(pr, st["field"], st["coarse"], seed_offset=s)
        per_seed.append({"seed": s, "rel_diff": r["rel_diff"], "rel_diff_ci": r["rel_diff_ci"]})
    worst = max(max(abs(x) for x in p["rel_diff_ci"]) for p in per_seed)
    return {"band": max(pr.band_floor, pr.band_multiplier * worst), "worst_abs_ci_end": worst, "per_seed": per_seed}


def gate1(pr: Prereg, stream: dict, band: float) -> dict:
    r = compare(pr, stream["field"], stream["coarse"])
    return {"result": r, "ci_excludes_zero": r["o4_strictly_better"], "o4_superior": superior(r, band),
            "equivalent": equivalent(r, band)}


def gate2(pr: Prereg, stream: dict, band: float) -> dict:
    f = stream["field"]
    nulls = {
        "phase_randomized": compare(pr, f, stream["coarse"], feature_field=phase_randomize(f, 1, pr.seed + 11)),
        "iaaft": compare(pr, f, stream["coarse"], feature_field=iaaft(f, 1, pr.seed + 13, pr.iaaft_iterations)[1]),
        "column_shuffle": compare(pr, f, stream["coarse"], shuffle_seed=pr.seed + 17),
    }
    eq = {k: equivalent(v, band) for k, v in nulls.items()}
    return {"band": band, "nulls": nulls, "null_equivalent": eq, "all_nulls_equivalent": all(eq.values())}


def realizability(pr: Prereg, fld: torch.Tensor) -> dict:
    masks = band_masks((pr.n,), list(pr.edges))
    m = band_moments(band_decompose(fld.to(torch.float64), masks, 1), 1)
    k, s, k2 = m["kurt"], m["skew"], m["kappa2"]
    pearson_gap = (k - (s**2 + 1)).min().item()
    power = (torch.fft.rfft(fld.to(torch.float64)).abs() ** 2).mean(0)
    covered = masks.any(0)
    min_power = power[covered].min().item()
    steps = k.shape[0]
    w = max(1, steps // 10)
    head, tail = k[:w].median(0).values, k[-w:].median(0).values
    growth = (tail / head.clamp_min(1e-12)).max().item()
    return {"pearson_min_gap": pearson_gap, "pearson_ok": pearson_gap >= -pr.pearson_tol,
            "min_band_kappa2": k2.min().item(), "min_mode_power": min_power,
            "positive_spectral_density": bool(k2.min() > 0 and min_power > 0),
            "max_kurt": k.max().item(), "kurt_cap_ok": bool(k.max() <= pr.kurt_cap),
            "kurt_growth": growth, "kurt_growth_ok": growth <= pr.kurt_growth_max,
            "finite": bool(torch.isfinite(fld).all())}


def gate3(pr: Prereg, stream: dict, gate1_result: dict | None) -> dict:
    r = realizability(pr, stream["field"])
    bounded = gate1_result["result"]["long_rollout_bounded"] if gate1_result else {"O2": True, "O4": True}
    checks = {"finite": r["finite"], "pearson": r["pearson_ok"],
              "positive_spectral_density": r["positive_spectral_density"],
              "kurt_cap": r["kurt_cap_ok"], "no_kurtosis_blowup": r["kurt_growth_ok"],
              "rollout_bounded": all(bounded.values())}
    return {"details": r, "rollout_bounded": bounded, "checks": checks, "pass": all(checks.values())}


def run_gates(pr: Prereg, stream: dict, band: float) -> dict:
    g3_pre = gate3(pr, stream, None)
    if not (g3_pre["checks"]["finite"] and g3_pre["checks"]["positive_spectral_density"]):
        return {"gate3": g3_pre, "gate1": None, "gate2": None}  # fail closed before any fitting
    g1 = gate1(pr, stream, band)
    g2 = gate2(pr, stream, band)
    return {"gate1": g1, "gate2": g2, "gate3": gate3(pr, stream, g1)}


def decide(canaries_ok: bool, gates: dict) -> str:
    if not canaries_ok:
        return "UNKNOWN"
    if gates["gate3"] is None or not gates["gate3"]["pass"]:
        return "STOP"
    if gates["gate2"] is None or not gates["gate2"]["all_nulls_equivalent"]:
        return "STOP"
    g1 = gates["gate1"]
    if g1["o4_superior"]:
        return "MEASURE"
    if g1["equivalent"]:
        return "OPEN_NULL"
    return "RESIDUE"


def run_canaries(pr: Prereg, band: float) -> dict:
    """C1 non-Gaussian: O4 wins, nulls tie, gate 3 passes. C2 Gaussian: tie. C3 blowup: gate 3 fails."""
    out = {}
    st = _stream(pr, "nongaussian", pr.canary_seeds["nongaussian"])
    g = run_gates(pr, st, band)
    ok = bool(g["gate3"]["pass"] and g["gate1"] and g["gate1"]["o4_superior"]
              and g["gate2"]["all_nulls_equivalent"])
    out["C1_nongaussian"] = {"expect": "O4 strictly better; nulls equivalent; gate3 pass", "pass": ok, "gates": g}
    st = _stream(pr, "gaussian", pr.canary_seeds["gaussian"])
    g = run_gates(pr, st, band)
    ok = bool(g["gate3"]["pass"] and g["gate1"] and not g["gate1"]["o4_superior"] and g["gate1"]["equivalent"])
    out["C2_gaussian"] = {"expect": "O4 and O2 equivalent; gate3 pass", "pass": ok, "gates": g}
    st = _stream(pr, "blowup", pr.canary_seeds["blowup"])
    g3 = gate3(pr, st, None)
    out["C3_kurtosis_blowup"] = {"expect": "gate3 FAIL", "pass": not g3["pass"], "gate3": g3}
    out["all_pass"] = all(v["pass"] for k, v in out.items() if k.startswith("C"))
    return out
