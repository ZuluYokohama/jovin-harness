# Fourth-order cumulant scale-derivative gates (O4 vs O2)

Status: **synthetic canaries only**. Nothing here has been run on real data, and code never emits
`OPEN`; the owner stamps that. A real run needs a frozen prereg ([template](PREREG_TEMPLATE.md))
and an owner go.

Install and run (CPU, two threads):

```bash
pip install -e '.[cumulant,dev]'
python -m jovin_harness.cumulant --out runs/canary_$(date +%Y%m%dT%H%M%S) --synthetic-target nongaussian
pytest tests/cumulant
```

## What is measured

| Piece | Definition | Code |
|---|---|---|
| Scale bands | Dyadic Fourier shells (annuli in 2D), exact masks | `bands.py` |
| `kappa2(ell)` | band variance `mu2` | `band_moments` |
| `kappa4(ell)` | connected fourth cumulant `mu4 - 3 mu2^2`; also `K = mu4/mu2^2`, `S = mu3/mu2^1.5` | `band_moments` |
| `O2` | `d log kappa2 / d ell` (raw `d kappa2 / d ell` with `standardized=False`) | `operators.py` |
| `O4` | `d (kappa4 / kappa2^2) / d ell` (raw `d kappa4 / d ell` with `standardized=False`) | `operators.py` |
| Capacity | same class, `L-1` channels, `2(L-1)` affine parameters each; asserted equal | `assert_equal_capacity` |
| `T~` | `c_{t+1} = c_t + W [c_t, tanh(V O(s_t))] + b`, identical init for both orders | `closure.py` |
| Closure defect | `e_t = ||R(T^t s0) - T~^t(R s0)||`, `t = 1..H`, `R` = Fourier modes 1..3 | `rollout_defect` |

The standardized form is the default because raw `kappa4` scales as amplitude^4 and would let O4
win through power alone; the raw form is kept and tested.

## Gates and decision (fail closed)

1. **Gate 1, equal-capacity ablation.** Matched O2/O4 closures trained with the same seed,
   steps and early stopping on a validation tail; defects compared on a held-out segment with a
   moving-block bootstrap (block = H).
2. **Gate 2, nulls.** Features recomputed on phase-randomized (exact power), IAAFT (exact marginal,
   near-exact power) and column-shuffled (time association destroyed) inputs, coarse targets kept.
   Each null must be *equivalent*: the 90% CI of the relative defect difference lies inside the
   pre-calibrated band.
3. **Gate 3, realizability.** Pearson bound `K >= S^2 + 1` per band and snapshot, positive band
   variance and mode power, finite values, `K <= kurt_cap`, no kurtosis growth (late/early median
   ratio `<= kurt_growth_max`), and long (4H) rollouts bounded by `rollout_bound x` the true scale.

Verdict order: canary failure -> `UNKNOWN`; gate 3 fail -> `STOP`; any null not equivalent ->
`STOP`; O4 superior -> `MEASURE`; true stream equivalent -> `OPEN_NULL`; else `RESIDUE`.

### Revisions to the pasted protocol (disclosed)

- **Equivalence band, not exact tie.** Finite-sample `kappa4` is not zero after phase randomization.
  The band is calibrated *before* canaries on six dedicated Gaussian-stream seeds:
  `band = max(0.01, 1.25 x max |end of 90% CI|)`.
- **Superiority needs a margin.** On Gaussian calibration streams O2 showed a small systematic
  handicap (median ~+4% relative, two of six seeds had CIs excluding 0), because persistent `kappa2`
  nuisance invites spurious regression. So "O4 strictly better" requires the absolute CI to exclude 0
  **and** the 95% CI of the relative difference to sit above the band. Plain "CI excludes 0" alone
  would have called two Gaussian seeds a discovery.
- **Early stopping** on a training-tail validation set applies identical shrinkage to both operators.
- **IAAFT** added beside phase randomization, so a marginal-shape effect cannot pass the null.
- Gate 3 cannot fail Pearson on plug-in moments of real samples (it holds exactly); that check
  guards numerics and any future moment-propagating closure. Blowup is caught by cap and growth.

## Canary results (prereg sha256 `601f038a…e766a5`, torch 2.15.0+cpu, 2 threads)

Band = **0.168**. All canaries pass. Peak RSS of the full test run: ~530 MB.

| Canary | Expectation | O2 defect | O4 defect | rel. diff (95% CI) | Result |
|---|---|---:|---:|---|---|
| C1 non-Gaussian | O4 superior, nulls equivalent, gate 3 pass | 2.759 | 1.457 | 0.472 [0.397, 0.535] | pass |
| C1 nulls (90% CI) | inside ±0.168 | | | phase [-0.020, 0.107], IAAFT [0.014, 0.137], shuffle [-0.038, 0.015] | pass |
| C2 Gaussian | equivalent, gate 3 pass | 2.829 | 2.704 | 0.044 [-0.024, 0.109] | pass |
| C3 kurtosis blowup | gate 3 FAIL | | | max K 165 > 30, growth 8.7x > 2x | pass (failed as required) |

Synthetic targets (paired, seed 20261029): non-Gaussian -> `MEASURE` (rel 0.516 [0.473, 0.558]);
Gaussian -> `OPEN_NULL` (rel 0.006 [-0.030, 0.041]). These demonstrate the plumbing, not science.

Caveat: on C1 the IAAFT null kept a small O4 edge (90% CI [0.014, 0.137]); it passes only because it
sits inside the band. The whole-field marginal is designed to carry no forcing information, so this
is residual scale-structure leakage through rank matching. Watch it on real data.

## Provenance

- Referenced `cst_validation_extended.py`: **not available**. It exists only as a hash
  (`8078924408b8e6e0…bad4de`) in `ZuluYokohama/cmb-cst-lab` `data/evidence/cst_package_audit.json`
  (CST package archive `e088852040a6…244224`, 2026-10-23); the archive itself is not in the repo or on
  the build box. Nothing from it is used.
- Referenced `frozen.py`: **not found** in local clones, ZuluYokohama or FractalDesignZ repos
  (GitHub code search hit its rate limit partway; see PR notes).
- `SPHERICAL_TOPOLOGY_RUN.md`: found in `ZuluYokohama/cmb-cst-lab` `docs/` (commit `0ea4885`).
  Conventions reused: +1-corrected Monte Carlo framing, preserved failures, positive/negative
  controls before claims, frozen plan by hash. The spherical (ducc0) pipeline is not used; this suite
  works on 1D/2D Fourier bands.
- IAAFT two-stage convention (spectral projection then rank match, return both stages) follows
  `cmb-cst-lab` `src/cmbcst/surrogate_topology.py::iaaft_reference` (same owner), reimplemented in
  batched torch.
- Column-shuffle design note (shuffle the association, not the sample list) follows the principle in
  FractalDesignZ `premature-sheafification` `src/ztime/nulls.py` (commit `9ead768`); idea only, no code
  copied. Owner approved reuse of FractalDesignZ material; no LICENSE file was edited.
- Canonical JSON / sha256 come from `jovin_harness.receipts`.
