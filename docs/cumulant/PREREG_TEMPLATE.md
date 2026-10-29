# PREREG: O4 vs O2 closure test on <DATASET> (template)

Fill every field, then freeze with `jovin_harness.cumulant.chain.freeze` and record the
`prereg_sha256`. Do not look at gate results on the real stream before freezing. Score exactly once.

## Binding
- `data_source`: <name; must not be "synthetic">
- `data_sha256`: <sha256 of the exact input array/file>
- `owner_go_ref`: <owner message or card id authorizing this real run>
- `frozen_by` / `approval_ref`: <who froze it; disclose if an agent froze it under owner go>
- `scored_once_marker`: <path; its existence blocks a second scoring>
- Code: `jovin-harness` commit <sha>, torch <version>, threads <n>

## Stream and coarse-graining
- Field geometry: <1D length / 2D shape; sphere not supported yet>, sampling, units, detrending
- Time axis and step; train / validation-tail / held-out split (`train_frac`, chronological)
- Coarse-graining `R`: <which modes or variables>; why these are the closure variables
- Band edges (`edges`), `standardized` (default true), `hidden`, `horizon` H, `long_horizon_mult`

## Pre-calibration (before canaries and before touching the real stream's gates)
- Equivalence band from Gaussian streams matched to the real stream's power spectrum and length:
  `calibration_seeds`, `band_multiplier`, `band_floor`, `equivalence_ci_level` (0.90)
- Superiority: absolute 95% CI excludes 0 AND relative 95% CI lower bound > band

## Canaries (must all pass, else UNKNOWN)
- C1 non-Gaussian synthetic with known kappa4 scale structure, matched to real geometry: O4 superior, nulls equivalent
- C2 Gaussian synthetic: equivalent
- C3 kurtosis blowup: gate 3 fails

## Nulls
- Phase randomization seed, IAAFT seed and iterations, column-shuffle seed

## Gate 3 thresholds
- `pearson_tol`, `kurt_cap`, `kurt_growth_max`, `rollout_bound`

## Decision rule (unchanged from code)
UNKNOWN (canary) > STOP (gate 3) > STOP (null) > MEASURE > OPEN_NULL > RESIDUE. Code never emits OPEN.

## Multiplicity and reporting
- Family for Holm correction if several datasets/targets; program-level Bonferroni line
- Negative results are frozen and reported; no re-scoring after `SCORED` exists
