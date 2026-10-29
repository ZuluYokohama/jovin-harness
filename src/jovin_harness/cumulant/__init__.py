"""Fourth-order cumulant scale-derivative gate suite (CPU, PyTorch).

Implements the JoVin / CST falsification protocol for an operator built on the scale derivative
of the connected fourth cumulant, ``O4 = d kappa4 / d ell``, against an equal-capacity
second-order baseline, ``O2 = d kappa2 / d ell``:

* Gate 1, equal-capacity ablation: closure defect ``e_t = ||R(T^t s0) - T~^t(R s0)||``.
* Gate 2, nulls: phase-randomized, IAAFT and column-shuffled surrogates must tie within a
  pre-calibrated equivalence band, while O4 must be strictly better on the true stream.
* Gate 3, realizability: Pearson bound ``K >= S^2 + 1``, positive spectral density and a
  bounded rollout without kurtosis blowup. Fails closed.

Canaries run first; a failed canary makes the verdict ``UNKNOWN``. Code never emits ``OPEN``;
the owner stamps that. This module needs the optional ``cumulant`` extra (``torch``).
Nothing here reads real data; see ``docs/cumulant/PREREG_TEMPLATE.md``.
"""

VERDICTS = ("OPEN_NULL", "RESIDUE", "STOP", "MEASURE", "UNKNOWN")
