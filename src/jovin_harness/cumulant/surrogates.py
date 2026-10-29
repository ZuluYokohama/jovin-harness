"""Null surrogates: phase randomization, IAAFT and column (time) shuffle.

Phase randomization keeps every Fourier amplitude (so the power spectrum, and every band's
``kappa2``) and draws uniform phases, which Gaussianizes the field; on a finite sample the band
``kappa4`` is pushed towards zero but not exactly to zero, which is why gate 2 uses a
pre-calibrated equivalence band. IAAFT (Schreiber & Schmitz 1996) alternates exact-spectrum and
exact-rank projections so the surrogate keeps the power spectrum approximately and the marginal
(histogram) exactly; it follows the two-stage convention of ``cmb-cst-lab``'s
``surrogate_topology.iaaft_reference`` (spectral projection, then rank match), reimplemented here
in batched torch. A null cannot be passed by marginal shape alone if O4 also ties under IAAFT.

The column shuffle permutes the TIME index of the conditioning features relative to the coarse
trajectory. Shuffling the points inside one snapshot would be a no-op for moment statistics, so
the permutation acts on the association, not on the sample list.
"""

from __future__ import annotations

import torch


def _gen(seed: int) -> torch.Generator:
    return torch.Generator().manual_seed(int(seed))


def phase_randomize(x: torch.Tensor, ndim: int, seed: int) -> torch.Tensor:
    """Random phases on every non-DC mode with amplitudes kept exactly.

    Phases are taken from the rFFT of white noise, so they already satisfy the Hermitian
    constraints of the real transform (self-conjugate modes such as Nyquist get a random sign),
    and the inverse transform preserves every amplitude, hence the power spectrum, exactly.
    """
    dims = tuple(range(-ndim, 0))
    size = x.shape[-ndim:]
    z = torch.fft.rfftn(x.to(torch.float64), dim=dims)
    noise = torch.randn(x.shape, generator=_gen(seed), dtype=torch.float64)
    w = torch.fft.rfftn(noise, dim=dims)
    mag = w.abs()
    unit = torch.where(mag > 0, w / torch.where(mag > 0, mag, torch.ones_like(mag)), torch.ones_like(w))
    out = z.abs() * unit
    zero = (0,) * ndim
    out[(...,) + zero] = z[(...,) + zero]
    return torch.fft.irfftn(out, s=size, dim=dims)


def _rank_match(candidate: torch.Tensor, sorted_target: torch.Tensor) -> torch.Tensor:
    order = candidate.argsort(dim=-1, stable=True)
    out = torch.empty_like(candidate)
    out.scatter_(-1, order, sorted_target)
    return out


def iaaft(x: torch.Tensor, ndim: int, seed: int, iterations: int = 50) -> tuple[torch.Tensor, torch.Tensor]:
    """Batched IAAFT. Returns ``(exact_spectrum_stage, exact_histogram_stage)``."""
    if iterations < 1:
        raise ValueError("iterations must be positive")
    dims = tuple(range(-ndim, 0))
    size = x.shape[-ndim:]
    lead = x.shape[:-ndim]
    target = x.to(torch.float64)
    amplitude = torch.fft.rfftn(target, dim=dims).abs()
    flat_sorted = target.reshape(*lead, -1).sort(dim=-1).values
    g = _gen(seed)
    perm = torch.argsort(torch.rand(*lead, flat_sorted.shape[-1], generator=g, dtype=torch.float64), dim=-1)
    current = torch.gather(flat_sorted, -1, perm).reshape(target.shape)
    spectral = current
    for _ in range(iterations):
        z = torch.fft.rfftn(current, dim=dims)
        mag = z.abs()
        unit = torch.where(mag > 0, z / torch.where(mag > 0, mag, torch.ones_like(mag)), torch.ones_like(z))
        spectral = torch.fft.irfftn(amplitude * unit, s=size, dim=dims)
        current = _rank_match(spectral.reshape(*lead, -1), flat_sorted).reshape(target.shape)
    return spectral, current


def column_shuffle(features: torch.Tensor, seed: int) -> torch.Tensor:
    """Permute rows (time) of a ``(T, C)`` feature matrix with a fixed seed."""
    perm = torch.randperm(features.shape[0], generator=_gen(seed))
    return features[perm]
