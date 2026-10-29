"""Scale-band decomposition and per-band moments for 1D and 2D periodic fields.

Bands are dyadic Fourier shells: band ``ell`` holds wavenumbers ``|k|`` in ``[edges[ell],
edges[ell+1])`` (the last band also keeps its upper edge). In 2D ``|k|`` is the radial
wavenumber, so bands are annuli. Band-pass is an exact Fourier mask, so the bands of a field
sum back to the field minus its mean.
"""

from __future__ import annotations

import torch


def dyadic_edges(n: int, first: int = 1) -> list[int]:
    """Dyadic edges ``first, 2*first, ...`` ending at the Nyquist wavenumber ``n // 2``."""
    if n < 4 or first < 1:
        raise ValueError("need n >= 4 and first >= 1")
    edges, k = [], first
    while k < n // 2:
        edges.append(k)
        k *= 2
    edges.append(n // 2)
    return edges


def _radial_wavenumber(shape: tuple[int, ...]) -> torch.Tensor:
    if len(shape) == 1:
        return torch.fft.rfftfreq(shape[0], d=1.0 / shape[0], dtype=torch.float64).abs()
    if len(shape) == 2:
        ky = torch.fft.fftfreq(shape[0], d=1.0 / shape[0], dtype=torch.float64)
        kx = torch.fft.rfftfreq(shape[1], d=1.0 / shape[1], dtype=torch.float64)
        return torch.sqrt(ky[:, None] ** 2 + kx[None, :] ** 2)
    raise ValueError("only 1D and 2D fields are supported")


def band_masks(shape: tuple[int, ...], edges: list[int]) -> torch.Tensor:
    """Boolean masks over the rFFT grid, one per band, shape ``(L, *rfft_shape)``."""
    if len(edges) < 2 or any(b <= a for a, b in zip(edges, edges[1:], strict=False)):
        raise ValueError("edges must be strictly increasing with at least two entries")
    k = _radial_wavenumber(tuple(shape))
    masks = []
    for i, (lo, hi) in enumerate(zip(edges, edges[1:], strict=False)):
        last = i == len(edges) - 2
        masks.append((k >= lo) & ((k <= hi) if last else (k < hi)))
    out = torch.stack(masks)
    if (out.sum(dim=0) > 1).any():
        raise AssertionError("bands overlap")
    return out


def band_decompose(x: torch.Tensor, masks: torch.Tensor, ndim: int) -> torch.Tensor:
    """Band-pass ``x`` (shape ``(..., *field)``) into ``(..., L, *field)``."""
    dims = tuple(range(-ndim, 0))
    size = x.shape[-ndim:]
    z = torch.fft.rfftn(x, dim=dims)
    zb = z.unsqueeze(-ndim - 1) * masks.to(z.dtype)
    return torch.fft.irfftn(zb, s=size, dim=dims)


def band_moments(bands: torch.Tensor, ndim: int, eps: float = 0.0) -> dict[str, torch.Tensor]:
    """Central moments and cumulants per band over the last ``ndim`` (spatial) dims.

    Returns ``kappa2`` (variance), ``kappa4 = mu4 - 3 mu2^2`` (connected fourth cumulant),
    ``skew = mu3 / mu2^1.5`` and ``kurt = mu4 / mu2^2`` (non-excess, Pearson's ``K``), plus the
    excess kurtosis ``kappa4 / kappa2^2``. These are plug-in (biased) sample moments, for which the
    Pearson inequality ``K >= S^2 + 1`` holds exactly, up to rounding.
    """
    dims = tuple(range(-ndim, 0))
    c = bands - bands.mean(dim=dims, keepdim=True)
    mu2 = (c**2).mean(dim=dims)
    mu3 = (c**3).mean(dim=dims)
    mu4 = (c**4).mean(dim=dims)
    denom = mu2 + eps
    kappa4 = mu4 - 3.0 * mu2**2
    return {"kappa2": mu2, "kappa4": kappa4, "mu3": mu3, "mu4": mu4,
            "skew": mu3 / denom**1.5, "kurt": mu4 / denom**2, "excess": kappa4 / denom**2}
