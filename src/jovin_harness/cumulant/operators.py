"""Matched scale-derivative operators O2 and O4 as ``torch.nn.Module``s.

Both operators share one class, so their parameter and channel counts are identical by
construction (a test asserts it). Each maps a field batch ``(..., *field)`` to ``L - 1``
channels: the forward finite difference over neighbouring bands of a per-band cumulant, then a
learnable per-channel affine map (``2 * (L - 1)`` parameters, identity at init).

* ``order=2``: ``d kappa2 / d ell``; standardized form ``d log kappa2 / d ell`` (scale-free).
* ``order=4``: ``d kappa4 / d ell``; standardized form ``d (kappa4 / kappa2^2) / d ell``,
  the scale derivative of the excess kurtosis, which removes the trivial amplitude^4 coupling
  to power so that O4 is not a disguised second-order statistic.
"""

from __future__ import annotations

import torch
from torch import nn

from .bands import band_decompose, band_masks, band_moments


class CumulantScaleDerivative(nn.Module):
    def __init__(self, order: int, shape: tuple[int, ...], edges: list[int], standardized: bool = True,
                 eps: float = 1e-12):
        super().__init__()
        if order not in (2, 4):
            raise ValueError("order must be 2 or 4")
        self.order, self.ndim, self.standardized, self.eps = order, len(shape), standardized, eps
        self.edges = list(edges)
        self.register_buffer("masks", band_masks(tuple(shape), self.edges), persistent=False)
        channels = len(self.edges) - 2
        if channels < 1:
            raise ValueError("need at least two bands for a scale derivative")
        self.channels = channels
        self.weight = nn.Parameter(torch.ones(channels, dtype=torch.float64))
        self.bias = nn.Parameter(torch.zeros(channels, dtype=torch.float64))

    def cumulant(self, x: torch.Tensor) -> torch.Tensor:
        m = band_moments(band_decompose(x.to(torch.float64), self.masks, self.ndim), self.ndim)
        if self.order == 2:
            return torch.log(m["kappa2"] + self.eps) if self.standardized else m["kappa2"]
        return m["kappa4"] / (m["kappa2"] + self.eps) ** 2 if self.standardized else m["kappa4"]

    def raw(self, x: torch.Tensor) -> torch.Tensor:
        """Finite difference over neighbouring bands, without the learnable affine."""
        c = self.cumulant(x)
        return c[..., 1:] - c[..., :-1]

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.raw(x) * self.weight + self.bias


def matched_pair(shape: tuple[int, ...], edges: list[int], standardized: bool = True):
    o2 = CumulantScaleDerivative(2, shape, edges, standardized)
    o4 = CumulantScaleDerivative(4, shape, edges, standardized)
    assert_equal_capacity(o2, o4)
    return o2, o4


def capacity(module: nn.Module) -> tuple[int, tuple[tuple[int, ...], ...]]:
    params = tuple(p for p in module.parameters())
    return sum(p.numel() for p in params), tuple(tuple(p.shape) for p in params)


def assert_equal_capacity(a: nn.Module, b: nn.Module) -> None:
    if capacity(a) != capacity(b):
        raise AssertionError(f"capacity mismatch: {capacity(a)} vs {capacity(b)}")
    if getattr(a, "channels", None) != getattr(b, "channels", None):
        raise AssertionError("channel mismatch")
