"""Synthetic 1D streams with known fourth-cumulant scale structure (canaries only).

State ``s_t`` is a periodic field of length ``n``. Its coarse part lives on Fourier modes
``1..coarse_modes`` and evolves as ``c_{t+1} = A c_t + B q_t + sigma * eps``. The latent forcing
``q_t`` (AR(1)) is written ONLY into the scale gradient of the excess kurtosis of the fine bands:
band ``ell`` gets target excess ``e0 + slope * q_t * z_ell`` with ``sum(z) = 0`` and equal band
variances, so the whole-field marginal kurtosis and every band variance carry no information
about ``q_t``. Band variances get an independent log-AR nuisance so O2 has something to fit.

Modes:

* ``nongaussian``: the above; O4 should beat O2 on closure.
* ``gaussian``: identical except every band is Gaussian; ``q_t`` is unobservable, O4 and O2 tie.
* ``blowup``: excess kurtosis grows geometrically in time; gate 3 must fail it.

Each band component is a band-passed Bernoulli-Gaussian white noise ``b * g``. For white noise
with excess kurtosis ``gamma`` a linear filter ``h`` gives excess ``gamma * sum h^4 / (sum h^2)^2``
exactly (in expectation), which is used to hit the target band excess.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field

import torch

from .bands import band_masks


@dataclass(frozen=True)
class StreamSpec:
    mode: str = "nongaussian"
    n: int = 512
    steps: int = 1200
    seed: int = 0
    coarse_modes: int = 3
    edges: tuple[int, ...] = (1, 4, 8, 16, 32, 64, 128, 256)
    structured_from: int = 2  # index of the first band carrying kurtosis structure ([8,16) here)
    excess0: float = 1.0
    excess_slope: float = 0.8
    q_phi: float = 0.85
    nuisance_phi: float = 0.9
    nuisance_sd: float = 0.3
    band_var: float = 0.5
    coarse_damping: float = 0.9
    forcing: float = 0.6
    coarse_noise: float = 0.05
    blowup_rate: float = 4.0  # total log-growth of the excess over the run in blowup mode
    min_spikes: float = 8.0
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["edges"] = list(self.edges)
        return d


def _ar1(gen: torch.Generator, steps: int, phi: float, shape=()) -> torch.Tensor:
    out = torch.empty((steps, *shape), dtype=torch.float64)
    x = torch.randn(shape, generator=gen, dtype=torch.float64)
    scale = math.sqrt(1 - phi**2)
    for t in range(steps):
        out[t] = x
        x = phi * x + scale * torch.randn(shape, generator=gen, dtype=torch.float64)
    return out


def filter_kurtosis_factor(mask: torch.Tensor, n: int) -> float:
    h = torch.fft.irfft(mask.to(torch.complex128), n=n)
    return float((h**4).sum() / (h**2).sum() ** 2)


def coarse_matrix(m: int, damping: float) -> torch.Tensor:
    a = torch.zeros(2 * m, 2 * m, dtype=torch.float64)
    for j in range(m):
        th = 0.3 + 0.4 * j
        r = damping
        a[2 * j:2 * j + 2, 2 * j:2 * j + 2] = r * torch.tensor([[math.cos(th), -math.sin(th)],
                                                               [math.sin(th), math.cos(th)]], dtype=torch.float64)
    return a


def coarse_field(c: torch.Tensor, n: int) -> torch.Tensor:
    m = c.shape[-1] // 2
    z = torch.zeros(*c.shape[:-1], n // 2 + 1, dtype=torch.complex128)
    z[..., 1:m + 1] = torch.complex(c[..., 0::2], c[..., 1::2]) * (n / 2)
    return torch.fft.irfft(z, n=n)


def restrict(s: torch.Tensor, m: int) -> torch.Tensor:
    """Coarse-graining ``R``: real/imag parts of Fourier modes ``1..m`` (exact inverse of ``coarse_field``)."""
    n = s.shape[-1]
    z = torch.fft.rfft(s.to(torch.float64))[..., 1:m + 1] / (n / 2)
    return torch.stack([z.real, z.imag], dim=-1).reshape(*s.shape[:-1], 2 * m)


def generate(spec: StreamSpec) -> dict:
    if spec.mode not in ("nongaussian", "gaussian", "blowup"):
        raise ValueError(f"unknown mode {spec.mode}")
    if spec.edges[1] <= spec.coarse_modes:
        raise ValueError("first band must contain the coarse modes")
    gen = torch.Generator().manual_seed(int(spec.seed))
    n, steps, m = spec.n, spec.steps, spec.coarse_modes
    masks = band_masks((n,), list(spec.edges))
    lo_mask = masks[0].clone()
    lo_mask[: m + 1] = False  # band 0 minus the coarse modes and DC: Gaussian nuisance
    fine = [lo_mask] + [masks[i] for i in range(1, masks.shape[0])]
    structured = list(range(spec.structured_from, masks.shape[0]))
    z = torch.linspace(-1.0, 1.0, len(structured), dtype=torch.float64)

    q = _ar1(gen, steps, spec.q_phi)
    nuis = _ar1(gen, steps, spec.nuisance_phi, (len(fine),)) * spec.nuisance_sd
    a = coarse_matrix(m, spec.coarse_damping)
    b = torch.randn(2 * m, generator=gen, dtype=torch.float64)
    b = spec.forcing * b / b.norm() * math.sqrt(2 * m)
    c = torch.zeros(steps, 2 * m, dtype=torch.float64)
    for t in range(steps - 1):
        c[t + 1] = a @ c[t] + b * q[t] + spec.coarse_noise * torch.randn(2 * m, generator=gen, dtype=torch.float64)

    s = coarse_field(c, n)
    target_excess = torch.zeros(steps, len(fine), dtype=torch.float64)
    for j, mask in enumerate(fine):
        if j in structured and spec.mode != "gaussian":
            k = structured.index(j)
            e = (spec.excess0 + spec.excess_slope * q * z[k]).clamp_min(0.05)
            if spec.mode == "blowup":
                e = e * torch.exp(spec.blowup_rate * torch.arange(steps, dtype=torch.float64) / steps)
            gamma = e / filter_kurtosis_factor(mask, n)
            p = (3.0 / (3.0 + gamma)).clamp(min=spec.min_spikes / n, max=1.0)
            spikes = torch.rand(steps, n, generator=gen, dtype=torch.float64) < p[:, None]
            white = torch.randn(steps, n, generator=gen, dtype=torch.float64) * spikes
            target_excess[:, j] = e
        else:
            white = torch.randn(steps, n, generator=gen, dtype=torch.float64)
        comp = torch.fft.irfft(torch.fft.rfft(white) * mask.to(torch.complex128), n=n)
        sd = comp.std(dim=-1, keepdim=True).clamp_min(1e-12)
        var = spec.band_var * torch.exp(2 * nuis[:, j])
        s = s + comp / sd * var.sqrt()[:, None]
    return {"field": s, "coarse": c, "q": q, "target_excess": target_excess, "spec": spec.as_dict(),
            "A": a, "B": b}
