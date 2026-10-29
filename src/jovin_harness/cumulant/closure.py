"""Learned coarse surrogate dynamics ``T~`` conditioned on O2 or O4 features, and closure defect.

``T~`` maps the coarse state ``c_t = R s_t`` and the operator features ``phi_t = O(s_t)`` of the
observed stream to ``c_{t+1} = c_t + W [c_t, tanh(V phi_t)] + b``. The O2 and O4 surrogates are the
same class with the same operator capacity, so their parameter counts are identical. Rollouts are
autonomous in the coarse state; the features are the exogenous conditioning stream, so the
closure defect is ``e_t = ||R(T^t s0) - T~^t(R s0)||`` for ``t = 1..H``.
"""

from __future__ import annotations

import torch
from torch import nn

from .operators import CumulantScaleDerivative, assert_equal_capacity


class ClosureModel(nn.Module):
    def __init__(self, operator: CumulantScaleDerivative, coarse_dim: int, hidden: int = 8):
        super().__init__()
        self.operator = operator
        self.embed = nn.Linear(operator.channels, hidden, dtype=torch.float64)
        self.step = nn.Linear(coarse_dim + hidden, coarse_dim, dtype=torch.float64)
        self.register_buffer("feat_mean", torch.zeros(operator.channels, dtype=torch.float64))
        self.register_buffer("feat_std", torch.ones(operator.channels, dtype=torch.float64))

    def features(self, raw: torch.Tensor) -> torch.Tensor:
        z = (raw - self.feat_mean) / self.feat_std
        return torch.tanh(self.embed(z * self.operator.weight + self.operator.bias))

    def forward(self, c: torch.Tensor, raw: torch.Tensor) -> torch.Tensor:
        return c + self.step(torch.cat([c, self.features(raw)], dim=-1))


def build_pair(o2: CumulantScaleDerivative, o4: CumulantScaleDerivative, coarse_dim: int, hidden: int, seed: int):
    torch.manual_seed(seed)
    m2 = ClosureModel(o2, coarse_dim, hidden)
    torch.manual_seed(seed)  # identical initial weights for everything but the operator order
    m4 = ClosureModel(o4, coarse_dim, hidden)
    assert_equal_capacity(m2, m4)
    return m2, m4


def train(model: ClosureModel, coarse: torch.Tensor, raw: torch.Tensor, steps: int, lr: float,
          weight_decay: float = 1e-4, val_frac: float = 0.25, check_every: int = 10) -> dict:
    """Full-batch one-step training on ``(c_t, raw_t) -> c_{t+1}`` with early stopping.

    The last ``val_frac`` of the training segment is a validation tail (still before the held-out
    segment). The state with the lowest validation one-step loss is kept, which applies the same
    shrinkage to useless features for both operators. Deterministic on CPU.
    """
    n = coarse.shape[0] - 1
    fit = int(n * (1 - val_frac))
    model.feat_mean.copy_(raw[:fit].mean(0))
    model.feat_std.copy_(raw[:fit].std(0).clamp_min(1e-9))
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)

    def loss_on(a: int, b: int) -> torch.Tensor:
        return ((model(coarse[a:b], raw[a:b]) - coarse[a + 1:b + 1]) ** 2).sum(-1).mean()

    best = (float("inf"), 0, {k: v.clone() for k, v in model.state_dict().items()})
    for i in range(1, steps + 1):
        opt.zero_grad()
        loss = loss_on(0, fit)
        loss.backward()
        opt.step()
        if i % check_every == 0 or i == steps:
            with torch.no_grad():
                val = float(loss_on(fit, n))
            if val < best[0]:
                best = (val, i, {k: v.clone() for k, v in model.state_dict().items()})
    model.load_state_dict(best[2])
    return {"best_val_loss": best[0], "best_step": best[1]}


@torch.no_grad()
def rollout_defect(model: ClosureModel, coarse: torch.Tensor, raw: torch.Tensor, starts: torch.Tensor,
                   horizon: int) -> tuple[torch.Tensor, torch.Tensor]:
    """Defects ``(n_starts, horizon)`` and predicted trajectories ``(n_starts, horizon, d)``."""
    c = coarse[starts].clone()
    errs, traj = [], []
    for t in range(1, horizon + 1):
        c = model(c, raw[starts + t - 1])
        traj.append(c)
        errs.append((c - coarse[starts + t]).norm(dim=-1))
    return torch.stack(errs, 1), torch.stack(traj, 1)


def block_bootstrap_ci(x: torch.Tensor, block: int, reps: int, seed: int, level: float,
                       ratio_den: torch.Tensor | None = None) -> tuple[float, float, float]:
    """Moving-block bootstrap of ``mean(x)`` (or ``mean(x) / mean(den)``); returns (est, lo, hi)."""
    n = x.shape[0]
    block = max(1, min(block, n))
    nblocks = -(-n // block)
    g = torch.Generator().manual_seed(int(seed))
    starts = torch.randint(0, n - block + 1, (reps, nblocks), generator=g)
    idx = (starts[:, :, None] + torch.arange(block)[None, None, :]).reshape(reps, -1)[:, :n]
    num = x[idx].mean(1)
    if ratio_den is None:
        est, stats = float(x.mean()), num
    else:
        est, stats = float(x.mean() / ratio_den.mean()), num / ratio_den[idx].mean(1)
    a = (1 - level) / 2
    q = torch.quantile(stats, torch.tensor([a, 1 - a], dtype=stats.dtype))
    return est, float(q[0]), float(q[1])
