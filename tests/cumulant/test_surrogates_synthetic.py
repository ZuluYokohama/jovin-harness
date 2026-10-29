import pytest

torch = pytest.importorskip("torch")

from jovin_harness.cumulant.bands import band_decompose, band_masks, band_moments  # noqa: E402
from jovin_harness.cumulant.surrogates import column_shuffle, iaaft, phase_randomize  # noqa: E402
from jovin_harness.cumulant.synthetic import (  # noqa: E402
    StreamSpec,
    coarse_field,
    filter_kurtosis_factor,
    generate,
    restrict,
)


def sparse(shape, seed=0, p=0.03):
    g = torch.Generator().manual_seed(seed)
    return torch.randn(shape, generator=g, dtype=torch.float64) * (torch.rand(shape, generator=g, dtype=torch.float64) < p)


@pytest.mark.parametrize("shape", [(512,), (511,), (32, 32), (31, 20)])
def test_phase_randomize_preserves_power_exactly(shape):
    x = sparse((4, *shape))
    nd = len(shape)
    y = phase_randomize(x, nd, seed=5)
    dims = tuple(range(-nd, 0))
    assert torch.allclose(torch.fft.rfftn(y, dim=dims).abs(), torch.fft.rfftn(x, dim=dims).abs(), atol=1e-9)
    assert not torch.allclose(x, y)
    assert torch.equal(phase_randomize(x, nd, seed=5), y)


def test_phase_randomize_pushes_kappa4_towards_zero():
    x = sparse((64, 512), p=0.01)
    edges = [1, 8, 32, 128, 256]
    mk = band_masks((512,), edges)
    ex = band_moments(band_decompose(x, mk, 1), 1)["excess"].mean(0)
    ey = band_moments(band_decompose(phase_randomize(x, 1, 1), mk, 1), 1)["excess"].mean(0)
    assert ex[-1] > 5
    assert ey.abs().max() < 0.3


@pytest.mark.parametrize("shape", [(256,), (24, 24)])
def test_iaaft_marginal_exact_spectrum_close(shape):
    x = sparse((3, *shape), p=0.1) + 0.1 * torch.randn(3, *shape, dtype=torch.float64,
                                                         generator=torch.Generator().manual_seed(8))
    nd = len(shape)
    spec, hist = iaaft(x, nd, seed=3, iterations=60)
    flat = lambda t: t.reshape(3, -1).sort(-1).values  # noqa: E731
    assert torch.equal(flat(hist), flat(x))
    dims = tuple(range(-nd, 0))
    a = torch.fft.rfftn(x, dim=dims).abs()
    assert torch.allclose(torch.fft.rfftn(spec, dim=dims).abs(), a, atol=1e-9)
    err = (torch.fft.rfftn(hist, dim=dims).abs() - a).norm() / a.norm()
    assert err < 0.2
    assert not torch.allclose(hist, x)


def test_column_shuffle_is_seeded_time_permutation():
    f = torch.arange(40, dtype=torch.float64).reshape(20, 2)
    s = column_shuffle(f, 9)
    assert torch.equal(s, column_shuffle(f, 9))
    assert not torch.equal(s, f)
    assert torch.equal(s[:, 0].sort().values, f[:, 0])
    assert torch.equal(s[:, 1] - s[:, 0], torch.ones(20, dtype=torch.float64))  # rows move together


def test_restrict_inverts_coarse_field():
    c = torch.randn(5, 6, dtype=torch.float64)
    assert torch.allclose(restrict(coarse_field(c, 128), 3), c, atol=1e-12)


def test_filter_kurtosis_factor_matches_empirical():
    n = 512
    mask = band_masks((n,), [1, 64, 256])[1]
    p = 0.02
    w = sparse((4000, n), seed=4, p=p)
    y = torch.fft.irfft(torch.fft.rfft(w) * mask, n=n)
    emp = band_moments(y, 1)["excess"].mean().item()
    pred = (3 / p - 3) * filter_kurtosis_factor(mask, n)
    assert abs(emp - pred) / pred < 0.15


def test_generator_deterministic_and_modes():
    a = generate(StreamSpec(seed=3, steps=200))
    b = generate(StreamSpec(seed=3, steps=200))
    assert torch.equal(a["field"], b["field"])
    assert torch.allclose(restrict(a["field"], 3), a["coarse"], atol=1e-10)
    g = generate(StreamSpec(mode="gaussian", seed=3, steps=200))
    mk = band_masks((512,), [1, 4, 8, 16, 32, 64, 128, 256])
    eg = band_moments(band_decompose(g["field"], mk, 1), 1)["excess"][:, 3:].mean(0)
    en = band_moments(band_decompose(a["field"], mk, 1), 1)["excess"][:, 3:].mean(0)
    # plug-in excess kurtosis is biased low on few effective samples (about -6/n), so allow it
    assert eg.max() < 0.05 and eg.min() > -0.3
    assert (en - eg).min() > 0.3
    with pytest.raises(ValueError):
        generate(StreamSpec(mode="nope"))
