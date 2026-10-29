import numpy as np
import pytest

torch = pytest.importorskip("torch")

from jovin_harness.cumulant.bands import band_decompose, band_masks, band_moments, dyadic_edges  # noqa: E402
from jovin_harness.cumulant.closure import build_pair  # noqa: E402
from jovin_harness.cumulant.operators import (  # noqa: E402
    CumulantScaleDerivative,
    assert_equal_capacity,
    capacity,
    matched_pair,
)

EDGES = [1, 4, 8, 16, 32, 64, 128, 256]


def test_dyadic_edges():
    assert dyadic_edges(512) == [1, 2, 4, 8, 16, 32, 64, 128, 256]
    assert dyadic_edges(64, first=4) == [4, 8, 16, 32]


@pytest.mark.parametrize("shape,edges", [((512,), EDGES), ((64, 64), [1, 2, 4, 8, 16, 32]), ((63, 50), [1, 3, 9, 25])])
def test_bands_partition_and_reconstruct(shape, edges):
    masks = band_masks(shape, edges)
    assert masks.sum(0).max() <= 1
    x = torch.randn(3, *shape, dtype=torch.float64, generator=torch.Generator().manual_seed(0))
    b = band_decompose(x, masks, len(shape))
    assert b.shape == (3, len(edges) - 1, *shape)
    covered = masks.any(0)
    dims = tuple(range(-len(shape), 0))
    z = torch.fft.rfftn(x, dim=dims) * covered
    expect = torch.fft.irfftn(z, s=shape, dim=dims)
    assert torch.allclose(b.sum(1), expect, atol=1e-10)


def test_moments_match_numpy_and_pearson():
    g = np.random.default_rng(1)
    x = g.standard_t(3, size=(5, 4, 300))
    m = band_moments(torch.tensor(x), 1)
    c = x - x.mean(-1, keepdims=True)
    mu2, mu3, mu4 = (c**2).mean(-1), (c**3).mean(-1), (c**4).mean(-1)
    assert np.allclose(m["kappa2"], mu2)
    assert np.allclose(m["kappa4"], mu4 - 3 * mu2**2)
    assert np.allclose(m["skew"], mu3 / mu2**1.5)
    assert np.allclose(m["kurt"], mu4 / mu2**2)
    assert np.allclose(m["excess"], m["kurt"] - 3)
    assert (m["kurt"] - m["skew"] ** 2 - 1).min() >= -1e-12  # Pearson bound holds for plug-in moments


@pytest.mark.parametrize("shape,edges", [((512,), EDGES), ((32, 32), [1, 2, 4, 8, 16])])
@pytest.mark.parametrize("standardized", [True, False])
def test_equal_capacity(shape, edges, standardized):
    o2, o4 = matched_pair(shape, edges, standardized)
    assert capacity(o2) == capacity(o4)
    assert capacity(o2)[0] == 2 * (len(edges) - 2)
    assert o2.channels == o4.channels == len(edges) - 2
    x = torch.randn(2, *shape, dtype=torch.float64, generator=torch.Generator().manual_seed(1))
    assert o2(x).shape == o4(x).shape == (2, len(edges) - 2)
    m2, m4 = build_pair(o2, o4, 6, 8, seed=3)
    assert capacity(m2) == capacity(m4)
    assert sum(p.numel() for p in m2.parameters()) == sum(p.numel() for p in m4.parameters())
    # identical initial weights apart from the operator order
    for (n2, p2), (n4, p4) in zip(m2.named_parameters(), m4.named_parameters(), strict=True):
        assert n2 == n4 and torch.equal(p2, p4)


def test_capacity_mismatch_raises():
    a = CumulantScaleDerivative(2, (64,), [1, 2, 4, 8, 16, 32])
    b = CumulantScaleDerivative(4, (64,), [1, 2, 4, 8, 32])
    with pytest.raises(AssertionError):
        assert_equal_capacity(a, b)


def test_raw_operators_are_band_finite_differences():
    x = torch.randn(4, 512, dtype=torch.float64, generator=torch.Generator().manual_seed(2)) ** 3
    o2, o4 = matched_pair((512,), EDGES, standardized=False)
    m = band_moments(band_decompose(x, band_masks((512,), EDGES), 1), 1)
    assert torch.allclose(o2.raw(x), m["kappa2"][:, 1:] - m["kappa2"][:, :-1])
    assert torch.allclose(o4.raw(x), m["kappa4"][:, 1:] - m["kappa4"][:, :-1])
    s2, s4 = matched_pair((512,), EDGES, standardized=True)
    assert torch.allclose(s4.raw(x), (m["excess"][:, 1:] - m["excess"][:, :-1]), atol=1e-8)
    assert torch.allclose(s2.raw(x), torch.log(m["kappa2"][:, 1:]) - torch.log(m["kappa2"][:, :-1]), atol=1e-9)
    # identity affine at init
    assert torch.allclose(o4(x), o4.raw(x))


def test_standardized_operators_are_amplitude_invariant():
    x = torch.randn(3, 512, dtype=torch.float64, generator=torch.Generator().manual_seed(4)) ** 3
    o2, o4 = matched_pair((512,), EDGES)
    assert torch.allclose(o4.raw(7.5 * x), o4.raw(x), atol=1e-8)
    assert torch.allclose(o2.raw(7.5 * x), o2.raw(x), atol=1e-8)
