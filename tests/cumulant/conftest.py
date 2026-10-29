import pytest

torch = pytest.importorskip("torch")
torch.set_num_threads(2)
