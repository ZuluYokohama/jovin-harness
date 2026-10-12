import pytest


def pytest_collection_modifyitems(config, items):
    """Container tests need a real engine; run them only when asked with `-m container`."""
    if "container" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="needs a container engine; run with -m container")
    for item in items:
        if "container" in item.keywords:
            item.add_marker(skip)
