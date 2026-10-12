import os

import pytest

from jovin_harness.config import load_settings
from jovin_harness.sandbox import Sandbox


def pytest_collection_modifyitems(config, items):
    """Container tests need a real engine; run them only when asked with `-m container`."""
    if "container" in (config.getoption("-m") or ""):
        return
    skip = pytest.mark.skip(reason="needs a container engine; run with -m container")
    for item in items:
        if "container" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def sandbox(tmp_path_factory):
    """A real sandbox, with the image built once per session into a temporary data directory.

    Uses JOVIN_HARNESS_RUNTIME / JOVIN_HARNESS_CONTAINER_ARGV like the server does.
    """
    env = dict(os.environ, JOVIN_HARNESS_DATA_DIR=str(tmp_path_factory.mktemp("harness")))
    env.pop("JOVIN_HARNESS_IMAGE", None)
    box = Sandbox(load_settings(env))
    box.build_image()
    assert box.status()["ready"], box.status()["problems"]
    return box
