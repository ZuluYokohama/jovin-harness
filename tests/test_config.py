import os

import pytest

from jovin_harness.config import (
    ConfigError,
    Limits,
    container_command,
    load_settings,
    save_pinned_image,
)

IMAGE = "sha256:" + "a" * 64


def env(tmp_path, **values):
    return {"JOVIN_HARNESS_DATA_DIR": str(tmp_path), **values}


def test_defaults(tmp_path):
    settings = load_settings(env(tmp_path))
    assert settings.runtime == "docker"
    assert settings.container_command == ("docker",)
    assert settings.image is None
    assert settings.limits == Limits()
    assert settings.receipts_dir == tmp_path / "receipts"


def test_image_must_be_an_immutable_id(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(env(tmp_path, JOVIN_HARNESS_IMAGE="python:3.12"))
    assert load_settings(env(tmp_path, JOVIN_HARNESS_IMAGE=IMAGE)).image == IMAGE


def test_pinned_image_round_trips_through_config_toml(tmp_path):
    settings = load_settings(env(tmp_path, JOVIN_HARNESS_RUNTIME="podman"))
    save_pinned_image(settings, IMAGE)
    reloaded = load_settings(env(tmp_path))
    assert reloaded.image == IMAGE
    assert reloaded.runtime == "podman"


def test_environment_overrides_stored_config(tmp_path):
    save_pinned_image(load_settings(env(tmp_path)), IMAGE)
    other = "sha256:" + "b" * 64
    assert load_settings(env(tmp_path, JOVIN_HARNESS_IMAGE=other)).image == other


def test_limits_cannot_exceed_ceilings(tmp_path):
    with pytest.raises(ConfigError):
        load_settings(env(tmp_path, JOVIN_HARNESS_TIMEOUT_S="31"))
    with pytest.raises(ConfigError):
        Limits(max_output_bytes=10**6).validate()
    (tmp_path / "config.toml").write_text("[limits]\nnetwork = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown limits"):
        load_settings(env(tmp_path))


def test_custom_argv(tmp_path):
    settings = load_settings(env(tmp_path, JOVIN_HARNESS_CONTAINER_ARGV='["nerdctl", "--namespace", "x"]'))
    assert settings.runtime == "custom"
    assert settings.container_command == ("nerdctl", "--namespace", "x")
    for bad in ("nerdctl", "[]", '["", "x"]', "[1]"):
        with pytest.raises(ConfigError):
            load_settings(env(tmp_path, JOVIN_HARNESS_CONTAINER_ARGV=bad))


def test_unknown_runtime_is_rejected():
    with pytest.raises(ConfigError):
        container_command("runc")


@pytest.mark.skipif(os.name != "nt", reason="WSL runtime is Windows-only")
def test_wsl_runtime_skips_the_login_shell():
    argv = container_command("wsl:Docker-Distro@root")
    assert argv[0].lower().endswith("wsl.exe")
    assert argv[1:] == ("--distribution", "Docker-Distro", "--user", "root", "--exec", "docker")
    for bad in ("wsl:", "wsl:a b", "wsl:x@Root;rm"):
        with pytest.raises(ConfigError):
            container_command(bad)
