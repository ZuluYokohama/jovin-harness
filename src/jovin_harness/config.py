"""Settings: which container runtime to use, which sandbox image, limits and the data directory.

Precedence, highest first: environment variables, ``<data_dir>/config.toml``, built-in defaults.
The data directory itself comes from ``JOVIN_HARNESS_DATA_DIR`` or the platform's user data dir.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

import platformdirs

KIB = 1024
MIB = 1024 * KIB

# Hard ceilings. Callers may lower limits but never raise them past these.
MAX_TIMEOUT_S = 30
MAX_INPUT_BYTES = 256 * KIB
MAX_OUTPUT_BYTES = 64 * KIB

IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_DISTRO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class ConfigError(ValueError):
    """The configuration is invalid; the harness refuses to run rather than guess."""


@dataclass(frozen=True)
class Limits:
    timeout_s: int = 10
    memory_bytes: int = 512 * MIB
    pids: int = 64
    cpus: float = 1.0
    tmpfs_bytes: int = 16 * MIB
    nofile: int = 64
    fsize_bytes: int = 16 * MIB
    max_input_bytes: int = MAX_INPUT_BYTES
    max_output_bytes: int = MAX_OUTPUT_BYTES

    def validate(self) -> Limits:
        if not 1 <= self.timeout_s <= MAX_TIMEOUT_S:
            raise ConfigError(f"timeout_s must be between 1 and {MAX_TIMEOUT_S}")
        if not 64 * MIB <= self.memory_bytes <= 2048 * MIB:
            raise ConfigError("memory_bytes must be between 64 MiB and 2 GiB")
        if not 8 <= self.pids <= 256:
            raise ConfigError("pids must be between 8 and 256")
        if not 0.1 <= self.cpus <= 4:
            raise ConfigError("cpus must be between 0.1 and 4")
        if not 1 * MIB <= self.tmpfs_bytes <= 64 * MIB:
            raise ConfigError("tmpfs_bytes must be between 1 MiB and 64 MiB")
        if not 16 <= self.nofile <= 1024:
            raise ConfigError("nofile must be between 16 and 1024")
        if not 1 * MIB <= self.fsize_bytes <= 64 * MIB:
            raise ConfigError("fsize_bytes must be between 1 MiB and 64 MiB")
        if not 1 <= self.max_input_bytes <= MAX_INPUT_BYTES:
            raise ConfigError(f"max_input_bytes must be at most {MAX_INPUT_BYTES}")
        if not 1 <= self.max_output_bytes <= MAX_OUTPUT_BYTES:
            raise ConfigError(f"max_output_bytes must be at most {MAX_OUTPUT_BYTES}")
        return self

    def as_dict(self) -> dict:
        return {
            "timeout_s": self.timeout_s,
            "memory_bytes": self.memory_bytes,
            "pids": self.pids,
            "cpus": self.cpus,
            "tmpfs_bytes": self.tmpfs_bytes,
            "nofile": self.nofile,
            "fsize_bytes": self.fsize_bytes,
            "max_input_bytes": self.max_input_bytes,
            "max_output_bytes": self.max_output_bytes,
        }


@dataclass(frozen=True)
class Settings:
    runtime: str
    container_command: tuple[str, ...]
    image: str | None
    data_dir: Path
    limits: Limits = field(default_factory=Limits)
    max_concurrency: int = 2

    @property
    def receipts_dir(self) -> Path:
        return self.data_dir / "receipts"

    @property
    def config_file(self) -> Path:
        return self.data_dir / "config.toml"

    def with_image(self, image: str) -> Settings:
        return replace(self, image=_check_image(image))


def _check_image(image: str) -> str:
    if not IMAGE_ID.match(image):
        raise ConfigError("image must be an immutable image ID of the form sha256:<64 hex>")
    return image


def container_command(spec: str) -> tuple[str, ...]:
    """Turn a runtime spec into the argv prefix that reaches a container CLI.

    ``docker`` and ``podman`` use the CLI on PATH. ``wsl:<distro>`` or ``wsl:<distro>@<user>``
    reaches a Docker CLI inside a WSL distribution without going through its login shell.
    """
    if spec in ("docker", "podman"):
        return (spec,)
    if spec.startswith("wsl:"):
        if os.name != "nt":
            raise ConfigError("the wsl runtime is only available on Windows")
        target = spec[4:]
        distro, _, user = target.partition("@")
        if not _DISTRO.match(distro) or (user and not _USER.match(user)):
            raise ConfigError(f"invalid WSL runtime spec: {spec!r}")
        wsl = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wsl.exe"
        argv = [str(wsl), "--distribution", distro]
        if user:
            argv += ["--user", user]
        return (*argv, "--exec", "docker")
    raise ConfigError(f"unknown container runtime {spec!r}; use docker, podman or wsl:<distro>")


def default_data_dir() -> Path:
    return Path(platformdirs.user_data_dir("jovin-harness", appauthor=False))


def _read_toml(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: {error}") from error


def load_settings(env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ if env is None else env)
    configured_dir = env.get("JOVIN_HARNESS_DATA_DIR")
    data_dir = Path(configured_dir) if configured_dir else default_data_dir()
    stored = _read_toml(data_dir / "config.toml")

    runtime = env.get("JOVIN_HARNESS_RUNTIME") or stored.get("runtime") or "docker"
    raw_argv = env.get("JOVIN_HARNESS_CONTAINER_ARGV")
    if raw_argv:
        try:
            argv = json.loads(raw_argv)
        except json.JSONDecodeError as error:
            raise ConfigError("JOVIN_HARNESS_CONTAINER_ARGV must be a JSON array of strings") from error
        if not (isinstance(argv, list) and argv and all(isinstance(part, str) and part for part in argv)):
            raise ConfigError("JOVIN_HARNESS_CONTAINER_ARGV must be a non-empty JSON array of strings")
        command = tuple(argv)
        runtime = "custom"
    else:
        command = container_command(runtime)

    image = env.get("JOVIN_HARNESS_IMAGE") or stored.get("image")
    if image is not None:
        image = _check_image(image)

    limit_values = dict(stored.get("limits", {}))
    if env.get("JOVIN_HARNESS_TIMEOUT_S"):
        limit_values["timeout_s"] = int(env["JOVIN_HARNESS_TIMEOUT_S"])
    unknown = set(limit_values) - set(Limits().as_dict())
    if unknown:
        raise ConfigError(f"unknown limits in config: {sorted(unknown)}")
    limits = Limits(**limit_values).validate()

    concurrency = int(env.get("JOVIN_HARNESS_MAX_CONCURRENCY") or stored.get("max_concurrency") or 2)
    if not 1 <= concurrency <= 8:
        raise ConfigError("max_concurrency must be between 1 and 8")

    return Settings(runtime=runtime, container_command=command, image=image, data_dir=data_dir,
                    limits=limits, max_concurrency=concurrency)


def save_pinned_image(settings: Settings, image: str) -> Path:
    """Record the image ID (and runtime) in ``config.toml`` so later runs use exactly that image."""
    image = _check_image(image)
    stored = _read_toml(settings.config_file)
    stored["image"] = image
    if settings.runtime != "custom":
        stored["runtime"] = settings.runtime
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.config_file.write_text(_dump_toml(stored), encoding="utf-8")
    return settings.config_file


def _dump_toml(values: dict) -> str:
    """Write the small, flat subset of TOML this file uses (scalars and one [limits] table)."""
    lines, tables = [], []
    for key, value in values.items():
        if isinstance(value, dict):
            tables.append((key, value))
        else:
            lines.append(f"{key} = {_toml_scalar(value)}")
    for name, table in tables:
        lines.append(f"\n[{name}]")
        lines.extend(f"{key} = {_toml_scalar(value)}" for key, value in table.items())
    return "\n".join(lines) + "\n"


def _toml_scalar(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise ConfigError(f"cannot store {type(value).__name__} in config.toml")
