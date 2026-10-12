"""Run submitted code in a fresh, hardened container and return what the in-container supervisor saw.

Every call: create the container, inspect it and refuse to start unless the hardening actually
applied, start it with the payload on stdin, enforce a host-side deadline, read the single result
line, then force-remove the container. There is no fallback to running anything on the host.
"""

from __future__ import annotations

import io
import json
import os
import secrets
import struct
import subprocess
import tarfile
import threading
from dataclasses import dataclass
from importlib import resources
from typing import Protocol

from . import __version__
from .config import IMAGE_ID, Settings, save_pinned_image
from .receipts import sha256_hex

RUN_LABEL = "io.jovin-harness.run"
RUNNER_LABEL = "io.jovin-harness.runner-sha256"
VERSION_LABEL = "io.jovin-harness.version"
RESULT_FORMAT = "jovin-harness.sandbox-result.v1"
STARTUP_GRACE_S = 20  # container create/start, plus wsl.exe hops on Windows
MAX_RESULT_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024


class SandboxUnavailable(RuntimeError):
    """The sandbox cannot run safely right now. Nothing was executed."""


class InputTooLarge(ValueError):
    pass


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class Executor(Protocol):
    def run(self, argv: list[str], *, input: bytes | None = None, timeout: float = 60) -> CommandResult: ...

    def start(self, argv: list[str]) -> subprocess.Popen: ...


class SubprocessExecutor:
    def run(self, argv, *, input=None, timeout=60):
        try:
            done = subprocess.run(argv, input=input, capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError as error:
            raise SandboxUnavailable(f"container CLI not found: {argv[0]}") from error
        except subprocess.TimeoutExpired as error:
            raise SandboxUnavailable(f"container CLI timed out after {timeout:.0f}s: {' '.join(argv[:3])}") from error
        return CommandResult(done.returncode, done.stdout, done.stderr)

    def start(self, argv):
        try:
            return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as error:
            raise SandboxUnavailable(f"container CLI not found: {argv[0]}") from error


def image_files() -> dict[str, bytes]:
    base = resources.files("jovin_harness") / "sandbox_image"
    return {name: (base / name).read_bytes() for name in ("Dockerfile", "runner.py")}


def runner_sha256() -> str:
    return sha256_hex(image_files()["runner.py"])


def _context_tar(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime = len(data), 0o644, 0
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _tail(data: bytes, limit: int = 500) -> str:
    return data.decode("utf-8", errors="replace").strip()[-limit:]


def _clean_text(value):
    """Replace lone UTF-16 surrogates (valid in JSON escapes, invalid in UTF-8) with U+FFFD."""
    if isinstance(value, str):
        return value.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    if isinstance(value, list):
        return [_clean_text(item) for item in value]
    if isinstance(value, dict):
        return {_clean_text(key): _clean_text(item) for key, item in value.items()}
    return value


def _caps(values) -> set[str]:
    return {str(v).upper().removeprefix("CAP_") for v in (values or [])}


class Sandbox:
    def __init__(self, settings: Settings, executor: Executor | None = None):
        self.settings = settings
        self.executor = executor or SubprocessExecutor()
        self._engine: dict | None = None
        self._image: dict | None = None

    def cli(self, *args: str) -> list[str]:
        return [*self.settings.container_command, *args]

    def _json(self, *args: str, timeout: float = 60):
        done = self.executor.run(self.cli(*args), timeout=timeout)
        if done.returncode != 0:
            raise SandboxUnavailable(f"`{' '.join(args[:3])}` failed: {_tail(done.stderr)}")
        try:
            return json.loads(done.stdout)
        except json.JSONDecodeError as error:
            raise SandboxUnavailable(f"`{' '.join(args[:3])}` returned invalid JSON") from error

    # -- admission ---------------------------------------------------------------------------

    def engine_info(self) -> dict:
        if self._engine is None:
            info = self._json("info", "--format", "{{json .}}")
            options = [str(o) for o in info.get("SecurityOptions") or []]
            if info.get("OSType") != "linux":
                raise SandboxUnavailable(f"container engine runs {info.get('OSType')!r} containers, not linux")
            if not any("name=seccomp" in o for o in options) or any("unconfined" in o for o in options):
                raise SandboxUnavailable("container engine does not enforce a seccomp profile")
            docker_host = os.environ.get("DOCKER_HOST", "")
            self._engine = {
                "server_version": info.get("ServerVersion"),
                "engine_id": info.get("ID"),
                "os_type": info.get("OSType"),
                "cgroup_version": info.get("CgroupVersion"),
                "security_options": options,
                "docker_host": docker_host or None,
                "docker_host_local": not docker_host or docker_host.startswith(("unix://", "npipe://")),
            }
        return self._engine

    def image_info(self) -> dict:
        if self._image is None:
            image = self.settings.image
            if not image:
                raise SandboxUnavailable("no sandbox image is pinned; run `jovin-harness image build` first")
            info = self._json("image", "inspect", image)[0]
            if info.get("Id") != image:
                raise SandboxUnavailable("image inspect returned a different image ID than the pinned one")
            config = info.get("Config") or {}
            if config.get("Volumes"):
                raise SandboxUnavailable("sandbox image declares volumes, which would be writable")
            labels = config.get("Labels") or {}
            self._image = {"id": image, "runner_sha256": labels.get(RUNNER_LABEL),
                           "harness_version": labels.get(VERSION_LABEL),
                           "architecture": info.get("Architecture")}
        return self._image

    # -- container settings ------------------------------------------------------------------

    def create_args(self, name: str, run_id: str) -> list[str]:
        limits = self.settings.limits
        return [
            "create", "--pull", "never", "--name", name, "--label", f"{RUN_LABEL}={run_id}",
            "--interactive", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
            "--security-opt", "no-new-privileges", "--user", "0:0",
            "--memory", str(limits.memory_bytes), "--memory-swap", str(limits.memory_bytes),
            "--pids-limit", str(limits.pids), "--cpus", str(limits.cpus),
            "--ulimit", f"nofile={limits.nofile}:{limits.nofile}", "--ulimit", "core=0:0",
            "--ulimit", f"fsize={limits.fsize_bytes}:{limits.fsize_bytes}",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes}",
            "--log-driver", "none",
            self.settings.image or "",
        ]

    def validate_container(self, info: dict, run_id: str) -> list[str]:
        """Compare the created container's actual settings with what was requested."""
        limits, problems = self.settings.limits, []
        host = info.get("HostConfig") or {}
        config = info.get("Config") or {}

        def expect(label, actual, wanted):
            if actual != wanted:
                problems.append(f"{label} is {actual!r}, expected {wanted!r}")

        expect("image", info.get("Image"), self.settings.image)
        expect("user", config.get("User"), "0:0")
        expect("run label", (config.get("Labels") or {}).get(RUN_LABEL), run_id)
        expect("network", host.get("NetworkMode"), "none")
        expect("read-only root", host.get("ReadonlyRootfs"), True)
        expect("privileged", host.get("Privileged"), False)
        expect("dropped capabilities", _caps(host.get("CapDrop")), {"ALL"})
        expect("added capabilities", _caps(host.get("CapAdd")), {"SETUID", "SETGID", "KILL"})
        expect("memory", host.get("Memory"), limits.memory_bytes)
        expect("memory+swap", host.get("MemorySwap"), limits.memory_bytes)
        expect("pids limit", host.get("PidsLimit"), limits.pids)
        expect("cpus", host.get("NanoCpus"), int(round(limits.cpus * 1e9)))
        expect("log driver", (host.get("LogConfig") or {}).get("Type"), "none")
        security = [str(o) for o in host.get("SecurityOpt") or []]
        if not any(o.replace("=", ":") in ("no-new-privileges", "no-new-privileges:true") for o in security):
            problems.append("no-new-privileges is not set")
        if any("unconfined" in o for o in security):
            problems.append("a security profile is unconfined")
        for key in ("Binds", "Devices", "Mounts", "VolumesFrom"):
            if host.get(key):
                problems.append(f"{key} must be empty")
        if info.get("Mounts"):
            problems.append("container has mounts (for example image volumes)")
        tmpfs = host.get("Tmpfs") or {}
        options = set((tmpfs.get("/tmp") or "").split(","))
        if set(tmpfs) != {"/tmp"} or options != {"rw", "noexec", "nosuid", "nodev", f"size={limits.tmpfs_bytes}"}:
            problems.append(f"tmpfs is {tmpfs!r}")
        ulimits = {u.get("Name"): (u.get("Soft"), u.get("Hard")) for u in host.get("Ulimits") or []}
        expect("ulimits", ulimits, {"nofile": (limits.nofile, limits.nofile), "core": (0, 0),
                                    "fsize": (limits.fsize_bytes, limits.fsize_bytes)})
        return problems

    # -- execution ---------------------------------------------------------------------------

    def check_inputs(self, **fields: str | None) -> None:
        limit = self.settings.limits.max_input_bytes
        for name, value in fields.items():
            if value is not None and len(value.encode("utf-8")) > limit:
                raise InputTooLarge(f"{name} is larger than {limit} bytes")

    def run(self, mode: str, code: str, tests: str | None = None, stdin: str | None = None,
            timeout_s: int | None = None) -> dict:
        if mode not in ("verify", "run"):
            raise ValueError("mode must be verify or run")
        self.check_inputs(code=code, tests=tests, stdin=stdin)
        limits = self.settings.limits
        timeout_s = min(timeout_s or limits.timeout_s, limits.timeout_s)
        engine, image = self.engine_info(), self.image_info()
        if image["runner_sha256"] != runner_sha256():
            raise SandboxUnavailable("the pinned image was built from a different runner; "
                                     "run `jovin-harness image build` again")
        run_id = secrets.token_hex(8)
        name = f"jovin-harness-{run_id}"
        payload = json.dumps({"mode": mode, "code": code, "tests": tests, "stdin": stdin,
                              "timeout_s": timeout_s, "max_output_bytes": limits.max_output_bytes}).encode()
        sandbox = {"runtime": self.settings.runtime, "engine": engine, "image": image,
                   "limits": {**limits.as_dict(), "timeout_s": timeout_s}, "run_id": run_id,
                   "inspect_verified": False, "kernel_verified": False, "cleanup": "not_created"}

        created = self.executor.run(self.cli(*self.create_args(name, run_id)), timeout=60)
        if created.returncode != 0:
            raise SandboxUnavailable(f"could not create the sandbox container: {_tail(created.stderr)}")
        sandbox["cleanup"] = "pending"
        try:
            problems = self.validate_container(self._json("container", "inspect", name)[0], run_id)
            if problems:
                result = {"format": RESULT_FORMAT, "status": "blocked",
                          "reason": "container settings did not match the hardening profile",
                          "problems": problems}
            else:
                sandbox["inspect_verified"] = True
                result = self._start(name, payload, timeout_s)
                kernel = result.get("kernel") or {}
                sandbox["kernel_verified"] = (kernel.get("memory_max") == str(limits.memory_bytes)
                                              and kernel.get("pids_max") == str(limits.pids))
        finally:
            sandbox["cleanup"] = self._remove(name)
        if result.get("status") in ("passed", "completed"):
            if not sandbox["kernel_verified"]:
                result = {**result, "status": "blocked",
                          "reason": "the kernel did not confirm the container's memory and PID limits"}
            elif sandbox["cleanup"] != "removed":
                result = {**result, "status": "blocked", "reason": "the container could not be confirmed removed"}
        return {"result": result, "sandbox": sandbox}

    def _start(self, name: str, payload: bytes, timeout_s: int) -> dict:
        process = self.executor.start(self.cli("start", "--attach", "--interactive", name))
        stdout, stderr = bytearray(), bytearray()

        def pump(stream, sink, limit):
            while chunk := stream.read(65536):
                if len(sink) < limit:
                    sink.extend(chunk[: limit - len(sink)])

        def feed():
            try:
                process.stdin.write(struct.pack(">Q", len(payload)) + payload)
                process.stdin.close()
            except OSError:
                pass

        threads = [threading.Thread(target=pump, args=(process.stdout, stdout, MAX_RESULT_BYTES), daemon=True),
                   threading.Thread(target=pump, args=(process.stderr, stderr, MAX_STDERR_BYTES), daemon=True),
                   threading.Thread(target=feed, daemon=True)]
        for thread in threads:
            thread.start()
        host_timeout = False
        try:
            process.wait(timeout=timeout_s + STARTUP_GRACE_S)
        except subprocess.TimeoutExpired:
            host_timeout = True
            try:
                self.executor.run(self.cli("kill", name), timeout=30)
            except SandboxUnavailable:
                pass  # removal in run() still force-removes the container
            process.kill()
            process.wait(timeout=30)
        for thread in threads:
            thread.join(timeout=5)

        state = {}
        try:
            with_state = self.executor.run(
                self.cli("container", "inspect", "--format", "{{json .State}}", name), timeout=60)
            if with_state.returncode == 0:
                state = json.loads(with_state.stdout)
        except (SandboxUnavailable, json.JSONDecodeError):
            state = {}
        result = self._parse_result(bytes(stdout))
        if result is not None:
            return result
        if state.get("OOMKilled"):
            status, reason = "memory_limit", "the sandbox ran out of memory"
        elif host_timeout or state.get("ExitCode") == 124:
            status, reason = "timeout", "the sandbox did not finish in time"
        else:
            status, reason = "blocked", f"the sandbox produced no result: {_tail(bytes(stderr))}"
        return {"format": RESULT_FORMAT, "status": status, "reason": reason, "timed_out": status == "timeout",
                "exit_code": state.get("ExitCode")}

    @staticmethod
    def _parse_result(stdout: bytes) -> dict | None:
        lines = stdout.strip().splitlines()
        if len(lines) != 1:
            return None
        try:
            result = json.loads(lines[0])
        except json.JSONDecodeError:
            return None
        if not isinstance(result, dict) or result.get("format") != RESULT_FORMAT:
            return None
        return _clean_text(result)

    def _remove(self, name: str) -> str:
        """Force-remove the container; report "removed" only when the engine says it no longer exists."""
        try:
            self.executor.run(self.cli("rm", "--force", name), timeout=60)
            gone = self.executor.run(self.cli("container", "inspect", name), timeout=60)
        except SandboxUnavailable:
            return "unconfirmed"
        # Any other inspect failure (daemon unreachable, permissions) proves nothing about removal.
        missing = gone.returncode != 0 and b"no such" in gone.stderr.lower()
        return "removed" if missing else "unconfirmed"

    # -- maintenance -------------------------------------------------------------------------

    def sweep(self) -> list[str]:
        """Force-remove containers left behind by earlier runs (for example after a crash)."""
        listed = self.executor.run(self.cli("ps", "--all", "--quiet", "--filter", f"label={RUN_LABEL}"), timeout=60)
        if listed.returncode != 0:
            raise SandboxUnavailable(f"could not list containers: {_tail(listed.stderr)}")
        ids = listed.stdout.decode().split()
        for container in ids:
            self.executor.run(self.cli("rm", "--force", container), timeout=60)
        return ids

    def build_image(self) -> str:
        files = image_files()
        argv = self.cli("build", "--quiet", "--label", f"{RUNNER_LABEL}={sha256_hex(files['runner.py'])}",
                        "--label", f"{VERSION_LABEL}={__version__}", "-")
        done = self.executor.run(argv, input=_context_tar(files), timeout=1800)
        if done.returncode != 0:
            raise SandboxUnavailable(f"image build failed: {_tail(done.stderr, 2000)}")
        image = done.stdout.decode().strip().splitlines()[-1].strip() if done.stdout.strip() else ""
        if not IMAGE_ID.match(image):
            raise SandboxUnavailable(f"image build did not report an image ID: {image[:100]!r}")
        save_pinned_image(self.settings, image)
        self.settings = self.settings.with_image(image)
        self._image = None
        return image

    def status(self) -> dict:
        """Report readiness without running anything. Never raises."""
        report = {"runtime": self.settings.runtime, "command": list(self.settings.container_command),
                  "image": self.settings.image, "packaged_runner_sha256": runner_sha256(),
                  "limits": self.settings.limits.as_dict(), "ready": False, "problems": []}
        try:
            report["engine"] = self.engine_info()
        except SandboxUnavailable as error:
            report["problems"].append(str(error))
            return report
        try:
            image = self.image_info()
            report["image_info"] = image
            if image["runner_sha256"] != report["packaged_runner_sha256"]:
                report["problems"].append("the pinned image was built from a different runner; rebuild it")
        except SandboxUnavailable as error:
            report["problems"].append(str(error))
        report["ready"] = not report["problems"]
        return report
