"""Run submitted code in a fresh, hardened container and return what the in-container supervisor saw.

Every call: create the container, inspect it and refuse to start unless the hardening actually
applied, start it with the payload on stdin, enforce a host-side deadline, read the single result
line, then force-remove the container. There is no fallback to running anything on the host.
"""

from __future__ import annotations

import io
import json
import os
import re
import secrets
import struct
import subprocess
import tarfile
import threading
import time
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
            "--cap-drop", "ALL",
            "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL", "--cap-add", "CHOWN",
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
        expect("added capabilities", _caps(host.get("CapAdd")), {"SETUID", "SETGID", "KILL", "CHOWN"})
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
            timeout_s: int | None = None, isolation: str = "process") -> dict:
        if mode not in ("verify", "run"):
            raise ValueError("mode must be verify or run")
        if isolation not in ("process", "shared"):
            raise ValueError("isolation must be process or shared")
        began = time.monotonic()
        expected_isolation = isolation if mode == "verify" else "none"
        self.check_inputs(code=code, tests=tests, stdin=stdin)
        limits = self.settings.limits
        timeout_s = min(timeout_s or limits.timeout_s, limits.timeout_s)
        engine, image = self.engine_info(), self.image_info()
        if image["runner_sha256"] != runner_sha256():
            raise SandboxUnavailable("the pinned image was built from a different runner; "
                                     "run `jovin-harness image build` again")
        run_id = secrets.token_hex(8)
        name = f"jovin-harness-{run_id}"
        payload = json.dumps({"mode": mode, "isolation": isolation, "code": code, "tests": tests, "stdin": stdin,
                              "timeout_s": timeout_s, "max_output_bytes": limits.max_output_bytes}).encode()
        sandbox = {"runtime": self.settings.runtime, "engine": engine, "image": image,
                   "limits": {**limits.as_dict(), "timeout_s": timeout_s}, "run_id": run_id,
                   "inspect_verified": False, "kernel_verified": False, "cleanup": "not_created"}

        timings = {"preflight": time.monotonic() - began, "create_inspect": 0.0,
                   "execution": 0.0, "cleanup": 0.0}
        sandbox["timings_s"] = timings
        sandbox["execution_may_have_started"] = False
        result = {"format": RESULT_FORMAT, "status": "blocked", "reason": "container creation did not finish"}
        created_ok = False
        phase, phase_start = "create_inspect", time.monotonic()
        try:
            created = self.executor.run(self.cli(*self.create_args(name, run_id)), timeout=60)
            if created.returncode != 0:
                raise SandboxUnavailable(f"could not create the sandbox container: {_tail(created.stderr)}")
            created_ok = True
            sandbox["cleanup"] = "pending"
            problems = self.validate_container(self._json("container", "inspect", name)[0], run_id)
            if problems:
                result = {"format": RESULT_FORMAT, "status": "blocked",
                          "reason": "container settings did not match the hardening profile",
                          "problems": problems}
            else:
                sandbox["inspect_verified"] = True
                timings[phase] = time.monotonic() - phase_start
                phase, phase_start = "execution", time.monotonic()
                sandbox["execution_may_have_started"] = True
                result = self._start(name, payload, timeout_s)
                reported = result.get("isolation")
                if (reported is not None or result.get("status") in ("passed", "completed")) \
                        and reported != expected_isolation:
                    result = self._blocked(result, "the sandbox reported a different isolation mode than requested")
                kernel = result.get("kernel") or {}
                sandbox["kernel_verified"] = (kernel.get("memory_max") == str(limits.memory_bytes)
                                              and kernel.get("pids_max") == str(limits.pids))
        except KeyboardInterrupt:
            sandbox["interrupted"] = True
            result = {**self._blocked(result, "sandbox lifecycle interrupted"), "interrupted": True}
        except Exception as error:  # Lifecycle failures must still reach the receipt writer.
            result = self._blocked(result, f"sandbox lifecycle error: {type(error).__name__}: {error}")
        finally:
            timings[phase] = time.monotonic() - phase_start
            cleanup_start = time.monotonic()
            try:
                sandbox["cleanup"] = self._remove(name) if created_ok else self._remove_uncertain(name, run_id)
            except KeyboardInterrupt:
                sandbox["cleanup"] = "unconfirmed"
                sandbox["interrupted"] = True
                sandbox["cleanup_error"] = "KeyboardInterrupt during cleanup"
                result = {**self._blocked(result, "sandbox cleanup interrupted"), "interrupted": True}
            except Exception as error:
                sandbox["cleanup"] = "unconfirmed"
                sandbox["cleanup_error"] = f"{type(error).__name__}: {error}"
            timings["cleanup"] = time.monotonic() - cleanup_start
        if result.get("status") in ("passed", "completed"):
            if not sandbox["kernel_verified"]:
                result = self._blocked(result, "the kernel did not confirm the container's memory and PID limits")
            elif sandbox["cleanup"] != "removed":
                result = self._blocked(result, "the container could not be confirmed removed")
        return {"result": result, "sandbox": sandbox}

    @staticmethod
    def _blocked(result: dict, reason: str) -> dict:
        return {"format": RESULT_FORMAT, "status": "blocked", "reason": reason,
                "reported_result": result}

    def _remove_uncertain(self, name: str, run_id: str) -> str:
        inspected = self.executor.run(self.cli("container", "inspect", name), timeout=60)
        if self._missing(inspected):
            return "not_created"
        if inspected.returncode != 0:
            return "unconfirmed"
        info = json.loads(inspected.stdout)[0]
        if (info.get("Image") != self.settings.image
                or (info.get("Config", {}).get("Labels") or {}).get(RUN_LABEL) != run_id):
            return "unconfirmed"
        return self._remove(name)

    def _start(self, name: str, payload: bytes, timeout_s: int) -> dict:
        process = self.executor.start(self.cli("start", "--attach", "--interactive", name))
        result = {"format": RESULT_FORMAT, "status": "blocked", "reason": "attach did not finish"}
        try:
            result = self._attached(process, name, payload, timeout_s)
        except KeyboardInterrupt:
            result = {**self._blocked(result, "sandbox attach interrupted"), "interrupted": True}
        finally:
            # Reap our CLI even if interruption happens outside the normal wait path.
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=30)
            except (Exception, KeyboardInterrupt) as error:
                result = {**self._blocked(result, f"attach cleanup failed: {type(error).__name__}: {error}"),
                          "interrupted": isinstance(error, KeyboardInterrupt) or bool(result.get("interrupted"))}
        return result

    def _attached(self, process, name: str, payload: bytes, timeout_s: int) -> dict:
        stdout, stderr = bytearray(), bytearray()
        stream_errors = []

        def pump(stream, sink, limit):
            try:
                while chunk := stream.read(65536):
                    if len(sink) < limit:
                        sink.extend(chunk[: limit - len(sink)])
            except (OSError, ValueError) as error:
                stream_errors.append(f"output stream: {type(error).__name__}: {error}")
            finally:
                try:
                    stream.close()
                except (OSError, ValueError) as error:
                    stream_errors.append(f"output close: {type(error).__name__}: {error}")

        def feed():
            try:
                process.stdin.write(struct.pack(">Q", len(payload)) + payload)
            except (OSError, ValueError) as error:
                stream_errors.append(f"input stream: {type(error).__name__}: {error}")
            finally:
                try:
                    process.stdin.close()
                except (OSError, ValueError) as error:
                    stream_errors.append(f"input close: {type(error).__name__}: {error}")

        threads = [threading.Thread(target=pump, args=(process.stdout, stdout, MAX_RESULT_BYTES), daemon=True),
                   threading.Thread(target=pump, args=(process.stderr, stderr, MAX_STDERR_BYTES), daemon=True),
                   threading.Thread(target=feed, daemon=True)]
        for thread in threads:
            thread.start()
        host_timeout = False
        interrupted = False
        attach_exit = None
        lifecycle_errors = []
        try:
            attach_exit = process.wait(timeout=timeout_s + STARTUP_GRACE_S)
        except (Exception, KeyboardInterrupt) as error:
            interrupted = isinstance(error, KeyboardInterrupt)
            host_timeout = isinstance(error, subprocess.TimeoutExpired)
            if not host_timeout:
                lifecycle_errors.append(f"attach wait: {type(error).__name__}: {error}")
            try:
                self.executor.run(self.cli("kill", name), timeout=30)
            except (Exception, KeyboardInterrupt) as error:
                interrupted = interrupted or isinstance(error, KeyboardInterrupt)
                lifecycle_errors.append(f"container kill: {type(error).__name__}: {error}")
            try:
                process.kill()
                attach_exit = process.wait(timeout=30)
            except (Exception, KeyboardInterrupt) as error:
                interrupted = interrupted or isinstance(error, KeyboardInterrupt)
                lifecycle_errors.append(f"attach cleanup: {type(error).__name__}: {error}")
        for thread in threads:
            thread.join(timeout=5)

        state = {}
        try:
            with_state = self.executor.run(
                self.cli("container", "inspect", "--format", "{{json .State}}", name), timeout=60)
            if with_state.returncode == 0:
                state = json.loads(with_state.stdout)
        except Exception as error:
            lifecycle_errors.append(f"terminal state: {type(error).__name__}: {error}")
            state = {}
        if not isinstance(state, dict):
            state = {}
        result = self._parse_result(bytes(stdout))
        terminal = (state.get("Status") == "exited" and state.get("Running") is False
                    and type(state.get("ExitCode")) is int and type(state.get("OOMKilled")) is bool
                    and state.get("Error") in (None, ""))
        if interrupted:
            status, reason = "blocked", "sandbox execution interrupted"
        elif host_timeout:
            status, reason = "timeout", "the sandbox exceeded the host deadline"
        elif state.get("OOMKilled") is True:
            status, reason = "memory_limit", "the sandbox ran out of memory"
        elif state.get("ExitCode") == 124:
            status, reason = "timeout", "the sandbox did not finish in time"
        elif not terminal:
            status, reason = "blocked", "the container terminal state could not be confirmed"
        elif state["ExitCode"] != 0 or attach_exit != 0:
            status, reason = "blocked", "the supervisor or attach process exited abnormally"
        elif lifecycle_errors or stream_errors or any(thread.is_alive() for thread in threads):
            status, reason = "blocked", "the attach lifecycle or streams did not finish cleanly"
        elif result is not None:
            return result
        else:
            status, reason = "blocked", f"the sandbox produced no result: {_tail(bytes(stderr))}"
        failure = {"format": RESULT_FORMAT, "status": status, "reason": reason,
                   "timed_out": status == "timeout", "interrupted": interrupted,
                   "exit_code": state.get("ExitCode"),
                   "host_observation": {"state": state, "attach_exit_code": attach_exit,
                                        "host_timeout": host_timeout,
                                        "errors": lifecycle_errors + stream_errors}}
        if result is not None:
            failure["reported_result"] = result
        return failure

    @staticmethod
    def _parse_result(stdout: bytes) -> dict | None:
        lines = stdout.strip().splitlines()
        if len(lines) != 1:
            return None
        try:
            result = json.loads(lines[0])
        except (json.JSONDecodeError, UnicodeDecodeError):
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
        missing = self._missing(gone)
        return "removed" if missing else "unconfirmed"

    # -- maintenance -------------------------------------------------------------------------

    def sweep(self) -> dict:
        """Remove only identifiable stopped leftovers; never force-remove active containers."""
        listed = self.executor.run(
            self.cli("ps", "--all", "--quiet", "--no-trunc", "--filter", f"label={RUN_LABEL}"), timeout=60)
        if listed.returncode != 0:
            raise SandboxUnavailable(f"could not list containers: {_tail(listed.stderr)}")
        report = {"swept": [], "skipped": [], "failed": []}
        for container in listed.stdout.decode().split():
            try:
                info = self._json("container", "inspect", container)[0]
                label = (info.get("Config", {}).get("Labels") or {}).get(RUN_LABEL)
                state = info.get("State") or {}
                owned = (self.settings.image is not None and info.get("Image") == self.settings.image
                         and isinstance(label, str) and re.fullmatch(r"[0-9a-f]{16}", label))
                if not owned or state.get("Status") not in ("exited", "dead") or state.get("Running") is not False:
                    report["skipped"].append({"id": container, "reason": "active, ambiguous, or not owned"})
                    continue
                # Non-force removal also refuses a container started after our inspection.
                removed = self.executor.run(self.cli("rm", container), timeout=60)
                gone = self.executor.run(self.cli("container", "inspect", container), timeout=60)
                if self._missing(gone):
                    report["swept"].append(container)
                else:
                    report["failed"].append({"id": container, "reason": "removal unconfirmed",
                                             "error": _tail(removed.stderr)})
            except Exception as error:
                report["failed"].append({"id": container, "reason": f"{type(error).__name__}: {error}"})
        return report

    @staticmethod
    def _missing(result: CommandResult) -> bool:
        message = result.stderr.lower()
        return result.returncode != 0 and (b"no such container" in message or b"no such object" in message)

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
