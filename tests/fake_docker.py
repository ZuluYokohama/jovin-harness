"""A scripted stand-in for the docker CLI, so sandbox logic can be tested without a container engine."""

import io
import json
import subprocess

from jovin_harness.sandbox import RESULT_FORMAT, RUN_LABEL, RUNNER_LABEL, CommandResult, runner_sha256

IMAGE = "sha256:" + "c" * 64


def ok(payload=b"", stderr=b""):
    if not isinstance(payload, bytes):
        payload = json.dumps(payload).encode()
    return CommandResult(0, payload, stderr)


def fail(stderr=b"error"):
    return CommandResult(1, b"", stderr)


def container_inspect(settings, run_id):
    limits = settings.limits
    return {
        "Image": settings.image,
        "Mounts": [],
        "Config": {"User": "0:0", "Labels": {RUN_LABEL: run_id}},
        "HostConfig": {
            "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapDrop": ["ALL"], "CapAdd": ["CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_CHOWN"],
            "SecurityOpt": ["no-new-privileges"],
            "Memory": limits.memory_bytes, "MemorySwap": limits.memory_bytes,
            "PidsLimit": limits.pids, "NanoCpus": int(limits.cpus * 1e9),
            "LogConfig": {"Type": "none", "Config": {}},
            "Binds": None, "Devices": [], "Mounts": None,
            "Tmpfs": {"/tmp": f"rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes}"},
            "Ulimits": [{"Name": "nofile", "Soft": limits.nofile, "Hard": limits.nofile},
                        {"Name": "core", "Soft": 0, "Hard": 0},
                        {"Name": "fsize", "Soft": limits.fsize_bytes, "Hard": limits.fsize_bytes}],
        },
    }


def passing_result(settings):
    return {"format": RESULT_FORMAT, "status": "passed", "mode": "verify", "isolation": "process", "exit_code": 0,
            "tests": [{"name": "<module>", "outcome": "passed", "message": ""}], "total": 1,
            "passed_count": 1, "stdout_tail": "", "stderr_tail": "", "timed_out": False,
            "kernel": {"memory_max": str(settings.limits.memory_bytes), "pids_max": str(settings.limits.pids),
                       "worker": {"uid": ["65534"] * 4}}}


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", hang=False):
        self.stdin = io.BytesIO()
        self.stdin.close = lambda: setattr(self, "stdin_closed", True)
        self.stdout, self.stderr = io.BytesIO(stdout), io.BytesIO(stderr)
        self.hang, self.killed = hang, False

    def wait(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("docker", timeout)
        return 0

    def kill(self):
        self.killed = True


class FakeDocker:
    """Answers docker CLI calls. Override attributes to script failures."""

    def __init__(self, settings, result=None, state=None):
        self.settings = settings
        self.calls = []
        self.engine = {"OSType": "linux", "ServerVersion": "27.0.0", "ID": "engine-1", "CgroupVersion": "2",
                       "SecurityOptions": ["name=seccomp,profile=builtin", "name=cgroupns"]}
        self.image = {"Id": settings.image, "Architecture": "amd64",
                      "Config": {"Labels": {RUNNER_LABEL: runner_sha256()}, "Volumes": None}}
        self.result = result
        self.state = state or {"ExitCode": 0, "OOMKilled": False}
        self.inspect_override = None
        self.removed = set()
        self.remove_fails = False
        self.process = None
        self.build_output = IMAGE.encode() + b"\n"
        self.build_input = None

    def _args(self, argv):
        return argv[len(self.settings.container_command):]

    def run(self, argv, *, input=None, timeout=60):
        args = self._args(argv)
        self.calls.append(args)
        match args:
            case ["info", *_]:
                return ok(self.engine)
            case ["image", "inspect", image]:
                return ok([self.image]) if image == self.settings.image else fail(b"No such image")
            case ["create", *rest]:
                self.created = rest[rest.index("--name") + 1]
                self.run_id = rest[rest.index("--label") + 1].split("=", 1)[1]
                return ok(b"0123abcd\n")
            case ["container", "inspect", "--format", _, name]:
                return ok(self.state)
            case ["container", "inspect", name]:
                if name in self.removed:
                    return fail(b"No such container")
                info = self.inspect_override or container_inspect(self.settings, self.run_id)
                return ok([info])
            case ["rm", "--force", name]:
                if not self.remove_fails:
                    self.removed.add(name)
                return ok()
            case ["kill", _]:
                return ok()
            case ["ps", *_]:
                return ok(b"aaa\nbbb\n")
            case ["build", *_]:
                self.build_input = input
                return ok(self.build_output)
        raise AssertionError(f"unexpected docker call: {args}")

    def start(self, argv):
        self.calls.append(self._args(argv))
        if self.process is None:
            out = b"" if self.result is None else json.dumps(self.result).encode() + b"\n"
            self.process = FakeProcess(stdout=out)
        return self.process
