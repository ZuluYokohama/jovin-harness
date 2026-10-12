import io
import json
import struct
import tarfile

import pytest
from fake_docker import IMAGE, FakeDocker, FakeProcess, container_inspect, fail, passing_result

from jovin_harness.config import load_settings
from jovin_harness.sandbox import InputTooLarge, Sandbox, SandboxUnavailable


@pytest.fixture
def settings(tmp_path):
    return load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path), "JOVIN_HARNESS_IMAGE": IMAGE})


def make(settings, **kwargs):
    docker = FakeDocker(settings, **kwargs)
    return Sandbox(settings, executor=docker), docker


def test_create_args_are_the_hardened_profile(settings):
    args = Sandbox(settings).create_args("jovin-harness-x", "x")
    joined = " ".join(args)
    for flag in ("--pull never", "--network none", "--read-only", "--cap-drop ALL", "--cap-add SETUID",
                 "--cap-add SETGID", "--security-opt no-new-privileges", "--user 0:0",
                 "--memory 536870912", "--memory-swap 536870912", "--pids-limit 64", "--cpus 1.0",
                 "--ulimit nofile=64:64", "--ulimit core=0:0", "--ulimit fsize=16777216:16777216",
                 "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16777216", "--log-driver none"):
        assert flag in joined, flag
    assert args[-1] == IMAGE
    assert "-v" not in args and "--volume" not in args and "--privileged" not in args


def test_matching_container_validates(settings):
    assert Sandbox(settings).validate_container(container_inspect(settings, "r1"), "r1") == []


@pytest.mark.parametrize("path, value", [
    (("HostConfig", "NetworkMode"), "bridge"),
    (("HostConfig", "ReadonlyRootfs"), False),
    (("HostConfig", "Privileged"), True),
    (("HostConfig", "CapAdd"), ["SETUID", "SETGID", "SYS_ADMIN"]),
    (("HostConfig", "SecurityOpt"), ["no-new-privileges", "seccomp=unconfined"]),
    (("HostConfig", "SecurityOpt"), []),
    (("HostConfig", "Memory"), 0),
    (("HostConfig", "PidsLimit"), None),
    (("HostConfig", "Binds"), ["/:/host"]),
    (("HostConfig", "Tmpfs"), {"/tmp": "rw,size=16777216"}),
    (("HostConfig", "Ulimits"), []),
    (("HostConfig", "LogConfig"), {"Type": "json-file"}),
    (("Mounts",), [{"Type": "volume", "Destination": "/data"}]),
    (("Image",), "sha256:" + "d" * 64),
    (("Config", "User"), "root"),
])
def test_any_deviation_is_reported(settings, path, value):
    info = container_inspect(settings, "r1")
    target = info
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert Sandbox(settings).validate_container(info, "r1")


def test_run_verifies_then_starts_then_removes(settings):
    sandbox, docker = make(settings, result=passing_result(settings))
    outcome = sandbox.run("verify", "def f():\n    return 1\n", "assert f() == 1\n")
    assert outcome["result"]["status"] == "passed"
    meta = outcome["sandbox"]
    assert meta["inspect_verified"] and meta["kernel_verified"]
    assert meta["cleanup"] == "removed"
    assert meta["engine"]["server_version"] == "27.0.0"
    order = [call[0] for call in docker.calls]
    assert order.index("create") < order.index("start") < order.index("rm")
    sent = docker.process.stdin.getvalue()
    (size,) = struct.unpack(">Q", sent[:8])
    payload = json.loads(sent[8:8 + size])
    assert payload["mode"] == "verify" and payload["tests"] == "assert f() == 1\n"


def test_mismatched_container_is_never_started(settings):
    sandbox, docker = make(settings, result=passing_result(settings))
    docker.inspect_override = {**container_inspect(settings, "x"), "Image": "sha256:" + "e" * 64}
    outcome = sandbox.run("verify", "x = 1", "assert x == 1")
    assert outcome["result"]["status"] == "blocked"
    assert not outcome["sandbox"]["inspect_verified"]
    assert all(call[0] != "start" for call in docker.calls)
    assert outcome["sandbox"]["cleanup"] == "removed"


def test_missing_result_with_oom_reports_memory_limit(settings):
    sandbox, _ = make(settings, result=None, state={"ExitCode": 137, "OOMKilled": True})
    outcome = sandbox.run("run", "x = 'a' * 10**10")
    assert outcome["result"]["status"] == "memory_limit"


def test_garbage_output_is_not_a_result(settings):
    sandbox, docker = make(settings)
    docker.process = FakeProcess(stdout=b'{"status":"passed"}\n')
    assert sandbox.run("verify", "x=1", "assert x")["result"]["status"] == "blocked"


def test_host_deadline_kills_the_container(settings, monkeypatch):
    monkeypatch.setattr("jovin_harness.sandbox.STARTUP_GRACE_S", 0)
    sandbox, docker = make(settings)
    docker.process = FakeProcess(hang=True)
    outcome = sandbox.run("run", "while True: pass", timeout_s=1)
    assert outcome["result"]["status"] == "timeout"
    assert ["kill", docker.created] in docker.calls


def test_unconfirmed_cleanup_downgrades_a_pass(settings):
    sandbox, docker = make(settings, result=passing_result(settings))
    docker.remove_fails = True
    outcome = sandbox.run("verify", "x=1", "assert x == 1")
    assert outcome["sandbox"]["cleanup"] == "unconfirmed"
    assert outcome["result"]["status"] == "blocked"


def test_inputs_are_capped_before_anything_runs(settings):
    sandbox, docker = make(settings)
    with pytest.raises(InputTooLarge):
        sandbox.run("verify", "x" * (256 * 1024 + 1), "assert True")
    assert docker.calls == []


def test_no_pinned_image_fails_closed(tmp_path):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path)})
    sandbox = Sandbox(settings, executor=FakeDocker(settings))
    with pytest.raises(SandboxUnavailable, match="image build"):
        sandbox.run("run", "print(1)")


def test_non_linux_engine_fails_closed(settings):
    sandbox, docker = make(settings)
    docker.engine["OSType"] = "windows"
    with pytest.raises(SandboxUnavailable):
        sandbox.run("run", "print(1)")
    assert all(call[0] != "create" for call in docker.calls)


def test_engine_without_seccomp_fails_closed(settings):
    sandbox, docker = make(settings)
    docker.engine["SecurityOptions"] = ["name=seccomp,profile=unconfined"]
    with pytest.raises(SandboxUnavailable):
        sandbox.engine_info()


def test_image_with_volumes_or_other_runner_is_refused(settings):
    sandbox, docker = make(settings)
    docker.image["Config"]["Volumes"] = {"/data": {}}
    with pytest.raises(SandboxUnavailable, match="volumes"):
        sandbox.image_info()
    sandbox, docker = make(settings)
    docker.image["Config"]["Labels"] = {}
    with pytest.raises(SandboxUnavailable, match="different runner"):
        sandbox.run("run", "print(1)")


def test_build_image_sends_context_and_pins_the_id(tmp_path):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path)})
    docker = FakeDocker(settings)
    sandbox = Sandbox(settings, executor=docker)
    assert sandbox.build_image() == IMAGE
    names = tarfile.open(fileobj=io.BytesIO(docker.build_input)).getnames()
    assert sorted(names) == ["Dockerfile", "runner.py"]
    assert load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path)}).image == IMAGE


def test_build_image_rejects_output_without_an_id(tmp_path):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path)})
    docker = FakeDocker(settings)
    docker.build_output = b"Successfully built\n"
    with pytest.raises(SandboxUnavailable):
        Sandbox(settings, executor=docker).build_image()


def test_status_reports_problems_without_raising(settings):
    sandbox, docker = make(settings)
    docker.run = lambda argv, **kw: fail(b"Cannot connect to the Docker daemon")
    report = sandbox.status()
    assert not report["ready"]
    assert "Cannot connect" in report["problems"][0]


def test_sweep_removes_labelled_leftovers(settings):
    sandbox, docker = make(settings)
    assert sandbox.sweep() == ["aaa", "bbb"]
    assert ["rm", "--force", "aaa"] in docker.calls
