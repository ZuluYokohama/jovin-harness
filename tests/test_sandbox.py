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
                 "--cap-add SETGID", "--cap-add KILL", "--cap-add CHOWN", "--security-opt no-new-privileges",
                 "--user 0:0",
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
    (("HostConfig", "CapAdd"), ["SETUID", "SETGID", "KILL", "CHOWN", "SYS_ADMIN"]),
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
    assert sandbox.sweep() == {"swept": ["aaa", "bbb"], "skipped": [], "failed": []}
    assert ["rm", "aaa"] in docker.calls


def test_cleanup_is_unconfirmed_when_inspect_fails_for_another_reason(settings):
    sandbox, docker = make(settings, result=passing_result(settings))
    original = docker.run

    def run(argv, **kwargs):
        args = argv[len(settings.container_command):]
        if args[:2] == ["container", "inspect"] and len(args) == 3 and args[2] in docker.removed:
            return fail(b"Cannot connect to the Docker daemon")
        return original(argv, **kwargs)

    docker.run = run
    outcome = sandbox.run("verify", "x=1", "assert x == 1")
    assert outcome["sandbox"]["cleanup"] == "unconfirmed"
    assert outcome["result"]["status"] == "blocked"


def test_lone_surrogates_in_output_are_replaced(settings):
    result = passing_result(settings)
    result["stdout_tail"] = "bad \ud800 text"
    result["tests"][0]["message"] = "\udfff"
    sandbox, _ = make(settings, result=result)
    outcome = sandbox.run("verify", "x=1", "assert x == 1")
    assert outcome["result"]["stdout_tail"] == "bad \ufffd text"
    assert outcome["result"]["tests"][0]["message"] == "\ufffd"
    outcome["result"]["stdout_tail"].encode("utf-8")


@pytest.mark.parametrize("kernel", [
    {}, {"memory_max": "max", "pids_max": "64"}, {"memory_max": "536870912", "pids_max": "max"}])
def test_unconfirmed_kernel_limits_downgrade_a_pass(settings, kernel):
    result = dict(passing_result(settings), kernel=kernel)
    sandbox, _ = make(settings, result=result)
    outcome = sandbox.run("verify", "x=1", "assert x == 1")
    assert not outcome["sandbox"]["kernel_verified"]
    assert outcome["result"]["status"] == "blocked"
    assert "memory and PID limits" in outcome["result"]["reason"]


def test_payload_carries_isolation_and_mismatch_is_blocked(settings):
    sandbox, docker = make(settings, result=dict(passing_result(settings), isolation="shared"))
    outcome = sandbox.run("verify", "x=1", "assert x == 1")  # process isolation requested by default
    sent = docker.process.stdin.getvalue()
    (size,) = struct.unpack(">Q", sent[:8])
    assert json.loads(sent[8:8 + size])["isolation"] == "process"
    assert outcome["result"]["status"] == "blocked"
    assert "isolation" in outcome["result"]["reason"]


def test_a_pass_without_a_reported_isolation_is_blocked(settings):
    result = passing_result(settings)
    result.pop("isolation")
    sandbox, _ = make(settings, result=result)
    assert sandbox.run("verify", "x=1", "assert x == 1")["result"]["status"] == "blocked"


@pytest.mark.parametrize("state, expected", [
    ({"Status": "exited", "Running": False, "ExitCode": 137, "OOMKilled": True}, "memory_limit"),
    ({"Status": "exited", "Running": False, "ExitCode": 3, "OOMKilled": False}, "blocked"),
    ({"Status": "exited", "Running": False, "ExitCode": 124, "OOMKilled": False}, "timeout"),
    ({}, "blocked"),
    ({"Status": "running", "Running": True, "ExitCode": 0, "OOMKilled": False}, "blocked"),
])
def test_engine_failure_overrides_reported_pass(settings, state, expected):
    reported = passing_result(settings)
    sandbox, _ = make(settings, result=reported, state=state)
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == expected
    assert outcome["result"]["reported_result"] == reported
    assert outcome["sandbox"]["cleanup"] == "removed"


def test_host_deadline_overrides_reported_pass(settings):
    reported = passing_result(settings)
    sandbox, docker = make(settings)
    docker.process = FakeProcess(stdout=json.dumps(reported).encode(), hang=True)
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "timeout"
    assert outcome["result"]["reported_result"] == reported


@pytest.mark.parametrize("failure", ["timeout", "nonzero"])
@pytest.mark.parametrize("owned", [True, False])
def test_uncertain_creation_cleans_only_owned_container(settings, failure, owned):
    sandbox, docker = make(settings)
    original = docker.run

    def run(argv, **kwargs):
        answer = original(argv, **kwargs)
        if docker._args(argv)[0] == "create":
            if not owned:
                docker.inspect_override = container_inspect(settings, "unrelated")
            if failure == "timeout":
                raise SandboxUnavailable("CLI timed out after creating")
            return fail(b"CLI response failure")
        return answer

    docker.run = run
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert outcome["sandbox"]["cleanup"] == ("removed" if owned else "unconfirmed")
    assert not outcome["sandbox"]["execution_may_have_started"]
    assert any(call[0] == "rm" for call in docker.calls) is owned
    assert not any(call[0] == "start" for call in docker.calls)


def test_start_error_and_cleanup_exception_return_receiptable_failure(settings):
    sandbox, docker = make(settings)

    def start(argv):
        raise OSError("attach failed after start request")

    def remove(name):
        raise OSError("cleanup unavailable")

    docker.start = start
    sandbox._remove = remove
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert outcome["sandbox"]["execution_may_have_started"]
    assert outcome["sandbox"]["cleanup"] == "unconfirmed"
    assert "cleanup unavailable" in outcome["sandbox"]["cleanup_error"]
    timings = outcome["sandbox"]["timings_s"]
    assert set(timings) == {"preflight", "create_inspect", "execution", "cleanup"}
    assert all(value >= 0 for value in timings.values())


@pytest.mark.parametrize("status", ["running", "paused", "created", "restarting", "unknown"])
def test_sweep_skips_nonterminal_containers(settings, status):
    sandbox, docker = make(settings)
    docker.inspect_override = container_inspect(settings, "a" * 16)
    docker.inspect_override["State"] = {"Status": status, "Running": status == "running"}
    report = sandbox.sweep()
    assert len(report["skipped"]) == 2
    assert not report["swept"]
    assert not any(call[0] == "rm" for call in docker.calls)


@pytest.mark.parametrize("change", ["image", "label", "state"])
def test_sweep_skips_ambiguous_ownership_and_state(settings, change):
    sandbox, docker = make(settings)
    info = container_inspect(settings, "a" * 16)
    if change == "image":
        info["Image"] = "sha256:" + "e" * 64
    elif change == "label":
        info["Config"]["Labels"] = {}
    else:
        info["State"] = {"Status": "exited"}
    docker.inspect_override = info
    report = sandbox.sweep()
    assert len(report["skipped"]) == 2
    assert not any(call[0] == "rm" for call in docker.calls)


def test_sweep_reports_unconfirmed_removal(settings):
    sandbox, docker = make(settings)
    docker.remove_fails = True
    report = sandbox.sweep()
    assert report["swept"] == []
    assert len(report["failed"]) == 2


def test_invalid_utf8_supervisor_output_fails_closed(settings):
    sandbox, docker = make(settings)
    docker.process = FakeProcess(stdout=b"\xff")
    assert sandbox.run("verify", "x=1", "assert x")["result"]["status"] == "blocked"


@pytest.mark.parametrize("fault", ["attach_exit", "state_inspection", "output_stream"])
def test_host_transport_failure_cannot_accept_pass(settings, fault):
    reported = passing_result(settings)
    sandbox, docker = make(settings, result=reported)
    process = FakeProcess(stdout=json.dumps(reported).encode())
    docker.process = process
    if fault == "attach_exit":
        process.wait = lambda timeout: 1
    elif fault == "state_inspection":
        original = docker.run

        def run(argv, **kwargs):
            if "--format" in docker._args(argv) and "inspect" in docker._args(argv):
                return fail(b"engine unavailable")
            return original(argv, **kwargs)

        docker.run = run
    else:
        def read(size):
            raise OSError("broken stderr")

        process.stderr.read = read
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert outcome["result"]["reported_result"] == reported


def test_cleanup_exception_preserves_reported_pass_as_diagnostic(settings):
    reported = passing_result(settings)
    sandbox, _ = make(settings, result=reported)

    def remove(name):
        raise OSError("daemon unavailable")

    sandbox._remove = remove
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert outcome["result"]["reported_result"] == reported
    assert outcome["sandbox"]["cleanup"] == "unconfirmed"


def test_cleanup_error_is_recorded_by_harness(settings):
    from jovin_harness.receipts import ReceiptStore
    from jovin_harness.tools import Harness

    sandbox, _ = make(settings, result=passing_result(settings))

    def remove(name):
        raise OSError("cleanup failed")

    sandbox._remove = remove
    store = ReceiptStore(settings.receipts_dir)
    harness = Harness(settings=settings, sandbox=sandbox, store=store)
    response = harness.verify_python("x=1", "assert x")
    receipt = store.get(response["receipt_id"])
    assert response["passed"] is False
    assert receipt["sandbox"]["cleanup"] == "unconfirmed"
    assert receipt["result"]["reported_result"]["status"] == "passed"


def test_sweep_skips_newly_running_container_when_nonforce_remove_fails(settings):
    sandbox, docker = make(settings)
    original = docker.run

    def run(argv, **kwargs):
        if docker._args(argv)[0] == "rm":
            assert "--force" not in docker._args(argv)
            return fail(b"container is running")
        return original(argv, **kwargs)

    docker.run = run
    report = sandbox.sweep()
    assert report["swept"] == []
    assert len(report["failed"]) == 2


@pytest.mark.parametrize("state", [
    {"Status": "dead", "Running": False, "ExitCode": 0, "OOMKilled": False},
    {"Status": "exited", "Running": False, "ExitCode": 0, "OOMKilled": False, "Error": "engine error"},
])
def test_unclean_engine_termination_rejects_pass(settings, state):
    reported = passing_result(settings)
    sandbox, _ = make(settings, result=reported, state=state)
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert outcome["result"]["reported_result"] == reported


@pytest.mark.parametrize("phase", ["create", "wait", "cleanup"])
def test_interruption_is_receipted_and_cleanup_attempted(settings, phase):
    from jovin_harness.receipts import ReceiptStore
    from jovin_harness.tools import Harness

    sandbox, docker = make(settings, result=passing_result(settings))
    original = docker.run
    interrupted = False

    def run(argv, **kwargs):
        nonlocal interrupted
        answer = original(argv, **kwargs)
        if not interrupted and docker._args(argv)[0] == ("create" if phase == "create" else "rm"):
            interrupted = True
            raise KeyboardInterrupt()
        return answer

    if phase in ("create", "cleanup"):
        docker.run = run
    else:
        process = FakeProcess(stdout=json.dumps(passing_result(settings)).encode())
        original_wait = process.wait

        def wait(timeout=None):
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                raise KeyboardInterrupt()
            return original_wait(timeout)

        process.wait = wait
        docker.process = process
    store = ReceiptStore(settings.receipts_dir)
    harness = Harness(settings=settings, sandbox=sandbox, store=store)
    response = harness.verify_python("x=1", "assert x")
    receipt = store.get(response["receipt_id"])
    assert response["passed"] is False
    assert receipt["result"]["interrupted"] is True
    assert any(call[0] == "rm" for call in docker.calls)
    assert receipt["sandbox"]["cleanup"] == ("unconfirmed" if phase == "cleanup" else "removed")
    if phase == "wait":
        assert docker.process.killed


def test_system_exit_is_not_swallowed(settings):
    sandbox, docker = make(settings)

    def start(argv):
        raise SystemExit(2)

    docker.start = start
    with pytest.raises(SystemExit):
        sandbox.run("verify", "x=1", "assert x")
    assert any(call[0] == "rm" for call in docker.calls)


def test_failed_input_stream_is_closed_and_cannot_pass(settings):
    sandbox, docker = make(settings, result=passing_result(settings))
    process = FakeProcess(stdout=json.dumps(passing_result(settings)).encode())

    def write(payload):
        raise OSError("broken input pipe")

    process.stdin.write = write
    docker.process = process
    outcome = sandbox.run("verify", "x=1", "assert x")
    assert outcome["result"]["status"] == "blocked"
    assert process.stdin_closed
