"""The tests-side call machinery of process isolation, exercised over real OS pipes."""

import importlib.util
import json
import os
import struct
import threading
from pathlib import Path

import pytest

RUNNER = Path(__file__).parents[1] / "src" / "jovin_harness" / "sandbox_image" / "runner.py"
spec = importlib.util.spec_from_file_location("sandbox_runner_proxies", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


@pytest.fixture
def side():
    """The tests-side namespace with its two pipes; returns (namespace, code_reads_fd, code_writes_fd)."""
    namespace = {"json": json, "os": os}
    exec(runner.CODEC + runner.PROXIES, namespace)
    requests_r, requests_w = os.pipe()
    responses_r, responses_w = os.pipe()
    namespace.update(requests=requests_w, responses=responses_r)
    yield namespace, requests_r, responses_w
    for fd in (requests_r, requests_w, responses_r, responses_w):
        try:
            os.close(fd)
        except OSError:
            pass


def reply(namespace, fd, message):
    """Write a reply from a thread: OS pipes hold only a few KiB, and nobody reads until the call."""
    threading.Thread(target=namespace["send_frame"], args=(fd, message), daemon=True).start()


def test_harness_failures_cannot_be_swallowed_by_except_exception(side):
    namespace, _, _ = side
    assert not issubclass(namespace["HarnessFailure"], Exception)
    stub = namespace["unavailable"]("Stack", "is a class; objects cannot cross the process boundary")
    with pytest.raises(namespace["HarnessFailure"], match="isolation='shared'"):
        try:
            stub()
        except Exception:  # what a sloppy test might write
            pytest.fail("a harness failure was swallowed")


@pytest.mark.parametrize("name, expected", [
    ("ValueError", ValueError), ("ZeroDivisionError", ZeroDivisionError), ("KeyError", KeyError),
    ("UnicodeDecodeError", UnicodeDecodeError), ("UnicodeEncodeError", UnicodeEncodeError),
    ("UnicodeTranslateError", UnicodeTranslateError),
])
def test_rebuild_returns_the_builtin_exception(side, name, expected):
    error = side[0]["rebuild"]({"type": name, "message": "boom"})
    assert type(error) is expected and "boom" in str(error)


@pytest.mark.parametrize("name", ["ExceptionGroup", "SystemExit", "KeyboardInterrupt", "NotABuiltin", "print"])
def test_rebuild_never_returns_anything_but_an_ordinary_exception(side, name):
    error = side[0]["rebuild"]({"type": name, "message": "boom"})
    assert isinstance(error, Exception) and not isinstance(error, (SystemExit, KeyboardInterrupt))


def test_a_matching_reply_returns_the_value(side):
    namespace, requests_r, responses_w = side
    add = namespace["proxy"]("add")
    reply(namespace, responses_w, {"id": 1, "ok": {"$t": [5, {"$i": format(10**5000, "x")}]}})
    assert add(2, 3) == (5, 10**5000)
    sent = namespace["recv_frame"](requests_r)
    assert sent["id"] == 1 and sent["call"] == "add" and namespace["decode"](sent["args"]) == [2, 3]


def test_a_mismatched_reply_breaks_the_channel(side):
    namespace, _, responses_w = side
    add = namespace["proxy"]("add")
    reply(namespace, responses_w, {"id": 99, "ok": 5})
    with pytest.raises(namespace["HarnessFailure"], match="does not match"):
        add(2, 3)
    reply(namespace, responses_w, {"id": 2, "ok": 5})
    with pytest.raises(namespace["HarnessFailure"], match="unusable"):
        add(2, 3)


def test_nested_json_reply_cannot_be_swallowed_and_breaks_channel(side):
    namespace, _, responses_w = side
    call = namespace["proxy"]("f")
    # This bounded depth also exceeds the C JSON recursion bound on Linux builds.
    payload = b"[" * 20000 + b"0" + b"]" * 20000

    def write_raw_reply():
        # Bypass JSON encoding: the hostile peer sends malformed raw frame bytes.
        frame = struct.pack(">I", len(payload)) + payload
        while frame:
            frame = frame[os.write(responses_w, frame):]

    writer = threading.Thread(target=write_raw_reply, daemon=True)
    writer.start()
    try:
        with pytest.raises(namespace["HarnessFailure"], match="malformed reply"):
            try:
                call()
            except Exception:
                pytest.fail("a response parser failure was swallowed")
    finally:
        writer.join(timeout=2)
    assert not writer.is_alive()

    # Even a subsequent valid reply cannot repair a poisoned channel.
    reply(namespace, responses_w, {"id": 2, "ok": None})
    with pytest.raises(namespace["HarnessFailure"], match="unusable"):
        call()


def test_raised_exceptions_cross_as_builtins(side):
    namespace, _, responses_w = side
    div = namespace["proxy"]("div")
    reply(namespace, responses_w, {"id": 1, "raised": {"type": "ZeroDivisionError", "message": "division by zero"}})
    with pytest.raises(ZeroDivisionError):
        div(1, 0)


def test_code_exiting_mid_call_is_a_harness_failure(side):
    namespace, _, responses_w = side
    os.close(responses_w)
    with pytest.raises(namespace["HarnessFailure"], match="exited during a call"):
        namespace["proxy"]("f")()


def test_unserializable_arguments_are_refused_before_sending(side):
    namespace, _, responses_w = side
    f = namespace["proxy"]("f")
    with pytest.raises(namespace["HarnessFailure"], match="argument"):
        f(object())
    reply(namespace, responses_w, {"id": 1, "ok": None})  # the channel is still usable
    assert f(1) is None


def test_big_ints_round_trip_and_bad_hex_is_rejected(side):
    namespace = side[0]
    value = -(10**6000) + 7
    assert namespace["decode"](json.loads(json.dumps(namespace["encode"](value)))) == value
    with pytest.raises(ValueError):
        namespace["decode"]({"$i": "not-hex"})


def test_user_defined_exceptions_arrive_as_their_builtin_base(side):
    error = side[0]["rebuild"]({"type": "InvalidInput", "builtin": "ValueError", "message": "negative"})
    assert type(error) is ValueError and str(error) == "InvalidInput: negative"
    fallback = side[0]["rebuild"]({"type": "Weird", "builtin": "SystemExit", "message": "x"})
    assert type(fallback) is RuntimeError
