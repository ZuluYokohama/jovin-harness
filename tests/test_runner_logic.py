"""The parts of the in-container supervisor that don't need Linux: test discovery and the verdict."""

import importlib.util
import json
from pathlib import Path

import pytest

RUNNER = Path(__file__).parents[1] / "src" / "jovin_harness" / "sandbox_image" / "runner.py"
spec = importlib.util.spec_from_file_location("sandbox_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def events(*items):
    return b"".join(json.dumps(item).encode() + b"\n" for item in items)


def judge(raw, names, returncode=0):
    result = {}
    runner.judge(raw, names, returncode, result)
    return result


NAMES = ["<module>", "test_a", "test_b"]
GOOD = [{"event": "loaded"}, {"event": "test", "name": "<module>", "outcome": "passed"},
        {"event": "test", "name": "test_a", "outcome": "passed"},
        {"event": "test", "name": "test_b", "outcome": "passed"}, {"event": "done"}]


def test_expected_tests_in_definition_order():
    source = "import math\n\ndef test_b():\n    assert 1\n\ndef helper(x):\n    pass\n\ndef test_a(x=1):\n    pass\n"
    assert runner.expected_tests(source) == ["<module>", "test_b", "test_a"]


def test_module_level_asserts_count_as_tests():
    assert runner.expected_tests("assert 1 + 1 == 2\n") == ["<module>"]


@pytest.mark.parametrize("source", [
    "x = 1\n",
    "def test_a(x):\n    assert x\n",
    "async def test_a():\n    assert True\n",
    "def test_a(*, x):\n    assert x\n",
])
def test_unusable_tests_are_rejected(source):
    with pytest.raises(ValueError):
        runner.expected_tests(source)


def test_all_reported_passes_is_a_pass():
    result = judge(events(*GOOD), NAMES)
    assert result["status"] == "passed"
    assert result["passed_count"] == 3 and result["total"] == 3


def test_a_failed_test_fails():
    items = list(GOOD)
    items[3] = {"event": "test", "name": "test_b", "outcome": "failed", "message": "AssertionError at line 4"}
    result = judge(events(*items), NAMES)
    assert result["status"] == "failed"
    assert result["tests"][2]["message"] == "AssertionError at line 4"


def test_early_exit_is_not_a_pass():
    assert judge(events(*GOOD[:3]), NAMES)["status"] == "protocol_error"


def test_nonzero_exit_is_not_a_pass():
    assert judge(events(*GOOD), NAMES, returncode=1)["status"] == "protocol_error"


def test_duplicate_or_unknown_reports_are_not_a_pass():
    duplicate = GOOD[:2] + [GOOD[2], GOOD[2]] + GOOD[3:]
    assert judge(events(*duplicate), NAMES)["status"] == "protocol_error"
    unknown = GOOD[:4] + [{"event": "test", "name": "test_z", "outcome": "passed"}] + GOOD[4:]
    assert judge(events(*unknown), NAMES)["status"] == "protocol_error"


def test_missing_test_is_not_a_pass():
    assert judge(events(*(GOOD[:3] + GOOD[4:])), NAMES)["status"] == "protocol_error"


def test_garbage_and_late_events_are_not_a_pass():
    assert judge(events(*GOOD) + b"PASSED\n", NAMES)["status"] == "protocol_error"
    late = GOOD + [{"event": "test", "name": "test_a", "outcome": "passed"}]
    assert judge(events(*late), NAMES)["status"] == "protocol_error"


def test_never_loaded_is_not_a_pass():
    assert judge(events(*GOOD[1:]), NAMES)["status"] == "protocol_error"


def test_load_error_is_reported():
    result = judge(events({"event": "load_error", "message": "SyntaxError at line 1"}), NAMES)
    assert result == {"status": "error", "load_error": "SyntaxError at line 1"}


def test_module_failure_fails_without_needing_other_tests():
    items = [GOOD[0], {"event": "test", "name": "<module>", "outcome": "failed", "message": "boom"},
             {"event": "done"}]
    assert judge(events(*items), NAMES)["status"] == "failed"


@pytest.mark.parametrize("source", [
    "def check():\n    assert False\n",
    "class TestThing:\n    def test_x(self):\n        assert False\n",
    "f = lambda: None\nassert_ok = True\n",
])
def test_asserts_that_never_run_are_not_tests(source):
    with pytest.raises(ValueError):
        runner.expected_tests(source)


def test_module_level_asserts_inside_blocks_count():
    assert runner.expected_tests("for x in range(3):\n    assert x >= 0\n") == ["<module>"]
    assert runner.expected_tests("if True:\n    assert 1\n") == ["<module>"]


@pytest.mark.parametrize("source", [
    "def test_x():\n    yield\n    assert False\n",
    "def test_x():\n    yield from range(1)\n",
])
def test_generator_tests_are_rejected(source):
    with pytest.raises(ValueError, match="generator"):
        runner.expected_tests(source)


def test_nested_generators_inside_a_test_are_fine():
    source = "def test_x():\n    def gen():\n        yield 1\n    assert list(gen()) == [1]\n"
    assert runner.expected_tests(source) == ["<module>", "test_x"]


codec = {}
exec(runner.CODEC, codec)  # the codec both sides of the process boundary run


@pytest.mark.parametrize("value", [
    None, True, 0, -12345678901234567890, 1.5, float("inf"), "text é", b"\x00\xff",
    [1, [2, "x"]], (1, (2,)), {1, 2}, frozenset({"a"}), {"k": [1, 2], (1, 2): {3}},
    {"$t": "a dict whose key looks like a tag"},
])
def test_codec_round_trips_plain_data(value):
    import json
    wire = json.loads(json.dumps(codec["encode"](value), allow_nan=False))
    decoded = codec["decode"](wire)
    assert decoded == value and type(decoded) is type(value)


def test_codec_round_trips_nan():
    import math
    assert math.isnan(codec["decode"](codec["encode"](float("nan"))))


@pytest.mark.parametrize("value", [
    object(), print, (x for x in ()), type("Int", (int,), {})(3), [object()]])
def test_codec_refuses_anything_but_plain_data(value):
    with pytest.raises(codec["Unsupported"]):
        codec["encode"](value)


@pytest.mark.parametrize("wire", [
    {"$x": []}, {"$t": [], "$s": []}, {"$d": [[1]]}, {"$f": "1.0"}, {"$b": "!!"}, 1e999])
def test_codec_rejects_malformed_wire_values(wire):
    with pytest.raises((ValueError, TypeError)):
        codec["decode"](wire)


def test_codec_limits_depth():
    deep = []
    for _ in range(100):
        deep = [deep]
    with pytest.raises(codec["Unsupported"]):
        codec["encode"](deep)


def test_exported_names_come_from_the_code_syntax():
    source = ("import math\nLIMIT = 3\ndef add(a, b):\n    return a + b\nsquare = lambda x: x * x\n"
              "class Stack:\n    pass\nasync def fetch():\n    pass\n"
              "def _helper():\n    pass\ndef __dunder__():\n    pass\n")
    exports, unavailable = runner.exported_names(source)
    assert exports == ["add", "square", "_helper"]
    assert set(unavailable) == {"Stack", "fetch"}
    assert runner.exported_names("def broken(:\n") == ([], {})
