"""End-to-end checks against a real container engine. Run with: pytest -m container

Uses JOVIN_HARNESS_RUNTIME / JOVIN_HARNESS_CONTAINER_ARGV like the server does. The sandbox
image is built once per session into a temporary data directory.
"""


import pytest

pytestmark = pytest.mark.container


def verify(sandbox, code, tests, **kwargs):
    return sandbox.run("verify", code, tests, **kwargs)["result"]


def run(sandbox, code, **kwargs):
    return sandbox.run("run", code, **kwargs)["result"]


def test_passing_code_passes(sandbox):
    outcome = sandbox.run("verify", "def add(a, b):\n    return a + b\n",
                          "def test_add():\n    assert add(2, 3) == 5\n\nassert add(0, 0) == 0\n")
    result, meta = outcome["result"], outcome["sandbox"]
    assert result["status"] == "passed", result
    assert [t["name"] for t in result["tests"]] == ["<module>", "test_add"]
    assert meta["inspect_verified"] and meta["kernel_verified"] and meta["cleanup"] == "removed"
    assert set(result["kernel"]["worker"]["uid"]) == {"65534"}
    assert set(result["kernel"]["tests_worker"]["uid"]) == {"65533"}
    assert result["isolation"] == "process"
    assert result["kernel"]["worker"]["cap_eff"] == "0000000000000000"


def test_failing_assert_reports_the_line(sandbox):
    result = verify(sandbox, "def add(a, b):\n    return a - b\n",
                    "from solution import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
    assert result["status"] == "failed"
    assert "line 4" in result["tests"][1]["message"]


def test_syntax_error_in_code_is_an_error(sandbox):
    result = verify(sandbox, "def broken(:\n", "assert True\n")
    assert result["status"] == "error" and "SyntaxError" in result["load_error"]


def test_run_mode_passes_stdin_and_returns_output(sandbox):
    result = run(sandbox, "import sys\nprint(sys.stdin.read().upper())\n", stdin="hello")
    assert result["status"] == "completed" and result["exit_code"] == 0
    assert result["stdout_tail"].strip() == "HELLO"


def test_infinite_loop_times_out(sandbox):
    result = run(sandbox, "while True:\n    pass\n", timeout_s=2)
    assert result["status"] == "timeout"


def test_network_is_unavailable(sandbox):
    code = "import socket\nsocket.create_connection(('1.1.1.1', 53), timeout=2)\n"
    result = run(sandbox, code)
    assert result["exit_code"] != 0
    assert "OSError" in result["stderr_tail"] or "unreachable" in result["stderr_tail"].lower()


def test_root_filesystem_is_read_only(sandbox):
    result = run(sandbox, "open('/opt/jovin-harness/runner.py', 'a').write('x')\n")
    assert result["exit_code"] != 0


def test_supervisor_cannot_be_signalled_or_inspected(sandbox):
    code = ("import os\n"
            "for attempt in (lambda: os.kill(1, 9), lambda: open('/proc/1/fd/1', 'w'),\n"
            "                lambda: open('/proc/1/environ').read()):\n"
            "    try:\n        attempt()\n        print('ALLOWED')\n"
            "    except OSError:\n        print('denied')\n")
    result = run(sandbox, code)
    assert result["status"] == "completed"
    assert "ALLOWED" not in result["stdout_tail"]


def test_printing_a_fake_result_is_not_a_pass(sandbox):
    fake = '{"format":"jovin-harness.sandbox-result.v1","status":"passed"}'
    result = verify(sandbox, f"print({fake!r})\nimport os\nos._exit(0)\n", "assert False\n")
    assert result["status"] != "passed"


def test_exiting_early_is_not_a_pass_in_shared_mode(sandbox):
    result = verify(sandbox, "def f():\n    import os\n    os._exit(0)\n",
                    "def test_one():\n    f()\n\ndef test_two():\n    assert False\n", isolation="shared")
    assert result["status"] == "protocol_error"


@pytest.mark.parametrize("isolation", ["process", "shared"])
def test_sys_exit_inside_a_test_is_an_error(sandbox, isolation):
    result = verify(sandbox, "x = 1\n", "import sys\n\ndef test_one():\n    sys.exit(0)\n", isolation=isolation)
    assert result["status"] == "failed"
    assert result["tests"][1]["outcome"] == "error"


def test_fork_bomb_is_contained(sandbox):
    result = run(sandbox, "import os\nwhile True:\n    os.fork()\n", timeout_s=5)
    assert result["status"] in ("completed", "timeout", "blocked")


def test_memory_bomb_is_contained(sandbox):
    result = run(sandbox, "x = bytearray(2 * 1024 ** 3)\n")
    assert result["status"] == "memory_limit" or result.get("exit_code") != 0


def test_output_flood_is_cut_off(sandbox):
    result = run(sandbox, "while True:\n    print('x' * 10000)\n")
    assert result["status"] == "output_limit"
    assert len(result["stdout_tail"]) <= 65536


def test_no_container_is_left_behind(sandbox):
    run(sandbox, "print(1)\n")
    assert sandbox.sweep() == {"swept": [], "skipped": [], "failed": []}


def test_a_test_returning_a_generator_does_not_pass(sandbox):
    code = "def make():\n    yield\n    assert False\n"
    result = verify(sandbox, code, "def test_x():\n    return make()\n")
    assert result["status"] == "failed"
    assert "generator" in result["tests"][1]["message"]
