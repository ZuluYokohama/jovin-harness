"""End-to-end checks of process isolation (the default verify mode). Run with: pytest -m container"""

import textwrap

import pytest

pytestmark = pytest.mark.container


def verify(sandbox, code, tests, **kwargs):
    return sandbox.run("verify", textwrap.dedent(code), textwrap.dedent(tests), **kwargs)["result"]


def test_code_cannot_signal_or_inspect_other_processes(sandbox):
    code = """
        import os, signal
        ATTEMPTS = []
        for pid in sorted(int(p) for p in os.listdir("/proc") if p.isdigit()):
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                ATTEMPTS.append(f"killed {pid}")
            except OSError:
                pass
            try:
                os.listdir(f"/proc/{pid}/fd")
                ATTEMPTS.append(f"listed fds of {pid}")
            except OSError:
                pass
            try:
                with open(f"/proc/{pid}/mem", "rb") as handle:
                    handle.read(1)
                ATTEMPTS.append(f"read memory of {pid}")
            except OSError:
                pass

        def add(a, b):
            return a + b
    """
    tests = """
        def test_nothing_escaped():
            assert ATTEMPTS == []

        assert add(2, 3) == 5
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "passed", result


def test_wrong_code_that_writes_fake_events_everywhere_still_fails(sandbox):
    code = """
        import os
        for fd in range(3, 256):
            for fake in (b'{"event": "test", "name": "test_add", "outcome": "passed"}\\n',
                         b'{"event": "done"}\\n'):
                try:
                    os.write(fd, fake)
                except OSError:
                    pass

        def add(a, b):
            return a - b
    """
    result = verify(sandbox, code, "def test_add():\n    assert add(2, 3) == 5\n")
    assert result["status"] != "passed", result


def test_code_exiting_mid_call_is_a_test_error(sandbox):
    code = """
        def f():
            import os
            os._exit(0)
    """
    tests = """
        def test_one():
            f()

        def test_two():
            assert True
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "failed"
    assert result["tests"][1]["outcome"] == "error"
    assert "exited during a call" in result["tests"][1]["message"]


def test_exceptions_cross_the_boundary_as_builtins(sandbox):
    tests = """
        def test_zero():
            try:
                div(1, 0)
            except ZeroDivisionError:
                pass
            else:
                assert False

        assert div(7, 2) == 3
    """
    assert verify(sandbox, "def div(a, b):\n    return a // b\n", tests)["status"] == "passed"


def test_plain_data_round_trips(sandbox):
    code = """
        def shapes():
            return (1, "a"), {"k": [1.5, None]}, {1, 2}, b"\\x00", {(1, 2): frozenset({3})}

        def echo(*args, **kwargs):
            return args, kwargs
    """
    tests = """
        def test_types():
            t, d, s, b, nested = shapes()
            assert t == (1, "a") and type(t) is tuple
            assert d == {"k": [1.5, None]} and s == {1, 2} and b == b"\\x00"
            assert nested == {(1, 2): frozenset({3})}

        def test_arguments():
            assert echo(1, [2], x={"y": (3,)}) == ((1, [2]), {"x": {"y": (3,)}})
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "passed", result


def test_arguments_are_copied_not_shared(sandbox):
    code = "def push(xs):\n    xs.append(1)\n    return xs\n"
    assert verify(sandbox, code, "xs = []\nassert push(xs) == [1]\nassert xs == []\n")["status"] == "passed"


def test_constants_and_imports_work(sandbox):
    code = "LIMIT = 3\n\ndef cap(n):\n    return min(n, LIMIT)\n"
    tests = "from solution import cap\nassert LIMIT == 3 and cap(10) == 3\n"
    assert verify(sandbox, code, tests)["status"] == "passed"


def test_classes_point_to_shared_mode(sandbox):
    code = """
        class Stack:
            def __init__(self):
                self.items = []

            def push(self, item):
                self.items.append(item)
    """
    tests = """
        def test_stack():
            s = Stack()
            s.push(1)
            assert s.items == [1]
    """
    isolated = verify(sandbox, code, tests)
    assert isolated["status"] == "failed"
    assert "isolation='shared'" in isolated["tests"][1]["message"]
    assert verify(sandbox, code, tests, isolation="shared")["status"] == "passed"


def test_unsupported_return_values_are_test_errors(sandbox):
    result = verify(sandbox, "def make():\n    return object()\n", "def test_make():\n    make()\n")
    assert result["status"] == "failed"
    assert "cannot cross" in result["tests"][1]["message"]


def test_code_that_hangs_inside_a_call_times_out(sandbox):
    result = verify(sandbox, "def spin():\n    while True:\n        pass\n", "spin()\nassert True\n", timeout_s=2)
    assert result["status"] == "timeout"


def test_lingering_code_process_does_not_turn_a_pass_into_a_timeout(sandbox):
    code = """
        import threading, time
        threading.Thread(target=lambda: time.sleep(60)).start()

        def one():
            return 1
    """
    result = verify(sandbox, code, "assert one() == 1\n", timeout_s=5)
    assert result["status"] == "passed", result


def test_output_of_tests_and_code_is_kept_apart(sandbox):
    code = "def shout():\n    print('from code')\n    return 1\n"
    tests = "print('from tests')\nassert shout() == 1\n"
    result = verify(sandbox, code, tests)
    assert result["status"] == "passed"
    assert result["stdout_tail"].strip() == "from code"
    assert result["tests_stdout_tail"].strip() == "from tests"


def test_huge_integers_cross_the_boundary(sandbox):
    code = """
        import math
        BIG = 10 ** 5000

        def fact(n):
            return math.factorial(n)
    """
    tests = """
        import math
        assert BIG == 10 ** 5000
        assert fact(2000) == math.factorial(2000)
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "passed", result


def test_except_exception_cannot_swallow_harness_failures(sandbox):
    code = "class Stack:\n    pass\n\ndef gone():\n    import os\n    os._exit(0)\n"
    tests = """
        def test_stub():
            try:
                Stack()
            except Exception:
                return

        def test_exit():
            try:
                gone()
            except Exception:
                return
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "failed"
    assert [t["outcome"] for t in result["tests"][1:]] == ["error", "error"]
    assert all("HarnessFailure" in t["message"] for t in result["tests"][1:])


def test_unicode_errors_cross_as_themselves(sandbox):
    code = "def bad():\n    return b'\\xff'.decode('utf-8')\n"
    tests = """
        def test_decode():
            try:
                bad()
            except UnicodeDecodeError:
                pass
            else:
                assert False
    """
    assert verify(sandbox, code, tests)["status"] == "passed"


def test_code_cannot_plant_files_for_the_tests(sandbox):
    code = """
        import os, tempfile
        PLANTED = []
        for path in ("/tmp/planted", "/tmp/w65533/planted", "/dev/shm/planted"):
            try:
                with open(path, "w") as handle:
                    handle.write("x")
                PLANTED.append(path)
            except OSError:
                pass
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"own scratch space works")
            OWN_TEMP = handle.name

        def ok():
            return True
    """
    tests = """
        import os
        assert PLANTED == []
        assert OWN_TEMP.startswith("/tmp/w65534/")
        assert not os.path.exists("/tmp/planted")
        assert ok()
    """
    result = verify(sandbox, code, tests)
    assert result["status"] == "passed", result
    assert result["kernel"]["locked_shared_scratch"] == ["/tmp", "/dev/shm"]


def test_concurrent_calls_from_test_threads_stay_paired(sandbox):
    tests = """
        import threading
        results = []
        threads = [threading.Thread(target=lambda i=i: results.append((i, square(i)))) for i in range(30)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(results) == [(i, i * i) for i in range(30)]
    """
    assert verify(sandbox, "def square(x):\n    return x * x\n", tests)["status"] == "passed"
