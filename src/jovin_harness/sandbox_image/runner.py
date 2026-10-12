"""Sandbox supervisor. Runs as PID 1 (root) inside a fresh jovin-harness container.

Protocol: the host writes one frame to stdin (8-byte big-endian length, then UTF-8 JSON). The
supervisor writes exactly one JSON line to stdout and exits. It never runs the submitted code
itself. A worker process does that after dropping to uid/gid 65534 with no capabilities, and
reports per-test events on a separate pipe. The supervisor decides the verdict from those events,
the worker's exit status and its own expectations derived from the test source. The worker's
stdout and stderr are returned only as escaped text tails and are never parsed.

This file uses only the standard library and is baked into the sandbox image.
"""

import ast
import ctypes
import json
import os
import selectors
import signal
import struct
import subprocess
import sys
import threading
import time

FORMAT = "jovin-harness.sandbox-result.v1"
NOBODY = 65534
MAX_PAYLOAD = 2 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
FLOOD_FACTOR = 64  # the worker is killed after writing this many times max_output_bytes
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38

# The worker bootstrap. It reads the payload from fd 4, runs the code and tests, and writes
# newline-delimited JSON events to fd 3. Everything it reports is treated as untrusted.
WORKER = r'''
import json, linecache, os, sys, traceback, types
events = os.fdopen(int(sys.argv[1]), "w", encoding="utf-8", buffering=1)
payload = json.loads(os.fdopen(int(sys.argv[2]), "rb").read().decode("utf-8"))
del sys.argv[1:]
def emit(**event):
    events.write(json.dumps(event) + "\n")
def describe(error, filename):
    frames = [f for f in traceback.extract_tb(error.__traceback__) if f.filename == filename]
    where = f" at line {frames[-1].lineno}: {(frames[-1].line or '').strip()}" if frames else ""
    text = str(error)
    return (type(error).__name__ + where + (": " + text if text else ""))[:2000]
def load(name, filename, source):
    linecache.cache[filename] = (len(source), None, source.splitlines(True), filename)
    module = types.ModuleType(name)
    module.__file__ = filename
    sys.modules[name] = module
    exec(compile(source, filename, "exec"), module.__dict__)
    return module
os.chdir("/tmp")
if payload["mode"] == "run":
    sys.argv = ["main.py"]
    load("__main__", "main.py", payload["code"])
    raise SystemExit(0)
try:
    solution = load("solution", "solution.py", payload["code"])
except BaseException as error:
    emit(event="load_error", message=describe(error, "solution.py"))
    raise SystemExit(0)
emit(event="loaded")
tests = types.ModuleType("test_solution")
tests.__dict__.update({k: v for k, v in vars(solution).items() if not k.startswith("__")})
linecache.cache["test_solution.py"] = (0, None, payload["tests"].splitlines(True), "test_solution.py")
try:
    exec(compile(payload["tests"], "test_solution.py", "exec"), tests.__dict__)
except BaseException as error:
    emit(event="test", name="<module>", outcome="failed", message=describe(error, "test_solution.py"))
    emit(event="done")
    raise SystemExit(0)
emit(event="test", name="<module>", outcome="passed")
for name in payload["test_names"]:
    if name == "<module>":
        continue
    function = tests.__dict__.get(name)
    if not callable(function):
        emit(event="test", name=name, outcome="error", message="test function not found after module execution")
        continue
    try:
        returned = function()
        if hasattr(returned, "send") and hasattr(returned, "throw"):
            returned.close()
            raise TypeError("test returned a generator or coroutine, so its body never ran")
    except AssertionError as error:
        emit(event="test", name=name, outcome="failed", message=describe(error, "test_solution.py"))
    except BaseException as error:
        emit(event="test", name=name, outcome="error", message=describe(error, "test_solution.py"))
    else:
        emit(event="test", name=name, outcome="passed")
emit(event="done")
'''


def write_result(result):
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    # PID 1 exiting tears down the PID namespace, including anything the worker left behind.
    os._exit(0)


def read_payload():
    header = sys.stdin.buffer.read(8)
    if len(header) != 8:
        raise ValueError("missing payload header")
    (size,) = struct.unpack(">Q", header)
    if size > MAX_PAYLOAD:
        raise ValueError("payload too large")
    body = sys.stdin.buffer.read(size)
    if len(body) != size:
        raise ValueError("truncated payload")
    payload = json.loads(body.decode("utf-8"))
    if payload.get("mode") not in ("verify", "run"):
        raise ValueError("unknown mode")
    for key in ("code",) + (("tests",) if payload["mode"] == "verify" else ()):
        if not isinstance(payload.get(key), str):
            raise ValueError(f"{key} must be a string")
    return payload


def expected_tests(source):
    """Names the worker must report: '<module>' plus each top-level test_* function, in order."""
    tree = ast.parse(source, "test_solution.py")
    names, seen = ["<module>"], set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            raise ValueError(f"test classes such as {node.name} are not supported; use top-level test_* functions")
        if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("test_"):
            raise ValueError(f"async test {node.name} is not supported")
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            required = len(node.args.args) - len(node.args.defaults) + len(node.args.posonlyargs)
            if required or any(d is None for d in node.args.kw_defaults):
                raise ValueError(f"test {node.name} must not take required arguments")
            if any(isinstance(n, (ast.Yield, ast.YieldFrom)) for n in _own_body(node)):
                raise ValueError(f"test {node.name} is a generator; its body would never run")
            if node.name not in seen:
                seen.add(node.name)
                names.append(node.name)
    if len(names) == 1 and not module_level_asserts(tree.body):
        raise ValueError("tests contain no assert statements and no test_* functions")
    return names


def _own_body(function):
    """Nodes in a function body, excluding nested functions, classes and lambdas."""
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


def kill_group(pid):
    """SIGKILL the worker's process group (needs CAP_KILL: the worker runs under another uid)."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def module_level_asserts(statements):
    """Asserts that run when the test module executes: not inside functions, classes or lambdas."""
    for node in statements:
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt) and module_level_asserts([child]):
                return True
    return False


def libc():
    return ctypes.CDLL(None, use_errno=True)


def drop_privileges():
    os.setgroups([])
    os.setgid(NOBODY)
    os.setuid(NOBODY)
    if libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        os._exit(125)


def process_status(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
        return dict(line.rstrip("\n").split(":\t", 1) for line in handle if ":\t" in line)


def worker_isolation(pid):
    status = process_status(pid)
    observed = {
        "uid": status.get("Uid", "").split(),
        "gid": status.get("Gid", "").split(),
        "cap_eff": status.get("CapEff", "").strip(),
        "no_new_privs": status.get("NoNewPrivs", "").strip(),
        "seccomp": status.get("Seccomp", "").strip(),
    }
    ok = (set(observed["uid"]) == {str(NOBODY)} and set(observed["gid"]) == {str(NOBODY)}
          and int(observed["cap_eff"] or "1", 16) == 0 and observed["no_new_privs"] == "1"
          and observed["seccomp"] == "2")
    return ok, observed


def cgroup_limits():
    """The memory and PID limits the kernel enforces on this container (cgroup v2, else v1)."""
    values = {}
    for key, paths in (("memory_max", ("memory.max", "memory/memory.limit_in_bytes")),
                       ("pids_max", ("pids.max", "pids/pids.max"))):
        values[key] = None
        for name in paths:
            try:
                with open(f"/sys/fs/cgroup/{name}", encoding="utf-8") as handle:
                    values[key] = handle.read().strip()
                break
            except OSError:
                continue
    return values


def feed(stream, data):
    try:
        stream.write(data)
        stream.close()
    except OSError:
        pass


class Tail:
    """Keep the last `limit` bytes of a stream and count everything seen."""

    def __init__(self, limit):
        self.limit, self.data, self.total = limit, b"", 0

    def add(self, chunk):
        self.total += len(chunk)
        self.data = (self.data + chunk)[-self.limit:]

    def text(self):
        return self.data.decode("utf-8", errors="replace")


def run_worker(payload, test_names, result):
    timeout_s = payload["timeout_s"]
    limit = payload["max_output_bytes"]
    # os.pipe() descriptors are not inheritable; pass_fds hands exactly these two to the worker.
    events_r, events_w = os.pipe()
    payload_r, payload_w = os.pipe()
    stdin_data = (payload.get("stdin") or "").encode("utf-8")
    started = time.monotonic()
    worker = subprocess.Popen(
        [sys.executable, "-I", "-c", WORKER, str(events_w), str(payload_r)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        pass_fds=(events_w, payload_r), close_fds=True, preexec_fn=drop_privileges,
        start_new_session=True, cwd="/tmp",
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
             "PYTHONHASHSEED": "0", "HOME": "/tmp", "LANG": "C.UTF-8"},
    )
    os.close(events_w)
    os.close(payload_r)
    ok, observed = worker_isolation(worker.pid)
    result["kernel"] = {"worker": observed, **cgroup_limits()}
    if not ok:
        kill_group(worker.pid)
        result.update(status="blocked", reason="worker privilege drop could not be verified")
        return
    job = dict(code=payload["code"], mode=payload["mode"], tests=payload.get("tests"), test_names=test_names)
    with os.fdopen(payload_w, "wb") as handle:  # the trusted bootstrap reads this before any submitted code
        handle.write(json.dumps(job).encode("utf-8"))
    # The submitted program may never read stdin, so feed it without blocking the event loop.
    threading.Thread(target=feed, args=(worker.stdin, stdin_data), daemon=True).start()

    out, err, events = Tail(limit), Tail(limit), bytearray()
    selector = selectors.DefaultSelector()
    selector.register(worker.stdout, selectors.EVENT_READ, out)
    selector.register(worker.stderr, selectors.EVENT_READ, err)
    events_file = os.fdopen(events_r, "rb", buffering=0)
    selector.register(events_file, selectors.EVENT_READ, events)
    deadline = started + timeout_s
    stop = None
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stop = "timeout"
            break
        for key, _ in selector.select(timeout=min(remaining, 0.25)):
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            if key.data is events:
                events.extend(chunk)
                if len(events) > MAX_EVENT_BYTES:
                    stop = "protocol_error"
            else:
                key.data.add(chunk)
                if key.data.total > limit * FLOOD_FACTOR:
                    stop = "output_limit"
        if stop:
            break
    if stop:
        kill_group(worker.pid)
    try:
        returncode = worker.wait(timeout=max(0.1, deadline + 1 - time.monotonic()))
    except subprocess.TimeoutExpired:
        kill_group(worker.pid)
        returncode = worker.wait()
        stop = stop or "timeout"
    kill_group(worker.pid)  # stray descendants of the worker
    result.update(
        duration_s=round(time.monotonic() - started, 4),
        exit_code=returncode,
        stdout_tail=out.text(), stdout_bytes=out.total,
        stderr_tail=err.text(), stderr_bytes=err.total,
        output_truncated=out.total > limit or err.total > limit,
    )
    if stop:
        result.update(status=stop, timed_out=stop == "timeout")
        return
    result["timed_out"] = False
    if payload["mode"] == "run":
        result["status"] = "completed"
        return
    judge(events, test_names, returncode, result)


def judge(raw_events, test_names, returncode, result):
    """Decide the verdict from the worker's events. Anything unexpected fails closed."""
    tests, loaded, done, problems = {}, False, False, []
    for line in bytes(raw_events).splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            problems.append("unparseable event")
            continue
        kind = event.get("event") if isinstance(event, dict) else None
        if done:
            problems.append("event after done")
        elif kind == "load_error":
            result.update(status="error", load_error=str(event.get("message", ""))[:2000])
            return
        elif kind == "loaded":
            loaded = True
        elif kind == "test":
            name, outcome = event.get("name"), event.get("outcome")
            if name not in test_names or name in tests or outcome not in ("passed", "failed", "error"):
                problems.append(f"unexpected test event for {str(name)[:100]}")
                continue
            tests[name] = {"name": name, "outcome": outcome, "message": str(event.get("message", ""))[:2000]}
        elif kind == "done":
            done = True
        else:
            problems.append("unknown event")
    reported = [tests[name] for name in test_names if name in tests]
    result["tests"] = reported
    result["total"] = len(test_names)
    result["passed_count"] = sum(t["outcome"] == "passed" for t in reported)
    if not loaded:
        problems.append("code was never reported as loaded")
    if tests.get("<module>", {}).get("outcome") == "passed" and not done:
        problems.append("worker stopped before reporting done")
    if returncode != 0:
        problems.append(f"worker exited with status {returncode}")
    if problems:
        result.update(status="protocol_error", problems=problems[:20])
        return
    if tests.get("<module>", {}).get("outcome") != "passed":
        result["status"] = "failed"
        return
    missing = [name for name in test_names if name not in tests]
    if missing:
        result.update(status="protocol_error", problems=[f"no result for {name}" for name in missing][:20])
        return
    result["status"] = "passed" if result["passed_count"] == len(test_names) else "failed"


def main():
    result = {"format": FORMAT, "status": "blocked"}
    try:
        if os.getpid() != 1 or os.getuid() != 0:
            raise PermissionError("the supervisor must run as root PID 1")
        if libc().prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError("could not make the supervisor non-dumpable")
        payload = read_payload()
        timeout_s = int(payload.get("timeout_s", 10))
        if not 1 <= timeout_s <= 30:
            raise ValueError("timeout_s out of range")
        payload["timeout_s"] = timeout_s
        payload["max_output_bytes"] = min(int(payload.get("max_output_bytes", 65536)), 65536)
        # Backstop: even if everything else hangs, the container's PID 1 exits.
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.setitimer(signal.ITIMER_REAL, timeout_s + 3)
        test_names = expected_tests(payload["tests"]) if payload["mode"] == "verify" else []
        result["mode"] = payload["mode"]
        run_worker(payload, test_names, result)
    except (ValueError, SyntaxError) as error:
        result.update(status="invalid_request", reason=f"{type(error).__name__}: {error}"[:500])
    except BaseException as error:  # noqa: BLE001 - every failure must still produce one result line
        result.update(status="blocked", reason=f"{type(error).__name__}: {error}"[:500])
    write_result(result)


if __name__ == "__main__":
    main()
