"""Sandbox supervisor. Runs as PID 1 (root) inside a fresh jovin-harness container.

Protocol: the host writes one frame to stdin (8-byte big-endian length, then UTF-8 JSON). The
supervisor writes exactly one JSON line to stdout and exits. It never runs submitted code itself.

Verification has two isolation modes:

- ``process`` (default): the code under test runs as uid 65534 and the tests run as uid 65533, in
  separate processes. Tests call the code's functions through proxies that exchange plain data
  (numbers, strings, lists, dicts, tuples, sets, bytes) over a pipe, so the code can influence the
  verdict only through the values it returns. The test process reports per-test events on a pipe
  the code under test cannot reach.
- ``shared``: tests and code share one process (uid 65534). Classes and I/O work, but code written
  to cheat can tamper with the tests.

Either way the supervisor decides the verdict from the events, the reporting process's exit status
and its own AST-derived list of expected tests. Program output is returned only as escaped tails.

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
CODE_UID = 65534  # the code under test
TESTS_UID = 65533  # the agent's tests, in process isolation
MAX_PAYLOAD = 2 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024
FLOOD_FACTOR = 64  # a process is killed after writing this many times max_output_bytes
LINGER_S = 1.0  # how long a non-reporting process may outlive the reporting one
PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
       "HOME": "/tmp", "LANG": "C.UTF-8"}

# Shared by every bootstrap: bounded failure descriptions and module loading with source lines.
COMMON = r'''
import json, linecache, os, sys, traceback, types
def describe(error, filename):
    frames = [f for f in traceback.extract_tb(error.__traceback__) if f.filename == filename]
    where = f" at line {frames[-1].lineno}: {(frames[-1].line or '').strip()}" if frames else ""
    text = str(error)
    return (type(error).__name__ + where + (": " + text if text else ""))[:2000]
def load(name, filename, source, namespace=None):
    linecache.cache[filename] = (len(source), None, source.splitlines(True), filename)
    module = types.ModuleType(name)
    module.__file__ = filename
    if namespace:
        module.__dict__.update(namespace)
    sys.modules[name] = module
    exec(compile(source, filename, "exec"), module.__dict__)
    return module
os.chdir("/tmp")
'''

# Runs the agent's tests: emits newline-delimited JSON events on the events fd.
TEST_LOOP = r'''
def run_tests(namespace, test_names, emit):
    try:
        tests = load("test_solution", "test_solution.py", payload["tests"], namespace)
    except BaseException as error:
        emit(event="test", name="<module>", outcome="failed", message=describe(error, "test_solution.py"))
        emit(event="done")
        return
    emit(event="test", name="<module>", outcome="passed")
    for name in test_names:
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

# Plain-data codec for values crossing the process boundary. No pickle, no custom objects: every
# value decodes to a built-in type, so returned data cannot run code or override comparisons.
CODEC = r'''
import base64, math, struct
MAX_DEPTH = 64
MAX_FRAME = 4 * 1024 * 1024
class Unsupported(Exception):
    pass
def encode(value, depth=0):
    if depth > MAX_DEPTH:
        raise Unsupported("value is nested too deeply")
    kind = type(value)
    if value is None or kind is bool or kind is str or kind is int:
        return value
    if kind is float:
        return value if math.isfinite(value) else {"$f": repr(value)}
    if kind is list:
        return [encode(item, depth + 1) for item in value]
    if kind is tuple:
        return {"$t": [encode(item, depth + 1) for item in value]}
    if kind is set:
        return {"$s": [encode(item, depth + 1) for item in value]}
    if kind is frozenset:
        return {"$fs": [encode(item, depth + 1) for item in value]}
    if kind is bytes:
        return {"$b": base64.b64encode(value).decode("ascii")}
    if kind is dict:
        return {"$d": [[encode(k, depth + 1), encode(v, depth + 1)] for k, v in value.items()]}
    raise Unsupported(f"values of type {kind.__name__} cannot cross the process boundary")
def decode(value, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError("value is nested too deeply")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite float outside its tag")
        return value
    if type(value) is list:
        return [decode(item, depth + 1) for item in value]
    if type(value) is dict and len(value) == 1:
        ((tag, body),) = value.items()
        if tag == "$f" and body in ("nan", "inf", "-inf"):
            return float(body)
        if tag == "$b" and type(body) is str:
            return base64.b64decode(body.encode("ascii"), validate=True)
        if type(body) is list:
            if tag == "$t":
                return tuple(decode(item, depth + 1) for item in body)
            if tag == "$s":
                return {decode(item, depth + 1) for item in body}
            if tag == "$fs":
                return frozenset(decode(item, depth + 1) for item in body)
            if tag == "$d" and all(type(pair) is list and len(pair) == 2 for pair in body):
                return {decode(k, depth + 1): decode(v, depth + 1) for k, v in body}
    raise ValueError("malformed value")
def _reject_constant(name):
    raise ValueError(f"invalid JSON constant {name}")
def send_frame(fd, message):
    data = json.dumps(message, allow_nan=False).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise Unsupported("value is too large to cross the process boundary")
    data = struct.pack(">I", len(data)) + data
    while data:
        data = data[os.write(fd, data):]
def recv_frame(fd):
    def exact(size):
        chunks, remaining = [], size
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                raise EOFError("the other process exited")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    (size,) = struct.unpack(">I", exact(4))
    if size > MAX_FRAME:
        raise ValueError("frame too large")
    return json.loads(exact(size).decode("utf-8"), parse_constant=_reject_constant)
'''

# Shared mode (and run mode): one worker runs code and tests together.
WORKER = COMMON + TEST_LOOP + r'''
events = os.fdopen(int(sys.argv[1]), "w", encoding="utf-8", buffering=1)
payload = json.loads(os.fdopen(int(sys.argv[2]), "rb").read().decode("utf-8"))
del sys.argv[1:]
def emit(**event):
    events.write(json.dumps(event) + "\n")
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
run_tests({k: v for k, v in vars(solution).items() if not k.startswith("__")}, payload["test_names"], emit)
'''

# Process mode, code side: load the code, then answer calls until the tests hang up.
CANDIDATE = COMMON + CODEC + r'''
requests, responses = int(sys.argv[1]), int(sys.argv[2])
payload = json.loads(os.fdopen(int(sys.argv[3]), "rb").read().decode("utf-8"))
del sys.argv[1:]
try:
    solution = load("solution", "solution.py", payload["code"])
except BaseException as error:
    send_frame(responses, {"load_error": describe(error, "solution.py")})
    raise SystemExit(0)
values = {}
for name, value in list(vars(solution).items())[:4096]:
    if name.startswith("__") or name in payload["exports"] or callable(value) or len(values) >= 256:
        continue
    try:
        values[name] = encode(value)
    except Unsupported:
        continue
try:
    send_frame(responses, {"ready": True, "values": values})
except Unsupported:
    send_frame(responses, {"ready": True, "values": {}})
while True:
    try:
        request = recv_frame(requests)
    except EOFError:
        break
    try:
        function = vars(solution).get(request["call"])
        if request["call"] not in payload["exports"] or not callable(function):
            raise NameError(f"name {request['call']!r} is not a function defined by the code")
        result = function(*decode(request["args"]), **decode(request["kwargs"]))
        if hasattr(result, "send") and hasattr(result, "throw"):
            result.close()
            raise Unsupported("generators and coroutines cannot cross the process boundary")
        reply = {"ok": encode(result)}
    except Unsupported as error:
        reply = {"unsupported": str(error)[:500]}
    except BaseException as error:
        reply = {"raised": {"type": type(error).__name__, "message": str(error)[:2000]}}
    try:
        send_frame(responses, reply)
    except Unsupported as error:
        send_frame(responses, {"unsupported": str(error)[:500]})
'''

# Process mode, tests side: proxies forward calls to the code process; events go to the supervisor.
TESTER = COMMON + CODEC + TEST_LOOP + r'''
import builtins, keyword
events = os.fdopen(int(sys.argv[1]), "w", encoding="utf-8", buffering=1)
requests, responses = int(sys.argv[2]), int(sys.argv[3])
payload = json.loads(os.fdopen(int(sys.argv[4]), "rb").read().decode("utf-8"))
del sys.argv[1:]
def emit(**event):
    events.write(json.dumps(event) + "\n")
def rebuild(raised):
    kind = getattr(builtins, str(raised.get("type")), None)
    message = str(raised.get("message", ""))[:2000]
    if isinstance(kind, type) and issubclass(kind, Exception):
        return kind(message)
    return RuntimeError(f"{str(raised.get('type'))[:100]}: {message}")
def proxy(name):
    def call(*args, **kwargs):
        try:
            send_frame(requests, {"call": name, "args": encode(list(args)), "kwargs": encode(kwargs)})
        except Unsupported as error:
            raise TypeError(f"argument to {name}(): {error}") from None
        except BrokenPipeError:
            raise RuntimeError(f"the code under test exited before a call to {name}()") from None
        try:
            reply = recv_frame(responses)
        except EOFError:
            raise RuntimeError(f"the code under test exited during a call to {name}()") from None
        if type(reply) is dict and "ok" in reply:
            return decode(reply["ok"])
        if type(reply) is dict and type(reply.get("raised")) is dict:
            raise rebuild(reply["raised"])
        if type(reply) is dict and "unsupported" in reply:
            raise TypeError(f"{name}() returned {str(reply['unsupported'])[:500]}")
        raise RuntimeError(f"the code under test sent an invalid reply to {name}()")
    call.__name__ = call.__qualname__ = name
    return call
def unavailable(name, why):
    def call(*args, **kwargs):
        raise TypeError(f"{name} {why}; use isolation='shared' to test it")
    call.__name__ = name
    return call
try:
    ready = recv_frame(responses)
except EOFError:
    emit(event="load_error", message="the code under test exited while loading")
    raise SystemExit(0)
if type(ready) is not dict or "load_error" in ready or ready.get("ready") is not True:
    message = ready.get("load_error") if type(ready) is dict else None
    emit(event="load_error", message=str(message or "the code under test failed to start")[:2000])
    raise SystemExit(0)
emit(event="loaded")
namespace = {}
values = ready.get("values")
for name, value in (values if type(values) is dict else {}).items():
    if type(name) is str and name.isidentifier() and not keyword.iskeyword(name):
        try:
            namespace[name] = decode(value)
        except (ValueError, TypeError):
            continue
for name in payload["exports"]:
    namespace[name] = proxy(name)
for name, why in payload["unavailable"].items():
    namespace[name] = unavailable(name, why)
solution = types.ModuleType("solution")
solution.__dict__.update(namespace)
sys.modules["solution"] = solution
run_tests(namespace, payload["test_names"], emit)
'''


def write_result(result):
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    # PID 1 exiting tears down the PID namespace, including anything the workers left behind.
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
    if payload.get("isolation", "process") not in ("process", "shared"):
        raise ValueError("unknown isolation")
    for key in ("code",) + (("tests",) if payload["mode"] == "verify" else ()):
        if not isinstance(payload.get(key), str):
            raise ValueError(f"{key} must be a string")
    return payload


def expected_tests(source):
    """Names the tests must report: '<module>' plus each top-level test_* function, in order."""
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


def exported_names(source):
    """Functions the tests may call across the boundary, and names they cannot use there.

    Derived from the code's syntax here, not reported by the code itself. On a syntax error both are
    empty; the code process then reports the error as a load failure.
    """
    try:
        tree = ast.parse(source, "solution.py")
    except SyntaxError:
        return [], {}
    exports, unavailable = [], {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            exports.append(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            unavailable[node.name] = "is an async function and cannot be called across the process boundary"
        elif isinstance(node, ast.ClassDef):
            unavailable[node.name] = "is a class; objects cannot cross the process boundary"
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            exports.extend(t.id for t in node.targets if isinstance(t, ast.Name))
    exports = [name for name in dict.fromkeys(exports) if not name.startswith("__")]
    return exports, {k: v for k, v in unavailable.items() if k not in exports}


def _own_body(function):
    """Nodes in a function body, excluding nested functions, classes and lambdas."""
    stack = list(function.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


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


def kill_group(pid):
    """SIGKILL a worker's process group (needs CAP_KILL: workers run under other uids)."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def libc():
    return ctypes.CDLL(None, use_errno=True)


def drop_to(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        if libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            os._exit(125)
    return drop


def spawn(script, uid, fds):
    """Start a bootstrap as `uid` with exactly `fds` inherited (their numbers are passed as argv)."""
    return subprocess.Popen(
        [sys.executable, "-I", "-c", script, *map(str, fds)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        pass_fds=tuple(fds), close_fds=True, preexec_fn=drop_to(uid), start_new_session=True,
        cwd="/tmp", env=ENV)


def process_status(pid):
    with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
        return dict(line.rstrip("\n").split(":\t", 1) for line in handle if ":\t" in line)


def isolation_of(pid, uid):
    status = process_status(pid)
    observed = {
        "uid": status.get("Uid", "").split(),
        "gid": status.get("Gid", "").split(),
        "cap_eff": status.get("CapEff", "").strip(),
        "no_new_privs": status.get("NoNewPrivs", "").strip(),
        "seccomp": status.get("Seccomp", "").strip(),
    }
    ok = (set(observed["uid"]) == {str(uid)} and set(observed["gid"]) == {str(uid)}
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


def send_json(fd, value):
    with os.fdopen(fd, "wb") as handle:  # read by a trusted bootstrap before any submitted code runs
        handle.write(json.dumps(value).encode("utf-8"))


class Tail:
    """Keep the last `limit` bytes of a stream and count everything seen."""

    def __init__(self, limit):
        self.limit, self.data, self.total = limit, b"", 0

    def add(self, chunk):
        self.total += len(chunk)
        self.data = (self.data + chunk)[-self.limit:]

    def text(self):
        return self.data.decode("utf-8", errors="replace")


def supervise(reporter, others, events_r, limit, deadline):
    """Collect output and events until the reporting process is done, then stop everything.

    Returns (stop_reason, reporter_returncode, tails, events). Every process is killed on return.
    """
    workers = [reporter, *others]
    tails = {id(p): (Tail(limit), Tail(limit)) for p in workers}
    events = bytearray()
    selector = selectors.DefaultSelector()
    for process in workers:
        out, err = tails[id(process)]
        selector.register(process.stdout, selectors.EVENT_READ, (process, out))
        selector.register(process.stderr, selectors.EVENT_READ, (process, err))
    events_file = os.fdopen(events_r, "rb", buffering=0)
    selector.register(events_file, selectors.EVENT_READ, (reporter, events))
    stop, finish_by = None, None

    def reporter_open():
        return any(key.data[0] is reporter for key in selector.get_map().values())

    while selector.get_map():
        now = time.monotonic()
        if now >= deadline:
            if finish_by is None:  # the reporting process itself ran out of time
                stop = "timeout"
            break
        if finish_by is None and not reporter_open():
            finish_by = now + LINGER_S  # others get a moment to flush, then they are stopped
        if finish_by is not None and now >= finish_by:
            break
        horizon = min(deadline, finish_by) if finish_by is not None else deadline
        for key, _ in selector.select(timeout=min(horizon - now, 0.25)):
            chunk = os.read(key.fd, 65536)
            if not chunk:
                selector.unregister(key.fileobj)
                continue
            sink = key.data[1]
            if sink is events:
                events.extend(chunk)
                if len(events) > MAX_EVENT_BYTES:
                    stop = "protocol_error"
            else:
                sink.add(chunk)
                if sink.total > limit * FLOOD_FACTOR:
                    stop = "output_limit"
        if stop:
            break
    if stop:
        for process in workers:
            kill_group(process.pid)
    try:
        returncode = reporter.wait(timeout=max(0.1, deadline + 1 - time.monotonic()))
    except subprocess.TimeoutExpired:
        kill_group(reporter.pid)
        returncode = reporter.wait()
        stop = stop or "timeout"
    for process in workers:
        kill_group(process.pid)  # the other processes and any stray descendants
        process.wait()
    return stop, returncode, tails, events


def run_shared(payload, test_names, result, limit, started, deadline):
    events_r, events_w = os.pipe()
    payload_r, payload_w = os.pipe()
    worker = spawn(WORKER, CODE_UID, (events_w, payload_r))
    os.close(events_w)
    os.close(payload_r)
    ok, observed = isolation_of(worker.pid, CODE_UID)
    result["kernel"] = {"worker": observed, **cgroup_limits()}
    if not ok:
        kill_group(worker.pid)
        result.update(status="blocked", reason="worker privilege drop could not be verified")
        return
    send_json(payload_w, dict(code=payload["code"], mode=payload["mode"], tests=payload.get("tests"),
                              test_names=test_names))
    # The submitted program may never read stdin, so feed it without blocking the event loop.
    stdin_data = (payload.get("stdin") or "").encode("utf-8")
    threading.Thread(target=feed, args=(worker.stdin, stdin_data), daemon=True).start()
    stop, returncode, tails, events = supervise(worker, [], events_r, limit, deadline)
    out, err = tails[id(worker)]
    result.update(duration_s=round(time.monotonic() - started, 4), exit_code=returncode,
                  stdout_tail=out.text(), stdout_bytes=out.total, stderr_tail=err.text(), stderr_bytes=err.total,
                  output_truncated=out.total > limit or err.total > limit)
    finish(stop, payload, events, test_names, returncode, result)


def run_isolated(payload, test_names, result, limit, started, deadline):
    exports, unavailable = exported_names(payload["code"])
    events_r, events_w = os.pipe()
    requests_r, requests_w = os.pipe()
    responses_r, responses_w = os.pipe()
    code_payload_r, code_payload_w = os.pipe()
    tests_payload_r, tests_payload_w = os.pipe()
    code = spawn(CANDIDATE, CODE_UID, (requests_r, responses_w, code_payload_r))
    tests = spawn(TESTER, TESTS_UID, (events_w, requests_w, responses_r, tests_payload_r))
    for fd in (requests_r, responses_w, code_payload_r, events_w, requests_w, responses_r, tests_payload_r):
        os.close(fd)
    code_ok, code_observed = isolation_of(code.pid, CODE_UID)
    tests_ok, tests_observed = isolation_of(tests.pid, TESTS_UID)
    result["kernel"] = {"worker": code_observed, "tests_worker": tests_observed, **cgroup_limits()}
    if not (code_ok and tests_ok):
        kill_group(code.pid)
        kill_group(tests.pid)
        result.update(status="blocked", reason="worker privilege drop could not be verified")
        return
    send_json(code_payload_w, {"code": payload["code"], "exports": exports})
    send_json(tests_payload_w, {"tests": payload["tests"], "test_names": test_names, "exports": exports,
                                "unavailable": unavailable})
    for process in (code, tests):
        threading.Thread(target=feed, args=(process.stdin, b""), daemon=True).start()
    stop, returncode, tails, events = supervise(tests, [code], events_r, limit, deadline)
    out, err = tails[id(code)]
    tests_out, tests_err = tails[id(tests)]
    result.update(duration_s=round(time.monotonic() - started, 4), exit_code=returncode,
                  code_exit_code=code.returncode, exports=exports,
                  stdout_tail=out.text(), stdout_bytes=out.total, stderr_tail=err.text(), stderr_bytes=err.total,
                  tests_stdout_tail=tests_out.text(), tests_stderr_tail=tests_err.text(),
                  output_truncated=any(t.total > limit for t in (out, err, tests_out, tests_err)))
    finish(stop, payload, events, test_names, returncode, result)


def finish(stop, payload, events, test_names, returncode, result):
    if stop:
        result.update(status=stop, timed_out=stop == "timeout")
        return
    result["timed_out"] = False
    if payload["mode"] == "run":
        result["status"] = "completed"
        return
    judge(events, test_names, returncode, result)


def judge(raw_events, test_names, returncode, result):
    """Decide the verdict from the reporting process's events. Anything unexpected fails closed."""
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
        problems.append("tests stopped before reporting done")
    if returncode != 0:
        problems.append(f"the test process exited with status {returncode}")
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
        limit = min(int(payload.get("max_output_bytes", 65536)), 65536)
        # Backstop: even if everything else hangs, the container's PID 1 exits.
        signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
        signal.setitimer(signal.ITIMER_REAL, timeout_s + 3)
        test_names = expected_tests(payload["tests"]) if payload["mode"] == "verify" else []
        isolation = payload.get("isolation", "process") if payload["mode"] == "verify" else "none"
        result.update(mode=payload["mode"], isolation=isolation)
        started = time.monotonic()
        runner = run_isolated if isolation == "process" else run_shared
        runner(payload, test_names, result, limit, started, started + timeout_s)
    except (ValueError, SyntaxError) as error:
        result.update(status="invalid_request", reason=f"{type(error).__name__}: {error}"[:500])
    except BaseException as error:  # noqa: BLE001 - every failure must still produce one result line
        result.update(status="blocked", reason=f"{type(error).__name__}: {error}"[:500])
    write_result(result)


if __name__ == "__main__":
    main()
