import json
import socket
import threading
import time
import urllib.error
import urllib.request

import anyio
import pytest
import uvicorn
from mcp import Client
from test_tools import make_harness

from jovin_harness.server import AccessGate, build_server, http_app, http_token, path_secret


def test_tools_are_listed_with_annotations(tmp_path):
    harness, _ = make_harness(tmp_path)

    async def main():
        async with Client(build_server(harness)) as client:
            return (await client.list_tools()).tools

    tools = {tool.name: tool for tool in anyio.run(main)}
    assert set(tools) == {"verify_python", "run_python", "get_receipt", "verify_receipt", "sandbox_status"}
    assert tools["verify_python"].annotations.read_only_hint is False
    assert tools["get_receipt"].annotations.read_only_hint is True
    assert tools["verify_python"].input_schema["required"] == ["code", "tests"]


def test_verify_python_over_mcp(tmp_path):
    harness, _ = make_harness(tmp_path)

    async def main():
        async with Client(build_server(harness)) as client:
            ok = await client.call_tool("verify_python", {"code": "x = 1", "tests": "assert x == 1"})
            bad = await client.call_tool("run_python", {"code": ""})
            return ok, bad

    ok, bad = anyio.run(main)
    assert not ok.is_error
    assert ok.structured_content["passed"] is True
    assert ok.structured_content["receipt_id"]
    assert bad.is_error
    assert "non-empty" in bad.content[0].text


async def _asgi(app, path="/mcp", headers=()):
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": path, "raw_path": path.encode(), "headers": list(headers)}
    await app(scope, receive, send)
    return sent


def test_access_gate_bearer():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    gate = AccessGate(inner, mode="bearer", secret="s" * 43)
    assert anyio.run(_asgi, gate)[0]["status"] == 401
    wrong = [(b"authorization", b"Bearer nope")]
    assert anyio.run(_asgi, gate, "/mcp", wrong)[0]["status"] == 401
    twice = [(b"authorization", b"Bearer " + b"s" * 43)] * 2
    assert anyio.run(_asgi, gate, "/mcp", twice)[0]["status"] == 401
    right = [(b"authorization", b"Bearer " + b"s" * 43)]
    assert anyio.run(_asgi, gate, "/mcp", right)[0]["status"] == 200
    assert seen == ["/mcp"]


def test_access_gate_path_secret_rewrites_only_the_exact_path():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    gate = AccessGate(inner, mode="path-secret", secret="k" * 43)
    assert anyio.run(_asgi, gate, "/mcp")[0]["status"] == 404
    assert anyio.run(_asgi, gate, "/mcp/" + "k" * 42)[0]["status"] == 404
    assert anyio.run(_asgi, gate, "/mcp/" + "k" * 43)[0]["status"] == 200
    assert seen == ["/mcp"]


def test_remote_bind_requires_allowed_host(tmp_path):
    harness, _ = make_harness(tmp_path)
    with pytest.raises(ValueError, match="allowed-host"):
        http_app(harness, host="0.0.0.0", auth="bearer", allowed_hosts=[])


def test_secrets_are_stable_and_distinct(tmp_path):
    harness, _ = make_harness(tmp_path)
    assert http_token(harness) == http_token(harness)
    assert path_secret(harness) != http_token(harness)
    assert len(http_token(harness)) >= 43


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _post(url, payload, headers):
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json, text/event-stream", **headers})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as error:
        return error.code, None


def test_http_transport_end_to_end(tmp_path):
    harness, _ = make_harness(tmp_path)
    port = _free_port()
    app = http_app(harness, host="127.0.0.1", auth="bearer", allowed_hosts=[])
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        url = f"http://127.0.0.1:{port}/mcp"
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "test", "version": "0"}}}
        status, _ = _post(url, init, {})
        assert status == 401
        auth = {"Authorization": f"Bearer {http_token(harness)}"}
        status, body = _post(url, init, auth)
        assert status == 200, body
        assert body["result"]["serverInfo"]["name"] == "jovin-harness"
        listed = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        status, body = _post(url, listed, {**auth, "MCP-Protocol-Version": "2025-06-18"})
        assert status == 200, body
        assert "verify_python" in {tool["name"] for tool in body["result"]["tools"]}
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_verify_python_schema_offers_isolation(tmp_path):
    harness, _ = make_harness(tmp_path)

    async def main():
        async with Client(build_server(harness)) as client:
            return {tool.name: tool for tool in (await client.list_tools()).tools}

    schema = anyio.run(main)["verify_python"].input_schema["properties"]["isolation"]
    assert schema["enum"] == ["process", "shared"] and schema["default"] == "process"


def test_access_gate_does_not_wait_forever_for_a_stalled_body(monkeypatch):
    import jovin_harness.server as server_module
    monkeypatch.setattr(server_module, "DENY_DRAIN_SECONDS", 0.2)

    async def inner(scope, receive, send):
        raise AssertionError("must not be reached")

    async def stalled():
        await anyio.sleep(30)

    sent = []

    async def send(message):
        sent.append(message)

    async def main():
        gate = AccessGate(inner, mode="bearer", secret="s" * 43)
        with anyio.fail_after(5):
            await gate({"type": "http", "method": "POST", "path": "/mcp", "headers": []}, stalled, send)

    anyio.run(main)
    assert sent[0]["status"] == 401
