# Connecting agents

jovin-harness speaks MCP, which Claude, ChatGPT/Codex and Grok clients all support. Local agents
start it as a subprocess over **stdio**. Cloud-hosted agents reach it over **Streamable HTTP**, which
needs a public HTTPS URL.

First, on the machine that will run the code:

```bash
pipx install jovin-harness        # or: uv tool install jovin-harness
jovin-harness image build         # builds the sandbox image and pins its ID
jovin-harness doctor              # "ready": true when everything checks out
```

You need a Linux container engine: Docker Engine, Docker Desktop, or Docker inside WSL 2. If Docker
only runs inside a WSL distribution, set `JOVIN_HARNESS_RUNTIME=wsl:<distro>` (or
`wsl:<distro>@<user>`). Podman (`JOVIN_HARNESS_RUNTIME=podman`) is experimental.

## Local agents (stdio)

The command is the same everywhere: `jovin-harness serve`. If it isn't on `PATH`, use
`python -m jovin_harness serve` from the environment you installed it into.

**Claude Code**

```bash
claude mcp add jovin -- jovin-harness serve
```

Or commit a project `.mcp.json`. Grok Build reads this file too:

```json
{ "mcpServers": { "jovin": { "command": "jovin-harness", "args": ["serve"] } } }
```

**Claude Desktop**: add the same `mcpServers` entry to `claude_desktop_config.json`.

**Codex CLI** (including Codex mode in the ChatGPT desktop app), in `~/.codex/config.toml`:

```toml
[mcp_servers.jovin]
command = "jovin-harness"
args = ["serve"]
```

**Grok Build**

```bash
grok mcp add jovin -- jovin-harness serve
```

## Remote agents (Streamable HTTP)

```bash
jovin-harness serve --transport http --port 8765        # http://127.0.0.1:8765/mcp
jovin-harness http-token                                 # the bearer token
```

Cloud services can't reach `127.0.0.1`, so put an HTTPS tunnel or reverse proxy in front, and tell
the harness which public hostname to accept:

```bash
jovin-harness serve --transport http --allowed-host your-tunnel.example.com
```

Read [SECURITY.md](../SECURITY.md) before exposing the endpoint: anyone who can call it can run code
in your sandbox.

**OpenAI Responses API**

```json
{"type": "mcp", "server_label": "jovin", "server_url": "https://your-tunnel.example.com/mcp",
 "headers": {"Authorization": "Bearer <token>"}, "require_approval": "never"}
```

**Anthropic Messages API** (MCP connector)

```json
"mcp_servers": [{"type": "url", "url": "https://your-tunnel.example.com/mcp",
                 "name": "jovin", "authorization_token": "<token>"}]
```

**xAI API** (remote MCP tools): add an MCP tool entry with `server_url` pointing at the tunnel and an
`authorization` value of `Bearer <token>`. xAI supports Streamable HTTP and SSE transports. Check
xAI's current remote-MCP documentation for the exact field names.

**ChatGPT and Grok web connectors**: ChatGPT developer-mode connectors can't send a static bearer
token; they support only OAuth or no authentication. For those, use a capability URL:

```bash
jovin-harness serve --transport http --auth path-secret --allowed-host your-tunnel.example.com
jovin-harness http-token --path-secret                  # /mcp/<secret>
```

Register `https://your-tunnel.example.com/mcp/<secret>` with "No authentication". The URL is the
credential: runs are limited to 10 a minute, one at a time. OAuth support is planned.

## Using it well

Add [templates/AGENTS.snippet.md](../templates/AGENTS.snippet.md) to your project's `AGENTS.md`,
`CLAUDE.md` or equivalent, so agents check their code before claiming it works and cite the receipt.

| Tool | Use it to |
|---|---|
| `verify_python(code, tests, timeout_s?)` | Run assert-style tests against code. Returns per-test results and a receipt. |
| `run_python(code, stdin?, timeout_s?)` | Run a program and see its exit code and output. |
| `get_receipt(receipt_id)` | Fetch the full record of a run. |
| `verify_receipt(receipt_id \| receipt)` | Check a receipt's hash and its place in the chain. |
| `sandbox_status()` | Check that the sandbox is ready, without running anything. |

Tests are plain Python. Top-level `assert` statements run as the `<module>` step, and every
top-level `test_*` function without arguments runs as its own test. The code's names are available
directly, or through `from solution import name`.
