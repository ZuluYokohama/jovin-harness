# jovin-harness

Let AI coding agents check their code before they claim it works.

`jovin-harness` is an [MCP](https://modelcontextprotocol.io) server. An agent (Claude Code,
Claude Desktop, Codex CLI or the ChatGPT desktop app, Grok Build, or any MCP client) sends Python code
and tests. The harness runs them in a fresh, locked-down container and returns the result along with a
**receipt**: a hash-chained record of exactly what ran, under which limits, and what the sandbox
reported.

- **No code runs on your machine.** Every call gets a new container with no network, a read-only
  root, no capabilities, and memory, PID, CPU and file limits. The container's settings are inspected
  before it starts. With no container engine, the harness refuses to run rather than fall back to the
  host.
- **The code under test can't touch the verdict.** By default the tests and the code run as
  different users in separate processes. Tests call the code's functions through proxies that pass
  plain data (numbers, strings, lists, dicts, tuples, sets, bytes), so the code influences the result
  only through what its functions return or raise. A supervisor decides pass or fail against its own list of
  expected tests. Receipts record `integrity: "process_isolated"`. For tests that need the code's
  classes or objects, `isolation="shared"` runs both in one process; such receipts say
  `"shared_interpreter"`. See [SECURITY.md](SECURITY.md).
- **Receipts are tamper-evident.** Each receipt hashes its inputs and results and links to the
  previous one, so `verify_receipt` notices edits, deletions and reordering. Failures are receipted
  too.

> Status: early development (0.2.0.dev0). Read [SECURITY.md](SECURITY.md) for what the sandbox does
> and doesn't protect against.

## Quick start

Requirements: Python 3.11+ and a Linux container engine (Docker Engine, Docker Desktop, or Docker
inside WSL 2).

```bash
pipx install jovin-harness
jovin-harness image build
jovin-harness doctor
```

Connect an agent. For example, Claude Code:

```bash
claude mcp add jovin -- jovin-harness serve
```

Codex CLI, Grok Build, Claude Desktop and remote HTTP setups (OpenAI Responses API, Anthropic API,
xAI API, ChatGPT connectors) are covered in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md). To make
agents use it consistently, add [templates/AGENTS.snippet.md](templates/AGENTS.snippet.md) to your
project's agent instructions.

You can also run checks by hand:

```bash
jovin-harness verify solution.py --tests test_solution.py              # process isolation
jovin-harness verify solution.py --tests test_solution.py --isolation shared
jovin-harness receipts verify          # check the whole chain
jovin-harness receipts head            # export this somewhere you trust
```

## What an agent sees

```json
{
  "status": "failed", "passed": false, "total": 2, "passed_count": 1,
  "failures": [{"name": "test_add", "outcome": "failed",
                "message": "AssertionError at line 4: assert add(2, 3) == 5"}],
  "integrity": "process_isolated",
  "receipt_id": "20261012T221530Z-3f9a1c0b7e2d",
  "receipt_sha256": "…"
}
```

## Configuration

| Variable | Meaning |
|---|---|
| `JOVIN_HARNESS_RUNTIME` | `docker` (default), `podman` (experimental), or `wsl:<distro>[@user]` |
| `JOVIN_HARNESS_CONTAINER_ARGV` | JSON array giving any other CLI prefix, for example `["nerdctl"]` |
| `JOVIN_HARNESS_IMAGE` | Override the pinned image ID (`sha256:…`) |
| `JOVIN_HARNESS_DATA_DIR` | Where receipts, the pinned config and HTTP secrets live (defaults to the platform data dir) |
| `JOVIN_HARNESS_TIMEOUT_S` | Default per-run limit, at most 30 |
| `JOVIN_HARNESS_MAX_CONCURRENCY` | Concurrent sandboxes (default 2) |

Limits can also be set in `<data_dir>/config.toml` under `[limits]`. They can be lowered, never
raised past the built-in ceilings.

## Development

```bash
python -m venv .venv && . .venv/bin/activate     # keep the venv outside synced folders
pip install -e ".[dev]"
pytest                    # unit tests; container tests are skipped
pytest -m container       # end-to-end tests against a real engine (builds the image)
ruff check .
```

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE). Commercial use requires a separate license from the copyright holder, B. Jones (b.jones@jtech.ai). See [NOTICE](NOTICE). Versions published before 2026-10-16 were released under the Apache License 2.0, and those versions keep it.
