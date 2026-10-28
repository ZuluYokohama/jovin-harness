# jovin-harness

Let AI coding agents check their code before they claim it works.

`jovin-harness` is an [MCP](https://modelcontextprotocol.io) server. An agent (Claude Code,
Claude Desktop, Codex CLI or the ChatGPT desktop app, Grok Build, or any MCP client) sends Python code
and tests. The harness runs them in a fresh, locked-down container and returns the result along with a
**receipt**: a hash-chained record of exactly what ran, under which limits, and what the sandbox
reported.

- **Submitted code runs only inside disposable containers.** Every call gets a new container with
  no network, a read-only root, unprivileged workers, and memory, PID, CPU and file limits. The container's settings are inspected
  before it starts. With no container engine, the harness refuses to run rather than fall back to the
  host.
- **Tests and candidate code are separated by default.** The tests and the code run as
  different users in separate processes. Tests call the code's functions through proxies that pass
  plain data (numbers, strings, lists, dicts, tuples, sets, bytes). This prevents shared-interpreter
  mutation; the remaining IPC and test-coverage limitations are documented in SECURITY.md. A supervisor decides pass or fail against its own list of
  expected tests. Receipts record `integrity: "process_isolated"`. For tests that need the code's
  classes or objects, `isolation="shared"` runs both in one process; such receipts say
  `"shared_interpreter"`. See [SECURITY.md](SECURITY.md).
- **Receipts are tamper-evident.** Each receipt hashes its inputs and results and links to the
  previous one. `verify_receipt` checks one receipt and its recorded index link;
  `jovin-harness receipts verify` checks the whole store, including missing receipt files and
  reordering. Failures are receipted too. Receipts are unsigned unless a signing key is configured
  (below); see SECURITY.md.

> Status: early development (0.2.0.dev0). Read [SECURITY.md](SECURITY.md) for what the sandbox does
> and doesn't protect against.

Local repair validation and measurements: [reliability results](docs/RELIABILITY.md).

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
| `JOVIN_HARNESS_SIGNING_KEY` | Optional Ed25519 private key (PEM, absolute path outside the data dir). Each receipt gets a `<id>.sig` and every append rewrites a signed `head.checkpoint` (count, head hash, epoch, wall time). Needs `pip install 'jovin-harness[signing]'` |
| `JOVIN_HARNESS_VERIFY_KEY` | Optional Ed25519 public key (PEM) for verify-only use; with it, unsigned or badly signed receipts and a checkpoint that does not match the index fail `receipts verify` |
| `JOVIN_HARNESS_HEAD_ANCHOR` | Optional append-only file (outside the data dir) that receives a copy of every signed checkpoint. Only this detects a rollback to an older signed checkpoint plus a matching truncation; keep it where the writer of the data dir cannot rewrite it |

The same three settings can be given in `config.toml` as `signing_key`, `verify_key` and `head_anchor`.
`jovin-harness receipts checkpoint` prints the signed checkpoint.

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

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
