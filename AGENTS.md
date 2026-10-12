# jovin-harness

An MCP server that runs agent-written Python in hardened, disposable containers and keeps
hash-chained receipts. It is Apache-2.0 and written fresh: don't copy code from JoVin or Renigma,
which are PolyForm Noncommercial. Reimplementing their published ideas is fine.

- `src/jovin_harness/sandbox_image/runner.py` runs inside the container as PID 1 and uses only the
  standard library. Any change to it changes the runner hash, so users must rebuild the image.
- Never add a code path that runs submitted code on the host, and never weaken a container setting
  without updating `Sandbox.validate_container` and SECURITY.md together.
- Every execution is receipted, including failures. Text that came from the sandbox is untrusted.

Checks: `pytest` (unit, no engine needed), `pytest -m container` (needs a Linux container engine),
`ruff check .`. Keep virtual environments and pytest temp dirs out of synced folders.
