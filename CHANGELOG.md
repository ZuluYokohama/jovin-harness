# Changelog

## 0.2.0 (unreleased)

- **Process isolation is the default for `verify_python`.** The code under test (uid 65534) and the
  tests (uid 65533) run in separate processes. Tests call the code's functions through proxies that
  exchange plain data only. Receipts record `integrity: "process_isolated"`.
  `isolation="shared"` keeps the single-process behavior for tests that need classes or objects.
- The supervisor stops a code process that outlives its tests without calling the run a timeout.
- The HTTP gate reads a bounded request body before rejecting, so clients reliably see the 401/404
  instead of a reset connection.

## 0.1.0 (unreleased)

- MCP server with `verify_python`, `run_python`, `get_receipt`, `verify_receipt` and
  `sandbox_status`, over stdio or Streamable HTTP (bearer token, or an opt-in capability path).
- Hardened per-call containers. Settings are inspected before start, a privilege-separated
  in-container supervisor runs the code, and the container is force-removed with confirmation.
- Hash-chained, append-only receipts for every run, including failures.
- CLI: `serve`, `doctor`, `image build`, `verify`, `run`, `receipts`, `http-token`.
