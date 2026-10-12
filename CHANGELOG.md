# Changelog

## 0.1.0 (unreleased)

- MCP server with `verify_python`, `run_python`, `get_receipt`, `verify_receipt` and
  `sandbox_status`, over stdio or Streamable HTTP (bearer token, or an opt-in capability path).
- Hardened per-call containers. Settings are inspected before start, a privilege-separated
  in-container supervisor runs the code, and the container is force-removed with confirmation.
- Hash-chained, append-only receipts for every run, including failures.
- CLI: `serve`, `doctor`, `image build`, `verify`, `run`, `receipts`, `http-token`.
