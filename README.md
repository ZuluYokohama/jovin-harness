# jovin-harness

Let AI coding agents check their code before they claim it works.

`jovin-harness` is an [MCP](https://modelcontextprotocol.io) server. An agent (Claude Code,
Codex CLI or the ChatGPT desktop app, Grok Build, or any MCP client) sends Python code and tests.
The harness runs them in a fresh, locked-down container and returns the result along with a
**receipt**: a hash-chained record of exactly what ran, under which limits, and what the sandbox
reported.

- **No code runs on your machine.** Every call gets a new container with no network, a read-only
  root, no capabilities, and memory, PID, CPU and file limits. With no container runtime, the
  harness refuses to run rather than fall back to the host.
- **The verdict comes from outside the code under test.** A supervisor process decides pass or
  fail from a separate channel, so printing fake results or exiting early doesn't count as a pass.
- **Receipts are tamper-evident.** Each receipt hashes its inputs and results and links to the
  previous one, so `verify_receipt` notices edits, deletions and reordering.

> Status: early development (0.1.0.dev0). See [SECURITY.md](SECURITY.md) for what the sandbox
> does and doesn't protect against.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
