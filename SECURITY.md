# Security model

jovin-harness runs code that an AI agent wrote, and that code may be wrong, confused or hostile. A
prompt-injected agent can be told to submit anything. This file describes what the sandbox does,
what it doesn't do, and how to report a problem.

## What every run gets

- A **fresh container** per call, removed afterwards. Leftovers from crashes are swept by
  `jovin-harness doctor --sweep`.
- **No network** (`--network none`), a **read-only root filesystem**, and a 16 MiB `noexec` tmpfs
  at `/tmp` as the only writable place.
- **All Linux capabilities dropped.** The in-container supervisor keeps only `SETUID`/`SETGID` (to
  drop the worker to uid 65534) and `KILL` (to stop it at the deadline). The worker has none. Plus `no-new-privileges`, the engine's default seccomp profile, and limits
  on memory (512 MiB, no swap), PIDs (64), CPU (1), open files (64) and file size (16 MiB).
- **Privilege separation inside the container.** The supervisor (PID 1, root, non-dumpable) never
  runs submitted code. A worker does, as uid/gid 65534 with no capabilities. The supervisor checks
  the worker's uid, gid, capabilities, `NoNewPrivs` and seccomp mode through `/proc` before sending it
  any code. The worker can't signal the supervisor, read its memory, or write to its output.
- **Settings are verified before start.** The host inspects each container after creating it and
  refuses to start it unless the image ID, network, mounts, capabilities, security options, limits,
  tmpfs, ulimits and log driver match the profile.
- **Deadlines on both sides.** The supervisor's own alarm ends PID 1 even if the host side
  disappears, and the host kills the container at its own deadline.
- **Bounded input and output.** Code, tests and stdin are capped at 256 KiB each. Output tails are
  capped at 64 KiB, and a flood stops the run.
- **Fail closed.** With no reachable engine, no pinned image, an engine without seccomp, or an image
  built from a different runner, the harness refuses to run. It never falls back to the host.

## What it does not protect against

- **A container is not a virtual machine.** Containers share the host kernel, so a kernel
  vulnerability could break isolation. If you expose the HTTP endpoint beyond your own machine, run
  the engine inside a VM (Docker Desktop and WSL 2 already do) or under gVisor (`--runtime=runsc`).
- **`shared_interpreter` verdicts can be faked by adversarial code.** In `verify_python`, the tests
  and the code under test share one Python process, so code written to cheat can tamper with the
  test functions or the result pipe. The verdict is reliable for honest mistakes, which is what agents
  usually make. Receipts carry `integrity: "shared_interpreter"` so nobody mistakes it for more. A
  stronger mode, with tests and code in separate processes, is planned.
- **Receipts are tamper-evident, not signed.** Each receipt hashes its contents and the previous
  receipt, so edits, deletions and reordering are detected. Someone with write access to the data
  directory could rebuild a consistent chain, though. Export the chain head
  (`jovin-harness receipts head`) somewhere you control if that matters.
- **Output is untrusted.** `stdout_tail`, `stderr_tail` and failure messages come from the code under
  test and may contain text aimed at the agent. The server's instructions tell agents to treat them as
  data.

## The HTTP endpoint

- By default it listens on `127.0.0.1` only and requires `Authorization: Bearer <token>`. The token
  lives in the data directory and `jovin-harness http-token` prints it.
- Binding to another address needs `--allow-remote` and `--allowed-host`, which keeps DNS-rebinding
  protection on for the hostname you expose.
- `--auth path-secret` serves the endpoint at `/mcp/<256-bit secret>` instead, for clients that can't
  send headers (ChatGPT developer-mode connectors). **The URL is the credential:** anyone who has it
  can run code in your sandbox. This mode limits runs to 10 a minute, one at a time, and disables
  access logging. Only use it behind an HTTPS tunnel, and rotate the secret by deleting
  `http_path_secret` in the data directory.

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository rather than a public issue.
