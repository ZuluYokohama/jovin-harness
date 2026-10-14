# Security model

jovin-harness runs code that an AI agent wrote, and that code may be wrong, confused or hostile. A
prompt-injected agent can be told to submit anything. This file describes what the sandbox does,
what it doesn't do, and how to report a problem.

## What every run gets

- A **fresh container** per call, removed afterwards. `jovin-harness doctor --sweep` removes only
  confirmed stopped harness containers with matching ownership and image evidence. Running, created
  and ambiguously owned containers are skipped. Removal is reported only after confirming absence;
  unresolved cleanup produces a nonzero command status.
- **No network** (`--network none`), a **read-only root filesystem**, and a 16 MiB `noexec` tmpfs
  at `/tmp` as the only writable place.
- **All Linux capabilities dropped.** The in-container supervisor keeps only `SETUID`/`SETGID` (to
  drop the workers to unprivileged uids), `CHOWN` (to give each worker a private scratch directory)
  and `KILL` (to stop them at the deadline). The workers have none. Plus `no-new-privileges`, the engine's default seccomp profile, and limits on memory (512 MiB,
  no swap), PIDs (64), CPU (1), open files (64) and file size (16 MiB).
- **Privilege separation inside the container.** The supervisor (PID 1, root, non-dumpable) never
  runs submitted code. Before sending any code, it checks each worker's uid, gid, capabilities,
  `NoNewPrivs` and seccomp mode through `/proc`. Workers can't signal the supervisor, read its
  memory, or write to its output.
- **Process isolation for verification (default).** The code under test runs as uid 65534 and the
  agent's tests as uid 65533, in separate processes. Neither can signal the other or read its memory
  or file descriptors. Tests reach the code only through proxies that exchange plain data over a
  pipe. The codec decodes to built-in types only (no pickle, no custom objects), so returned values
  can't run code or override comparisons. Exceptions come back as builtin exception types. Harness
  failures, such as the code exiting mid-call or an unsupported value, are raised as a
  `BaseException` that a test's `except Exception` can't swallow. Each worker gets a private 0700
  home and `TMPDIR`, and `/tmp` and `/dev/shm` are made unwritable, so the code can't plant files for
  the tests. The workers still share the loopback interface and SysV IPC, so tests that deliberately
  read from those could see data the code left there. The test process reports results on a pipe the code
  process doesn't hold, and the supervisor still judges against its own expected-test list. Receipts
  carry `integrity: "process_isolated"`.
- **Settings are verified before start.** The host inspects each container after creating it and
  refuses to start it unless the image ID, network, mounts, capabilities, security options, limits,
  tmpfs, ulimits and log driver match the profile.
- **Deadlines on both sides.** The supervisor's own alarm ends PID 1 even if the host side
  disappears, and the host kills the container at its own deadline. A host timeout, OOM, abnormal
  supervisor exit or unconfirmed terminal state cannot be overridden by a passing runner payload.
  Overridden payloads remain diagnostic data in failure receipts.
- **Bounded input and output.** Code, tests and stdin are capped at 256 KiB each. Output tails are
  capped at 64 KiB, and a flood stops the run.
- **Fail closed.** With no reachable engine, no pinned image, an engine without seccomp, or an image
  built from a different runner, the harness refuses to run. It never falls back to the host.

## What it does not protect against

- **A container is not a virtual machine.** Containers share the host kernel, so a kernel
  vulnerability could break isolation. If you expose the HTTP endpoint beyond your own machine, run
  the engine inside a VM (Docker Desktop and WSL 2 already do) or under gVisor (`--runtime=runsc`).
- **`isolation="shared"` verdicts can be faked by adversarial code.** That mode runs tests and code
  in one Python process (needed when tests use the code's classes or objects), so code written to
  cheat can tamper with the test functions or the result pipe. The verdict is reliable for honest
  mistakes. Receipts carry `integrity: "shared_interpreter"` so nobody mistakes it for more.
- **Process isolation proves what the tests check, nothing more.** The code can still behave
  differently on inputs the tests don't cover, or detect that it's being tested. Weak tests give weak
  evidence, and `tests_sha256` in the receipt shows exactly which tests ran. The tests themselves are
  agent-written and run unprivileged; they're judged, not trusted.
- **Receipts are tamper-evident, not signed.** Each receipt hashes its contents and the previous
  receipt. Whole-store verification detects edits, missing files and reordering; individual
  verification checks the selected receipt and its recorded index link. Readers and writers share
  a cross-process lock. Interrupted final index writes are recovered only from one unambiguous,
  hash-valid matching receipt, retaining the damaged bytes; ambiguous corruption is refused.
  Someone with write access to the data
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
