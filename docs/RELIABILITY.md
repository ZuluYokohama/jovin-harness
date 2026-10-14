# Reliability repair: local setup and results

This repair starts at `713dd0e83bcbba96a4c21225b1de338ce1ee00ab` on
`codex/jovin-reliability`. It preserves fresh containers, default process isolation,
the five MCP tools, and unsigned v1 receipts. Validation completed on 2026-10-14.
The machine's retained evidence is under `D:\JovinHarness_Artifacts\evidence`;
[the evidence manifest](RELIABILITY_EVIDENCE.json) records source and artifact hashes.

## Fixes and evidence

| Finding | Fix | Regression / retained evidence |
| --- | --- | --- |
| A passing payload could override timeout, OOM or abnormal termination | [Host termination is authoritative](../src/jovin_harness/sandbox.py); `reported_result` retains the payload as diagnostics | [Lifecycle tests](../tests/test_sandbox.py): `test_engine_failure_overrides_reported_pass`, `test_host_deadline_overrides_reported_pass`, `test_unclean_engine_termination_rejects_pass`; `container-check-2.xml` |
| Deeply nested replies could be caught by `except Exception` and produce a false pass | [Parser converts recursion failure to `HarnessFailure`](../src/jovin_harness/sandbox_image/runner.py) and leaves the channel broken | [Proxy tests](../tests/test_proxies.py), [real-container regression](../tests/test_container_isolation.py); `parser-baseline-proof-001.json` versus `parser-fixed-proof-001.json` |
| Uncertain creation or cleanup could lose ownership/accounting | Exact run label and pinned image are checked before cleanup; interruptions and cleanup failures produce receiptable blocked outcomes | [Lifecycle tests](../tests/test_sandbox.py): `test_uncertain_creation_cleans_only_owned_container`, `test_interruption_is_receipted_and_cleanup_attempted`, `test_cleanup_error_is_recorded_by_harness` |
| Sweeping could affect active or unrelated containers | Only confirmed stopped containers with the expected image and valid run label are removed, without force; absence is confirmed | [Sweep tests](../tests/test_sandbox.py), [CLI diagnostics](../tests/test_cli.py); `installed-smoke-2.json`, `final-cleanup.json` |
| Readers could observe receipt/index writes inconsistently | [Readers and writers share the cross-process lock](../src/jovin_harness/receipts.py); verification and head use one parsed snapshot | [Receipt concurrency tests](../tests/test_receipts.py), including a real cross-process reader/writer; [single-snapshot tool test](../tests/test_tools.py) |
| Malformed records and torn final index writes were unsafe | Validate JSON structure before field access; recover only a unique complete hash-valid matching orphan after checking the preceding chain; preserve original damaged bytes | [Receipt tests](../tests/test_receipts.py): malformed objects, duplicates, torn writes, ambiguous recovery, failed replacement, tampering, deletion and old canonical receipts |

Individual receipt verification checks its hash and immediate recorded index link.
Use `jovin-harness receipts verify` to check all indexed files and the whole chain.
Recovery never rewrites historical receipt contents. Receipts remain unsigned;
rewriting an entire store cannot be detected without a separately trusted head.
Process separation does not eliminate shared loopback/SysV IPC or limitations of
the tests themselves. See [SECURITY.md](../SECURITY.md).

## Local runtime

Source, Windows virtual environments, downloads, caches, temporary files, Docker
storage and evidence live under `D:\JovinHarness_Artifacts`. A separate Ubuntu
24.04 distribution named `JovinHarness` is stored at `runtime\JovinHarness`.
Docker Engine 29.9.0 was installed from Docker's signed official Ubuntu repository
inside that distribution and uses its local Unix socket. No Docker TCP listener
was enabled. WSL 2.7.3 / kernel 6.6.114.1 and Ubuntu 24.04.5 were recorded.
The host is an Intel i9-9900K with 32 GB RAM; these checks do not use a GPU.

The retained setup scripts are `runtime\setup-docker.sh` and
`runtime\setup-python.sh`; the former records the version selected at installation.
Dependency snapshots are `windows-dependencies.txt`, `linux-dependencies.txt` and
`wheel-check-dependencies.txt`. They are observations of this installation, not a
promise that running an unpinned installer later yields identical dependencies.
ClayMaths disks/registrations and global WSL configuration were left unchanged.
No host repair or restart was required for this distribution.

For the already installed local runtime, use PowerShell:

```powershell
Set-Location D:\JovinHarness_Artifacts\source
$env:TEMP = 'D:\JovinHarness_Artifacts\temp'
$env:TMP = $env:TEMP
$env:PIP_CACHE_DIR = 'D:\JovinHarness_Artifacts\cache\pip'
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:JOVIN_HARNESS_RUNTIME = 'wsl:JovinHarness'
$env:JOVIN_HARNESS_DATA_DIR = 'D:\JovinHarness_Artifacts\runtime\harness-data'
$python = 'D:\JovinHarness_Artifacts\environments\windows\Scripts\python.exe'
& $python -m jovin_harness doctor
& $python -m jovin_harness serve
```

These are process-local settings. MCP clients must inherit or supply the same
runtime/data environment. The Linux development interpreter is
`/opt/jovin-venv/bin/python` inside this D-backed distribution. The separately
installed wheel interpreter is `environments\wheel-check\Scripts\python.exe`.

Current sandbox image:
`sha256:c6ecb3c2dd0a63a8612371f06cd1a4c110ea5fd46ea7825f51174b3a6393fab4`.
Packaged runner SHA-256:
`8a847c3e8ac4d31afd86fe9b415e077d4be2ef3ede7cbf28696b6010f58ddfb2`.
Run `& $python -m jovin_harness image build` after changing the runner; admission
checks reject an image whose runner hash differs. Every execution still inspects
its fresh container and checks the reported kernel enforcement.

Run `doctor --sweep` after active harness jobs finish. `swept` contains confirmed
removals; `sweep_skipped` and `sweep_failed` explain unresolved entries. Either
nonempty diagnostic list makes this command return nonzero. It preserves active
containers rather than treating them as leftovers.

## Acceptance results

| Command / check | Result | Evidence file under `evidence` |
| --- | --- | --- |
| Windows `python -m pytest -q` | 234 passed, 36 container tests skipped | `final-windows-2.txt`, `.xml` |
| WSL Linux `python -m pytest -q` | 233 passed, 37 skipped (container tests and one Windows-specific test) | `final-linux-2.txt`, `.xml` |
| `python -m pytest -q -m container` via `wsl:JovinHarness` | **36 passed**, 234 deselected; no container skips | `container-check-2.txt`, `.xml` |
| `python -m ruff check .` | Passed | `final-ruff-2.txt` |
| `python -m build --outdir ...` | Wheel and sdist built; packaged modules match evaluated source and include runner/Dockerfile | `final-package-build.txt`, `package-content-check.json` |
| Installed wheel CLI and real stdio MCP | Passed: pass/fail CLI paths, five tools listed, MCP execution, receipt lookup/verification and full chain | `installed-smoke-2.json` |
| Removal after all local execution | No containers remain in the dedicated engine | `final-cleanup.json` |

The real tests exercise memory/PID/output/time limits, network/filesystem
restrictions, worker user/process separation, malformed replies and complete
container removal. Unit-test skips are not used as container acceptance.
Two bounded source reviews found no remaining blockers; they do not represent
external security certification. Local tests used Python 3.12; the full GitHub
Python/OS matrix has not executed successfully.

Earlier failed attempts remain retained. The first Linux/container parser test
used 5,000 nesting levels, below the Linux parser's failure threshold; 20,000
levels reproduced the original false pass and the repaired `HarnessFailure` in
real containers. The first installed smoke's final sweep overlapped the container
suite and correctly refused to remove its active container. Its isolated retry
passed. No failure record was converted into a pass or removed.

GitHub's baseline CI run was blocked before job steps by billing/spending limits:
[run 38512243636](https://github.com/ZuluYokohama/jovin-harness/actions/runs/38512243636).
Local acceptance is recorded separately. No account settings were changed; a
failed infrastructure run is not evidence of executed tests.

## Measurements

[The receipt benchmark](../tools/benchmark_receipts.py) uses 10, 1,000 and 10,000
synthetic canonical v1 records. Both source versions performed 405 timed API calls,
33 fixture prechecks and 240 reads overlapping append calls, with zero errors or
invalid snapshots. Every mutating repetition starts from its own exact-size
fixture. Five repeats were used for sequential operations.

Median milliseconds, baseline → repaired:

| Records | Verify + head | Append | Whole chain | Concurrent verify + head |
| ---: | ---: | ---: | ---: | ---: |
| 10 | 0.574 → 0.490 | 1.834 → 1.793 | 1.750 → 1.889 | 1.121 → 2.577 |
| 1,000 | 4.362 → 7.436 | 9.465 → 11.814 | 153.432 → 149.991 | 10.022 → 19.681 |
| 10,000 | 44.477 → 74.971 | 85.381 → 105.777 | 1,705.789 → 1,580.269 | 81.669 → 257.686 |

Removing redundant index parsing did not establish a general speedup. Validation
and coordinated readers/writers add work and contention. Background Docker/tests
and filesystem-cache state were not isolated or equalized; these are observations,
not a controlled causal comparison. Raw events and hashes remain in
`benchmarks\baseline-001.json`, `updated-001.json` and `comparison-001.json`.

[The sandbox benchmark](../tools/benchmark_sandbox.py) ran five sequential calls
with one harness instance and five fresh containers. All results and receipt
checks passed; all five containers were removed. Seconds on this Windows-to-WSL
configuration:

| Phase | Median seconds | Range seconds |
| --- | ---: | ---: |
| Preflight | 0.000 | 0.000–4.906 |
| Create + inspect | 0.500 | 0.500–0.531 |
| Execution + terminal inspection | 0.766 | 0.750–0.922 |
| Cleanup | 0.469 | 0.469–0.484 |
| Receipt persistence | 0.0028 | 0.0019–0.0030 |
| End to end | 1.750 | 1.739–6.830 |

The first preflight took 4.906 seconds; subsequent preflight calls used the existing
instance's admission cache. Container inspection and kernel checks still ran per
execution. The execution phase includes attach/I/O and terminal inspection, not
just candidate compute. Receipt persistence is measured externally because a
receipt cannot seal its own completed append duration. Total time includes small
uncategorized host overhead; phase medians need not sum to the total median.
See `sandbox-benchmark-001.json` for each sample. No baseline sandbox speedup is
claimed, and no container pooling was introduced.

To repeat benchmarks, choose new evidence/data paths so prior attempts remain:

```powershell
& $python tools\benchmark_receipts.py --source D:\JovinHarness_Artifacts\source --data-root D:\JovinHarness_Artifacts\temp\receipt-benchmark-new --output D:\JovinHarness_Artifacts\evidence\receipt-benchmark-new.json
& $python tools\benchmark_sandbox.py --output D:\JovinHarness_Artifacts\evidence\sandbox-benchmark-new.json --repeats 5
```

Receipt signing, model integration, container reuse, unrelated recovery and PR
merging are outside this repair.
