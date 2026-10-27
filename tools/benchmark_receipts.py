"""Receipt-only before/after benchmark; never runs a sandbox or candidate code.

Use the same interpreter, repeats and this script for each source tree. Every run
requires a new data root and output filename. Synthetic canonical v1 chains are
built and fully verified outside the measured calls. Read-only samples reuse an
unchanged fixture; each mutation repeat starts from a separately written fixture
of exactly the requested size. Prechecks warm filesystem caches: these are not
cold-cache measurements. Concurrent wall time includes journal writes/scheduling;
individual API timings exclude fixture preparation, validation and journaling.

Every completed call (including errors and invalid observations) is flushed to
events.jsonl, then included in the final JSON. A hard process kill may leave only
the journal. No speedup or security guarantee is inferred from these measurements.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import statistics
import sys
import threading
import time
import traceback
from collections import defaultdict
from datetime import UTC, datetime
from functools import partial
from pathlib import Path

SIZES = (10, 1000, 10000)
CONCURRENT_APPENDS = 8
CONCURRENT_READS_PER_READER = 8
CONCURRENT_READERS = 2


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_pins(source: Path) -> dict[str, str]:
    return {p.relative_to(source).as_posix(): digest(p)
            for p in sorted((source / "src" / "jovin_harness").rglob("*.py"))}


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


class NoSandbox:
    """Fail loudly if this benchmark accidentally attempts container activity."""

    def __getattr__(self, name):
        raise AssertionError(f"benchmark must not use sandbox.{name}")


class Journal:
    def __init__(self, path: Path):
        self.handle = path.open("x", encoding="utf-8", newline="\n")
        self.events = []
        self.lock = threading.Lock()

    def add(self, event: dict) -> dict:
        with self.lock:
            event["sequence"] = len(self.events)
            self.events.append(event)
            self.handle.write(json.dumps(event, sort_keys=True, allow_nan=False) + "\n")
            self.handle.flush()
            os.fsync(self.handle.fileno())
        return event

    def timed(self, operation: str, size: int, repeat: int, call, **context) -> dict:
        event = {"kind": "timing", "operation": operation, "size": size,
                 "repeat": repeat, **context}
        start = time.perf_counter_ns()
        try:
            event["result"] = call()
        except Exception as error:
            event["error"] = {"type": type(error).__name__, "message": str(error),
                              "traceback": traceback.format_exc()}
        finally:
            end = time.perf_counter_ns()
            event.update(start_ns=start, end_ns=end, elapsed_ns=end - start)
        return self.add(event)


def check_snapshot(result, expected_head=None, count_range=None) -> list[str]:
    problems = []
    if not isinstance(result, dict):
        return ["verification returned a non-object"]
    if result.get("valid") is not True or result.get("chain") != "linked" or result.get("problems") != []:
        problems.append("verification did not report a valid linked receipt")
    head = result.get("head")
    if not isinstance(head, dict):
        return [*problems, "verification returned no head object"]
    if expected_head is not None and head != expected_head:
        problems.append("verification head differs from the expected fixture head")
    if count_range is not None:
        count = head.get("count")
        if type(count) is not int or not count_range[0] <= count <= count_range[1]:
            problems.append("verification head count is outside the possible append range")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    source = args.source.resolve(strict=True)
    data_root = args.data_root.resolve()
    output = args.output.resolve()
    if data_root.exists() or output.exists():
        parser.error("--data-root and --output must both be new")
    if data_root.is_relative_to(source) or output.is_relative_to(source):
        parser.error("benchmark artifacts must be outside the source checkout")
    if not (source / "src" / "jovin_harness" / "receipts.py").is_file():
        parser.error("--source is not a Jovin Harness checkout")
    if any(name == "jovin_harness" or name.startswith("jovin_harness.") for name in sys.modules):
        parser.error("run this script in a fresh interpreter")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(source / "src"))
    receipts = importlib.import_module("jovin_harness.receipts")
    tools = importlib.import_module("jovin_harness.tools")
    config = importlib.import_module("jovin_harness.config")
    for module in (receipts, tools, config):
        if not Path(module.__file__).resolve().is_relative_to(source):
            parser.error(f"module came from a different checkout: {module.__name__}")

    data_root.mkdir(parents=True, exist_ok=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    journal = Journal(data_root / "events.jsonl")
    report = {
        "format": "jovin-harness.receipt-benchmark.v1",
        "started_at": utc_now(), "source": str(source), "source_before": source_pins(source),
        "script": {"path": str(Path(__file__).resolve()), "sha256": digest(Path(__file__))},
        "interpreter": {"executable": sys.executable, "sha256": digest(Path(sys.executable)),
                        "version": sys.version, "implementation": platform.python_implementation()},
        "platform": platform.platform(), "data_root": str(data_root),
        "sizes": list(SIZES), "repeats": args.repeats,
        "concurrency": {"writers": 1, "appends": CONCURRENT_APPENDS,
                        "readers": CONCURRENT_READERS, "reads_per_reader": CONCURRENT_READS_PER_READER},
        "timing_clock": {"name": "perf_counter_ns", "resolution_s": time.get_clock_info("perf_counter").resolution},
        "limitations": [
            "Synthetic receipts only; no model, candidate or container execution.",
            "Prechecks and fixture construction warm caches; no cold-cache or randomized-order claim.",
            "Read-only repeats share an unchanged fixture; each mutation repeat has a separate fresh fixture.",
            "Concurrent individual API timing excludes journaling; wall time includes journaling and scheduling.",
            "Thread concurrency is exercised within one process; this is not a multiprocess stress test.",
            "Retained measurements alone do not establish a speedup or security guarantee.",
        ],
    }
    invalid_count = 0

    def validate(event: dict, problems: list[str]) -> None:
        nonlocal invalid_count
        if "error" in event:
            problems = [*problems, "API raised an exception"]
        invalid_count += bool(problems)
        journal.add({"kind": "validation", "timing_sequence": event["sequence"],
                     "valid": not problems, "problems": problems})

    def chain_check(store, size, dataset, phase, expected_count):
        result = store.verify_chain()
        valid = result.get("valid") is True and result.get("count") == expected_count
        journal.add({"kind": "chain_check", "size": size, "dataset": str(dataset),
                     "phase": phase, "expected_count": expected_count, "valid": valid, "result": result})
        if not valid:
            raise RuntimeError(f"{phase} chain check failed: {dataset}")
        return result

    try:
        for size in SIZES:
            print(f"Preparing and measuring {size} receipts", flush=True)
            fixture = []
            index = []
            previous = None
            for number in range(size):
                receipt = {
                    "format": receipts.FORMAT, "id": f"20260101T000000Z-{number:012x}",
                    "created_at": "2026-01-01T00:00:00.000Z", "notice": receipts.NOTICE,
                    "tool": "benchmark_fixture",
                    "inputs": {"code_sha256": hashlib.sha256(f"synthetic-{number}".encode()).hexdigest()},
                    "result": {"status": "synthetic", "sequence": number}, "prev_sha256": previous,
                }
                receipt["sha256"] = receipts.receipt_hash(receipt)
                fixture.append((receipt["id"], receipts.canonical_json(receipt)))
                index.append(receipts.canonical_json({
                    key: receipt[key] for key in ("id", "sha256", "prev_sha256")}) + b"\n")
                previous = receipt["sha256"]
            index_bytes = b"".join(index)
            target_id = fixture[-1][0]
            initial_head = {"count": size, "head_sha256": previous, "head_id": target_id}
            journal.add({"kind": "fixture_spec", "size": size, "target_id": target_id,
                         "index_sha256": hashlib.sha256(index_bytes).hexdigest(),
                         "initial_head": initial_head, "receipt_bytes": sum(len(raw) for _, raw in fixture)})

            def build_fixture(label, size=size, fixture=fixture, index_bytes=index_bytes):
                dataset = data_root / f"size-{size}" / label
                directory = dataset / "receipts"
                directory.mkdir(parents=True, exist_ok=False)
                for receipt_id, raw in fixture:
                    with (directory / f"{receipt_id}.json").open("xb") as handle:
                        handle.write(raw)
                with (directory / "index.jsonl").open("xb") as handle:
                    handle.write(index_bytes)
                store = receipts.ReceiptStore(directory)
                chain_check(store, size, dataset, "before_measurement", size)
                settings = config.Settings(runtime="benchmark-disabled", container_command=(), image=None,
                                           data_dir=dataset)
                harness = tools.Harness(settings=settings, sandbox=NoSandbox(), store=store)
                return dataset, store, harness

            dataset, store, harness = build_fixture("readonly")
            for repeat in range(args.repeats):
                event = journal.timed("verify_and_head", size, repeat,
                                      partial(harness.verify_receipt, receipt_id=target_id), dataset=str(dataset))
                validate(event, check_snapshot(event.get("result"), expected_head=initial_head))
                event = journal.timed("full_chain", size, repeat, store.verify_chain, dataset=str(dataset))
                result = event.get("result", {})
                validate(event, [] if result.get("valid") is True and result.get("count") == size
                         and result.get("head_sha256") == previous else ["full chain result differs from fixture"])
            chain_check(store, size, dataset, "after_readonly", size)

            for repeat in range(args.repeats):
                dataset, store, harness = build_fixture(f"append-{repeat:03d}")
                event = journal.timed("append", size, repeat,
                                      partial(store.append, {"tool": "benchmark_append",
                                                             "result": {"synthetic": True}}),
                                      dataset=str(dataset))
                result = event.get("result", {})
                validate(event, [] if result.get("prev_sha256") == previous
                         and result.get("sha256") == receipts.receipt_hash(result) else ["appended receipt is invalid"])
                chain_check(store, size, dataset, "after_append", size + (0 if "error" in event else 1))

                dataset, store, harness = build_fixture(f"concurrent-{repeat:03d}")
                barrier = threading.Barrier(CONCURRENT_READERS + 2)
                observations = []
                successful_appends = []
                worker_errors = []
                collected_lock = threading.Lock()

                def writer(barrier=barrier, size=size, repeat=repeat, store=store, dataset=dataset,
                           collected_lock=collected_lock, successful_appends=successful_appends,
                           observations=observations, worker_errors=worker_errors):
                    try:
                        barrier.wait()
                        for item in range(CONCURRENT_APPENDS):
                            event = journal.timed(
                                "concurrent_append", size, repeat,
                                partial(store.append, {"tool": "benchmark_concurrent", "result": {"sequence": item}}),
                                dataset=str(dataset), item=item)
                            with collected_lock:
                                if "error" not in event:
                                    successful_appends.append(event["result"])
                                observations.append(event)
                    except BaseException as error:
                        with collected_lock:
                            worker_errors.append({"worker": "writer", "type": type(error).__name__,
                                                  "message": str(error), "traceback": traceback.format_exc()})

                def reader(reader_id, barrier=barrier, size=size, repeat=repeat, harness=harness,
                           target_id=target_id, dataset=dataset, collected_lock=collected_lock,
                           observations=observations, worker_errors=worker_errors):
                    try:
                        barrier.wait()
                        for item in range(CONCURRENT_READS_PER_READER):
                            event = journal.timed("concurrent_verify_and_head", size, repeat,
                                                  partial(harness.verify_receipt, receipt_id=target_id),
                                                  dataset=str(dataset), reader=reader_id, item=item)
                            with collected_lock:
                                observations.append(event)
                    except BaseException as error:
                        with collected_lock:
                            worker_errors.append({"worker": f"reader-{reader_id}", "type": type(error).__name__,
                                                  "message": str(error), "traceback": traceback.format_exc()})

                threads = [threading.Thread(target=writer)] + [
                    threading.Thread(target=reader, args=(i,)) for i in range(CONCURRENT_READERS)]
                for thread in threads:
                    thread.start()
                concurrent_start = time.perf_counter_ns()
                barrier.wait()
                for thread in threads:
                    thread.join()
                concurrent_end = time.perf_counter_ns()
                journal.add({"kind": "concurrent_wall", "size": size, "repeat": repeat,
                             "elapsed_ns": concurrent_end - concurrent_start, "worker_errors": worker_errors,
                             "successful_appends": len(successful_appends), "dataset": str(dataset)})
                invalid_count += len(worker_errors)
                expected_heads = {size: initial_head}
                for item, receipt in enumerate(successful_appends, size + 1):
                    expected_heads[item] = {"count": item, "head_sha256": receipt["sha256"], "head_id": receipt["id"]}
                reader_counts = {}
                reads = [e for e in observations if e["operation"] == "concurrent_verify_and_head"]
                writes = [e for e in observations if e["operation"] == "concurrent_append"]
                overlap_count = 0
                for event in sorted(observations, key=lambda e: (e.get("reader", -1), e.get("item", -1))):
                    if event["operation"] == "concurrent_verify_and_head":
                        result = event.get("result", {})
                        problems = check_snapshot(result, count_range=(size, size + CONCURRENT_APPENDS))
                        head = result.get("head", {})
                        count = head.get("count")
                        if type(count) is not int or head != expected_heads.get(count):
                            problems.append("observed head is not a complete prefix of the final append chain")
                        elif count < reader_counts.get(event["reader"], size):
                            problems.append("reader observed a decreasing head count")
                        else:
                            reader_counts[event["reader"]] = count
                        overlap_count += any(e["start_ns"] < event["end_ns"] and event["start_ns"] < e["end_ns"]
                                             for e in writes)
                    else:
                        receipt = event.get("result", {})
                        problems = [] if (receipt.get("format") == receipts.FORMAT
                                          and receipt.get("sha256") == receipts.receipt_hash(receipt)) else [
                                              "concurrent append returned an invalid receipt"]
                    validate(event, problems)
                journal.add({"kind": "concurrent_observations", "size": size, "repeat": repeat,
                             "read_calls": len(reads), "append_calls": len(writes),
                             "reads_overlapping_append_calls": overlap_count})
                chain_check(store, size, dataset, "after_concurrent", size + len(successful_appends))
        report["completed"] = True
    except BaseException as error:
        report["completed"] = False
        report["fatal_error"] = {"type": type(error).__name__, "message": str(error),
                                 "traceback": traceback.format_exc()}
        journal.add({"kind": "fatal_error", **report["fatal_error"]})
    finally:
        report["finished_at"] = utc_now()
        report["source_after"] = source_pins(source)
        report["source_unchanged"] = report["source_before"] == report["source_after"]
        report["invalid_observations"] = invalid_count
        report["events"] = journal.events
        samples = defaultdict(list)
        for event in journal.events:
            if event["kind"] == "timing":
                samples[(event["size"], event["operation"])].append(event)
        report["timing_summary"] = [
            {"size": size, "operation": operation, "calls": len(events),
             "errors": sum("error" in event for event in events),
             "min_ns": min(event["elapsed_ns"] for event in events),
             "median_ns": statistics.median(event["elapsed_ns"] for event in events),
             "max_ns": max(event["elapsed_ns"] for event in events)}
            for (size, operation), events in sorted(samples.items())]
        journal.handle.close()
        report["journal_sha256"] = digest(data_root / "events.jsonl")
        with output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        print(f"Receipt: {output}; completed={report['completed']}; invalid={invalid_count}", flush=True)
    return 0 if report["completed"] and report["source_unchanged"] and not invalid_count else 1


if __name__ == "__main__":
    raise SystemExit(main())
