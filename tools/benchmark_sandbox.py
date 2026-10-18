"""Measure sequential real-sandbox calls; every call still gets a fresh container.

Run against an already built and pinned image using the normal JOVIN_HARNESS_* settings.
Receipt persistence is measured externally: an append cannot seal its own completed duration.
Results are observations of this host/configuration, not a container-engine speedup claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

from jovin_harness import sandbox
from jovin_harness.tools import Harness

CODE = "def add(a, b):\n    return a + b\n"
TESTS = "def test_add():\n    assert add(2, 3) == 5\n    assert add(-2, 2) == 0\n"


def _write_evidence(path: Path, evidence: dict) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    partial = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(evidence, output, indent=2, allow_nan=False)
            output.flush()
            os.fsync(output.fileno())
        os.replace(partial, path)
    finally:
        partial.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 30:
        parser.error("repeats must be between 1 and 30")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    harness = Harness.from_environment()
    source = Path(sandbox.__file__).parent
    evidence = {
        "schema": "jovin-sandbox-benchmark.v1", "python": sys.version,
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.glob("*.py"))},
        "runner_sha256": sandbox.runner_sha256(), "samples": [],
        "note": "Sequential calls on one harness instance; fresh containers, no pooling. Includes first-call costs.",
    }
    append = harness.store.append
    append_times = []

    def timed_append(body):
        start = time.perf_counter()
        try:
            return append(body)
        finally:
            append_times.append(time.perf_counter() - start)

    harness.store.append = timed_append
    failed = False
    # Reserve a new destination without overwriting an earlier benchmark run.
    with args.output.open("x", encoding="utf-8"):
        pass
    for number in range(args.repeats):
        start, before = time.perf_counter(), len(append_times)
        sample = {"sample": number}
        try:
            result = harness.verify_python(CODE, TESTS)
            sample["total_s"] = time.perf_counter() - start
            receipt = harness.get_receipt(result["receipt_id"])
            sample.update({"result": result, "sandbox": receipt["sandbox"],
                           "receipt_valid": harness.verify_receipt(receipt_id=receipt["id"])["valid"]})
            failed |= (not result["passed"] or not sample["receipt_valid"]
                       or receipt["sandbox"]["cleanup"] != "removed")
        except Exception as error:
            sample.update({"total_s": time.perf_counter() - start,
                           "error": f"{type(error).__name__}: {error}"})
            failed = True
        sample["receipt_persistence_s"] = append_times[before:]
        evidence["samples"].append(sample)
        _write_evidence(args.output, evidence)
    evidence["median_total_s"] = statistics.median(s["total_s"] for s in evidence["samples"])
    evidence["valid"] = not failed
    try:
        evidence["chain"] = harness.store.verify_chain()
    except Exception as error:
        evidence["chain"] = {"valid": False, "error": f"{type(error).__name__}: {error}"}
    evidence["valid"] &= evidence["chain"]["valid"]
    _write_evidence(args.output, evidence)
    print(json.dumps({"valid": evidence["valid"], "median_total_s": evidence["median_total_s"]}))
    return 0 if evidence["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
