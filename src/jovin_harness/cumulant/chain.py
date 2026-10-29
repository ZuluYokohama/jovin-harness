"""Preregistration freeze and a hash-chained gate-run journal.

Uses the package's canonical JSON (sorted keys, no NaN) and SHA-256 so hashes match
``jovin_harness.receipts``. Every journal record carries ``prev_sha256`` and a ``sha256`` over all
its other fields; editing, deleting or reordering a record breaks ``verify_chain``. A content hash
is not a signature.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..receipts import canonical_json, sha256_hex

GENESIS = "0" * 64
FORMAT = "jovin-harness.cumulant-gates.journal.v1"


def prereg_sha256(prereg: dict) -> str:
    return sha256_hex(canonical_json(prereg))


def freeze(prereg: dict, path: Path, frozen_by: str, approval_ref: str) -> dict:
    """Write an OWNER_FREEZE-style document. Refuses to overwrite a different frozen prereg."""
    doc = {"format": "jovin-harness.cumulant-gates.prereg.v1", "prereg": prereg,
           "prereg_sha256": prereg_sha256(prereg), "frozen_by": frozen_by, "approval_ref": approval_ref,
           "frozen_utc": datetime.now(UTC).isoformat()}
    path = Path(path)
    if path.exists():
        old = json.loads(path.read_text())
        if old.get("prereg_sha256") != doc["prereg_sha256"]:
            raise PermissionError("a different prereg is already frozen at this path")
        return old
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True))
    return doc


def check_frozen(doc: dict) -> None:
    if prereg_sha256(doc["prereg"]) != doc.get("prereg_sha256"):
        raise PermissionError("frozen prereg hash mismatch")


def assert_real_run_authorized(doc: dict, data_sha256: str) -> None:
    """Fail closed unless a frozen prereg binds this exact data hash and cites an owner go."""
    check_frozen(doc)
    p = doc["prereg"]
    if p.get("data_source") == "synthetic":
        raise PermissionError("prereg is synthetic-only")
    if not str(p.get("owner_go_ref", "")).strip():
        raise PermissionError("no owner go reference in the frozen prereg")
    if p.get("data_sha256") != data_sha256:
        raise PermissionError("data hash does not match the frozen prereg")
    if p.get("scored_once_marker") and Path(p["scored_once_marker"]).exists():
        raise PermissionError("already scored once; re-scoring is not allowed")


class Journal:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def records(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]

    def head(self) -> str:
        recs = self.records()
        return recs[-1]["sha256"] if recs else GENESIS

    def append(self, kind: str, payload: dict) -> dict:
        recs = self.records()
        rec = {"format": FORMAT, "index": len(recs), "kind": kind, "payload": payload,
               "utc": datetime.now(UTC).isoformat(), "prev_sha256": recs[-1]["sha256"] if recs else GENESIS}
        rec["sha256"] = sha256_hex(canonical_json(rec))
        with self.path.open("ab") as fh:
            fh.write(canonical_json(rec) + b"\n")
        return rec


def verify_chain(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    for i, rec in enumerate(Journal(path).records()):
        body = {k: v for k, v in rec.items() if k != "sha256"}
        if rec.get("index") != i:
            return False, f"record {i}: index mismatch"
        if rec.get("prev_sha256") != prev:
            return False, f"record {i}: broken link"
        if sha256_hex(canonical_json(body)) != rec.get("sha256"):
            return False, f"record {i}: content hash mismatch"
        prev = rec["sha256"]
    return True, prev
