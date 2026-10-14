"""Hash-chained, append-only receipts.

Each receipt is canonical JSON whose ``sha256`` covers every other field, including
``prev_sha256``, the hash of the receipt written before it. ``index.jsonl`` lists receipts in
order, so deleting, editing or reordering one breaks the chain and ``verify_chain`` reports it.

A content hash is not a signature. Anyone who can write the data directory can rebuild a
consistent chain, so export the chain head (``jovin-harness receipts head``) somewhere you trust
if you need to detect that.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

FORMAT = "jovin-harness.receipt.v1"
NOTICE = ("A content hash is not a signature and a passing check is not a proof of correctness; "
          "the receipt records what ran, under which limits, and what the sandbox reported.")
RECEIPT_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReceiptError(ValueError):
    pass


def canonical_json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def receipt_hash(receipt: dict) -> str:
    return sha256_hex(canonical_json({k: v for k, v in receipt.items() if k != "sha256"}))


def new_receipt_id(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return f"{now:%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}"


_process_lock = threading.Lock()


@contextlib.contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Serialize readers and writers across threads (in-process lock) and processes (OS file lock)."""
    with _process_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a+b") as handle:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                for attempt in range(6):  # LK_LOCK itself retries for ~10 s per attempt
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                        break
                    except OSError:
                        if attempt == 5:
                            raise ReceiptError(f"timed out waiting for {path}") from None
                try:
                    yield
                finally:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _decode_json(raw: bytes, label: str):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError("non-finite JSON number: " + value)

    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ReceiptError(f"{label} is not valid JSON: {error}") from error


def _matches(pattern, value) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _receipt_problems(receipt) -> list[str]:
    if not isinstance(receipt, dict):
        return ["receipt must be a JSON object"]
    problems = []
    if receipt.get("format") != FORMAT:
        problems.append("unknown format")
    if not _matches(RECEIPT_ID, receipt.get("id")):
        problems.append("missing or malformed id")
    if not _matches(_SHA256, receipt.get("sha256")):
        problems.append("missing or malformed sha256")
    if "prev_sha256" not in receipt or (receipt["prev_sha256"] is not None
                                       and not _matches(_SHA256, receipt["prev_sha256"])):
        problems.append("missing or malformed prev_sha256")
    for name in ("created_at", "notice"):
        if not isinstance(receipt.get(name), str):
            problems.append(f"missing or malformed {name}")
    try:
        canonical_json(receipt)
    except (TypeError, ValueError, RecursionError) as error:
        problems.append(f"receipt is not canonical JSON: {error}")
    return problems


def _index_entry(receipt: dict) -> dict:
    return {name: receipt[name] for name in ("id", "sha256", "prev_sha256")}


class ReceiptStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.index = self.directory / "index.jsonl"
        self.lock = self.directory / ".lock"

    def path_for(self, receipt_id: str) -> Path:
        if not _matches(RECEIPT_ID, receipt_id):
            raise ReceiptError(f"invalid receipt id {receipt_id!r}")
        return self.directory / f"{receipt_id}.json"

    def _read_index(self, *, allow_tail=False) -> tuple[list[dict], bytes, bytes]:
        """Read once while locked; only an unterminated final line can be a torn append."""
        try:
            raw = self.index.read_bytes()
        except FileNotFoundError:
            raw = b""
        end = raw.rfind(b"\n") + 1
        prefix, tail = raw[:end], raw[end:]
        if tail and not allow_tail:
            raise ReceiptError("index.jsonl has an interrupted final line")
        entries, known = [], set()
        for number, line in enumerate(prefix.splitlines(), 1):
            if not line.strip():
                continue
            entry = _decode_json(line, f"index.jsonl line {number}")
            if (not isinstance(entry, dict) or not _matches(RECEIPT_ID, entry.get("id"))
                    or not _matches(_SHA256, entry.get("sha256"))
                    or "prev_sha256" not in entry
                    or (entry["prev_sha256"] is not None and not _matches(_SHA256, entry["prev_sha256"]))):
                raise ReceiptError(f"index.jsonl line {number} has a malformed entry")
            if entry["id"] in known:
                raise ReceiptError(f"index.jsonl line {number} repeats receipt id {entry['id']}")
            known.add(entry["id"])
            entries.append(entry)
        return entries, prefix, tail

    def _entries(self) -> list[dict]:
        return self._read_index()[0]

    @contextlib.contextmanager
    def _snapshot(self) -> Iterator[list[dict]]:
        """Keep the index, receipt reads and directory listing in one writer-free snapshot."""
        with _exclusive(self.lock):
            yield self._entries()

    @staticmethod
    def _head(entries: list[dict]) -> dict:
        return {"count": len(entries), "head_sha256": entries[-1]["sha256"] if entries else None,
                "head_id": entries[-1]["id"] if entries else None}

    def head(self) -> dict:
        with self._snapshot() as entries:
            return self._head(entries)

    def append(self, body: dict) -> dict:
        """Seal body using the unchanged v1 canonical representation."""
        if not isinstance(body, dict):
            raise ReceiptError("receipt body must be a JSON object")
        reserved = {"format", "id", "created_at", "prev_sha256", "sha256", "notice"} & set(body)
        if reserved:
            raise ReceiptError(f"body may not set {sorted(reserved)}")
        with _exclusive(self.lock):
            entries, prefix, tail = self._read_index(allow_tail=True)
            previous = None
            for entry in entries:
                if entry["prev_sha256"] != previous:
                    raise ReceiptError("cannot append to an invalid index chain: " + entry["id"])
                previous = entry["sha256"]
            entries = self._recover_tail(entries, prefix, tail)
            now = datetime.now(UTC)
            receipt = {
                "format": FORMAT,
                "id": new_receipt_id(now),
                "created_at": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                **body,
                "notice": NOTICE,
                "prev_sha256": entries[-1]["sha256"] if entries else None,
            }
            receipt["sha256"] = receipt_hash(receipt)
            path = self.path_for(receipt["id"])
            if path.exists():
                raise ReceiptError(f"receipt {receipt['id']} already exists")
            # Flush and publish the complete receipt before its index append starts. Recovery never
            # changes those bytes or rehashes an existing receipt.
            partial = path.with_name(path.name + ".partial")
            self._write_new(partial, canonical_json(receipt))
            os.replace(partial, path)
            self._append_index(receipt)
            return receipt

    @staticmethod
    def _write_new(path: Path, content: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

    def _append_index(self, receipt: dict) -> None:
        with self.index.open("ab") as handle:
            handle.write(canonical_json(_index_entry(receipt)) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _recover_tail(self, entries: list[dict], prefix: bytes, tail: bytes) -> list[dict]:
        """Recover only a unique hash-valid orphan matching the preceding chain and torn bytes."""
        known = {entry["id"] for entry in entries}
        head = entries[-1]["sha256"] if entries else None
        candidates = []
        for path in self.directory.glob("*.json"):
            if path.stem in known or not _matches(RECEIPT_ID, path.stem):
                continue
            try:
                receipt = self._get(path.stem)
            except ReceiptError:
                continue
            if (receipt["id"] != path.stem or receipt["prev_sha256"] != head
                    or receipt["sha256"] != receipt_hash(receipt)):
                continue
            if tail and not (canonical_json(_index_entry(receipt)) + b"\n").startswith(tail):
                continue
            candidates.append(receipt)
        if len(candidates) > 1:
            raise ReceiptError("ambiguous receipt index recovery: multiple matching orphans")
        if not candidates:
            if tail:
                raise ReceiptError("interrupted index tail has no matching valid orphan; original bytes retained")
            return entries
        problems = self._chain_problems(entries)
        if problems:
            raise ReceiptError("cannot recover onto an invalid preceding chain: " + "; ".join(problems))
        receipt = candidates[0]
        if tail:
            # Save the exact prior index before replacing it. Recovery evidence is outside
            # the receipt namespace, so it cannot be mistaken for another receipt.
            recovery = self.directory / "recovery"
            recovery.mkdir(exist_ok=True)
            token = secrets.token_hex(12)
            self._write_new(recovery / f"index-{token}.jsonl", prefix + tail)
            partial = self.index.with_name(f"index-{token}.partial")
            try:
                self._write_new(partial, prefix + canonical_json(_index_entry(receipt)) + b"\n")
                os.replace(partial, self.index)
            finally:
                partial.unlink(missing_ok=True)
        else:
            self._append_index(receipt)
        return [*entries, _index_entry(receipt)]

    def _get(self, receipt_id: str) -> dict:
        path = self.path_for(receipt_id)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raise ReceiptError(f"no receipt {receipt_id}") from None
        receipt = _decode_json(raw, f"receipt {receipt_id}")
        problems = _receipt_problems(receipt)
        if problems:
            raise ReceiptError(f"receipt {receipt_id}: " + "; ".join(problems))
        if receipt["id"] != receipt_id:
            raise ReceiptError(f"receipt {receipt_id}: contents have a different id")
        return receipt

    def get(self, receipt_id: str) -> dict:
        with _exclusive(self.lock):
            return self._get(receipt_id)

    def _verify(self, receipt: dict, entries: list[dict]) -> dict:
        problems = _receipt_problems(receipt)
        chain = "not_in_store"
        if not isinstance(receipt, dict):
            return {"valid": False, "chain": chain, "problems": problems}
        if not problems and receipt_hash(receipt) != receipt["sha256"]:
            problems.append("sha256 does not match the receipt contents")
        receipt_id = receipt.get("id")
        if _matches(RECEIPT_ID, receipt_id):
            position = next((i for i, entry in enumerate(entries) if entry["id"] == receipt_id), None)
            if position is not None:
                entry = entries[position]
                expected_prev = entries[position - 1]["sha256"] if position else None
                chain = "linked"
                if entry["sha256"] != receipt.get("sha256"):
                    problems.append("index records a different sha256 for this id")
                    chain = "broken"
                if entry["prev_sha256"] != expected_prev:
                    problems.append("index chain link does not match the preceding receipt")
                    chain = "broken"
                if receipt.get("prev_sha256") != expected_prev:
                    problems.append("prev_sha256 does not match the preceding receipt")
                    chain = "broken"
        return {"valid": not problems, "chain": chain, "problems": problems}

    def verify(self, receipt: dict) -> dict:
        """Check this receipt's own hash and immediate link, not the entire chain."""
        with self._snapshot() as entries:
            return self._verify(receipt, entries)

    def verify_snapshot(self, *, receipt_id: str | None = None, receipt: dict | None = None) -> dict:
        """Return verification, stored-copy comparison and head from one locked index read."""
        if (receipt_id is None) == (receipt is None):
            raise ReceiptError("pass exactly one of receipt_id or receipt")
        with self._snapshot() as entries:
            by_id = receipt is None
            if by_id:
                receipt = self._get(receipt_id)
            verdict = self._verify(receipt, entries)
            if verdict["chain"] == "linked" and not by_id and self._get(receipt["id"]) != receipt:
                verdict["valid"] = False
                verdict["problems"].append("receipt differs from the stored copy")
            return {**verdict, "head": self._head(entries)}

    def _chain_problems(self, entries: list[dict]) -> list[str]:
        problems, previous = [], None
        for entry in entries:
            label = entry["id"]
            if entry["prev_sha256"] != previous:
                problems.append(f"{label}: chain link does not match the previous entry")
            try:
                receipt = self._get(label)
            except (ReceiptError, OSError) as error:
                problems.append(f"{label}: {error}")
            else:
                recorded = entry["sha256"]
                if receipt_hash(receipt) != recorded or receipt["sha256"] != recorded:
                    problems.append(f"{label}: receipt file does not match its index entry")
                if receipt["id"] != label or receipt["prev_sha256"] != previous:
                    problems.append(f"{label}: receipt's own chain link does not match the previous receipt")
            previous = entry["sha256"]
        return problems

    def verify_chain(self) -> dict:
        with self._snapshot() as entries:
            problems = self._chain_problems(entries)
            on_disk = {p.stem for p in self.directory.glob("*.json")}
            for stray in sorted(on_disk - {entry["id"] for entry in entries}):
                problems.append(f"{stray}: receipt file is not in the index")
            head = self._head(entries)
            return {"valid": not problems, "count": head["count"], "head_sha256": head["head_sha256"],
                    "problems": problems}
