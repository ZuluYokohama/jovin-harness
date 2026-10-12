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
    """Serialize writers across threads (in-process lock) and processes (OS file lock)."""
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


class ReceiptStore:
    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.index = self.directory / "index.jsonl"
        self.lock = self.directory / ".lock"

    def path_for(self, receipt_id: str) -> Path:
        if not RECEIPT_ID.match(receipt_id):
            raise ReceiptError(f"invalid receipt id {receipt_id!r}")
        return self.directory / f"{receipt_id}.json"

    def _entries(self) -> list[dict]:
        if not self.index.is_file():
            return []
        entries = []
        for number, line in enumerate(self.index.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ReceiptError(f"index.jsonl line {number} is not valid JSON") from error
        return entries

    def head(self) -> dict:
        entries = self._entries()
        return {"count": len(entries), "head_sha256": entries[-1]["sha256"] if entries else None,
                "head_id": entries[-1]["id"] if entries else None}

    def append(self, body: dict) -> dict:
        """Seal ``body`` into a receipt chained to the current head, write it, and return it."""
        reserved = {"format", "id", "created_at", "prev_sha256", "sha256", "notice"} & set(body)
        if reserved:
            raise ReceiptError(f"body may not set {sorted(reserved)}")
        with _exclusive(self.lock):
            entries = self._recover_tail(self._entries())
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
            # Write under a name the store ignores, then rename: a crash never leaves a partial
            # receipt. A crash between the rename and the index line leaves a complete receipt that
            # chains onto the head; the next append indexes it (see _recover_tail).
            partial = path.with_name(path.name + ".partial")
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(receipt))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial, path)
            self._append_index(receipt)
            return receipt

    def _append_index(self, receipt: dict) -> None:
        entry = {"id": receipt["id"], "sha256": receipt["sha256"], "prev_sha256": receipt["prev_sha256"]}
        with self.index.open("ab") as handle:
            handle.write(canonical_json(entry) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def _recover_tail(self, entries: list[dict]) -> list[dict]:
        """Index a receipt whose index line was lost to a crash, if it chains exactly onto the head.

        Only a complete, self-consistent receipt linked to the current head qualifies. Anything else
        stays an unindexed stray that verify_chain reports.
        """
        if not self.directory.is_dir():
            return entries
        known = {entry.get("id") for entry in entries}
        head = entries[-1]["sha256"] if entries else None
        for path in sorted(self.directory.glob("*.json")):
            if path.stem in known or not RECEIPT_ID.match(path.stem):
                continue
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if (isinstance(receipt, dict) and receipt.get("id") == path.stem and receipt.get("prev_sha256") == head
                    and receipt.get("sha256") == receipt_hash(receipt)):
                self._append_index(receipt)
                return [*entries, {"id": receipt["id"], "sha256": receipt["sha256"], "prev_sha256": head}]
        return entries

    def get(self, receipt_id: str) -> dict:
        path = self.path_for(receipt_id)
        if not path.is_file():
            raise ReceiptError(f"no receipt {receipt_id}")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ReceiptError(f"receipt {receipt_id} is not valid JSON") from error

    def verify(self, receipt: dict) -> dict:
        """Check one receipt's own hash and, if it is in this store, its place in the chain."""
        problems = []
        if receipt.get("format") != FORMAT:
            problems.append("unknown format")
        if not _SHA256.match(str(receipt.get("sha256", ""))):
            problems.append("missing or malformed sha256")
        elif receipt_hash(receipt) != receipt["sha256"]:
            problems.append("sha256 does not match the receipt contents")
        chain = "not_in_store"
        receipt_id = receipt.get("id")
        if isinstance(receipt_id, str) and RECEIPT_ID.match(receipt_id):
            entries = self._entries()
            position = next((i for i, e in enumerate(entries) if e["id"] == receipt_id), None)
            if position is not None:
                entry = entries[position]
                expected_prev = entries[position - 1]["sha256"] if position else None
                chain = "linked"
                if entry["sha256"] != receipt.get("sha256"):
                    problems.append("index records a different sha256 for this id")
                    chain = "broken"
                if receipt.get("prev_sha256") != expected_prev:
                    problems.append("prev_sha256 does not match the preceding receipt")
                    chain = "broken"
        else:
            problems.append("missing or malformed id")
        return {"valid": not problems, "chain": chain, "problems": problems}

    def verify_chain(self) -> dict:
        problems, previous = [], None
        entries = self._entries()
        for entry in entries:
            label = entry.get("id", "?")
            if entry.get("prev_sha256") != previous:
                problems.append(f"{label}: chain link does not match the previous entry")
            try:
                receipt = self.get(entry["id"])
            except (ReceiptError, KeyError, json.JSONDecodeError) as error:
                problems.append(f"{label}: {error}")
            else:
                recorded = entry.get("sha256")
                if receipt_hash(receipt) != recorded or receipt.get("sha256") != recorded:
                    problems.append(f"{label}: receipt file does not match its index entry")
            previous = entry.get("sha256")
        on_disk = {p.stem for p in self.directory.glob("*.json")} if self.directory.is_dir() else set()
        for stray in sorted(on_disk - {e.get("id") for e in entries}):
            problems.append(f"{stray}: receipt file is not in the index")
        return {"valid": not problems, "count": len(entries), "head_sha256": previous, "problems": problems}
