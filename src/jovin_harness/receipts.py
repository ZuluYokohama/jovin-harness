"""Hash-chained, append-only receipts.

Each receipt is canonical JSON whose ``sha256`` covers every other field, including
``prev_sha256``, the hash of the receipt written before it. ``index.jsonl`` lists receipts in
order, so deleting, editing or reordering one breaks the chain and ``verify_chain`` reports it.

A content hash is not a signature. Anyone who can write the data directory can rebuild a
consistent chain, so export the chain head (``jovin-harness receipts head``) somewhere you trust
if you need to detect that.

Optional signing (``signing_key`` / ``verify_key`` / ``head_anchor`` in the config, see
``signing.py``): every receipt gets an Ed25519 ``<id>.sig`` written before the receipt is
published, and every append rewrites a signed ``head.checkpoint`` (count, head hash, epoch, wall
time, link to the previous checkpoint). With a verify key, ``verify_chain`` rejects unsigned or
badly signed receipts, a checkpoint that does not match the index (truncation), and, when a
``head_anchor`` copy is configured, a checkpoint older than the anchored one (rollback). The
receipt format and its hash are unchanged, so unsigned stores verify exactly as before.
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

from .signing import Verifier

FORMAT = "jovin-harness.receipt.v1"
NOTICE = ("A content hash is not a signature and a passing check is not a proof of correctness; "
          "the receipt records what ran, under which limits, and what the sandbox reported.")
RECEIPT_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE_FORMAT = "jovin-harness.receipt-signature.v1"
CHECKPOINT_FORMAT = "jovin-harness.head-checkpoint.v1"


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


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


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
    def __init__(self, directory: Path, *, signer=None, verifier=None, head_anchor: Path | None = None):
        self.directory = Path(directory)
        self.index = self.directory / "index.jsonl"
        self.lock = self.directory / ".lock"
        self.checkpoint_path = self.directory / "head.checkpoint"
        self.signer = signer
        if verifier is None and signer is not None:
            verifier = Verifier(signer.public_key)
        self.verifier = verifier
        self.head_anchor = Path(head_anchor) if head_anchor else None

    def sig_path(self, receipt_id: str) -> Path:
        if not _matches(RECEIPT_ID, receipt_id):
            raise ReceiptError(f"invalid receipt id {receipt_id!r}")
        return self.directory / f"{receipt_id}.sig"

    # ---------------------------------------------------------------- signatures and checkpoint
    @staticmethod
    def _signature_message(receipt_id: str, sha256: str, key: str) -> bytes:
        return canonical_json({"format": SIGNATURE_FORMAT, "receipt_id": receipt_id, "sha256": sha256,
                               "key_id": key})

    def _write_signature(self, receipt: dict) -> None:
        message = self._signature_message(receipt["id"], receipt["sha256"], self.signer.key_id)
        record = {"format": SIGNATURE_FORMAT, "receipt_id": receipt["id"], "sha256": receipt["sha256"],
                  "key_id": self.signer.key_id, "alg": "ed25519", "sig": self.signer.sign(message)}
        path = self.sig_path(receipt["id"])
        partial = path.with_name(path.name + ".partial")
        self._write_new(partial, canonical_json(record))
        os.replace(partial, path)

    def _signature_problems(self, receipt_id: str, sha256: str) -> list[str]:
        try:
            raw = self.sig_path(receipt_id).read_bytes()
        except FileNotFoundError:
            return [f"{receipt_id}: receipt is not signed"]
        try:
            record = _decode_json(raw, f"signature {receipt_id}")
        except ReceiptError as error:
            return [f"{receipt_id}: {error}"]
        if not isinstance(record, dict) or record.get("format") != SIGNATURE_FORMAT:
            return [f"{receipt_id}: malformed signature record"]
        problems = []
        if record.get("receipt_id") != receipt_id or record.get("sha256") != sha256:
            problems.append(f"{receipt_id}: signature covers a different receipt")
        if record.get("key_id") != self.verifier.key_id:
            problems.append(f"{receipt_id}: signed by an unknown key")
        elif not self.verifier.verify(self._signature_message(receipt_id, sha256, record["key_id"]),
                                      record.get("sig")):
            problems.append(f"{receipt_id}: signature does not verify")
        return problems

    @staticmethod
    def _checkpoint_body(record: dict) -> dict:
        return {k: v for k, v in record.items() if k not in ("sha256", "sig")}

    def _read_checkpoint(self, raw: bytes | None = None, label: str = "head.checkpoint"):
        """Return (checkpoint, problems); checkpoint is None when absent or unusable."""
        if raw is None:
            try:
                raw = self.checkpoint_path.read_bytes()
            except FileNotFoundError:
                return None, [f"{label} is missing"]
        try:
            record = _decode_json(raw, label)
        except ReceiptError as error:
            return None, [str(error)]
        if not isinstance(record, dict) or record.get("format") != CHECKPOINT_FORMAT:
            return None, [f"{label} is malformed"]
        body = self._checkpoint_body(record)
        problems = []
        if not isinstance(record.get("epoch"), int) or isinstance(record.get("epoch"), bool) or record["epoch"] < 1:
            problems.append(f"{label} has a malformed epoch")
        if not isinstance(record.get("count"), int) or isinstance(record.get("count"), bool):
            problems.append(f"{label} has a malformed count")
        if record.get("sha256") != sha256_hex(canonical_json(body)):
            problems.append(f"{label} sha256 does not match its contents")
        if self.verifier is None:
            problems.append(f"{label} cannot be checked without a verify key")
        elif record.get("key_id") != self.verifier.key_id:
            problems.append(f"{label} is signed by an unknown key")
        elif not self.verifier.verify(canonical_json(body), record.get("sig")):
            problems.append(f"{label} signature does not verify")
        return (None if problems else record), problems

    def _write_checkpoint(self, entries: list[dict]) -> dict:
        previous = None
        if self.checkpoint_path.exists():
            previous, problems = self._read_checkpoint()
            if problems:
                raise ReceiptError("refusing to extend an invalid head checkpoint: " + "; ".join(problems))
        body = {"format": CHECKPOINT_FORMAT, "count": len(entries),
                "head_id": entries[-1]["id"] if entries else None,
                "head_sha256": entries[-1]["sha256"] if entries else None,
                "epoch": (previous["epoch"] + 1) if previous else 1,
                "wall_time": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "prev_checkpoint_sha256": previous["sha256"] if previous else None,
                "key_id": self.signer.key_id}
        record = {**body, "sha256": sha256_hex(canonical_json(body)), "sig": self.signer.sign(canonical_json(body))}
        partial = self.checkpoint_path.with_name(f"head-{secrets.token_hex(8)}.partial")
        try:
            self._write_new(partial, canonical_json(record))
            os.replace(partial, self.checkpoint_path)
        finally:
            partial.unlink(missing_ok=True)
        _fsync_dir(self.directory)
        if self.head_anchor is not None:
            self.head_anchor.parent.mkdir(parents=True, exist_ok=True)
            with self.head_anchor.open("ab") as handle:
                handle.write(canonical_json(record) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
        return record

    def checkpoint(self) -> dict | None:
        """The signed head checkpoint as stored (None when the store is unsigned)."""
        with self._snapshot():
            if not self.checkpoint_path.exists():
                return None
            return _decode_json(self.checkpoint_path.read_bytes(), "head.checkpoint")

    def _anchor_problems(self, checkpoint: dict | None) -> tuple[list[str], dict | None]:
        if self.head_anchor is None:
            return [], None
        try:
            lines = [line for line in self.head_anchor.read_bytes().splitlines() if line.strip()]
        except FileNotFoundError:
            return ["head anchor file is missing"], None
        if not lines:
            return ["head anchor file is empty"], None
        problems, previous, latest = [], None, None
        for number, line in enumerate(lines, 1):
            record, bad = self._read_checkpoint(line, f"head anchor line {number}")
            if bad:
                problems += bad
                continue
            if previous is not None and (record["epoch"] != previous["epoch"] + 1
                                         or record["prev_checkpoint_sha256"] != previous["sha256"]):
                problems.append(f"head anchor line {number} does not extend the previous anchored checkpoint")
            previous = latest = record
        if latest is not None and checkpoint is not None:
            if latest["epoch"] > checkpoint["epoch"]:
                problems.append(f"rollback: head anchor holds epoch {latest['epoch']} (count {latest['count']}) "
                                f"but the store's checkpoint is epoch {checkpoint['epoch']} "
                                f"(count {checkpoint['count']})")
            elif latest["sha256"] != checkpoint["sha256"]:
                problems.append("store checkpoint differs from the latest anchored checkpoint")
        return problems, latest

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
            if self.signer is not None:
                self._write_signature(receipt)  # signed before it is published, so a recovered orphan is signed
            partial = path.with_name(path.name + ".partial")
            self._write_new(partial, canonical_json(receipt))
            os.replace(partial, path)
            _fsync_dir(path.parent)
            self._append_index(receipt)
            if self.signer is not None:
                self._write_checkpoint([*entries, _index_entry(receipt)])
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
            _fsync_dir(recovery)
            _fsync_dir(recovery.parent)
            partial = self.index.with_name(f"index-{token}.partial")
            try:
                self._write_new(partial, prefix + canonical_json(_index_entry(receipt)) + b"\n")
                os.replace(partial, self.index)
                _fsync_dir(self.index.parent)
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
            if self.verifier is not None and _matches(_SHA256, receipt.get("sha256")):
                problems += self._signature_problems(receipt_id, receipt["sha256"])
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
            report = {"count": head["count"], "head_sha256": head["head_sha256"]}
            if self.verifier is not None:
                report.update(self._signed_chain_problems(entries, problems))
            return {"valid": not problems, **report, "problems": problems}

    def _signed_chain_problems(self, entries: list[dict], problems: list[str]) -> dict:
        """Signatures, checkpoint-vs-index (truncation) and anchor (rollback) checks; appends to problems."""
        for entry in entries:
            problems += self._signature_problems(entry["id"], entry["sha256"])
        known = {entry["id"] for entry in entries}
        for path in sorted(self.directory.glob("*.sig")):
            if path.stem not in known:
                problems.append(f"{path.stem}: signature file has no indexed receipt (truncated?)")
        checkpoint, bad = self._read_checkpoint()
        problems += bad
        if checkpoint is not None:
            head = self._head(entries)
            if checkpoint["count"] != head["count"] or checkpoint["head_sha256"] != head["head_sha256"]:
                problems.append(f"signed checkpoint records {checkpoint['count']} receipts (head "
                                f"{checkpoint['head_id']}) but the index has {head['count']}: truncated or rewritten")
            elif entries:
                try:
                    created = self._get(entries[-1]["id"])["created_at"]
                except ReceiptError:
                    created = None  # already reported by the chain check
                if created is not None and checkpoint["wall_time"] < created:
                    problems.append("signed checkpoint is older than the head receipt")
        anchor_problems, anchored = self._anchor_problems(checkpoint)
        problems += anchor_problems
        return {"signed": True, "key_id": self.verifier.key_id,
                "checkpoint_epoch": checkpoint["epoch"] if checkpoint else None,
                "anchored_epoch": anchored["epoch"] if anchored else None,
                "anchor_configured": self.head_anchor is not None}
