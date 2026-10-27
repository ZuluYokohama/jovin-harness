import json
import os
import threading
from types import SimpleNamespace

import pytest

from jovin_harness import receipts
from jovin_harness.receipts import (
    FORMAT,
    ReceiptError,
    ReceiptStore,
    canonical_json,
    receipt_hash,
)


def body(n=0):
    return {"tool": "run_python", "inputs": {"code_sha256": f"{n:064x}"}, "result": {"exit_code": n}}


def test_canonical_json_is_order_independent_and_utf8():
    assert canonical_json({"b": 1, "a": "é"}) == canonical_json({"a": "é", "b": 1})
    assert canonical_json({"a": "é"}) == '{"a":"é"}'.encode()


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_append_chains_receipts(tmp_path):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    second = store.append(body(2))
    assert first["format"] == FORMAT
    assert first["prev_sha256"] is None
    assert second["prev_sha256"] == first["sha256"]
    assert receipt_hash(second) == second["sha256"]
    assert store.head() == {"count": 2, "head_sha256": second["sha256"], "head_id": second["id"]}
    assert store.verify_chain()["valid"]
    assert store.verify(store.get(first["id"])) == {"valid": True, "chain": "linked", "problems": []}


def test_body_cannot_set_reserved_fields(tmp_path):
    with pytest.raises(ReceiptError):
        ReceiptStore(tmp_path).append({"sha256": "0" * 64})


def test_edited_receipt_is_detected(tmp_path):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body(1))
    path = store.path_for(receipt["id"])
    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["result"]["exit_code"] = 0
    path.write_bytes(canonical_json(tampered))
    assert not store.verify(tampered)["valid"]
    chain = store.verify_chain()
    assert not chain["valid"]
    assert "does not match its index entry" in chain["problems"][0]


def test_rehashed_edit_still_breaks_the_chain(tmp_path):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    store.append(body(2))
    forged = dict(first, result={"exit_code": 0})
    forged["sha256"] = receipt_hash(forged)
    store.path_for(first["id"]).write_bytes(canonical_json(forged))
    verdict = store.verify(forged)
    assert verdict["chain"] == "broken"
    assert not store.verify_chain()["valid"]


def test_deleted_receipt_is_detected(tmp_path):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    store.append(body(2))
    store.path_for(first["id"]).unlink()
    assert not store.verify_chain()["valid"]


def test_removed_index_line_is_detected(tmp_path):
    store = ReceiptStore(tmp_path)
    store.append(body(1))
    store.append(body(2))
    store.append(body(3))
    lines = store.index.read_text(encoding="utf-8").splitlines()
    store.index.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    problems = store.verify_chain()["problems"]
    assert any("chain link" in p for p in problems)
    assert any("not in the index" in p for p in problems)


def test_receipt_ids_cannot_escape_the_store(tmp_path):
    store = ReceiptStore(tmp_path)
    for bad in ("../x", "..\\x", "20260101T000000Z-zzzzzzzzzzzz", ""):
        with pytest.raises(ReceiptError):
            store.path_for(bad)


def test_unknown_receipt_reports_not_in_store(tmp_path):
    store = ReceiptStore(tmp_path)
    receipt = ReceiptStore(tmp_path / "other").append(body(1))
    assert store.verify(receipt) == {"valid": True, "chain": "not_in_store", "problems": []}


def test_concurrent_appends_keep_a_single_chain(tmp_path):
    store = ReceiptStore(tmp_path)
    threads = [threading.Thread(target=store.append, args=(body(n),)) for n in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    chain = store.verify_chain()
    assert chain["valid"], chain["problems"]
    assert chain["count"] == 16


def test_crash_before_indexing_is_repaired_by_the_next_append(tmp_path, monkeypatch):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    original = ReceiptStore._append_index

    def crash(self, receipt):
        raise OSError("disk full")

    monkeypatch.setattr(ReceiptStore, "_append_index", crash)
    with pytest.raises(OSError):
        store.append(body(2))
    assert not store.verify_chain()["valid"]  # the orphaned receipt is reported until repaired
    assert not list(tmp_path.glob("*.partial"))
    monkeypatch.setattr(ReceiptStore, "_append_index", original)
    third = store.append(body(3))
    chain = store.verify_chain()
    assert chain["valid"], chain["problems"]
    assert chain["count"] == 3
    assert store.get(third["id"])["prev_sha256"] != first["sha256"]


def test_unrelated_stray_is_not_adopted(tmp_path):
    store = ReceiptStore(tmp_path)
    store.append(body(1))
    stray = dict(store.get(store.head()["head_id"]), id="20260101T000000Z-aaaaaaaaaaaa", prev_sha256="0" * 64)
    stray["sha256"] = receipt_hash(stray)
    store.path_for(stray["id"]).write_bytes(canonical_json(stray))
    store.append(body(2))
    problems = store.verify_chain()["problems"]
    assert any("not in the index" in p for p in problems)


def test_corrupt_receipt_file_is_a_receipt_error(tmp_path):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body(1))
    store.path_for(receipt["id"]).write_text("{not json", encoding="utf-8")
    with pytest.raises(ReceiptError, match="not valid JSON"):
        store.get(receipt["id"])


def test_rewritten_middle_receipt_with_patched_index_is_detected(tmp_path):
    store = ReceiptStore(tmp_path)
    first, middle, last = (store.append(body(n)) for n in (1, 2, 3))
    forged = dict(middle, result={"exit_code": 0})
    forged["sha256"] = receipt_hash(forged)
    store.path_for(middle["id"]).write_bytes(canonical_json(forged))
    lines = [json.loads(line) for line in store.index.read_text(encoding="utf-8").splitlines()]
    lines[1]["sha256"] = forged["sha256"]
    lines[2]["prev_sha256"] = forged["sha256"]
    store.index.write_text("".join(canonical_json(e).decode() + "\n" for e in lines), encoding="utf-8")
    chain = store.verify_chain()
    assert not chain["valid"]
    assert any(last["id"] in p and "own chain link" in p for p in chain["problems"])

def make_orphan(store, previous, suffix="aaaaaaaaaaaa"):
    receipt = dict(previous, id="20260101T000000Z-" + suffix, prev_sha256=previous["sha256"])
    receipt["sha256"] = receipt_hash(receipt)
    store.path_for(receipt["id"]).write_bytes(canonical_json(receipt))
    return receipt


def index_line(receipt):
    return canonical_json({key: receipt[key] for key in ("id", "sha256", "prev_sha256")}) + b"\n"


@pytest.mark.parametrize("raw", [b"null\n", b"[]\n", b"{}\n", b'{"id":[]}\n', b"\xff\n",
                                  b'{"id":"a","id":"b"}\n'])
def test_malformed_index_is_a_receipt_error(tmp_path, raw):
    store = ReceiptStore(tmp_path)
    store.index.write_bytes(raw)
    for read in (store.head, store.verify_chain):
        with pytest.raises(ReceiptError):
            read()
    before = set(tmp_path.iterdir())
    with pytest.raises(ReceiptError):
        store.append(body())
    assert store.index.read_bytes() == raw and set(tmp_path.iterdir()) == before


@pytest.mark.parametrize("raw", [b"null", b"[]", b"{}", b"\xff", b'{"x":NaN}', b'{"id":"a","id":"b"}'])
def test_malformed_receipt_has_structured_failure(tmp_path, raw):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body())
    store.path_for(receipt["id"]).write_bytes(raw)
    with pytest.raises(ReceiptError):
        store.get(receipt["id"])
    verdict = store.verify_chain()
    assert not verdict["valid"] and verdict["problems"]


@pytest.mark.parametrize("value", [None, [], {"format": "other"}, {"result": float("inf")}])
def test_external_malformed_receipt_is_invalid_not_an_attribute_error(tmp_path, value):
    verdict = ReceiptStore(tmp_path).verify(value)
    assert not verdict["valid"] and verdict["problems"]


def test_invalid_receipt_id_types_and_trailing_newline(tmp_path):
    for value in (None, [], 5, "20260101T000000Z-aaaaaaaaaaaa\n"):
        with pytest.raises(ReceiptError):
            ReceiptStore(tmp_path).path_for(value)


def test_duplicate_index_identity_is_rejected(tmp_path):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body())
    store.index.write_bytes(index_line(receipt) * 2)
    with pytest.raises(ReceiptError, match="repeats receipt id"):
        store.verify_chain()


@pytest.mark.parametrize("cut", [1, 35, -1])
def test_torn_final_index_is_repaired_without_rewriting_receipts(tmp_path, cut):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    orphan = make_orphan(store, first)
    first_bytes, orphan_bytes = (store.path_for(row["id"]).read_bytes() for row in (first, orphan))
    prefix = store.index.read_bytes()
    damaged = prefix + index_line(orphan)[:cut]
    store.index.write_bytes(damaged)
    with pytest.raises(ReceiptError, match="interrupted final line"):
        store.head()
    third = store.append(body(3))
    assert third["prev_sha256"] == orphan["sha256"]
    assert store.verify_chain()["valid"] and store.head()["count"] == 3
    backups = list((tmp_path / "recovery").glob("*.jsonl"))
    assert len(backups) == 1 and backups[0].read_bytes() == damaged
    assert store.index.read_bytes().startswith(prefix + index_line(orphan))
    assert store.path_for(first["id"]).read_bytes() == first_bytes
    assert store.path_for(orphan["id"]).read_bytes() == orphan_bytes


@pytest.mark.parametrize("tail", [b"", b'{"id":'])
def test_ambiguous_orphans_are_never_selected_by_filename_order(tmp_path, tail):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    make_orphan(store, first, "aaaaaaaaaaaa")
    make_orphan(store, first, "bbbbbbbbbbbb")
    original = store.index.read_bytes() + tail
    store.index.write_bytes(original)
    with pytest.raises(ReceiptError, match="ambiguous"):
        store.append(body(4))
    assert store.index.read_bytes() == original
    assert len(list(tmp_path.glob("*.json"))) == 3


@pytest.mark.parametrize("problem", ["mismatched-tail", "bad-orphan-hash", "invalid-prefix-chain", "interior-json"])
def test_torn_recovery_requires_exact_bytes_and_valid_preceding_chain(tmp_path, problem):
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    orphan = make_orphan(store, first)
    tail = index_line(orphan)[:-1]
    if problem == "mismatched-tail":
        tail = tail.replace(orphan["sha256"].encode(), b"f" * 64)
    elif problem == "bad-orphan-hash":
        store.path_for(orphan["id"]).write_bytes(canonical_json(dict(orphan, result={"exit_code": 99})))
    elif problem == "invalid-prefix-chain":
        store.path_for(first["id"]).write_bytes(canonical_json(dict(first, result={"exit_code": 99})))
    prefix = b"{broken\n" if problem == "interior-json" else store.index.read_bytes()
    original = prefix + tail
    store.index.write_bytes(original)
    with pytest.raises(ReceiptError):
        store.append(body(3))
    assert store.index.read_bytes() == original
    assert not (tmp_path / "recovery").exists()


def test_recovery_replacement_failure_keeps_index_and_backup(tmp_path, monkeypatch):
    import jovin_harness.receipts as receipts
    store = ReceiptStore(tmp_path)
    first = store.append(body(1))
    orphan = make_orphan(store, first)
    original = store.index.read_bytes() + index_line(orphan)[:30]
    store.index.write_bytes(original)
    replace = receipts.os.replace

    def fail_replace(source, target):
        if target == store.index:
            assert any(path.read_bytes() == original for path in (tmp_path / "recovery").glob("*.jsonl"))
            raise OSError("synthetic index replacement failure")
        return replace(source, target)

    monkeypatch.setattr(receipts.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        store.append(body(3))
    assert store.index.read_bytes() == original
    assert not list(tmp_path.glob("*.partial"))
    monkeypatch.setattr(receipts.os, "replace", replace)
    store.append(body(3))
    assert store.verify_chain()["valid"]


@pytest.mark.skipif(os.name == "nt", reason="Windows does not support directory fsync")
@pytest.mark.parametrize("recover", [None, "new", "existing"])
def test_replacements_sync_directory_before_appending_index(tmp_path, monkeypatch, recover):
    store = ReceiptStore(tmp_path)
    recovery = tmp_path / "recovery"
    if recover:
        first = store.append(body(1))
        orphan = make_orphan(store, first)
        store.index.write_bytes(store.index.read_bytes() + index_line(orphan)[:30])
        if recover == "existing":
            recovery.mkdir()
    events = []
    replace, fsync_dir, append_index = receipts.os.replace, receipts._fsync_dir, store._append_index

    def track_replace(source, target):
        replace(source, target)
        events.append("index replaced" if target == store.index else "receipt replaced")

    def track_fsync_dir(directory):
        fsync_dir(directory)
        if directory == recovery:
            assert any(path.read_bytes() == store.index.read_bytes() for path in recovery.glob("*.jsonl"))
        events.append("recovery synced" if directory == recovery else "directory synced")

    def track_append(receipt):
        events.append("index append")
        append_index(receipt)

    monkeypatch.setattr(receipts.os, "replace", track_replace)
    monkeypatch.setattr(receipts, "_fsync_dir", track_fsync_dir)
    monkeypatch.setattr(store, "_append_index", track_append)
    store.append(body(3))
    expected = ["receipt replaced", "directory synced", "index append"]
    if recover:
        expected = ["recovery synced", "directory synced", "index replaced", "directory synced", *expected]
    assert events == expected
    assert store.verify_chain()["valid"]


def test_directory_fsync_is_skipped_on_windows(tmp_path, monkeypatch):
    # No directory file operations are available in this Windows stand-in.
    monkeypatch.setattr(receipts, "os", SimpleNamespace(name="nt"))
    receipts._fsync_dir(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not support directory fsync")
def test_directory_fsync_failure_closes_descriptor(tmp_path, monkeypatch):
    descriptors = []
    open_dir = receipts.os.open

    def track_open(*args):
        fd = open_dir(*args)
        descriptors.append(fd)
        return fd

    def fail_fsync(fd):
        raise OSError("synthetic directory sync failure")

    monkeypatch.setattr(receipts.os, "open", track_open)
    monkeypatch.setattr(receipts.os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="directory sync failure"):
        receipts._fsync_dir(tmp_path)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_verify_snapshot_reads_index_once_and_checks_stored_copy(tmp_path, monkeypatch):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body())
    reads = []
    original = store._entries

    def count_reads():
        reads.append(1)
        return original()

    monkeypatch.setattr(store, "_entries", count_reads)
    verdict = store.verify_snapshot(receipt_id=receipt["id"])
    assert verdict["valid"] and verdict["head"]["head_sha256"] == receipt["sha256"]
    assert reads == [1]
    store.path_for(receipt["id"]).write_bytes(canonical_json(dict(receipt, result={"exit_code": 9})))
    assert not store.verify_snapshot(receipt=receipt)["valid"]


def test_readers_and_writers_share_consistent_snapshots(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    store = ReceiptStore(tmp_path)
    first = store.append(body())
    barrier = threading.Barrier(4)

    def write_runs():
        barrier.wait(timeout=5)
        for number in range(20):
            store.append(body(number))

    def read_snapshots():
        barrier.wait(timeout=5)
        for _ in range(25):
            assert store.verify_chain()["valid"]
            verdict = store.verify_snapshot(receipt=first)
            assert verdict["valid"] and verdict["head"]["count"] >= 1
            assert store.get(first["id"]) == first

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(write_runs), *(pool.submit(read_snapshots) for _ in range(3))]
        for future in futures:
            future.result(timeout=20)
    assert store.verify_chain()["count"] == 21


def paused_append_process(directory, published, release):
    store = ReceiptStore(directory)
    append_index = store._append_index

    def paused(receipt):
        published.set()
        if not release.wait(15):
            raise RuntimeError("parent did not release paused writer")
        append_index(receipt)

    store._append_index = paused
    store.append(body())


def read_snapshot_process(directory, entered, done, verdicts):
    entered.set()
    try:
        verdicts.put(ReceiptStore(directory).verify_chain())
    finally:
        done.set()


def test_cross_process_reader_waits_until_receipt_and_index_are_published(tmp_path):
    import multiprocessing
    context = multiprocessing.get_context("spawn")
    published, release, entered, done = (context.Event() for _ in range(4))
    verdicts = context.Queue()
    writer = context.Process(target=paused_append_process, args=(tmp_path, published, release))
    reader = context.Process(target=read_snapshot_process, args=(tmp_path, entered, done, verdicts))
    writer.start()
    try:
        assert published.wait(10)
        reader.start()
        assert entered.wait(10)
        assert not done.wait(.2), "Reader observed the unpublished index while writer still held its lock"
        release.set()
        writer.join(15)
        reader.join(15)
        assert writer.exitcode == reader.exitcode == 0
        assert verdicts.get(timeout=2) == {
            "valid": True, "count": 1,
            "head_sha256": ReceiptStore(tmp_path).head()["head_sha256"], "problems": []}
    finally:
        release.set()
        for process in (writer, reader):
            if process.pid is not None:
                process.join(2)
                if process.is_alive():
                    process.terminate()
                    process.join(2)
        verdicts.close()
        verdicts.join_thread()


@pytest.mark.parametrize("position", [0, 1])
def test_single_receipt_verification_checks_index_predecessor(tmp_path, position):
    store = ReceiptStore(tmp_path)
    receipts = [store.append(body(n)) for n in range(3)]
    entries = [json.loads(line) for line in store.index.read_bytes().splitlines()]
    entries[position]["prev_sha256"] = "f" * 64
    damaged = b"".join(canonical_json(row) + b"\n" for row in entries)
    store.index.write_bytes(damaged)
    verdict = store.verify_snapshot(receipt_id=receipts[position]["id"])
    assert not verdict["valid"] and verdict["chain"] == "broken"
    assert any("index chain link" in problem for problem in verdict["problems"])
    assert not store.verify_chain()["valid"]
    with pytest.raises(ReceiptError, match="invalid index chain"):
        store.append(body(4))
    assert store.index.read_bytes() == damaged
    assert len(list(tmp_path.glob("*.json"))) == 3


def test_stored_receipt_id_is_bound_to_requested_filename(tmp_path):
    store = ReceiptStore(tmp_path)
    receipt = store.append(body())
    replacement = dict(receipt, id="20260101T000000Z-aaaaaaaaaaaa")
    replacement["sha256"] = receipt_hash(replacement)
    store.path_for(receipt["id"]).write_bytes(canonical_json(replacement))
    for read in (lambda: store.get(receipt["id"]),
                 lambda: store.verify_snapshot(receipt_id=receipt["id"])):
        with pytest.raises(ReceiptError, match="different id"):
            read()
    assert not store.verify_chain()["valid"]
