import json
import threading

import pytest

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
