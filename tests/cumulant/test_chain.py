import json

import pytest

pytest.importorskip("torch")

from jovin_harness.cumulant.chain import (  # noqa: E402
    GENESIS,
    Journal,
    assert_real_run_authorized,
    check_frozen,
    freeze,
    prereg_sha256,
    verify_chain,
)
from jovin_harness.receipts import canonical_json, sha256_hex  # noqa: E402


def test_prereg_hash_is_canonical_sha256():
    a = {"b": 1, "a": [1, 2], "c": {"y": 1, "x": 2}}
    b = {"c": {"x": 2, "y": 1}, "a": [1, 2], "b": 1}
    assert prereg_sha256(a) == prereg_sha256(b) == sha256_hex(canonical_json(a))


def test_freeze_refuses_different_prereg(tmp_path):
    p = tmp_path / "PREREG_FROZEN.json"
    doc = freeze({"seed": 1}, p, "agent", "ref")
    check_frozen(doc)
    assert freeze({"seed": 1}, p, "agent", "ref")["prereg_sha256"] == doc["prereg_sha256"]
    with pytest.raises(PermissionError):
        freeze({"seed": 2}, p, "agent", "ref")
    doc["prereg"]["seed"] = 3
    with pytest.raises(PermissionError):
        check_frozen(doc)


def test_journal_chain_and_tamper_detection(tmp_path):
    path = tmp_path / "journal.jsonl"
    j = Journal(path)
    assert j.head() == GENESIS
    for i in range(4):
        j.append("EVENT", {"i": i})
    ok, head = verify_chain(path)
    assert ok and head == j.head()
    lines = path.read_text().splitlines()
    edited = json.loads(lines[1])
    edited["payload"]["i"] = 99
    path.write_text("\n".join([lines[0], json.dumps(edited)] + lines[2:]) + "\n")
    assert not verify_chain(path)[0]
    path.write_text("\n".join([lines[0]] + lines[2:]) + "\n")
    assert not verify_chain(path)[0]
    path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not verify_chain(path)[0]


def test_real_run_guard_fails_closed(tmp_path):
    base = {"data_source": "kansas_real", "owner_go_ref": "t99u", "data_sha256": "ab" * 32}
    doc = freeze(base, tmp_path / "f.json", "agent", "ref")
    assert_real_run_authorized(doc, "ab" * 32)
    with pytest.raises(PermissionError):
        assert_real_run_authorized(doc, "cd" * 32)
    for bad in ({"owner_go_ref": ""}, {"data_source": "synthetic"}):
        d = freeze(base | bad, tmp_path / f"{len(bad)}{list(bad)[0]}.json", "agent", "ref")
        with pytest.raises(PermissionError):
            assert_real_run_authorized(d, "ab" * 32)
    marker = tmp_path / "SCORED"
    marker.write_text("x")
    d = freeze(base | {"scored_once_marker": str(marker)}, tmp_path / "m.json", "agent", "ref")
    with pytest.raises(PermissionError):
        assert_real_run_authorized(d, "ab" * 32)
