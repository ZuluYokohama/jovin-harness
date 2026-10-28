"""Signed receipts and the signed head checkpoint.

Regression tests for the harness gap check (2026-10-28): P7 (delete the newest receipts and their
index lines), P9-style rollback (truncate and restore an older signed checkpoint) and the
unsigned-rebuild case (edit a middle receipt and rehash forward).
"""

import json

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from jovin_harness.config import ConfigError, load_settings  # noqa: E402
from jovin_harness.receipts import ReceiptError, ReceiptStore, canonical_json, receipt_hash  # noqa: E402
from jovin_harness.signing import Signer, Verifier  # noqa: E402
from jovin_harness.tools import store_for  # noqa: E402


def write_key(path):
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return key


def write_public(path, key):
    path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo))


@pytest.fixture
def signer(tmp_path):
    keydir = tmp_path / "keys"
    keydir.mkdir()
    write_key(keydir / "signing.pem")
    return Signer.from_file(keydir / "signing.pem")


def body(status):
    return {"tool": "verify_python", "result": {"status": status}}


def signed_store(tmp_path, signer, anchor=False):
    return ReceiptStore(tmp_path / "receipts", signer=signer,
                        head_anchor=(tmp_path / "anchor" / "heads.jsonl") if anchor else None)


def test_signed_append_writes_signature_and_checkpoint(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    ids = [store.append(body(s))["id"] for s in ("passed", "failed")]
    for rid in ids:
        assert store.sig_path(rid).is_file()
    cp = store.checkpoint()
    assert cp["count"] == 2 and cp["epoch"] == 2 and cp["head_id"] == ids[-1]
    report = store.verify_chain()
    assert report["valid"], report["problems"]
    assert report["signed"] is True and report["checkpoint_epoch"] == 2


def test_unsigned_store_is_unchanged(tmp_path):
    store = ReceiptStore(tmp_path)
    store.append(body("passed"))
    assert not (tmp_path / "head.checkpoint").exists()
    assert "signed" not in store.verify_chain()


def truncate(store, keep):
    lines = store.index.read_text().splitlines(True)
    store.index.write_text("".join(lines[:keep]))
    for line in lines[keep:]:
        rid = json.loads(line)["id"]
        store.path_for(rid).unlink()
        store.sig_path(rid).unlink()


def test_p7_truncating_newest_receipts_is_detected(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    for s in ("passed", "failed", "failed"):
        store.append(body(s))
    truncate(store, 1)
    report = store.verify_chain()
    assert not report["valid"]
    assert any("truncated or rewritten" in p for p in report["problems"])


def test_p9_rollback_of_old_checkpoint_needs_anchor(tmp_path, signer):
    # Without an anchor an older signed checkpoint plus a matching truncation is internally consistent.
    # This test documents that limit; the anchored test below is the defence.
    store = signed_store(tmp_path, signer)
    store.append(body("passed"))
    old = store.checkpoint_path.read_bytes()
    store.append(body("failed"))
    store.append(body("failed"))
    truncate(store, 1)
    store.checkpoint_path.write_bytes(old)
    assert store.verify_chain()["valid"]


def test_p9_rollback_detected_with_head_anchor(tmp_path, signer):
    store = signed_store(tmp_path, signer, anchor=True)
    store.append(body("passed"))
    old = store.checkpoint_path.read_bytes()
    store.append(body("failed"))
    store.append(body("failed"))
    assert store.verify_chain()["valid"]
    truncate(store, 1)
    store.checkpoint_path.write_bytes(old)
    report = store.verify_chain()
    assert not report["valid"]
    assert any(p.startswith("rollback:") for p in report["problems"])
    assert report["anchored_epoch"] == 3 and report["checkpoint_epoch"] == 1


def test_edit_middle_and_rehash_forward_is_detected(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    for s in ("passed", "passed", "passed"):
        store.append(body(s))
    entries = [json.loads(line) for line in store.index.read_text().splitlines()]
    previous, index = None, []
    for entry in entries:
        receipt = json.loads(store.path_for(entry["id"]).read_text())
        if entry is entries[1]:
            receipt["result"] = {"status": "rewritten"}
        receipt["prev_sha256"] = previous
        receipt["sha256"] = receipt_hash(receipt)
        store.path_for(entry["id"]).write_bytes(canonical_json(receipt))
        index.append(canonical_json({"id": receipt["id"], "sha256": receipt["sha256"],
                                     "prev_sha256": previous}).decode() + "\n")
        previous = receipt["sha256"]
    store.index.write_text("".join(index))
    report = store.verify_chain()
    assert not report["valid"]
    assert any("signature covers a different receipt" in p for p in report["problems"])


def test_unsigned_receipt_in_signed_store_is_rejected(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    store.append(body("passed"))
    ReceiptStore(store.directory).append(body("passed"))  # writer without the key
    report = store.verify_chain()
    assert not report["valid"]
    assert any("not signed" in p for p in report["problems"])


def test_signature_from_other_key_is_rejected(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    rid = store.append(body("passed"))["id"]
    other = tmp_path / "other.pem"
    write_key(other)
    verifier_store = ReceiptStore(store.directory, verifier=Verifier(Signer.from_file(other).public_key))
    report = verifier_store.verify_chain()
    assert not report["valid"]
    assert any(rid in p and "unknown key" in p for p in report["problems"])


def test_tampered_checkpoint_is_rejected_and_not_extended(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    store.append(body("passed"))
    cp = json.loads(store.checkpoint_path.read_text())
    cp["epoch"] = 99
    store.checkpoint_path.write_text(json.dumps(cp))
    assert not store.verify_chain()["valid"]
    with pytest.raises(ReceiptError, match="invalid head checkpoint"):
        store.append(body("passed"))


def test_single_receipt_verify_checks_signature(tmp_path, signer):
    store = signed_store(tmp_path, signer)
    receipt = store.append(body("passed"))
    assert store.verify(receipt)["valid"]
    store.sig_path(receipt["id"]).unlink()
    assert not store.verify(receipt)["valid"]


def test_config_reads_key_paths_and_refuses_key_in_data_dir(tmp_path):
    data = tmp_path / "data"
    key = tmp_path / "keys" / "signing.pem"
    env = {"JOVIN_HARNESS_DATA_DIR": str(data), "JOVIN_HARNESS_SIGNING_KEY": str(key),
           "JOVIN_HARNESS_HEAD_ANCHOR": str(tmp_path / "anchor.jsonl")}
    settings = load_settings(env)
    assert settings.signing_key == key and settings.head_anchor == tmp_path / "anchor.jsonl"
    with pytest.raises(ConfigError, match="outside the data directory"):
        load_settings({**env, "JOVIN_HARNESS_SIGNING_KEY": str(data / "signing.pem")})
    with pytest.raises(ConfigError, match="absolute"):
        load_settings({**env, "JOVIN_HARNESS_SIGNING_KEY": "signing.pem"})


def test_store_for_signs_with_configured_key_and_rejects_mismatched_pair(tmp_path):
    keydir = tmp_path / "keys"
    keydir.mkdir()
    write_key(keydir / "a.pem")
    other = write_key(keydir / "b.pem")
    write_public(keydir / "b.pub", other)
    env = {"JOVIN_HARNESS_DATA_DIR": str(tmp_path / "data"), "JOVIN_HARNESS_SIGNING_KEY": str(keydir / "a.pem")}
    store = store_for(load_settings(env))
    store.append(body("passed"))
    assert store.verify_chain()["valid"]
    with pytest.raises(ReceiptError, match="not a key pair"):
        store_for(load_settings({**env, "JOVIN_HARNESS_VERIFY_KEY": str(keydir / "b.pub")}))
    with pytest.raises(ReceiptError, match="cannot load signing key"):
        (keydir / "bad.pem").write_text("not a key")
        store_for(load_settings({**env, "JOVIN_HARNESS_SIGNING_KEY": str(keydir / "bad.pem")}))
