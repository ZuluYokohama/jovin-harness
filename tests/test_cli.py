import json

from fake_docker import IMAGE, FakeDocker, passing_result

from jovin_harness import cli
from jovin_harness.config import load_settings
from jovin_harness.receipts import ReceiptStore
from jovin_harness.sandbox import Sandbox
from jovin_harness.tools import Harness


def patch_harness(monkeypatch, tmp_path):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path), "JOVIN_HARNESS_IMAGE": IMAGE})
    harness = Harness(settings=settings, store=ReceiptStore(settings.receipts_dir),
                      sandbox=Sandbox(settings, executor=FakeDocker(settings, result=passing_result(settings))))
    monkeypatch.setattr(cli.Harness, "from_environment", classmethod(lambda cls, env=None: harness))
    return harness


def test_verify_then_check_receipts(monkeypatch, tmp_path, capsys):
    patch_harness(monkeypatch, tmp_path)
    (tmp_path / "code.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "tests.py").write_text("assert x == 1\n", encoding="utf-8")
    assert cli.main(["verify", str(tmp_path / "code.py"), "--tests", str(tmp_path / "tests.py")]) == 0
    receipt_id = json.loads(capsys.readouterr().out)["receipt_id"]
    assert cli.main(["receipts", "verify", receipt_id]) == 0
    capsys.readouterr()
    assert cli.main(["receipts", "verify"]) == 0
    assert json.loads(capsys.readouterr().out)["count"] == 1
    assert cli.main(["receipts", "head"]) == 0


def test_doctor_reports_readiness(monkeypatch, tmp_path, capsys):
    patch_harness(monkeypatch, tmp_path)
    assert cli.main(["doctor"]) == 0
    assert json.loads(capsys.readouterr().out)["ready"] is True


def test_errors_exit_2_with_a_message(monkeypatch, tmp_path, capsys):
    patch_harness(monkeypatch, tmp_path)
    assert cli.main(["receipts", "show", "../../etc/passwd"]) == 2
    assert "invalid receipt id" in capsys.readouterr().err


def test_doctor_sweep_exposes_unresolved_cleanup(monkeypatch, tmp_path, capsys):
    harness = patch_harness(monkeypatch, tmp_path)
    harness.sandbox.executor.remove_fails = True
    assert cli.main(["doctor", "--sweep"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["swept"] == []
    assert len(report["sweep_failed"]) == 2


def test_doctor_sweep_reports_confirmed_removal(monkeypatch, tmp_path, capsys):
    patch_harness(monkeypatch, tmp_path)
    assert cli.main(["doctor", "--sweep"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["swept"] == ["aaa", "bbb"]
    assert report["sweep_failed"] == report["sweep_skipped"] == []
