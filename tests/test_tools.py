import pytest
from fake_docker import IMAGE, FakeDocker, passing_result

from jovin_harness.config import load_settings
from jovin_harness.receipts import ReceiptStore
from jovin_harness.sandbox import Sandbox
from jovin_harness.tools import Harness, ToolError


def make_harness(tmp_path, result="pass"):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path), "JOVIN_HARNESS_IMAGE": IMAGE})
    docker = FakeDocker(settings, result=passing_result(settings) if result == "pass" else result)
    harness = Harness(settings=settings, sandbox=Sandbox(settings, executor=docker),
                      store=ReceiptStore(settings.receipts_dir))
    return harness, docker


def test_verify_python_returns_verdict_and_receipt(tmp_path):
    harness, _ = make_harness(tmp_path)
    out = harness.verify_python("def f():\n    return 1\n", "assert f() == 1\n")
    assert out["passed"] and out["status"] == "passed"
    assert out["integrity"] == "shared_interpreter"
    receipt = harness.get_receipt(out["receipt_id"])
    assert receipt["sha256"] == out["receipt_sha256"]
    assert receipt["inputs"]["code_sha256"] and receipt["inputs"]["tests_sha256"]
    assert receipt["sandbox"]["inspect_verified"]
    assert harness.verify_receipt(receipt_id=out["receipt_id"])["valid"]


def test_failures_are_receipted_too(tmp_path):
    failed = {"format": "jovin-harness.sandbox-result.v1", "status": "failed", "total": 2, "passed_count": 1,
              "tests": [{"name": "<module>", "outcome": "passed", "message": ""},
                        {"name": "test_x", "outcome": "failed", "message": "AssertionError at line 2"}]}
    harness, _ = make_harness(tmp_path, result=failed)
    out = harness.verify_python("x = 1\n", "def test_x():\n    assert x == 2\n")
    assert not out["passed"]
    assert out["failures"] == [{"name": "test_x", "outcome": "failed", "message": "AssertionError at line 2"}]
    assert harness.store.head()["count"] == 1


def test_tampered_receipt_object_is_rejected(tmp_path):
    harness, _ = make_harness(tmp_path)
    receipt = harness.get_receipt(harness.verify_python("x = 1", "assert x == 1")["receipt_id"])
    receipt["result"]["status"] = "passed!"
    assert not harness.verify_receipt(receipt=receipt)["valid"]


def test_bad_requests_run_nothing(tmp_path):
    harness, docker = make_harness(tmp_path)
    with pytest.raises(ToolError):
        harness.verify_python("", "assert True")
    with pytest.raises(ToolError):
        harness.verify_python("x = 1", "  ")
    with pytest.raises(ToolError):
        harness.run_python("print(1)", timeout_s=99)
    with pytest.raises(ToolError, match="larger than"):
        harness.run_python("x" * 300_000)
    with pytest.raises(ToolError):
        harness.verify_receipt()
    assert docker.calls == []
    assert harness.store.head()["count"] == 0


def test_unavailable_sandbox_is_a_clear_error(tmp_path):
    harness, docker = make_harness(tmp_path)
    docker.engine["OSType"] = "windows"
    with pytest.raises(ToolError, match="nothing was run"):
        harness.run_python("print(1)")


def test_rate_limit(tmp_path):
    harness, _ = make_harness(tmp_path)
    harness.limit_rate(runs_per_minute=2)
    harness.run_python("print(1)")
    harness.run_python("print(1)")
    with pytest.raises(ToolError, match="rate limit"):
        harness.run_python("print(1)")


def test_status_includes_receipt_head(tmp_path):
    harness, _ = make_harness(tmp_path)
    status = harness.sandbox_status()
    assert status["ready"] and status["receipts"]["count"] == 0


def test_corrupt_receipt_store_is_a_tool_error(tmp_path):
    harness, _ = make_harness(tmp_path)
    out = harness.verify_python("x = 1", "assert x == 1")
    harness.store.index.write_text("{broken\n", encoding="utf-8")
    with pytest.raises(ToolError, match="could not be read"):
        harness.verify_receipt(receipt_id=out["receipt_id"])
    with pytest.raises(ToolError, match="receipt could not be written"):
        harness.run_python("print(1)")
    status = harness.sandbox_status()
    assert not status["ready"] and any("receipt store" in p for p in status["problems"])


def test_surrogates_in_sandbox_output_still_get_a_receipt(tmp_path):
    from fake_docker import passing_result as passing
    harness, docker = make_harness(tmp_path)
    docker.result = dict(passing(harness.settings), stderr_tail="\ud800")
    out = harness.verify_python("x = 1", "assert x == 1")
    assert out["receipt_id"] and harness.verify_receipt(receipt_id=out["receipt_id"])["valid"]
