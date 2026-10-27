import importlib.util
import json
from pathlib import Path

import pytest
from fake_docker import IMAGE, FakeDocker, passing_result

from jovin_harness.config import load_settings
from jovin_harness.receipts import ReceiptError, ReceiptStore
from jovin_harness.sandbox import Sandbox
from jovin_harness.tools import Harness

SCRIPT = Path(__file__).parents[1] / "tools" / "benchmark_sandbox.py"
spec = importlib.util.spec_from_file_location("benchmark_sandbox", SCRIPT)
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


@pytest.fixture
def benchmark_run(tmp_path, monkeypatch):
    settings = load_settings({"JOVIN_HARNESS_DATA_DIR": str(tmp_path / "data"), "JOVIN_HARNESS_IMAGE": IMAGE})

    class FreshProcessDocker(FakeDocker):
        def start(self, argv):
            self.process = None
            return super().start(argv)

    docker = FreshProcessDocker(settings, result=passing_result(settings))
    harness = Harness(settings=settings, sandbox=Sandbox(settings, executor=docker),
                      store=ReceiptStore(settings.receipts_dir))
    output = tmp_path / "results.json"
    monkeypatch.setattr(benchmark.Harness, "from_environment", lambda: harness)
    monkeypatch.setattr(benchmark.sys, "argv", [str(SCRIPT), "--output", str(output), "--repeats", "2"])
    return harness, output


@pytest.mark.parametrize("chain_failure", [None, "invalid", ReceiptError, OSError])
def test_benchmark_publishes_samples_and_chain_failures(benchmark_run, monkeypatch, chain_failure):
    harness, output = benchmark_run
    if chain_failure:
        def verify_chain():
            if chain_failure == "invalid":
                return {"valid": False, "problems": ["synthetic invalid chain"]}
            raise chain_failure("synthetic chain check failure")

        monkeypatch.setattr(harness.store, "verify_chain", verify_chain)
    publications = []
    replace = benchmark.os.replace

    def track_replace(source, target):
        assert source.parent == target.parent
        if target == output:
            publications.append(json.loads(source.read_text(encoding="utf-8")))
        replace(source, target)

    monkeypatch.setattr(benchmark.os, "replace", track_replace)
    assert benchmark.main() == (1 if chain_failure else 0)
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["valid"] is (chain_failure is None)
    assert evidence["chain"]["valid"] is (chain_failure is None)
    if chain_failure in (ReceiptError, OSError):
        assert evidence["chain"]["error"] == f"{chain_failure.__name__}: synthetic chain check failure"
    assert [len(item["samples"]) for item in publications] == [1, 2, 2]
    assert all(sample["receipt_valid"] and len(sample["receipt_persistence_s"]) == 1
               for sample in evidence["samples"])
    assert publications[-1] == evidence
    assert not list(output.parent.glob("*.tmp"))


@pytest.mark.parametrize("failure_stage", ["serialize", "fsync", "replace"])
def test_interrupted_update_preserves_previous_evidence(tmp_path, monkeypatch, failure_stage):
    output = tmp_path / "results.json"
    benchmark._write_evidence(output, {"samples": [{"sample": 0}]})
    previous = output.read_bytes()

    def interrupt(*args, **kwargs):
        if failure_stage == "serialize":
            args[1].write('{"samples": [')
        raise KeyboardInterrupt("synthetic interruption")

    if failure_stage == "serialize":
        monkeypatch.setattr(benchmark.json, "dump", interrupt)
    else:
        monkeypatch.setattr(benchmark.os, failure_stage, interrupt)
    with pytest.raises(KeyboardInterrupt, match="synthetic interruption"):
        benchmark._write_evidence(output, {"samples": [{"sample": 0}, {"sample": 1}]})
    assert output.read_bytes() == previous
    assert not list(tmp_path.glob("*.tmp"))


def test_existing_benchmark_output_is_preserved(benchmark_run):
    _, output = benchmark_run
    previous = '{"valid": true}'
    output.write_text(previous, encoding="utf-8")
    with pytest.raises(FileExistsError):
        benchmark.main()
    assert output.read_text(encoding="utf-8") == previous
