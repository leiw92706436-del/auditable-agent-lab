from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_synthetic_release_gate_runs_end_to_end() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "examples/synthetic_release_gate/run_example.py"],
        cwd=REPO_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)

    assert result["scenario"] == "ai_assisted_release_gate"
    assert result["release_executed"] is False
    assert result["expected_artifacts"] == [
        "candidate.bin",
        "ci-report.json",
    ]
    assert result["evidence_valid_before_change"] is True
    assert result["missing_authorization_reason"] == "authorization_missing"
    assert result["gate_stage"] == "release_ready"
    assert result["gate_frozen"] is True
    assert result["tampered_evidence_valid"] is False
    assert "artifact_hash_mismatch" in result["tamper_reason_codes"]
    assert result["tampered_receipt_configured_as_trusted"] is True
    assert result["tampered_gate_allowed"] is False
    assert result["tampered_gate_reason"] == "state_requirement_not_met"
