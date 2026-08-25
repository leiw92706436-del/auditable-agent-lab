from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_synthetic_example_runs_end_to_end() -> None:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(REPO_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "examples/synthetic_research/run_example.py"],
        cwd=REPO_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)

    assert result["missing_authorization_reason"] == "authorization_missing"
    assert result["forged_authorization_reason"] == (
        "authorization_receipt_untrusted"
    )
    assert result["authorized_stage"] == "approved"
    assert result["terminal_stage"] == "archived"
    assert result["terminal_frozen"] is True
    assert result["evidence_valid_before_change"] is True
    assert result["rewritten_evidence_valid"] is False
    assert "manifest_anchor_mismatch" in result["rewritten_reason_codes"]
    assert "artifact_set_mismatch" in result["rewritten_reason_codes"]
    assert result["evidence_valid_after_change"] is False
    assert "artifact_hash_mismatch" in result["tamper_reason_codes"]
