from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from auditable_agent_lab import (
    AuthorizationReceipt,
    PolicyEvaluator,
    PolicyRule,
    hash_machine_state,
)
from auditable_agent_lab.cli import main
from auditable_agent_lab.evidence import EvidenceManifest


NOW = datetime(2030, 1, 1, tzinfo=UTC)
STATE = {"review_status": "approved"}


def _policy_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "synthetic-cli-policy",
        "known_state_fields": ["review_status"],
        "rules": [
            {
                "action": "publish.summary",
                "required_state": {"review_status": "approved"},
                "authorization_required": True,
            }
        ],
    }


def _policy_definition() -> PolicyEvaluator:
    return PolicyEvaluator(
        policy_id="synthetic-cli-policy",
        known_state_fields=["review_status"],
        rules=[PolicyRule("publish.summary", STATE)],
    )


def _receipt() -> AuthorizationReceipt:
    return AuthorizationReceipt(
        receipt_id="receipt-cli-001",
        actor="reviewer@example.invalid",
        action="publish.summary",
        scope="study-001",
        policy_sha256=_policy_definition().policy_sha256,
        state_sha256=hash_machine_state(STATE),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _action_paths(tmp_path: Path) -> tuple[Path, Path]:
    state_path = tmp_path / "state.json"
    policy_path = tmp_path / "policy.json"
    _write_json(state_path, STATE)
    _write_json(policy_path, _policy_payload())
    return state_path, policy_path


def test_action_check_returns_stable_pass_envelope_for_trusted_receipt(
    tmp_path: Path, capsys
) -> None:
    state_path, policy_path = _action_paths(tmp_path)
    receipt = _receipt()
    receipt_path = tmp_path / "receipt.json"
    _write_json(receipt_path, receipt.to_dict())

    exit_code = main(
        [
            "action-check",
            "--state",
            str(state_path),
            "--policy",
            str(policy_path),
            "--action",
            "publish.summary",
            "--scope",
            "study-001",
            "--receipt",
            str(receipt_path),
            "--trusted-receipt-sha256",
            receipt.receipt_sha256,
            "--at",
            NOW.isoformat(),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert set(output) == {"schema_version", "command", "status", "result", "error"}
    assert output["command"] == "action-check"
    assert output["status"] == "pass"
    assert output["result"]["allowed"] is True
    assert output["error"] is None


def test_action_check_denies_unknown_action_with_fail_envelope(
    tmp_path: Path, capsys
) -> None:
    state_path, policy_path = _action_paths(tmp_path)

    exit_code = main(
        [
            "action-check",
            "--state",
            str(state_path),
            "--policy",
            str(policy_path),
            "--action",
            "unknown",
            "--scope",
            "study-001",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["status"] == "fail"
    assert output["result"]["reason_code"] == "unknown_action"
    assert output["error"] is None


def test_action_check_denies_caller_receipt_without_trust_anchor(
    tmp_path: Path, capsys
) -> None:
    state_path, policy_path = _action_paths(tmp_path)
    receipt_path = tmp_path / "receipt.json"
    _write_json(receipt_path, _receipt().to_dict())

    exit_code = main(
        [
            "action-check",
            "--state",
            str(state_path),
            "--policy",
            str(policy_path),
            "--action",
            "publish.summary",
            "--scope",
            "study-001",
            "--receipt",
            str(receipt_path),
            "--at",
            NOW.isoformat(),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["status"] == "fail"
    assert output["result"]["reason_code"] == "authorization_verifier_missing"


def test_action_check_rejects_duplicate_state_key_as_invalid_json(
    tmp_path: Path, capsys
) -> None:
    state_path, policy_path = _action_paths(tmp_path)
    state_path.write_text(
        '{"review_status":"pending","review_status":"approved"}',
        encoding="utf-8",
    )

    exit_code = main(
        [
            "action-check",
            "--state",
            str(state_path),
            "--policy",
            str(policy_path),
            "--action",
            "publish.summary",
            "--scope",
            "study-001",
        ]
    )

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 2
    assert output["status"] == "error"
    assert output["result"] is None
    assert output["error"]["reason_code"] == "invalid_json"


def _evidence_fixture(tmp_path: Path) -> tuple[Path, Path, EvidenceManifest]:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "result.json").write_text("{}\n", encoding="utf-8")
    manifest = EvidenceManifest.build(
        artifact_root=artifact_root,
        artifact_paths=["result.json"],
        manifest_id="manifest-001",
        producer_label="synthetic-producer",
        created_at=NOW,
    )
    manifest_path = tmp_path / "manifest.json"
    manifest.write(manifest_path)
    return artifact_root, manifest_path, manifest


def _evidence_args(
    artifact_root: Path, manifest_path: Path, manifest: EvidenceManifest
) -> list[str]:
    return [
        "evidence-verify",
        "--manifest",
        str(manifest_path),
        "--artifact-root",
        str(artifact_root),
        "--expected-manifest-sha256",
        manifest.manifest_sha256,
        "--expect-artifact",
        "result.json",
    ]


def test_evidence_verify_cli_returns_stable_pass_envelope(
    tmp_path: Path, capsys
) -> None:
    artifact_root, manifest_path, manifest = _evidence_fixture(tmp_path)

    exit_code = main(_evidence_args(artifact_root, manifest_path, manifest))

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert set(output) == {"schema_version", "command", "status", "result", "error"}
    assert output["command"] == "evidence-verify"
    assert output["status"] == "pass"
    assert output["result"]["valid"] is True
    assert output["error"] is None


def test_evidence_verify_cli_reports_tamper_as_fail(tmp_path: Path, capsys) -> None:
    artifact_root, manifest_path, manifest = _evidence_fixture(tmp_path)
    (artifact_root / "result.json").write_text("changed", encoding="utf-8")

    exit_code = main(_evidence_args(artifact_root, manifest_path, manifest))

    output = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert output["status"] == "fail"
    assert "artifact_hash_mismatch" in output["result"]["reason_codes"]
    assert output["error"] is None


def test_cli_returns_stable_error_envelope_for_io_and_arguments(
    tmp_path: Path, capsys
) -> None:
    missing_manifest = tmp_path / "missing.json"
    io_exit = main(
        [
            "evidence-verify",
            "--manifest",
            str(missing_manifest),
            "--artifact-root",
            str(tmp_path),
            "--expected-manifest-sha256",
            "a" * 64,
            "--expect-artifact",
            "result.json",
        ]
    )
    io_output = json.loads(capsys.readouterr().out)

    argument_exit = main(
        [
            "evidence-verify",
            "--manifest",
            str(missing_manifest),
            "--artifact-root",
            str(tmp_path),
        ]
    )
    argument_output = json.loads(capsys.readouterr().out)

    assert io_exit == 2
    assert io_output["status"] == "error"
    assert io_output["result"] is None
    assert io_output["error"]["reason_code"] == "io_error"
    assert argument_exit == 2
    assert argument_output["status"] == "error"
    assert argument_output["error"]["reason_code"] == "argument_error"
