from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory

from auditable_agent_lab import (
    AuthorizationReceipt,
    EvidenceManifest,
    LifecycleError,
    LifecycleManager,
    LifecycleState,
    PolicyEvaluator,
    PolicyRule,
    TrustedReceiptVerifier,
    Verifier,
    hash_machine_state,
)


def run() -> dict[str, object]:
    evaluated_at = datetime(2030, 1, 1, tzinfo=UTC)
    workflow = LifecycleState(
        workflow_id="synthetic-release-candidate-001",
        stage="candidate",
    )
    transitions = {
        "candidate": {"release_ready"},
        "release_ready": set(),
    }
    protected_action = LifecycleManager.transition_action(
        "candidate",
        "release_ready",
    )

    with TemporaryDirectory() as temporary_directory:
        artifact_root = Path(temporary_directory)
        (artifact_root / "candidate.bin").write_bytes(
            b"synthetic release candidate\n"
        )
        (artifact_root / "ci-report.json").write_text(
            json.dumps(
                {
                    "checks": 12,
                    "status": "passed",
                    "source": "synthetic-ci",
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        manifest = EvidenceManifest.build(
            artifact_root=artifact_root,
            artifact_paths=["candidate.bin", "ci-report.json"],
            manifest_id="synthetic-release-manifest-001",
            producer_label="synthetic-build-agent",
            created_at=evaluated_at,
        )

        # These values stand in for trust inputs retained by a supervisor
        # outside the build agent's write boundary.
        trusted_manifest_sha256 = manifest.manifest_sha256
        expected_artifacts = ["candidate.bin", "ci-report.json"]
        verifier = Verifier()
        evidence_result = verifier.verify(
            manifest=manifest,
            artifact_root=artifact_root,
            expected_manifest_sha256=trusted_manifest_sha256,
            expected_artifacts=expected_artifacts,
        )

        machine_state = {
            "ci_status": "passed",
            "evidence_status": (
                "verified" if evidence_result.valid else "failed"
            ),
            "manifest_sha256": trusted_manifest_sha256,
            "review_status": "approved",
        }
        rule = PolicyRule(
            action=protected_action,
            required_state={
                "ci_status": "passed",
                "evidence_status": "verified",
                "manifest_sha256": trusted_manifest_sha256,
                "review_status": "approved",
            },
            authorization_required=True,
        )
        policy_definition = PolicyEvaluator(
            policy_id="synthetic-release-gate-policy",
            known_state_fields=machine_state,
            rules=[rule],
        )
        receipt = AuthorizationReceipt(
            receipt_id="synthetic-release-approval-001",
            actor="maintainer@example.invalid",
            action=protected_action,
            scope=workflow.workflow_id,
            policy_sha256=policy_definition.policy_sha256,
            state_sha256=hash_machine_state(machine_state),
            issued_at=evaluated_at,
            expires_at=evaluated_at + timedelta(minutes=30),
        )
        evaluator = PolicyEvaluator(
            policy_id="synthetic-release-gate-policy",
            known_state_fields=machine_state,
            rules=[rule],
            authorization_verifier=TrustedReceiptVerifier(
                {receipt.receipt_sha256}
            ),
        )
        manager = LifecycleManager(
            transitions=transitions,
            evaluator=evaluator,
        )

        missing_authorization_reason = None
        try:
            manager.advance(
                workflow,
                "release_ready",
                machine_state=machine_state,
                at=evaluated_at,
            )
        except LifecycleError as exc:
            missing_authorization_reason = str(exc)

        release_ready = manager.advance(
            workflow,
            "release_ready",
            machine_state=machine_state,
            receipt=receipt,
            at=evaluated_at,
        )

        (artifact_root / "candidate.bin").write_bytes(
            b"changed after independent verification\n"
        )
        tampered_evidence = verifier.verify(
            manifest=manifest,
            artifact_root=artifact_root,
            expected_manifest_sha256=trusted_manifest_sha256,
            expected_artifacts=expected_artifacts,
        )
        tampered_state = {
            **machine_state,
            "evidence_status": (
                "verified" if tampered_evidence.valid else "failed"
            ),
        }
        tampered_workflow_id = "synthetic-release-candidate-002"
        tampered_receipt = AuthorizationReceipt(
            receipt_id="synthetic-release-approval-002",
            actor="maintainer@example.invalid",
            action=protected_action,
            scope=tampered_workflow_id,
            policy_sha256=policy_definition.policy_sha256,
            state_sha256=hash_machine_state(tampered_state),
            issued_at=evaluated_at,
            expires_at=evaluated_at + timedelta(minutes=30),
        )
        tampered_evaluator = PolicyEvaluator(
            policy_id="synthetic-release-gate-policy",
            known_state_fields=tampered_state,
            rules=[rule],
            authorization_verifier=TrustedReceiptVerifier(
                {tampered_receipt.receipt_sha256}
            ),
        )
        tampered_gate = tampered_evaluator.evaluate(
            state=tampered_state,
            action=protected_action,
            scope=tampered_workflow_id,
            receipt=tampered_receipt,
            at=evaluated_at,
        )

    return {
        "scenario": "ai_assisted_release_gate",
        "release_executed": False,
        "expected_artifacts": expected_artifacts,
        "evidence_valid_before_change": evidence_result.valid,
        "missing_authorization_reason": missing_authorization_reason,
        "gate_stage": release_ready.stage,
        "gate_frozen": release_ready.frozen,
        "tampered_evidence_valid": tampered_evidence.valid,
        "tamper_reason_codes": list(tampered_evidence.reason_codes),
        "tampered_receipt_configured_as_trusted": True,
        "tampered_gate_allowed": tampered_gate.allowed,
        "tampered_gate_reason": tampered_gate.reason_code,
    }


def main() -> int:
    print(json.dumps(run(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
