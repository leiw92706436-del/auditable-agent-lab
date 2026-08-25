from __future__ import annotations

import json
from dataclasses import replace
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
    issued_at = datetime(2030, 1, 1, tzinfo=UTC)
    machine_state = {"review_status": "approved", "evidence_complete": True}
    transitions = {
        "draft": {"approved"},
        "approved": {"archived"},
        "archived": set(),
    }
    protected_action = LifecycleManager.transition_action("draft", "approved")
    archive_action = LifecycleManager.transition_action("approved", "archived")
    rules = [
        PolicyRule(
            action=protected_action,
            required_state=machine_state,
            authorization_required=True,
        ),
        PolicyRule(
            action=archive_action,
            required_state={"evidence_complete": True},
            authorization_required=False,
        ),
    ]
    policy_definition = PolicyEvaluator(
        policy_id="synthetic-lifecycle-policy",
        known_state_fields=machine_state,
        rules=rules,
    )
    workflow = LifecycleState(workflow_id="synthetic-study", stage="draft")
    receipt = AuthorizationReceipt(
        receipt_id="receipt-synthetic-001",
        actor="reviewer@example.invalid",
        action=protected_action,
        scope=workflow.workflow_id,
        policy_sha256=policy_definition.policy_sha256,
        state_sha256=hash_machine_state(machine_state),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )
    # Synthetic stand-in for a digest delivered by an external supervisor.
    trusted_receipt_digests = frozenset({receipt.receipt_sha256})
    evaluator = PolicyEvaluator(
        policy_id="synthetic-lifecycle-policy",
        known_state_fields=machine_state,
        rules=rules,
        authorization_verifier=TrustedReceiptVerifier(trusted_receipt_digests),
    )
    manager = LifecycleManager(transitions=transitions, evaluator=evaluator)

    missing_authorization_reason = None
    try:
        manager.advance(
            workflow,
            "approved",
            machine_state=machine_state,
            at=issued_at,
        )
    except LifecycleError as exc:
        missing_authorization_reason = str(exc)

    forged_authorization_reason = None
    forged = replace(receipt, actor="caller@example.invalid")
    try:
        manager.advance(
            workflow,
            "approved",
            machine_state=machine_state,
            receipt=forged,
            at=issued_at,
        )
    except LifecycleError as exc:
        forged_authorization_reason = str(exc)

    approved = manager.advance(
        workflow,
        "approved",
        machine_state=machine_state,
        receipt=receipt,
        at=issued_at,
    )
    archived = manager.advance(
        approved,
        "archived",
        machine_state=machine_state,
        at=issued_at,
    )

    with TemporaryDirectory() as temporary_directory:
        artifact_root = Path(temporary_directory)
        summary_path = artifact_root / "summary.json"
        review_path = artifact_root / "review.json"
        summary_path.write_text(
            json.dumps({"finding": "synthetic", "reviewed": True}),
            encoding="utf-8",
        )
        review_path.write_text(
            json.dumps({"status": "complete"}),
            encoding="utf-8",
        )
        manifest = EvidenceManifest.build(
            artifact_root=artifact_root,
            artifact_paths=["summary.json", "review.json"],
            manifest_id="manifest-synthetic-001",
            producer_label="synthetic-example",
            created_at=issued_at,
        )
        # Synthetic stand-in for a digest retained outside the evidence bundle.
        trusted_manifest_sha256 = manifest.manifest_sha256
        verifier = Verifier()
        expected_artifacts = ["review.json", "summary.json"]
        verified = verifier.verify(
            manifest=manifest,
            artifact_root=artifact_root,
            expected_manifest_sha256=trusted_manifest_sha256,
            expected_artifacts=expected_artifacts,
        )

        rewritten = EvidenceManifest.build(
            artifact_root=artifact_root,
            artifact_paths=["summary.json"],
            manifest_id="manifest-synthetic-001",
            producer_label="rewritten-producer-label",
            created_at=issued_at,
        )
        rewritten_result = verifier.verify(
            manifest=rewritten,
            artifact_root=artifact_root,
            expected_manifest_sha256=trusted_manifest_sha256,
            expected_artifacts=expected_artifacts,
        )

        summary_path.write_text("changed after manifest", encoding="utf-8")
        tampered = verifier.verify(
            manifest=manifest,
            artifact_root=artifact_root,
            expected_manifest_sha256=trusted_manifest_sha256,
            expected_artifacts=expected_artifacts,
        )

    return {
        "missing_authorization_reason": missing_authorization_reason,
        "forged_authorization_reason": forged_authorization_reason,
        "authorized_stage": approved.stage,
        "terminal_stage": archived.stage,
        "terminal_frozen": archived.frozen,
        "evidence_valid_before_change": verified.valid,
        "rewritten_evidence_valid": rewritten_result.valid,
        "rewritten_reason_codes": list(rewritten_result.reason_codes),
        "evidence_valid_after_change": tampered.valid,
        "tamper_reason_codes": list(tampered.reason_codes),
    }


def main() -> int:
    print(json.dumps(run(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
