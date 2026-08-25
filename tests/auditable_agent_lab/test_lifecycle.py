from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from auditable_agent_lab import (
    AuthorizationReceipt,
    LifecycleError,
    LifecycleManager,
    LifecycleState,
    PolicyEvaluator,
    PolicyRule,
    TrustedReceiptVerifier,
    hash_machine_state,
)


NOW = datetime(2030, 1, 1, tzinfo=UTC)
STATE = {"review_status": "approved"}
TRANSITIONS = {
    "draft": {"approved"},
    "approved": {"archived"},
    "archived": set(),
}


def _rules() -> list[PolicyRule]:
    protected = LifecycleManager.transition_action("draft", "approved")
    automatic = LifecycleManager.transition_action("approved", "archived")
    return [
        PolicyRule(protected, STATE),
        PolicyRule(automatic, {}, authorization_required=False),
    ]


def _evaluator(
    verifier: TrustedReceiptVerifier | None = None,
) -> PolicyEvaluator:
    return PolicyEvaluator(
        policy_id="synthetic-lifecycle-policy",
        known_state_fields=STATE,
        rules=_rules(),
        authorization_verifier=verifier,
    )


def _manager(evaluator: PolicyEvaluator) -> LifecycleManager:
    return LifecycleManager(transitions=TRANSITIONS, evaluator=evaluator)


def _receipt(
    workflow: LifecycleState, evaluator: PolicyEvaluator
) -> AuthorizationReceipt:
    return AuthorizationReceipt(
        receipt_id="receipt-001",
        actor="reviewer@example.invalid",
        action=LifecycleManager.transition_action("draft", "approved"),
        scope=workflow.workflow_id,
        policy_sha256=evaluator.policy_sha256,
        state_sha256=hash_machine_state(STATE),
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )


def test_lifecycle_rejects_invalid_and_unauthorized_transition() -> None:
    manager = _manager(_evaluator())
    workflow = LifecycleState("study-001", "draft")

    with pytest.raises(LifecycleError, match="invalid_transition"):
        manager.advance(workflow, "archived", machine_state=STATE, at=NOW)
    with pytest.raises(LifecycleError, match="authorization_missing"):
        manager.advance(workflow, "approved", machine_state=STATE, at=NOW)


def test_lifecycle_rejects_forged_receipt_then_freezes_terminal_state() -> None:
    workflow = LifecycleState("study-001", "draft")
    policy_definition = _evaluator()
    receipt = _receipt(workflow, policy_definition)
    manager = _manager(
        _evaluator(TrustedReceiptVerifier([receipt.receipt_sha256]))
    )

    forged = replace(receipt, actor="caller@example.invalid")
    with pytest.raises(LifecycleError, match="authorization_receipt_untrusted"):
        manager.advance(
            workflow,
            "approved",
            machine_state=STATE,
            receipt=forged,
            at=NOW,
        )

    approved = manager.advance(
        workflow,
        "approved",
        machine_state=STATE,
        receipt=receipt,
        at=NOW,
    )
    archived = manager.advance(
        approved,
        "archived",
        machine_state=STATE,
        at=NOW,
    )

    assert approved.stage == "approved"
    assert archived.stage == "archived"
    assert archived.frozen is True
    with pytest.raises(LifecycleError, match="workflow_frozen"):
        manager.advance(archived, "approved", machine_state=STATE, at=NOW)
