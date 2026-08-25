from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from auditable_agent_lab import (
    AuthorizationReceipt,
    PolicyError,
    PolicyEvaluator,
    PolicyRule,
    TrustedReceiptVerifier,
    hash_machine_state,
)


NOW = datetime(2030, 1, 1, tzinfo=UTC)
STATE = {"review_status": "approved", "evidence_complete": True}
POLICY_ID = "synthetic-publication-policy"


def _rules() -> list[PolicyRule]:
    return [
        PolicyRule(
            action="publish.summary",
            required_state=STATE,
        ),
        PolicyRule(
            action="archive.summary",
            required_state={"evidence_complete": True},
            authorization_required=False,
        ),
    ]


def _evaluator(
    verifier: TrustedReceiptVerifier | None = None,
    *,
    rules: list[PolicyRule] | None = None,
) -> PolicyEvaluator:
    return PolicyEvaluator(
        policy_id=POLICY_ID,
        known_state_fields=["review_status", "evidence_complete"],
        rules=rules or _rules(),
        authorization_verifier=verifier,
    )


def _receipt(evaluator: PolicyEvaluator, **changes: object) -> AuthorizationReceipt:
    values: dict[str, object] = {
        "receipt_id": "receipt-001",
        "actor": "reviewer@example.invalid",
        "action": "publish.summary",
        "scope": "study-001",
        "policy_sha256": evaluator.policy_sha256,
        "state_sha256": hash_machine_state(STATE),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return AuthorizationReceipt(**values)  # type: ignore[arg-type]


def test_policy_hash_is_stable_across_input_order() -> None:
    first = _evaluator()
    second = PolicyEvaluator(
        policy_id=POLICY_ID,
        known_state_fields=["evidence_complete", "review_status"],
        rules=list(reversed(_rules())),
    )

    assert first.policy_sha256 == second.policy_sha256


def test_policy_fails_closed_for_unknown_action_field_and_missing_receipt() -> None:
    evaluator = _evaluator()

    assert evaluator.evaluate(
        state=STATE, action="unknown", scope="study-001"
    ).reason_code == "unknown_action"
    assert evaluator.evaluate(
        state={**STATE, "extra": True},
        action="publish.summary",
        scope="study-001",
    ).reason_code == "unknown_state_field"
    assert evaluator.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
    ).reason_code == "authorization_missing"


def test_policy_rejects_non_json_state_and_invalid_receipt_object() -> None:
    evaluator = _evaluator()

    assert evaluator.evaluate(
        state={"review_status": object(), "evidence_complete": True},
        action="publish.summary",
        scope="study-001",
    ).reason_code == "invalid_state"
    assert evaluator.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        receipt=object(),  # type: ignore[arg-type]
    ).reason_code == "authorization_invalid"
    with pytest.raises(PolicyError, match="canonical JSON v1 scalars"):
        PolicyRule("publish.detail", {"threshold": 1.5})


def test_protected_action_denies_receipt_without_trusted_verifier() -> None:
    evaluator = _evaluator()
    receipt = _receipt(evaluator)

    decision = evaluator.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        receipt=receipt,
        at=NOW,
    )

    assert decision.allowed is False
    assert decision.reason_code == "authorization_verifier_missing"


def test_policy_allows_only_trusted_policy_bound_receipt_once() -> None:
    policy_definition = _evaluator()
    receipt = _receipt(policy_definition)
    evaluator = _evaluator(TrustedReceiptVerifier([receipt.receipt_sha256]))

    decision = evaluator.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        receipt=receipt,
        at=NOW,
    )
    replay = evaluator.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        receipt=receipt,
        at=NOW,
    )

    assert decision.allowed is True
    assert decision.reason_code == "allowed_with_trusted_authorization"
    assert decision.policy_sha256 == policy_definition.policy_sha256
    assert replay.allowed is False
    assert replay.reason_code == "authorization_receipt_replayed"


def test_policy_drift_invalidates_previously_trusted_receipt() -> None:
    original = _evaluator()
    receipt = _receipt(original, replay_policy="reusable")
    changed_rules = [
        *_rules(),
        PolicyRule(
            action="inspect.summary",
            required_state={},
            authorization_required=False,
        ),
    ]
    changed = _evaluator(
        TrustedReceiptVerifier([receipt.receipt_sha256]), rules=changed_rules
    )

    decision = changed.evaluate(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        receipt=receipt,
        at=NOW,
    )

    assert changed.policy_sha256 != original.policy_sha256
    assert decision.allowed is False
    assert decision.reason_code == "authorization_policy_mismatch"


def test_policy_can_allow_registered_non_authorized_action() -> None:
    decision = _evaluator().evaluate(
        state=STATE,
        action="archive.summary",
        scope="study-001",
    )

    assert decision.allowed is True
    assert decision.reason_code == "allowed_by_policy"
