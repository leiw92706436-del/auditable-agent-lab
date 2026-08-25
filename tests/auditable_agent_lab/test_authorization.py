from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from auditable_agent_lab import (
    AuthorizationError,
    AuthorizationReceipt,
    AuthorizationVerifier,
    TrustedReceiptVerifier,
    hash_machine_state,
)


NOW = datetime(2030, 1, 1, tzinfo=UTC)
STATE = {"review_status": "approved"}
POLICY_SHA256 = "a" * 64


def _receipt(**changes: object) -> AuthorizationReceipt:
    values: dict[str, object] = {
        "receipt_id": "receipt-001",
        "actor": "reviewer@example.invalid",
        "action": "publish.summary",
        "scope": "study-001",
        "policy_sha256": POLICY_SHA256,
        "state_sha256": hash_machine_state(STATE),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return AuthorizationReceipt(**values)  # type: ignore[arg-type]


def test_receipt_claims_bind_policy_action_scope_state_and_time() -> None:
    receipt = _receipt()

    assert receipt.validate_claims(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    ).valid
    assert receipt.validate_claims(
        state=STATE,
        action="publish.detail",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    ).reason_code == "action_mismatch"
    assert receipt.validate_claims(
        state=STATE,
        action="publish.summary",
        scope="study-002",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    ).reason_code == "scope_mismatch"
    assert receipt.validate_claims(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256="b" * 64,
        at=NOW,
    ).reason_code == "policy_mismatch"
    assert receipt.validate_claims(
        state={"review_status": "pending"},
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    ).reason_code == "state_mismatch"
    assert receipt.validate_claims(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW - timedelta(seconds=1),
    ).reason_code == "receipt_not_yet_valid"
    assert receipt.validate_claims(
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW + timedelta(hours=1),
    ).reason_code == "receipt_expired"


def test_receipt_rejects_invalid_time_schema_and_replay_policy() -> None:
    with pytest.raises(AuthorizationError, match="timezone-aware"):
        _receipt(issued_at=datetime(2030, 1, 1))
    with pytest.raises(AuthorizationError, match="replay_policy"):
        _receipt(replay_policy="undefined")

    receipt = _receipt()
    payload = receipt.to_dict()
    assert AuthorizationReceipt.from_dict(payload) == receipt
    payload["unexpected"] = True
    with pytest.raises(AuthorizationError, match="fields"):
        AuthorizationReceipt.from_dict(payload)


def test_trusted_verifier_rejects_caller_created_or_modified_receipt() -> None:
    receipt = _receipt()
    verifier = TrustedReceiptVerifier([])

    assert isinstance(verifier, AuthorizationVerifier)
    result = verifier.verify_authorization(
        receipt=receipt,
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    )
    assert result.valid is False
    assert result.reason_code == "receipt_untrusted"

    trusted = TrustedReceiptVerifier([receipt.receipt_sha256])
    changed_actor = replace(receipt, actor="caller@example.invalid")
    assert changed_actor.receipt_sha256 != receipt.receipt_sha256
    changed = trusted.verify_authorization(
        receipt=changed_actor,
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    )
    assert changed.valid is False
    assert changed.reason_code == "receipt_untrusted"


def test_one_shot_receipt_is_consumed_atomically() -> None:
    receipt = _receipt()
    verifier = TrustedReceiptVerifier([receipt.receipt_sha256])

    first = verifier.verify_authorization(
        receipt=receipt,
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    )
    replay = verifier.verify_authorization(
        receipt=receipt,
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    )

    assert first.valid is True
    assert replay.valid is False
    assert replay.reason_code == "receipt_replayed"
    assert verifier.consumed_receipt_sha256s == {receipt.receipt_sha256}


def test_reusable_receipt_has_explicit_replay_contract() -> None:
    receipt = _receipt(replay_policy="reusable")
    verifier = TrustedReceiptVerifier([receipt.receipt_sha256])

    results = [
        verifier.verify_authorization(
            receipt=receipt,
            state=STATE,
            action="publish.summary",
            scope="study-001",
            policy_sha256=POLICY_SHA256,
            at=NOW,
        )
        for _ in range(2)
    ]

    assert all(result.valid for result in results)
    assert verifier.consumed_receipt_sha256s == frozenset()


def test_deny_receipt_never_authorizes() -> None:
    receipt = _receipt(decision="deny")
    verifier = TrustedReceiptVerifier([receipt.receipt_sha256])
    result = verifier.verify_authorization(
        receipt=receipt,
        state=STATE,
        action="publish.summary",
        scope="study-001",
        policy_sha256=POLICY_SHA256,
        at=NOW,
    )

    assert result.valid is False
    assert result.reason_code == "receipt_denied"
    assert verifier.consumed_receipt_sha256s == frozenset()
