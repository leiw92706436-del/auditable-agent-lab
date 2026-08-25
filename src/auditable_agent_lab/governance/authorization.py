from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Iterable, Mapping, Protocol, runtime_checkable

from ..evidence.canonical import CanonicalizationError, sha256_json


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class AuthorizationError(ValueError):
    """Raised when an authorization receipt is structurally invalid."""


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuthorizationError(f"{field} must be non-empty text")
    return value.strip()


def _sha256_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise AuthorizationError(f"{field} must be lowercase SHA-256 text")
    return value


def parse_utc_datetime(value: object, field: str = "timestamp") -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise AuthorizationError(f"{field} must be ISO-8601 text") from exc
    else:
        raise AuthorizationError(f"{field} must be a datetime or ISO-8601 text")
    if parsed.tzinfo is None:
        raise AuthorizationError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def hash_machine_state(state: Mapping[str, object]) -> str:
    if not isinstance(state, Mapping):
        raise AuthorizationError("machine state must be a mapping")
    try:
        return sha256_json(state)
    except CanonicalizationError as exc:
        raise AuthorizationError("machine state must be canonical JSON data") from exc


@dataclass(frozen=True)
class ReceiptVerification:
    valid: bool
    reason_code: str


@dataclass(frozen=True)
class AuthorizationReceipt:
    """A policy-bound authorization claim that requires a trusted verifier."""

    receipt_id: str
    actor: str
    action: str
    scope: str
    policy_sha256: str
    state_sha256: str
    issued_at: datetime
    expires_at: datetime
    replay_policy: str = "one_shot"
    decision: str = "allow"
    schema_version: int = 1

    def __post_init__(self) -> None:
        for field in ("receipt_id", "actor", "action", "scope"):
            object.__setattr__(self, field, _required_text(getattr(self, field), field))
        if not isinstance(self.schema_version, int) or isinstance(
            self.schema_version, bool
        ):
            raise AuthorizationError("schema_version must be an integer")
        if self.schema_version != 1:
            raise AuthorizationError("schema_version must be 1")
        if self.decision not in {"allow", "deny"}:
            raise AuthorizationError("decision must be allow or deny")
        if self.replay_policy not in {"one_shot", "reusable"}:
            raise AuthorizationError("replay_policy must be one_shot or reusable")
        object.__setattr__(
            self,
            "policy_sha256",
            _sha256_text(self.policy_sha256, "policy_sha256"),
        )
        object.__setattr__(
            self,
            "state_sha256",
            _sha256_text(self.state_sha256, "state_sha256"),
        )
        issued_at = parse_utc_datetime(self.issued_at, "issued_at")
        expires_at = parse_utc_datetime(self.expires_at, "expires_at")
        if expires_at <= issued_at:
            raise AuthorizationError("expires_at must be later than issued_at")
        object.__setattr__(self, "issued_at", issued_at)
        object.__setattr__(self, "expires_at", expires_at)

    @property
    def receipt_sha256(self) -> str:
        """Return the digest an external trust boundary must approve."""

        return sha256_json(self.to_dict())

    def validate_claims(
        self,
        *,
        state: Mapping[str, object],
        action: str,
        scope: str,
        policy_sha256: str,
        at: datetime | None = None,
    ) -> ReceiptVerification:
        """Validate bindings only; this method does not establish trust."""

        if self.decision != "allow":
            return ReceiptVerification(False, "receipt_denied")
        if self.action != action:
            return ReceiptVerification(False, "action_mismatch")
        if self.scope != scope:
            return ReceiptVerification(False, "scope_mismatch")
        if self.policy_sha256 != policy_sha256:
            return ReceiptVerification(False, "policy_mismatch")
        try:
            evaluated_at = parse_utc_datetime(at or datetime.now(UTC), "at")
        except AuthorizationError:
            return ReceiptVerification(False, "invalid_evaluation_time")
        if evaluated_at < self.issued_at:
            return ReceiptVerification(False, "receipt_not_yet_valid")
        if evaluated_at >= self.expires_at:
            return ReceiptVerification(False, "receipt_expired")
        try:
            current_state_sha256 = hash_machine_state(state)
        except AuthorizationError:
            return ReceiptVerification(False, "state_not_canonicalizable")
        if self.state_sha256 != current_state_sha256:
            return ReceiptVerification(False, "state_mismatch")
        return ReceiptVerification(True, "receipt_valid")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "actor": self.actor,
            "action": self.action,
            "scope": self.scope,
            "policy_sha256": self.policy_sha256,
            "state_sha256": self.state_sha256,
            "issued_at": _timestamp_text(self.issued_at),
            "expires_at": _timestamp_text(self.expires_at),
            "replay_policy": self.replay_policy,
            "decision": self.decision,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> AuthorizationReceipt:
        expected = {
            "schema_version",
            "receipt_id",
            "actor",
            "action",
            "scope",
            "policy_sha256",
            "state_sha256",
            "issued_at",
            "expires_at",
            "replay_policy",
            "decision",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise AuthorizationError("receipt fields must match schema version 1")
        return cls(
            schema_version=payload["schema_version"],  # type: ignore[arg-type]
            receipt_id=payload["receipt_id"],  # type: ignore[arg-type]
            actor=payload["actor"],  # type: ignore[arg-type]
            action=payload["action"],  # type: ignore[arg-type]
            scope=payload["scope"],  # type: ignore[arg-type]
            policy_sha256=payload["policy_sha256"],  # type: ignore[arg-type]
            state_sha256=payload["state_sha256"],  # type: ignore[arg-type]
            issued_at=parse_utc_datetime(payload["issued_at"], "issued_at"),
            expires_at=parse_utc_datetime(payload["expires_at"], "expires_at"),
            replay_policy=payload["replay_policy"],  # type: ignore[arg-type]
            decision=payload["decision"],  # type: ignore[arg-type]
        )


@runtime_checkable
class AuthorizationVerifier(Protocol):
    """Trust-boundary interface used by protected policy actions."""

    def verify_authorization(
        self,
        *,
        receipt: AuthorizationReceipt,
        state: Mapping[str, object],
        action: str,
        scope: str,
        policy_sha256: str,
        at: datetime | None = None,
    ) -> ReceiptVerification: ...


class TrustedReceiptVerifier:
    """Verify receipts against externally trusted digests.

    One-shot consumption is atomic within this verifier instance. Integrations
    that need durable or distributed replay protection should implement the
    ``AuthorizationVerifier`` protocol with their own trusted store.
    """

    def __init__(self, trusted_receipt_sha256s: Iterable[str]) -> None:
        if isinstance(trusted_receipt_sha256s, (str, bytes)):
            raise AuthorizationError("trusted receipt digests must be an iterable")
        try:
            trusted = frozenset(
                _sha256_text(value, "trusted receipt digest")
                for value in trusted_receipt_sha256s
            )
        except TypeError as exc:
            raise AuthorizationError(
                "trusted receipt digests must be an iterable"
            ) from exc
        self._trusted_receipt_sha256s = trusted
        self._consumed_receipt_sha256s: set[str] = set()
        self._lock = Lock()

    @property
    def consumed_receipt_sha256s(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._consumed_receipt_sha256s)

    def verify_authorization(
        self,
        *,
        receipt: AuthorizationReceipt,
        state: Mapping[str, object],
        action: str,
        scope: str,
        policy_sha256: str,
        at: datetime | None = None,
    ) -> ReceiptVerification:
        if not isinstance(receipt, AuthorizationReceipt):
            return ReceiptVerification(False, "receipt_invalid")
        claims = receipt.validate_claims(
            state=state,
            action=action,
            scope=scope,
            policy_sha256=policy_sha256,
            at=at,
        )
        if not claims.valid:
            return claims
        receipt_sha256 = receipt.receipt_sha256
        if receipt_sha256 not in self._trusted_receipt_sha256s:
            return ReceiptVerification(False, "receipt_untrusted")
        if receipt.replay_policy == "one_shot":
            with self._lock:
                if receipt_sha256 in self._consumed_receipt_sha256s:
                    return ReceiptVerification(False, "receipt_replayed")
                self._consumed_receipt_sha256s.add(receipt_sha256)
        return ReceiptVerification(True, "receipt_trusted")
