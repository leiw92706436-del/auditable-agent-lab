from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Iterable, Mapping

from ..evidence.canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    sha256_json,
)
from .authorization import (
    AuthorizationError,
    AuthorizationReceipt,
    AuthorizationVerifier,
    hash_machine_state,
)


JSONScalar = str | int | bool | None


class PolicyError(ValueError):
    """Raised when policy configuration is invalid."""


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{field} must be non-empty text")
    return value.strip()


def _is_json_scalar(value: object) -> bool:
    if value is not None and not isinstance(value, (str, bool, int)):
        return False
    try:
        canonical_json_bytes(value)
    except CanonicalizationError:
        return False
    return True


@dataclass(frozen=True)
class PolicyRule:
    action: str
    required_state: Mapping[str, JSONScalar]
    authorization_required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _required_text(self.action, "action"))
        if not isinstance(self.required_state, Mapping):
            raise PolicyError("required_state must be a mapping")
        normalized: dict[str, JSONScalar] = {}
        for field, value in self.required_state.items():
            key = _required_text(field, "required_state field")
            if not _is_json_scalar(value):
                raise PolicyError(
                    "required_state values must be canonical JSON v1 scalars"
                )
            normalized[key] = value
        if not isinstance(self.authorization_required, bool):
            raise PolicyError("authorization_required must be boolean")
        object.__setattr__(self, "required_state", MappingProxyType(normalized))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> PolicyRule:
        expected = {"action", "required_state", "authorization_required"}
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise PolicyError("policy rule fields must match schema version 1")
        return cls(
            action=payload["action"],  # type: ignore[arg-type]
            required_state=payload["required_state"],  # type: ignore[arg-type]
            authorization_required=payload[
                "authorization_required"
            ],  # type: ignore[arg-type]
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "required_state": dict(self.required_state),
            "authorization_required": self.authorization_required,
        }


@dataclass(frozen=True)
class PolicyDecision:
    action: str
    scope: str
    policy_id: str
    policy_sha256: str
    allowed: bool
    reason_code: str
    receipt_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "scope": self.scope,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "receipt_id": self.receipt_id,
        }


class PolicyEvaluator:
    def __init__(
        self,
        *,
        policy_id: str,
        rules: Iterable[PolicyRule],
        known_state_fields: Iterable[str],
        authorization_verifier: AuthorizationVerifier | None = None,
    ) -> None:
        self._policy_id = _required_text(policy_id, "policy_id")
        if isinstance(known_state_fields, (str, bytes)):
            raise PolicyError("known_state_fields must be an iterable of text")
        fields = frozenset(
            _required_text(field, "known_state_field")
            for field in known_state_fields
        )
        if isinstance(rules, (str, bytes)):
            raise PolicyError("rules must be an iterable of PolicyRule instances")
        indexed: dict[str, PolicyRule] = {}
        for rule in rules:
            if not isinstance(rule, PolicyRule):
                raise PolicyError("rules must contain PolicyRule instances")
            if rule.action in indexed:
                raise PolicyError(f"duplicate policy action: {rule.action}")
            unknown_requirements = set(rule.required_state) - fields
            if unknown_requirements:
                raise PolicyError(
                    "rule references unknown state fields: "
                    f"{sorted(unknown_requirements)}"
                )
            indexed[rule.action] = rule
        if authorization_verifier is not None and not isinstance(
            authorization_verifier, AuthorizationVerifier
        ):
            raise PolicyError(
                "authorization_verifier must implement AuthorizationVerifier"
            )
        self._rules = MappingProxyType(indexed)
        self._known_state_fields = fields
        self._authorization_verifier = authorization_verifier
        self._policy_sha256 = sha256_json(
            {
                "schema_version": 1,
                "policy_id": self._policy_id,
                "known_state_fields": sorted(fields),
                "rules": [indexed[action].to_dict() for action in sorted(indexed)],
            }
        )

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def policy_sha256(self) -> str:
        return self._policy_sha256

    @property
    def known_actions(self) -> frozenset[str]:
        return frozenset(self._rules)

    def _decision(
        self,
        action: str,
        scope: str,
        allowed: bool,
        reason_code: str,
        receipt_id: str | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            action=action,
            scope=scope,
            policy_id=self._policy_id,
            policy_sha256=self._policy_sha256,
            allowed=allowed,
            reason_code=reason_code,
            receipt_id=receipt_id,
        )

    def evaluate(
        self,
        *,
        state: Mapping[str, object],
        action: str,
        scope: str,
        receipt: AuthorizationReceipt | None = None,
        at: datetime | None = None,
    ) -> PolicyDecision:
        try:
            requested_action = _required_text(action, "action")
            requested_scope = _required_text(scope, "scope")
        except PolicyError:
            return self._decision(
                str(action), str(scope), False, "invalid_request"
            )
        if not isinstance(state, Mapping) or any(
            not isinstance(field, str) or not field.strip() for field in state
        ):
            return self._decision(
                requested_action, requested_scope, False, "invalid_state"
            )
        unknown_fields = set(state) - self._known_state_fields
        if unknown_fields:
            return self._decision(
                requested_action,
                requested_scope,
                False,
                "unknown_state_field",
            )
        try:
            hash_machine_state(state)
        except AuthorizationError:
            return self._decision(
                requested_action, requested_scope, False, "invalid_state"
            )
        rule = self._rules.get(requested_action)
        if rule is None:
            return self._decision(
                requested_action, requested_scope, False, "unknown_action"
            )
        for field, expected in rule.required_state.items():
            if field not in state:
                return self._decision(
                    requested_action,
                    requested_scope,
                    False,
                    "missing_state_field",
                )
            actual = state[field]
            if type(actual) is not type(expected) or actual != expected:
                return self._decision(
                    requested_action,
                    requested_scope,
                    False,
                    "state_requirement_not_met",
                )
        if not rule.authorization_required:
            return self._decision(
                requested_action, requested_scope, True, "allowed_by_policy"
            )
        if receipt is None:
            return self._decision(
                requested_action,
                requested_scope,
                False,
                "authorization_missing",
            )
        if not isinstance(receipt, AuthorizationReceipt):
            return self._decision(
                requested_action,
                requested_scope,
                False,
                "authorization_invalid",
            )
        if self._authorization_verifier is None:
            return self._decision(
                requested_action,
                requested_scope,
                False,
                "authorization_verifier_missing",
                receipt.receipt_id,
            )
        verification = self._authorization_verifier.verify_authorization(
            receipt=receipt,
            state=state,
            action=requested_action,
            scope=requested_scope,
            policy_sha256=self._policy_sha256,
            at=at,
        )
        if not verification.valid:
            return self._decision(
                requested_action,
                requested_scope,
                False,
                f"authorization_{verification.reason_code}",
                receipt.receipt_id,
            )
        return self._decision(
            requested_action,
            requested_scope,
            True,
            "allowed_with_trusted_authorization",
            receipt.receipt_id,
        )
