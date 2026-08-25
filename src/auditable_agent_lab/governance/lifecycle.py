from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from types import MappingProxyType
from typing import Iterable, Mapping

from .authorization import AuthorizationReceipt
from .policy import PolicyEvaluator


class LifecycleError(ValueError):
    """Raised when a lifecycle transition is invalid or denied."""


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LifecycleError(f"{field} must be non-empty text")
    return value.strip()


@dataclass(frozen=True)
class LifecycleState:
    workflow_id: str
    stage: str
    frozen: bool = False
    last_transition: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "workflow_id", _required_text(self.workflow_id, "workflow_id")
        )
        object.__setattr__(self, "stage", _required_text(self.stage, "stage"))
        if not isinstance(self.frozen, bool):
            raise LifecycleError("frozen must be boolean")
        if self.last_transition is not None:
            object.__setattr__(
                self,
                "last_transition",
                _required_text(self.last_transition, "last_transition"),
            )


class LifecycleManager:
    def __init__(
        self,
        *,
        transitions: Mapping[str, Iterable[str]],
        evaluator: PolicyEvaluator,
    ) -> None:
        if not isinstance(transitions, Mapping) or not transitions:
            raise LifecycleError("transitions must be a non-empty mapping")
        normalized: dict[str, frozenset[str]] = {}
        for source, targets in transitions.items():
            source_name = _required_text(source, "transition source")
            normalized[source_name] = frozenset(
                _required_text(target, "transition target") for target in targets
            )
        missing_stages = set().union(*normalized.values()) - set(normalized)
        if missing_stages:
            raise LifecycleError(
                f"transition targets must declare their own stage: {sorted(missing_stages)}"
            )
        required_actions = {
            self.transition_action(source, target)
            for source, targets in normalized.items()
            for target in targets
        }
        missing_actions = required_actions - evaluator.known_actions
        if missing_actions:
            raise LifecycleError(
                f"transitions missing policy rules: {sorted(missing_actions)}"
            )
        self._transitions = MappingProxyType(normalized)
        self._evaluator = evaluator

    @staticmethod
    def transition_action(source: str, target: str) -> str:
        return f"lifecycle.transition.{source}.{target}"

    def advance(
        self,
        workflow: LifecycleState,
        target: str,
        *,
        machine_state: Mapping[str, object],
        receipt: AuthorizationReceipt | None = None,
        at: datetime | None = None,
    ) -> LifecycleState:
        if not isinstance(workflow, LifecycleState):
            raise LifecycleError("workflow must be a LifecycleState")
        if workflow.frozen:
            raise LifecycleError("workflow_frozen")
        if workflow.stage not in self._transitions:
            raise LifecycleError("unknown_current_stage")
        target_stage = _required_text(target, "target")
        if target_stage not in self._transitions[workflow.stage]:
            raise LifecycleError("invalid_transition")
        action = self.transition_action(workflow.stage, target_stage)
        decision = self._evaluator.evaluate(
            state=machine_state,
            action=action,
            scope=workflow.workflow_id,
            receipt=receipt,
            at=at,
        )
        if not decision.allowed:
            raise LifecycleError(decision.reason_code)
        is_terminal = not self._transitions[target_stage]
        return replace(
            workflow,
            stage=target_stage,
            frozen=is_terminal,
            last_transition=f"{workflow.stage}->{target_stage}",
        )
