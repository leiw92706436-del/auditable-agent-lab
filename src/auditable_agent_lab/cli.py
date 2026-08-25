from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

from .evidence import (
    CanonicalizationError,
    EvidenceError,
    EvidenceManifest,
    Verifier,
    strict_json_loads,
)
from .governance import (
    AuthorizationError,
    AuthorizationReceipt,
    PolicyError,
    PolicyEvaluator,
    PolicyRule,
    TrustedReceiptVerifier,
    parse_utc_datetime,
)


class CLIError(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _MachineReadableParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise CLIError("argument_error", message)


def _json_mapping(path: str | Path, label: str) -> Mapping[str, object]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise CLIError("io_error", f"{label} file could not be read") from exc
    try:
        payload = strict_json_loads(text)
    except CanonicalizationError as exc:
        raise CLIError("invalid_json", f"{label}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise CLIError("invalid_json_root", f"{label} root must be a mapping")
    return payload


def _policy_evaluator(
    payload: Mapping[str, object],
    *,
    authorization_verifier: TrustedReceiptVerifier | None = None,
) -> PolicyEvaluator:
    expected = {"schema_version", "policy_id", "known_state_fields", "rules"}
    if (
        set(payload) != expected
        or type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
    ):
        raise PolicyError("policy fields must match schema version 1")
    raw_fields = payload["known_state_fields"]
    raw_rules = payload["rules"]
    if not isinstance(raw_fields, list) or not isinstance(raw_rules, list):
        raise PolicyError("policy fields and rules must be lists")
    rules: list[PolicyRule] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, Mapping):
            raise PolicyError("policy rule must be a mapping")
        rules.append(PolicyRule.from_dict(raw_rule))
    return PolicyEvaluator(
        policy_id=payload["policy_id"],  # type: ignore[arg-type]
        rules=rules,
        known_state_fields=raw_fields,
        authorization_verifier=authorization_verifier,
    )


def _envelope(
    *,
    command: str | None,
    status: str,
    result: Mapping[str, object] | None = None,
    error: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "command": command,
        "status": status,
        "result": dict(result) if result is not None else None,
        "error": dict(error) if error is not None else None,
    }


def _print_envelope(payload: Mapping[str, object]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def _action_check(args: argparse.Namespace) -> int:
    state = _json_mapping(args.state, "state")
    try:
        verifier = (
            TrustedReceiptVerifier(args.trusted_receipt_sha256)
            if args.trusted_receipt_sha256
            else None
        )
    except AuthorizationError as exc:
        raise CLIError("invalid_trust_anchor", str(exc)) from exc
    try:
        evaluator = _policy_evaluator(
            _json_mapping(args.policy, "policy"),
            authorization_verifier=verifier,
        )
    except PolicyError as exc:
        raise CLIError("invalid_policy", str(exc)) from exc
    receipt = None
    if args.receipt is not None:
        try:
            receipt = AuthorizationReceipt.from_dict(
                _json_mapping(args.receipt, "receipt")
            )
        except AuthorizationError as exc:
            raise CLIError("invalid_receipt", str(exc)) from exc
    evaluated_at = None
    if args.at is not None:
        try:
            evaluated_at = parse_utc_datetime(args.at, "at")
        except AuthorizationError as exc:
            raise CLIError("invalid_evaluation_time", str(exc)) from exc
    decision = evaluator.evaluate(
        state=state,
        action=args.action,
        scope=args.scope,
        receipt=receipt,
        at=evaluated_at,
    )
    _print_envelope(
        _envelope(
            command="action-check",
            status="pass" if decision.allowed else "fail",
            result=decision.to_dict(),
        )
    )
    return 0 if decision.allowed else 1


def _evidence_verify(args: argparse.Namespace) -> int:
    try:
        manifest = EvidenceManifest.from_dict(
            _json_mapping(args.manifest, "manifest")
        )
        result = Verifier().verify(
            manifest=manifest,
            artifact_root=args.artifact_root,
            expected_manifest_sha256=args.expected_manifest_sha256,
            expected_artifacts=args.expect_artifact,
            expected_previous_manifest_sha256=(
                args.expected_previous_manifest_sha256
            ),
        )
    except EvidenceError as exc:
        raise CLIError("invalid_evidence_input", str(exc)) from exc
    _print_envelope(
        _envelope(
            command="evidence-verify",
            status="pass" if result.valid else "fail",
            result=result.to_dict(),
        )
    )
    return 0 if result.valid else 1


def build_parser() -> argparse.ArgumentParser:
    parser = _MachineReadableParser(
        prog="auditable-agent-lab",
        description="Fail-closed governance and evidence checks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    action = subparsers.add_parser(
        "action-check", help="Evaluate one action against state and policy JSON."
    )
    action.add_argument("--state", required=True)
    action.add_argument("--policy", required=True)
    action.add_argument("--action", required=True)
    action.add_argument("--scope", required=True)
    action.add_argument("--receipt")
    action.add_argument(
        "--trusted-receipt-sha256",
        action="append",
        help="Receipt digest approved outside the supervised agent.",
    )
    action.add_argument("--at")
    action.set_defaults(handler=_action_check)

    evidence = subparsers.add_parser(
        "evidence-verify", help="Verify artifacts against a trusted manifest digest."
    )
    evidence.add_argument("--manifest", required=True)
    evidence.add_argument("--artifact-root", required=True)
    evidence.add_argument(
        "--expected-manifest-sha256",
        required=True,
        help="Manifest digest retained outside the evidence bundle.",
    )
    evidence.add_argument(
        "--expect-artifact",
        action="append",
        required=True,
        help="One artifact required by the complete expected set; repeat as needed.",
    )
    evidence.add_argument("--expected-previous-manifest-sha256")
    evidence.set_defaults(handler=_evidence_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    raw_arguments = list(argv) if argv is not None else sys.argv[1:]
    command = (
        raw_arguments[0]
        if raw_arguments and not raw_arguments[0].startswith("-")
        else None
    )
    try:
        args = build_parser().parse_args(raw_arguments)
        command = args.command
        return args.handler(args)
    except CLIError as exc:
        reason_code = exc.reason_code
        message = str(exc)
    except AuthorizationError as exc:
        reason_code = "invalid_authorization_input"
        message = str(exc)
    except PolicyError as exc:
        reason_code = "invalid_policy"
        message = str(exc)
    except EvidenceError as exc:
        reason_code = "invalid_evidence_input"
        message = str(exc)
    except (CanonicalizationError, ValueError) as exc:
        reason_code = "invalid_input"
        message = str(exc)
    except OSError:
        reason_code = "io_error"
        message = "an input file could not be read"
    _print_envelope(
        _envelope(
            command=command,
            status="error",
            error={"reason_code": reason_code, "message": message},
        )
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
