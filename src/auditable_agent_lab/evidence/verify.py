from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .canonical import sha256_file, sha256_json
from .manifest import (
    EvidenceError,
    EvidenceManifest,
    _normalize_relative_path,
    _resolve_artifact,
    _sha256_text,
)


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason_codes: tuple[str, ...]
    missing_artifacts: tuple[str, ...] = ()
    unexpected_artifacts: tuple[str, ...] = ()
    hash_mismatches: tuple[str, ...] = ()
    size_mismatches: tuple[str, ...] = ()
    unreadable_artifacts: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason_codes": list(self.reason_codes),
            "missing_artifacts": list(self.missing_artifacts),
            "unexpected_artifacts": list(self.unexpected_artifacts),
            "hash_mismatches": list(self.hash_mismatches),
            "size_mismatches": list(self.size_mismatches),
            "unreadable_artifacts": list(self.unreadable_artifacts),
        }


class Verifier:
    """Verify artifacts against an out-of-band manifest anchor and full set."""

    def verify(
        self,
        *,
        manifest: EvidenceManifest,
        artifact_root: str | Path,
        expected_manifest_sha256: str,
        expected_artifacts: Iterable[str],
        expected_previous_manifest_sha256: str | None = None,
    ) -> VerificationResult:
        if not isinstance(manifest, EvidenceManifest):
            raise EvidenceError("manifest must be an EvidenceManifest")
        root = Path(artifact_root)
        reasons: list[str] = []
        missing: list[str] = []
        unexpected: list[str] = []
        hash_mismatches: list[str] = []
        size_mismatches: list[str] = []
        unreadable: list[str] = []

        trusted_manifest_sha256 = _sha256_text(
            expected_manifest_sha256, "expected_manifest_sha256"
        )
        if manifest.manifest_sha256 != trusted_manifest_sha256:
            reasons.append("manifest_anchor_mismatch")
        if sha256_json(manifest.content_dict()) != manifest.manifest_sha256:
            reasons.append("manifest_hash_mismatch")
        if expected_previous_manifest_sha256 is not None:
            trusted_previous_sha256 = _sha256_text(
                expected_previous_manifest_sha256,
                "expected_previous_manifest_sha256",
            )
            if manifest.previous_manifest_sha256 != trusted_previous_sha256:
                reasons.append("previous_manifest_mismatch")

        manifest_paths = {item.path for item in manifest.artifacts}
        if expected_artifacts is None or isinstance(expected_artifacts, (str, bytes)):
            raise EvidenceError("expected_artifacts must be an explicit iterable")
        normalized_expected = [
            _normalize_relative_path(path) for path in expected_artifacts
        ]
        if len(set(normalized_expected)) != len(normalized_expected):
            raise EvidenceError("expected artifact paths must be unique")
        expected_paths = set(normalized_expected)
        missing.extend(sorted(expected_paths - manifest_paths))
        unexpected.extend(sorted(manifest_paths - expected_paths))
        if missing or unexpected:
            reasons.append("artifact_set_mismatch")

        for record in manifest.artifacts:
            artifact = _resolve_artifact(root, record.path)
            if not artifact.is_file():
                missing.append(record.path)
                continue
            try:
                actual_size = artifact.stat().st_size
                actual_sha256 = sha256_file(artifact)
            except OSError:
                unreadable.append(record.path)
                continue
            if actual_size != record.size_bytes:
                size_mismatches.append(record.path)
            if actual_sha256 != record.sha256:
                hash_mismatches.append(record.path)

        if missing and "artifact_missing" not in reasons:
            reasons.append("artifact_missing")
        if unreadable:
            reasons.append("artifact_unreadable")
        if size_mismatches:
            reasons.append("artifact_size_mismatch")
        if hash_mismatches:
            reasons.append("artifact_hash_mismatch")
        unique_reasons = tuple(dict.fromkeys(reasons))
        return VerificationResult(
            valid=not unique_reasons,
            reason_codes=unique_reasons,
            missing_artifacts=tuple(sorted(set(missing))),
            unexpected_artifacts=tuple(unexpected),
            hash_mismatches=tuple(hash_mismatches),
            size_mismatches=tuple(size_mismatches),
            unreadable_artifacts=tuple(unreadable),
        )

    def verify_file(
        self,
        *,
        manifest_path: str | Path,
        artifact_root: str | Path,
        expected_manifest_sha256: str,
        expected_artifacts: Iterable[str],
        expected_previous_manifest_sha256: str | None = None,
    ) -> VerificationResult:
        return self.verify(
            manifest=EvidenceManifest.from_json_file(manifest_path),
            artifact_root=artifact_root,
            expected_manifest_sha256=expected_manifest_sha256,
            expected_artifacts=expected_artifacts,
            expected_previous_manifest_sha256=expected_previous_manifest_sha256,
        )
