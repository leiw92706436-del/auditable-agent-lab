from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from .canonical import (
    CanonicalizationError,
    sha256_file,
    sha256_json,
    strict_json_loads,
)


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    """Raised when evidence structure or paths are invalid."""


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{field} must be non-empty text")
    return value.strip()


def _sha256_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise EvidenceError(f"{field} must be lowercase SHA-256 text")
    return value


def _utc_datetime(value: object, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceError(f"{field} must be ISO-8601 text") from exc
    else:
        raise EvidenceError(f"{field} must be a datetime or ISO-8601 text")
    if parsed.tzinfo is None:
        raise EvidenceError(f"{field} must be timezone-aware")
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _normalize_relative_path(value: object) -> str:
    path_text = _required_text(value, "artifact path")
    if "\\" in path_text:
        raise EvidenceError("artifact path must use POSIX separators")
    relative = PurePosixPath(path_text)
    normalized = relative.as_posix()
    if relative.is_absolute() or ".." in relative.parts or normalized in {"", "."}:
        raise EvidenceError("artifact path must stay below the artifact root")
    if normalized != path_text:
        raise EvidenceError("artifact path must be canonical relative text")
    return normalized


def _resolve_artifact(root: Path, relative_path: str) -> Path:
    resolved_root = root.resolve()
    candidate = (resolved_root / Path(*PurePosixPath(relative_path).parts)).resolve()
    try:
        candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise EvidenceError("artifact path escapes the artifact root") from exc
    return candidate


@dataclass(frozen=True)
class ArtifactEvidence:
    path: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _normalize_relative_path(self.path))
        object.__setattr__(self, "sha256", _sha256_text(self.sha256, "sha256"))
        if (
            not isinstance(self.size_bytes, int)
            or isinstance(self.size_bytes, bool)
            or self.size_bytes < 0
        ):
            raise EvidenceError("size_bytes must be a non-negative integer")

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class EvidenceManifest:
    manifest_id: str
    producer_label: str
    created_at: datetime
    artifacts: tuple[ArtifactEvidence, ...]
    manifest_sha256: str
    previous_manifest_sha256: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "manifest_id", _required_text(self.manifest_id, "manifest_id")
        )
        object.__setattr__(
            self,
            "producer_label",
            _required_text(self.producer_label, "producer_label"),
        )
        object.__setattr__(
            self, "created_at", _utc_datetime(self.created_at, "created_at")
        )
        if (
            not isinstance(self.schema_version, int)
            or isinstance(self.schema_version, bool)
            or self.schema_version != 1
        ):
            raise EvidenceError("schema_version must be 1")
        if not isinstance(self.artifacts, tuple) or not self.artifacts:
            raise EvidenceError("artifacts must be a non-empty tuple")
        if any(not isinstance(item, ArtifactEvidence) for item in self.artifacts):
            raise EvidenceError("artifacts must contain ArtifactEvidence values")
        paths = tuple(item.path for item in self.artifacts)
        if len(set(paths)) != len(paths):
            raise EvidenceError("artifact paths must be unique")
        if paths != tuple(sorted(paths)):
            raise EvidenceError("artifact paths must be sorted")
        object.__setattr__(
            self,
            "manifest_sha256",
            _sha256_text(self.manifest_sha256, "manifest_sha256"),
        )
        if self.previous_manifest_sha256 is not None:
            object.__setattr__(
                self,
                "previous_manifest_sha256",
                _sha256_text(
                    self.previous_manifest_sha256, "previous_manifest_sha256"
                ),
            )

    @classmethod
    def build(
        cls,
        *,
        artifact_root: str | Path,
        artifact_paths: Iterable[str],
        manifest_id: str,
        producer_label: str,
        created_at: datetime | None = None,
        previous_manifest_sha256: str | None = None,
    ) -> EvidenceManifest:
        root = Path(artifact_root)
        if not root.is_dir():
            raise EvidenceError("artifact_root must be an existing directory")
        normalized_paths = tuple(
            sorted(_normalize_relative_path(path) for path in artifact_paths)
        )
        if not normalized_paths:
            raise EvidenceError("at least one artifact path is required")
        if len(set(normalized_paths)) != len(normalized_paths):
            raise EvidenceError("artifact paths must be unique")
        records: list[ArtifactEvidence] = []
        for relative_path in normalized_paths:
            artifact = _resolve_artifact(root, relative_path)
            if not artifact.is_file():
                raise EvidenceError(f"artifact does not exist: {relative_path}")
            records.append(
                ArtifactEvidence(
                    path=relative_path,
                    sha256=sha256_file(artifact),
                    size_bytes=artifact.stat().st_size,
                )
            )
        normalized_created_at = _utc_datetime(
            created_at or datetime.now(UTC), "created_at"
        )
        content = cls._content_dict(
            schema_version=1,
            manifest_id=_required_text(manifest_id, "manifest_id"),
            producer_label=_required_text(producer_label, "producer_label"),
            created_at=normalized_created_at,
            artifacts=tuple(records),
            previous_manifest_sha256=previous_manifest_sha256,
        )
        return cls(
            manifest_id=manifest_id,
            producer_label=producer_label,
            created_at=normalized_created_at,
            artifacts=tuple(records),
            previous_manifest_sha256=previous_manifest_sha256,
            manifest_sha256=sha256_json(content),
        )

    @staticmethod
    def _content_dict(
        *,
        schema_version: int,
        manifest_id: str,
        producer_label: str,
        created_at: datetime,
        artifacts: tuple[ArtifactEvidence, ...],
        previous_manifest_sha256: str | None,
    ) -> dict[str, object]:
        return {
            "schema_version": schema_version,
            "manifest_id": manifest_id,
            "producer_label": producer_label,
            "created_at": _timestamp_text(created_at),
            "previous_manifest_sha256": previous_manifest_sha256,
            "artifacts": [item.to_dict() for item in artifacts],
        }

    def content_dict(self) -> dict[str, object]:
        return self._content_dict(
            schema_version=self.schema_version,
            manifest_id=self.manifest_id,
            producer_label=self.producer_label,
            created_at=self.created_at,
            artifacts=self.artifacts,
            previous_manifest_sha256=self.previous_manifest_sha256,
        )

    def to_dict(self) -> dict[str, object]:
        return {**self.content_dict(), "manifest_sha256": self.manifest_sha256}

    def write(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("x", encoding="utf-8") as handle:
            json.dump(
                self.to_dict(),
                handle,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            handle.write("\n")

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> EvidenceManifest:
        expected = {
            "schema_version",
            "manifest_id",
            "producer_label",
            "created_at",
            "previous_manifest_sha256",
            "artifacts",
            "manifest_sha256",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected:
            raise EvidenceError("manifest fields must match schema version 1")
        raw_artifacts = payload["artifacts"]
        if not isinstance(raw_artifacts, list):
            raise EvidenceError("artifacts must be a list")
        artifacts: list[ArtifactEvidence] = []
        for item in raw_artifacts:
            if not isinstance(item, Mapping) or set(item) != {
                "path",
                "sha256",
                "size_bytes",
            }:
                raise EvidenceError("artifact fields must match schema version 1")
            artifacts.append(
                ArtifactEvidence(
                    path=item["path"],  # type: ignore[arg-type]
                    sha256=item["sha256"],  # type: ignore[arg-type]
                    size_bytes=item["size_bytes"],  # type: ignore[arg-type]
                )
            )
        return cls(
            schema_version=payload["schema_version"],  # type: ignore[arg-type]
            manifest_id=payload["manifest_id"],  # type: ignore[arg-type]
            producer_label=payload["producer_label"],  # type: ignore[arg-type]
            created_at=_utc_datetime(payload["created_at"], "created_at"),
            previous_manifest_sha256=payload[
                "previous_manifest_sha256"
            ],  # type: ignore[arg-type]
            artifacts=tuple(artifacts),
            manifest_sha256=payload["manifest_sha256"],  # type: ignore[arg-type]
        )

    @classmethod
    def from_json_file(cls, path: str | Path) -> EvidenceManifest:
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise EvidenceError("manifest file could not be read") from exc
        try:
            payload = strict_json_loads(text)
        except CanonicalizationError as exc:
            raise EvidenceError("manifest file violates canonical JSON v1") from exc
        if not isinstance(payload, Mapping):
            raise EvidenceError("manifest root must be a mapping")
        return cls.from_dict(payload)
