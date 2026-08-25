from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from auditable_agent_lab import EvidenceError, EvidenceManifest, Verifier


NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _manifest(tmp_path: Path) -> EvidenceManifest:
    (tmp_path / "result.json").write_text(
        '{"status":"complete"}\n', encoding="utf-8"
    )
    return EvidenceManifest.build(
        artifact_root=tmp_path,
        artifact_paths=["result.json"],
        manifest_id="manifest-001",
        producer_label="synthetic-producer",
        created_at=NOW,
    )


def test_manifest_verifies_against_anchor_and_detects_artifact_change(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    verifier = Verifier()

    valid = verifier.verify(
        manifest=manifest,
        artifact_root=tmp_path,
        expected_manifest_sha256=manifest.manifest_sha256,
        expected_artifacts=["result.json"],
    )
    assert valid.valid is True

    (tmp_path / "result.json").write_text("changed\n", encoding="utf-8")
    changed = verifier.verify(
        manifest=manifest,
        artifact_root=tmp_path,
        expected_manifest_sha256=manifest.manifest_sha256,
        expected_artifacts=["result.json"],
    )
    assert changed.valid is False
    assert "artifact_hash_mismatch" in changed.reason_codes
    assert "artifact_size_mismatch" in changed.reason_codes


def test_rewritten_manifest_and_omitted_artifact_fail_trusted_checks(
    tmp_path: Path,
) -> None:
    (tmp_path / "one.json").write_text("{}", encoding="utf-8")
    (tmp_path / "two.json").write_text("{}", encoding="utf-8")
    original = EvidenceManifest.build(
        artifact_root=tmp_path,
        artifact_paths=["one.json", "two.json"],
        manifest_id="manifest-001",
        producer_label="synthetic-producer",
        created_at=NOW,
    )
    rewritten = EvidenceManifest.build(
        artifact_root=tmp_path,
        artifact_paths=["one.json"],
        manifest_id="manifest-001",
        producer_label="rewritten-producer-label",
        created_at=NOW,
    )

    result = Verifier().verify(
        manifest=rewritten,
        artifact_root=tmp_path,
        expected_manifest_sha256=original.manifest_sha256,
        expected_artifacts=["one.json", "two.json"],
    )

    assert result.valid is False
    assert "manifest_anchor_mismatch" in result.reason_codes
    assert "artifact_set_mismatch" in result.reason_codes
    assert result.missing_artifacts == ("two.json",)


def test_verifier_checks_internal_hash_and_previous_anchor(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    payload = manifest.to_dict()
    payload["producer_label"] = "changed-producer-label"
    changed_manifest = EvidenceManifest.from_dict(payload)

    result = Verifier().verify(
        manifest=changed_manifest,
        artifact_root=tmp_path,
        expected_manifest_sha256=manifest.manifest_sha256,
        expected_artifacts=["result.json"],
        expected_previous_manifest_sha256="b" * 64,
    )

    assert result.valid is False
    assert "manifest_hash_mismatch" in result.reason_codes
    assert "previous_manifest_mismatch" in result.reason_codes


def test_verifier_detects_missing_physical_artifact(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    (tmp_path / "result.json").unlink()

    result = Verifier().verify(
        manifest=manifest,
        artifact_root=tmp_path,
        expected_manifest_sha256=manifest.manifest_sha256,
        expected_artifacts=["result.json"],
    )

    assert result.valid is False
    assert result.reason_codes == ("artifact_missing",)
    assert result.missing_artifacts == ("result.json",)


def test_verifier_requires_explicit_complete_artifact_set(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    with pytest.raises(EvidenceError, match="explicit iterable"):
        Verifier().verify(
            manifest=manifest,
            artifact_root=tmp_path,
            expected_manifest_sha256=manifest.manifest_sha256,
            expected_artifacts=None,  # type: ignore[arg-type]
        )


def test_manifest_rejects_path_escape_and_duplicate_path(tmp_path: Path) -> None:
    (tmp_path / "result.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvidenceError, match="artifact root"):
        EvidenceManifest.build(
            artifact_root=tmp_path,
            artifact_paths=["../outside.json"],
            manifest_id="manifest-001",
            producer_label="synthetic-producer",
            created_at=NOW,
        )
    with pytest.raises(EvidenceError, match="unique"):
        EvidenceManifest.build(
            artifact_root=tmp_path,
            artifact_paths=["result.json", "result.json"],
            manifest_id="manifest-001",
            producer_label="synthetic-producer",
            created_at=NOW,
        )


def test_manifest_write_is_create_only_and_strictly_loaded(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    manifest = _manifest(artifact_root)
    destination = tmp_path / "manifest.json"

    manifest.write(destination)
    loaded = EvidenceManifest.from_json_file(destination)
    assert loaded == manifest
    with pytest.raises(FileExistsError):
        manifest.write(destination)

    manifest_text = destination.read_text(encoding="utf-8")
    duplicate = manifest_text.replace(
        '"schema_version": 1\n}',
        '"schema_version": 1,\n  "schema_version": 1\n}',
    )
    assert duplicate != manifest_text
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(duplicate, encoding="utf-8")
    with pytest.raises(EvidenceError, match="canonical JSON v1"):
        EvidenceManifest.from_json_file(duplicate_path)


def test_manifest_schema_version_requires_an_integer(tmp_path: Path) -> None:
    payload = _manifest(tmp_path).to_dict()
    payload["schema_version"] = 1.0

    with pytest.raises(EvidenceError, match="schema_version"):
        EvidenceManifest.from_dict(payload)
