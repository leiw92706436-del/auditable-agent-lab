from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence


CANONICAL_JSON_PROFILE = "auditable-agent-lab-json-v1"
MAX_SAFE_INTEGER = (2**53) - 1


class CanonicalizationError(ValueError):
    """Raised when a value violates the package's canonical JSON v1 profile."""


def _normalize_json(value: object, path: str = "root") -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError(
                f"{path} contains an invalid Unicode surrogate"
            ) from exc
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalizationError(
                f"{path} contains an integer outside the safe v1 range"
            )
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            f"{path} contains a floating-point number, which v1 forbids"
        )
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{path} contains a non-text key")
            _normalize_json(key, f"{path} object key")
            if key in normalized:
                raise CanonicalizationError(f"{path} contains duplicate key: {key}")
            normalized[key] = _normalize_json(item, f"{path}.{key}")
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [
            _normalize_json(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    raise CanonicalizationError(f"{path} is not JSON data")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalizationError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _reject_non_standard_constant(value: str) -> object:
    raise CanonicalizationError(f"non-standard JSON constant is forbidden: {value}")


def strict_json_loads(text: str) -> object:
    """Parse JSON and enforce the canonical v1 value domain.

    The v1 profile rejects duplicate object keys, floating-point numbers,
    non-standard constants, integers outside the interoperable 53-bit range,
    non-text object keys, and non-JSON Python values.
    """

    if not isinstance(text, str):
        raise CanonicalizationError("JSON input must be text")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_non_standard_constant,
        )
    except CanonicalizationError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CanonicalizationError("input must contain valid JSON") from exc
    return _normalize_json(value)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize the auditable-agent-lab JSON v1 profile deterministically.

    Objects are sorted by Python Unicode code-point order, strings retain their
    original code points without normalization, UTF-8 is emitted directly, and
    insignificant whitespace is omitted. This is a package profile, not JCS.
    """

    normalized = _normalize_json(value)
    return json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
