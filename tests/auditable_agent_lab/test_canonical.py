from __future__ import annotations

import pytest

from auditable_agent_lab.evidence import (
    CANONICAL_JSON_PROFILE,
    CanonicalizationError,
    canonical_json_bytes,
    sha256_json,
    strict_json_loads,
)


def test_canonical_v1_golden_vector() -> None:
    value = {"z": None, "a": [True, 7, "é"]}

    assert CANONICAL_JSON_PROFILE == "auditable-agent-lab-json-v1"
    assert canonical_json_bytes(value) == '{"a":[true,7,"é"],"z":null}'.encode()
    assert sha256_json(value) == (
        "90ffae40bc3521ad1289f3ae73bf6d711057ff26b7fa9a00f9d23da04108cba5"
    )


def test_strict_json_rejects_duplicate_keys_at_any_depth() -> None:
    with pytest.raises(CanonicalizationError, match="duplicate object key: status"):
        strict_json_loads('{"state":{"status":"pending","status":"approved"}}')


@pytest.mark.parametrize(
    "value",
    [1.0, float("nan"), (2**53), {"nested": -2**53}],
)
def test_canonical_v1_rejects_floats_and_unsafe_integers(value: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonical_json_bytes(value)


@pytest.mark.parametrize("text", ["1.0", "NaN", str(2**53)])
def test_strict_json_enforces_v1_number_domain(text: str) -> None:
    with pytest.raises(CanonicalizationError):
        strict_json_loads(text)


def test_v1_preserves_unicode_code_points_without_normalization() -> None:
    composed = canonical_json_bytes({"value": "é"})
    decomposed = canonical_json_bytes({"value": "e\u0301"})

    assert composed != decomposed


def test_v1_rejects_unpaired_unicode_surrogates() -> None:
    with pytest.raises(CanonicalizationError, match="Unicode surrogate"):
        strict_json_loads('"\\ud800"')
