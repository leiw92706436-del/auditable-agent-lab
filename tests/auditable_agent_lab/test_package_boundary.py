from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "src" / "auditable_agent_lab"


def _python_files() -> list[Path]:
    return sorted(PACKAGE_ROOT.rglob("*.py"))


def test_core_imports_only_standard_library_and_its_own_package() -> None:
    forbidden_network_modules = {
        "ftplib",
        "http",
        "imaplib",
        "poplib",
        "requests",
        "smtplib",
        "socket",
        "urllib",
    }
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                top_level = name.split(".", 1)[0]
                assert top_level in sys.stdlib_module_names or top_level == (
                    "auditable_agent_lab"
                ), f"non-stdlib import in {path}: {name}"
                assert top_level not in forbidden_network_modules, (
                    f"network import in {path}: {name}"
                )


def test_core_has_no_domain_or_credential_terms() -> None:
    forbidden_patterns = {
        "btc terminology": re.compile(r"\b(?:btc|bitcoin)\b", re.IGNORECASE),
        "private package import": re.compile(r"\bfrom\s+src\b|\bimport\s+src\b"),
        "credential field": re.compile(
            r"\b(?:api[_-]?key|password|private[_-]?key|client[_-]?secret)\b",
            re.IGNORECASE,
        ),
    }
    for path in _python_files():
        content = path.read_text(encoding="utf-8")
        for label, pattern in forbidden_patterns.items():
            assert not pattern.search(content), f"{label} found in {path}"


def test_build_metadata_has_no_runtime_dependencies_and_packages_only_core() -> None:
    metadata = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["build-system"]["requires"] == ["setuptools>=77"]
    assert metadata["project"]["name"] == "auditable-agent-lab"
    assert metadata["project"]["license"] == "Apache-2.0"
    assert metadata["project"]["license-files"] == ["LICENSE"]
    assert metadata["project"]["dependencies"] == []
    assert metadata["tool"]["setuptools"]["packages"]["find"]["include"] == [
        "auditable_agent_lab*"
    ]
    assert (REPO_ROOT / "LICENSE").is_file()
