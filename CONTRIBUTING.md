# Contributing to Auditable Agent Lab

Thank you for helping improve fail-closed agent governance and evidence
verification.

The project intentionally favors a small, inspectable core over broad framework
coverage. A contribution is most useful when it closes a concrete governance or
audit gap without weakening the trust model.

## Good contribution areas

- denial-path and adversarial synthetic tests;
- deterministic reason codes and input validation;
- AuthorizationVerifier adapters with explicit trust ownership;
- evidence verification and filesystem hardening;
- canonical JSON golden vectors;
- documentation that makes security boundaries easier to understand;
- offline examples that use invented data only;
- packaging, CI, and cross-version compatibility.

Domain-specific agents, network integrations, credential management, and
execution systems belong in separate integrations, not in the dependency-free
core.

## Development setup

Use Python 3.11 or 3.12:

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
python -m pip install pytest
python -m pytest -q tests/auditable_agent_lab
~~~

The package has no runtime third-party dependencies. Pytest is a development
tool only.

## Design requirements

Every behavior change must preserve or deliberately version these invariants:

- protected actions fail when trusted authorization is absent;
- authorization is bound to policy, state, action, scope, and time;
- ambiguous or unsupported JSON fails before hashing or evaluation;
- evidence verification depends on an external anchor and complete expected set;
- unrecognized inputs do not silently become allowed;
- trust labels are not presented as authenticated identities;
- storage and replay guarantees are described at their actual scope.

If a proposal changes canonical bytes, receipt or manifest fields, reason codes,
CLI flags, or exit semantics, open a design discussion before implementation.
Incompatible canonicalization changes require a new profile and schema version.

## Tests

Tests must be:

- synthetic;
- deterministic;
- offline;
- free of credentials, personal information, and external provider data;
- focused on observable allow, deny, error, or verification behavior.

At minimum, run:

~~~bash
python -m pytest -q tests/auditable_agent_lab
git diff --check
~~~

Packaging changes also require an isolated wheel build, fresh virtual
environment install, import smoke test, CLI smoke test, example run, and pip
check.

## Pull requests

Keep pull requests narrow and explain:

1. the invariant or user problem;
2. the trust boundary before and after the change;
3. new or changed public contracts;
4. the denial paths covered by tests;
5. known limitations that remain.

Before requesting review, confirm:

- [ ] targeted tests pass on every supported Python version;
- [ ] new behavior has synthetic tests;
- [ ] no runtime dependency or network path was added unintentionally;
- [ ] no secret, personal path, real data, or generated artifact is present;
- [ ] public claims do not exceed the implementation;
- [ ] canonical and CLI compatibility were considered;
- [ ] documentation and examples match the installed package.

## Security reports

Do not disclose suspected vulnerabilities in a public issue. Follow the
[security policy](SECURITY.md).

## Contribution licensing

Unless explicitly stated otherwise, contributions submitted to this repository
are licensed under the [Apache License 2.0](LICENSE). Do not contribute material
you do not have the right to license.
