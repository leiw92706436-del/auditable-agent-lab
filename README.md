# Auditable Agent Lab

A dependency-free Python control layer that prevents agents from approving
their own high-impact actions and makes the evidence behind each decision
independently verifiable.

> Stop an agent from approving its own high-impact action—and prove later which
> policy, state, authorization, and artifacts justified the decision.

~~~text
External Authority
        ↓
Machine State
        ↓
Policy Evaluation
        ↓
Allowed Action
        ↓
Agent Execution or Artifact Production
        ↓
Create-Only, Tamper-Evident Evidence
        ↓
Independent Verification
        ↓
Human-Controlled Gate Decision
~~~

The core helps a supervisor answer four narrow questions:

1. Is this action allowed by the current machine-readable policy and state?
2. Did an authority outside the supervised agent approve the protected action?
3. Do the agent's artifacts still match an externally retained evidence
   anchor and complete expected artifact set?
4. Can the workflow advance without letting a failure, unknown input, or agent
   assertion become an allow decision?

Unknown actions, missing authorization, ambiguous JSON, policy drift, stale
receipts, replay within a verifier instance, incomplete evidence, and changed
artifacts fail closed.

## First use case: AI-assisted release gate

An agent can write code, run a build, and report that checks passed. None of
those statements should by itself authorize a release.

The primary synthetic example treats the build agent as untrusted and requires:

- authoritative CI and review state;
- a maintainer authorization receipt bound to the exact policy, state, action,
  scope, and time window;
- an independently checked manifest anchor and complete artifact set;
- an explicit lifecycle transition to `release_ready`.

If authorization is missing or a candidate changes after verification, the gate
stays closed. The example returns a decision only; it never publishes or
deploys anything.

This same control pattern can sit in front of report publication, dataset
acceptance, multi-agent handoffs, or other workflows where the actor producing
the work must not approve its own result.

## What this project provides

- AuthorizationReceipt binds an action, scope, policy, machine state, validity
  window, decision, and replay policy.
- AuthorizationVerifier is the integration boundary for supervisor-controlled
  trust.
- PolicyEvaluator returns deterministic allow or deny decisions and reason
  codes.
- LifecycleManager enforces an explicit transition graph and freezes terminal
  states.
- EvidenceManifest records sorted artifact paths, sizes, hashes, provenance
  labels, and an optional previous-manifest link.
- Verifier checks a manifest against an external digest and an explicit complete
  artifact set.
- auditable-agent-lab-json-v1 defines a strict, deterministic JSON and hash
  profile.
- A machine-readable CLI uses a stable pass, fail, or error envelope with exit
  codes 0, 1, and 2.

The runtime package uses only the Python standard library.

## What this project does not provide

Auditable Agent Lab is not:

- an identity provider, signature service, or key-management system;
- a durable or distributed authorization service;
- global replay protection across processes;
- WORM, append-only, or remote evidence storage;
- an agent runtime, model gateway, network client, or scheduler;
- a substitute for human review, domain validation, or deployment controls.

The built-in TrustedReceiptVerifier keeps replay state in memory for one
verifier instance. Production integrations that need global one-shot receipts
must provide an AuthorizationVerifier backed by an atomic store outside the
agent's authority.

Similarly, an evidence digest is trustworthy only when it is retained outside
the evidence bundle and outside the supervised agent's write boundary.

## Quick start

Auditable Agent Lab requires Python 3.11 or 3.12.

~~~bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
python examples/synthetic_release_gate/run_example.py
~~~

The example uses invented candidate bytes, state, actors, policies, timestamps,
and trust anchors. It does not access a network, publish a release, or call an
external service.

Inspect the CLI:

~~~bash
python -m auditable_agent_lab --help
python -m auditable_agent_lab action-check --help
python -m auditable_agent_lab evidence-verify --help
~~~

## CLI contract

Every operational result uses these top-level fields:

~~~text
schema_version
command
status
result
error
~~~

| Outcome | Status | Exit code |
|---|---|---:|
| Policy or evidence check passed | pass | 0 |
| Policy denied or evidence did not match | fail | 1 |
| Input, schema, or runtime error | error | 2 |

For action-check, the supervisor supplies machine state, a policy, the requested
action and scope, and optionally a receipt plus externally trusted receipt
digest.

For evidence-verify, the auditor supplies the manifest, artifact root,
externally retained manifest digest, and the complete expected artifact set.

Trust anchors must not be generated or selected by the agent being supervised.

## Canonical JSON v1

Hash-bound JSON inputs share one deliberately narrow profile:

- UTF-8 output;
- object keys sorted by Unicode code-point order;
- no insignificant whitespace;
- no Unicode normalization;
- duplicate object keys rejected at every depth;
- floating-point values and non-standard constants rejected;
- integers restricted to the interoperable 53-bit safe range;
- invalid Unicode surrogates and non-text object keys rejected.

This is the auditable-agent-lab-json-v1 profile, not RFC 8785/JCS. Changing its
value domain or byte representation requires a new profile and schema version.

## Architecture and security model

Start with:

- [Architecture](docs/architecture.md) for components and execution flow;
- [Threat model](docs/threat-model.md) for trust zones, assumptions, and
  non-goals;
- [Security policy](SECURITY.md) for vulnerability reporting and supported
  versions;
- [Synthetic release gate](examples/synthetic_release_gate/README.md) for the
  primary runnable example;
- [Synthetic research lifecycle](examples/synthetic_research/README.md) for a
  second domain-neutral composition;
- [Sanitized B08 case study](docs/case-study-b08-sanitized.md) for aggregate
  operational evidence.

The public case study reports aggregate governance behavior only. It contains no
provider content, raw observations, private runtime artifacts, machine paths, or
domain outcomes.

## Development

Install a test runner and execute the public suite:

~~~bash
python -m pip install pytest
python -m pytest -q tests/auditable_agent_lab
~~~

Before proposing a change:

~~~bash
python -m pytest -q tests/auditable_agent_lab
git diff --check
~~~

See [CONTRIBUTING.md](CONTRIBUTING.md) for compatibility, test, and review
requirements.

## License

Auditable Agent Lab is licensed under the
[Apache License 2.0](LICENSE).

## Project status

Version 0.1.0 is the initial alpha release. Its reviewed API surface is
intentionally small: governance, evidence verification, a CLI skeleton, and
synthetic examples.

Current roadmap themes include:

1. a durable AuthorizationVerifier adapter example;
2. durable atomic manifest creation without claiming WORM storage;
3. published JSON schemas and additional cross-language golden vectors;
4. a signature-verifier adapter that keeps secrets outside the core;
5. external clone-and-run feedback before a v0.1.1 release.

Roadmap items are proposals, not implemented capabilities. They do not expand
the current trust boundary without separately reviewed changes.
