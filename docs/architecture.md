# Architecture

Auditable Agent Lab separates policy, authorization, lifecycle, evidence
production, and independent verification. No component is allowed to turn its
own output into authority.

The primary reference scenario is an AI-assisted release gate. The agent may
produce a candidate and build report, while a supervisor assembles authoritative
state, verifies the complete artifact set, validates external authorization,
and decides whether the lifecycle may enter `release_ready`. The example emits
that decision but performs no release or deployment.

## Control flow

~~~mermaid
flowchart LR
    H["Human or external supervisor"] --> T["Trusted receipt digest or verifier"]
    S["Machine-readable state"] --> P["Policy evaluator"]
    R["Authorization receipt"] --> P
    T --> P
    P -->|"allow or deny"| L["Lifecycle manager"]
    L -->|"allowed transition"| A["Supervised agent action"]
    A --> E["Evidence manifest and artifacts"]
    X["Externally retained manifest digest and expected set"] --> V["Independent verifier"]
    E --> V
    V --> G["Gate decision"]
~~~

The supervisor and independent verifier may be implemented by the same
integration, but their trusted inputs must remain outside the supervised agent's
write authority.

## Components

| Component | Responsibility | Does not establish |
|---|---|---|
| AuthorizationReceipt | Bind a claim to actor label, action, scope, policy, state, time, and replay policy | Identity or trust |
| AuthorizationVerifier | Decide whether an external authority trusts a receipt | Policy requirements |
| TrustedReceiptVerifier | Reference digest allowlist with instance-local replay state | Durable replay protection |
| PolicyEvaluator | Match a known action to required state and trusted authorization | Lifecycle topology |
| LifecycleManager | Enforce allowed transitions and freeze terminal states | Authorization trust |
| Canonical JSON v1 | Produce deterministic bytes and hashes for a narrow JSON domain | General JSON interoperability |
| EvidenceManifest | Describe sorted artifact identities and provenance labels | External authenticity |
| Verifier | Compare artifacts with an external manifest anchor and expected set | Anchor custody |
| CLI | Expose policy and evidence checks through a stable machine envelope | A secure supervisor process |

## Governance path

Policy construction produces a deterministic policy hash from:

- schema version;
- policy identifier;
- sorted known state fields;
- sorted action rules;
- required state values;
- authorization requirements.

An authorization receipt binds that hash to the requested action, scope, current
machine-state hash, validity window, decision, and replay policy. The receipt is
only a claim until an AuthorizationVerifier accepts it using information that
the supervised agent does not control.

Policy evaluation proceeds in this order:

1. validate the request and machine-state shape;
2. reject unknown state fields;
3. reject non-canonicalizable state;
4. reject unknown actions;
5. check required state values with exact types;
6. require a receipt for protected actions;
7. require a trusted verifier;
8. verify all receipt bindings;
9. return one deterministic decision and reason code.

No fallback action or permissive default exists.

## Lifecycle path

LifecycleManager receives an explicit directed transition map. It:

- rejects unknown current stages;
- rejects transitions not present in the map;
- maps each transition to a policy action;
- delegates authorization to PolicyEvaluator;
- freezes a state whose destination has no outgoing transitions.

The manager returns a new immutable LifecycleState. It does not mutate the
previous value.

## Evidence path

EvidenceManifest.build resolves every declared artifact below a root, records
its byte size and SHA-256 digest, sorts paths, and hashes the canonical manifest
content. The producer field is intentionally named producer_label because it is
not authenticated.

Verifier requires two inputs that are not taken from the manifest:

1. the expected manifest SHA-256 digest;
2. the complete expected artifact path set.

It then checks:

- external manifest anchor equality;
- internal manifest hash consistency;
- optional previous-manifest anchor equality;
- expected and manifest artifact-set parity;
- path containment;
- current artifact existence, size, and hash.

This makes rewriting a manifest together with its self-hash detectable when the
external anchor is preserved. It does not make the filesystem immutable.

## Canonical JSON profile

The auditable-agent-lab-json-v1 profile is shared by machine state, policy
hashes, receipts, and manifests. It has a deliberately smaller value domain than
general JSON.

The profile is part of the public compatibility contract. A future incompatible
profile must use a new identifier and schema version; historical hashes remain
interpreted under v1.

## CLI boundary

The CLI has two operational commands:

- action-check for policy decisions;
- evidence-verify for artifact verification.

Both emit a common envelope with schema_version, command, status, result, and
error. Exit code 0 means pass, 1 means a valid check failed, and 2 means the
check could not be performed because input or runtime handling failed.

The CLI accepts trust inputs; it does not protect them. A secure integration
must construct the command or call the Python API from a supervisor-controlled
process.

## Extension points

Safe extensions generally implement an existing boundary rather than adding
authority to the core:

- a durable AuthorizationVerifier with transactional replay consumption;
- a signature verifier whose public keys are supervisor-controlled;
- remote or hardware-backed manifest-anchor storage;
- a durable manifest writer;
- adapters that translate an external state system into canonical JSON.

These integrations should remain optional so the core stays offline and
dependency-free.
