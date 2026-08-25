# AGENTS.md

This file defines the stable contribution rules for the public Auditable Agent
Lab repository. It applies to human and automated contributors.

## Mission

Build small, dependency-free primitives that make agent authorization,
lifecycle transitions, evidence integrity, and independent audit explicit and
machine-readable.

Correctness priorities are:

1. fail-closed behavior;
2. honest trust-boundary claims;
3. deterministic and auditable data contracts;
4. compatibility and testability;
5. minimal scope.

## Sources of truth

When instructions conflict, use this order:

1. the maintainer's latest explicit instruction;
2. this file's hard boundaries;
3. versioned public API and data contracts;
4. current tests;
5. explanatory documentation and examples.

Historical issues and examples describe prior decisions. They do not silently
authorize changes to a current security boundary.

## Hard boundaries

Unless a maintainer explicitly approves a versioned boundary change:

- keep the runtime package free of third-party dependencies;
- do not add network clients, credentials, secret storage, account access,
  execution integrations, or domain-specific automation to the core;
- deny unknown actions, unknown state fields, malformed inputs, ambiguous JSON,
  missing authorization, and unverifiable evidence;
- never let the supervised agent establish its own trust anchor;
- never describe a label as authenticated identity;
- never describe create-only or tamper-evident files as WORM or absolutely
  immutable;
- never describe instance-local replay state as durable or cross-process replay
  protection;
- use synthetic fixtures only; do not commit real user, provider, account,
  runtime, or research data;
- do not commit caches, virtual environments, build outputs, logs, databases,
  manifests generated at runtime, or local paths;
- do not publish, release, push, or change repository visibility without
  explicit maintainer authorization.

## API and schema discipline

- Authorization receipts remain bound to action, scope, policy hash, machine
  state hash, validity window, decision, and replay policy.
- Protected actions must deny when a trusted AuthorizationVerifier is absent.
- Policy and evidence reason codes are public machine contracts. Change them
  only with compatibility analysis and tests.
- The auditable-agent-lab-json-v1 canonical byte representation is frozen.
  Any incompatible number, Unicode, ordering, or serialization change requires
  a new profile and schema version.
- Evidence verification must require an external manifest anchor and an
  explicit complete expected artifact set.
- CLI status and exit semantics remain: pass/0, fail/1, error/2.

## Change workflow

Before editing:

1. identify the consumer and security invariant;
2. keep the change within governance, evidence, CLI, packaging, documentation,
   or synthetic examples;
3. determine whether the change affects a public schema, hash, reason code, or
   trust boundary.

For implementation changes:

- add or update synthetic tests for every behavior change;
- run python -m pytest -q tests/auditable_agent_lab;
- run the complete public test suite;
- run an installed-wheel smoke test when packaging or imports change;
- run git diff --check;
- inspect git status and keep generated artifacts untracked and ignored.

For documentation changes:

- keep claims narrower than the implemented guarantees;
- distinguish a core primitive from a production integration;
- keep examples synthetic and offline;
- verify every command against a fresh installation when it changes.

## Review expectations

Reviewers should look first for:

- caller-controlled authorization or evidence anchors;
- replay, expiry, policy-drift, and state-binding gaps;
- parser ambiguity or canonicalization drift;
- incomplete artifact-set verification;
- path traversal, symlink, and filesystem durability assumptions;
- error paths that stop failing closed;
- accidental dependencies, network access, secrets, or domain coupling;
- claims that exceed the tested threat model.

A green test run is necessary but not sufficient. Review the decisive denial
paths and the trust assumptions they depend on.
