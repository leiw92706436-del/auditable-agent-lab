# Changelog

All notable public changes to Auditable Agent Lab are recorded here.

## 0.1.0 - 2026-08-26

Initial public alpha release.

### Added

- Dependency-free governance primitives for fail-closed policy evaluation,
  authorization receipts, and explicit lifecycle transitions.
- Tamper-evident evidence manifests with external digest anchoring and complete
  expected-artifact verification.
- The strict `auditable-agent-lab-json-v1` canonical JSON and hashing profile.
- A machine-readable CLI with stable pass, fail, and error envelopes.
- Offline synthetic release-gate and research-lifecycle examples.
- Architecture, threat-model, security, contribution, and sanitized case-study
  documentation.
- Python 3.11 and 3.12 CI with tests, wheel inspection, and fresh-install
  checks.

### Trust boundaries

- The runtime package has no third-party or network dependencies.
- The core does not provide identity, signing, key management, durable replay
  protection, WORM storage, deployment, or execution integrations.
- Authorization and evidence trust anchors must remain outside the supervised
  agent's authority.
