# Security Policy

Auditable Agent Lab provides governance and evidence primitives. Its security
depends on an integration keeping trust anchors and durable state outside the
supervised agent's authority.

Read the [threat model](docs/threat-model.md) before using the package for a
high-impact workflow.

## Supported versions

| Version | Support |
|---|---|
| Current development branch | Security fixes accepted |
| Tagged v0.1 releases | Supported after publication |
| Older development snapshots | Not supported |

The project is pre-release. This table will be replaced with exact release
ranges after the first public release.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository Security tab
when it is enabled.

Do not include exploit details, secrets, private artifacts, or personal
information in a public issue. If private reporting is temporarily unavailable,
open a minimal public issue asking the maintainers to provide a private channel;
do not describe the vulnerability itself.

Before the first public release, maintainers must enable private vulnerability
reporting and verify the reporting path from a non-maintainer account.

Helpful private reports include:

- affected version or commit;
- the violated security invariant;
- a minimal synthetic reproduction;
- expected and actual allow, deny, or verification behavior;
- impact and preconditions;
- a suggested mitigation, if known.

Please use invented data. Never send real credentials or private evidence.

## Security scope

High-priority issues include:

- protected actions allowed without a trusted verifier;
- caller-created trust anchors accepted as external authority;
- policy, state, action, scope, expiry, or replay bindings bypassed;
- duplicate-key or canonicalization ambiguity that changes a decision or hash;
- evidence accepted without an external anchor or complete expected set;
- artifact path escape or verification of the wrong file;
- fail-open exception or CLI exit behavior;
- secrets, network capability, or private dependencies introduced into the core;
- claims or defaults that hide a weaker trust boundary.

## Known limitations

The following are documented boundaries, not implemented guarantees:

- TrustedReceiptVerifier stores consumed receipts in memory for one instance.
  It is not durable or distributed replay protection.
- The package does not authenticate an actor or issuer. A trusted integration
  approves a receipt digest or implements another AuthorizationVerifier.
- EvidenceManifest.write is create-only. It is not WORM storage and does not
  promise atomic durability across power loss.
- Artifact verification assumes the operating system and artifact root are not
  being maliciously replaced during a check.
- The package does not protect a trust anchor that the supervised agent can
  read, replace, or choose.
- The package does not provide sandboxing, process isolation, model security, or
  deployment authorization.

A report that demonstrates an undocumented bypass within the stated threat
model is a security issue. Requests for one of the non-goals above may instead
be handled as a hardening proposal.

## Disclosure and fixes

Maintainers will validate reports with synthetic evidence, minimize access to
report details, and coordinate a fix and release note before public disclosure.
No response or remediation deadline is promised while the project is
maintainer-operated and pre-release.
