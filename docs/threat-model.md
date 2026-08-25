# Threat Model

This document defines the security claims Auditable Agent Lab is designed to
support and the assumptions those claims require.

## Security objective

A supervised agent must not be able to expand its own authority or make changed
or incomplete evidence pass an independent audit merely by constructing new
inputs.

The package aims to make unauthorized, ambiguous, stale, replayed within one
verifier instance, or unverifiable operations fail closed with deterministic
reasons.

## Trust zones

### External supervisor

Trusted to:

- define policy and known state fields;
- retain or approve receipt digests;
- own any durable replay store;
- retain manifest digests and expected artifact sets;
- control phase or gate decisions.

The supervisor must not delegate those trust decisions to the supervised agent.

### Supervised agent

Assumed able to:

- construct arbitrary receipt and manifest files;
- choose labels and identifiers;
- modify files inside its artifact workspace;
- retry calls and replay prior inputs;
- provide malformed, ambiguous, or unexpected JSON;
- observe normal policy and verification outputs.

The agent is not trusted to attest its own identity, authorization, evidence
completeness, or manifest authenticity.

### Local operating environment

Assumed to provide:

- correct Python and SHA-256 implementations;
- ordinary filesystem path and permission behavior;
- an artifact root that is not maliciously swapped during verification;
- process isolation appropriate to the integration.

The core does not harden or attest the host operating system.

## Protected assets

- policy definitions and their canonical hashes;
- current machine state and its canonical hash;
- trusted receipt digests or verifier configuration;
- consumed-receipt state when one-shot behavior is required;
- externally retained manifest digests;
- complete expected artifact sets;
- evidence artifacts and audit decisions;
- stable CLI schemas and reason codes used by automation.

## Threats and controls

| Threat | Control | Remaining assumption |
|---|---|---|
| Agent invents an approval receipt | Protected action requires an AuthorizationVerifier and trusted digest | Supervisor protects verifier inputs |
| Agent changes receipt actor or fields | Trust binds the canonical digest of all receipt fields | Digest approval happened out of band |
| Old receipt is used after policy drift | Receipt binds deterministic policy hash | Supervisor defines intended policy |
| Receipt is used for another state, action, or scope | Exact bindings are checked before trust acceptance | Input state reflects the real gate state |
| Receipt is replayed concurrently | Lock-protected instance-local consumption | Global replay needs a durable adapter |
| Duplicate JSON keys change interpretation | Strict loader rejects duplicates at every depth | Integrations use the strict loaders |
| Numeric or Unicode ambiguity changes a hash | Canonical v1 narrows the value domain and fixes bytes | All parties implement the same profile |
| Agent rewrites manifest and self-hash | Verifier requires an external expected manifest digest | Anchor remains outside agent control |
| Agent omits an artifact | Verifier requires a complete external expected set | Expected set is complete and trusted |
| Agent changes an artifact | Size and SHA-256 are recomputed | Host and hash implementation are trusted |
| Artifact path escapes root | Canonical relative paths and resolved containment checks | Root is not raced or replaced |
| Failure is mistaken for denial or success | CLI separates pass, fail, and error with exit 0, 1, and 2 | Caller handles all three states |

## Fail-closed invariants

An integration must treat all of these as denial or error:

- unknown action;
- unknown or missing state field;
- non-canonicalizable state;
- missing or invalid receipt;
- missing trusted verifier;
- untrusted, expired, not-yet-valid, mismatched, or replayed receipt;
- duplicate or malformed JSON;
- missing external manifest digest;
- missing or duplicate expected artifact set;
- manifest-anchor, content-hash, chain, size, hash, path, or set mismatch;
- unreadable artifact;
- any CLI status other than the expected pass result.

No exception, timeout, parser failure, or unavailable trust store should become
an allow decision.

## Explicit non-goals

The current core does not claim to mitigate:

- a compromised external supervisor;
- trust anchors stored where the supervised agent can replace them;
- replay across new processes or hosts using TrustedReceiptVerifier;
- malicious operating-system or interpreter behavior;
- concurrent filesystem replacement during manifest creation or verification;
- hash-function compromise;
- secrets, signing keys, or certificate lifecycle;
- WORM retention, remote notarization, or legal non-repudiation;
- agent sandboxing, prompt injection, model behavior, or tool permissions;
- correctness or value of domain evidence.

## Integration checklist

Before using a protected action in a higher-impact workflow:

- [ ] policy is versioned and stored outside the agent's write boundary;
- [ ] machine state comes from an authoritative source;
- [ ] receipt trust is established outside the agent;
- [ ] durable one-shot use has an atomic persistent verifier;
- [ ] receipt expiry uses a trusted clock;
- [ ] manifest digest and expected set are stored independently;
- [ ] artifact root permissions and symlink behavior are understood;
- [ ] pass, fail, and error paths are all tested;
- [ ] logs do not contain secrets or private evidence;
- [ ] human override and recovery procedures are documented;
- [ ] public claims match the implemented guarantees.

If any required trust input is unavailable or ambiguous, stop rather than
substituting a caller-provided value.
