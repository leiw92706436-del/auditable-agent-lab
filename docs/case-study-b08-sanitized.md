# B08: A Sanitized Fail-Closed Collection Case Study

This case study describes aggregate operational behavior from a private,
high-risk research collection. It contains no provider content, raw
observations, asset identifiers, machine paths, runtime manifests, or outcome
data.

The public Auditable Agent Lab code is a clean, generic reimplementation of the
governance invariants. It is not the original collection system.

## The governance problem

An autonomous collector was scheduled three times per operating day. The
research value depended on preserving what was visible at each real observation
time, including later revisions.

The dangerous failure modes were:

- silently losing a scheduled observation;
- filling a missed observation later and presenting it as prospective;
- overwriting an earlier value after a source revision;
- treating operational coverage as accepted research data;
- letting the collector continue after a repeated failure threshold;
- letting the agent relax the gate after seeing partial results.

The fixed policy required every scheduled slot to receive an immutable-by-policy
accounting record. A missed slot remained a miss. It could not be replayed,
backfilled, or converted into an accepted observation.

## Milestone snapshot

At the dated 20-day operational review snapshot on 2026-08-12:

| Operational measure | Result |
|---|---:|
| Distinct scheduled days | 20 |
| Expected slots | 60 |
| Slots with accounting | 60 |
| Accepted and independently audited slots | 58 |
| Explicit early misses | 2 |
| Accepted runtime re-audits passed | 58 of 58 |
| Recorded source-revision events | 503 |

The two misses were not repaired. All 58 accepted runtimes passed independent
artifact, hash, and boundary checks. Revision events remained separate records
instead of overwriting earlier observations.

The gate still concluded:

~~~text
dataset_accepted=false
accepted_for_research_use=false
phase_upgrade=false
continue_bounded_collection=true
~~~

Operational completeness was necessary, but unresolved source timing and field
semantics meant it was not sufficient for data acceptance.

## Later stop and recovery behavior

In a later, separate operating window, three consecutive scheduled misses
triggered a global stop. Recovery required a human-controlled acknowledgement.
It restored future scheduling only:

- old accounting records were unchanged;
- missed slots were not backfilled;
- the failure threshold was not reset by rewriting history;
- no dataset, outcome, validation, or phase gate was opened.

This is the practical meaning of fail closed: the system preserved an
uncomfortable record and reduced authority instead of manufacturing
completeness.

## Mapping to the public primitives

| Case-study invariant | Public primitive |
|---|---|
| Only registered actions may run | PolicyEvaluator |
| Recovery requires external approval | AuthorizationReceipt plus AuthorizationVerifier |
| Approval is tied to current state and policy | Policy and state hashes in the receipt |
| Terminal or stopped states cannot silently advance | LifecycleManager |
| Every accepted artifact has a content identity | EvidenceManifest |
| Rewritten or incomplete evidence must fail | Verifier plus external anchor and expected set |
| Ambiguous machine input must not pass | Canonical JSON v1 strict loader |
| CI and auditors need deterministic outcomes | CLI envelope and reason codes |

The [synthetic example](../examples/synthetic_research) recreates these classes
of behavior without copying any private fixture or domain data.

## What this case study proves

It is evidence that the governance pattern was exercised against a real,
long-running operational process:

- missing data was recorded rather than concealed;
- independent re-audit covered every accepted runtime in the milestone window;
- revisions were preserved as history;
- recovery did not expand authority;
- a successful engineering milestone did not auto-accept the dataset.

## What it does not prove

This document is not:

- a public dataset or independently reproducible provider audit;
- evidence of strategy quality, prediction, performance, or financial value;
- proof that the public package operated the original collector;
- adoption evidence for the public project;
- a claim of WORM storage or authenticated producer identity.

Public confidence in the package must come from its synthetic tests, public CI,
clean releases, security review, and external users. The aggregate private case
study is supporting design evidence only.
