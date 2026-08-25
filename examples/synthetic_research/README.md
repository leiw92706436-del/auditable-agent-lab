# Synthetic Research Example

This example uses invented state, authorization, lifecycle, and artifact data. It
performs no network access and requires no external service.

After installing the package, run:

```text
python examples/synthetic_research/run_example.py
```

The output shows missing and caller-created authorization being denied, a
policy-bound trusted receipt allowing one transition, a frozen terminal state,
evidence verification against an external digest and complete artifact set, and
detection of both a rewritten manifest and a changed artifact.

The in-memory trusted receipt set stands in for a digest supplied by an external
supervisor. The trusted manifest digest stands in for a value retained outside
the evidence bundle. Production integrations must keep those trust decisions
outside the agent being supervised.
