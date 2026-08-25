# Synthetic AI-Assisted Release Gate

This offline example shows a familiar integration boundary: an agent may build
a release candidate, but it cannot mark that candidate `release_ready` using
its own assertion alone.

The synthetic supervisor requires all of the following:

1. machine state says the CI checks passed;
2. an independent evidence check matches an externally retained manifest
   digest and complete artifact set;
3. maintainer review state is approved;
4. a trusted, policy-bound authorization receipt permits this exact lifecycle
   transition.

After installing the package, run:

```text
python examples/synthetic_release_gate/run_example.py
```

The output demonstrates three outcomes:

- the gate remains closed when authorization is missing;
- verified evidence plus a trusted receipt permits the terminal
  `release_ready` decision;
- changing the candidate after verification invalidates the evidence and makes
  a new gate check fail closed, even when that second check has its own trusted
  receipt.

The example does not publish, deploy, sign, upload, or access a network. Its
candidate bytes, CI report, timestamps, actor label, policy, receipt, and trust
anchors are invented.

For compactness, the trusted receipt digest and manifest digest are represented
inside one process. A real integration must retain those values, authoritative
machine state, and durable replay state outside the supervised agent's write
boundary.
