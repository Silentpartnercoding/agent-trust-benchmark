# Running Authority Relations v0.1 independently

Authority Relations v0.1 is frozen at Git tag `authority-relations-v0.1`.
Use that tag for a comparable run. The runner verifies the frozen manifest
before invoking an adapter.

## What counts as independent

An independent implementation:

- is maintained outside this repository;
- maps the case into its native authorization or policy engine;
- does not import, translate, or reproduce the decision rules in
  `adapters/relation_aware.py`;
- does not inspect the vector's `expected` object while deciding; and
- reports `UNSUPPORTED` when its native model cannot represent a relation.

A thin transport adapter is expected. Reimplementing this repository's oracle
inside that adapter is not an independent result.

## Adapter contract

The adapter is an executable. For each vector it receives one compact JSON
object on standard input and writes exactly one JSON object on standard output.
The case contains `schema`, `vector_id`, descriptive text, explicit `policy`,
and `observed` evidence. It never contains the expected answer.

The output schema and exact fields are defined by
`vectors/authority-relations-v0.1/schema.json`. The safest implementation path
is:

1. parse the case;
2. translate observed facts into the native engine's input types;
3. ask the native engine to classify authority and apply the supplied policy;
4. translate the native result into `atb-authority-relation-output/0.1`; and
5. write the output without logs on standard output.

Diagnostics may be written to standard error. The runner limits each case to
five seconds and one megabyte of output.

## One-command run

From a checkout of the frozen tag:

```bash
python -m pip install -e '.[test]'
python -m agent_trust_benchmark authority-relations \
  --adapter /absolute/path/to/your-adapter \
  --output-dir external-result
```

The command first verifies the frozen release manifest. It then writes
`external-result/result.json` and `external-result/SUMMARY.md`. Exit status 0
means every vector passed. Exit status 1 may still represent a valid completed
run containing failures or `UNSUPPORTED` cases; inspect the artifacts.

To verify the checkout without running an adapter:

```bash
python -m agent_trust_benchmark authority-relations-verify-release
```

## Result submission

See `results/authority-relations-v0.1/submissions/README.md`. Results are
append-only. A submission does not become “verified” merely because its author
labels it that way. Verification requires schema validation, frozen hash
matching, and an independently reproducible run when the implementation is
available.
