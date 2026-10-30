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

## Reason codes

This section documents v0.1 as frozen. It changes no vector, expected
output, schema, or scoring rule.

The runner compares every output field with the expected output, `reason`
included, by exact string equality. The output schema only requires `reason`
to be a nonempty string, so the schema alone does not tell an adapter which
strings will match. Until this section was added, that was undocumented. An
adapter that reaches the right decision with its own reason text is scored
`FAIL` on that case, and the summary lists `reason` as the mismatched field.

v0.1 uses eight reason codes. When more than one condition holds, the
expected reason is the first one in this order:

1. `INVALID_EVIDENCE`: the policy rejects invalid evidence and some request,
   execution, or delegation evidence has status `INVALID`.
2. `REQUEST_AUTHORITY_REQUIRED`: the policy requires requester authority and
   the requester has no valid request authority.
3. `EXECUTION_AUTHORITY_INVALID`: the actor has no valid execution
   authority, delegated or independent.
4. `RELATION_NOT_ALLOWED`: the derived relation is outside the policy's
   `allowed_relations`.
5. `RELATIONSHIP_MISMATCH`: the policy requires the declared relation to
   match the derived one, and it does not.
6. `EXECUTOR_AUTHORITY_VERIFIED_PERMISSIONLESS_REQUEST`: authorized, and the
   policy does not require requester authority.
7. `VALID_DELEGATION`: authorized through a delegated relation.
8. `VALID_INDEPENDENT_AUTHORITY_PATHS`: authorized through independent
   request and execution authority.

Expected reason per vector:

| Vector | Expected `reason` |
|---|---|
| AR-001-VALID-DELEGATION | `VALID_DELEGATION` |
| AR-002-VALID-MANDATE | `VALID_INDEPENDENT_AUTHORITY_PATHS` |
| AR-003-UNAUTHORIZED-REQUESTER | `REQUEST_AUTHORITY_REQUIRED` |
| AR-004-UNAUTHORIZED-EXECUTOR | `INVALID_EVIDENCE` |
| AR-005-NO-AUTHORITY | `REQUEST_AUTHORITY_REQUIRED` |
| AR-006-SPOOFED-DELEGATION | `INVALID_EVIDENCE` |
| AR-007-RELATIONSHIP-MISMATCH | `RELATIONSHIP_MISMATCH` |
| AR-008-PERMISSIONLESS-REQUEST | `EXECUTOR_AUTHORITY_VERIFIED_PERMISSIONLESS_REQUEST` |

The table is here so that a mismatch can be read correctly. An independent
adapter still derives its reason from the case it receives. An adapter that maps
`vector_id` to a reason does not count as independent.

A native engine with its own reason vocabulary may translate its result into
these codes in the thin transport adapter, the same way it translates the
other output fields. A run that reports native reason text instead is still a
valid completed run. Its result shows which cases differ only in `reason`,
and a submission should say so.

The next suite version will settle this one of two ways: keep exact reason
codes as part of the output contract, now documented, or score `reason`
separately from the decision fields. That choice needs a new suite version and
tag under the release's change policy. v0.1 results stay as recorded.

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
