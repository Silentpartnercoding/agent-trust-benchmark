# External submissions

External results are stored append-only under:

```text
submissions/<implementation-slug>/<implementation-commit-or-version>/
  submission.json
  result.json
  SUMMARY.md
```

`submission.json` must validate against
`schemas/authority-relations-submission-v0.1.schema.json`. `result.json` is the
unaltered runner output. `SUMMARY.md` is the unaltered runner summary.

## Acceptance states

- `SUBMITTED`: required files and metadata are present.
- `HASH_VALIDATED`: the suite, frozen vector hash, result hash, and artifact
  hashes match.
- `REPRODUCED`: a maintainer reran the disclosed implementation and obtained
  the same case outcomes.
- `DISPUTED`: the result or independence claim has a documented unresolved
  problem.

Only maintainers assign acceptance state. A participant's assertion that it
used its native engine is recorded as an attestation, not treated as proof.

Never replace a prior submission. Corrections go in a new version directory
and link to the superseded submission. Never edit the frozen vectors to make an
external implementation pass; semantic changes require a new benchmark version.
