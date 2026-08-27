# CDX-AADP-INPUT-PROVENANCE-001

## Result

**EXACT.** At the frozen CycloneDX 2.0 development commit, a verifier can distinguish an
authorization-relevant value supplied by authenticated authority state from the same value
supplied by the caller without a custom evidence property or a new trace schema.

This is an independent interoperability fixture. It is not an AADP or CycloneDX contribution,
endorsement, implementation claim, or assertion that the two projects are coordinating.

## Question

Can a native CycloneDX record preserve this difference?

| | Authority-sourced lane | Caller-sourced lane |
|---|---|---|
| Tool digest | same | same |
| Policy digest | same | same |
| Decision field | `organization` | `organization` |
| Evaluated value | `org-b` | `org-b` |
| Verdict | `permit` | `permit` |
| Whole-record JSS signature | valid | valid |
| Source | authenticated authority state | caller agent |

The policy result is deliberately uninformative. Both lanes permit. The evidence must preserve
which source supplied the value that produced the verdict.

## Why AADP is here

AADP-01 is one test profile, not the benchmark's foundation. Its evaluation invariant says a
verdict is determined over the full evaluation input: policy, request, mutable authorization
state, and evaluation time. Its evidence requirement makes each verdict re-derivable given the
policy version in force. Its request model also says the wire-level `source` value is self-asserted
and must not be treated as authenticated authority; authorization-relevant provenance must instead
come from authenticated context.

AADP-01's minimum evidence entry does not explicitly enumerate the provenance of every
authorization-relevant field. In this fixture's byte-identical-value case, preserving that
provenance is a necessary consequence of re-derivability: without it, two different evaluation
inputs collapse into the same record. The fixture therefore treats field-level provenance as a
derived requirement for this case, not as verbatim AADP-01 record syntax. The AADP author has
indicated that AADP-02 is expected to make the distinction explicit.

AADP does not define a portable schema for that internal authorization context. This fixture
therefore does not invent one. It records the value the PDP evaluated as a CycloneDX formulation
task input and uses native CycloneDX source, party, process, and citation references to preserve
where it came from.

The underlying property is protocol-neutral: evidence of an authorization decision must identify
the exact decision input and the provenance of every authorization-relevant field.

## Frozen inputs

- AADP: `draft-saha-aadp-01`, published 2026-08-20.
- CycloneDX: branch `2.0-dev`, commit
  `1a950b106df221c30cf208b4ffad3e5e1303385f`.
- E006: this repository at commit `dea23be5618625e1d40aba708ad62aae9934e7b5`.

URLs and content hashes are in
[`frozen-sources.json`](../vectors/input-provenance-v0.1/frozen-sources.json).

## Native CycloneDX mapping

| Evidence element | CycloneDX 2.0 representation |
|---|---|
| Tool surface | Component `tool-documents-read` plus SHA-256 hash |
| Policy | Data component `policy-input-provenance` plus SHA-256 hash |
| Full evaluation | Formulation workflow and `task-aadp-decision` |
| Decision-input field | Single-parameter task input named `organization` |
| Structural source | That input's `source.ref` |
| Supplying party | Source component's `parties[].bom-ref` |
| Exact field attribution | Citation JSON Pointer plus `attributedTo` |
| Generating process | Citation `process` reference to the decision task |
| Authorization verdict | Task evidence output containing `permit` / `passed` |
| Action and effect | Observed blueprint behavior instances |
| Record integrity | CycloneDX JSS whole-record signature |

No `properties` extension, Minority Prophet namespace, or parallel agent-evidence envelope is used.

## Classification rule

The verifier emits one of four values:

- `EXACT`: the exact field is structurally sourced and its citation binds the field pointer,
  supplying party, and decision process.
- `DERIVABLE`: a source exists for the single-field input wrapper, but no citation attributes the
  exact field.
- `AMBIGUOUS`: the field is cited, but its supplying party cannot be matched to the input source.
- `UNREPRESENTED`: the record carries neither a source edge nor field attribution.

Negative-control tests remove these edges one at a time and confirm all four outcomes.

## Run

```bash
PYTHONPATH=src python3 -m agent_trust_benchmark.input_provenance \
  vectors/input-provenance-v0.1/authority-sourced.cdx.json \
  vectors/input-provenance-v0.1/caller-sourced.cdx.json \
  --expect EXACT
```

The verifier uses OpenSSL to validate the JSS signatures. The fixture keys are the public test
keys in ITU-T X.590 Appendix II; they are test material and confer no production identity.

## Schema validation

Both records were validated with CycloneDX's own AJV 2020 validation setup against the modular
2.0 schemas at the frozen commit. The schema and behavior-taxonomy hashes are recorded in
`frozen-sources.json`.

## What this establishes

CycloneDX's current combination of formulation inputs, source references, parties, citations,
process references, behaviors, and signatures is expressive enough for this narrow distinction.
The smallest standards result is therefore compatibility evidence, not a schema proposal.

## What this does not establish

- AADP is an individual Internet-Draft with no adopted IETF working group or standards status.
- The fixture is not a complete AADP conformance test or wire transcript.
- A signature proves which key signed a record; it does not prove that the party labels are true.
  A deployment still has to authenticate the authority source and control the signing key.
- The fixture does not show that current agent gateways collect this provenance in production.
- CycloneDX or the AADP author may disagree with the mapping. That is why the artifact is being
  offered for review as an independent result.

## Publication sequence

1. Publish this reproducible fixture in Agent Trust Benchmark.
2. Link the result in CycloneDX issue #1016 as implementation evidence.
3. Send the same public link to the AADP author and ask whether the fixture accurately represents
   AADP-01's evidence and authenticated-context semantics.

The author is being asked for technical correction, not permission to conduct or publish an
independent test.
