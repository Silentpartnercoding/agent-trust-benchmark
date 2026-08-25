# CDX-AADP-INPUT-PROVENANCE-001 result

**Classification: EXACT**

The frozen CycloneDX 2.0 development model preserves the difference between an identical
authorization field supplied by authenticated authority state and by the caller.

- Tool SHA-256: identical.
- Policy SHA-256: identical.
- Evaluated `organization` value: `org-b` in both records.
- Verdict: `permit` / `passed` in both records.
- Whole-record Ed25519 JSS signatures: valid in both records.
- Non-provenance projection: identical.
- Source edge and attributed party: different and field-addressable.

The decisive native mechanism is a CycloneDX citation pointing to the exact formulation parameter
value and binding it to both the supplying party and the decision task. Removing the citation
reduces the result to `DERIVABLE`; retaining only process attribution makes it `AMBIGUOUS`; removing
both source and citation makes it `UNREPRESENTED`.

This is a synthetic representability result, not evidence of AADP adoption, CycloneDX endorsement,
or a production deployment.
