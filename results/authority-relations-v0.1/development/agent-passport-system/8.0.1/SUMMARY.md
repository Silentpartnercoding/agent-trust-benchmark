# Authority Relations v0.1 result

**Invariant:** REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE

| Adapter | Passed | Total |
|---|---:|---:|
| `aps_adapter.py` | 0 | 8 |

## aps_adapter.py

| Vector | Outcome | Mismatch |
|---|---|---|
| AR-001-VALID-DELEGATION | FAIL | reason |
| AR-002-VALID-MANDATE | UNSUPPORTED | authorized, declared_relation_matches, derived_authority_relation, evidence_status, execution_authority_source, execution_authority_valid, immediate_authority_grantor, reason, request_authority_source, request_authority_valid, status |
| AR-003-UNAUTHORIZED-REQUESTER | UNSUPPORTED | declared_relation_matches, derived_authority_relation, evidence_status, execution_authority_source, execution_authority_valid, immediate_authority_grantor, reason, status |
| AR-004-UNAUTHORIZED-EXECUTOR | UNSUPPORTED | declared_relation_matches, evidence_status, reason, request_authority_source, request_authority_valid, status |
| AR-005-NO-AUTHORITY | UNSUPPORTED | declared_relation_matches, reason, status |
| AR-006-SPOOFED-DELEGATION | FAIL | reason |
| AR-007-RELATIONSHIP-MISMATCH | UNSUPPORTED | declared_relation_matches, derived_authority_relation, evidence_status, execution_authority_source, execution_authority_valid, immediate_authority_grantor, reason, request_authority_source, request_authority_valid, status |
| AR-008-PERMISSIONLESS-REQUEST | FAIL | reason |

## Claim boundary

- Synthetic black-box conformance evidence only.
- No external protocol or provider was tested.
- Evidence classification is evaluated separately from the supplied policy verdict.
- This suite evaluates post-verification semantics; it does not verify signatures or credential provenance.
