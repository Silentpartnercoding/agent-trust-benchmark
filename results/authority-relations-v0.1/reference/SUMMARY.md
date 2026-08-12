# Authority Relations v0.1 result

**Invariant:** REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE

| Adapter | Passed | Total |
|---|---:|---:|
| `delegation_only.py` | 4 | 8 |
| `relation_aware.py` | 8 | 8 |

## delegation_only.py

| Vector | Outcome | Mismatch |
|---|---|---|
| AR-001-VALID-DELEGATION | PASS | — |
| AR-002-VALID-MANDATE | FAIL | authorized, declared_relation_matches, derived_authority_relation, execution_authority_source, immediate_authority_grantor, reason |
| AR-003-UNAUTHORIZED-REQUESTER | FAIL | declared_relation_matches, derived_authority_relation, execution_authority_source, immediate_authority_grantor |
| AR-004-UNAUTHORIZED-EXECUTOR | PASS | — |
| AR-005-NO-AUTHORITY | PASS | — |
| AR-006-SPOOFED-DELEGATION | PASS | — |
| AR-007-RELATIONSHIP-MISMATCH | FAIL | declared_relation_matches, derived_authority_relation, execution_authority_source, immediate_authority_grantor, reason |
| AR-008-PERMISSIONLESS-REQUEST | FAIL | authorized, declared_relation_matches, derived_authority_relation, execution_authority_source, immediate_authority_grantor, reason |

## relation_aware.py

| Vector | Outcome | Mismatch |
|---|---|---|
| AR-001-VALID-DELEGATION | PASS | — |
| AR-002-VALID-MANDATE | PASS | — |
| AR-003-UNAUTHORIZED-REQUESTER | PASS | — |
| AR-004-UNAUTHORIZED-EXECUTOR | PASS | — |
| AR-005-NO-AUTHORITY | PASS | — |
| AR-006-SPOOFED-DELEGATION | PASS | — |
| AR-007-RELATIONSHIP-MISMATCH | PASS | — |
| AR-008-PERMISSIONLESS-REQUEST | PASS | — |

## Claim boundary

- Synthetic black-box conformance evidence only.
- No external protocol or provider was tested.
- Evidence classification is evaluated separately from the supplied policy verdict.
- This suite evaluates post-verification semantics; it does not verify signatures or credential provenance.
