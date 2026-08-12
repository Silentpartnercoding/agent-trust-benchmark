# Authority Relations v0.1 result

**Invariant:** REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE

| Adapter | Passed | Total |
|---|---:|---:|
| `delegation_only.py` | 4 | 7 |
| `relation_aware.py` | 7 | 7 |

## delegation_only.py

| Vector | Outcome | Mismatch |
|---|---|---|
| AR-001-VALID-DELEGATION | PASS | — |
| AR-002-VALID-MANDATE | FAIL | authority_relation, execution_authority_source, immediate_authority_grantor, reason |
| AR-003-UNAUTHORIZED-REQUESTER | FAIL | authority_relation, execution_authority_source, execution_authority_valid, immediate_authority_grantor |
| AR-004-UNAUTHORIZED-EXECUTOR | PASS | — |
| AR-005-NO-AUTHORITY | PASS | — |
| AR-006-SPOOFED-DELEGATION | PASS | — |
| AR-007-RELATIONSHIP-MISMATCH | FAIL | authority_relation, authorized, execution_authority_source, immediate_authority_grantor, reason |

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

## Claim boundary

- Synthetic black-box conformance evidence only.
- No external protocol or provider was tested.
- ALLOW is correct only when the authority relation and both required authority paths are correct.
