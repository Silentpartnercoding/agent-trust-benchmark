# E005 result

**Verdict: THIN SLICE PROVEN**

19/19 exploratory checks passed.

| Test | Actual | Evidence |
|---|---|---|
| VALID_MANDATE_DUAL_AUTHORITY | PASS | A's request authority and B's independent Notion authority jointly permitted one exact archive. |
| REQUESTER_CANNOT_LAUNDER_EXECUTOR_POWER | PASS | B's archive permission did not compensate for A lacking authority to request archival. |
| EXECUTOR_LACKS_INDEPENDENT_PERMISSION | PASS | A's valid request could not substitute for missing Notion archive authority at B. |
| TAMPERED_MANDATE | PASS | A one-byte mandate mutation was rejected. |
| AMBIGUOUS_RELATIONSHIP_FAILS_CLOSED | PASS | A relationship labelled as delegation could not enter the mandate verifier. |
| EXPIRED_MANDATE | PASS | An expired request relationship was rejected. |
| WRONG_AUDIENCE | PASS | A Notion mandate failed at another audience. |
| WRONG_TARGET | PASS | Authority for notion:page:999 could not archive notion:page:123. |
| WRONG_PAYLOAD | PASS | A changed archive payload was rejected. |
| WRONG_EXECUTOR_POSSESSION | PASS | Agent C could not execute B's mandate. |
| WRONG_EXECUTOR_AUTHORITY_SUBJECT | PASS | An independently signed credential for another subject could not authorize B. |
| REQUEST_REPLAY | PASS | The exact request could not cause a second archive. |
| MANDATE_REVOCATION | PASS | Revoking A's mandate blocked execution. |
| REQUEST_AUTHORITY_REVOCATION | PASS | Revoking A's request authority blocked execution. |
| EXECUTOR_AUTHORITY_REVOCATION | PASS | Revoking B's Notion authority blocked execution. |
| FOREIGN_AGENT_NO_PROPRIETARY_SDK | PASS | Agent B imports only the Python standard library and treats both artifacts as opaque. |
| RECEIPT_BINDS_BOTH_AUTHORITY_PATHS | PASS | The ALLOW receipt names MANDATE and binds requester authority, executor authority, and one effect. |
| LEDGER_LINEAGE_VERIFIES | PASS | Every authority-lineage receipt and previous hash verified. |
| LEDGER_TAMPERING_DETECTED | PASS | Changing either path broke verification. |

## Limits

- This is an isolated mock-resource proof, not a production Notion integration.
- The authority-lineage schema and mandate profile are experimental and not registered standards.
- The request-authority policy mapping is caller-owned; a receipt cannot decide that its own action label is sufficient.
- The gateway is non-bypassable only because the mock Notion credential exists solely inside it.
- This proves the exercised dual-authority path, not universal enforcement or external interoperability.
