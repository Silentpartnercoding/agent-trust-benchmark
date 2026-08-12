# E004 result

**Verdict: PARTIALLY SOLVED**

16/16 exploratory checks passed.

| Test | Actual | Evidence |
|---|---|---|
| VALID_DELEGATION | PASS | H -> A -> B create_page reached the mock resource exactly once. |
| FORBIDDEN_READ_PAGE | PASS | read_page was denied before the resource. |
| FORBIDDEN_ARCHIVE_PAGE | PASS | archive_page was denied before the resource. |
| FORBIDDEN_ADMIN_WORKSPACE | PASS | admin_workspace was denied before the resource. |
| PARENT_SCOPE_ESCALATION | PASS | A could not delegate authority it lacked. |
| TAMPERED_DELEGATION | PASS | A one-byte token mutation was rejected. |
| EXPIRED_DELEGATION | PASS | Expired child authority was rejected. |
| WRONG_AUDIENCE | PASS | A Notion delegation failed at another audience. |
| WRONG_SUBJECT_POSSESSION | PASS | Agent C could not use B's subject-bound token. |
| REDELEGATION_DISABLED | PASS | B could not delegate to C when depth was zero. |
| REQUEST_REPLAY | PASS | The same request id could not create a second page. |
| CHILD_REVOCATION | PASS | Revoked A -> B delegation failed closed. |
| PARENT_REVOCATION_CASCADE | PASS | Revoked H -> A authority invalidated B's chain. |
| FOREIGN_AGENT_NO_PROPRIETARY_SDK | PASS | Agent B imports only the Python standard library and treats delegation as opaque. |
| LEDGER_LINEAGE_VERIFIES | PASS | Every authority receipt signature and previous hash verified. |
| LEDGER_TAMPERING_DETECTED | PASS | Changing history broke verification. |

## Limits

- The authority-lineage ledger and A-to-B token are isolated benchmark extensions, not current Knowledge Ledger behavior.
- The gateway is non-bypassable only because the mock resource credential exists solely inside it.
- This is one-controller exploratory evidence, not external interoperability or production validation.
- The token uses standard Ed25519 compact JWS mechanics but an experimental claim profile, not a registered standard.
