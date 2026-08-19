# E001 result: okta-admin-consent

- Run: `e001-okta-admin-consent-replay-v1`
- Started: `2026-08-19T05:31:41.846496Z`
- Completed: `2026-08-19T05:31:43.071761Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **NOT_SUPPORTED** | Okta exposes no administrative path to create a user consent grant for a custom authorization server scope. The app grants endpoint governs Okta API scopes only, and rejected payments:preview as an invalid scopeId. An administrator cannot author this human's approval. |
| `SCOPE_VISIBLE` | **INDETERMINATE** | no credential to inspect. |
| `ALLOWED_ACTION_SUCCEEDS` | **INDETERMINATE** | no credential; allowed action not attempted. |
| `FORBIDDEN_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | forbidden action not attempted. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **FAIL** | Human attribution was not proven. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the authenticated agent identity at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **INDETERMINATE** | no grant recorded to revoke. |
| `POST_REVOCATION_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | post-revocation attempt not run. |

## Metrics

- `REVOCATION_LATENCY_MS`: `None`
- `TOKEN_LIFETIME_SECONDS`: `None`
- `EVIDENCE_COMPLETENESS_PERCENT`: `40.0`

No raw credential, token, signature, or private key is included in this result.
