# E001 result: okta-user-consent

- Run: `e001-okta-user-consent-replay-v1`
- Started: `2026-08-19T05:53:54.386370Z`
- Completed: `2026-08-19T05:53:56.393369Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | forbidden action not attempted. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **FAIL** | Human attribution was not proven. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the authenticated agent identity at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | post-revocation attempt not run. |

## Metrics

- `REVOCATION_LATENCY_MS`: `None`
- `TOKEN_LIFETIME_SECONDS`: `None`
- `EVIDENCE_COMPLETENESS_PERCENT`: `80.0`

No raw credential, token, signature, or private key is included in this result.
