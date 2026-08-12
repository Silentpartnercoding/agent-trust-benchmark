# E001 result: baseline

Run: `e001-baseline-21ae873b-a5d7-45ec-bcf7-20faea25acbb`
Started: `2026-08-11T16:34:04.206055Z`
Completed: `2026-08-11T16:34:04.206428Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the human principal. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the verified agent key at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `0.016834121197462082`
- `TOKEN_LIFETIME_SECONDS`: `300`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

No raw credential, token, signature, or private key is included in this result.
