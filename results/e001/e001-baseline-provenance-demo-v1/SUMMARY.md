# E001 result: baseline

- Run: `e001-baseline-provenance-demo-v1`
- Started: `2026-08-19T14:39:07.562692Z`
- Completed: `2026-08-19T14:39:07.562984Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the human principal. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the authenticated agent identity at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `0.016666948795318604`
- `TOKEN_LIFETIME_SECONDS`: `300`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

No raw credential, token, signature, or private key is included in this result.
