# E001 result: ory-hydra

- Run: `e001-ory-hydra-replay-v1`
- Started: `2026-08-19T05:36:13.453780Z`
- Completed: `2026-08-19T05:36:13.553230Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **NOT_SUPPORTED** | Hydra exposes no audit or event log for actions taken under an issued token. The only action record available is the benchmark consent application's own log, which is a benchmark-generated observation and is not a provider-native receipt. |
| `AGENT_ATTRIBUTION_PROVABLE` | **NOT_SUPPORTED** | Hydra exposes no audit or event log for actions taken under an issued token. The only action record available is the benchmark consent application's own log, which is a benchmark-generated observation and is not a provider-native receipt. |
| `ACTION_AUDITABLE` | **NOT_SUPPORTED** | Hydra exposes no audit or event log for actions taken under an issued token. The only action record available is the benchmark consent application's own log, which is a benchmark-generated observation and is not a provider-native receipt. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `1.1129379272460938`
- `TOKEN_LIFETIME_SECONDS`: `None`
- `EVIDENCE_COMPLETENESS_PERCENT`: `70.0`

No raw credential, token, signature, or private key is included in this result.
