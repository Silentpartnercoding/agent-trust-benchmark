# E001 result: zitadel-opa

- Run: `e001-zitadel-opa-a0584a5b-2852-4a96-8764-54d1387ed4b3`
- Started: `2026-08-11T17:05:04.614248Z`
- Completed: `2026-08-11T17:05:05.296944Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **FAIL** | Human attribution was not proven. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the verified agent key at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `55.36020826548338`
- `TOKEN_LIFETIME_SECONDS`: `43199`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

## Named limitations

- ZITADEL supplies identity, grant, token, introspection, and change-history evidence; OPA is the benchmark-owned enforcement point.
- The human-to-agent link is administrator-authored metadata, not interactive consent or a human claim cryptographically bound into the action token.
- The opaque token is long-lived; the fast post-revocation block depends on online introspection at every exercised action.

No raw credential, token, signature, or private key is included in this result.
