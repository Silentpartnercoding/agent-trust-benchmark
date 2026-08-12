# E001 result: zitadel-opa

- Run: `e001-zitadel-opa-c7ce5a22-17ac-480c-ba26-a242219fbc13`
- Started: `2026-08-11T17:05:41.841892Z`
- Completed: `2026-08-11T17:05:42.004418Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **FAIL** | Human attribution was not proven. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The action is attributable to the authenticated agent identity at the exercised enforcement point. |
| `ACTION_AUDITABLE` | **PASS** | The action can be reconstructed from audit evidence. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `8.986042346805334`
- `TOKEN_LIFETIME_SECONDS`: `43199`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

## Named limitations

- ZITADEL supplies identity, grant, token, introspection, and change-history evidence; OPA is the benchmark-owned enforcement point.
- The human-to-agent link is administrator-authored metadata, not interactive consent or a human claim cryptographically bound into the action token.
- The opaque token is long-lived; the fast post-revocation block depends on online introspection at every exercised action.

No raw credential, token, signature, or private key is included in this result.
