# E001 result: entra-admin-consent

- Run: `e001-entra-admin-consent-v1`
- Started: `2026-08-19T02:25:16.844791Z`
- Completed: `2026-08-19T02:25:27.083008Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent has a distinct identity. |
| `DELEGATION_PROVABLE` | **PASS** | The human-to-agent delegation is provable. |
| `SCOPE_VISIBLE` | **PASS** | The granted preview scope is visible. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The allowed action succeeded exactly once. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | The forbidden action was blocked before effect. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **BLOCKED_EXTERNAL_ACCESS** | Sign-in logs are withheld by licence tier (Authentication_RequestFromNonPremiumTenantOrB2CTenant). Directory audits remain readable, but the agent's own action cannot be reconstructed from provider evidence on this tenant. This is an access limitation, not an absent capability, so it is not NOT_SUPPORTED. |
| `AGENT_ATTRIBUTION_PROVABLE` | **BLOCKED_EXTERNAL_ACCESS** | Sign-in logs are withheld by licence tier (Authentication_RequestFromNonPremiumTenantOrB2CTenant). Directory audits remain readable, but the agent's own action cannot be reconstructed from provider evidence on this tenant. This is an access limitation, not an absent capability, so it is not NOT_SUPPORTED. |
| `ACTION_AUDITABLE` | **BLOCKED_EXTERNAL_ACCESS** | Sign-in logs are withheld by licence tier (Authentication_RequestFromNonPremiumTenantOrB2CTenant). Directory audits remain readable, but the agent's own action cannot be reconstructed from provider evidence on this tenant. This is an access limitation, not an absent capability, so it is not NOT_SUPPORTED. |
| `REVOCATION_SUPPORTED` | **PASS** | The credential or delegation can be revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The action was blocked after revocation. |

## Metrics

- `REVOCATION_LATENCY_MS`: `7440.590143203735`
- `TOKEN_LIFETIME_SECONDS`: `None`
- `EVIDENCE_COMPLETENESS_PERCENT`: `70.0`

## Named limitations

- Neither arm is headless. The tenant's only human principal is an external B2B guest backed by a personal Microsoft account, so no non-interactive path to a delegated token exists and the authorization code was obtained in a browser. See docs/E001-DELEGATION-FLOW-MAPPING.md, Correction 1 to Amendment 2.
- Sign-in logs are withheld by licence tier on this tenant, so HUMAN_ATTRIBUTION_PROVABLE, AGENT_ATTRIBUTION_PROVABLE and ACTION_AUDITABLE all derive from an observation that could not be read. They are BLOCKED_EXTERNAL_ACCESS rather than failures.
- Directory audits are readable on this tenant and do name the human on consent events. That evidence is not scored here because all three attribution checks derive from the single audit observation that the licence gate blocked. Recorded as a limitation rather than resolved by changing shared harness code under already-published results.
- REVOCATION_LATENCY_MS measures time from the revocation call to the first proven removal of the grant, including Entra directory propagation. It does not measure invalidation of an already-issued access token, which remains valid until expiry.
- Entra's directory is eventually consistent in both directions: a newly created grant can reject an immediate delete, and a deleted grant can still read as present. Both operations poll to a bounded deadline so propagation is measured rather than reported as a failure.
- The issued token carries the human's object id, name and email alongside the agent's application id, yet no consent prompt was ever shown and no human approval event exists. The token is not distinguishable from one produced by genuine user consent. This is the substantive finding of this arm and is not captured by any single check.

No raw credential, token, signature, or private key is included in this result.
