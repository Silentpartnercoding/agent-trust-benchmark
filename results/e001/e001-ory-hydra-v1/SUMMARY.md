# E001 result: ory-hydra

Run: `e001-ory-hydra-v1`  
Class: pure OAuth2 authorization server (no user management)

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | Introspection returns sub=human-1 and client_id=atb-e001-agent as separate fields. |
| `DELEGATION_PROVABLE` | **PASS** | A consent session is recorded with grant_scope and handled_at. Qualified: see HUMAN_ATTRIBUTION_PROVABLE — the delegation is recorded, but its human root is asserted by the consent app, not established by Hydra. |
| `SCOPE_VISIBLE` | **PASS** | Introspection returns scope 'openid payments:preview'. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The authorization_code flow completed and issued an active token bearing exactly the delegated scope. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | Requesting payments:execute, which is not among the client's registered scopes, was refused with error=invalid_scope before any code was issued. Provider-native refusal. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **INDETERMINATE** | The token names the human directly: sub=human-1 plus four custom claims the consent app wrote into ext. The record is fully self-contained. But Hydra does not manage users and does not authenticate anyone; it stored the subject string the login app handed it. Nothing in Hydra's evidence backs the claim that human-1 exists, is a person, or consented. Attribution is present and unverifiable, which is neither PASS nor FAIL. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The client authenticated with client_secret_post and introspection names it. Weaker than a private_key_jwt confidential client. |
| `ACTION_AUDITABLE` | **INDETERMINATE** | Hydra exposes the consent session and introspection, but emits no audit event stream of its own. The only action log in this run is the one the benchmark's consent app wrote, which is a benchmark-generated observation, not a provider-native receipt. |
| `REVOCATION_SUPPORTED` | **NOT_SUPPORTED** | Not exercised in this run. Hydra exposes consent-session revocation via its admin API, but this run did not reach it; reported as unexercised rather than inferred. |
| `POST_REVOCATION_ACTION_BLOCKED` | **NOT_SUPPORTED** | Not exercised; no revocation was performed. |

## Metrics

- `EVIDENCE_COMPLETENESS_PERCENT`: `60.0`
- `HEADLESS`: `True`
- `BROWSER_REQUIRED`: `False`

## Named limitations

- Hydra is not an identity provider. It delegates login and consent to an application the operator writes, so every attribution claim in this result was authored by the benchmark's own consent app. That is a property of the system under test, not a shortcoming of the run.
- The consent app is included in the repository so the claims it writes are inspectable. It is a benchmark-generated observation and is not presented as a provider-native receipt.
- The subject is the pseudonym human-1. No real human authenticated; Hydra has no mechanism by which one could have.
- Client authentication is client_secret_post rather than private_key_jwt, so the agent-side evidence is weaker than the Okta run.
- Revocation was not exercised. Two checks are NOT_SUPPORTED on that basis rather than inferred from the admin API's existence.
- In-memory DSN, single client, single scope pair, --dev mode. No claim about production Hydra deployments.

No raw credential, token, signature, or private key is included in this result.
