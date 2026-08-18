# E001 result: auth0

Run: `e001-auth0-v1`  
**Auth0 is owned by Okta. The two runs are reported separately and are not independent vendors.**

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The access token carries sub (the human) and azp (the agent client) as separate claims. |
| `DELEGATION_PROVABLE` | **PASS** | A grant object records the client, the human and the scope ['openid','payments:preview']. Qualified: see ACTION_AUDITABLE — the grant exists, but no audit event records its creation. |
| `SCOPE_VISIBLE` | **PASS** | The token carries scope and permissions claims. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | The authorization_code flow with PKCE issued a token bearing the delegated scope, and the token is accepted by a live Auth0 endpoint. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | Qualified, and the manner matters. Requesting the undelegated payments:execute was NOT refused: Auth0 presented a consent dialog listing no scopes at all, then issued a token with the scope silently stripped (scope returned 'openid'). The forbidden capability is absent from the token, so no effect is possible — but the human was prompted to approve a blank scope list and received no indication that the request had been downgraded. Contrast Okta, which refused the same request with access_denied and 'Policy evaluation failed' before issuing anything. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **PASS** | Stronger than Okta on this check. The tenant log names the human directly on both the login (type 's') and the code-for-token exchange (type 'seacft'), so attribution requires no cross-event correlation. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The token's azp claim names the client, and log entries carry client_name. |
| `ACTION_AUDITABLE` | **INDETERMINATE** | Auth0 emits no consent-specific event. Enumerating every log type in the tenant produced none relating to consent. A consent dialog was displayed and approved by a human, and the resulting grant object exists, but no audit record attests that the approval occurred or when. The action is auditable; the authorization decision is not. |
| `REVOCATION_SUPPORTED` | **PASS** | DELETE on the grant returned HTTP 204 and the user's grant list became empty. |
| `POST_REVOCATION_ACTION_BLOCKED` | **FAIL** | After the grant was revoked and confirmed absent, the previously issued access token was still accepted by Auth0's own /userinfo endpoint (HTTP 200, returning the subject). Revoking the grant prevents new tokens; it does not invalidate outstanding ones. This was exercised against a live endpoint, not inferred from token format. |

## Metrics

- `REVOCATION_ACK_LATENCY_MS`: `235.9`
- `POST_REVOCATION_TOKEN_STILL_ACCEPTED`: `True`
- `EVIDENCE_COMPLETENESS_PERCENT`: `90.0`

## Named limitations

- Auth0 is owned by Okta. This is not an independent second vendor and must not be counted as one.
- The tenant was in a 22-day trial during this run. Features exercised were not verified as free-plan-only, so reproducibility on the free plan is unconfirmed.
- A third-party client was created first, because third-party status is what makes consent mandatory in Auth0. It could not access the custom API: 'Client is not authorized to access resource server', persisting after an explicit client grant. A first-party client identical in every other respect reached the login page, isolating is_first_party as the variable. The third-party path is therefore recorded as unavailable for custom API scopes in this configuration rather than as a benchmark error.
- Consent was displayed for the first-party client because the resource server's skip_consent_for_verifiable_first_party_clients is false. Consent behaviour is governed by the API, not by client type alone.
- The human principal is a synthetic fixture user, pseudonymised as human-1.
- RBAC was enabled on the resource server (enforce_policies, access_token_authz), so the token carries a permissions claim. In the forbidden-scope run the token carried permissions ['payments:preview'] while scope was only 'openid' — the two claims disagreed about what had been authorized.
- The post-revocation test exercised /userinfo, an Auth0 endpoint. A separate resource server enforcing the custom audience was not stood up.

No raw credential, token, signature, or private key is included in this result.
