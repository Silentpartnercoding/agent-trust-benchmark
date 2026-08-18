# E001 result: okta-user-consent

Run: `e001-okta-user-consent-v1`  
Arm: B (user-consented)

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The access token carries cid (the agent client) and uid (the human) as separate claims; the agent identity is not the human's. |
| `DELEGATION_PROVABLE` | **PASS** | A scope consent grant for payments:preview exists against human-1, created by the human approving the scope interactively. |
| `SCOPE_VISIBLE` | **PASS** | The token's scp claim is ['openid','payments:preview']. The undelegated payments:execute is absent. |
| `ALLOWED_ACTION_SUCCEEDS` | **PASS** | An authorization code was issued and exchanged for an access token bearing exactly the delegated scope. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | Requesting payments:execute was refused by the authorization server with access_denied and 'Policy evaluation failed for this request'. No code was issued and no effect occurred. The refusal is provider-native, not produced by a benchmark-owned gate. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **PASS** | Qualified. The token binds the human as sub/uid, so the credential the action carries names the human. However the app.oauth2.as.consent.grant event records actor=system@okta.com (SystemPrincipal) and carries no user target; the human is recoverable only by correlating externalSessionId across the session's events, where exactly one User actor appears. Attribution is reconstructible, not self-contained. |
| `AGENT_ATTRIBUTION_PROVABLE` | **PASS** | The token's cid claim names the confidential client, which authenticated by private_key_jwt; app.oauth2.as.authorize.code records the client as actor. |
| `ACTION_AUDITABLE` | **PASS** | The System Log reconstructs sign-on, MFA, consent grant and authorization code issuance for the session. |
| `REVOCATION_SUPPORTED` | **PASS** | DELETE on the user's grant returned HTTP 204 and the user's grant list became empty. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The identical authorize request that redirected straight through before revocation returned the consent prompt afterwards, and no code was issued. The block is by re-consent requirement rather than denial; it is attributed to the revocation because nothing else changed between the two requests. |

## Metrics

- `REVOCATION_ACK_LATENCY_MS`: `277.1`
- `POST_REVOCATION_BLOCK_CONFIRMED`: `True`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

## Named limitations

- Arm B is not headless. The human authorization step requires an interactive browser session with MFA; this run could not be executed end to end without a person present. That is a reproducibility limitation and is not worked around by substituting an administrator-created grant.
- The authorization server policy permits payments:preview and omits payments:execute, so the forbidden action is refused by Okta at token issuance rather than by a benchmark-owned enforcement point. This is stronger provider-native evidence than the Keycloak and ZITADEL runs, and it also means FORBIDDEN_ACTION_BLOCKED is not strictly comparable across those three providers.
- The human principal is the operator of this benchmark rather than a synthetic fixture user. A fixture user was created but could not satisfy the org's MFA sign-on policy, and its authentication failed. The operator's identity is pseudonymised as 'human-1' in this result; the mapping is not published.
- REVOCATION_ACK_LATENCY_MS measures the revocation API acknowledgement, not the time from revocation to first proven block. The two are not comparable to the Keycloak and ZITADEL revocation latencies, which timed the proven block.
- Single authorization server, single client, single scope pair. No claim is made about other Okta configurations.

No raw credential, token, signature, or private key is included in this result.
