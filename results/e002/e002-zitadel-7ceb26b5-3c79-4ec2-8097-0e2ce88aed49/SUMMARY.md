# E002 result: zitadel

- Run: `e002-zitadel-7ceb26b5-3c79-4ec2-8097-0e2ce88aed49`
- Authorization mode observed: `administrator_configured`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `TRUSTED_ISSUER_PROVEN` | **PASS** | The detached Ed25519 JWS verifies under the caller-trusted receipt-issuer key. |
| `HUMAN_AUTHORIZATION_WITNESSED` | **FAIL** | Only an administrator-configured relationship was observed; interactive human authorization was not proven. |
| `AGENT_IDENTITY_BOUND` | **PASS** | The verified action credential and receipt name the same agent identity. |
| `AGENT_KEY_BOUND` | **PASS** | The agent proved possession of the key bound by the receipt and credential. |
| `CREDENTIAL_RECEIPT_BOUND` | **PASS** | The signed action credential carries the exact signed-receipt digest. |
| `AUDIENCE_BOUND` | **PASS** | Receipt and credential address the exercised payments gate. |
| `ALLOWED_ACTION_SUCCEEDS` | **FAIL** | Preview was safely denied because the required human witness was absent. |
| `FORBIDDEN_ACTION_BLOCKED` | **PASS** | Execute was rejected before effect. |
| `RECEIPT_SWAP_BLOCKED` | **PASS** | A newly signed but differently digested receipt could not be paired with the existing credential. |
| `UNAVAILABLE_REVOCATION_FAILS_CLOSED` | **PASS** | An unavailable revocation answer remained visibly indeterminate and produced no effect. |
| `ADMIN_LABEL_REJECTED_AS_CONSENT` | **PASS** | A signed administrator-configured label did not satisfy an interactive-consent policy. |
| `REVOCATION_SUPPORTED` | **PASS** | The receipt was valid before its receipt-specific handle was revoked. |
| `POST_REVOCATION_ACTION_BLOCKED` | **PASS** | The next preview attempt was rejected after receipt revocation. |
| `FULL_PATH_AUDITABLE` | **PASS** | Provider witness references, receipt ID, credential ID, and gate outcomes form one reconstructable path. |

## Metrics

- `REVOCATION_LATENCY_MS`: `5.198250059038401`
- `RECEIPT_LIFETIME_SECONDS`: `300`
- `EVIDENCE_COMPLETENESS_PERCENT`: `100.0`

## Named limitations

- The current ZITADEL fixture proves an administrator-authored link and role grant, not an interactive human authorization event.
- The receipt issuer and short-lived action credential authority are benchmark-owned neutral components, not provider-native features.
- Provider bearer tokens, JWS values, signatures, private keys, and raw proofs are not retained.

No raw token, credential, signature, proof, or private key is retained.
