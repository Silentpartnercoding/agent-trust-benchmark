# E002 run register

Only the accepted current runs are used in the comparison.

| Provider | Accepted run | Status |
|---|---|---|
| Reference verifier | `REFERENCE-RESULT.md` | 18/18 expected outcomes |
| Keycloak + OPA | `e002-keycloak-baad0a6e-5f6c-4f86-815d-7037da9e1f28` | 14 pass, 0 fail |
| ZITADEL + OPA | `e002-zitadel-1cebd3a7-8082-48a4-a494-b75f91b4d7e5` | 12 pass, 2 fail-safe gaps |

Earlier E002 directories are development runs and are superseded by the two
accepted provider runs above.
