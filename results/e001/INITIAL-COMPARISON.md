# E001 current comparison

Run date: 2026-08-11

| Exercised surface | Pass | Fail | Not supported | Indeterminate | Blocked | Evidence completeness |
|---|---:|---:|---:|---:|---:|---:|
| Neutral local baseline | 10 | 0 | 0 | 0 | 0 | 100% |
| Keycloak 26.7.0 + OPA 1.19.0 | 10 | 0 | 0 | 0 | 0 | 100% |
| ZITADEL 4.15.0 + OPA 1.19.0 | 9 | 1 | 0 | 0 | 0 | 100% |
| Okta | 0 | 0 | 0 | 0 | 10 | 0% |
| Microsoft Entra | 0 | 0 | 0 | 0 | 10 | 0% |

## What this means

The harness works: it can prove the complete path in its neutral baseline and
rejects both unauthorized actions and a tampered credential.

Keycloak proves the full path in this fixture, but its human/client binding uses
Direct Access Grants and its tested revocation is realm-wide. ZITADEL proves a
more granular service-account grant and revocation path, but its action token
does not prove which human authorized that service account. Both use the same
benchmark-owned OPA policy, so neither row is evidence of provider-native action
enforcement.

Okta and Entra have no score yet. Their rows record missing test access, not a
security result.

## Evidence directories

- `e001-baseline-21ae873b-a5d7-45ec-bcf7-20faea25acbb/`
- `e001-keycloak-opa-c96221c2-229c-4cb6-8514-8d6068c2faaa/`
- `e001-zitadel-opa-c7ce5a22-17ac-480c-ba26-a242219fbc13/`
- `e001-okta-8704dc94-a5f7-4ccf-a720-01c3b89bf77d/`
- `e001-entra-9b9f8846-5aaf-4466-9cfb-ecae4fc0e6cd/`

Each directory contains a machine-readable `result.json` and a human-readable
`SUMMARY.md`. No raw credential, token, private key, or signature is retained.
`RUN-REGISTER.md` identifies the accepted runs and preserves the excluded
engineering runs without quietly cherry-picking them.
