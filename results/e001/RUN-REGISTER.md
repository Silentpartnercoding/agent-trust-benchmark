# E001 run register

This register distinguishes accepted comparison evidence from engineering runs.
It prevents a later reader from silently selecting whichever local result looks
best.

## Accepted comparison runs

- Neutral baseline: `e001-baseline-21ae873b-a5d7-45ec-bcf7-20faea25acbb`
- Keycloak + OPA: `e001-keycloak-opa-c96221c2-229c-4cb6-8514-8d6068c2faaa`
- ZITADEL + OPA: `e001-zitadel-opa-c7ce5a22-17ac-480c-ba26-a242219fbc13`
- Okta, user consent: `e001-okta-user-consent-v1`
- Auth0: `e001-auth0-v1`
- Ory Hydra: `e001-ory-hydra-v1`
- Microsoft Entra, user consent: `e001-entra-user-consent-v1`

## Controlled comparison arms

These are not second provider scores. Each isolates consent origin against the accepted run
above it, holding client, scope and enforcement point constant. See
`docs/E001-DELEGATION-FLOW-MAPPING.md`, Amendments 1 and 2.

- Okta, administrator consent: `e001-okta-admin-consent-v1` — the arm could not be
  constructed; Okta exposes no administrative path to author a user's consent for a custom
  authorization server scope.
- Microsoft Entra, administrator consent: `e001-entra-admin-consent-v1`

## Superseded by a later measurement

These recorded `BLOCKED_EXTERNAL_ACCESS` on all ten outputs because no test tenant was
configured at the time. That was an accurate statement of what had been measured on
2026-08-11, not a security result. Both providers have since been exercised. The runs are
retained so the earlier published comparison remains checkable against the evidence that
existed when it was written.

- Okta access-boundary run: `e001-okta-8704dc94-a5f7-4ccf-a720-01c3b89bf77d`
- Entra access-boundary run: `e001-entra-9b9f8846-5aaf-4466-9cfb-ecae4fc0e6cd`

## Engineering runs excluded from the comparison

- `e001-keycloak-opa-1d6281df-4317-4d86-8ff7-981c4583713f` ran before the
  Direct Access Grant and broad-revocation limitations were added to the
  result itself.
- `e001-keycloak-opa-1dd56a27-5c1e-49ec-b853-cf01536b2eff` ran before the
  generic agent-attribution wording was corrected from “key” to “identity.”
- `e001-zitadel-opa-4693bf52-b75c-44da-9bbb-5d34a5023949` and
  `e001-zitadel-opa-a0584a5b-2852-4a96-8764-54d1387ed4b3` ran before the
  revocation timer was aligned exactly with the preregistered acknowledgement
  boundary and before all limitations were embedded in the result.

The excluded runs are retained as an audit trail, not used as evidence for the
comparison, and contain no raw credential, token, secret, private key, or full
signature.
