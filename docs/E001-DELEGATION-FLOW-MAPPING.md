# E001 delegation-flow mapping

**Written before the Okta and Entra runs, and before any result from them exists.**

E001 is preregistered. Deciding *after* seeing results which authorization flow counts as a
human-to-agent delegation would let the choice be fitted to the outcome. This document fixes that
choice in advance, and states plainly what a negative result would look like so it cannot later be
reframed as a harness problem.

## The bar, restated

`DELEGATION_PROVABLE` and `HUMAN_ATTRIBUTION_PROVABLE` ask whether an independent observer can
establish **which human authorized this exact agent authority**, from evidence the provider emits.

The bar already applied to the exercised providers:

- **Keycloak + OPA — PASS.** The token names the human as subject and the confidential agent
  client as authorized party, so both identities survive into the allow and deny decisions. The
  run also records that Direct Access Grants is a *measurement mechanism, not a production
  recommendation*, and that the grant is administrator-configured rather than an interactive
  consent record.
- **ZITADEL + OPA — FAIL.** The human-to-agent link is administrator-authored metadata: not
  interactive consent, and not a human claim cryptographically bound into the action token.

The operative distinction is therefore **bound into the credential the action carries** versus
**recorded beside it in administrative configuration**.

## What will be exercised

### Okta

**Exercised:** the authorization-code flow with interactive user consent. The human authenticates,
consents to a scope limited to `payments:preview`, and the resulting token names the human as
subject and the agent client as authorized party.

**Not exercised as a delegation:** the client-credentials / service-app flow. It has no human in
the loop by construction, so it cannot evidence a human-to-agent delegation whatever else it
proves. This is already recorded in `PROVIDER_ACCESS.md`: *"Okta's service-app flow is not treated
as proof of human-to-agent delegation by itself."*

### Microsoft Entra

**Exercised:** delegated permissions with recorded user consent (`OAuth2PermissionGrant`). The
resulting token carries both the human and the calling application as distinct claims.

**Not exercised as a delegation:** app-only tokens and application permissions. Per
`PROVIDER_ACCESS.md`: *"An app-only token is not treated as proof of a human delegation unless the
human authorization event is independently bound."*

## Predicted outcomes, recorded in advance

Stated now so that neither result can be presented later as a surprise or as vindication:

1. **Both platforms may pass** `DELEGATION_PROVABLE` via the consent flow, since consent produces
   a durable record naming the human.
2. **Both may still fail or be indeterminate on** `HUMAN_ATTRIBUTION_PROVABLE` **at the point of
   action**, if the token presented at the enforcement point carries the human only by reference
   to a consent grant held elsewhere, rather than as a claim bound into that token.
3. A `NOT_SUPPORTED` on either is an acceptable and interesting result. If the two dominant
   enterprise IAM platforms cannot produce independently verifiable evidence that a specific human
   authorized a specific agent action, that is a finding about the state of the field, not a
   defect in this benchmark.

## What would invalidate a run

- Substituting a different flow after seeing a result.
- Reporting `FAIL` where the surface was not exercised. That is `BLOCKED_EXTERNAL_ACCESS`.
- Reporting `NOT_SUPPORTED` where the interface does not make the boundary explicit. That is
  `INDETERMINATE`.
- Treating a benchmark-owned enforcement point's observation as a provider-native receipt.

## Audit evidence

Attribution must come from provider-native audit surfaces — Okta System Log, Entra sign-in and
audit logs — not from the benchmark's own gate observations. Where that surface is unavailable
under the tenant tier in use, the correct output is `BLOCKED_EXTERNAL_ACCESS` with the tier named,
not a lower score.

---

## Amendment 1 — the consent-origin arms

**Written before either Okta run exists.**

Configuring the Okta tenant surfaced something the original mapping did not anticipate. Okta's
consent requirement can be satisfied two ways, and they are not equivalent evidence:

- **Arm A — administrator-granted.** `POST /api/v1/apps/{id}/grants` creates the scope consent
  grant as an administrator. The flow becomes fully headless.
- **Arm B — user-consented.** The human authenticates and approves the scope in a browser. Okta
  records a consent event attributable to that user.

Both produce a token bearing the same scope. They differ only in **who created the grant**.

### Why this is worth running twice

That difference is exactly what separated the two providers already measured. Keycloak passed
`HUMAN_ATTRIBUTION_PROVABLE`; ZITADEL failed it because the human-to-agent link was
administrator-authored metadata rather than an interactive consent record. Those were two
platforms differing in many ways at once, so the mechanism was inferred rather than shown.

Running both arms against **one** platform, holding client, scope, policy, key and enforcement
point constant, isolates consent origin as the single variable.

### Predicted outcomes, recorded in advance

1. **Arm A fails or is indeterminate on** `HUMAN_ATTRIBUTION_PROVABLE`. The grant names a human
   as subject, but no evidence attributes the authorization decision to that human — an
   administrator made it. This is the ZITADEL result reproduced deliberately.
2. **Arm B passes it**, because Okta records a consent event whose actor is the human.
3. **Every other check is identical across the arms.** If any other output differs, the arms were
   not held constant and the comparison is void.

Prediction 3 is the falsifiable one. It is the reason to record both arms rather than assert the
mechanism.

### Reporting

Arm B is the E001 result of record for Okta, per the original mapping: interactive consent is the
flow this benchmark treats as a human-to-agent delegation. Arm A is reported alongside it as a
controlled comparison, not as a second provider score.

Arm B requires a browser step and is therefore not fully headless. That is a reproducibility
limitation and is recorded in the result, not worked around by substituting Arm A.
