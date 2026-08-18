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

## Amendment 2 — the Entra consent-origin arms

**Written before any Entra E001 run exists.**

Amendment 1 was written while configuring Okta and is specific to it. Entra needs the same
treatment, and one prediction below is only interesting because Okta already answered it
differently.

### Prior probe, and why it is not an E001 result

Before this amendment, the Entra tenant was exercised with **client credentials and application
permissions** to confirm the tenant, app registration, and Graph access worked at all. That probe
returned a token carrying `roles` and no human claim, and it read the directory audit log
successfully.

That probe is **not** an E001 delegation run and is not reported as one. The original mapping
excludes it by name: *"Not exercised as a delegation: app-only tokens and application
permissions."* It is recorded here so it cannot later be mistaken for a fitted result.

The probe did establish one fact used below: `GET /auditLogs/signIns` returns
`Authentication_RequestFromNonPremiumTenantOrB2CTenant` on this tenant's licence tier. That is a
measured access boundary, recorded before the runs rather than discovered during them.

### The two arms

- **Arm A — administrator-granted.** An `OAuth2PermissionGrant` with `consentType: "Principal"`
  bound to the human principal's object id, created by an administrator through Graph. Fully
  headless.
- **Arm B — user-consented.** The human principal authenticates in a browser and approves the
  delegated scope. Entra records a consent event.

**On the identity of the human principal.** A synthetic fixture user is preferred. The Okta run
could not use one — the fixture could not satisfy the tenant's MFA policy — and fell back to the
operator, pseudonymised as `human-1`. The same fallback is anticipated here and is recorded now so
it is not presented later as a choice made after seeing results. Either way the human is
pseudonymised in published evidence and the mapping is not published.

As with Okta, both arms hold client, scope, key, and enforcement point constant and differ only in
who created the grant.

### Predicted outcomes, recorded in advance

1. **Arm A is constructible on Entra, where it was not on Okta.** Okta returned `NOT_SUPPORTED`:
   its app-grants endpoint governs Okta API scopes only and refused a custom scope, so an
   administrator could not author a user's approval. Entra's `oauth2PermissionGrants` endpoint is
   documented to accept exactly that. If this holds, the two dominant enterprise platforms differ
   on whether administrator-authored consent is expressible at all — a platform-level finding, not
   a score.
2. **Arm A fails or is indeterminate on** `HUMAN_ATTRIBUTION_PROVABLE`, reproducing the ZITADEL
   result deliberately: the grant names a human as principal, but no evidence attributes the
   authorization decision to that human.
3. **Arm B passes** `HUMAN_ATTRIBUTION_PROVABLE` if, and only if, the consent event names the
   human as actor. Okta's did not — it recorded `system@okta.com` and the human was recoverable
   only by session correlation. Entra is predicted to name the human directly. If it does not,
   that is the more interesting result.
4. **`ACTION_AUDITABLE` is predicted `BLOCKED_EXTERNAL_ACCESS` on both arms**, on the measured
   licence boundary above. Per the status vocabulary this is an access limitation, not
   `NOT_SUPPORTED`: the interface does not say the capability is absent, it says the tenant may
   not read it.
5. **Every other check is identical across the arms.** If any other output differs, the arms were
   not held constant and the comparison is void.

Predictions 1, 3 and 5 are the falsifiable ones.

### Reporting

Arm B is the E001 result of record for Entra, per the original mapping. Arm A is reported
alongside it as a controlled comparison, not as a second provider score. Arm B requires a browser
step and is not fully headless; that is recorded as a reproducibility limitation rather than
worked around by substituting Arm A.
