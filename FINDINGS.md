# Findings

What has actually been measured, and what it shows. Every claim links to a run under
[`results/`](results/).

**Two kinds of run appear there, and they are not equally checkable.** Most were emitted by the
harness and carry raw evidence references and machine timestamps. Four — both Okta arms, Auth0
and Ory Hydra — are **hand-authored records of live sessions**: the provider was genuinely
exercised, but the result file was written afterwards rather than emitted by a runner, and no
adapter in this repository reproduces it. They are marked as such in
[`RUN-REGISTER.md`](results/e001/RUN-REGISTER.md). Treat them as reported observations, not as
independently checkable ones, until the adapters land.

## Headline

**No exercised provider lets an independent observer establish that a specific human
authorized a specific agent authority** — and the two dominant enterprise platforms fail in
opposite directions.

Okta does not name the human who consented: the consent event records `system@okta.com`, and
the human is recoverable only by correlating session events. Entra names a human who did not
consent: an administrator-authored grant produces a token identical to one from a genuine
interactive approval. ZITADEL and Ory Hydra cannot bind a human to the action credential at
all.

The Entra shape is the worse one for a verifier. An absent claim is visibly absent. **A
present claim that carries no information about consent origin reads as evidence and is
not.**

Enforcement is solved. **Provenance of human authority is not.**

## E001 — Human → Agent → Action

| Check | Baseline | Keycloak + OPA | ZITADEL + OPA | Okta | Entra |
|---|---|---|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | PASS | PASS | PASS | PASS | PASS |
| `DELEGATION_PROVABLE` | PASS | PASS | PASS | PASS | PASS |
| `SCOPE_VISIBLE` | PASS | PASS | PASS | PASS | PASS |
| `ALLOWED_ACTION_SUCCEEDS` | PASS | PASS | PASS | PASS | PASS |
| `FORBIDDEN_ACTION_BLOCKED` | PASS | PASS | PASS | PASS | PASS |
| `HUMAN_ATTRIBUTION_PROVABLE` | PASS | PASS | **FAIL** | PASS* | — |
| `AGENT_ATTRIBUTION_PROVABLE` | PASS | PASS | PASS | PASS | — |
| `ACTION_AUDITABLE` | PASS | PASS | PASS | PASS | — |
| `REVOCATION_SUPPORTED` | PASS | PASS | PASS | PASS | PASS |
| `POST_REVOCATION_ACTION_BLOCKED` | PASS | PASS | PASS | PASS | PASS |
| **Revocation latency** | 0.02 ms | **768 ms** | **9 ms** | 277 ms† | 180 ms – 7.4 s ‡ |
| Evidence completeness | 100% | 100% | 100% | 100% | 70% |

`—` is `BLOCKED_EXTERNAL_ACCESS`. It is **not** a failure, and it is deliberately distinct
from `NOT_SUPPORTED`. Absence is never inferred from an unsearched surface. Two different
causes appear under it: earlier rows were blocked for want of a test tenant, and Entra's three
cells are blocked by licence tier — sign-in logs return
`Authentication_RequestFromNonPremiumTenantOrB2CTenant` on a free-tier tenant. Directory
audits remain readable there; the interface says this tenant may not read the logs, not that
the capability is absent.

### Okta — and what "provable" turns out to mean

Okta passes all ten. Two details matter more than the score.

**Human attribution is reconstructible, not self-contained.** The access token binds both parties —
`sub`/`uid` name the human, `cid` names the agent client — so the credential the action carries does
identify who authorized it. But the consent event itself records:

```json
{ "type": "SystemPrincipal", "alternateId": "system@okta.com", "displayName": "Okta System" }
```

No user target. The human is recoverable only by correlating `externalSessionId` across the
session's events, where exactly one `User` actor appears. A relying party holding the consent grant
alone learns nothing about who approved it. That is marked `PASS*` above.

**The administrator-granted arm could not be constructed at all.** Amendment 1 set out to run the
same flow twice, differing only in who created the grant, to isolate the variable that separated
Keycloak from ZITADEL. Okta refused:

```
POST /api/v1/apps/{id}/grants  →  "scopeId: 'scopeId' is invalid"
```

That endpoint governs Okta API scopes, not custom authorization server scopes. **There is no
administrative path to author a user's consent for `payments:preview`.** Okta structurally prevents
the thing ZITADEL permitted.

This is a stronger result than the amendment predicted, and it also invalidates one of its
predictions: "every other check will be identical across the arms" is now untestable rather than
confirmed, because Arm A cannot reach those checks. Recorded rather than dropped.

† Okta's revocation figure measures API acknowledgement, not time-to-proven-block, so it is **not**
comparable to the Keycloak and ZITADEL latencies above. The post-revocation block was confirmed
separately: an identical request that redirected straight through before revocation returned the
consent prompt afterwards.

Okta's forbidden-action refusal is also provider-native — `access_denied`, *"Policy evaluation
failed"* — rather than produced by a benchmark-owned OPA, so `FORBIDDEN_ACTION_BLOCKED` is not
strictly comparable across the three either.

### Ory Hydra — and the two axes nobody satisfies

Hydra is not an identity provider. It is a pure OAuth2 server that **delegates login and consent to
an application the operator writes**, so it was added to answer one question the full IdPs cannot:
**is the attribution gap a property of OAuth2, or of how the platforms implement it?**

**It is not the protocol.** The token Hydra issued names the human directly — `sub=human-1`, plus
four custom claims the consent app wrote into `ext`. Putting rich, self-contained human attribution
into an OAuth2 token was trivial. Okta's decision to record `system@okta.com` as the consent actor
is a product choice, not a protocol constraint.

**But Hydra's attribution is unverifiable.** Hydra never authenticated anyone. It stored the subject
string the login app handed it. Nothing in its evidence backs the claim that `human-1` exists, is a
person, or consented — which is why `HUMAN_ATTRIBUTION_PROVABLE` is `INDETERMINATE` rather than
PASS or FAIL. The claim is present and unbacked.

That exposes two independent axes that the single check had been conflating:

| Provider | Self-contained? *(is the human in the record the action carries?)* | Verifiable? *(is anything backing it?)* |
|---|---|---|
| Keycloak + OPA | yes | partial — Direct Access Grants, recorded as a measurement mechanism |
| ZITADEL + OPA | **no** — administrator-authored metadata | no |
| Okta | **no** — consent event names `system@okta.com`; human recoverable only by session correlation | **yes** — MFA-backed interactive sign-in |
| Ory Hydra | **yes** — `sub` and custom claims in the token | **no** — asserted by the consent app |

**No provider tested satisfies both.** Okta has a real human behind the delegation but does not put
them in the record. Hydra puts them in the record with nothing behind them.

That is directly relevant to proposals asking for "lineage to a human-signed delegation root": on
this evidence, none of the exercised systems supply one. The property is not merely unimplemented,
it is split across two groups of systems that each have half of it.

Hydra was also the only provider to run **fully headless** — no browser, no interactive step. That
is a consequence of it authenticating nobody, which is the same fact that costs it verifiability.

### Auth0 — the first hard failure, and a consent dialog that says nothing

*Auth0 is owned by Okta. It is not an independent second vendor and is not counted as one.*

**`POST_REVOCATION_ACTION_BLOCKED` — FAIL.** After the grant was revoked (HTTP 204, grant list
confirmed empty), the previously issued access token was **still accepted by Auth0's own
`/userinfo` endpoint**, returning the subject. Revoking a grant prevents new tokens; it does not
invalidate outstanding ones. This was exercised against a live endpoint, not inferred from the
token's format.

Every other provider blocked here — Keycloak by a realm-wide not-before, ZITADEL by online
introspection, Okta by requiring re-consent. Auth0 did not.

**The forbidden-scope path fails differently from Okta's, and the difference is instructive.**

| | Okta | Auth0 |
|---|---|---|
| Undelegated scope requested | refused, `access_denied` | token issued |
| What the human saw | an error page | a consent dialog **listing no scopes at all** |
| Outcome | nothing issued | scope silently stripped to `openid` |

Auth0 does prevent the capability — `payments:execute` is absent from the token, so no effect is
possible, and the check passes. But a human was asked to approve a blank scope list, and neither
the human nor the client was told the request had been downgraded. A caller that trusts its own
request would believe it holds a scope it does not.

The same run also produced two claims that disagree: `scope` was `openid` while `permissions` was
`['payments:preview']` — a scope never requested in that flow.

**On attribution, Auth0 is better than Okta.** The tenant log names the human directly on both the
login and the code-for-token exchange, so no cross-event correlation is needed.

**On auditability, it is worse.** Enumerating every log type in the tenant produced **no
consent-specific event**. A consent dialog was displayed and approved by a human, the grant object
exists — and nothing attests that the approval happened or when. The action is auditable; the
authorization decision is not.

### Entra — the same token, whoever authorized it

Entra ran twice, differing only in who created the delegated permission grant, per
[Amendment 2](docs/E001-DELEGATION-FLOW-MAPPING.md). Both arms returned seven passes and
three blocked, at 70% evidence completeness.

**Arm A could be constructed, and on Okta it could not.** An administrator created an
`oauth2PermissionGrant` with `consentType: Principal` bound to the human's object id, through
Graph, with no consent prompt shown and no approval event recorded.

```
Okta:   POST /api/v1/apps/{id}/grants   ->  NOT_SUPPORTED  ("scopeId is invalid")
Entra:  POST /oauth2PermissionGrants    ->  created
```

The two dominant enterprise platforms differ on whether administrator-authored consent is
expressible at all. That is a platform-level difference, not a score.

**The two arms are indistinguishable in the credential.** Arm B's human authenticated, passed
multi-factor, and approved interactively. Arm A's human did none of those things. The tokens
carry the same twenty-six claim names and the same values for `oid`, `sub`, `email`, `name`,
`appid` and `scp`. All ten E001 outputs are identical across the arms.

Amendment 2 predicted Arm B would differ. It does not. That prediction was falsifiable and it
was falsified.

**A third shape appeared that the amendment did not anticipate.** Consenting through the
interactive screen with *"Consent on behalf of your organization"* ticked produces
`consentType: AllPrincipals` with `principalId: null` — a grant recording no human at all,
from a genuine human approval.

| How the grant was created | What the grant records | What the token shows |
|---|---|---|
| Administrator, via Graph | `Principal` + object id | human + agent |
| Human, org checkbox ticked | `AllPrincipals`, no principal | human + agent |
| Human, org checkbox unticked | `Principal` + object id | human + agent |

Rows one and three are identical in the token. Row two records no human despite a real one
having clicked Accept. So **whether the record names a human is independent of whether a human
approved.** It is determined by which API path or checkbox was used, and the distinction
survives only in the directory grant record — reachable solely through an authenticated live
Graph call.

**The consent screen is not the problem; the record is.** The dialog names the human, the
agent, and the scope in the words the tenant configured. What it does not disclose is that the
org-wide checkbox — which appears on the second screen, listing only profile read and
refresh-token access — silently broadens the *payments* grant shown on the first screen, and
erases the consenting human from it.

**Why this matters more than a failed check.** Nothing here is forged. No signature fails. No
scope is exceeded. A verifier re-deriving this chain offline confirms every property it can
check and concludes that a named human authorized a named agent for a named scope. That
conclusion is not supported by the evidence, and nothing in the evidence says so.

Runs: [`e001-entra-user-consent-v1`](results/e001/e001-entra-user-consent-v1/) (result of
record) and [`e001-entra-admin-consent-v1`](results/e001/e001-entra-admin-consent-v1/)
(controlled comparison).

**Boundaries.** Neither arm is headless: the tenant's only human principal is an external B2B
guest backed by a personal Microsoft account, so no non-interactive path to a delegated token
exists. Three checks are blocked by licence tier, so `HUMAN_ATTRIBUTION_PROVABLE` is neither
confirmed nor falsified here — the finding above rests on comparing the two arms' credentials,
not on that check. Single tenant, single client, single scope pair.

‡ Entra's revocation figure is dominated by directory propagation and is unstable: the same
operation measured 180 ms and 7.4 s across the two arms. It measures removal of the grant, not
invalidation of an issued token, and is not comparable to the Keycloak or ZITADEL figures.

## What the numbers mean

**Scope enforcement works.** `FORBIDDEN_ACTION_BLOCKED` passes on every exercised stack: the
`payments:execute` attempt is stopped before effect, not merely recorded as out of scope.

**Human attribution is where they diverge, and neither result is comfortable.**

- **ZITADEL fails outright.** The human-to-agent link is administrator-authored metadata —
  not interactive consent, and not a human claim cryptographically bound into the action token.
- **Keycloak passes, but read the limitation.** It binds human subject and confidential agent
  client in one token using Direct Access Grants. That is a *measurement mechanism, not a
  production recommendation*, and the grant is administrator-configured rather than an
  interactive consent record.

So the PASS and the FAIL are closer than the table suggests. Neither stack demonstrates what a
relying party actually wants: proof that a particular human authorized this exact scope.

**Revocation latency differs by ~85×, and the mechanisms are not comparable.**

- **Keycloak — 768 ms**, achieved via the realm-wide *not-before* boundary. The proven block
  is **broader than the delegation being revoked**: it invalidates more than the one grant.
- **ZITADEL — 9 ms**, but that speed depends on **online introspection at every exercised
  action**. Fast precisely because it is not offline.

Neither is a free lunch: one is coarse, the other requires a live call on every action. A
system needing fine-grained revocation *and* offline verification is not served by either.

## E006 — Predicate boundary enforcement

E001 varies the **action** and holds the resource fixed. E006 does the reverse: both requests
are `documents:read` against a document, and only the relation between the resource and the
granted organization differs. This is the cross-tenant IDOR / BOLA class — the failure that
after-the-fact lineage verification cannot detect, because the recorded authorization and the
performed action agree. The predicate was wrong, not the record.

Two policies, one binding the resource's organization to the grant and one checking only that
the action type was granted:

| Check | `action-only` | `relation-aware` |
|---|---|---|
| `IN_SCOPE_RESOURCE_ALLOWED` | PASS | PASS |
| `OUT_OF_SCOPE_RESOURCE_BLOCKED` | **FAIL** | PASS |
| `RELATION_PRESENT_IN_DECISION_INPUT` | **FAIL** | PASS |
| `RELATION_EVALUATED_NOT_ASSUMED` | **FAIL** | PASS |
| `SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION` | **FAIL** | PASS |

**Both policies would pass E001.** The action-only policy correctly grants `documents:read` and
correctly denies `documents:write` — action-axis scope is intact. E001 cannot observe this
failure at all. That is the point of E006, and it is a claim about action-scoped authorization
testing generally, not about any one engine.

Two checks exist to keep a pass honest:

- `RELATION_EVALUATED_NOT_ASSUMED` — a denial counts as relation enforcement only where the
  decision surface shows the relation was an input. An engine that denies for an unrelated
  reason and exposes no decision input is `INDETERMINATE`, not `PASS`.
- `SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION` — the adversarial form, identical request with only
  the resource identifier changed. Catches an engine enforcing something other than the relation.

Each run records its `policy_source` verbatim, so a weak policy is visible as a finding about
expressiveness rather than something silently corrected.

### Engine class changes what can go wrong

Four engines, two classes. Each row is one check; each column is one policy or model.

| | `opa::action-only` | `opa::relation-aware` | `cedar::action-only` | `cedar::relation-aware` | `openfga` | `spicedb` |
|---|---|---|---|---|---|---|
| Engine class | policy | policy | policy | policy | relationship | relationship |
| `IN_SCOPE_RESOURCE_ALLOWED` | PASS | PASS | PASS | PASS | PASS | PASS |
| `OUT_OF_SCOPE_RESOURCE_BLOCKED` | **FAIL** | PASS | **FAIL** | PASS | PASS | PASS |
| `RELATION_PRESENT_IN_DECISION_INPUT` | **FAIL** | PASS | PASS | PASS | PASS | PASS |
| `RELATION_EVALUATED_NOT_ASSUMED` | **FAIL** | PASS | **FAIL** | PASS | PASS | PASS |
| `SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION` | **FAIL** | PASS | **FAIL** | PASS | PASS | PASS |

**In both policy engines the insecure version is authorable.** OPA and Cedar each appear twice
because the engine permits either policy; the difference between the columns is a person, not the
engine. `permit(principal == User::"G", action == Action::"read", resource)` is four lines of
ordinary Cedar and it grants read over every document in the system.

**In both relationship engines it is not.** A check omitting the resource is rejected before
evaluation — OpenFGA returns `invalid CheckRequestTupleKey.Object`, SpiceDB returns
`validation error: resource: value is required`. The failure E006 detects cannot be expressed at
the decision layer. Two independent vendors, so this is a property of the class rather than of one
API.

### The most informative cell

`cedar::action-only` is the one to read closely: `RELATION_PRESENT_IN_DECISION_INPUT` **passes**
while `RELATION_EVALUATED_NOT_ASSUMED` **fails**.

Cedar's request shape always carries principal, action and resource, so the resource is present in
every decision. The policy simply never consults it. That is the precise anatomy of the
vulnerability — *the data was there and nothing looked at it* — and it is visible only because the
two checks are kept apart. A benchmark reporting "was the resource in the request?" would score
this policy as safe.

The contrast with `opa::action-only`, which fails both, is also real: in Rego the decision input is
whatever the policy author constructs, so an action-only policy need not receive the resource's
organization at all. Present-and-ignored and never-supplied are different defects with the same
outcome.

### What this does and does not say

It does **not** say relationship engines are secure. The corresponding risk in that class is
over-broad relationship issuance — granting a relation more widely than intended — which moves the
failure from decision logic to grant administration. **E006 does not exercise that**, and both
relationship results record the gap in their limitations.

What it says is narrower and more useful to a standards body: **the insecure pattern is authorable
in policy engines and unauthorable in relationship engines.** Where the pattern is authorable, the
control is policy review, and a conformance requirement should say so rather than assuming the
engine prevents it.

Preregistration: [`docs/E006.md`](docs/E006.md). Runs: [`results/e006/`](results/e006/).

## Also measured

- **E002** — human-authorization receipt binding (Keycloak, ZITADEL)
- **E004 / E005** — isolated delegation and mandate slices
- **Authority Relations v0.1** — eight provider-neutral conformance vectors testing whether an
  implementation distinguishes *request causality* from *authority provenance*
  ([frozen release](results/authority-relations-v0.1/))

Narrative detail for E001 is in [`docs/E001-FINDINGS.md`](docs/E001-FINDINGS.md).

## Method

Preregistered — the question is frozen before the run ([`docs/E001.md`](docs/E001.md)). Every
provider receives the same semantic task and output schema. Status vocabulary is `PASS` /
`FAIL` / `BLOCKED_EXTERNAL_ACCESS` / `NOT_SUPPORTED` / `INDETERMINATE`; a provider may report
`NOT_SUPPORTED` only where the exercised interface makes that boundary explicit, otherwise
`INDETERMINATE`. Accepted comparison runs are separated from engineering runs in
[`results/e001/RUN-REGISTER.md`](results/e001/RUN-REGISTER.md) so no reader can silently pick
the most flattering result. No credential, token, private key, or full signature is stored.

## Open

- Okta and Entra pending test tenants. Both platforms' standard machine-to-machine patterns
  have no human in the loop by construction, so a *negative* result there would itself be the
  finding.
- Interactive-consent flows, as distinct from administrator-configured grants.
