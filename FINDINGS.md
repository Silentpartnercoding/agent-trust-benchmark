# Findings

What has actually been measured, and what it shows. Every claim links to a run under
[`results/`](results/); nothing here is asserted without a run id.

## Headline

**No exercised provider produces an offline-verifiable, cryptographically human-bound
delegation.** Both stacks that ran to completion enforce scope correctly — but in both,
the link from a *specific human* to a *specific agent authority* is administrator-authored
configuration, not an interactive consent record and not a human claim bound into the token
the action carries.

Enforcement is solved. **Provenance of human authority is not.**

## E001 — Human → Agent → Action

| Check | Baseline | Keycloak + OPA | ZITADEL + OPA | Okta | Entra |
|---|---|---|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | PASS | PASS | PASS | PASS | — |
| `DELEGATION_PROVABLE` | PASS | PASS | PASS | PASS | — |
| `SCOPE_VISIBLE` | PASS | PASS | PASS | PASS | — |
| `ALLOWED_ACTION_SUCCEEDS` | PASS | PASS | PASS | PASS | — |
| `FORBIDDEN_ACTION_BLOCKED` | PASS | PASS | PASS | PASS | — |
| `HUMAN_ATTRIBUTION_PROVABLE` | PASS | PASS | **FAIL** | PASS* | — |
| `AGENT_ATTRIBUTION_PROVABLE` | PASS | PASS | PASS | PASS | — |
| `ACTION_AUDITABLE` | PASS | PASS | PASS | PASS | — |
| `REVOCATION_SUPPORTED` | PASS | PASS | PASS | PASS | — |
| `POST_REVOCATION_ACTION_BLOCKED` | PASS | PASS | PASS | PASS | — |
| **Revocation latency** | 0.02 ms | **768 ms** | **9 ms** | 277 ms† | — |
| Evidence completeness | 100% | 100% | 100% | 100% | — |

`—` is `BLOCKED_EXTERNAL_ACCESS`: the provider could not be exercised for want of a test
tenant. It is **not** a failure, and it is deliberately distinct from `NOT_SUPPORTED`.
Absence is never inferred from an unsearched surface.

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
