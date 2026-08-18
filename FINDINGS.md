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
| `DISTINCT_AGENT_IDENTITY` | PASS | PASS | PASS | — | — |
| `DELEGATION_PROVABLE` | PASS | PASS | PASS | — | — |
| `SCOPE_VISIBLE` | PASS | PASS | PASS | — | — |
| `ALLOWED_ACTION_SUCCEEDS` | PASS | PASS | PASS | — | — |
| `FORBIDDEN_ACTION_BLOCKED` | PASS | PASS | PASS | — | — |
| `HUMAN_ATTRIBUTION_PROVABLE` | PASS | PASS | **FAIL** | — | — |
| `AGENT_ATTRIBUTION_PROVABLE` | PASS | PASS | PASS | — | — |
| `ACTION_AUDITABLE` | PASS | PASS | PASS | — | — |
| `REVOCATION_SUPPORTED` | PASS | PASS | PASS | — | — |
| `POST_REVOCATION_ACTION_BLOCKED` | PASS | PASS | PASS | — | — |
| **Revocation latency** | 0.02 ms | **768 ms** | **9 ms** | — | — |
| Evidence completeness | 100% | 100% | 100% | — | — |

`—` is `BLOCKED_EXTERNAL_ACCESS`: the provider could not be exercised for want of a test
tenant. It is **not** a failure, and it is deliberately distinct from `NOT_SUPPORTED`.
Absence is never inferred from an unsearched surface.

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

Adding OpenFGA — a relationship engine rather than a policy engine — produces the more
interesting result:

| | `opa::action-only` | `opa::relation-aware` | `openfga` |
|---|---|---|---|
| Engine class | policy | policy | relationship |
| `IN_SCOPE_RESOURCE_ALLOWED` | PASS | PASS | PASS |
| `OUT_OF_SCOPE_RESOURCE_BLOCKED` | **FAIL** | PASS | PASS |
| `RELATION_PRESENT_IN_DECISION_INPUT` | **FAIL** | PASS | PASS |
| `RELATION_EVALUATED_NOT_ASSUMED` | **FAIL** | PASS | PASS |
| `SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION` | **FAIL** | PASS | PASS |

The two OPA rows are the same engine. The difference between them is entirely how the policy was
written — "check the action and ignore the resource" is a policy a person can author, and nothing
in the engine objects.

OpenFGA's pass is a different kind of pass. **The object is a required parameter of every check.**
A decision request naming no resource is rejected as a validation error, so the action-only
mistake cannot be expressed at the decision layer at all. That is not a well-authored model; it is
a property of the engine.

So the useful question for a standards body is not *which engine is secure*. It is **which engines
make the insecure pattern hard to write.** A policy engine can express either and the outcome
rests on review. A relationship engine cannot express the failure E006 detects.

That is not a clean win for relationship engines, and the result records why: the corresponding
risk in that class is **over-broad tuple issuance** — granting a relation more widely than intended
— which moves the failure from the decision layer to grant administration. E006 does not exercise
that, and the OpenFGA result says so in its limitations.

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
