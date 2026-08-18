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

## Also measured

- **E002** — human-authorization receipt binding (Keycloak, ZITADEL)
- **E004 / E005** — isolated delegation and mandate slices
- **Authority Relations v0.1** — eight provider-neutral conformance vectors testing whether an
  implementation distinguishes *request causality* from *authority provenance*
  ([frozen release](results/authority-relations-v0.1/))

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
