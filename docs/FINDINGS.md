# E001 initial findings

This document records only conclusions supported by the local runs. It does not
rank whole companies or infer capabilities from surfaces that were not tested.

## Harness finding

The neutral baseline proves that the experiment can distinguish all required
states. It creates separate human and agent identities, binds a preview-only
delegation, allows preview once, denies execute before effect, reconstructs the
action from audit evidence, revokes the credential, and blocks a retry. A
tampered credential that adds execute authority is rejected.

This is a harness-validity result, not evidence that a production identity
system is secure.

## Okta and Microsoft Entra finding

No vendor behavior has been measured yet. Both adapters correctly return
`BLOCKED_EXTERNAL_ACCESS` because no configured test tenant, resource server,
or audit access was available in this environment.

That is not a failure result. It is a paper-trail result showing exactly what
must be supplied before a fair comparison is possible.

## Open-source control finding

Two local, self-hosted controls now run the same E001 task against the exact
same OPA enforcement policy. Holding the enforcement point fixed makes the
identity evidence—not two different application policies—the variable under
test.

Keycloak + OPA passed all ten binary outputs. The exercised token names the
human as subject and the confidential agent client as authorized party, so the
allow and deny decisions retain both identities. This result has two important
boundaries: the fixture uses Direct Access Grants as a measurement mechanism,
and revocation advances a realm-wide not-before boundary rather than revoking
only the E001 delegation. It is a capability result, not a production blueprint.

ZITADEL + OPA passed nine outputs and failed one. ZITADEL clearly separates the
human and service account, records the preview-only grant, exposes the role in
introspection, audits changes, removes the grant specifically, and causes the
next introspected action to be denied. The action token proves the service
account, but it does not contain the human link. That link exists only as
administrator-authored metadata, so `HUMAN_ATTRIBUTION_PROVABLE` correctly
fails instead of being inferred.

The most useful finding is therefore not “one product wins.” It is that agent
identity and human authorization are different evidence problems. A system can
strongly identify the machine actor and still lack a witnessed, token-bound
answer to “which human authorized this exact authority?”

## E002 finding

E002 implemented the preregistered Human Authorization Receipt as a detached
Ed25519 JWS, bound a short-lived action credential to the digest of that exact
receipt, bound the agent to a proof-of-possession key, and kept trust anchors,
accepted authorization modes, expected use, proof verification, and revocation
outside the untrusted payload.

The accepted Keycloak + OPA run passed all 14 outputs. Keycloak recorded the
fixture human's interactive consent for `payments:preview`; the receipt carried
that witness into the fixed gate; preview produced one effect; execute, receipt
swapping, administrator-label substitution, missing revocation evidence, and
post-revocation retry produced none.

The accepted ZITADEL + OPA run passed 12 outputs and failed two safely. Its
administrator-configured metadata and role grant did not prove interactive
human authorization, so `HUMAN_AUTHORIZATION_WITNESSED` failed and the preview
effect remained blocked. The benchmark did not turn a useful administrative
fact into a stronger human-consent claim.

Across both live runs, 28 checks tie out to 26 passes and two explicit failures.
The reference verifier passed 18/18 mutation cases and the unchanged OPA policy
passed 8/8 tests. See the [current E002 comparison](../results/e002/CURRENT-COMPARISON.md).

The result supports a narrower and more useful claim than "one provider wins":
a neutral receipt can preserve a genuine provider witness through enforcement,
but it cannot create a human witness that the upstream evidence never supplied.

## Next experiment

Exercise an interactive ZITADEL authorization path against the frozen E002
receipt and gate. That is the smallest test that distinguishes portable receipt
design from a provider-fixture evidence gap. Okta and Entra remain fair later
comparators when disposable tenants and audit access are available. No further
surface should be inferred or exercised until its full API and intended
authorization contract are available for review.
