# Human Authorization Receipt v0.1

## ELI5

An agent credential currently says, “I am this robot.” It does not always say,
“this particular human gave this robot this particular permission.”

The Human Authorization Receipt is a signed permission slip that travels beside
the agent credential:

1. The human signs in to a trusted identity provider and approves a narrow job.
2. The provider witnesses that event and issues the receipt.
3. The receipt names the human, the agent and its key, the exact actions, the
   intended service, the expiry, and a revocation handle.
4. The agent's action credential carries a digest of that exact signed receipt.
5. The gate checks both together. A different receipt, robot, key, action, or
   destination does not fit.

The gate first verifies the normal action credential using its existing OAuth
or identity-provider rules. The reference receipt verifier consumes only those
already-verified credential claims; it does not replace token verification.

It is the difference between a robot showing an ID card and a robot showing an
ID card stapled to a witnessed permission slip.

## What is proven

A `VERIFIED` result means the configured gate directly established all of the
following for this attempted action:

- the receipt proof verifies under a caller-trusted issuer;
- the issuer says it witnessed an accepted kind of human authorization;
- the action credential is bound to the exact signed receipt digest;
- the credential and receipt identify the same agent and key;
- both address the current audience;
- the exact resource and action are present in both authorities;
- the receipt is inside its validity window; and
- the configured revocation authority definitively says it is not revoked.

It does **not** prove that the human understood the request, that the identity
provider is honest, or that the downstream service performed the requested
effect correctly. Those remain separate claims and evidence boundaries.

## Grounded vocabulary

The payload reuses familiar identity and authorization vocabulary where the
semantics fit:

- issuer and audience;
- OAuth-style scopes;
- `cnf.jkt` to bind the agent's proof-of-possession key;
- `acr` and `amr` for the witnessed authentication context; and
- short issuance, not-before, and expiry windows.

The payload is an experimental profile, not a claim that a new standard already
exists. A production envelope should use an established proof format such as
COSE or JOSE. The reference verifier deliberately accepts proof verification as
a caller-supplied function; its HMAC test proof is only a deterministic harness
fixture and is not a production signature design.

## Trust boundary

The receipt is untrusted input until verification completes. It may describe
its media type, but it cannot choose:

- which issuers are trusted;
- which proof formats or algorithms are accepted;
- which keys verify those proofs;
- which authorization modes satisfy the current service;
- which audience, resource, and action are expected; or
- how revocation status is obtained.

Those decisions come from `ReceiptContext`, owned by the gate. Payload fields
never select their own provenance or verification mode.

## Binding invariant

The action credential must be cryptographically bound to the SHA-256 digest of
the complete signed receipt envelope. The benchmark normalizes the provider's
binding into `receipt_digest`; a provider can carry it in a token claim,
proof-of-possession exchange, or another cryptographically covered field.

For a production COSE or JOSE envelope, the digest is computed over the exact
signed envelope bytes that are transported. The Python reference uses its
deterministic JSON encoding only for local test vectors; it is not presented as
a new canonicalization standard.

The rule is:

> The credential that authorizes the action and the receipt that explains the
> human authorization must be inseparable at verification time.

This prevents a valid credential for one agent from being paired with a broader
or differently witnessed receipt.

## Authorization modes

- `interactive_consent`: the trusted issuer witnessed the human authenticate
  and explicitly authorize the narrow grant.
- `administrator_configured`: an administrator created the relationship.

These are not interchangeable. A service that requires interactive consent
rejects an administrator-configured receipt even if it is correctly signed.
That directly preserves the gap found in the ZITADEL E001 run instead of hiding
it behind an administrator-authored label.

## Revocation

The receipt carries an authority and opaque handle, not an arbitrary URL to
fetch. The gate chooses the trusted checker for that authority. If the checker
is missing or returns no definitive answer, the verdict is `INDETERMINATE` and
the action fails closed.

No blockchain is required. The receipt needs a trustworthy issuer, exact digest
binding, and a live revocation decision. A transparency log can later preserve
issuance evidence, but it cannot turn a false authorization claim into truth.

## Reference files

- Payload schema: `schemas/human-authorization-receipt-v0.1.schema.json`
- Provider-neutral verifier: `src/agent_trust_benchmark/receipt.py`
- Threat matrix encoded as tests: `tests/test_receipt.py`
- Live experiment preregistration: `docs/E002.md`

## Standards referenced, not reinvented

- RFC 7800: proof-of-possession `cnf` semantics
- RFC 7515: JSON Web Signature (JOSE)
- RFC 9052: COSE structures and processing
- OpenID Connect Core: `acr`, `amr`, and authenticated-session vocabulary
