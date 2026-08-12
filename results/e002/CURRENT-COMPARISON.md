# E002 current comparison

Run date: 2026-08-11

## ELI5 result

The receipt is a signed permission slip. It says which human approved which
agent key to perform one exact action for one exact audience. The gate checks
the slip, the agent's credential, the agent's key, the requested action, and
revocation before allowing an effect.

Keycloak supplied a real interactive `payments:preview` consent event, so the
whole path worked. The current ZITADEL fixture supplied an
administrator-configured relationship instead. The verifier did not rename
that relationship "human consent," so it safely refused the effect.

## Accepted live runs

| Provider fixture | Observed authorization | Passed | Failed | Preview effect | Verification | Revocation-to-block |
|---|---|---:|---:|---|---:|---:|
| Keycloak + OPA | Interactive consent | 14 | 0 | Allowed once | 15.98 ms | 14.55 ms |
| ZITADEL + OPA | Administrator configured | 12 | 2 | Safely blocked | 6.47 ms | 5.53 ms |

Everything ties out: **28 live checks = 26 pass + 2 fail**. Both failures are
in the ZITADEL run: no interactive human authorization was witnessed, and the
corresponding action was therefore not allowed.

The latency values are observations from one local fixture run, not provider
performance rankings.

## Attack results

The live runners blocked action expansion, receipt swapping, relabeling an
administrator event as consent, unavailable revocation evidence, and a retry
after revocation. The deterministic verifier matrix additionally exercised
agent swaps, key swaps, credential-scope expansion, wrong audience, expiry, causal-order violations,
unapproved proof formats, proof-verifier failure, tampering, and malformed
credential data: **18/18 expected outcomes passed**. The unchanged OPA policy
suite passed **8/8**.

## What this proves

- A neutral signed receipt can carry a genuine provider witness into a strict
  pre-effect gate without inventing provider-native claims.
- Agent identity and human authorization remain separate facts. Strong proof
  of the agent does not manufacture proof that a human approved its authority.
- `INDETERMINATE` is operationally useful: missing revocation evidence is
  visible as missing evidence and still produces no effect.

## What this does not prove

- The benchmark-owned receipt issuer and short-lived action credential are not
  native Keycloak or ZITADEL features.
- The automated fixture proves that the interactive consent mechanism occurred,
  not that a real person understood a production consent screen.
- A single loopback run is not a throughput, availability, or vendor ranking.
- The ZITADEL result does not prove that ZITADEL cannot support an interactive
  design; it proves only that the exercised fixture did not provide one.

## Next test

Add an interactive ZITADEL authorization witness without changing the receipt,
gate, action, or scoring contract. If that closes the two failed checks, the
receipt is portable across two independent open-source identity providers. If
it does not, the remaining gap will be attributable to a specific evidence
surface rather than to the receipt design.
