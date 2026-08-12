# E002 reference-verifier result

Run date: 2026-08-11

This is a local harness result, not evidence about an external provider. It
tests whether the proposed receipt verifier distinguishes the intended states
before any live adapter is built.

| Case | Expected gate result | Result |
|---|---|---|
| Valid witnessed receipt and matching credential | `VERIFIED` | PASS |
| Receipt swapped after credential issuance | `REJECTED` | PASS |
| Different agent identity | `REJECTED` | PASS |
| Different agent key | `REJECTED` | PASS |
| Action expanded from preview to execute | `REJECTED` | PASS |
| Credential scope expanded without receipt authority | `REJECTED` | PASS |
| Wrong audience | `REJECTED` | PASS |
| Expired receipt | `REJECTED` | PASS |
| Impossible event/not-before ordering | `REJECTED` | PASS |
| Revoked receipt | `REJECTED` | PASS |
| Missing revocation checker | `INDETERMINATE` | PASS |
| Revocation checker error | `INDETERMINATE` | PASS |
| Administrator label offered as interactive consent | `REJECTED` | PASS |
| Unapproved proof media type | `INDETERMINATE` | PASS |
| Approved proof verifier error | `INDETERMINATE` | PASS |
| Payload attempts to select its own verification mode | `REJECTED` | PASS |
| Signed payload tampered without a new proof | `REJECTED` | PASS |
| Malformed credential confirmation data | `REJECTED` | PASS |

Total: **18/18 expected outcomes**.

The deterministic HMAC proof used by the tests is a harness fixture only. The
result does not claim production cryptographic interoperability, provider
support, or live human consent. Those are the subjects of the preregistered E002
provider runs.
