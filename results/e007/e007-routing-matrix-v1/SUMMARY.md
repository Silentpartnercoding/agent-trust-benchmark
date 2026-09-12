# E007 result

**Verdict: SUPPORTED**

Preregistration commit: `717653f53e9b964026512bd3be5dc9ed5279c0f8`

Preregistration SHA-256: `c1f6b5b1b776c205fae30bb3aa4043a57ea54b188d35262186fe8e17e70b4d73`

| Arrangement | Placement | Predicted failures | Actual failures | Prediction |
|---|---|---|---|---|
| router-complete | router | none | none | PASS |
| middleware-complete | middleware | none | none | PASS |
| decorator-complete | decorator | none | none | PASS |
| handler-complete | handler | none | none | PASS |
| verb-asymmetric | decorator | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, OUT_OF_SCOPE_READ_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, OUT_OF_SCOPE_READ_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | PASS |
| router-late-bypass | router | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | PASS |
| middleware-late-bypass | middleware | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH, LATE_REGISTRATION_COVERED, OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT, ZERO_UNAUTHORIZED_EFFECTS | PASS |

## Limits

- Synthetic standard-library routing fixture; no production MCP implementation or web framework was measured.
- Expressibility and detectability are supported; prevalence is not measured.
- Entitled controls prevent default-deny false confidence but do not measure false-positive rate against an external labelled corpus.
- Reverse proxies, generated routes, service meshes, and direct resource bypasses are outside this fixture.
