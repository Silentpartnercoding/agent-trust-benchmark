# Development run, revision 2: Agent Passport System SDK 8.0.1

This is a second oracle-exposed development run, not a submission. It sits beside the first run in `../8.0.1/`, which stays unchanged as the historical record. The SDK is the same `agent-passport-system` 8.0.1. Only the adapter changed. The adapter author read the vector files, their expected results and the reference adapter before writing it.

- Suite: `authority-relations-v0.1`, tag commit `d4bb114eff241c3ef9367b1c252752f85f378c6e`, vector manifest `sha256:ffc2363895a77a62b5673366e334140d2682f436891f570b9bfb321bdfa4ade3`. `authority-relations-verify-release` exited 0 before the run.
- Implementation: `agent-passport-system` 8.0.1 from npm, integrity `sha512-g9/AlzqX+L/fKzdsFQICGj59rYnXgeFxZcnmwD8WFNOK8aPSxT8FZEQe/PzGpnpG31xTLeLuMyrInX2B/Id5oA==`, called through the adapter in `adapter/`.
- Runner: aeoess, 2026-10-30, Python 3.14.6, Node v24.11.1, npm 11.6.2, macOS. The runner exits 1 because not every vector passed, as the adapter guide describes for a completed run.
- `result.json` and `SUMMARY.md` are the unaltered scored runner output, with the adapter returning the v0.1 reason codes.
- `supplementary-aps-labels/` is an unscored comparison: the same adapter with `ATB_APS_REASONS=native`, which returns adapter-defined APS labels instead of the v0.1 codes. It is there only to show which results depend on the reason translation.
- `counterfactuals/` holds fourteen boundary cases, each one change from a frozen vector, run against the first adapter, this adapter and the suite's reference control `adapters/relation_aware.py`.

| file | sha256 |
|---|---|
| `result.json` | `59f8b2e2a9a0c55507664d96c6c1b533421e354340560d4edc8afc5b8273c386` |
| `SUMMARY.md` | `45db8b937bd92377a6a5694bf4db1d7b8d9c40ab9a78d804fc42d057c88b92b5` |
| `supplementary-aps-labels/result.json` | `df1f9f1e9d64fa9f657152f34b04c0443a819b4f2c0ebcb2397d65f97bd878b2` |
| `supplementary-aps-labels/SUMMARY.md` | `46a2996390cac13a4bbd1d9d04665b9acc06c02e5fad87c6297137d6d68ae483` |
| `adapter/aps_adapter.mjs` | `0cf17a5f34e4c610e7e58d430e87467256442950ee9e185a642699fa1d874ca2` |
| `adapter/aps_adapter.py` | `56c2a0057de0e1c7e109519ad824eb38d0e0640b6828b3046dcef6d622efebe4` |
| `adapter/package.json` | `e0b3e0d2f42a3b2b0e86d936ca602cb268a95741a5b8bdbc924a9bd351c8f09e` |
| `adapter/package-lock.json` | `b36f695f256bc7ff093c62ea0a3ab1c3aa5ceb48b84fb3af16f21f909384f5f0` |
| `counterfactuals/counterfactual.py` | `a968b4d0e17beb7437ff6eb1ce3321f12cc3ec26f38efbe5768822cf5f469fb6` |
| `counterfactuals/counterfactual-results.json` | `b54b057b701a913eeedb7ee6b63a7a077d2e8f2629137b04ac8f0fbbb4413918` |

## Reproduce

From a checkout of the suite at the release tag with this `results/` directory in place:

```
git checkout authority-relations-v0.1
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
python -m agent_trust_benchmark authority-relations-verify-release
R=results/authority-relations-v0.1/development/agent-passport-system
(cd "$R/8.0.1/adapter" && npm ci --ignore-scripts)
(cd "$R/8.0.1-r2/adapter" && npm ci --ignore-scripts)
python -m agent_trust_benchmark authority-relations --adapter "$R/8.0.1-r2/adapter/aps_adapter.py" --output-dir r2-scored
ATB_APS_REASONS=native python -m agent_trust_benchmark authority-relations --adapter "$R/8.0.1-r2/adapter/aps_adapter.py" --output-dir r2-aps-labels
python3 -I "$R/8.0.1-r2/counterfactuals/counterfactual.py" .
```

Both runs were repeated after the final adapter change and gave byte-identical `result.json` and `SUMMARY.md`.

## Result

Scored, v0.1 reason codes: 5 PASS, 3 UNSUPPORTED, 0 FAIL, 0 ERROR. With adapter-defined APS labels: 0 PASS, 5 FAIL on `reason` only, 3 UNSUPPORTED.

| vector | first run | this run, scored | this run, APS labels | what decided it |
|---|---|---|---|---|
| AR-001 | FAIL, reason | PASS | FAIL, reason only | SDK chain verification, adapter relation and reason |
| AR-002 | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | valid evidence of kind REQUEST |
| AR-003 | UNSUPPORTED | PASS | FAIL, reason only | input status MISSING for the requester, SDK for the executor's chain |
| AR-004 | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | valid evidence of kind REQUEST |
| AR-005 | UNSUPPORTED | PASS | FAIL, reason only | input statuses only, the SDK is not called |
| AR-006 | FAIL, reason | PASS | FAIL, reason only | SDK `SIGNATURE_INVALID` |
| AR-007 | UNSUPPORTED | UNSUPPORTED | UNSUPPORTED | valid evidence of kind REQUEST |
| AR-008 | FAIL, reason | PASS | FAIL, reason only | SDK executor chain, input `independently_issued` |

Read the improvements separately:

- AR-003 and AR-005 becoming decidable is adapter coverage work. Missing request evidence means no valid request authority was presented, which needs no REQUEST semantics.
- All five PASS results also depend on the reason translation. With APS labels, all 17 fields other than `reason`, including `authorized`, equal the expected output on the same five vectors.
- Neither change is new SDK capability. The SDK verification is the same as in the first run.

AR-002, AR-004 and AR-007 stay UNSUPPORTED. Each carries a VALID request-authority item of kind REQUEST, and the output schema requires `request_authority_valid` as a boolean. This adapter, with the current SDK mapping, has no record for authority to request an action apart from authority to execute it, so it cannot state that value. On AR-004 the denial itself would be decidable, because the execution evidence is invalid, but v0.1 has no way to leave that one field unknown.

## What changed in the adapter

- UNSUPPORTED is returned only when the output would have to state that REQUEST-kind authority is valid. Missing or invalid request evidence is decided.
- An SDK result of `indeterminate` is reported as UNSUPPORTED with the SDK codes. The first adapter reported it as invalid evidence.
- `independently_issued` is read as a benchmark input condition. `false` blocks the independent execution path. `true` only satisfies the benchmark's condition. It is supplied test data and the SDK does not verify it.
- Any item the case marks INVALID makes the evidence invalid, as in the reference.
- The delegated path requires valid requester authority for exactly the requested action, as the benchmark requires. APS itself lets a broader parent grant delegate a narrower one. That is unchanged in the SDK and only mapped differently here.
- Reasons follow the v0.1 precedence, applied in the adapter. APS verification semantics are not changed to match the scorer.
- Each run writes a provenance record to stderr naming which step the SDK, the adapter or the supplied input decided.

## Counterfactuals

`counterfactuals/counterfactual-results.json` holds every output from all three adapters for each case, compared on every output field.

| case | change | reference | first run | this run |
|---|---|---|---|---|
| CF-01 | REQUEST evidence missing, requester required | deny | UNSUPPORTED | equal |
| CF-02 | REQUEST evidence invalid, invalid evidence rejected | deny | UNSUPPORTED | equal |
| CF-03 | REQUEST evidence invalid, invalid evidence not rejected | deny | UNSUPPORTED | equal |
| CF-04 | `independently_issued` false | deny | **authorizes** | equal |
| CF-06 | requester and executor both fail, invalid rejected | deny | UNSUPPORTED | equal |
| CF-07 | as CF-06, invalid not rejected | deny | UNSUPPORTED | equal |
| CF-08 | delegation valid, delegator has no request authority | deny | deny, `reason` and `evidence_status` differ | equal |
| CF-09 | valid REQUEST evidence, requester not required | allow | allow, `request_authority_valid` wrong | UNSUPPORTED |
| CF-10 | invalid delegation with a mismatched source | deny | deny, `reason` differs | equal |
| CF-11 | as CF-10, plus a valid independent path | deny | deny, `reason` differs | equal |
| CF-12 | execution item of kind REQUEST marked invalid | deny | deny, `reason` differs | equal |
| CF-13 | requester grant broader than the requested action | deny | **authorizes** | equal |
| CF-14 | as CF-13, requester not required | deny | **authorizes** | equal |

CF-05 is reported separately. It sets every revocation status to unknown through `ATB_APS_REVOCATION=unknown`, a hook only this adapter reads. The reference has no revocation input and the first adapter ignores the hook, so neither gives a comparable answer. This adapter returns UNSUPPORTED with `REVOCATION_UNKNOWN`.

CF-04, CF-13 and CF-14 are the three cases where the first adapter authorized and the reference denies. They are defects in how that adapter mapped the benchmark onto APS, reported in the PR thread, and none of the eight frozen vectors exercises them.

## Limits

- Oracle exposure. This run is development work, not independent implementation evidence. A run claiming independent construction would need an adapter written without access to the expected results or the reference logic.
- The counterfactual harness is diagnostic. It records outputs and differences, and its exit code is not a pass or fail gate.
- The fourteen cases are boundary probes, not an exhaustive test of the adapter.
- The npm tarball was not mapped to a git commit.
