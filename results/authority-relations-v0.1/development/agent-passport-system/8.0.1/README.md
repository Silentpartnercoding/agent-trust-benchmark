# Development run: Agent Passport System SDK 8.0.1

This is an oracle-exposed development run, not a submission. The adapter author read the vector files, including their expected results, before writing the adapter. At the maintainer's request in #11 the run is kept outside `submissions/`.

- Suite: `authority-relations-v0.1`, tag commit `d4bb114eff241c3ef9367b1c252752f85f378c6e`, vector manifest `sha256:ffc2363895a77a62b5673366e334140d2682f436891f570b9bfb321bdfa4ade3`. `authority-relations-verify-release` exited 0 before the run.
- Implementation: `agent-passport-system` 8.0.1 from npm, integrity `sha512-g9/AlzqX+L/fKzdsFQICGj59rYnXgeFxZcnmwD8WFNOK8aPSxT8FZEQe/PzGpnpG31xTLeLuMyrInX2B/Id5oA==`, called through the adapter in `adapter/`.
- Runner: aeoess, 2026-10-29T21:10:35Z, Python 3.14.6, Node v24.11.1, npm 11.6.2, macOS.
- `result.json` and `SUMMARY.md` are the unaltered runner output.

| file | sha256 |
|---|---|
| `result.json` | `d399ca345a61e78f775d6b9a35a8fa8aa21f2bf77133182cc719a3d4f92c7d2d` |
| `SUMMARY.md` | `e615ccb559867ebc7ea86c10496f287695ddb21ab578858a119b98ca775ac3e9` |
| `adapter/aps_adapter.py` | `56c2a0057de0e1c7e109519ad824eb38d0e0640b6828b3046dcef6d622efebe4` |
| `adapter/aps_adapter.mjs` | `d87c08d426b18015d18b9163e8b4eec62814750c4ae5fb92e8aabe754c2721b6` |
| `adapter/package.json` | `e0b3e0d2f42a3b2b0e86d936ca602cb268a95741a5b8bdbc924a9bd351c8f09e` |
| `adapter/package-lock.json` | `b36f695f256bc7ff093c62ea0a3ab1c3aa5ceb48b84fb3af16f21f909384f5f0` |

## Reproduce

From a checkout of the suite at the release tag, with a copy of `adapter/` from this directory at `$ADAPTER`:

```
git checkout authority-relations-v0.1
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
python -m agent_trust_benchmark authority-relations-verify-release
(cd "$ADAPTER" && npm ci --ignore-scripts)
python -m agent_trust_benchmark authority-relations --adapter "$ADAPTER/aps_adapter.py" --output-dir external-result
```

The run command exits 1 because not every vector passed, as the adapter guide describes for a completed run. A rerun from a fresh clone on 2026-10-30 gave byte-identical `result.json` and `SUMMARY.md` (hashes above).

## Result

0 of 8 under the v0.1 scorer, with 3 FAIL, 5 UNSUPPORTED and 0 ERROR.

- AR-001, AR-006 and AR-008 fail on `reason` only. The verdict and the other 17 output fields equal the expected result. The adapter returned APS labels, and the scorer compares the exact v0.1 reason codes, which were documented after this run in #12.
- AR-002, AR-003, AR-004, AR-005 and AR-007 are UNSUPPORTED. Each policy requires requester authority of kind REQUEST. This adapter does not model requester authority of kind `REQUEST` separately from execution authority, so it returns UNSUPPORTED for these five cases before evaluating the remaining policy and evidence conditions. Different reason strings would not change them. The run does not establish whether a different APS integration could support them.

## How the adapter maps a case

The adapter builds APS records from the synthetic evidence statuses in each vector. The run therefore does not test authentication of credentials supplied by the benchmark.

- Each evidence item becomes an `AuthorityDelegationV1` record, a root from `issueAuthorityDelegation` or the A to B link from `issueSubAuthorityDelegation`. VALID evidence is signed normally, INVALID has one signature hex digit changed, MISSING produces no record. Grants are `resource:action:target`, matched exactly.
- `verifyAuthorityDelegationChain` decides each chain and `scopeGrantCovers` checks the leaf against the requested action. The leaf subject has to be the actor.
- The relation comes from the chain shape. A single root issued to the actor is INDEPENDENT. A root with one child is DELEGATED, with the root issuer as source and the leaf issuer as immediate grantor.

## Limits

- Oracle exposure. The adapter author examined the expected results and the reference adapter before writing this adapter. The adapter does not read `expected`, but every match here is oracle-exposed.
- The relation rule and the UNSUPPORTED rule are adapter code, not SDK behavior.
- One change before the run. A smoke test on a synthetic case, not a vector, showed the SDK refusing a child whose `not_before` predates `issued_at`, so the adapter sets `not_before` equal to `issued_at`. Nothing changed after the run.
- The npm tarball was not mapped to a git commit.
- This is an oracle-exposed development run, not an independent implementation result. A future run claiming independent construction would need an adapter developed without access to the expected results or the reference decision logic, with its provenance documented.
