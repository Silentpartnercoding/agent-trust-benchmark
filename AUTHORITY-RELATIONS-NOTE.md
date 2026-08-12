# Candidate Authority Relation Interoperability Vectors v0.1

Status: **candidate synthetic conformance fixture**

## Invariant

> REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE.

An `A -> B` request proves that A asked B to do something. It does not, by
itself, prove that authority moved from A to B.

```text
DELEGATION                         INDEPENDENT AUTHORITY / MANDATE

Principal H                       Workflow policy H ── request authority ──→ A
    │                             Resource admin C ─ execution authority ─→ B
    ▼                                                                    ▲
Agent A ── delegated authority ─→ Agent B        A ─── request only ─────┘
```

The observable request can look similar. The authority relations are not.

## Eight vectors

1. valid attenuated delegation;
2. valid independently authorized Mandate;
3. requester authority required by policy but missing, while B is independently authorized;
4. authorized requester with an unauthorized executor;
5. no authority path;
6. spoofed delegation; and
7. independent authority mislabeled as delegation; and
8. permissionless request where A needs no permission but B must verify exact,
   independent execution authority before acting.

Vectors 3 and 8 deliberately contain identical observed evidence. Only the
declared policy differs. Vector 3 denies because that policy requires A to have
request authority. Vector 8 allows because its policy permits anyone to ask,
while B still proves authority for the exact action. This pair prevents the
suite from smuggling one universal authorization policy into relationship
classification.

The verdict is not enough. An adapter must report the requester, actor,
evidence status, declared and derived relations, request-authority source,
execution-authority source, policy profile, and authorization reason.

## Two-stage decision

1. **Classify evidence:** derive whether B's authority is `DELEGATED`,
   `INDEPENDENT`, or `NONE`. A claimed relationship is untrusted input and is
   compared with, not used to determine, the derived relationship.
2. **Apply policy:** decide whether the derived relationship, request
   authority, evidence state, and claimed relationship are acceptable under
   the vector's explicit policy.

This means “A may ask” and “B may act” can be separate questions. In the
permissionless vector, B must check its own exact execution authority even
though A needs no authority merely to send the request.

## Black-box adapter contract

An adapter is an executable that:

1. reads one `atb-authority-relation-case/0.1` JSON object from standard input;
2. receives only observed evidence and explicit policy, never the expected oracle;
3. writes one `atb-authority-relation-output/0.1` JSON object to standard output;
4. writes no secrets or credentials; and
5. exits nonzero when it cannot evaluate the case.

An implementation that cannot represent a relation should return
`status: UNSUPPORTED`; the runner records that separately from an incorrect
`ALLOW` or `DENY`. The output also separates the evidence classification from
the policy verdict and the root execution-authority
source from the immediate grantor, so `Principal H -> A -> B` is not flattened
into an ambiguous single name.

Run the reference controls:

```bash
PYTHONPATH=src python3 -m agent_trust_benchmark authority-relations \
  --output-dir results/authority-relations-v0.1/latest
```

Or evaluate another implementation:

```bash
PYTHONPATH=src python3 -m agent_trust_benchmark authority-relations \
  --adapter path/to/adapter \
  --output-dir /tmp/authority-relations
```

`delegation_only.py` is intentionally wrong: it treats request causality as
proof that A delegated to B. `relation_aware.py` derives request and execution
authority paths independently, then applies the supplied policy. Tests rename
the fixture identities, sources, resource, action, and target to catch trivial
case-ID or literal-name hardcoding in the reference adapter.

## Claim boundary

This suite tests the semantics of supplied synthetic, post-verification
authority evidence. It does not authenticate the evidence, validate a
signature, discover credentials, define a credential format, delegation
protocol, OAuth profile, agent identity system, or universal production
policy. It has not tested any external protocol, proprietary integration, or
commercial provider. An outside implementation may correctly report that it
cannot represent a relation; that is not the same as incorrectly authorizing
it.
