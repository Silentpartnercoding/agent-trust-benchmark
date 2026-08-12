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

## Seven vectors

1. valid attenuated delegation;
2. valid independently authorized Mandate;
3. unauthorized requester with an independently authorized executor;
4. authorized requester with an unauthorized executor;
5. no authority path;
6. spoofed delegation; and
7. independent authority mislabeled as delegation.

The verdict is not enough. An adapter must report the requester, actor,
request-authority source, execution-authority source, verified relation, and
authorization reason.

## Black-box adapter contract

An adapter is an executable that:

1. reads one `atb-authority-relation-case/0.1` JSON object from standard input;
2. receives only observed evidence, never the expected oracle;
3. writes one `atb-authority-relation-output/0.1` JSON object to standard output;
4. writes no secrets or credentials; and
5. exits nonzero when it cannot evaluate the case.

An implementation that cannot represent a relation should return
`status: UNSUPPORTED`; the runner records that separately from an incorrect
`ALLOW` or `DENY`. The output also separates the root execution-authority
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
proof that A delegated to B. `relation_aware.py` tracks the request and
execution authority paths independently.

## Claim boundary

This suite tests the semantics of supplied synthetic authority evidence. It
does not define a credential format, delegation protocol, OAuth profile, agent
identity system, or production policy. It has not tested any external
protocol, proprietary integration, or commercial provider. An outside
implementation may correctly report that it cannot represent a relation; that
is not the same as incorrectly authorizing it.
