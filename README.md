# Agent Trust Benchmark

A vendor-neutral, evidence-first benchmark for agent identity, delegated
authority, enforcement, attribution, auditability, and revocation.

## ELI5

This project tests whether an agent has a valid passport and permission slip
before it acts. It keeps four questions separate:

1. **Who is the agent?**
2. **Which human authorized it?**
3. **What exact action may it perform?**
4. **Can an independent gateway prove all of that before the action happens?**

It also tests two different ways agents can work together:

- **Delegate:** A gives B a smaller piece of A's own authority.
- **Mandate:** A requests an exact action that B is independently authorized
  to perform; A does not give B B's permission.

The benchmark is the product. Providers are adapters. A missing credential or
API is reported as `BLOCKED_EXTERNAL_ACCESS`; it is never replaced by a mock
provider and presented as vendor evidence.

## First experiment

`E001: Human -> Agent -> Action` asks whether an independent observer can
establish:

1. who authorized an agent;
2. what exact authority the agent received;
3. whether an allowed action succeeded;
4. whether a forbidden action was blocked;
5. whether the human, agent, and action can be reconstructed from evidence; and
6. whether revocation prevents another action, and how quickly.

See [the preregistration](docs/E001.md) for the frozen question, sequence, and
status rules.

The second preregistered experiment is [E002](docs/E002.md). It tests a
provider-neutral [Human Authorization Receipt](docs/HUMAN-AUTHORIZATION-RECEIPT.md)
designed to bind a witnessed human authorization event to the exact agent
credential and action checked by the gate.

## Run it

```bash
python3 -m venv .venv
.venv/bin/pip install -e .

benchmark run e001 --provider baseline
benchmark run e001 --provider keycloak-opa
benchmark run e001 --provider zitadel-opa
benchmark run e001 --provider okta
benchmark run e001 --provider entra
benchmark run e001 --provider all
```

Every run prints a human-readable table and writes machine-readable JSON plus a
Markdown summary under `results/e001/`. Raw credentials are never written.

With the matching local provider fixture running, E002 is invoked directly:

```bash
PYTHONPATH=src python3 -m agent_trust_benchmark.e002 --provider keycloak
PYTHONPATH=src python3 -m agent_trust_benchmark.e002 --provider zitadel
```

E002 writes the same two reviewable formats under `results/e002/` and retains
no raw token, signed credential, proof, signature, or private key.

[E004](docs/E004.md) and [E005](docs/E005.md) are isolated cross-runtime thin
slices. E004 exercises derived delegation from A to an SDK-free B. E005
exercises authorized invocation ("Mandate"), where A may request one exact
action and B independently holds execution authority. Neither is a production
provider result.

```bash
PYTHONPATH=src python3 -m agent_trust_benchmark e004 --output-dir results/e004/latest
PYTHONPATH=src python3 -m agent_trust_benchmark e005 --output-dir results/e005/latest
```

The checked-in Notion-style reference runs passed 16/16 delegation checks and
19/19 Mandate checks. They are exploratory mock-resource results, not a claim
of production Notion integration or universal enforcement.

## Current provider boundary

- `baseline`: fully runnable local reference implementation.
- `keycloak-opa`: a local composed open-source control. Keycloak supplies
  identity/token evidence and OPA supplies pre-effect decisions.
- `zitadel-opa`: a local audit-first open-source control. ZITADEL supplies the
  human and service-account identities, role grant, opaque token,
  introspection, revocation, and change history. The same OPA policy is reused
  so enforcement stays fixed across both open-source controls.
- `okta`: returns `BLOCKED_EXTERNAL_ACCESS` until the variables in
  [provider access](docs/PROVIDER_ACCESS.md) are supplied.
- `entra`: returns `BLOCKED_EXTERNAL_ACCESS` until the variables in
  [provider access](docs/PROVIDER_ACCESS.md) are supplied.

The blocked adapters are intentional measurement controls. They stop missing
access from being confused with a provider failure or a successful simulation.
