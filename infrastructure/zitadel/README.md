# Local ZITADEL E001 control

This fixture pins ZITADEL `v4.15.0`, PostgreSQL `17.2-alpine`, and OPA `1.19.0`.
It binds only to loopback and uses conspicuous local-only fixture credentials.

The bootstrap creates two different principals:

- `human-e001`, the human identity referenced by the experiment; and
- `atb-admin-service`, an automation-only administrator whose PAT provisions
  the E001 project, roles, service account, and grant through ZITADEL's API.

The PAT is written to `runtime/admin.pat`. That directory is ignored by Git and
must never be copied into results. The tested agent is created separately and is
not the bootstrap administrator.

OPA uses the exact same benchmark-owned policy as the Keycloak control. This
keeps the enforcement point fixed so the comparison isolates the identity and
delegation evidence supplied by each provider.

Start a clean instance:

```sh
docker compose -f infrastructure/zitadel/docker-compose.yml down -v
mkdir -p infrastructure/zitadel/runtime
docker compose -f infrastructure/zitadel/docker-compose.yml up -d --wait
```

Run E001:

```sh
PYTHONPATH=src python3 -m agent_trust_benchmark run e001 --provider zitadel
```

The adapter labels administrator-created delegation honestly. It does not treat
an administrator's grant as proof of interactive human consent.
