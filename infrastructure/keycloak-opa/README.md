# Keycloak + OPA E001 fixture

This is an isolated local research fixture, not a production deployment.

- Keycloak issues and introspects a token binding a human subject, the agent
  client, a preview-only realm role, and an imported delegation identifier.
- OPA independently decides whether the requested action is allowed and emits a
  decision identifier.
- The benchmark resource performs an effect only after both token introspection
  and the OPA decision succeed.

The fixture uses obvious `local-*` credentials, listens only on loopback, keeps
no database volume, and contains no external credential.

```bash
docker compose up -d
ATB_KEYCLOAK_OPA_URL=http://127.0.0.1:18080 \
ATB_OPA_URL=http://127.0.0.1:18181 \
  benchmark run e001 --provider keycloak-opa
docker compose down
```

The password grant is used only to make the experiment deterministic and
non-interactive. The resulting token proves that Keycloak bound the human
subject and agent client, but it must not be described as an interactive user
consent ceremony.
