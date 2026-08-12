# E001 result: okta

Run: `e001-okta-8704dc94-a5f7-4ccf-a720-01c3b89bf77d`
Started: `2026-08-11T16:34:04.714771Z`
Completed: `2026-08-11T16:34:04.714815Z`

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **BLOCKED_EXTERNAL_ACCESS** | create_agent not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `DELEGATION_PROVABLE` | **BLOCKED_EXTERNAL_ACCESS** | delegate not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `SCOPE_VISIBLE` | **BLOCKED_EXTERNAL_ACCESS** | inspect_credential not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `ALLOWED_ACTION_SUCCEEDS` | **BLOCKED_EXTERNAL_ACCESS** | execute_allowed_action not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `FORBIDDEN_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | execute_forbidden_action not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `HUMAN_ATTRIBUTION_PROVABLE` | **BLOCKED_EXTERNAL_ACCESS** | get_audit_events not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `AGENT_ATTRIBUTION_PROVABLE` | **BLOCKED_EXTERNAL_ACCESS** | get_audit_events not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `ACTION_AUDITABLE` | **BLOCKED_EXTERNAL_ACCESS** | get_audit_events not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `REVOCATION_SUPPORTED` | **BLOCKED_EXTERNAL_ACCESS** | revoke not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |
| `POST_REVOCATION_ACTION_BLOCKED` | **BLOCKED_EXTERNAL_ACCESS** | execute_after_revocation not run: external test access is unavailable; missing ATB_OKTA_ISSUER, ATB_OKTA_CLIENT_ID, ATB_OKTA_PRIVATE_KEY_FILE, ATB_OKTA_RESOURCE_SERVER |

## Metrics

- `REVOCATION_LATENCY_MS`: `None`
- `TOKEN_LIFETIME_SECONDS`: `None`
- `EVIDENCE_COMPLETENESS_PERCENT`: `0.0`

## Named limitations

- No vendor behavior was tested because required external tenant access was unavailable.

No raw credential, token, signature, or private key is included in this result.
