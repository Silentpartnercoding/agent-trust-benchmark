# E001 result: okta-admin-consent

Run: `e001-okta-admin-consent-v1`  
Arm: A (administrator-granted)

| Output | Status | Evidence-led explanation |
|---|---|---|
| `DISTINCT_AGENT_IDENTITY` | **PASS** | The agent is a confidential OAuth client with an identity distinct from the human. |
| `DELEGATION_PROVABLE` | **NOT_SUPPORTED** | Okta exposes no administrative path to create a user consent grant for a custom authorization server scope. POST /api/v1/apps/{id}/grants governs Okta API scopes and rejected payments:preview with "scopeId: 'scopeId' is invalid". An administrator cannot author this human's approval. |
| `SCOPE_VISIBLE` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `ALLOWED_ACTION_SUCCEEDS` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `FORBIDDEN_ACTION_BLOCKED` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `HUMAN_ATTRIBUTION_PROVABLE` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `AGENT_ATTRIBUTION_PROVABLE` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `REVOCATION_SUPPORTED` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `POST_REVOCATION_ACTION_BLOCKED` | **INDETERMINATE** | Not reached: the arm could not establish a delegation, so no credential was issued and downstream behaviour was not exercised. |
| `ACTION_AUDITABLE` | **PASS** | The System Log is readable and returned events for the org. |

## Metrics

- `EVIDENCE_COMPLETENESS_PERCENT`: `30.0`

## Named limitations

- This arm did not fail; it could not be constructed. Okta refuses the administrative grant that the arm exists to test.
- Amendment 1 predicted that every check other than HUMAN_ATTRIBUTION_PROVABLE would be identical across the two arms. That prediction is now untestable rather than confirmed, because Arm A cannot reach those checks. It is recorded here rather than dropped.

No raw credential, token, signature, or private key is included in this result.
