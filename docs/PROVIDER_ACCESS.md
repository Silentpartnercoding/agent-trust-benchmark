# Provider access required for live runs

No secret belongs in this repository or in a result file.

## Okta

Required configuration:

- `ATB_OKTA_ISSUER`
- `ATB_OKTA_CLIENT_ID`
- `ATB_OKTA_PRIVATE_KEY_FILE`
- a test authorization server or resource server exposing the equivalent of
  `payments:preview` and `payments:execute`
- permission to create/revoke the test grant and read its audit events

The Okta adapter currently stops at `BLOCKED_EXTERNAL_ACCESS` until that test
tenant contract is supplied. Okta's service-app flow is not treated as proof of
human-to-agent delegation by itself.

Reference: [Okta service-app OAuth guide](https://developer.okta.com/docs/guides/implement-oauth-for-okta-serviceapp/-/main/).

## Microsoft Entra

Required configuration:

- `ATB_ENTRA_TENANT_ID`
- `ATB_ENTRA_CLIENT_ID`
- `ATB_ENTRA_CLIENT_CERT_FILE` or a federated test credential
- a test resource application with separate preview and execute app roles
- permission to assign/revoke the test role and read sign-in/audit evidence

The Entra adapter currently stops at `BLOCKED_EXTERNAL_ACCESS` until that test
tenant contract is supplied. An app-only token is not treated as proof of a
human delegation unless the human authorization event is independently bound.

References: [Microsoft Entra authorization for applications, resources, and
workloads](https://learn.microsoft.com/en-us/entra/architecture/authorize-applications-resources-workloads)
and [permissions and consent](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview).
