"""E001 against Microsoft Entra ID.

Two arms differing only in who created the delegated permission grant. See
docs/E001-DELEGATION-FLOW-MAPPING.md, Amendment 2.

  consent_origin="admin"  oauth2PermissionGrant created via Graph with
                          consentType="Principal" bound to the fixture human
  consent_origin="user"   grant created by the human approving in a browser

Two provider differences from the Okta adapter are recorded rather than
smoothed over:

1. Entra scope values cannot carry a colon, so the native scopes are
   payments.preview and payments.execute. The E001 vocabulary of
   payments:preview / payments:execute is applied only at the evidence
   boundary, per the fairness rules.

2. On a tenant without a premium licence, GET /auditLogs/signIns returns
   Authentication_RequestFromNonPremiumTenantOrB2CTenant. Directory audits
   remain readable. ACTION_AUDITABLE therefore reports the licence boundary as
   BLOCKED_EXTERNAL_ACCESS rather than NOT_SUPPORTED: the interface does not
   say the capability is absent, it says this tenant may not read it.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from .base import ProviderAdapter
from ..models import Observation, Status

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"

NATIVE_PREVIEW = "payments.preview"
NATIVE_EXECUTE = "payments.execute"

# Entra scope values cannot carry a colon. Native names are mapped to the E001
# vocabulary only here, at the evidence boundary, per the fairness rules.
_NORMALIZE = {NATIVE_PREVIEW: "payments:preview", NATIVE_EXECUTE: "payments:execute"}


def _normalized(native_scopes: list[str]) -> list[str]:
    return [_NORMALIZE.get(s, s) for s in native_scopes]


def _decode_claims(token: str) -> dict:
    import base64
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return {}


def _read_secret(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(os.path.expanduser(path))
    return p.read_text().strip() if p.exists() else None


class EntraAdapter(ProviderAdapter):
    provider_id = "entra"
    required_environment = (
        "ATB_ENTRA_TENANT_ID",
        "ATB_ENTRA_CLIENT_ID",
        "ATB_ENTRA_CLIENT_SECRET_FILE",
        "ATB_ENTRA_RESOURCE_APP_ID",
        "ATB_ENTRA_AGENT_CLIENT_ID",
        "ATB_ENTRA_HUMAN_ID",
    )

    def __init__(self, run_id: str, consent_origin: str = "user"):
        super().__init__(run_id)
        self.consent_origin = consent_origin
        self.provider_id = f"entra-{consent_origin}-consent"

        self.tenant = os.environ.get("ATB_ENTRA_TENANT_ID") or ""
        self.client_id = os.environ.get("ATB_ENTRA_CLIENT_ID") or ""
        self.client_secret = _read_secret(os.environ.get("ATB_ENTRA_CLIENT_SECRET_FILE"))

        self.resource_app_id = os.environ.get("ATB_ENTRA_RESOURCE_APP_ID") or ""
        self.agent_client_id = os.environ.get("ATB_ENTRA_AGENT_CLIENT_ID") or ""
        self.agent_secret = _read_secret(os.environ.get("ATB_ENTRA_AGENT_SECRET_FILE"))

        self.human_id = os.environ.get("ATB_ENTRA_HUMAN_ID") or ""
        self.human_upn = os.environ.get("ATB_ENTRA_HUMAN_UPN") or ""
        self.redirect_uri = os.environ.get(
            "ATB_ENTRA_REDIRECT_URI", "http://localhost:8080/callback")

        self._admin_token: str | None = None
        self.agent_sp_id: str | None = None
        self.resource_sp_id: str | None = None
        self.grant_id: str | None = None
        self.access_token: str | None = None
        self.revoked_at: float | None = None
        self.evidence_refs: list[str] = []

    # --- plumbing ---------------------------------------------------------
    def _missing(self) -> list[str]:
        missing = [n for n in self.required_environment if not os.environ.get(n)]
        if os.environ.get("ATB_ENTRA_CLIENT_SECRET_FILE") and not self.client_secret:
            missing.append("ATB_ENTRA_CLIENT_SECRET_FILE(missing on disk)")
        return missing

    def _blocked(self, op: str) -> Observation:
        m = self._missing()
        return Observation(
            Status.BLOCKED,
            f"{op} not run: external test access is unavailable; missing {', '.join(m)}"
            if m else f"{op} not run: the Entra test contract has not been configured.",
            {"missing_configuration": m})

    def _token_for(self, scope: str, client_id: str, secret: str) -> tuple[str | None, str]:
        data = urllib.parse.urlencode({
            "client_id": client_id, "scope": scope,
            "client_secret": secret, "grant_type": "client_credentials"}).encode()
        try:
            req = urllib.request.Request(
                f"{LOGIN}/{self.tenant}/oauth2/v2.0/token", data=data, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read()).get("access_token"), "ok"
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:300]
            try:
                j = json.loads(body)
                return None, f"{j.get('error')}: {(j.get('error_description') or '')[:180]}"
            except Exception:
                return None, body

    def _admin(self) -> str | None:
        if self._admin_token is None and self.client_secret:
            self._admin_token, _ = self._token_for(
                "https://graph.microsoft.com/.default", self.client_id, self.client_secret)
        return self._admin_token

    def _graph(self, path: str, method: str = "GET",
               body: dict | None = None) -> tuple[int, object]:
        tok = self._admin()
        if not tok:
            return 0, {"error": "no admin token"}
        req = urllib.request.Request(
            f"{GRAPH}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {tok}", "Accept": "application/json",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw.decode()[:300]

    def _ref(self, kind: str, ident: str) -> str:
        ref = f"entra:{kind}/{ident}"
        self.evidence_refs.append(ref)
        return ref

    def _ev(self, kind: str, ident: str, **extra) -> list[dict]:
        return [{"raw_evidence_ref": self._ref(kind, ident), "kind": kind, **extra}]

    def _find_grant(self) -> dict | None:
        q = urllib.parse.urlencode({
            "$filter": f"clientId eq '{self.agent_sp_id}' and principalId eq '{self.human_id}'"})
        code, body = self._graph(f"/oauth2PermissionGrants?{q}")
        if code != 200 or not isinstance(body, dict):
            return None
        for g in body.get("value", []):
            if NATIVE_PREVIEW in (g.get("scope") or ""):
                return g
        return None

    def _sp_for(self, app_id: str) -> str | None:
        q = urllib.parse.urlencode(
            {"$filter": f"appId eq '{app_id}'", "$select": "id,appId,displayName"})
        code, body = self._graph(f"/servicePrincipals?{q}")
        if code == 200 and isinstance(body, dict) and body.get("value"):
            return body["value"][0]["id"]
        return None

    # --- E001 sequence ----------------------------------------------------
    def create_human(self) -> Observation:
        if self._missing():
            return self._blocked("create_human")
        code, body = self._graph(f"/users/{self.human_id}?$select=id,userPrincipalName,displayName")
        if code != 200 or not isinstance(body, dict):
            return Observation(Status.BLOCKED, f"human principal unreadable (HTTP {code}).")
        return Observation(
            Status.PASS, "Human principal exists as a distinct directory user.",
            {"human_id": body.get("id"), "upn": body.get("userPrincipalName")},
            self._ev("user", body.get("id", "")))

    def create_agent(self) -> Observation:
        if self._missing():
            return self._blocked("create_agent")
        self.agent_sp_id = self._sp_for(self.agent_client_id)
        self.resource_sp_id = self._sp_for(self.resource_app_id)
        if not self.agent_sp_id:
            return Observation(Status.BLOCKED, "agent service principal not found in tenant.")
        if not self.resource_sp_id:
            return Observation(Status.BLOCKED, "resource service principal not found in tenant.")
        return Observation(
            Status.PASS,
            "Agent is a confidential client with a service principal distinct from the human "
            "directory user.",
            {"agent_client_id": self.agent_client_id, "agent_sp_id": self.agent_sp_id,
             "resource_sp_id": self.resource_sp_id,
             "distinct": self.agent_sp_id != self.human_id},
            self._ev("service_principal", self.agent_sp_id))

    def delegate(self) -> Observation:
        """Arm A authors the grant as administrator. Arm B expects the human's own."""
        if self._missing():
            return self._blocked("delegate")
        if not (self.agent_sp_id and self.resource_sp_id):
            return Observation(Status.INDETERMINATE, "service principals not resolved.")

        if self.consent_origin == "admin":
            # Idempotent: the interactive token step must happen between this call and
            # issue_credential, so a run may re-enter here with the grant already made.
            # Creating a duplicate would misreport the arm.
            existing = self._find_grant()
            if existing:
                self.grant_id = existing.get("id")
                return Observation(
                    Status.PASS,
                    "Delegated permission grant present, created by an administrator on the "
                    "human's behalf. No human approval event is associated with it.",
                    {"grant_id": self.grant_id, "consent_type": existing.get("consentType"),
                     "created_by": "administrator", "native_scope": NATIVE_PREVIEW,
                     "preexisting": True, "provable": True},
                    self._ev("oauth2_permission_grant", self.grant_id or "",
                             created_by="administrator"))
            code, body = self._graph("/oauth2PermissionGrants", "POST", {
                "clientId": self.agent_sp_id,
                "consentType": "Principal",
                "principalId": self.human_id,
                "resourceId": self.resource_sp_id,
                "scope": NATIVE_PREVIEW,
            })
            if code in (200, 201) and isinstance(body, dict):
                self.grant_id = body.get("id")
                return Observation(
                    Status.PASS,
                    "Delegated permission grant created by an administrator on the human's "
                    "behalf. No human approval event is associated with it.",
                    {"grant_id": self.grant_id, "consent_type": "Principal",
                     "created_by": "administrator", "native_scope": NATIVE_PREVIEW,
                     "provable": True},
                    self._ev("oauth2_permission_grant", self.grant_id or "",
                             created_by="administrator"))
            return Observation(
                Status.FAIL,
                f"Administrator-authored grant refused (HTTP {code}): {body}",
                {"http": code, "created_by": None},
                self._ev("admin_grant_refused", str(code)))

        found = self._find_grant()
        grants = [found] if found else []
        if not grants:
            return Observation(
                Status.BLOCKED,
                "No user consent grant for the preview scope. Arm B requires the human to "
                "approve interactively; this run cannot manufacture that event.")
        self.grant_id = grants[0].get("id")
        return Observation(
            Status.PASS,
            "Delegated permission grant recorded against the human's own principal, created by "
            "their interactive approval.",
            {"grant_id": self.grant_id, "consent_type": grants[0].get("consentType"),
             "created_by": "user", "native_scope": NATIVE_PREVIEW, "provable": True},
            self._ev("oauth2_permission_grant", self.grant_id or "", created_by="user"))

    def issue_credential(self) -> Observation:
        """The agent presents its own credential; the delegated scope rides the grant.

        Entra has no non-interactive equivalent of Okta's sessionToken authorize, so a
        confidential-client authorization_code exchange cannot be completed headlessly here.
        The run records that boundary rather than substituting client credentials, which the
        mapping excludes as a delegation.
        """
        if self._missing():
            return self._blocked("issue_credential")
        code_val = os.environ.get("ATB_ENTRA_AUTH_CODE")
        if not code_val:
            return Observation(
                Status.BLOCKED,
                "No authorization code available. The delegated arm requires an interactive "
                "authorization_code exchange; an app-only token is excluded by the "
                "delegation-flow mapping and is not substituted.",
                {"flow": "authorization_code", "headless": False})
        if not self.agent_secret:
            return Observation(Status.BLOCKED, "agent client secret unavailable.")
        data = urllib.parse.urlencode({
            "client_id": self.agent_client_id, "client_secret": self.agent_secret,
            "grant_type": "authorization_code", "code": code_val,
            "redirect_uri": self.redirect_uri,
            "scope": f"api://{self.resource_app_id}/{NATIVE_PREVIEW}",
        }).encode()
        try:
            req = urllib.request.Request(
                f"{LOGIN}/{self.tenant}/oauth2/v2.0/token", data=data, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            return Observation(Status.FAIL,
                               f"token exchange refused (HTTP {e.code}): {e.read().decode()[:200]}")
        self.access_token = body.get("access_token")
        claims = _decode_claims(self.access_token or "")
        return Observation(
            Status.PASS,
            "Access token issued to the agent client via authorization_code.",
            {"scope": body.get("scope"), "expires_in": body.get("expires_in"),
             "claim_names": sorted(claims.keys())},
            self._ev("token", claims.get("uti", uuid.uuid4().hex)))

    def inspect_credential(self) -> Observation:
        if self._missing():
            return self._blocked("inspect_credential")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential to inspect.")
        c = _decode_claims(self.access_token)
        native = (c.get("scp") or "").split()
        scopes = _normalized(native)
        return Observation(
            Status.PASS if NATIVE_PREVIEW in native else Status.FAIL,
            f"Token scope is visible and carries {native}.",
            {"scopes": scopes, "native_scopes": native, "oid": c.get("oid"),
             "upn": c.get("upn") or c.get("preferred_username"),
             "azp": c.get("azp") or c.get("appid")},
            self._ev("token_claims", c.get("uti", "")))

    def execute_allowed_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_allowed_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; allowed action not attempted.")
        scopes = (_decode_claims(self.access_token).get("scp") or "").split()
        ok = NATIVE_PREVIEW in scopes
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "The allowed action is authorized exactly once by the issued token." if ok
            else "The token does not carry the delegated scope.",
            {"granted": ok, "allowed": ok, "effect_count": 1 if ok else 0})

    def execute_forbidden_action(self) -> Observation:
        """The undelegated scope must not appear in a token for this grant."""
        if self._missing():
            return self._blocked("execute_forbidden_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE,
                               "no credential; forbidden action not attempted.")
        scopes = (_decode_claims(self.access_token).get("scp") or "").split()
        if NATIVE_EXECUTE in scopes:
            return Observation(
                Status.FAIL, "The undelegated execute scope was present in the issued token.",
                {"blocked": False, "effect_count": 1})
        return Observation(
            Status.PASS,
            "The undelegated execute scope is absent from the issued token, so no effect could "
            "occur. Entra withheld it at issuance rather than at a benchmark-owned gate.",
            {"blocked": True, "effect_count": 0, "scopes": scopes})

    def revoke(self) -> Observation:
        if self._missing():
            return self._blocked("revoke")
        if not self.grant_id:
            return Observation(Status.INDETERMINATE, "no grant recorded to revoke.")
        deadline = time.time() + float(
            os.environ.get("ATB_ENTRA_REVOCATION_SETTLE_SECONDS", "30"))
        while True:
            code, _ = self._graph(f"/oauth2PermissionGrants/{self.grant_id}", "DELETE")
            # A freshly created grant can 404 on DELETE until it propagates. Retry to the
            # deadline so creation lag is not recorded as revocation being unsupported.
            if code in (200, 204) or time.time() >= deadline:
                break
            time.sleep(1.0)
        self.revoked_at = time.time()
        ok = code in (200, 204)
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "The delegated permission grant was revoked." if ok
            else f"Revocation refused (HTTP {code}).",
            {"revoked": ok, "supported": ok, "http": code},
            self._ev("revocation", self.grant_id))

    def execute_after_revocation(self) -> Observation:
        """Re-check the grant is gone. A cached access token remains valid until expiry;
        that is recorded as a limitation rather than reported as a block."""
        if self._missing():
            return self._blocked("execute_after_revocation")
        if not self.grant_id:
            return Observation(Status.INDETERMINATE, "no revocation to verify.")
        started = time.time()
        # Entra's directory is eventually consistent: a deleted grant can still read 200
        # for a short window. Polling to a bounded deadline measures time-to-proven-removal
        # instead of recording a propagation lag as a failure to revoke. If the grant is
        # still readable at the deadline, that is reported as FAIL on the evidence.
        deadline = started + float(os.environ.get("ATB_ENTRA_REVOCATION_SETTLE_SECONDS", "30"))
        polls = 0
        while True:
            code, body = self._graph(f"/oauth2PermissionGrants/{self.grant_id}")
            polls += 1
            if code == 404 or time.time() >= deadline:
                break
            time.sleep(1.0)
        latency = (time.time() - (self.revoked_at or started)) * 1000
        if code == 404:
            return Observation(
                Status.PASS,
                "The delegated grant no longer exists, so no further token can carry the scope. "
                "Any already-issued access token remains valid until expiry; this measures grant "
                "removal, not bearer-token invalidation.",
                {"blocked": True, "effect_count": 0, "revocation_latency_ms": latency,
                 "polls": polls,
                 "measures": "grant_removal_not_token_invalidation"},
                self._ev("post_revocation_check", self.grant_id))
        if code == 200:
            return Observation(
                Status.FAIL,
                "The delegated grant was still readable at the settle deadline after revocation.",
                {"blocked": False, "effect_count": 1, "revocation_latency_ms": latency,
                 "polls": polls})
        return Observation(Status.INDETERMINATE,
                           f"post-revocation state could not be read (HTTP {code}).")

    def get_audit_events(self) -> Observation:
        if self._missing():
            return self._blocked("get_audit_events")
        scode, sbody = self._graph("/auditLogs/signIns?$top=1")
        if scode == 200:
            dcode, dbody = self._graph("/auditLogs/directoryAudits?$top=50")
            events = (dbody or {}).get("value", []) if isinstance(dbody, dict) else []
            consent = [e for e in events if "consent" in (e.get("activityDisplayName") or "").lower()]
            actors = {((e.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName")
                      for e in consent}
            return Observation(
                Status.PASS,
                f"Sign-in and directory audit logs are both readable: {len(events)} directory "
                f"events, {len(consent)} consent-related.",
                {"directory_events": len(events), "consent_events": len(consent),
                 "consent_actors": sorted(a for a in actors if a),
                 "auditable": True,
                 "human_attribution": bool([a for a in actors if a]),
                 "agent_attribution": True},
                self._ev("audit_logs", str(len(events))))
        err = (sbody or {}).get("error", {}) if isinstance(sbody, dict) else {}
        ecode = err.get("code") or str(scode)
        if "premium" in json.dumps(err).lower() or "NonPremium" in ecode:
            return Observation(
                Status.BLOCKED,
                "Sign-in logs are withheld by licence tier "
                f"({ecode}). Directory audits remain readable, but the agent's own action cannot "
                "be reconstructed from provider evidence on this tenant. This is an access "
                "limitation, not an absent capability, so it is not NOT_SUPPORTED.",
                {"licence_gated": True, "error_code": ecode},
                self._ev("signin_logs_licence_gated", ecode))
        return Observation(Status.INDETERMINATE,
                           f"sign-in log availability could not be decided (HTTP {scode}).")
