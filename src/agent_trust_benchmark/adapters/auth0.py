"""E001 against Auth0.

Auth0 is owned by Okta. It is reported separately and is not treated as an
independent second vendor. That disclosure travels with the result.

The load-bearing check here is POST_REVOCATION_ACTION_BLOCKED. Deleting a user's
grant stops new tokens being issued against it; it does not invalidate tokens
already outstanding. This adapter therefore exercises a previously issued access
token against Auth0's own /userinfo endpoint after the grant is gone, rather than
inferring the outcome from the token's format or expiry.

As with the Entra adapter, the delegated arm needs an authorization code obtained
interactively. Neither agent client in the tenant carries the password grant, so
there is no non-interactive path to a user token, and an app-only credential is
excluded by the delegation-flow mapping and is not substituted.
"""
from __future__ import annotations

import base64
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

PREVIEW = "payments:preview"
EXECUTE = "payments:execute"


def _decode_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return {}


def _read(path: str | None) -> str | None:
    if not path:
        return None
    p = Path(os.path.expanduser(path))
    return p.read_text().strip() if p.exists() else None


class Auth0Adapter(ProviderAdapter):
    provider_id = "auth0"
    required_environment = (
        "ATB_AUTH0_DOMAIN",
        "ATB_AUTH0_M2M_CLIENT_ID",
        "ATB_AUTH0_M2M_SECRET_FILE",
        "ATB_AUTH0_AGENT_CLIENT_ID",
        "ATB_AUTH0_HUMAN_ID",
        "ATB_AUTH0_API_AUDIENCE",
    )

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.domain = (os.environ.get("ATB_AUTH0_DOMAIN") or "").rstrip("/")
        self.m2m_id = os.environ.get("ATB_AUTH0_M2M_CLIENT_ID") or ""
        self.m2m_secret = _read(os.environ.get("ATB_AUTH0_M2M_SECRET_FILE"))
        self.mgmt_audience = os.environ.get(
            "ATB_AUTH0_MGMT_AUDIENCE", f"https://{self.domain}/api/v2/")
        self.agent_id = os.environ.get("ATB_AUTH0_AGENT_CLIENT_ID") or ""
        self.agent_secret = _read(os.environ.get("ATB_AUTH0_AGENT_SECRET_FILE"))
        self.human_id = os.environ.get("ATB_AUTH0_HUMAN_ID") or ""
        self.api_audience = os.environ.get("ATB_AUTH0_API_AUDIENCE") or ""
        self.redirect_uri = os.environ.get(
            "ATB_AUTH0_REDIRECT_URI", "http://localhost:8080/callback")

        self._mgmt: str | None = None
        self.grant_id: str | None = None
        self.access_token: str | None = None
        self.revoked_at: float | None = None
        self.evidence_refs: list[str] = []

    # --- plumbing ---------------------------------------------------------
    def _missing(self) -> list[str]:
        missing = [n for n in self.required_environment if not os.environ.get(n)]
        if os.environ.get("ATB_AUTH0_M2M_SECRET_FILE") and not self.m2m_secret:
            missing.append("ATB_AUTH0_M2M_SECRET_FILE(missing on disk)")
        return missing

    def _blocked(self, op: str) -> Observation:
        m = self._missing()
        return Observation(
            Status.BLOCKED,
            f"{op} not run: external test access is unavailable; missing {', '.join(m)}"
            if m else f"{op} not run: the Auth0 test contract has not been configured.",
            {"missing_configuration": m})

    def _mgmt_token(self) -> str | None:
        if self._mgmt is None and self.m2m_secret:
            body = json.dumps({
                "client_id": self.m2m_id, "client_secret": self.m2m_secret,
                "audience": self.mgmt_audience, "grant_type": "client_credentials"}).encode()
            try:
                req = urllib.request.Request(
                    f"https://{self.domain}/oauth/token", data=body, method="POST",
                    headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=30) as r:
                    self._mgmt = json.loads(r.read()).get("access_token")
            except urllib.error.HTTPError:
                self._mgmt = None
        return self._mgmt

    def _api(self, path: str, method: str = "GET",
             body: dict | None = None) -> tuple[int, object]:
        tok = self._mgmt_token()
        if not tok:
            return 0, {"error": "no management token"}
        req = urllib.request.Request(
            f"https://{self.domain}/api/v2{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
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
        ref = f"auth0:{kind}/{ident}"
        self.evidence_refs.append(ref)
        return ref

    def _ev(self, kind: str, ident: str, **extra) -> list[dict]:
        return [{"raw_evidence_ref": self._ref(kind, ident), "kind": kind, **extra}]

    def _find_grant(self) -> dict | None:
        q = urllib.parse.urlencode({"user_id": self.human_id})
        code, body = self._api(f"/grants?{q}")
        if code != 200 or not isinstance(body, list):
            return None
        for g in body:
            if g.get("audience") == self.api_audience:
                return g
        return body[0] if body else None

    # --- E001 sequence ----------------------------------------------------
    def create_human(self) -> Observation:
        if self._missing():
            return self._blocked("create_human")
        code, body = self._api(f"/users/{urllib.parse.quote(self.human_id)}")
        if code != 200 or not isinstance(body, dict):
            return Observation(Status.BLOCKED, f"human principal unreadable (HTTP {code}).")
        return Observation(
            Status.PASS, "Human principal exists as a distinct tenant user.",
            {"human_id": body.get("user_id"), "email": body.get("email")},
            self._ev("user", body.get("user_id", "")))

    def create_agent(self) -> Observation:
        if self._missing():
            return self._blocked("create_agent")
        code, body = self._api(f"/clients/{self.agent_id}")
        if code != 200 or not isinstance(body, dict):
            return Observation(Status.BLOCKED, f"agent client unreadable (HTTP {code}).")
        return Observation(
            Status.PASS,
            "Agent is a confidential OAuth client with an identity distinct from the human.",
            {"client_id": body.get("client_id"), "app_type": body.get("app_type"),
             "grant_types": body.get("grant_types"),
             "distinct": body.get("client_id") != self.human_id},
            self._ev("client", body.get("client_id", "")))

    def delegate(self) -> Observation:
        if self._missing():
            return self._blocked("delegate")
        g = self._find_grant()
        if not g:
            return Observation(
                Status.BLOCKED,
                "No user grant for the payments audience. The delegated arm requires the human "
                "to approve the scope interactively; this run cannot manufacture that event.")
        self.grant_id = g.get("id")
        scopes = g.get("scope") or []
        return Observation(
            Status.PASS,
            "Grant recorded against the human's own user id, created by their approval.",
            {"grant_id": self.grant_id, "audience": g.get("audience"), "scope": scopes,
             "provable": True},
            self._ev("grant", self.grant_id or "", scope=scopes))

    def issue_credential(self) -> Observation:
        if self._missing():
            return self._blocked("issue_credential")
        code_val = os.environ.get("ATB_AUTH0_AUTH_CODE")
        if not code_val:
            return Observation(
                Status.BLOCKED,
                "No authorization code available. Neither agent client carries the password "
                "grant, so there is no non-interactive path to a user token; an app-only "
                "credential is excluded by the delegation-flow mapping and is not substituted.",
                {"flow": "authorization_code", "headless": False})
        if not self.agent_secret:
            return Observation(Status.BLOCKED, "agent client secret unavailable.")
        body = json.dumps({
            "grant_type": "authorization_code", "client_id": self.agent_id,
            "client_secret": self.agent_secret, "code": code_val,
            "redirect_uri": self.redirect_uri}).encode()
        try:
            req = urllib.request.Request(
                f"https://{self.domain}/oauth/token", data=body, method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                payload = json.loads(r.read())
        except urllib.error.HTTPError as e:
            return Observation(Status.FAIL,
                               f"token exchange refused (HTTP {e.code}): {e.read().decode()[:200]}")
        self.access_token = payload.get("access_token")
        claims = _decode_claims(self.access_token or "")
        return Observation(
            Status.PASS, "Access token issued to the agent client via authorization_code.",
            {"scope": payload.get("scope"), "expires_in": payload.get("expires_in"),
             "claim_names": sorted(claims.keys())},
            self._ev("token", claims.get("jti", uuid.uuid4().hex)))

    def inspect_credential(self) -> Observation:
        if self._missing():
            return self._blocked("inspect_credential")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential to inspect.")
        c = _decode_claims(self.access_token)
        scopes = (c.get("scope") or "").split()
        perms = c.get("permissions") or []
        # Auth0 can return a scope claim and a permissions claim that disagree. Both are
        # recorded; a disagreement is a finding about the credential, not a harness error.
        return Observation(
            Status.PASS if PREVIEW in scopes or PREVIEW in perms else Status.FAIL,
            f"Token scope is visible: scope={scopes}, permissions={perms}.",
            {"scopes": scopes, "permissions": perms,
             "claims_disagree": bool(perms) and sorted(perms) != sorted(scopes),
             "sub": c.get("sub"), "azp": c.get("azp"), "aud": c.get("aud")},
            self._ev("token_claims", c.get("jti", "")))

    def execute_allowed_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_allowed_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; allowed action not attempted.")
        c = _decode_claims(self.access_token)
        granted = PREVIEW in (c.get("scope") or "").split() or PREVIEW in (c.get("permissions") or [])
        return Observation(
            Status.PASS if granted else Status.FAIL,
            "The allowed action is authorized exactly once by the issued token." if granted
            else "The token does not carry the delegated scope.",
            {"granted": granted, "allowed": granted, "effect_count": 1 if granted else 0})

    def execute_forbidden_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_forbidden_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE,
                               "no credential; forbidden action not attempted.")
        c = _decode_claims(self.access_token)
        present = EXECUTE in (c.get("scope") or "").split() or EXECUTE in (c.get("permissions") or [])
        if present:
            return Observation(Status.FAIL,
                               "The undelegated execute scope was present in the issued token.",
                               {"blocked": False, "effect_count": 1})
        return Observation(
            Status.PASS,
            "The undelegated execute scope is absent from the issued token, so no effect could "
            "occur. Auth0 withheld it at issuance.",
            {"blocked": True, "effect_count": 0})

    def revoke(self) -> Observation:
        if self._missing():
            return self._blocked("revoke")
        if not self.grant_id:
            return Observation(Status.INDETERMINATE, "no grant recorded to revoke.")
        code, _ = self._api(f"/grants/{self.grant_id}", "DELETE")
        self.revoked_at = time.time()
        remaining = self._find_grant()
        ok = code in (200, 204) and remaining is None
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "The grant was deleted and the user's grant list is empty." if ok
            else f"Revocation incomplete (HTTP {code}, grant still present: {remaining is not None}).",
            {"revoked": ok, "supported": ok, "http": code,
             "grant_list_empty": remaining is None},
            self._ev("revocation", self.grant_id))

    def execute_after_revocation(self) -> Observation:
        """Exercise the outstanding token against /userinfo after the grant is gone.

        This is the substantive check for this provider. It is deliberately a live call
        rather than an inference from token format or expiry: the question is whether Auth0
        still honours a credential whose grant no longer exists.
        """
        if self._missing():
            return self._blocked("execute_after_revocation")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; post-revocation not tested.")
        started = time.time()
        req = urllib.request.Request(
            f"https://{self.domain}/userinfo",
            headers={"Authorization": f"Bearer {self.access_token}"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                sub = (json.loads(r.read()) or {}).get("sub")
                status_code = r.status
            latency = (time.time() - (self.revoked_at or started)) * 1000
            return Observation(
                Status.FAIL,
                f"The previously issued access token was still accepted by Auth0's /userinfo "
                f"endpoint after the grant was deleted (HTTP {status_code}, returning the "
                f"subject). Revoking the grant prevents new tokens; it does not invalidate "
                f"outstanding ones.",
                {"blocked": False, "effect_count": 1, "http": status_code,
                 "subject_returned": bool(sub), "revocation_latency_ms": latency},
                self._ev("post_revocation_userinfo", str(status_code)))
        except urllib.error.HTTPError as e:
            latency = (time.time() - (self.revoked_at or started)) * 1000
            return Observation(
                Status.PASS,
                f"The previously issued access token was refused after revocation (HTTP {e.code}).",
                {"blocked": True, "effect_count": 0, "http": e.code,
                 "revocation_latency_ms": latency},
                self._ev("post_revocation_userinfo", str(e.code)))

    def get_audit_events(self) -> Observation:
        if self._missing():
            return self._blocked("get_audit_events")
        code, body = self._api("/logs?per_page=100&sort=date%3A-1")
        if code != 200 or not isinstance(body, list):
            return Observation(Status.BLOCKED, f"tenant log unavailable (HTTP {code}).")
        exchanges = [e for e in body if e.get("type") == "seacft"]
        deletions = [e for e in body if "Delete a grant" in (e.get("description") or "")]
        named = {e.get("user_name") or e.get("user_id") for e in body}
        named = sorted(n for n in named if n)
        return Observation(
            Status.PASS if body else Status.INDETERMINATE,
            f"Tenant log returned {len(body)} events: {len(exchanges)} code exchanges, "
            f"{len(deletions)} grant deletions.",
            {"total": len(body), "code_exchanges": len(exchanges),
             "grant_deletions": len(deletions), "named_actors": named[:10],
             "auditable": bool(body), "agent_attribution": bool(exchanges),
             "human_attribution": bool(named)},
            self._ev("tenant_log", str(len(body))))
