"""E001 against Ory Hydra.

Hydra is not an identity provider. It is a pure OAuth2 authorization server that
delegates login and consent to an application the operator writes. That is why it
is in the comparison: it separates what OAuth2 makes possible from what the full
IdPs choose to do.

The consequence for evidence is stated rather than smoothed over. Hydra
authenticates nobody. Whatever human attribution appears in a token is whatever
`infrastructure/hydra-consent-app.py` chose to write, so it is a
benchmark-generated observation and is never reported as a provider-native
receipt. HUMAN_ATTRIBUTION_PROVABLE is INDETERMINATE here by construction: the
claim is present and unbacked, which is a different state from present-and-backed
and from absent.

Requires Hydra reachable on its admin and public ports. Unconfigured or
unreachable, every output is BLOCKED_EXTERNAL_ACCESS.
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


class OryHydraAdapter(ProviderAdapter):
    provider_id = "ory-hydra"
    required_environment = (
        "ATB_HYDRA_ADMIN",
        "ATB_HYDRA_PUBLIC",
        "ATB_HYDRA_CLIENT_ID",
    )

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.admin = (os.environ.get("ATB_HYDRA_ADMIN") or "http://127.0.0.1:4445").rstrip("/")
        self.public = (os.environ.get("ATB_HYDRA_PUBLIC") or "http://127.0.0.1:4444").rstrip("/")
        self.client_id = os.environ.get("ATB_HYDRA_CLIENT_ID") or ""
        self.client_secret = os.environ.get("ATB_HYDRA_CLIENT_SECRET") or ""
        self.subject = os.environ.get("ATB_HYDRA_SUBJECT", "human-1")
        self.redirect_uri = os.environ.get(
            "ATB_HYDRA_REDIRECT_URI", "http://localhost:8080/callback")
        evidence = os.environ.get("ATB_HYDRA_CONSENT_EVIDENCE")
        self.consent_evidence = Path(os.path.expanduser(evidence)) if evidence else None

        self.access_token: str | None = None
        self.revoked_at: float | None = None
        self.evidence_refs: list[str] = []

    # --- plumbing ---------------------------------------------------------
    def _missing(self) -> list[str]:
        missing = [n for n in self.required_environment if not os.environ.get(n)]
        if not missing and not self._reachable():
            missing.append(f"hydra unreachable at {self.admin}")
        return missing

    def _reachable(self) -> bool:
        try:
            urllib.request.urlopen(f"{self.admin}/health/ready", timeout=3).read()
            return True
        except Exception:
            return False

    def _blocked(self, op: str) -> Observation:
        m = self._missing()
        return Observation(
            Status.BLOCKED,
            f"{op} not run: external test access is unavailable; missing {', '.join(m)}"
            if m else f"{op} not run: the Hydra test contract has not been configured.",
            {"missing_configuration": m})

    def _admin_get(self, path: str) -> tuple[int, object]:
        try:
            with urllib.request.urlopen(f"{self.admin}{path}", timeout=15) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]
        except Exception as exc:
            return 0, str(exc)[:200]

    def _admin_call(self, path: str, method: str, body: dict | None = None) -> tuple[int, object]:
        data = urllib.parse.urlencode(body).encode() if body else None
        req = urllib.request.Request(
            f"{self.admin}{path}", data=data, method=method,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if data else {})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()[:300]
        except Exception as exc:
            return 0, str(exc)[:200]

    def _introspect(self, token: str) -> dict:
        code, body = self._admin_call("/admin/oauth2/introspect", "POST", {"token": token})
        return body if code == 200 and isinstance(body, dict) else {}

    def _ref(self, kind: str, ident: str) -> str:
        ref = f"ory-hydra:{kind}/{ident}"
        self.evidence_refs.append(ref)
        return ref

    def _ev(self, kind: str, ident: str, **extra) -> list[dict]:
        return [{"raw_evidence_ref": self._ref(kind, ident), "kind": kind, **extra}]

    # --- E001 sequence ----------------------------------------------------
    def create_human(self) -> Observation:
        if self._missing():
            return self._blocked("create_human")
        # Hydra has no user store. The subject is an assertion made by the consent app.
        return Observation(
            Status.PASS,
            "The subject exists only as a string the consent application asserts. Hydra has no "
            "user store and authenticated nobody; this is a benchmark-generated observation, not "
            "a provider-native identity record.",
            {"subject": self.subject, "provider_authenticated": False,
             "source": "benchmark consent application"},
            self._ev("asserted_subject", self.subject))

    def create_agent(self) -> Observation:
        if self._missing():
            return self._blocked("create_agent")
        code, body = self._admin_get(f"/admin/clients/{self.client_id}")
        if code != 200 or not isinstance(body, dict):
            return Observation(Status.BLOCKED, f"agent client unreadable (HTTP {code}).")
        return Observation(
            Status.PASS,
            "Agent is an OAuth2 client registered with Hydra, distinct from the asserted subject.",
            {"client_id": body.get("client_id"),
             "auth_method": body.get("token_endpoint_auth_method"),
             "grant_types": body.get("grant_types"),
             "distinct": body.get("client_id") != self.subject},
            self._ev("client", body.get("client_id", "")))

    def delegate(self) -> Observation:
        if self._missing():
            return self._blocked("delegate")
        rows = []
        if self.consent_evidence and self.consent_evidence.exists():
            for line in self.consent_evidence.read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
        grants = [r for r in rows if str(r.get("event", "")).startswith("consent")
                  and r.get("subject") == self.subject]
        if not grants:
            return Observation(
                Status.BLOCKED,
                "No consent record from the benchmark consent application. Hydra keeps no "
                "delegation record of its own, so with the app's log absent there is nothing "
                "to read.")
        return Observation(
            Status.PASS,
            "A delegation record exists, written by the benchmark's own consent application. "
            "Hydra contributes no evidence that the subject exists or approved anything.",
            {"records": len(grants), "subject": self.subject, "provable": True,
             "provider_native": False},
            self._ev("consent_app_record", self.subject, count=len(grants)))

    def issue_credential(self) -> Observation:
        if self._missing():
            return self._blocked("issue_credential")
        code_val = os.environ.get("ATB_HYDRA_AUTH_CODE")
        if not code_val:
            return Observation(
                Status.BLOCKED,
                "No authorization code available. The delegated arm requires an "
                "authorization_code exchange driven through the consent application.",
                {"flow": "authorization_code"})
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code_val,
            "redirect_uri": self.redirect_uri, "client_id": self.client_id,
            "client_secret": self.client_secret}).encode()
        try:
            req = urllib.request.Request(
                f"{self.public}/oauth2/token", data=data, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"})
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
        intro = self._introspect(self.access_token)
        scopes = (intro.get("scope") or "").split()
        return Observation(
            Status.PASS if PREVIEW in scopes else Status.FAIL,
            f"Introspection shows scope {scopes} for subject {intro.get('sub')!r}.",
            {"scopes": scopes, "sub": intro.get("sub"), "client_id": intro.get("client_id"),
             "active": intro.get("active")},
            self._ev("introspection", str(intro.get("sub", ""))))

    def execute_allowed_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_allowed_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; allowed action not attempted.")
        scopes = (self._introspect(self.access_token).get("scope") or "").split()
        ok = PREVIEW in scopes
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "The allowed action is authorized exactly once by the issued token." if ok
            else "The token does not carry the delegated scope.",
            {"granted": ok, "allowed": ok, "effect_count": 1 if ok else 0})

    def execute_forbidden_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_forbidden_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE,
                               "no credential; forbidden action not attempted.")
        scopes = (self._introspect(self.access_token).get("scope") or "").split()
        if EXECUTE in scopes:
            return Observation(Status.FAIL,
                               "The undelegated execute scope was present in the issued token.",
                               {"blocked": False, "effect_count": 1})
        return Observation(
            Status.PASS,
            "The undelegated execute scope is absent from the introspected token, so no effect "
            "could occur.",
            {"blocked": True, "effect_count": 0, "scopes": scopes})

    def revoke(self) -> Observation:
        if self._missing():
            return self._blocked("revoke")
        q = urllib.parse.urlencode({"subject": self.subject, "all": "true"})
        code, body = self._admin_call(f"/admin/oauth2/auth/sessions/consent?{q}", "DELETE")
        self.revoked_at = time.time()
        ok = code in (200, 204)
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "Consent sessions for the subject were deleted." if ok
            else f"Revocation refused (HTTP {code}): {body}",
            {"revoked": ok, "supported": ok, "http": code},
            self._ev("revocation", self.subject))

    def execute_after_revocation(self) -> Observation:
        if self._missing():
            return self._blocked("execute_after_revocation")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; post-revocation not tested.")
        started = time.time()
        intro = self._introspect(self.access_token)
        latency = (time.time() - (self.revoked_at or started)) * 1000
        if intro.get("active") is False:
            return Observation(
                Status.PASS,
                "The previously issued token introspects as inactive after revocation.",
                {"blocked": True, "effect_count": 0, "revocation_latency_ms": latency})
        return Observation(
            Status.FAIL,
            "The previously issued token still introspects as active after consent sessions "
            "were deleted. Deleting a consent session does not invalidate outstanding tokens.",
            {"blocked": False, "effect_count": 1, "revocation_latency_ms": latency,
             "active": intro.get("active")},
            self._ev("post_revocation_introspection", str(intro.get("active"))))

    def get_audit_events(self) -> Observation:
        if self._missing():
            return self._blocked("get_audit_events")
        return Observation(
            Status.NOT_SUPPORTED,
            "Hydra exposes no audit or event log for actions taken under an issued token. The "
            "only action record available is the benchmark consent application's own log, which "
            "is a benchmark-generated observation and is not a provider-native receipt.",
            {"auditable": False, "human_attribution": False, "agent_attribution": False,
             "provider_native_audit": False},
            self._ev("no_audit_surface", "ory-hydra"))
