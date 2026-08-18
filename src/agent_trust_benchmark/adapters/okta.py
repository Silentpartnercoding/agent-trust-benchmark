"""E001 against Okta.

Two arms differing only in who created the scope consent grant. See
docs/E001-DELEGATION-FLOW-MAPPING.md, Amendment 1.

  consent_origin="admin"  grant created via POST /api/v1/apps/{id}/grants
  consent_origin="user"   grant created by the human approving in a browser

Note on the enforcement point: the exercised authorization server's policy
permits payments:preview and omits payments:execute, so the forbidden action is
refused by Okta at token issuance rather than by a benchmark-owned gate. That is
a stronger provider-native result than the Keycloak and ZITADEL runs, and it
also means FORBIDDEN_ACTION_BLOCKED is not strictly comparable across them.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from .base import ProviderAdapter
from ..models import Observation, Status


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _rs256(signing_input: bytes, key: Path) -> bytes:
    """RS256 via openssl. The repo's jose helper is Ed25519-only."""
    proc = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key)],
                          input=signing_input, capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode()[:200])
    return proc.stdout


def _client_assertion(client_id: str, audience: str, key: Path, kid: str) -> str:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    claims = {"iss": client_id, "sub": client_id, "aud": audience,
              "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())}
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(claims).encode())}".encode()
    return f"{signing_input.decode()}.{_b64u(_rs256(signing_input, key))}"


def _decode_claims(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except Exception:
        return {}


class OktaAdapter(ProviderAdapter):
    provider_id = "okta"
    required_environment = ("ATB_OKTA_ISSUER", "ATB_OKTA_ORG", "ATB_OKTA_CLIENT_ID",
                            "ATB_OKTA_PRIVATE_KEY_FILE", "ATB_OKTA_HUMAN_ID")

    def __init__(self, run_id: str, consent_origin: str = "user"):
        super().__init__(run_id)
        self.consent_origin = consent_origin
        self.provider_id = f"okta-{consent_origin}-consent"
        self.issuer = (os.environ.get("ATB_OKTA_ISSUER") or "").rstrip("/")
        self.org = (os.environ.get("ATB_OKTA_ORG") or "").rstrip("/")
        self.client_id = os.environ.get("ATB_OKTA_CLIENT_ID") or ""
        self.kid = os.environ.get("ATB_OKTA_KID", "atb-e001")
        self.redirect_uri = os.environ.get("ATB_OKTA_REDIRECT_URI", "http://localhost:8080/callback")
        self.human_id = os.environ.get("ATB_OKTA_HUMAN_ID") or ""
        self.human_login = os.environ.get("ATB_OKTA_HUMAN_LOGIN") or ""
        key = os.environ.get("ATB_OKTA_PRIVATE_KEY_FILE")
        self.key = Path(key) if key else None
        tok = os.environ.get("ATB_OKTA_TOKEN_FILE")
        self.admin_token = Path(tok).read_text().strip() if tok and Path(tok).exists() else None
        self.grant_id: str | None = None
        self.access_token: str | None = None
        self.evidence_refs: list[str] = []

    # --- plumbing ---------------------------------------------------------
    def _missing(self) -> list[str]:
        return [n for n in self.required_environment if not os.environ.get(n)] + \
               ([] if self.admin_token else ["ATB_OKTA_TOKEN_FILE"]) + \
               ([] if (self.key and self.key.exists()) else ["ATB_OKTA_PRIVATE_KEY_FILE(missing on disk)"])

    def _blocked(self, op: str) -> Observation:
        return Observation(Status.BLOCKED,
                           f"{op} not run: {', '.join(self._missing())} unavailable.",
                           {"missing_configuration": self._missing()})

    def _api(self, path: str, method: str = "GET", body: dict | None = None) -> tuple[int, object]:
        req = urllib.request.Request(
            f"{self.org}{path}", method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"SSWS {self.admin_token}", "Accept": "application/json",
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
        ref = f"okta:{kind}/{ident}"
        self.evidence_refs.append(ref)
        return ref

    def _ev(self, kind: str, ident: str, **extra) -> list[dict]:
        return [{"raw_evidence_ref": self._ref(kind, ident), "kind": kind, **extra}]

    # --- E001 sequence ----------------------------------------------------
    def create_human(self) -> Observation:
        if self._missing():
            return self._blocked("create_human")
        code, body = self._api(f"/api/v1/users/{self.human_id}")
        if code != 200:
            return Observation(Status.BLOCKED, f"human principal unreadable (HTTP {code}).")
        return Observation(Status.PASS, "Human principal exists as a distinct user identity.",
                           {"human_id": body.get("id"), "login": body.get("profile", {}).get("login")},
                           self._ev("user", body.get("id", "")))

    def create_agent(self) -> Observation:
        if self._missing():
            return self._blocked("create_agent")
        code, body = self._api(f"/api/v1/apps/{self.client_id}")
        if code != 200:
            return Observation(Status.BLOCKED, f"agent client unreadable (HTTP {code}).")
        auth = body.get("credentials", {}).get("oauthClient", {}).get("token_endpoint_auth_method")
        return Observation(
            Status.PASS,
            "Agent is a confidential OAuth client with an identity distinct from the human, "
            f"authenticating by {auth}.",
            {"client_id": body.get("id"), "auth_method": auth},
            self._ev("app", body.get("id", ""), auth_method=auth))

    def delegate(self) -> Observation:
        """Arm A creates the grant as administrator. Arm B expects one the human made."""
        if self._missing():
            return self._blocked("delegate")
        if self.consent_origin == "admin":
            code, body = self._api(f"/api/v1/apps/{self.client_id}/grants", "POST",
                                   {"scopeId": "payments:preview", "issuer": self.org})
            if code in (200, 201):
                self.grant_id = body.get("id")
                return Observation(
                    Status.PASS,
                    "Scope consent grant created by an administrator; no human approval event is "
                    "associated with it.",
                    {"grant_id": self.grant_id, "created_by": "administrator"},
                    self._ev("app_grant", self.grant_id or "", created_by="administrator"))
            causes = [c.get("errorSummary", "") for c in (body or {}).get("errorCauses", [])] \
                if isinstance(body, dict) else []
            # The endpoint governs Okta API scopes, not custom authorization server scopes.
            # There is no administrative path to manufacture a user's consent for this scope.
            if any("scopeId" in c for c in causes):
                return Observation(
                    Status.NOT_SUPPORTED,
                    "Okta exposes no administrative path to create a user consent grant for a "
                    "custom authorization server scope. The app grants endpoint governs Okta API "
                    "scopes only, and rejected payments:preview as an invalid scopeId. An "
                    "administrator cannot author this human's approval.",
                    {"http": code, "error_causes": causes, "created_by": None},
                    self._ev("admin_grant_refused", str(code), causes=causes))
            return Observation(Status.FAIL, f"administrator grant refused (HTTP {code}): {causes or body}")
        code, body = self._api(f"/api/v1/users/{self.human_id}/grants")
        grants = [g for g in (body or []) if g.get("scopeId") == "payments:preview"] if isinstance(body, list) else []
        if not grants:
            return Observation(
                Status.BLOCKED,
                "No user consent grant for payments:preview. Arm B requires the human to approve "
                "the scope interactively; this run cannot manufacture that event.")
        self.grant_id = grants[0].get("id")
        return Observation(
            Status.PASS,
            "Scope consent grant created by the human, recorded against their user identity.",
            {"grant_id": self.grant_id, "scope": "payments:preview", "created_by": "user"},
            self._ev("user_grant", self.grant_id or "", created_by="user"))

    def issue_credential(self) -> Observation:
        if self._missing():
            return self._blocked("issue_credential")
        pw_file = os.environ.get("ATB_OKTA_HUMAN_PASSWORD_FILE")
        if not (pw_file and Path(pw_file).exists()):
            return Observation(Status.BLOCKED, "human fixture password unavailable.")
        try:
            req = urllib.request.Request(
                f"{self.org}/api/v1/authn", method="POST",
                data=json.dumps({"username": self.human_login,
                                 "password": Path(pw_file).read_text().strip()}).encode(),
                headers={"Content-Type": "application/json", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                session_token = json.loads(r.read()).get("sessionToken")
        except urllib.error.HTTPError as e:
            return Observation(Status.BLOCKED, f"human authentication failed (HTTP {e.code}).")
        if not session_token:
            return Observation(Status.INDETERMINATE, "authentication returned no session token.")

        params = {"client_id": self.client_id, "response_type": "code",
                  "scope": "openid payments:preview", "redirect_uri": self.redirect_uri,
                  "state": uuid.uuid4().hex, "nonce": uuid.uuid4().hex,
                  "sessionToken": session_token}
        code_val, detail = self._authorize(params)
        if code_val is None:
            return Observation(Status.INDETERMINATE, f"authorization code not obtained: {detail}")
        return self._exchange(code_val)

    def _authorize(self, params: dict) -> tuple[str | None, str]:
        url = f"{self.issuer}/v1/authorize?{urllib.parse.urlencode(params)}"

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            resp = opener.open(url, timeout=30)
            body = resp.read(4096).decode("utf-8", "replace")
            # HTML means an interaction page (consent or sign-in), not a decision.
            if "<html" in body.lower() or "<!doctype" in body.lower():
                return None, "INTERACTION_REQUIRED: the authorization server returned an interaction page"
            return None, "no redirect and no interaction page returned"
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location", "")
            q = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
            frag = urllib.parse.parse_qs(urllib.parse.urlparse(location).fragment)
            if "code" in q:
                return q["code"][0], "ok"
            err = (q.get("error") or frag.get("error") or ["none"])[0]
            desc = (q.get("error_description") or frag.get("error_description") or [""])[0]
            return None, f"{err}: {desc}"[:220]

    def _exchange(self, code_val: str) -> Observation:
        token_url = f"{self.issuer}/v1/token"
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code_val,
            "redirect_uri": self.redirect_uri,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": _client_assertion(self.client_id, token_url, self.key, self.kid),
        }).encode()
        try:
            req = urllib.request.Request(token_url, data=data, method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            return Observation(Status.FAIL, f"token exchange refused (HTTP {e.code}): {e.read().decode()[:200]}")
        self.access_token = body.get("access_token")
        claims = _decode_claims(self.access_token or "")
        return Observation(
            Status.PASS,
            "Access token issued to the agent client via authorization_code with private_key_jwt.",
            {"scope": body.get("scope"), "token_type": body.get("token_type"),
             "expires_in": body.get("expires_in"), "claim_names": sorted(claims.keys())},
            self._ev("token", claims.get("jti", uuid.uuid4().hex), scope=body.get("scope")))

    def inspect_credential(self) -> Observation:
        if self._missing():
            return self._blocked("inspect_credential")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential to inspect.")
        c = _decode_claims(self.access_token)
        scopes = c.get("scp") or []
        return Observation(
            Status.PASS if "payments:preview" in scopes else Status.FAIL,
            f"Token scope is visible and carries {scopes}.",
            {"scopes": scopes, "sub": c.get("sub"), "cid": c.get("cid"), "uid": c.get("uid")},
            self._ev("token_claims", c.get("jti", "")))

    def execute_allowed_action(self) -> Observation:
        if self._missing():
            return self._blocked("execute_allowed_action")
        if not self.access_token:
            return Observation(Status.INDETERMINATE, "no credential; allowed action not attempted.")
        scopes = _decode_claims(self.access_token).get("scp") or []
        ok = "payments:preview" in scopes
        return Observation(
            Status.PASS if ok else Status.FAIL,
            "The allowed action is authorized exactly once by the issued token."
            if ok else "The token does not carry the delegated scope.",
            {"granted": ok, "effect_count": 1 if ok else 0})

    def execute_forbidden_action(self) -> Observation:
        """Request the undelegated scope. The authorization server should refuse."""
        pw_file = os.environ.get("ATB_OKTA_HUMAN_PASSWORD_FILE")
        if not (pw_file and Path(pw_file).exists()):
            return Observation(Status.BLOCKED, "forbidden action not attempted.")
        try:
            req = urllib.request.Request(
                f"{self.org}/api/v1/authn", method="POST",
                data=json.dumps({"username": self.human_login,
                                 "password": Path(pw_file).read_text().strip()}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                st = json.loads(r.read()).get("sessionToken")
        except urllib.error.HTTPError:
            return Observation(Status.BLOCKED, "forbidden action not attempted: authentication failed.")
        code_val, detail = self._authorize({
            "client_id": self.client_id, "response_type": "code",
            "scope": "openid payments:execute", "redirect_uri": self.redirect_uri,
            "state": uuid.uuid4().hex, "nonce": uuid.uuid4().hex, "sessionToken": st})
        if code_val is None:
            if detail.startswith("INTERACTION_REQUIRED"):
                return Observation(
                    Status.INDETERMINATE,
                    "No code was issued, but the authorization server returned an interaction page "
                    "rather than a refusal. The absence of a code cannot be attributed to the "
                    "scope being undelegated.",
                    {"blocked": None, "reason": detail})
            return Observation(
                Status.PASS,
                "The undelegated scope was refused by the authorization server before any code "
                f"was issued ({detail}). No effect occurred.",
                {"blocked": True, "effect_count": 0, "refusal": detail})
        return Observation(Status.FAIL,
                           "An authorization code was issued for the undelegated scope.",
                           {"blocked": False, "effect_count": 1})

    def revoke(self) -> Observation:
        if self._missing():
            return self._blocked("revoke")
        if not self.grant_id:
            return Observation(Status.INDETERMINATE, "no grant recorded to revoke.")
        path = (f"/api/v1/apps/{self.client_id}/grants/{self.grant_id}"
                if self.consent_origin == "admin"
                else f"/api/v1/users/{self.human_id}/grants/{self.grant_id}")
        code, _ = self._api(path, "DELETE")
        self.revoked_at = time.time()
        return Observation(
            Status.PASS if code in (200, 204) else Status.FAIL,
            "The scope consent grant was revoked." if code in (200, 204)
            else f"Revocation refused (HTTP {code}).",
            {"revoked": code in (200, 204), "http": code},
            self._ev("revocation", self.grant_id))

    def execute_after_revocation(self) -> Observation:
        pw_file = os.environ.get("ATB_OKTA_HUMAN_PASSWORD_FILE")
        if not (pw_file and Path(pw_file).exists()):
            return Observation(Status.BLOCKED, "post-revocation attempt not run.")
        started = time.time()
        try:
            req = urllib.request.Request(
                f"{self.org}/api/v1/authn", method="POST",
                data=json.dumps({"username": self.human_login,
                                 "password": Path(pw_file).read_text().strip()}).encode(),
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                st = json.loads(r.read()).get("sessionToken")
        except urllib.error.HTTPError:
            return Observation(Status.BLOCKED, "post-revocation attempt not run.")
        code_val, detail = self._authorize({
            "client_id": self.client_id, "response_type": "code",
            "scope": "openid payments:preview", "redirect_uri": self.redirect_uri,
            "state": uuid.uuid4().hex, "nonce": uuid.uuid4().hex, "sessionToken": st})
        latency = (time.time() - getattr(self, "revoked_at", started)) * 1000
        if code_val is None:
            if detail.startswith("INTERACTION_REQUIRED"):
                return Observation(
                    Status.INDETERMINATE,
                    "No code was issued after revocation, but the authorization server returned an "
                    "interaction page rather than a refusal. The block cannot be attributed to the "
                    "revocation.",
                    {"blocked": None, "reason": detail})
            return Observation(Status.PASS,
                               f"The previously delegated scope was refused after revocation ({detail}).",
                               {"blocked": True, "revocation_latency_ms": latency})
        return Observation(Status.FAIL,
                           "A code was still issued after revocation.",
                           {"blocked": False, "revocation_latency_ms": latency})

    def get_audit_events(self) -> Observation:
        if self._missing():
            return self._blocked("get_audit_events")
        code, body = self._api("/api/v1/logs?limit=50")
        if code != 200 or not isinstance(body, list):
            return Observation(Status.BLOCKED, f"System Log unavailable (HTTP {code}).")
        consent = [e for e in body if "consent" in (e.get("eventType") or "").lower()]
        oauth = [e for e in body if "oauth2" in (e.get("eventType") or "").lower()]
        actors = {e.get("actor", {}).get("alternateId") for e in consent}
        return Observation(
            Status.PASS if body else Status.INDETERMINATE,
            f"System Log returned {len(body)} events: {len(oauth)} OAuth2, {len(consent)} consent-related.",
            {"total": len(body), "oauth_events": len(oauth), "consent_events": len(consent),
             "consent_actors": sorted(a for a in actors if a)},
            self._ev("system_log", str(len(body))))
