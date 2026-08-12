from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import ProviderAdapter
from ..models import Observation, Status


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ZitadelOpaAdapter(ProviderAdapter):
    provider_id = "zitadel-opa"

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.zitadel = os.environ.get("ATB_ZITADEL_URL", "http://localhost:28080").rstrip("/")
        self.opa = os.environ.get("ATB_ZITADEL_OPA_URL", "http://127.0.0.1:28181").rstrip("/")
        self.pat_path = Path(os.environ.get("ATB_ZITADEL_PAT_PATH", "infrastructure/zitadel/runtime/admin.pat"))
        self.admin_pat: str | None = None
        self.human_id: str | None = None
        self.agent_id: str | None = None
        self.project_id: str | None = None
        self.grant_id: str | None = None
        self.delegation_id: str | None = None
        self.agent_client_id: str | None = None
        self.agent_client_secret: str | None = None
        self.api_client_id: str | None = None
        self.api_client_secret: str | None = None
        self.token: str | None = None
        self.credential_id: str | None = None
        self.introspection: dict[str, Any] = {}
        self.decision_ids: list[str] = []
        self.revocation_started: float | None = None

    def _request(
        self,
        url: str,
        *,
        method: str = "GET",
        form: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
        bearer: str | None = None,
        basic: tuple[str, str] | None = None,
    ) -> Any:
        headers: dict[str, str] = {"Accept": "application/json"}
        data: bytes | None = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        if basic:
            encoded = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read()
            return json.loads(payload) if payload else {}

    def _api(
        self,
        path: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not self.admin_pat:
            self.admin_pat = self.pat_path.read_text().strip()
        return self._request(
            f"{self.zitadel}/management/v1{path}",
            method=method,
            body=body,
            bearer=self.admin_pat,
        )

    def _blocked(self, operation: str, error: Exception | None = None) -> Observation:
        suffix = f" ({type(error).__name__})" if error else ""
        return Observation(
            Status.BLOCKED,
            f"{operation} not run: the local ZITADEL + OPA fixture is unavailable{suffix}.",
        )

    def _roles(self, introspection: dict[str, Any] | None = None) -> list[str]:
        value = (introspection or self.introspection).get("urn:zitadel:iam:org:project:roles", {})
        return sorted(value) if isinstance(value, dict) else []

    def _event(
        self,
        event_type: str,
        raw_ref: str,
        *,
        origin: str = "provider_native",
        action: str | None = None,
        decision: str = "observe",
        effect_count: int = 0,
        event_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "0.1",
            "provider": self.provider_id,
            "experiment_id": "e001",
            "run_id": self.run_id,
            "event_type": event_type,
            "human_id": self.human_id,
            "agent_id": self.agent_id,
            "credential_id": self.credential_id,
            "delegation_id": self.delegation_id,
            "requested_scopes": [f"payments:{action}"] if action else [],
            "granted_scopes": ["payments:preview"] if "payments_preview" in self._roles() else [],
            "resource": "payments" if action else None,
            "action": action,
            "decision": decision,
            "effect_count": effect_count,
            "observed_at": _iso(),
            "provider_event_id": event_id,
            "correlation_id": self.run_id,
            "evidence_origin": origin,
            "raw_evidence_ref": raw_ref,
        }

    def create_human(self) -> Observation:
        try:
            response = self._api(
                "/users/_search",
                method="POST",
                body={
                    "queries": [
                        {
                            "userNameQuery": {
                                "userName": "human-e001",
                                "method": "TEXT_QUERY_METHOD_CONTAINS_IGNORE_CASE",
                            }
                        }
                    ]
                },
            )
            humans = [user for user in response.get("result", []) if "human" in user]
            if len(humans) != 1:
                return Observation(Status.FAIL, "The fixture did not expose exactly one E001 human.")
            self.human_id = humans[0]["id"]
            event = self._event("human.directory_record", "zitadel:management/users/human-e001")
            return Observation(
                Status.PASS,
                "ZITADEL exposes one verified human directory identity.",
                {"human_id": self.human_id},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("create_human", error)

    def create_agent(self) -> Observation:
        try:
            project = self._api(
                "/projects",
                method="POST",
                body={
                    "name": f"E001 Payments {self.run_id[-8:]}",
                    "projectRoleAssertion": True,
                    "projectRoleCheck": True,
                },
            )
            self.project_id = project["id"]
            for role in ("payments_preview", "payments_execute"):
                self._api(
                    f"/projects/{self.project_id}/roles",
                    method="POST",
                    body={"roleKey": role, "displayName": role.replace("_", " ").title()},
                )
            agent = self._api(
                "/users/machine",
                method="POST",
                body={
                    "userName": f"agent-e001-{self.run_id[-8:]}",
                    "name": "E001 Agent",
                    "description": "Local E001 benchmark fixture",
                    "accessTokenType": "ACCESS_TOKEN_TYPE_BEARER",
                },
            )
            self.agent_id = agent["userId"]
            secret = self._api(f"/users/{self.agent_id}/secret", method="PUT", body={})
            self.agent_client_id = secret["clientId"]
            self.agent_client_secret = secret["clientSecret"]
            resource_app = self._api(
                f"/projects/{self.project_id}/apps/api",
                method="POST",
                body={"name": "E001 Resource Server", "authMethodType": "API_AUTH_METHOD_TYPE_BASIC"},
            )
            self.api_client_id = resource_app["clientId"]
            self.api_client_secret = resource_app["clientSecret"]
            event = self._event("agent.service_account_created", f"zitadel:management/users/{self.agent_id}")
            return Observation(
                Status.PASS,
                "ZITADEL created a service-account identity distinct from the human and a separate resource-server client.",
                {"agent_id": self.agent_id, "distinct": self.agent_id != self.human_id},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("create_agent", error)

    def delegate(self) -> Observation:
        if not self.human_id or not self.agent_id or not self.project_id:
            return self._blocked("delegate")
        try:
            self.delegation_id = f"zitadel-delegation-{uuid.uuid4()}"
            bindings = {
                "e001_delegated_by": self.human_id,
                "e001_delegation_id": self.delegation_id,
            }
            for key, value in bindings.items():
                self._api(
                    f"/users/{self.agent_id}/metadata/{key}",
                    method="POST",
                    body={"value": base64.b64encode(value.encode()).decode()},
                )
            grant = self._api(
                f"/users/{self.agent_id}/grants",
                method="POST",
                body={"projectId": self.project_id, "roleKeys": ["payments_preview"]},
            )
            self.grant_id = grant["userGrantId"]
            metadata = self._api(f"/users/{self.agent_id}/metadata/_search", method="POST", body={})
            decoded = {
                item["key"]: base64.b64decode(item["value"]).decode()
                for item in metadata.get("result", [])
                if item.get("key") in bindings
            }
            user_grant = self._api(f"/users/{self.agent_id}/grants/{self.grant_id}")["userGrant"]
            provable = decoded == bindings and user_grant.get("roleKeys") == ["payments_preview"]
            event = self._event(
                "delegation.configuration",
                f"zitadel:management/users/{self.agent_id}/metadata-and-grant/{self.grant_id}",
            )
            return Observation(
                Status.PASS if provable else Status.FAIL,
                "ZITADEL records an administrator-configured human-to-agent link and preview-only role grant; this is not an interactive human-consent record.",
                {"provable": provable, "authorization_mode": "administrator_configured"},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("delegate", error)

    def issue_credential(self) -> Observation:
        if not all((self.project_id, self.agent_client_id, self.agent_client_secret)):
            return self._blocked("issue_credential")
        try:
            scope = f"openid profile urn:zitadel:iam:org:project:id:{self.project_id}:aud"
            response = self._request(
                f"{self.zitadel}/oauth/v2/token",
                method="POST",
                form={"grant_type": "client_credentials", "scope": scope},
                basic=(self.agent_client_id, self.agent_client_secret),
            )
            self.token = response["access_token"]
            self.credential_id = "sha256:" + hashlib.sha256(self.token.encode()).hexdigest()
            event = self._event("credential.issued", "zitadel:oauth/token/credential-hash")
            return Observation(
                Status.PASS,
                "ZITADEL issued an opaque access token to the service account for the E001 project audience.",
                {
                    "credential_id": self.credential_id,
                    "token_lifetime_seconds": response.get("expires_in"),
                },
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("issue_credential", error)

    def _introspect(self) -> dict[str, Any]:
        if not self.token or not self.api_client_id or not self.api_client_secret:
            return {"active": False}
        return self._request(
            f"{self.zitadel}/oauth/v2/introspect",
            method="POST",
            form={"token": self.token},
            basic=(self.api_client_id, self.api_client_secret),
        )

    def inspect_credential(self) -> Observation:
        try:
            self.introspection = self._introspect()
            roles = self._roles()
            bound = (
                self.introspection.get("active") is True
                and self.introspection.get("sub") == self.agent_id
                and self.introspection.get("client_id") == self.agent_client_id
                and self.project_id in self.introspection.get("aud", [])
            )
            event = self._event("credential.introspected", "zitadel:oauth/introspection/credential-hash")
            return Observation(
                Status.PASS if bound else Status.FAIL,
                "ZITADEL introspection binds the live token to the service account, project audience, and preview role; it does not carry the human link.",
                {"scopes": ["payments:preview"] if "payments_preview" in roles else [], "bound": bound},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("inspect_credential", error)

    def _decide(self, action: str) -> Observation:
        try:
            self.introspection = self._introspect()
            response = self._request(
                f"{self.opa}/v1/data/agent_authz/decision",
                method="POST",
                body={
                    "input": {
                        "token_active": self.introspection.get("active") is True,
                        "human_id": self.human_id or "",
                        "agent_id": self.introspection.get("sub", ""),
                        "delegation_id": self.delegation_id or "",
                        "roles": self._roles(),
                        "resource": "payments",
                        "action": action,
                    }
                },
            )
            allowed = response["result"]["allow"] is True
            effect_count = 1 if allowed else 0
            decision_id = response.get("decision_id") or f"opa-response-{uuid.uuid4()}"
            self.decision_ids.append(decision_id)
            event = self._event(
                "policy.allowed" if allowed else "policy.denied",
                f"opa:decision/{decision_id}",
                origin="enforcement_point",
                action=action,
                decision="allow" if allowed else "deny",
                effect_count=effect_count,
                event_id=decision_id,
            )
            return Observation(
                Status.PASS,
                f"ZITADEL introspection plus OPA {'allowed' if allowed else 'denied'} payments:{action}; effect count is {effect_count}.",
                {
                    "allowed": allowed,
                    "blocked": not allowed,
                    "effect_count": effect_count,
                    "agent_attribution": self.introspection.get("sub") == self.agent_id,
                },
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked(f"execute_{action}", error)

    def execute_allowed_action(self) -> Observation:
        return self._decide("preview")

    def execute_forbidden_action(self) -> Observation:
        return self._decide("execute")

    def get_audit_events(self) -> Observation:
        if not self.agent_id or not self.project_id:
            return self._blocked("get_audit_events")
        try:
            user_changes = self._api(f"/users/{self.agent_id}/changes/_search", method="POST", body={})
            project_changes = self._api(f"/projects/{self.project_id}/changes/_search", method="POST", body={})
            user_event_types = {
                json.dumps(item.get("eventType"), sort_keys=True)
                for item in user_changes.get("result", [])
            }
            project_event_types = {
                json.dumps(item.get("eventType"), sort_keys=True)
                for item in project_changes.get("result", [])
            }
            complete = bool(user_event_types) and bool(project_event_types) and len(self.decision_ids) >= 2
            event = self._event(
                "identity.audit_observed",
                f"zitadel:changes/users/{self.agent_id}+projects/{self.project_id}",
                event_id=str(len(user_event_types) + len(project_event_types)),
            )
            return Observation(
                Status.PASS if complete else Status.FAIL,
                "ZITADEL change history plus OPA decision identifiers reconstruct the service-account grant, allow, and deny path; the action token itself does not prove the human principal.",
                {
                    "auditable": complete,
                    "human_attribution": False,
                    "agent_attribution": self.introspection.get("sub") == self.agent_id,
                },
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("get_audit_events", error)

    def revoke(self) -> Observation:
        if not self.agent_id or not self.grant_id:
            return self._blocked("revoke")
        try:
            self._api(f"/users/{self.agent_id}/grants/{self.grant_id}", method="DELETE")
            self.revocation_started = time.monotonic()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                self.introspection = self._introspect()
                if "payments_preview" not in self._roles():
                    break
                time.sleep(0.1)
            event = self._event(
                "delegation.revoked",
                f"zitadel:management/users/{self.agent_id}/grants/{self.grant_id}/deleted",
            )
            return Observation(
                Status.PASS,
                "ZITADEL acknowledged deletion of the preview-role grant.",
                {"supported": True},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("revoke", error)

    def execute_after_revocation(self) -> Observation:
        result = self._decide("preview")
        result.data["revocation_latency_ms"] = (
            (time.monotonic() - self.revocation_started) * 1000
            if self.revocation_started is not None
            else None
        )
        return result
