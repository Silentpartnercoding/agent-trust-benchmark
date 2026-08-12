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
from typing import Any

from .base import ProviderAdapter
from ..models import Observation, Status


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class KeycloakOpaAdapter(ProviderAdapter):
    provider_id = "keycloak-opa"

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.keycloak = os.environ.get("ATB_KEYCLOAK_OPA_URL", "http://127.0.0.1:18080").rstrip("/")
        self.opa = os.environ.get("ATB_OPA_URL", "http://127.0.0.1:18181").rstrip("/")
        self.realm = "atb"
        self.admin_token: str | None = None
        self.human_id: str | None = None
        self.agent_id: str | None = None
        self.client_uuid: str | None = None
        self.delegation_id: str | None = None
        self.credential_id: str | None = None
        self.token: str | None = None
        self.claims: dict[str, Any] = {}
        self.decision_ids: list[str] = []
        self.preview_effects = 0
        self.revocation_ack: float | None = None

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
            return json.loads(payload) if payload else None

    def _blocked(self, operation: str, error: Exception | None = None) -> Observation:
        suffix = f" ({type(error).__name__})" if error else ""
        return Observation(Status.BLOCKED, f"{operation} not run: the local Keycloak + OPA fixture is unavailable{suffix}.")

    def _admin(self) -> str:
        if not self.admin_token:
            response = self._request(
                f"{self.keycloak}/realms/master/protocol/openid-connect/token",
                method="POST",
                form={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": "atb-admin",
                    "password": "local-admin-password",
                },
            )
            self.admin_token = response["access_token"]
        return self.admin_token

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
            "granted_scopes": ["payments:preview"] if self.claims else [],
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
            users = self._request(
                f"{self.keycloak}/admin/realms/{self.realm}/users?username=human-e001&exact=true",
                bearer=self._admin(),
            )
            if len(users) != 1:
                return Observation(Status.FAIL, "The fixture did not expose exactly one E001 human.")
            self.human_id = users[0]["id"]
            event = self._event("human.directory_record", "keycloak:admin/users/human-e001")
            return Observation(Status.PASS, "Keycloak exposes one enabled human directory identity.", {"human_id": self.human_id}, [event])
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("create_human", error)

    def create_agent(self) -> Observation:
        try:
            clients = self._request(
                f"{self.keycloak}/admin/realms/{self.realm}/clients?clientId=agent-e001",
                bearer=self._admin(),
            )
            if len(clients) != 1:
                return Observation(Status.FAIL, "The fixture did not expose exactly one E001 agent client.")
            self.client_uuid = clients[0]["id"]
            self.agent_id = f"keycloak-client:{self.client_uuid}"
            event = self._event("agent.client_record", "keycloak:admin/clients/agent-e001")
            return Observation(Status.PASS, "The confidential agent client is distinct from the human directory identity.", {"agent_id": self.agent_id, "distinct": self.agent_id != self.human_id}, [event])
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("create_agent", error)

    def delegate(self) -> Observation:
        if not self.human_id or not self.client_uuid:
            return self._blocked("delegate")
        try:
            roles = self._request(
                f"{self.keycloak}/admin/realms/{self.realm}/users/{self.human_id}/role-mappings/realm",
                bearer=self._admin(),
            )
            mappers = self._request(
                f"{self.keycloak}/admin/realms/{self.realm}/clients/{self.client_uuid}/protocol-mappers/models",
                bearer=self._admin(),
            )
            role_names = {role["name"] for role in roles}
            delegation_mapper = next((item for item in mappers if item.get("name") == "delegation-id"), None)
            self.delegation_id = delegation_mapper["config"]["claim.value"] if delegation_mapper else None
            provable = "payments_preview" in role_names and "payments_execute" not in role_names and bool(self.delegation_id)
            event = self._event("delegation.configuration", "keycloak:admin/e001-role-and-claim-mapping")
            return Observation(
                Status.PASS if provable else Status.FAIL,
                "The imported grant binds the human, agent client, preview-only role, and delegation identifier; it is administrator-configured, not an interactive consent record.",
                {"provable": provable, "authorization_mode": "administrator_configured"},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("delegate", error)

    def issue_credential(self) -> Observation:
        try:
            response = self._request(
                f"{self.keycloak}/realms/{self.realm}/protocol/openid-connect/token",
                method="POST",
                form={
                    "grant_type": "password",
                    "client_id": "agent-e001",
                    "client_secret": "local-agent-client-secret",
                    "username": "human-e001",
                    "password": "local-human-password",
                    "scope": "openid",
                },
            )
            self.token = response["access_token"]
            self.credential_id = "sha256:" + hashlib.sha256(self.token.encode()).hexdigest()
            body = self.token.split(".")[1]
            self.claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            self.delegation_id = self.claims.get("delegation_id")
            event = self._event("credential.issued", "keycloak:token/credential-hash")
            return Observation(
                Status.PASS,
                "Keycloak issued an access token binding the human subject, agent client, preview role, and delegation identifier.",
                {"credential_id": self.credential_id, "token_lifetime_seconds": self.claims["exp"] - self.claims["iat"]},
                [event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, IndexError, json.JSONDecodeError) as error:
            return self._blocked("issue_credential", error)

    def _introspect(self) -> dict[str, Any]:
        if not self.token:
            return {"active": False}
        return self._request(
            f"{self.keycloak}/realms/{self.realm}/protocol/openid-connect/token/introspect",
            method="POST",
            form={"token": self.token},
            basic=("agent-e001", "local-agent-client-secret"),
        )

    def inspect_credential(self) -> Observation:
        if not self.token:
            return self._blocked("inspect_credential")
        try:
            introspection = self._introspect()
            roles = self.claims.get("realm_access", {}).get("roles", [])
            scopes = ["payments:preview"] if "payments_preview" in roles else []
            bound = (
                introspection.get("active") is True
                and self.claims.get("sub") == self.human_id
                and self.claims.get("azp") == "agent-e001"
                and self.claims.get("delegation_id") == self.delegation_id
            )
            event = self._event("credential.introspected", "keycloak:introspection/credential-hash")
            return Observation(Status.PASS if bound else Status.FAIL, "Active introspection and token claims bind the exercised identities and scope.", {"scopes": scopes, "bound": bound}, [event])
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("inspect_credential", error)

    def _decide(self, action: str) -> Observation:
        if not self.token:
            return self._blocked(f"execute_{action}")
        try:
            introspection = self._introspect()
            roles = self.claims.get("realm_access", {}).get("roles", [])
            response = self._request(
                f"{self.opa}/v1/data/agent_authz/decision",
                method="POST",
                body={
                    "input": {
                        "token_active": introspection.get("active") is True,
                        "human_id": self.claims.get("sub", ""),
                        "agent_id": self.claims.get("azp", ""),
                        "delegation_id": self.claims.get("delegation_id", ""),
                        "roles": roles,
                        "resource": "payments",
                        "action": action,
                    }
                },
            )
            allowed = response["result"]["allow"] is True
            if allowed and action == "preview":
                self.preview_effects += 1
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
                f"Keycloak introspection plus OPA {'allowed' if allowed else 'denied'} payments:{action}; effect count is {effect_count}.",
                {
                    "allowed": allowed,
                    "blocked": not allowed,
                    "effect_count": effect_count,
                    "human_attribution": bool(self.claims.get("sub")),
                    "agent_attribution": bool(self.claims.get("azp")),
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
        if not self.human_id or not self.agent_id:
            return self._blocked("get_audit_events")
        try:
            events = self._request(
                f"{self.keycloak}/admin/realms/{self.realm}/events?max=100",
                bearer=self._admin(),
            )
            matching = [
                event for event in events
                if event.get("userId") == self.human_id and event.get("clientId") == "agent-e001"
            ]
            provider_event = self._event(
                "identity.audit_observed",
                "keycloak:events/e001-filtered",
                event_id=str(matching[0].get("time")) if matching else None,
            )
            complete = bool(matching) and len(self.decision_ids) >= 2
            return Observation(
                Status.PASS if complete else Status.FAIL,
                "Keycloak identity events and OPA decision identifiers reconstruct the human, agent client, allow, and deny path.",
                {"auditable": complete, "human_attribution": bool(matching), "agent_attribution": bool(matching)},
                [provider_event],
            )
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("get_audit_events", error)

    def revoke(self) -> Observation:
        try:
            not_before = int(time.time()) + 1
            self._request(
                f"{self.keycloak}/admin/realms/{self.realm}",
                method="PUT",
                body={"notBefore": not_before},
                bearer=self._admin(),
            )
            self.revocation_ack = time.monotonic()
            time.sleep(max(0.0, not_before - time.time() + 0.1))
            event = self._event("realm.revocation_acknowledged", "keycloak:admin/realm/not-before")
            return Observation(Status.PASS, "Keycloak acknowledged a realm not-before revocation boundary.", {"supported": True}, [event])
        except (OSError, urllib.error.URLError, KeyError, ValueError, json.JSONDecodeError) as error:
            return self._blocked("revoke", error)

    def execute_after_revocation(self) -> Observation:
        result = self._decide("preview")
        result.data["revocation_latency_ms"] = (
            (time.monotonic() - self.revocation_ack) * 1000 if self.revocation_ack is not None else None
        )
        return result
