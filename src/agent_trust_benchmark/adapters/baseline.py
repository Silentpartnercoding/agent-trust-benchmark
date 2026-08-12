from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .base import ProviderAdapter
from ..models import Observation, Status


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class BaselineAdapter(ProviderAdapter):
    provider_id = "baseline"

    def __init__(self, run_id: str):
        super().__init__(run_id)
        self.secret = secrets.token_bytes(32)
        self.human_id: str | None = None
        self.agent_id: str | None = None
        self.delegation_id: str | None = None
        self.credential_id: str | None = None
        self.token: str | None = None
        self.revoked: set[str] = set()
        self.audit_events: list[dict[str, Any]] = []
        self.revoked_monotonic: float | None = None

    def _event(
        self,
        event_type: str,
        *,
        action: str | None = None,
        decision: str = "observe",
        effect_count: int = 0,
        requested_scopes: list[str] | None = None,
        granted_scopes: list[str] | None = None,
    ) -> dict[str, Any]:
        event_id = f"evt-{uuid.uuid4()}"
        event = {
            "schema_version": "0.1",
            "provider": self.provider_id,
            "experiment_id": "e001",
            "run_id": self.run_id,
            "event_type": event_type,
            "human_id": self.human_id,
            "agent_id": self.agent_id,
            "credential_id": self.credential_id,
            "delegation_id": self.delegation_id,
            "requested_scopes": requested_scopes or [],
            "granted_scopes": granted_scopes or [],
            "resource": "payments" if action else None,
            "action": action,
            "decision": decision,
            "effect_count": effect_count,
            "observed_at": _iso(),
            "provider_event_id": event_id,
            "correlation_id": self.run_id,
            "evidence_origin": "provider_native",
            "raw_evidence_ref": f"memory:audit/{event_id}",
        }
        self.audit_events.append(event)
        return event

    def create_human(self) -> Observation:
        self.human_id = f"human-{uuid.uuid4()}"
        event = self._event("human.created")
        return Observation(Status.PASS, "Created a distinct local human principal.", {"human_id": self.human_id}, [event])

    def create_agent(self) -> Observation:
        self.agent_id = f"agent-{uuid.uuid4()}"
        event = self._event("agent.created")
        return Observation(Status.PASS, "Created an agent identity distinct from the human principal.", {"agent_id": self.agent_id, "distinct": self.agent_id != self.human_id}, [event])

    def delegate(self) -> Observation:
        self.delegation_id = f"delegation-{uuid.uuid4()}"
        event = self._event(
            "delegation.created",
            requested_scopes=["payments:preview"],
            granted_scopes=["payments:preview"],
        )
        return Observation(Status.PASS, "Bound the human, agent, resource, and preview-only scope in one delegation.", {"provable": True}, [event])

    def issue_credential(self) -> Observation:
        issued = _now()
        expires = issued + timedelta(minutes=5)
        self.credential_id = f"credential-{uuid.uuid4()}"
        payload = {
            "jti": self.credential_id,
            "sub": self.agent_id,
            "act": {"sub": self.human_id},
            "delegation_id": self.delegation_id,
            "scope": ["payments:preview"],
            "aud": "payments",
            "iat": int(issued.timestamp()),
            "exp": int(expires.timestamp()),
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        self.token = f"{body}.{signature}"
        event = self._event("credential.issued", granted_scopes=["payments:preview"])
        return Observation(Status.PASS, "Issued a five-minute signed credential; only its identifier is retained as evidence.", {"credential_id": self.credential_id, "token_lifetime_seconds": 300}, [event])

    def _inspect(self) -> dict[str, Any]:
        if not self.token:
            raise ValueError("credential has not been issued")
        body, signature = self.token.split(".", 1)
        expected = hmac.new(self.secret, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(signature)):
            raise ValueError("credential signature mismatch")
        return json.loads(_unb64(body))

    def inspect_credential(self) -> Observation:
        payload = self._inspect()
        event = self._event("credential.inspected", granted_scopes=list(payload["scope"]))
        return Observation(Status.PASS, "The granted preview scope is visible in the verified credential.", {"scopes": payload["scope"]}, [event])

    def _execute(self, action: str) -> Observation:
        try:
            payload = self._inspect()
        except ValueError as error:
            event = self._event("action.denied", action=action, decision="deny")
            return Observation(Status.FAIL, str(error), {"blocked": True, "effect_count": 0}, [event])
        now_epoch = int(_now().timestamp())
        required = f"payments:{action}"
        allowed = (
            payload["exp"] >= now_epoch
            and payload["jti"] not in self.revoked
            and required in payload["scope"]
            and payload["aud"] == "payments"
        )
        effect_count = 1 if allowed else 0
        event = self._event(
            "action.allowed" if allowed else "action.denied",
            action=action,
            decision="allow" if allowed else "deny",
            effect_count=effect_count,
            requested_scopes=[required],
            granted_scopes=list(payload["scope"]),
        )
        return Observation(Status.PASS, f"payments:{action} {'executed once' if allowed else 'was blocked before effect'}.", {"allowed": allowed, "blocked": not allowed, "effect_count": effect_count}, [event])

    def execute_allowed_action(self) -> Observation:
        return self._execute("preview")

    def execute_forbidden_action(self) -> Observation:
        return self._execute("execute")

    def revoke(self) -> Observation:
        if not self.credential_id:
            return Observation(Status.FAIL, "No credential exists to revoke.")
        self.revoked.add(self.credential_id)
        self.revoked_monotonic = time.monotonic()
        event = self._event("credential.revoked")
        return Observation(Status.PASS, "Revocation was acknowledged by the same enforcement authority.", {"supported": True}, [event])

    def execute_after_revocation(self) -> Observation:
        result = self._execute("preview")
        latency_ms = None
        if self.revoked_monotonic is not None:
            latency_ms = (time.monotonic() - self.revoked_monotonic) * 1000
        result.data["revocation_latency_ms"] = latency_ms
        result.detail = "The formerly allowed preview action was blocked after revocation."
        return result

    def get_audit_events(self) -> Observation:
        action_events = [event for event in self.audit_events if event["event_type"].startswith("action.")]
        complete = bool(action_events) and all(event["human_id"] and event["agent_id"] for event in action_events)
        return Observation(
            Status.PASS if complete else Status.FAIL,
            "Audit events bind the human, agent, delegation, action, decision, and effect count.",
            {"auditable": complete, "human_attribution": complete, "agent_attribution": complete},
            list(action_events),
        )
