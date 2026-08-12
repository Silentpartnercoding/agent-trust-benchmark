from __future__ import annotations

import os

from .base import ProviderAdapter
from ..models import Observation, Status


class BlockedExternalAdapter(ProviderAdapter):
    required_environment: tuple[str, ...] = ()

    def _blocked(self, operation: str) -> Observation:
        missing = [name for name in self.required_environment if not os.environ.get(name)]
        detail = (
            f"{operation} not run: external test access is unavailable; missing "
            + ", ".join(missing)
            if missing
            else f"{operation} not run: the external resource-server contract has not been configured."
        )
        return Observation(Status.BLOCKED, detail, {"missing_configuration": missing})

    def create_human(self) -> Observation: return self._blocked("create_human")
    def create_agent(self) -> Observation: return self._blocked("create_agent")
    def delegate(self) -> Observation: return self._blocked("delegate")
    def issue_credential(self) -> Observation: return self._blocked("issue_credential")
    def inspect_credential(self) -> Observation: return self._blocked("inspect_credential")
    def execute_allowed_action(self) -> Observation: return self._blocked("execute_allowed_action")
    def execute_forbidden_action(self) -> Observation: return self._blocked("execute_forbidden_action")
    def revoke(self) -> Observation: return self._blocked("revoke")
    def execute_after_revocation(self) -> Observation: return self._blocked("execute_after_revocation")
    def get_audit_events(self) -> Observation: return self._blocked("get_audit_events")


class OktaAdapter(BlockedExternalAdapter):
    provider_id = "okta"
    required_environment = (
        "ATB_OKTA_ISSUER",
        "ATB_OKTA_CLIENT_ID",
        "ATB_OKTA_PRIVATE_KEY_FILE",
        "ATB_OKTA_RESOURCE_SERVER",
    )


class EntraAdapter(BlockedExternalAdapter):
    provider_id = "entra"
    required_environment = (
        "ATB_ENTRA_TENANT_ID",
        "ATB_ENTRA_CLIENT_ID",
        "ATB_ENTRA_CLIENT_CERT_FILE",
        "ATB_ENTRA_RESOURCE_SERVER",
    )
