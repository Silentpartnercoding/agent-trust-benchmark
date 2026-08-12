from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Observation


class ProviderAdapter(ABC):
    """The shared E001 adapter contract.

    Methods return observations rather than booleans so unavailable access,
    unsupported features, and undecidable evidence cannot collapse together.
    """

    provider_id: str

    def __init__(self, run_id: str):
        self.run_id = run_id

    @abstractmethod
    def create_human(self) -> Observation: ...

    @abstractmethod
    def create_agent(self) -> Observation: ...

    @abstractmethod
    def delegate(self) -> Observation: ...

    @abstractmethod
    def issue_credential(self) -> Observation: ...

    @abstractmethod
    def inspect_credential(self) -> Observation: ...

    @abstractmethod
    def execute_allowed_action(self) -> Observation: ...

    @abstractmethod
    def execute_forbidden_action(self) -> Observation: ...

    @abstractmethod
    def revoke(self) -> Observation: ...

    @abstractmethod
    def execute_after_revocation(self) -> Observation: ...

    @abstractmethod
    def get_audit_events(self) -> Observation: ...

    def normalize_evidence(self, observations: list[Observation]) -> list[dict]:
        normalized: list[dict] = []
        seen: set[str] = set()
        for observation in observations:
            for event in observation.evidence:
                reference = event["raw_evidence_ref"]
                if reference not in seen:
                    normalized.append(event)
                    seen.add(reference)
        return normalized

    def cleanup(self) -> None:
        return None
