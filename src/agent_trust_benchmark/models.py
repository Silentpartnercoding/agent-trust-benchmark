from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED_EXTERNAL_ACCESS"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INDETERMINATE = "INDETERMINATE"


class CheckId(str, Enum):
    DISTINCT_AGENT_IDENTITY = "DISTINCT_AGENT_IDENTITY"
    DELEGATION_PROVABLE = "DELEGATION_PROVABLE"
    SCOPE_VISIBLE = "SCOPE_VISIBLE"
    ALLOWED_ACTION_SUCCEEDS = "ALLOWED_ACTION_SUCCEEDS"
    FORBIDDEN_ACTION_BLOCKED = "FORBIDDEN_ACTION_BLOCKED"
    HUMAN_ATTRIBUTION_PROVABLE = "HUMAN_ATTRIBUTION_PROVABLE"
    AGENT_ATTRIBUTION_PROVABLE = "AGENT_ATTRIBUTION_PROVABLE"
    ACTION_AUDITABLE = "ACTION_AUDITABLE"
    REVOCATION_SUPPORTED = "REVOCATION_SUPPORTED"
    POST_REVOCATION_ACTION_BLOCKED = "POST_REVOCATION_ACTION_BLOCKED"


@dataclass
class Observation:
    status: Status
    detail: str
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CheckResult:
    check: CheckId
    status: Status
    detail: str
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    schema_version: str
    experiment_id: str
    provider: str
    run_id: str
    started_at: str
    completed_at: str
    checks: list[CheckResult]
    metrics: dict[str, float | int | None]
    evidence: list[dict[str, Any]]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for item in value["checks"]:
            item["check"] = item["check"].value
            item["status"] = item["status"].value
        return value
