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
    # Whether this file is a declared root or a derivation, stated by the file
    # rather than inferred from it. Four E001 results written before this field
    # existed were hand-authored records of live sessions, indistinguishable at
    # read time from harness output, and were cited publicly as measurements.
    #
    # The shape follows Minority Prophet's memory-evidence interoperability
    # profile, whose first principle is that a claim with no derived_from is a
    # declared root and that a parentless claim is not automatically trusted.
    # Anything constructed as a RunResult and written by write_result is by
    # definition machine-emitted, so that is the default; a record derived from
    # a session must say what it was derived from.
    provenance: dict[str, Any] = field(default_factory=lambda: {
        "derived_from": [],
        "root_authentication": {
            "status": "machine-emitted",
            "method": "agent_trust_benchmark.report.write_result",
        },
    })

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for item in value["checks"]:
            item["check"] = item["check"].value
            item["status"] = item["status"].value
        return value
