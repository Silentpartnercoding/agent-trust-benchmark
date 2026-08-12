#!/usr/bin/env python3
"""Intentionally limited control that treats A requesting B as delegation."""

from __future__ import annotations

import json
import sys
from typing import Any


OUTPUT_SCHEMA = "atb-authority-relation-output/0.1"


def evidence_valid(evidence: dict[str, Any], subject: str, action: dict[str, str]) -> bool:
    return (
        evidence.get("status") == "VALID"
        and evidence.get("subject") == subject
        and evidence.get("action") == action
    )


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    observed = case["observed"]
    requester = observed["requester"]
    actor = observed["actor"]
    action = observed["requested_action"]
    request = observed["request_authority"]
    execution = observed["execution_authority"]
    delegation = observed["delegation"]
    request_valid = evidence_valid(request, requester, action)
    direct_execution_valid = evidence_valid(execution, actor, action)
    actual_delegation = (
        delegation.get("status") == "VALID"
        and delegation.get("delegator") == requester
        and delegation.get("delegatee") == actor
        and delegation.get("action") == action
        and delegation.get("attenuated") is True
        and request_valid
    )

    relation = "NONE"
    execution_valid = False
    execution_source = None
    immediate_grantor = None
    authorized = False
    reason = "NO_VALID_AUTHORITY"
    if delegation.get("status") == "INVALID":
        relation = "INVALID"
        reason = "DELEGATION_PROOF_INVALID"
    elif actual_delegation:
        relation = "DELEGATED"
        execution_valid = True
        execution_source = delegation.get("authority_source")
        immediate_grantor = requester
        authorized = True
        reason = "VALID_DELEGATION"
    elif request_valid and direct_execution_valid:
        # This is the intentional modeling defect: request causality is used
        # to invent an A -> B delegation that the evidence never established.
        relation = "DELEGATED"
        execution_valid = True
        execution_source = requester
        immediate_grantor = requester
        authorized = True
        reason = "ASSUMED_DELEGATION_FROM_REQUEST"
    elif request_valid:
        reason = "EXECUTION_AUTHORITY_INVALID"
    elif direct_execution_valid:
        reason = "REQUEST_AUTHORITY_INVALID"

    return {
        "schema": OUTPUT_SCHEMA,
        "status": "DECIDED",
        "vector_id": case["vector_id"],
        "requester": requester,
        "actor": actor,
        "request_authority_source": request.get("source") if request_valid else None,
        "request_authority_valid": request_valid,
        "execution_authority_source": execution_source,
        "immediate_authority_grantor": immediate_grantor,
        "execution_authority_valid": execution_valid,
        "authority_relation": relation,
        "authorized": authorized,
        "reason": reason,
    }


def main() -> int:
    case = json.load(sys.stdin)
    json.dump(evaluate(case), sys.stdout, sort_keys=True, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
