#!/usr/bin/env python3
"""Provider-neutral control adapter that tracks request and authority separately."""

from __future__ import annotations

import json
import sys
from typing import Any


OUTPUT_SCHEMA = "atb-authority-relation-output/0.1"


def valid_evidence(evidence: dict[str, Any], subject: str, kind: str, action: dict[str, str]) -> bool:
    return (
        evidence.get("status") == "VALID"
        and evidence.get("subject") == subject
        and evidence.get("kind") == kind
        and evidence.get("action") == action
        and isinstance(evidence.get("source"), str)
        and bool(evidence["source"])
    )


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    observed = case["observed"]
    vector_id = case["vector_id"]
    requester = observed["requester"]
    actor = observed["actor"]
    action = observed["requested_action"]
    request = observed["request_authority"]
    execution = observed["execution_authority"]
    delegation = observed["delegation"]
    claimed = observed["claimed_relation"]

    request_valid = valid_evidence(request, requester, "REQUEST", action) or valid_evidence(
        request, requester, "EXECUTION", action
    )
    direct_execution_valid = valid_evidence(execution, actor, "EXECUTION", action)
    delegation_valid = (
        delegation.get("status") == "VALID"
        and delegation.get("delegator") == requester
        and delegation.get("delegatee") == actor
        and delegation.get("action") == action
        and delegation.get("attenuated") is True
        and request_valid
    )

    request_source = request.get("source") if request_valid else None
    execution_source = None
    immediate_grantor = None
    execution_valid = False
    relation = "NONE"
    authorized = False
    reason = "NO_VALID_AUTHORITY"

    if claimed == "DELEGATED":
        if delegation_valid:
            relation = "DELEGATED"
            execution_valid = True
            execution_source = delegation.get("authority_source")
            immediate_grantor = requester
            authorized = True
            reason = "VALID_DELEGATION"
        elif delegation.get("status") == "INVALID":
            relation = "INVALID"
            reason = "DELEGATION_PROOF_INVALID"
        elif direct_execution_valid:
            relation = "INVALID"
            execution_valid = True
            execution_source = execution.get("source")
            immediate_grantor = execution.get("source")
            reason = "RELATIONSHIP_MISMATCH"
        elif request_valid:
            reason = "EXECUTION_AUTHORITY_INVALID"
        else:
            reason = "REQUEST_AUTHORITY_INVALID"
    elif claimed == "INDEPENDENT":
        if delegation.get("status") == "VALID":
            relation = "INVALID"
            reason = "RELATIONSHIP_MISMATCH"
        elif direct_execution_valid:
            relation = "INDEPENDENT"
            execution_valid = True
            execution_source = execution.get("source")
            immediate_grantor = execution.get("source")
            if request_valid and execution.get("independently_issued") is True:
                authorized = True
                reason = "VALID_INDEPENDENT_AUTHORITY_PATHS"
            elif not request_valid:
                reason = "REQUEST_AUTHORITY_INVALID"
            else:
                relation = "INVALID"
                reason = "RELATIONSHIP_MISMATCH"
        elif request_valid:
            reason = "EXECUTION_AUTHORITY_INVALID"
        else:
            reason = "NO_VALID_AUTHORITY"

    return {
        "schema": OUTPUT_SCHEMA,
        "status": "DECIDED",
        "vector_id": vector_id,
        "requester": requester,
        "actor": actor,
        "request_authority_source": request_source,
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
