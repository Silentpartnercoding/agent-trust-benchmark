#!/usr/bin/env python3
"""Intentionally limited control that treats A requesting B as delegation."""

from __future__ import annotations

import json
import sys
from typing import Any


OUTPUT_SCHEMA = "atb-authority-relation-output/0.1"


def valid_evidence(
    evidence: dict[str, Any], subject: str, kind: str, action: dict[str, str]
) -> bool:
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
    policy = case["policy"]
    requester = observed["requester"]
    actor = observed["actor"]
    action = observed["requested_action"]
    request = observed["request_authority"]
    execution = observed["execution_authority"]
    delegation = observed["delegation"]
    declared = observed["declared_relation"]

    request_execution_valid = valid_evidence(request, requester, "EXECUTION", action)
    request_valid = valid_evidence(request, requester, "REQUEST", action) or request_execution_valid
    direct_execution_valid = (
        valid_evidence(execution, actor, "EXECUTION", action)
        and execution.get("independently_issued") is True
    )
    actual_delegation = (
        delegation.get("status") == "VALID"
        and delegation.get("delegator") == requester
        and delegation.get("delegatee") == actor
        and delegation.get("action") == action
        and delegation.get("attenuated") is True
        and request_execution_valid
        and delegation.get("authority_source") == request.get("source")
    )

    relation = "NONE"
    execution_valid = False
    execution_source = None
    immediate_grantor = None
    if actual_delegation:
        relation = "DELEGATED"
        execution_valid = True
        execution_source = delegation.get("authority_source")
        immediate_grantor = requester
    elif direct_execution_valid:
        # Deliberate defect: B's independent authority is mislabeled as
        # delegation merely because the causal request was A -> B.
        relation = "DELEGATED"
        execution_valid = True
        execution_source = requester
        immediate_grantor = requester

    invalid_evidence = any(
        evidence.get("status") == "INVALID" for evidence in (request, execution, delegation)
    )
    evidence_status = "INVALID" if invalid_evidence else "VERIFIED" if execution_valid else "INCOMPLETE"
    declared_matches = None if declared is None else declared == relation
    requester_required = policy["requester_authority"] == "REQUIRED"
    request_ok = request_valid or not requester_required
    relation_ok = relation in policy["allowed_relations"]
    declaration_ok = (
        not policy["require_declared_relation_match"] or declared_matches is True
    )
    evidence_ok = not policy["reject_invalid_evidence"] or evidence_status != "INVALID"
    authorized = request_ok and execution_valid and relation_ok and declaration_ok and evidence_ok

    if not evidence_ok:
        reason = "INVALID_EVIDENCE"
    elif not request_ok:
        reason = "REQUEST_AUTHORITY_REQUIRED"
    elif not execution_valid:
        reason = "EXECUTION_AUTHORITY_INVALID"
    elif not relation_ok:
        reason = "RELATION_NOT_ALLOWED"
    elif not declaration_ok:
        reason = "RELATIONSHIP_MISMATCH"
    elif not requester_required:
        reason = "EXECUTOR_AUTHORITY_VERIFIED_PERMISSIONLESS_REQUEST"
    elif relation == "DELEGATED":
        reason = "VALID_DELEGATION"
    else:
        reason = "VALID_INDEPENDENT_AUTHORITY_PATHS"

    return {
        "schema": OUTPUT_SCHEMA,
        "status": "DECIDED",
        "vector_id": case["vector_id"],
        "requester": requester,
        "actor": actor,
        "evidence_status": evidence_status,
        "declared_relation": declared,
        "declared_relation_matches": declared_matches,
        "request_authority_source": request.get("source") if request_valid else None,
        "request_authority_valid": request_valid,
        "execution_authority_source": execution_source,
        "immediate_authority_grantor": immediate_grantor,
        "execution_authority_valid": execution_valid,
        "derived_authority_relation": relation,
        "policy_profile": policy["profile"],
        "requester_authority_required": requester_required,
        "authorized": authorized,
        "reason": reason,
    }


def main() -> int:
    case = json.load(sys.stdin)
    json.dump(evaluate(case), sys.stdout, sort_keys=True, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
