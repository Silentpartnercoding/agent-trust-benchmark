from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .jose import verify_compact_jws
from .receipt import ReceiptContext, ReceiptVerdict, canonical_json, receipt_digest, verify_receipt


class DelegationError(ValueError):
    """Fail-closed portable-delegation verification error."""


RevocationChecker = Callable[[str, str], bool | None]


@dataclass(frozen=True)
class DelegationContext:
    receipt_context: ReceiptContext
    agent_a_public_key: Path
    agent_a_key_id: str
    agent_b_public_key: Path
    agent_b_key_id: str
    expected_agent_a: str
    expected_agent_b: str
    expected_agent_b_thumbprint: str
    expected_audience: str
    expected_resource: str
    expected_action: str
    now: datetime
    delegation_revocation_checker: RevocationChecker | None


DELEGATION_KEYS = {
    "schema_version", "jti", "iss", "sub", "cnf", "parent_receipt_digest",
    "original_authority_source", "audience", "authorization", "issued_at",
    "not_before", "expires_at", "can_redelegate", "remaining_delegation_depth",
    "revocation",
}

PROOF_KEYS = {
    "request_id", "delegation_digest", "audience", "resource", "action",
    "body_digest", "issued_at",
}


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def token_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode()).hexdigest()


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise DelegationError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DelegationError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise DelegationError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _unique_strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise DelegationError(f"{field} must be a non-empty string array")
    if len(value) != len(set(value)):
        raise DelegationError(f"{field} must not contain duplicates")
    return value


def validate_delegation_shape(claims: dict[str, Any]) -> None:
    if set(claims) != DELEGATION_KEYS or claims.get("schema_version") != "atb-delegation/0.1":
        raise DelegationError("delegation shape is invalid or contains undeclared fields")
    for field in ("jti", "iss", "sub", "parent_receipt_digest", "original_authority_source"):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise DelegationError(f"{field} must be a non-empty string")
    if not isinstance(claims.get("cnf"), dict) or set(claims["cnf"]) != {"jkt"}:
        raise DelegationError("delegation cnf must bind exactly one key thumbprint")
    if not isinstance(claims["cnf"]["jkt"], str) or not claims["cnf"]["jkt"]:
        raise DelegationError("delegation key thumbprint is invalid")
    _unique_strings(claims.get("audience"), "audience")
    authorization = claims.get("authorization")
    if not isinstance(authorization, dict) or set(authorization) != {"scopes", "actions"}:
        raise DelegationError("authorization shape is invalid")
    _unique_strings(authorization.get("scopes"), "authorization.scopes")
    actions = authorization.get("actions")
    if not isinstance(actions, list) or not actions:
        raise DelegationError("authorization.actions must be non-empty")
    normalized = []
    for action in actions:
        if not isinstance(action, dict) or set(action) != {"resource", "action"}:
            raise DelegationError("each delegated action must contain only resource and action")
        if any(not isinstance(action[key], str) or not action[key] for key in ("resource", "action")):
            raise DelegationError("delegated resource and action must be non-empty")
        normalized.append((action["resource"], action["action"]))
    if len(normalized) != len(set(normalized)):
        raise DelegationError("delegated actions must not contain duplicates")
    if not isinstance(claims.get("can_redelegate"), bool):
        raise DelegationError("can_redelegate must be Boolean")
    depth = claims.get("remaining_delegation_depth")
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0:
        raise DelegationError("remaining_delegation_depth must be a non-negative integer")
    revocation = claims.get("revocation")
    if not isinstance(revocation, dict) or set(revocation) != {"authority", "handle"}:
        raise DelegationError("delegation revocation reference is invalid")
    if any(not isinstance(revocation[key], str) or not revocation[key] for key in revocation):
        raise DelegationError("delegation revocation values must be non-empty")


def verify_delegation_chain(
    token: str,
    parent_receipt: dict[str, Any],
    parent_credential: dict[str, Any],
    context: DelegationContext,
) -> dict[str, Any]:
    claims = verify_compact_jws(
        token,
        context.agent_a_public_key,
        expected_kid=context.agent_a_key_id,
        expected_typ="atb-delegation+jwt",
    )
    if claims is None:
        raise DelegationError("delegation signature did not verify")
    validate_delegation_shape(claims)

    if context.now.tzinfo is None:
        raise DelegationError("gateway clock has no timezone")
    issued = _time(claims["issued_at"], "issued_at")
    starts = _time(claims["not_before"], "not_before")
    expires = _time(claims["expires_at"], "expires_at")
    now = context.now.astimezone(timezone.utc)
    if not issued <= starts < expires or now < starts or now >= expires:
        raise DelegationError("delegation is not currently valid")

    parent_result = verify_receipt(parent_receipt, parent_credential, context.receipt_context)
    if parent_result.verdict is not ReceiptVerdict.VERIFIED:
        raise DelegationError(f"parent authority is not verified: {parent_result.verdict.value}")
    parent = parent_receipt["payload"]
    parent_expires = _time(parent["expires_at"], "parent.expires_at")
    parent_starts = _time(parent["not_before"], "parent.not_before")
    if starts < parent_starts or expires > parent_expires:
        raise DelegationError("child time window expands its parent")
    if claims["iss"] != context.expected_agent_a or claims["iss"] != parent["agent"]["id"]:
        raise DelegationError("delegation issuer is not the parent agent")
    if claims["sub"] != context.expected_agent_b:
        raise DelegationError("delegation subject does not match Agent B")
    if claims["cnf"]["jkt"] != context.expected_agent_b_thumbprint:
        raise DelegationError("delegation is bound to a different Agent B key")
    if not hmac.compare_digest(claims["parent_receipt_digest"], receipt_digest(parent_receipt)):
        raise DelegationError("delegation does not bind the exact parent receipt")
    if claims["original_authority_source"] != parent["issuer"]:
        raise DelegationError("original authority source does not match the parent issuer")
    if context.expected_audience not in claims["audience"]:
        raise DelegationError("delegation audience mismatch")

    child_scopes = set(claims["authorization"]["scopes"])
    parent_scopes = set(parent["authorization"]["scopes"])
    child_actions = {(item["resource"], item["action"]) for item in claims["authorization"]["actions"]}
    parent_actions = {(item["resource"], item["action"]) for item in parent["authorization"]["actions"]}
    if not child_scopes <= parent_scopes or not child_actions <= parent_actions:
        raise DelegationError("child authority expands its parent")
    requested = (context.expected_resource, context.expected_action)
    required_scope = f"{context.expected_resource}:{context.expected_action}"
    if requested not in child_actions or required_scope not in child_scopes:
        raise DelegationError("requested action is outside the child delegation")

    checker = context.delegation_revocation_checker
    if checker is None:
        raise DelegationError("delegation revocation status is unavailable")
    try:
        revoked = checker(claims["revocation"]["authority"], claims["revocation"]["handle"])
    except Exception as exc:
        raise DelegationError("delegation revocation check failed closed") from exc
    if revoked is None:
        raise DelegationError("delegation revocation status is indeterminate")
    if revoked:
        raise DelegationError("delegation has been revoked")
    return claims


def verify_agent_b_proof(
    proof: str,
    statement: dict[str, Any],
    delegation_token: str,
    context: DelegationContext,
) -> None:
    if set(statement) != PROOF_KEYS:
        raise DelegationError("Agent B proof statement shape is invalid")
    verified = verify_compact_jws(
        proof,
        context.agent_b_public_key,
        expected_kid=context.agent_b_key_id,
        expected_typ="atb-action+jwt",
    )
    if verified is None or verified != statement:
        raise DelegationError("Agent B possession proof did not verify")
    if statement["delegation_digest"] != token_digest(delegation_token):
        raise DelegationError("Agent B proof is not bound to the delegation")
    if statement["audience"] != context.expected_audience:
        raise DelegationError("Agent B proof audience mismatch")
    if statement["resource"] != context.expected_resource or statement["action"] != context.expected_action:
        raise DelegationError("Agent B proof action mismatch")
    proof_time = _time(statement["issued_at"], "proof.issued_at")
    now = context.now.astimezone(timezone.utc)
    if abs((now - proof_time).total_seconds()) > 60:
        raise DelegationError("Agent B proof is stale")


def validate_redelegation(parent: dict[str, Any], child: dict[str, Any]) -> None:
    validate_delegation_shape(parent)
    validate_delegation_shape(child)
    if parent["can_redelegate"] is not True or parent["remaining_delegation_depth"] < 1:
        raise DelegationError("parent delegation forbids redelegation")
    if child["iss"] != parent["sub"]:
        raise DelegationError("redelegation issuer is not the parent subject")
    if child["remaining_delegation_depth"] >= parent["remaining_delegation_depth"]:
        raise DelegationError("redelegation depth did not decrease")
    parent_scopes = set(parent["authorization"]["scopes"])
    child_scopes = set(child["authorization"]["scopes"])
    parent_actions = {(item["resource"], item["action"]) for item in parent["authorization"]["actions"]}
    child_actions = {(item["resource"], item["action"]) for item in child["authorization"]["actions"]}
    if not child_scopes <= parent_scopes or not child_actions <= parent_actions:
        raise DelegationError("redelegation expands parent authority")
    if _time(child["not_before"], "child.not_before") < _time(parent["not_before"], "parent.not_before"):
        raise DelegationError("redelegation starts before its parent")
    if _time(child["expires_at"], "child.expires_at") > _time(parent["expires_at"], "parent.expires_at"):
        raise DelegationError("redelegation expires after its parent")
