from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .delegation import digest, token_digest
from .jose import verify_compact_jws
from .receipt import ReceiptContext, ReceiptVerdict, receipt_digest, verify_receipt


class MandateError(ValueError):
    """Fail-closed authorized-invocation verification error."""


RevocationChecker = Callable[[str, str], bool | None]


@dataclass(frozen=True)
class MandateContext:
    requester_receipt_context: ReceiptContext
    executor_receipt_context: ReceiptContext
    requester_public_key: Path
    requester_key_id: str
    executor_public_key: Path
    executor_key_id: str
    expected_requester: str
    expected_executor: str
    expected_executor_thumbprint: str
    expected_audience: str
    expected_resource: str
    expected_action: str
    expected_request_action: str
    expected_target: str
    expected_body_digest: str
    allowed_request_authority: frozenset[tuple[str, str]]
    now: datetime
    mandate_revocation_checker: RevocationChecker | None


MANDATE_KEYS = {
    "schema_version",
    "jti",
    "relationship",
    "iss",
    "executor",
    "executor_cnf",
    "request_authority_receipt_digest",
    "audience",
    "action",
    "issued_at",
    "not_before",
    "expires_at",
    "revocation",
}

ACTION_KEYS = {"resource", "action", "target", "payload_digest"}

PROOF_KEYS = {
    "request_id",
    "mandate_digest",
    "executor_credential_digest",
    "audience",
    "resource",
    "action",
    "target",
    "body_digest",
    "issued_at",
}


def _time(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise MandateError(f"{field} must be an RFC 3339 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MandateError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise MandateError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _unique_strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise MandateError(f"{field} must be a non-empty string array")
    if len(value) != len(set(value)):
        raise MandateError(f"{field} must not contain duplicates")
    return value


def validate_mandate_shape(claims: dict[str, Any]) -> None:
    if set(claims) != MANDATE_KEYS or claims.get("schema_version") != "atb-mandate/0.1":
        raise MandateError("mandate shape is invalid or contains undeclared fields")
    if claims.get("relationship") != "authorized_invocation":
        raise MandateError("relationship is not an authorized invocation")
    for field in ("jti", "iss", "executor", "request_authority_receipt_digest"):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise MandateError(f"{field} must be a non-empty string")
    if not isinstance(claims.get("executor_cnf"), dict) or set(claims["executor_cnf"]) != {"jkt"}:
        raise MandateError("mandate executor_cnf must bind exactly one key thumbprint")
    if not isinstance(claims["executor_cnf"]["jkt"], str) or not claims["executor_cnf"]["jkt"]:
        raise MandateError("mandate executor key thumbprint is invalid")
    _unique_strings(claims.get("audience"), "audience")
    action = claims.get("action")
    if not isinstance(action, dict) or set(action) != ACTION_KEYS:
        raise MandateError("mandate action must bind resource, action, target, and payload digest")
    if any(not isinstance(action[field], str) or not action[field] for field in ACTION_KEYS):
        raise MandateError("mandate action values must be non-empty strings")
    if not action["payload_digest"].startswith("sha256:") or len(action["payload_digest"]) != 71:
        raise MandateError("mandate payload digest is invalid")
    revocation = claims.get("revocation")
    if not isinstance(revocation, dict) or set(revocation) != {"authority", "handle"}:
        raise MandateError("mandate revocation reference is invalid")
    if any(not isinstance(revocation[field], str) or not revocation[field] for field in revocation):
        raise MandateError("mandate revocation values must be non-empty")


def verify_mandate(
    token: str,
    requester_receipt: dict[str, Any],
    requester_credential: dict[str, Any],
    executor_receipt: dict[str, Any],
    executor_credential: dict[str, Any],
    context: MandateContext,
) -> dict[str, Any]:
    """Verify a request mandate and two independent authority paths.

    The requester's receipt proves permission to request/cause an action. The
    executor's receipt proves permission to execute it. The mandate transfers
    no authority and therefore performs no parent/child subset comparison.
    """

    claims = verify_compact_jws(
        token,
        context.requester_public_key,
        expected_kid=context.requester_key_id,
        expected_typ="atb-mandate+jwt",
    )
    if claims is None:
        raise MandateError("mandate signature did not verify")
    validate_mandate_shape(claims)

    if context.now.tzinfo is None:
        raise MandateError("gateway clock has no timezone")
    issued = _time(claims["issued_at"], "issued_at")
    starts = _time(claims["not_before"], "not_before")
    expires = _time(claims["expires_at"], "expires_at")
    now = context.now.astimezone(timezone.utc)
    if not issued <= starts < expires or now < starts or now >= expires:
        raise MandateError("mandate is not currently valid")

    requester = verify_receipt(requester_receipt, requester_credential, context.requester_receipt_context)
    if requester.verdict is not ReceiptVerdict.VERIFIED:
        raise MandateError(f"request authority is not verified: {requester.verdict.value}")
    executor = verify_receipt(executor_receipt, executor_credential, context.executor_receipt_context)
    if executor.verdict is not ReceiptVerdict.VERIFIED:
        raise MandateError(f"executor authority is not verified: {executor.verdict.value}")

    requester_payload = requester_receipt["payload"]
    executor_payload = executor_receipt["payload"]
    if claims["iss"] != context.expected_requester or claims["iss"] != requester_payload["agent"]["id"]:
        raise MandateError("mandate issuer is not the authorized requester")
    if claims["executor"] != context.expected_executor or claims["executor"] != executor_payload["agent"]["id"]:
        raise MandateError("mandate executor is not the independently authorized executor")
    if claims["executor_cnf"]["jkt"] != context.expected_executor_thumbprint:
        raise MandateError("mandate is bound to a different executor key")
    if not hmac.compare_digest(claims["request_authority_receipt_digest"], receipt_digest(requester_receipt)):
        raise MandateError("mandate does not bind the exact request-authority receipt")
    if context.expected_audience not in claims["audience"]:
        raise MandateError("mandate audience mismatch")

    request_actions = {
        (item["resource"], item["action"])
        for item in requester_payload["authorization"]["actions"]
    }
    required_request_edge = (context.expected_resource, context.expected_request_action)
    if required_request_edge not in context.allowed_request_authority or required_request_edge not in request_actions:
        raise MandateError("requester lacks an approved authority to cause this execution action")

    action = claims["action"]
    expected = {
        "resource": context.expected_resource,
        "action": context.expected_action,
        "target": context.expected_target,
        "payload_digest": context.expected_body_digest,
    }
    if action != expected:
        raise MandateError("mandate does not bind the exact requested action")

    requester_starts = _time(requester_payload["not_before"], "requester.not_before")
    requester_expires = _time(requester_payload["expires_at"], "requester.expires_at")
    executor_starts = _time(executor_payload["not_before"], "executor.not_before")
    executor_expires = _time(executor_payload["expires_at"], "executor.expires_at")
    if starts < max(requester_starts, executor_starts) or expires > min(requester_expires, executor_expires):
        raise MandateError("mandate time window exceeds one of its independent authority paths")

    checker = context.mandate_revocation_checker
    if checker is None:
        raise MandateError("mandate revocation status is unavailable")
    try:
        revoked = checker(claims["revocation"]["authority"], claims["revocation"]["handle"])
    except Exception as exc:
        raise MandateError("mandate revocation check failed closed") from exc
    if revoked is None:
        raise MandateError("mandate revocation status is indeterminate")
    if revoked:
        raise MandateError("mandate has been revoked")
    return claims


def verify_executor_proof(
    proof: str,
    statement: dict[str, Any],
    mandate_token: str,
    executor_credential_token: str,
    context: MandateContext,
) -> None:
    if set(statement) != PROOF_KEYS:
        raise MandateError("executor proof statement shape is invalid")
    verified = verify_compact_jws(
        proof,
        context.executor_public_key,
        expected_kid=context.executor_key_id,
        expected_typ="atb-action+jwt",
    )
    if verified is None or verified != statement:
        raise MandateError("executor possession proof did not verify")
    if statement["mandate_digest"] != token_digest(mandate_token):
        raise MandateError("executor proof is not bound to the mandate")
    if statement["executor_credential_digest"] != token_digest(executor_credential_token):
        raise MandateError("executor proof is not bound to its independent authority credential")
    if statement["audience"] != context.expected_audience:
        raise MandateError("executor proof audience mismatch")
    if statement["resource"] != context.expected_resource or statement["action"] != context.expected_action:
        raise MandateError("executor proof action mismatch")
    if statement["target"] != context.expected_target or statement["body_digest"] != context.expected_body_digest:
        raise MandateError("executor proof is not bound to the exact target and payload")
    proof_time = _time(statement["issued_at"], "proof.issued_at")
    now = context.now.astimezone(timezone.utc)
    if abs((now - proof_time).total_seconds()) > 60:
        raise MandateError("executor proof is stale")


def authority_path_digest(receipt: dict[str, Any], credential_token: str | None = None) -> str:
    value: dict[str, Any] = {"receipt_digest": receipt_digest(receipt)}
    if credential_token is not None:
        value["credential_digest"] = token_digest(credential_token)
    return digest(value)
