from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


class ReceiptVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class ReceiptResult:
    verdict: ReceiptVerdict
    reason: str


ProofVerifier = Callable[[bytes, str, str], bool]
RevocationChecker = Callable[[str, str], bool | None]


@dataclass(frozen=True)
class ReceiptContext:
    """Caller-owned verification context.

    Trust anchors, proof mechanisms, expected use, and revocation access come
    from the caller. The untrusted receipt cannot select any of them.
    """

    trusted_issuers: frozenset[str]
    proof_verifiers: dict[str, ProofVerifier]
    expected_audience: str
    expected_resource: str
    expected_action: str
    allowed_authorization_modes: frozenset[str]
    now: datetime
    revocation_checker: RevocationChecker | None


PAYLOAD_KEYS = {
    "schema_version",
    "receipt_id",
    "issuer",
    "human",
    "agent",
    "authorization",
    "audience",
    "authorization_event",
    "revocation",
    "issued_at",
    "not_before",
    "expires_at",
    "nonce",
}
ENVELOPE_KEYS = {"media_type", "payload", "proof"}


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def receipt_digest(envelope: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(envelope)).hexdigest()


def _time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _shape_is_valid(envelope: Any) -> bool:
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_KEYS:
        return False
    if not isinstance(envelope.get("media_type"), str) or not envelope["media_type"]:
        return False
    if not isinstance(envelope.get("proof"), str) or not envelope["proof"]:
        return False
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or set(payload) != PAYLOAD_KEYS:
        return False
    try:
        receipt_id = payload["receipt_id"]
        if not isinstance(receipt_id, str) or not receipt_id.startswith("urn:uuid:"):
            return False
        uuid.UUID(receipt_id.removeprefix("urn:uuid:"))
        scopes = payload["authorization"]["scopes"]
        actions = payload["authorization"]["actions"]
        audience = payload["audience"]
        amr = payload["authorization_event"]["amr"]
        return (
            payload["schema_version"] == "har/0.1"
            and isinstance(payload["issuer"], str) and bool(payload["issuer"])
            and set(payload["human"]) == {"id"}
            and isinstance(payload["human"]["id"], str) and bool(payload["human"]["id"])
            and set(payload["agent"]) == {"id", "cnf"}
            and isinstance(payload["agent"]["id"], str) and bool(payload["agent"]["id"])
            and set(payload["agent"]["cnf"]) == {"jkt"}
            and isinstance(payload["agent"]["cnf"]["jkt"], str) and bool(payload["agent"]["cnf"]["jkt"])
            and set(payload["authorization"]) == {"scopes", "actions"}
            and isinstance(scopes, list) and bool(scopes)
            and all(isinstance(item, str) and item for item in scopes)
            and len(scopes) == len(set(scopes))
            and isinstance(actions, list) and bool(actions)
            and all(
                isinstance(item, dict)
                and set(item) == {"resource", "action"}
                and isinstance(item["resource"], str) and bool(item["resource"])
                and isinstance(item["action"], str) and bool(item["action"])
                for item in actions
            )
            and len(actions) == len({(item["resource"], item["action"]) for item in actions})
            and isinstance(audience, list) and bool(audience)
            and all(isinstance(item, str) and item for item in audience)
            and len(audience) == len(set(audience))
            and set(payload["authorization_event"]) == {
                "event_id", "mode", "authenticated_at", "witnessed_at", "acr", "amr"
            }
            and isinstance(payload["authorization_event"]["event_id"], str)
            and bool(payload["authorization_event"]["event_id"])
            and payload["authorization_event"]["mode"] in {
                "interactive_consent", "administrator_configured"
            }
            and isinstance(payload["authorization_event"]["acr"], str)
            and bool(payload["authorization_event"]["acr"])
            and isinstance(amr, list) and bool(amr)
            and all(isinstance(item, str) and item for item in amr)
            and len(amr) == len(set(amr))
            and set(payload["revocation"]) == {"authority", "handle"}
            and all(
                isinstance(payload["revocation"][key], str) and payload["revocation"][key]
                for key in ("authority", "handle")
            )
            and isinstance(payload["nonce"], str)
            and len(payload["nonce"]) >= 16
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def verify_receipt(
    envelope: dict[str, Any],
    credential: dict[str, Any],
    context: ReceiptContext,
) -> ReceiptResult:
    """Verify a receipt against already-verified credential claims.

    The caller must authenticate and cryptographically verify the action
    credential before passing its claims here. This function verifies the
    additional human-authorization binding; it is not a token verifier.
    """
    if not _shape_is_valid(envelope):
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt shape is invalid or contains undeclared fields.")

    payload = envelope["payload"]
    issuer = payload["issuer"]
    if issuer not in context.trusted_issuers:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt issuer is not trusted by the caller.")

    verifier = context.proof_verifiers.get(envelope["media_type"])
    if verifier is None:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Caller has no approved verifier for this proof media type.")
    try:
        proof_valid = verifier(canonical_json(payload), envelope["proof"], issuer)
    except Exception:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Approved proof verifier did not return a result; fail closed.")
    if not proof_valid:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt proof did not verify under the caller's trust policy.")

    try:
        not_before = _time(payload["not_before"])
        expires_at = _time(payload["expires_at"])
        authenticated_at = _time(payload["authorization_event"]["authenticated_at"])
        witnessed_at = _time(payload["authorization_event"]["witnessed_at"])
        issued_at = _time(payload["issued_at"])
    except (TypeError, ValueError):
        return ReceiptResult(ReceiptVerdict.REJECTED, "One or more receipt timestamps are invalid.")
    if context.now.tzinfo is None:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Caller time has no timezone; fail closed.")
    now = context.now.astimezone(timezone.utc)
    if not (authenticated_at <= witnessed_at <= issued_at <= not_before <= expires_at):
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt event timestamps are not causally ordered.")
    if now < not_before or now >= expires_at:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt is not currently valid.")

    if payload["authorization_event"]["mode"] not in context.allowed_authorization_modes:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Authorization mode is not accepted by the caller.")
    if context.expected_audience not in payload["audience"]:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt is not addressed to this audience.")

    expected_digest = receipt_digest(envelope)
    presented_digest = credential.get("receipt_digest")
    if not isinstance(presented_digest, str) or not hmac.compare_digest(presented_digest, expected_digest):
        return ReceiptResult(ReceiptVerdict.REJECTED, "Action credential is not bound to this exact signed receipt.")
    if credential.get("sub") != payload["agent"]["id"]:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Credential agent does not match the authorized agent.")
    credential_cnf = credential.get("cnf", {})
    if not isinstance(credential_cnf, dict) or credential_cnf.get("jkt") != payload["agent"]["cnf"]["jkt"]:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Credential key does not match the authorized agent key.")
    credential_audience = credential.get("aud", [])
    if isinstance(credential_audience, str):
        credential_audience = [credential_audience]
    if context.expected_audience not in credential_audience:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Credential is not addressed to this audience.")

    action = {"resource": context.expected_resource, "action": context.expected_action}
    if action not in payload["authorization"]["actions"]:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Requested action is outside the human authorization.")
    required_scope = f"{context.expected_resource}:{context.expected_action}"
    if required_scope not in payload["authorization"]["scopes"]:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Requested scope is absent from the receipt.")
    credential_scopes = credential.get("scope", [])
    if isinstance(credential_scopes, str):
        credential_scopes = credential_scopes.split()
    if required_scope not in credential_scopes:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Requested scope is absent from the action credential.")

    if context.revocation_checker is None:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Revocation status could not be checked; fail closed.")
    try:
        revoked = context.revocation_checker(
            payload["revocation"]["authority"],
            payload["revocation"]["handle"],
        )
    except Exception:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Revocation checker did not return a result; fail closed.")
    if revoked is None:
        return ReceiptResult(ReceiptVerdict.INDETERMINATE, "Revocation authority returned no definitive status; fail closed.")
    if revoked:
        return ReceiptResult(ReceiptVerdict.REJECTED, "Receipt has been revoked.")

    return ReceiptResult(
        ReceiptVerdict.VERIFIED,
        "Trusted issuer witnessed the accepted human authorization; receipt, agent credential, audience, action, key, time, and revocation status all bind.",
    )
