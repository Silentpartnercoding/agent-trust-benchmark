from __future__ import annotations

import copy
import hashlib
import hmac
import unittest
from datetime import datetime, timedelta, timezone

from agent_trust_benchmark.receipt import (
    ReceiptContext,
    ReceiptVerdict,
    canonical_json,
    receipt_digest,
    verify_receipt,
)


NOW = datetime(2026, 8, 11, 18, 0, tzinfo=timezone.utc)
ISSUER = "https://issuer.example"
TEST_SECRET = b"benchmark-only-proof-key"


def _proof(payload: dict) -> str:
    return hmac.new(TEST_SECRET, canonical_json(payload), hashlib.sha256).hexdigest()


def _verifier(payload: bytes, proof: str, issuer: str) -> bool:
    expected = hmac.new(TEST_SECRET, payload, hashlib.sha256).hexdigest()
    return issuer == ISSUER and hmac.compare_digest(expected, proof)


def _envelope(mode: str = "interactive_consent") -> dict:
    payload = {
        "schema_version": "har/0.1",
        "receipt_id": "urn:uuid:1c52ab38-3214-4f05-b5ec-b8febaab92ec",
        "issuer": ISSUER,
        "human": {"id": "human-123"},
        "agent": {"id": "agent-456", "cnf": {"jkt": "agent-key-thumbprint"}},
        "authorization": {
            "scopes": ["payments:preview"],
            "actions": [{"resource": "payments", "action": "preview"}],
        },
        "audience": ["https://payments.example"],
        "authorization_event": {
            "event_id": "idp-event-789",
            "mode": mode,
            "authenticated_at": (NOW - timedelta(minutes=2)).isoformat(),
            "witnessed_at": (NOW - timedelta(minutes=1)).isoformat(),
            "acr": "urn:example:assurance:mfa",
            "amr": ["pwd", "otp"],
        },
        "revocation": {"authority": ISSUER, "handle": "revocation-handle-abc"},
        "issued_at": (NOW - timedelta(seconds=30)).isoformat(),
        "not_before": (NOW - timedelta(seconds=30)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "nonce": "random-nonce-123456789",
    }
    return {"media_type": "application/test-proof", "payload": payload, "proof": _proof(payload)}


def _credential(envelope: dict) -> dict:
    return {
        "sub": "agent-456",
        "cnf": {"jkt": "agent-key-thumbprint"},
        "aud": ["https://payments.example"],
        "scope": ["payments:preview"],
        "receipt_digest": receipt_digest(envelope),
    }


def _context(**overrides) -> ReceiptContext:
    values = {
        "trusted_issuers": frozenset({ISSUER}),
        "proof_verifiers": {"application/test-proof": _verifier},
        "expected_audience": "https://payments.example",
        "expected_resource": "payments",
        "expected_action": "preview",
        "allowed_authorization_modes": frozenset({"interactive_consent"}),
        "now": NOW,
        "revocation_checker": lambda authority, handle: False,
    }
    values.update(overrides)
    return ReceiptContext(**values)


class ReceiptTests(unittest.TestCase):
    def test_valid_receipt_verifies(self):
        envelope = _envelope()
        self.assertIs(verify_receipt(envelope, _credential(envelope), _context()).verdict, ReceiptVerdict.VERIFIED)

    def test_receipt_swap_is_rejected_by_credential_digest(self):
        original = _envelope()
        credential = _credential(original)
        swapped = _envelope()
        swapped["payload"]["nonce"] = "different-nonce-123456"
        swapped["proof"] = _proof(swapped["payload"])
        self.assertIs(verify_receipt(swapped, credential, _context()).verdict, ReceiptVerdict.REJECTED)

    def test_agent_identity_mismatch_is_rejected(self):
        envelope = _envelope()
        credential = _credential(envelope)
        credential["sub"] = "attacker-agent"
        self.assertIs(verify_receipt(envelope, credential, _context()).verdict, ReceiptVerdict.REJECTED)

    def test_agent_key_mismatch_is_rejected(self):
        envelope = _envelope()
        credential = _credential(envelope)
        credential["cnf"]["jkt"] = "attacker-key"
        self.assertIs(verify_receipt(envelope, credential, _context()).verdict, ReceiptVerdict.REJECTED)

    def test_action_expansion_is_rejected(self):
        envelope = _envelope()
        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(expected_action="execute")).verdict,
            ReceiptVerdict.REJECTED,
        )

    def test_credential_scope_expansion_does_not_expand_receipt(self):
        envelope = _envelope()
        credential = _credential(envelope)
        credential["scope"].append("payments:execute")
        self.assertIs(
            verify_receipt(envelope, credential, _context(expected_action="execute")).verdict,
            ReceiptVerdict.REJECTED,
        )

    def test_wrong_audience_is_rejected(self):
        envelope = _envelope()
        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(expected_audience="https://attacker.example")).verdict,
            ReceiptVerdict.REJECTED,
        )

    def test_expired_receipt_is_rejected(self):
        envelope = _envelope()
        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(now=NOW + timedelta(hours=1))).verdict,
            ReceiptVerdict.REJECTED,
        )

    def test_revoked_receipt_is_rejected(self):
        envelope = _envelope()
        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(revocation_checker=lambda a, h: True)).verdict,
            ReceiptVerdict.REJECTED,
        )

    def test_missing_revocation_evidence_is_indeterminate(self):
        envelope = _envelope()
        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(revocation_checker=None)).verdict,
            ReceiptVerdict.INDETERMINATE,
        )

    def test_revocation_checker_error_is_indeterminate(self):
        envelope = _envelope()

        def unavailable(authority, handle):
            raise TimeoutError("fixture outage")

        self.assertIs(
            verify_receipt(envelope, _credential(envelope), _context(revocation_checker=unavailable)).verdict,
            ReceiptVerdict.INDETERMINATE,
        )

    def test_administrator_label_cannot_impersonate_interactive_consent(self):
        envelope = _envelope("administrator_configured")
        self.assertIs(verify_receipt(envelope, _credential(envelope), _context()).verdict, ReceiptVerdict.REJECTED)

    def test_untrusted_proof_media_type_is_indeterminate(self):
        envelope = _envelope()
        envelope["media_type"] = "application/attacker-selected-proof"
        credential = _credential(envelope)
        self.assertIs(verify_receipt(envelope, credential, _context()).verdict, ReceiptVerdict.INDETERMINATE)

    def test_approved_proof_verifier_error_is_indeterminate(self):
        envelope = _envelope()

        def broken_verifier(payload, proof, issuer):
            raise RuntimeError("fixture verifier failure")

        context = _context(proof_verifiers={"application/test-proof": broken_verifier})
        self.assertIs(verify_receipt(envelope, _credential(envelope), context).verdict, ReceiptVerdict.INDETERMINATE)

    def test_payload_cannot_select_verification_mode(self):
        envelope = _envelope()
        envelope["payload"]["verification_mode"] = "trust-me"
        envelope["proof"] = _proof(envelope["payload"])
        self.assertIs(verify_receipt(envelope, _credential(envelope), _context()).verdict, ReceiptVerdict.REJECTED)

    def test_tampered_proof_is_rejected(self):
        envelope = _envelope()
        credential = _credential(envelope)
        tampered = copy.deepcopy(envelope)
        tampered["payload"]["authorization"]["scopes"].append("payments:execute")
        self.assertIs(verify_receipt(tampered, credential, _context()).verdict, ReceiptVerdict.REJECTED)

    def test_malformed_credential_is_rejected_without_crashing(self):
        envelope = _envelope()
        credential = _credential(envelope)
        credential["cnf"] = "not-an-object"
        self.assertIs(verify_receipt(envelope, credential, _context()).verdict, ReceiptVerdict.REJECTED)

    def test_impossible_not_before_order_is_rejected(self):
        envelope = _envelope()
        envelope["payload"]["not_before"] = (NOW - timedelta(hours=1)).isoformat()
        envelope["proof"] = _proof(envelope["payload"])
        credential = _credential(envelope)
        self.assertIs(verify_receipt(envelope, credential, _context()).verdict, ReceiptVerdict.REJECTED)


if __name__ == "__main__":
    unittest.main()
