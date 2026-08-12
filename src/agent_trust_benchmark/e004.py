from __future__ import annotations

import ast
import copy
import json
import subprocess
import tempfile
import threading
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .delegation import (
    DelegationContext, DelegationError, digest, token_digest,
    validate_redelegation, verify_agent_b_proof, verify_delegation_chain,
)
from .jose import (
    generate_ed25519_keypair, public_jwk_thumbprint, sign_compact_jws,
    sign_detached_jws, verify_detached_jws,
)
from .receipt import ReceiptContext, canonical_json, receipt_digest


AUDIENCE = "urn:atb:e004:notion-gateway"
RESOURCE = "notion"
ISSUER = "urn:atb:e004:human-authority"
AGENT_A = "urn:atb:e004:agent-a"
AGENT_B = "urn:atb:e004:agent-b"


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def tamper_compact_jws(token: str) -> str:
    """Mutate signed payload bytes, avoiding non-canonical trailing Base64 bits."""
    protected, payload, signature = token.split(".")
    position = max(0, len(payload) // 2)
    replacement = "A" if payload[position] != "A" else "B"
    return f"{protected}.{payload[:position]}{replacement}{payload[position + 1:]}.{signature}"


class Ledger:
    def __init__(self, private_key: Path, public_key: Path) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.records: list[dict[str, Any]] = []

    def append(self, record: dict[str, Any]) -> None:
        payload = {
            "schema": "atb-authority-lineage/0.1",
            "sequence": len(self.records) + 1,
            "previous": digest(self.records[-1]) if self.records else None,
            **record,
        }
        self.records.append({
            "payload": payload,
            "proof": sign_detached_jws(canonical_json(payload), self.private_key, "e004-ledger", "atb-ledger+jws"),
        })

    def verify(self, records: list[dict[str, Any]] | None = None) -> bool:
        values = records if records is not None else self.records
        previous = None
        for sequence, envelope in enumerate(values, 1):
            payload = envelope.get("payload")
            if not isinstance(payload, dict) or payload.get("sequence") != sequence or payload.get("previous") != previous:
                return False
            if not verify_detached_jws(canonical_json(payload), envelope.get("proof", ""), self.public_key,
                                       expected_kid="e004-ledger", expected_typ="atb-ledger+jws"):
                return False
            previous = digest(envelope)
        return True


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.authority_private, self.authority_public = generate_ed25519_keypair(root, "human-authority")
        self.a_private, self.a_public = generate_ed25519_keypair(root, "agent-a")
        self.b_private, self.b_public = generate_ed25519_keypair(root, "agent-b")
        self.c_private, self.c_public = generate_ed25519_keypair(root, "agent-c")
        self.ledger_private, self.ledger_public = generate_ed25519_keypair(root, "ledger")
        self.a_thumbprint = public_jwk_thumbprint(self.a_public)
        self.b_thumbprint = public_jwk_thumbprint(self.b_public)
        self.revoked: set[tuple[str, str]] = set()
        self.effects: list[dict[str, Any]] = []
        self.consumed: set[str] = set()
        self.ledger = Ledger(self.ledger_private, self.ledger_public)
        self.parent = self._parent_receipt()
        self.parent_credential = {
            "sub": AGENT_A, "cnf": {"jkt": self.a_thumbprint}, "aud": [AUDIENCE],
            "scope": ["notion:read_page", "notion:create_page"],
            "receipt_digest": receipt_digest(self.parent),
        }

    def _parent_receipt(self) -> dict[str, Any]:
        payload = {
            "schema_version": "har/0.1", "receipt_id": f"urn:uuid:{uuid.uuid4()}", "issuer": ISSUER,
            "human": {"id": "human-h"}, "agent": {"id": AGENT_A, "cnf": {"jkt": self.a_thumbprint}},
            "authorization": {
                "scopes": ["notion:read_page", "notion:create_page"],
                "actions": [{"resource": RESOURCE, "action": "read_page"},
                            {"resource": RESOURCE, "action": "create_page"}],
            },
            "audience": [AUDIENCE],
            "authorization_event": {
                "event_id": "fixture-human-consent", "mode": "interactive_consent",
                "authenticated_at": iso(self.now - timedelta(minutes=2)),
                "witnessed_at": iso(self.now - timedelta(minutes=1)),
                "acr": "urn:atb:fixture", "amr": ["fixture"],
            },
            "revocation": {"authority": ISSUER, "handle": "human-to-a"},
            "issued_at": iso(self.now - timedelta(seconds=30)),
            "not_before": iso(self.now - timedelta(seconds=30)),
            "expires_at": iso(self.now + timedelta(minutes=15)),
            "nonce": "e004-parent-nonce-0001",
        }
        return {"media_type": "application/atb-har+jws", "payload": payload,
                "proof": sign_detached_jws(canonical_json(payload), self.authority_private,
                                             "human-authority", "har+jws")}

    def receipt_context(self, action: str, now: datetime) -> ReceiptContext:
        return ReceiptContext(
            trusted_issuers=frozenset({ISSUER}),
            proof_verifiers={"application/atb-har+jws": lambda payload, proof, issuer:
                issuer == ISSUER and verify_detached_jws(payload, proof, self.authority_public,
                    expected_kid="human-authority", expected_typ="har+jws")},
            expected_audience=AUDIENCE, expected_resource=RESOURCE, expected_action=action,
            allowed_authorization_modes=frozenset({"interactive_consent"}), now=now,
            revocation_checker=lambda authority, handle: (authority, handle) in self.revoked,
        )

    def delegation_claims(self, **changes: Any) -> dict[str, Any]:
        claims = {
            "schema_version": "atb-delegation/0.1", "jti": f"urn:uuid:{uuid.uuid4()}",
            "iss": AGENT_A, "sub": AGENT_B, "cnf": {"jkt": self.b_thumbprint},
            "parent_receipt_digest": receipt_digest(self.parent), "original_authority_source": ISSUER,
            "audience": [AUDIENCE],
            "authorization": {"scopes": ["notion:create_page"],
                              "actions": [{"resource": RESOURCE, "action": "create_page"}]},
            "issued_at": iso(self.now), "not_before": iso(self.now),
            "expires_at": iso(self.now + timedelta(minutes=10)),
            "can_redelegate": False, "remaining_delegation_depth": 0,
            "revocation": {"authority": ISSUER, "handle": "a-to-b"},
        }
        claims.update(changes)
        return claims

    def sign_delegation(self, claims: dict[str, Any] | None = None) -> str:
        return sign_compact_jws(claims or self.delegation_claims(), self.a_private,
                                "agent-a", "atb-delegation+jwt")

    def context(self, action: str, now: datetime | None = None) -> DelegationContext:
        current = now or datetime.now(timezone.utc)
        return DelegationContext(
            receipt_context=self.receipt_context(action, current), agent_a_public_key=self.a_public,
            agent_a_key_id="agent-a", agent_b_public_key=self.b_public, agent_b_key_id="agent-b",
            expected_agent_a=AGENT_A, expected_agent_b=AGENT_B,
            expected_agent_b_thumbprint=self.b_thumbprint, expected_audience=AUDIENCE,
            expected_resource=RESOURCE, expected_action=action, now=current,
            delegation_revocation_checker=lambda authority, handle: (authority, handle) in self.revoked,
        )


def gateway(fixture: Fixture) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            token = self.headers.get("Delegation", "")
            statement = request.get("statement", {})
            action = statement.get("action", "")
            status, outcome, reason, result = 403, "deny", "invalid_request", None
            before = len(fixture.effects)
            try:
                context = fixture.context(action)
                claims = verify_delegation_chain(token, fixture.parent, fixture.parent_credential, context)
                verify_agent_b_proof(request.get("proof", ""), statement, token, context)
                if statement.get("body_digest") != digest(request.get("body")):
                    raise DelegationError("request body digest mismatch")
                request_id = statement.get("request_id")
                if request_id in fixture.consumed:
                    raise DelegationError("request replay detected")
                fixture.consumed.add(request_id)
                if action != "create_page":
                    raise DelegationError("mock resource action is not permitted")
                # This fixture credential never leaves the gateway process.
                resource_credential = "fixture-resource-secret"
                if resource_credential != "fixture-resource-secret":
                    raise RuntimeError("resource credential unavailable")
                result = {"page_id": f"notion:page:created-{len(fixture.effects) + 1}"}
                fixture.effects.append({"request_id": request_id, "action": action, **result})
                status, outcome, reason = 200, "allow", "verified_chain"
            except Exception as exc:
                claims = None
                reason = str(exc)
            effect_count = len(fixture.effects) - before
            fixture.ledger.append({
                "human": "human-h", "agent_a": AGENT_A,
                "agent_b": (claims or {}).get("sub", statement.get("agent", AGENT_B)),
                "parent_receipt_digest": receipt_digest(fixture.parent),
                "delegation_digest": token_digest(token), "request_id": statement.get("request_id"),
                "resource": statement.get("resource"), "action": action, "decision": outcome,
                "reason": reason, "effect_count": effect_count,
                "resource_result": result, "recorded_at": iso(datetime.now(timezone.utc)),
            })
            body = canonical_json({"decision": outcome, "reason": reason, "result": result})
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return None
    return Handler


def call_foreign(fixture: Fixture, url: str, token: str, action: str, request_id: str,
                 *, private_key: Path | None = None, key_id: str = "agent-b") -> dict[str, Any]:
    token_file = fixture.root / f"delegation-{uuid.uuid4()}.txt"
    token_file.write_text(token)
    command = [
        "python3", str(Path(__file__).parents[2] / "experiments/e004/foreign_agent_b.py"),
        "--gateway", url, "--delegation-file", str(token_file),
        "--private-key", str(private_key or fixture.b_private), "--key-id", key_id,
        "--request-id", request_id, "--audience", AUDIENCE,
        "--resource", RESOURCE, "--action", action,
        "--body", json.dumps({"title": "E004 safe mock page"}),
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def run_e004() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="atb-e004-") as directory:
        fixture = Fixture(Path(directory))
        server = ThreadingHTTPServer(("127.0.0.1", 0), gateway(fixture))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        url = f"http://127.0.0.1:{server.server_port}/protected/notion"
        token = fixture.sign_delegation()
        tests: list[dict[str, Any]] = []

        def observed(name: str, condition: bool, detail: str) -> None:
            tests.append({"test": name, "outcome": "PASS" if condition else "FAIL", "detail": detail})

        try:
            valid = call_foreign(fixture, url, token, "create_page", "request-valid")
            observed("VALID_DELEGATION", valid["status"] == 200 and len(fixture.effects) == 1,
                     "H -> A -> B create_page reached the mock resource exactly once.")
            for action in ("read_page", "archive_page", "admin_workspace"):
                before = len(fixture.effects); response = call_foreign(fixture, url, token, action, f"request-{action}")
                observed(f"FORBIDDEN_{action.upper()}", response["status"] == 403 and len(fixture.effects) == before,
                         f"{action} was denied before the resource.")

            escalation = fixture.sign_delegation(fixture.delegation_claims(
                authorization={"scopes": ["notion:admin_workspace"],
                               "actions": [{"resource": RESOURCE, "action": "admin_workspace"}]}))
            response = call_foreign(fixture, url, escalation, "admin_workspace", "request-escalation")
            observed("PARENT_SCOPE_ESCALATION", response["status"] == 403, "A could not delegate authority it lacked.")

            tampered = tamper_compact_jws(token)
            response = call_foreign(fixture, url, tampered, "create_page", "request-tampered")
            observed("TAMPERED_DELEGATION", response["status"] == 403, "A one-byte token mutation was rejected.")

            expired = fixture.sign_delegation(fixture.delegation_claims(
                issued_at=iso(fixture.now - timedelta(minutes=20)),
                not_before=iso(fixture.now - timedelta(minutes=20)),
                expires_at=iso(fixture.now - timedelta(minutes=10))))
            response = call_foreign(fixture, url, expired, "create_page", "request-expired")
            observed("EXPIRED_DELEGATION", response["status"] == 403, "Expired child authority was rejected.")

            wrong_audience = fixture.sign_delegation(fixture.delegation_claims(audience=["urn:github-gateway"]))
            response = call_foreign(fixture, url, wrong_audience, "create_page", "request-wrong-audience")
            observed("WRONG_AUDIENCE", response["status"] == 403, "A Notion delegation failed at another audience.")

            response = call_foreign(fixture, url, token, "create_page", "request-stolen",
                                    private_key=fixture.c_private, key_id="agent-c")
            observed("WRONG_SUBJECT_POSSESSION", response["status"] == 403, "Agent C could not use B's subject-bound token.")

            parent_claims = fixture.delegation_claims()
            child_claims = fixture.delegation_claims(iss=AGENT_B, sub="urn:atb:e004:agent-c")
            try: validate_redelegation(parent_claims, child_claims); redelegation_denied = False
            except DelegationError: redelegation_denied = True
            observed("REDELEGATION_DISABLED", redelegation_denied, "B could not delegate to C when depth was zero.")

            before = len(fixture.effects); replay = call_foreign(fixture, url, token, "create_page", "request-valid")
            observed("REQUEST_REPLAY", replay["status"] == 403 and len(fixture.effects) == before,
                     "The same request id could not create a second page.")

            fixture.revoked.add((ISSUER, "a-to-b"))
            response = call_foreign(fixture, url, token, "create_page", "request-child-revoked")
            observed("CHILD_REVOCATION", response["status"] == 403, "Revoked A -> B delegation failed closed.")
            fixture.revoked.remove((ISSUER, "a-to-b")); fixture.revoked.add((ISSUER, "human-to-a"))
            response = call_foreign(fixture, url, token, "create_page", "request-parent-revoked")
            observed("PARENT_REVOCATION_CASCADE", response["status"] == 403, "Revoked H -> A authority invalidated B's chain.")

            agent_source = ast.parse((Path(__file__).parents[2] / "experiments/e004/foreign_agent_b.py").read_text())
            imports = {node.names[0].name.split(".")[0] for node in ast.walk(agent_source)
                       if isinstance(node, (ast.Import, ast.ImportFrom)) and node.names}
            proprietary = imports & {"agent_trust_benchmark"}
            observed("FOREIGN_AGENT_NO_PROPRIETARY_SDK", not proprietary,
                     "Agent B imports only the Python standard library and treats delegation as opaque.")

            ledger_ok = fixture.ledger.verify()
            mutated = copy.deepcopy(fixture.ledger.records); mutated[0]["payload"]["decision"] = "deny"
            observed("LEDGER_LINEAGE_VERIFIES", ledger_ok, "Every authority receipt signature and previous hash verified.")
            observed("LEDGER_TAMPERING_DETECTED", not fixture.ledger.verify(mutated), "Changing history broke verification.")
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)

        return {
            "schema": "atb-e004-result/0.1", "experiment": "E004",
            "classification": "PARTIALLY SOLVED",
            "tests": tests, "passed": sum(item["outcome"] == "PASS" for item in tests),
            "total": len(tests), "resource_effects": fixture.effects,
            "foreign_agent": {"proprietary_sdk": False, "delegation_parsing": False},
            "ledger": fixture.ledger.records,
            "limits": [
                "The authority-lineage ledger and A-to-B token are isolated benchmark extensions, not current Knowledge Ledger behavior.",
                "The gateway is non-bypassable only because the mock resource credential exists solely inside it.",
                "This is one-controller exploratory evidence, not external interoperability or production validation.",
                "The token uses standard Ed25519 compact JWS mechanics but an experimental claim profile, not a registered standard.",
            ],
        }


def write_e004(output: Path) -> tuple[Path, Path]:
    result = run_e004(); output.mkdir(parents=True, exist_ok=True)
    json_path = output / "result.json"; summary_path = output / "SUMMARY.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n")
    rows = "\n".join(f"| {item['test']} | {item['outcome']} | {item['detail']} |" for item in result["tests"])
    summary_path.write_text(
        f"# E004 result\n\n**Verdict: {result['classification']}**\n\n"
        f"{result['passed']}/{result['total']} exploratory checks passed.\n\n"
        "| Test | Actual | Evidence |\n|---|---|---|\n" + rows +
        "\n\n## Limits\n\n" + "\n".join(f"- {item}" for item in result["limits"]) + "\n"
    )
    return json_path, summary_path
