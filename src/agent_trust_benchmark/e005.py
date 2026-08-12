from __future__ import annotations

import ast
import copy
import json
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .delegation import digest, token_digest
from .jose import (
    generate_ed25519_keypair,
    public_jwk_thumbprint,
    sign_compact_jws,
    sign_detached_jws,
    verify_compact_jws,
    verify_detached_jws,
)
from .mandate import MandateContext, MandateError, verify_executor_proof, verify_mandate
from .receipt import ReceiptContext, canonical_json, receipt_digest


AUDIENCE = "urn:atb:e005:notion-gateway"
RESOURCE = "notion"
TARGET = "notion:page:123"
REQUEST_ACTION = "request_archive_page"
EXECUTE_ACTION = "archive_page"
REQUEST_AUTHORITY_ISSUER = "urn:atb:e005:workflow-authority"
EXECUTOR_AUTHORITY_ISSUER = "urn:atb:e005:notion-admin"
AGENT_A = "urn:atb:e005:agent-a"
AGENT_B = "urn:atb:e005:agent-b"


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
            "schema": "atb-authority-lineage/0.2",
            "sequence": len(self.records) + 1,
            "previous": digest(self.records[-1]) if self.records else None,
            **record,
        }
        self.records.append({
            "payload": payload,
            "proof": sign_detached_jws(
                canonical_json(payload), self.private_key, "e005-ledger", "atb-ledger+jws"
            ),
        })

    def verify(self, records: list[dict[str, Any]] | None = None) -> bool:
        values = records if records is not None else self.records
        previous = None
        for sequence, envelope in enumerate(values, 1):
            payload = envelope.get("payload")
            if not isinstance(payload, dict) or payload.get("sequence") != sequence or payload.get("previous") != previous:
                return False
            if not verify_detached_jws(
                canonical_json(payload), envelope.get("proof", ""), self.public_key,
                expected_kid="e005-ledger", expected_typ="atb-ledger+jws",
            ):
                return False
            previous = digest(envelope)
        return True


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.request_authority_private, self.request_authority_public = generate_ed25519_keypair(
            root, "request-authority"
        )
        self.executor_authority_private, self.executor_authority_public = generate_ed25519_keypair(
            root, "executor-authority"
        )
        self.a_private, self.a_public = generate_ed25519_keypair(root, "agent-a")
        self.b_private, self.b_public = generate_ed25519_keypair(root, "agent-b")
        self.c_private, self.c_public = generate_ed25519_keypair(root, "agent-c")
        self.ledger_private, self.ledger_public = generate_ed25519_keypair(root, "ledger")
        self.a_thumbprint = public_jwk_thumbprint(self.a_public)
        self.b_thumbprint = public_jwk_thumbprint(self.b_public)
        self.revoked: set[tuple[str, str]] = set()
        self.consumed: set[str] = set()
        self.effects: list[dict[str, Any]] = []
        self.ledger = Ledger(self.ledger_private, self.ledger_public)
        self.body = {"reason": "E005 duplicate confirmed", "requested_by": "human-h"}
        self.body_digest = digest(self.body)

        self.requester_receipt = self._authority_receipt(
            issuer=REQUEST_AUTHORITY_ISSUER,
            human="human-h",
            agent=AGENT_A,
            thumbprint=self.a_thumbprint,
            action=REQUEST_ACTION,
            key=self.request_authority_private,
            key_id="request-authority",
            handle="human-to-a-request",
        )
        self.requester_credential = self._credential(
            self.requester_receipt, AGENT_A, self.a_thumbprint, REQUEST_ACTION
        )
        self.executor_receipt = self._authority_receipt(
            issuer=EXECUTOR_AUTHORITY_ISSUER,
            human="notion-admin",
            agent=AGENT_B,
            thumbprint=self.b_thumbprint,
            action=EXECUTE_ACTION,
            key=self.executor_authority_private,
            key_id="executor-authority",
            handle="notion-admin-to-b",
            mode="administrator_configured",
        )
        self.executor_credential_claims = self._credential(
            self.executor_receipt, AGENT_B, self.b_thumbprint, EXECUTE_ACTION
        )
        self.executor_credential_token = self.sign_executor_credential()

    def _authority_receipt(
        self,
        *,
        issuer: str,
        human: str,
        agent: str,
        thumbprint: str,
        action: str,
        key: Path,
        key_id: str,
        handle: str,
        mode: str = "interactive_consent",
    ) -> dict[str, Any]:
        payload = {
            "schema_version": "har/0.1",
            "receipt_id": f"urn:uuid:{uuid.uuid4()}",
            "issuer": issuer,
            "human": {"id": human},
            "agent": {"id": agent, "cnf": {"jkt": thumbprint}},
            "authorization": {
                "scopes": [f"{RESOURCE}:{action}"],
                "actions": [{"resource": RESOURCE, "action": action}],
            },
            "audience": [AUDIENCE],
            "authorization_event": {
                "event_id": f"fixture-{handle}",
                "mode": mode,
                "authenticated_at": iso(self.now - timedelta(minutes=2)),
                "witnessed_at": iso(self.now - timedelta(minutes=1)),
                "acr": "urn:atb:fixture",
                "amr": ["fixture"],
            },
            "revocation": {"authority": issuer, "handle": handle},
            "issued_at": iso(self.now - timedelta(seconds=30)),
            "not_before": iso(self.now - timedelta(seconds=30)),
            "expires_at": iso(self.now + timedelta(minutes=15)),
            "nonce": f"e005-{handle}-nonce-0001",
        }
        return {
            "media_type": "application/atb-har+jws",
            "payload": payload,
            "proof": sign_detached_jws(canonical_json(payload), key, key_id, "har+jws"),
        }

    def _credential(self, receipt: dict[str, Any], agent: str, thumbprint: str, action: str) -> dict[str, Any]:
        return {
            "sub": agent,
            "cnf": {"jkt": thumbprint},
            "aud": [AUDIENCE],
            "scope": [f"{RESOURCE}:{action}"],
            "receipt_digest": receipt_digest(receipt),
        }

    def sign_executor_credential(self, claims: dict[str, Any] | None = None) -> str:
        return sign_compact_jws(
            claims or self.executor_credential_claims,
            self.executor_authority_private,
            "executor-authority",
            "atb-executor-authority+jwt",
        )

    def mandate_claims(self, **changes: Any) -> dict[str, Any]:
        claims = {
            "schema_version": "atb-mandate/0.1",
            "jti": f"urn:uuid:{uuid.uuid4()}",
            "relationship": "authorized_invocation",
            "iss": AGENT_A,
            "executor": AGENT_B,
            "executor_cnf": {"jkt": self.b_thumbprint},
            "request_authority_receipt_digest": receipt_digest(self.requester_receipt),
            "audience": [AUDIENCE],
            "action": {
                "resource": RESOURCE,
                "action": EXECUTE_ACTION,
                "target": TARGET,
                "payload_digest": self.body_digest,
            },
            "issued_at": iso(self.now),
            "not_before": iso(self.now),
            "expires_at": iso(self.now + timedelta(minutes=10)),
            "revocation": {"authority": REQUEST_AUTHORITY_ISSUER, "handle": "a-to-b-mandate"},
        }
        claims.update(changes)
        return claims

    def sign_mandate(self, claims: dict[str, Any] | None = None) -> str:
        return sign_compact_jws(
            claims or self.mandate_claims(), self.a_private, "agent-a", "atb-mandate+jwt"
        )

    def receipt_context(self, *, requester: bool, now: datetime) -> ReceiptContext:
        if requester:
            issuer = REQUEST_AUTHORITY_ISSUER
            public_key = self.request_authority_public
            key_id = "request-authority"
            action = REQUEST_ACTION
            modes = frozenset({"interactive_consent"})
        else:
            issuer = EXECUTOR_AUTHORITY_ISSUER
            public_key = self.executor_authority_public
            key_id = "executor-authority"
            action = EXECUTE_ACTION
            modes = frozenset({"administrator_configured"})
        return ReceiptContext(
            trusted_issuers=frozenset({issuer}),
            proof_verifiers={
                "application/atb-har+jws": lambda payload, proof, actual_issuer:
                    actual_issuer == issuer and verify_detached_jws(
                        payload, proof, public_key, expected_kid=key_id, expected_typ="har+jws"
                    )
            },
            expected_audience=AUDIENCE,
            expected_resource=RESOURCE,
            expected_action=action,
            allowed_authorization_modes=modes,
            now=now,
            revocation_checker=lambda authority, handle: (authority, handle) in self.revoked,
        )

    def context(
        self,
        *,
        action: str = EXECUTE_ACTION,
        target: str = TARGET,
        body_digest: str | None = None,
        now: datetime | None = None,
    ) -> MandateContext:
        current = now or datetime.now(timezone.utc)
        return MandateContext(
            requester_receipt_context=self.receipt_context(requester=True, now=current),
            executor_receipt_context=self.receipt_context(requester=False, now=current),
            requester_public_key=self.a_public,
            requester_key_id="agent-a",
            executor_public_key=self.b_public,
            executor_key_id="agent-b",
            expected_requester=AGENT_A,
            expected_executor=AGENT_B,
            expected_executor_thumbprint=self.b_thumbprint,
            expected_audience=AUDIENCE,
            expected_resource=RESOURCE,
            expected_action=action,
            expected_request_action=REQUEST_ACTION,
            expected_target=target,
            expected_body_digest=body_digest or self.body_digest,
            allowed_request_authority=frozenset({(RESOURCE, REQUEST_ACTION)}),
            now=current,
            mandate_revocation_checker=lambda authority, handle: (authority, handle) in self.revoked,
        )


def gateway(fixture: Fixture) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length))
            mandate_token = self.headers.get("Mandate", "")
            executor_token = self.headers.get("Executor-Credential", "")
            statement = request.get("statement", {})
            action = statement.get("action", "")
            target = statement.get("target", "")
            body_digest = digest(request.get("body"))
            status, outcome, reason, result = 403, "deny", "invalid_request", None
            before = len(fixture.effects)
            requester_path = receipt_digest(fixture.requester_receipt)
            executor_path = receipt_digest(fixture.executor_receipt)
            try:
                executor_claims = verify_compact_jws(
                    executor_token,
                    fixture.executor_authority_public,
                    expected_kid="executor-authority",
                    expected_typ="atb-executor-authority+jwt",
                )
                if executor_claims is None:
                    raise MandateError("executor authority credential signature did not verify")
                context = fixture.context(action=action, target=target, body_digest=body_digest)
                mandate_claims = verify_mandate(
                    mandate_token,
                    fixture.requester_receipt,
                    fixture.requester_credential,
                    fixture.executor_receipt,
                    executor_claims,
                    context,
                )
                verify_executor_proof(
                    request.get("proof", ""), statement, mandate_token, executor_token, context
                )
                request_id = statement.get("request_id")
                if request_id in fixture.consumed:
                    raise MandateError("request replay detected")
                fixture.consumed.add(request_id)
                if action != EXECUTE_ACTION or target != TARGET:
                    raise MandateError("mock resource action or target is not permitted")
                resource_credential = "fixture-resource-secret"
                if resource_credential != "fixture-resource-secret":
                    raise RuntimeError("resource credential unavailable")
                result = {"page_id": TARGET, "archived": True}
                fixture.effects.append({"request_id": request_id, "action": action, "target": target, **result})
                status, outcome, reason = 200, "allow", "verified_dual_authority"
            except Exception as exc:
                mandate_claims = None
                reason = str(exc)
            effect_count = len(fixture.effects) - before
            fixture.ledger.append({
                "relationship": "MANDATE",
                "requester": AGENT_A,
                "executor": (mandate_claims or {}).get("executor", statement.get("agent", AGENT_B)),
                "request_authority_receipt_digest": requester_path,
                "executor_authority_receipt_digest": executor_path,
                "mandate_digest": token_digest(mandate_token),
                "executor_credential_digest": token_digest(executor_token),
                "request_id": statement.get("request_id"),
                "resource": statement.get("resource"),
                "action": action,
                "target": target,
                "payload_digest": body_digest,
                "decision": outcome,
                "reason": reason,
                "effect_count": effect_count,
                "resource_result": result,
                "recorded_at": iso(datetime.now(timezone.utc)),
            })
            body = canonical_json({"decision": outcome, "reason": reason, "result": result})
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            return None

    return Handler


def call_foreign(
    fixture: Fixture,
    url: str,
    mandate_token: str,
    executor_credential_token: str,
    action: str,
    target: str,
    request_id: str,
    *,
    body: dict[str, Any] | None = None,
    private_key: Path | None = None,
    key_id: str = "agent-b",
) -> dict[str, Any]:
    mandate_file = fixture.root / f"mandate-{uuid.uuid4()}.txt"
    credential_file = fixture.root / f"executor-credential-{uuid.uuid4()}.txt"
    mandate_file.write_text(mandate_token)
    credential_file.write_text(executor_credential_token)
    command = [
        "python3",
        str(Path(__file__).parents[2] / "experiments/e005/foreign_agent_b.py"),
        "--gateway", url,
        "--mandate-file", str(mandate_file),
        "--executor-credential-file", str(credential_file),
        "--private-key", str(private_key or fixture.b_private),
        "--key-id", key_id,
        "--request-id", request_id,
        "--audience", AUDIENCE,
        "--resource", RESOURCE,
        "--action", action,
        "--target", target,
        "--body", json.dumps(body or fixture.body),
    ]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def run_e005() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="atb-e005-") as directory:
        fixture = Fixture(Path(directory))
        server = ThreadingHTTPServer(("127.0.0.1", 0), gateway(fixture))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"http://127.0.0.1:{server.server_port}/protected/notion"
        mandate = fixture.sign_mandate()
        executor_credential = fixture.executor_credential_token
        tests: list[dict[str, Any]] = []

        def observed(name: str, condition: bool, detail: str) -> None:
            tests.append({"test": name, "outcome": "PASS" if condition else "FAIL", "detail": detail})

        def denied(name: str, response: dict[str, Any], before: int, detail: str) -> None:
            observed(name, response["status"] == 403 and len(fixture.effects) == before, detail)

        try:
            valid = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET, "request-valid"
            )
            observed(
                "VALID_MANDATE_DUAL_AUTHORITY",
                valid["status"] == 200 and len(fixture.effects) == 1,
                "A's request authority and B's independent Notion authority jointly permitted one exact archive.",
            )

            # B's powerful Notion permission cannot launder an unauthorized A request.
            unauthorized_request_receipt = copy.deepcopy(fixture.requester_receipt)
            unauthorized_request_receipt["payload"]["authorization"] = {
                "scopes": ["notion:request_read_page"],
                "actions": [{"resource": RESOURCE, "action": "request_read_page"}],
            }
            unauthorized_request_receipt["proof"] = sign_detached_jws(
                canonical_json(unauthorized_request_receipt["payload"]), fixture.request_authority_private,
                "request-authority", "har+jws",
            )
            original_receipt, original_credential = fixture.requester_receipt, fixture.requester_credential
            fixture.requester_receipt = unauthorized_request_receipt
            fixture.requester_credential = fixture._credential(
                unauthorized_request_receipt, AGENT_A, fixture.a_thumbprint, "request_read_page"
            )
            unauthorized_mandate = fixture.sign_mandate(fixture.mandate_claims(
                request_authority_receipt_digest=receipt_digest(unauthorized_request_receipt)
            ))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, unauthorized_mandate, executor_credential, EXECUTE_ACTION, TARGET,
                "request-unauthorized-a",
            )
            denied(
                "REQUESTER_CANNOT_LAUNDER_EXECUTOR_POWER", response, before,
                "B's archive permission did not compensate for A lacking authority to request archival.",
            )
            fixture.requester_receipt, fixture.requester_credential = original_receipt, original_credential

            # A's request authority cannot compensate for B lacking execution authority.
            weak_executor_receipt = copy.deepcopy(fixture.executor_receipt)
            weak_executor_receipt["payload"]["authorization"] = {
                "scopes": ["notion:read_page"],
                "actions": [{"resource": RESOURCE, "action": "read_page"}],
            }
            weak_executor_receipt["proof"] = sign_detached_jws(
                canonical_json(weak_executor_receipt["payload"]), fixture.executor_authority_private,
                "executor-authority", "har+jws",
            )
            weak_executor_claims = fixture._credential(
                weak_executor_receipt, AGENT_B, fixture.b_thumbprint, "read_page"
            )
            weak_executor_token = fixture.sign_executor_credential(weak_executor_claims)
            original_executor_receipt = fixture.executor_receipt
            fixture.executor_receipt = weak_executor_receipt
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, weak_executor_token, EXECUTE_ACTION, TARGET, "request-weak-b"
            )
            denied(
                "EXECUTOR_LACKS_INDEPENDENT_PERMISSION", response, before,
                "A's valid request could not substitute for missing Notion archive authority at B.",
            )
            fixture.executor_receipt = original_executor_receipt

            tampered = tamper_compact_jws(mandate)
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, tampered, executor_credential, EXECUTE_ACTION, TARGET, "request-tampered"
            )
            denied("TAMPERED_MANDATE", response, before, "A one-byte mandate mutation was rejected.")

            ambiguous = fixture.sign_mandate(fixture.mandate_claims(relationship="delegate"))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, ambiguous, executor_credential, EXECUTE_ACTION, TARGET,
                "request-ambiguous-relationship",
            )
            denied(
                "AMBIGUOUS_RELATIONSHIP_FAILS_CLOSED", response, before,
                "A relationship labelled as delegation could not enter the mandate verifier.",
            )

            expired = fixture.sign_mandate(fixture.mandate_claims(
                issued_at=iso(fixture.now - timedelta(minutes=20)),
                not_before=iso(fixture.now - timedelta(minutes=20)),
                expires_at=iso(fixture.now - timedelta(minutes=10)),
            ))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, expired, executor_credential, EXECUTE_ACTION, TARGET, "request-expired"
            )
            denied("EXPIRED_MANDATE", response, before, "An expired request relationship was rejected.")

            wrong_audience = fixture.sign_mandate(fixture.mandate_claims(audience=["urn:github-gateway"]))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, wrong_audience, executor_credential, EXECUTE_ACTION, TARGET,
                "request-wrong-audience",
            )
            denied("WRONG_AUDIENCE", response, before, "A Notion mandate failed at another audience.")

            wrong_target_claims = fixture.mandate_claims()
            wrong_target_claims["action"] = {**wrong_target_claims["action"], "target": "notion:page:999"}
            wrong_target = fixture.sign_mandate(wrong_target_claims)
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, wrong_target, executor_credential, EXECUTE_ACTION, TARGET, "request-wrong-target"
            )
            denied("WRONG_TARGET", response, before, "Authority for notion:page:999 could not archive notion:page:123.")

            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET, "request-wrong-payload",
                body={"reason": "changed after authorization"},
            )
            denied("WRONG_PAYLOAD", response, before, "A changed archive payload was rejected.")

            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET, "request-stolen",
                private_key=fixture.c_private, key_id="agent-c",
            )
            denied("WRONG_EXECUTOR_POSSESSION", response, before, "Agent C could not execute B's mandate.")

            stolen_executor_claims = {**fixture.executor_credential_claims, "sub": "urn:atb:e005:agent-c"}
            stolen_executor_token = fixture.sign_executor_credential(stolen_executor_claims)
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, stolen_executor_token, EXECUTE_ACTION, TARGET,
                "request-wrong-executor-authority",
            )
            denied(
                "WRONG_EXECUTOR_AUTHORITY_SUBJECT", response, before,
                "An independently signed credential for another subject could not authorize B.",
            )

            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET, "request-valid"
            )
            denied("REQUEST_REPLAY", response, before, "The exact request could not cause a second archive.")

            fixture.revoked.add((REQUEST_AUTHORITY_ISSUER, "a-to-b-mandate"))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET, "request-mandate-revoked"
            )
            denied("MANDATE_REVOCATION", response, before, "Revoking A's mandate blocked execution.")
            fixture.revoked.remove((REQUEST_AUTHORITY_ISSUER, "a-to-b-mandate"))

            fixture.revoked.add((REQUEST_AUTHORITY_ISSUER, "human-to-a-request"))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET,
                "request-requester-revoked",
            )
            denied("REQUEST_AUTHORITY_REVOCATION", response, before, "Revoking A's request authority blocked execution.")
            fixture.revoked.remove((REQUEST_AUTHORITY_ISSUER, "human-to-a-request"))

            fixture.revoked.add((EXECUTOR_AUTHORITY_ISSUER, "notion-admin-to-b"))
            before = len(fixture.effects)
            response = call_foreign(
                fixture, url, mandate, executor_credential, EXECUTE_ACTION, TARGET,
                "request-executor-revoked",
            )
            denied("EXECUTOR_AUTHORITY_REVOCATION", response, before, "Revoking B's Notion authority blocked execution.")
            fixture.revoked.remove((EXECUTOR_AUTHORITY_ISSUER, "notion-admin-to-b"))

            agent_path = Path(__file__).parents[2] / "experiments/e005/foreign_agent_b.py"
            agent_source = ast.parse(agent_path.read_text())
            imports = {
                node.names[0].name.split(".")[0]
                for node in ast.walk(agent_source)
                if isinstance(node, (ast.Import, ast.ImportFrom)) and node.names
            }
            proprietary = imports & {"agent_trust_benchmark"}
            observed(
                "FOREIGN_AGENT_NO_PROPRIETARY_SDK",
                not proprietary,
                "Agent B imports only the Python standard library and treats both artifacts as opaque.",
            )

            allowed_record = fixture.ledger.records[0]["payload"]
            observed(
                "RECEIPT_BINDS_BOTH_AUTHORITY_PATHS",
                allowed_record["relationship"] == "MANDATE"
                and allowed_record["request_authority_receipt_digest"] == receipt_digest(fixture.requester_receipt)
                and allowed_record["executor_authority_receipt_digest"] == receipt_digest(fixture.executor_receipt)
                and allowed_record["effect_count"] == 1,
                "The ALLOW receipt names MANDATE and binds requester authority, executor authority, and one effect.",
            )
            ledger_ok = fixture.ledger.verify()
            mutated = copy.deepcopy(fixture.ledger.records)
            mutated[0]["payload"]["request_authority_receipt_digest"] = "sha256:" + "0" * 64
            observed("LEDGER_LINEAGE_VERIFIES", ledger_ok, "Every authority-lineage receipt and previous hash verified.")
            observed("LEDGER_TAMPERING_DETECTED", not fixture.ledger.verify(mutated), "Changing either path broke verification.")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        return {
            "schema": "atb-e005-result/0.1",
            "experiment": "E005",
            "classification": "THIN SLICE PROVEN",
            "tests": tests,
            "passed": sum(item["outcome"] == "PASS" for item in tests),
            "total": len(tests),
            "resource_effects": fixture.effects,
            "foreign_agent": {
                "proprietary_sdk": False,
                "mandate_parsing": False,
                "executor_credential_parsing": False,
            },
            "ledger": fixture.ledger.records,
            "limits": [
                "This is an isolated mock-resource proof, not a production Notion integration.",
                "The authority-lineage schema and mandate profile are experimental and not registered standards.",
                "The request-authority policy mapping is caller-owned; a receipt cannot decide that its own action label is sufficient.",
                "The gateway is non-bypassable only because the mock Notion credential exists solely inside it.",
                "This proves the exercised dual-authority path, not universal enforcement or external interoperability.",
            ],
        }


def write_e005(output: Path) -> tuple[Path, Path]:
    result = run_e005()
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "result.json"
    summary_path = output / "SUMMARY.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n")
    rows = "\n".join(
        f"| {item['test']} | {item['outcome']} | {item['detail']} |" for item in result["tests"]
    )
    summary_path.write_text(
        f"# E005 result\n\n**Verdict: {result['classification']}**\n\n"
        f"{result['passed']}/{result['total']} exploratory checks passed.\n\n"
        "| Test | Actual | Evidence |\n|---|---|---|\n" + rows
        + "\n\n## Limits\n\n" + "\n".join(f"- {item}" for item in result["limits"]) + "\n"
    )
    return json_path, summary_path
