from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from .adapters.zitadel_opa import ZitadelOpaAdapter
from .jose import (
    generate_ed25519_keypair,
    public_jwk_thumbprint,
    sign_action_proof,
    sign_compact_jws,
    sign_detached_jws,
    verify_action_proof,
    verify_compact_jws,
    verify_detached_jws,
)
from .receipt import ReceiptContext, ReceiptVerdict, canonical_json, receipt_digest, verify_receipt


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime | None = None) -> str:
    return (value or _now()).isoformat().replace("+00:00", "Z")


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


@dataclass(frozen=True)
class Witness:
    provider: str
    human_id: str
    agent_id: str
    authorization_mode: str
    scopes: tuple[str, ...]
    authenticated_at: datetime
    witnessed_at: datetime
    event_id: str
    acr: str
    amr: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    limitation: str


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.current = {"action": values.get("action"), "inputs": []}
            self.forms.append(self.current)
        elif tag in {"input", "button"} and self.current is not None:
            self.current["inputs"].append(values)


class _CallbackHandler(BaseHTTPRequestHandler):
    query: dict[str, list[str]] | None = None

    def do_GET(self) -> None:
        type(self).query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Authorization received. This local fixture may be closed.")

    def log_message(self, *args: Any) -> None:
        return None


def _form_post(url: str, values: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(values).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def _json_get(url: str, bearer: str) -> Any:
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def keycloak_witness(base_url: str = "http://127.0.0.1:18080") -> Witness:
    callback_url = "http://127.0.0.1:18999/callback"
    _CallbackHandler.query = None
    server = HTTPServer(("127.0.0.1", 18999), _CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        state = secrets.token_urlsafe(24)
        query = urllib.parse.urlencode(
            {
                "client_id": "agent-e001",
                "response_type": "code",
                "redirect_uri": callback_url,
                "scope": "openid payments:preview",
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "prompt": "consent",
            }
        )
        cookies = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookies))
        with opener.open(f"{base_url}/realms/atb/protocol/openid-connect/auth?{query}", timeout=10) as response:
            parser = _FormParser()
            parser.feed(response.read().decode())
            login_base = response.geturl()
        if not parser.forms:
            raise RuntimeError("Keycloak did not return a login form")

        # Keycloak marks dev-mode cookies Secure even on the loopback HTTP
        # fixture. Relaxing that transport flag is confined to this local run.
        for cookie in cookies:
            cookie.secure = False
        login_action = urllib.parse.urljoin(login_base, parser.forms[0]["action"])
        login_request = urllib.request.Request(
            login_action,
            data=urllib.parse.urlencode(
                {"username": "human-e001", "password": "local-human-password", "credentialId": ""}
            ).encode(),
            method="POST",
        )
        with opener.open(login_request, timeout=10) as response:
            parser = _FormParser()
            parser.feed(response.read().decode())
            consent_base = response.geturl()
        if not parser.forms or "consent" not in (parser.forms[0]["action"] or ""):
            raise RuntimeError("Keycloak did not return an explicit consent form")

        hidden = {
            item["name"]: item.get("value", "")
            for item in parser.forms[0]["inputs"]
            if item.get("type") == "hidden" and item.get("name")
        }
        hidden["accept"] = "Yes"
        for cookie in cookies:
            cookie.secure = False
        consent_action = urllib.parse.urljoin(consent_base, parser.forms[0]["action"])
        consent_request = urllib.request.Request(
            consent_action,
            data=urllib.parse.urlencode(hidden).encode(),
            method="POST",
        )
        with opener.open(consent_request, timeout=10) as response:
            response.read()

        callback = _CallbackHandler.query
        if not callback or callback.get("state") != [state] or "code" not in callback:
            raise RuntimeError("Keycloak callback did not preserve the authorization state")
        token_response = _form_post(
            f"{base_url}/realms/atb/protocol/openid-connect/token",
            {
                "grant_type": "authorization_code",
                "client_id": "agent-e001",
                "client_secret": "local-agent-client-secret",
                "redirect_uri": callback_url,
                "code": callback["code"][0],
                "code_verifier": verifier,
            },
        )
        claims = _decode_jwt_payload(token_response["access_token"])

        admin_token = _form_post(
            f"{base_url}/realms/master/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "atb-admin",
                "password": "local-admin-password",
            },
        )["access_token"]
        humans = _json_get(f"{base_url}/admin/realms/atb/users?username=human-e001&exact=true", admin_token)
        clients = _json_get(f"{base_url}/admin/realms/atb/clients?clientId=agent-e001", admin_token)
        if len(humans) != 1 or len(clients) != 1:
            raise RuntimeError("Keycloak fixture identities were not unique")
        human_id = humans[0]["id"]
        consents = _json_get(f"{base_url}/admin/realms/atb/users/{human_id}/consents", admin_token)
        events = _json_get(f"{base_url}/admin/realms/atb/events?max=100", admin_token)
        client_events = [
            event for event in events
            if event.get("clientId") == "agent-e001" and event.get("userId") == human_id
        ]
        event_types = {event.get("type") for event in client_events}
        consent = next((item for item in consents if item.get("clientId") == "agent-e001"), None)
        consent_scopes = set((consent or {}).get("grantedClientScopes", []))
        consent_scopes.update((consent or {}).get("additionalGrants", []))
        token_scopes = set(str(claims.get("scope", "")).split())
        exact_witness = (
            claims.get("sub") == human_id
            and claims.get("azp") == "agent-e001"
            and "payments:preview" in token_scopes
            and "payments:preview" in consent_scopes
            and {"LOGIN", "CODE_TO_TOKEN"}.issubset(event_types)
        )
        if not exact_witness:
            diagnostic = {
                "token_subject": claims.get("sub"),
                "directory_human": human_id,
                "token_claim_keys": sorted(claims),
                "subject_matches": claims.get("sub") == human_id,
                "authorized_party_matches": claims.get("azp") == "agent-e001",
                "token_scope_present": "payments:preview" in token_scopes,
                "consent_scope_present": "payments:preview" in consent_scopes,
                "login_event_present": "LOGIN" in event_types,
                "code_exchange_event_present": "CODE_TO_TOKEN" in event_types,
            }
            raise RuntimeError(f"Keycloak exact witness incomplete: {diagnostic}")
        auth_epoch = int(claims.get("auth_time") or claims["iat"])
        witnessed_epoch = int((consent or {})["lastUpdatedDate"] / 1000)
        login_event = next(event for event in client_events if event.get("type") == "LOGIN")
        return Witness(
            provider="keycloak",
            human_id=human_id,
            agent_id=f"keycloak-client:{clients[0]['id']}",
            authorization_mode="interactive_consent",
            scopes=("payments:preview",),
            authenticated_at=datetime.fromtimestamp(auth_epoch, timezone.utc),
            witnessed_at=datetime.fromtimestamp(max(auth_epoch, witnessed_epoch), timezone.utc),
            event_id=f"keycloak-login:{login_event['time']}:consent:{(consent or {})['lastUpdatedDate']}",
            acr=str(claims.get("acr", "0")),
            amr=tuple(claims.get("amr", ["pwd"])),
            evidence_refs=(
                "keycloak:events/LOGIN",
                "keycloak:user-consent/agent-e001/payments:preview",
                "keycloak:events/CODE_TO_TOKEN",
            ),
            limitation="The interactive browser endpoint was exercised automatically with a fixture human credential; this proves provider mechanics, not real-world human comprehension.",
        )
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


def zitadel_witness(run_id: str) -> Witness:
    adapter = ZitadelOpaAdapter(run_id)
    human = adapter.create_human()
    agent = adapter.create_agent()
    delegation = adapter.delegate()
    if any(item.status.value != "PASS" for item in (human, agent, delegation)):
        raise RuntimeError("ZITADEL fixture did not create the expected administrator-configured relationship")
    now = _now()
    return Witness(
        provider="zitadel",
        human_id=adapter.human_id or "",
        agent_id=adapter.agent_id or "",
        authorization_mode="administrator_configured",
        scopes=("payments:preview",),
        authenticated_at=now,
        witnessed_at=now,
        event_id=f"zitadel-grant:{adapter.grant_id}",
        acr="urn:atb:administrator-configured",
        amr=("admin_api",),
        evidence_refs=(
            f"zitadel:management/users/{adapter.agent_id}/metadata",
            f"zitadel:management/users/{adapter.agent_id}/grants/{adapter.grant_id}",
        ),
        limitation="The current ZITADEL fixture proves an administrator-authored link and role grant, not an interactive human authorization event.",
    )


def _opa_decision(opa_url: str, active: bool, witness: Witness, action: str, receipt_id: str) -> bool:
    request = urllib.request.Request(
        f"{opa_url.rstrip('/')}/v1/data/agent_authz/decision",
        data=json.dumps(
            {
                "input": {
                    "token_active": active,
                    "human_id": witness.human_id,
                    "agent_id": witness.agent_id,
                    "delegation_id": receipt_id,
                    "roles": ["payments_preview"],
                    "resource": "payments",
                    "action": action,
                }
            }
        ).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)["result"]["allow"] is True


def _check(name: str, passed: bool, detail: str) -> dict[str, str]:
    return {"check": name, "status": "PASS" if passed else "FAIL", "detail": detail}


def run_e002(witness: Witness, opa_url: str) -> dict[str, Any]:
    run_id = f"e002-{witness.provider}-{uuid.uuid4()}"
    started = _now()
    issuer = f"urn:agent-trust-benchmark:receipt-issuer:{witness.provider}"
    issuer_kid = f"{witness.provider}-issuer-key"
    revoked_handles: set[str] = set()
    with tempfile.TemporaryDirectory() as directory:
        key_dir = Path(directory)
        issuer_private, issuer_public = generate_ed25519_keypair(key_dir, "issuer")
        agent_private, agent_public = generate_ed25519_keypair(key_dir, "agent")
        agent_jkt = public_jwk_thumbprint(agent_public)
        issued = max(_now(), witness.witnessed_at)
        receipt_id = f"urn:uuid:{uuid.uuid4()}"
        revocation_handle = f"receipt-status-{uuid.uuid4()}"
        payload = {
            "schema_version": "har/0.1",
            "receipt_id": receipt_id,
            "issuer": issuer,
            "human": {"id": witness.human_id},
            "agent": {"id": witness.agent_id, "cnf": {"jkt": agent_jkt}},
            "authorization": {
                "scopes": list(witness.scopes),
                "actions": [{"resource": "payments", "action": "preview"}],
            },
            "audience": ["https://payments.example"],
            "authorization_event": {
                "event_id": witness.event_id,
                "mode": witness.authorization_mode,
                "authenticated_at": _iso(witness.authenticated_at),
                "witnessed_at": _iso(witness.witnessed_at),
                "acr": witness.acr,
                "amr": list(witness.amr),
            },
            "revocation": {"authority": issuer, "handle": revocation_handle},
            "issued_at": _iso(issued),
            "not_before": _iso(issued),
            "expires_at": _iso(issued + timedelta(minutes=5)),
            "nonce": secrets.token_urlsafe(24),
        }
        envelope = {
            "media_type": "application/jose",
            "payload": payload,
            "proof": sign_detached_jws(canonical_json(payload), issuer_private, issuer_kid),
        }
        digest = receipt_digest(envelope)
        credential_claims = {
            "iss": issuer,
            "jti": f"urn:uuid:{uuid.uuid4()}",
            "sub": witness.agent_id,
            "cnf": {"jkt": agent_jkt},
            "aud": ["https://payments.example"],
            "scope": list(witness.scopes),
            "receipt_digest": digest,
            "iat": int(issued.timestamp()),
            "exp": int((issued + timedelta(minutes=5)).timestamp()),
        }
        action_credential = sign_compact_jws(credential_claims, issuer_private, issuer_kid, "at+jwt")
        verified_credential = verify_compact_jws(
            action_credential,
            issuer_public,
            expected_kid=issuer_kid,
            expected_typ="at+jwt",
        )
        action_statement = {
            "nonce": secrets.token_urlsafe(24),
            "method": "POST",
            "audience": "https://payments.example",
            "resource": "payments",
            "action": "preview",
            "credential_digest": "sha256:" + hashlib.sha256(action_credential.encode()).hexdigest(),
            "receipt_digest": digest,
        }
        action_proof = sign_action_proof(action_statement, agent_private)
        action_proof_valid = verify_action_proof(action_statement, action_proof, agent_public)

        def proof_verifier(value: bytes, proof: str, claimed_issuer: str) -> bool:
            return claimed_issuer == issuer and verify_detached_jws(
                value,
                proof,
                issuer_public,
                expected_kid=issuer_kid,
            )

        def revoked(authority: str, handle: str) -> bool | None:
            if authority != issuer:
                return None
            return handle in revoked_handles

        def context(
            action: str,
            modes: frozenset[str] = frozenset({"interactive_consent"}),
            *,
            revocation_checker=revoked,
        ) -> ReceiptContext:
            return ReceiptContext(
                trusted_issuers=frozenset({issuer}),
                proof_verifiers={"application/jose": proof_verifier},
                expected_audience="https://payments.example",
                expected_resource="payments",
                expected_action=action,
                allowed_authorization_modes=modes,
                now=issued + timedelta(seconds=1),
                revocation_checker=revocation_checker,
            )

        credential_ok = verified_credential is not None
        verification_started = time.monotonic()
        positive = verify_receipt(envelope, verified_credential or {}, context("preview"))
        verification_latency_ms = (time.monotonic() - verification_started) * 1000
        positive_verified = positive.verdict is ReceiptVerdict.VERIFIED and action_proof_valid and credential_ok
        allowed = _opa_decision(opa_url, positive_verified, witness, "preview", receipt_id)

        execute = verify_receipt(envelope, verified_credential or {}, context("execute"))
        execute_allowed = _opa_decision(
            opa_url,
            execute.verdict is ReceiptVerdict.VERIFIED and action_proof_valid and credential_ok,
            witness,
            "execute",
            receipt_id,
        )

        swapped_payload = dict(payload)
        swapped_payload["nonce"] = secrets.token_urlsafe(24)
        swapped = {
            "media_type": "application/jose",
            "payload": swapped_payload,
            "proof": sign_detached_jws(canonical_json(swapped_payload), issuer_private, issuer_kid),
        }
        swap_result = verify_receipt(swapped, verified_credential or {}, context("preview"))

        unavailable_revocation = verify_receipt(
            envelope,
            verified_credential or {},
            context(
                "preview",
                frozenset({"interactive_consent", "administrator_configured"}),
                revocation_checker=None,
            ),
        )
        unavailable_allowed = _opa_decision(
            opa_url,
            unavailable_revocation.verdict is ReceiptVerdict.VERIFIED,
            witness,
            "preview",
            receipt_id,
        )

        admin_payload = dict(payload)
        admin_payload["authorization_event"] = dict(payload["authorization_event"])
        admin_payload["authorization_event"]["mode"] = "administrator_configured"
        admin_envelope = {
            "media_type": "application/jose",
            "payload": admin_payload,
            "proof": sign_detached_jws(canonical_json(admin_payload), issuer_private, issuer_kid),
        }
        admin_credential_claims = dict(credential_claims)
        admin_credential_claims["receipt_digest"] = receipt_digest(admin_envelope)
        admin_credential = sign_compact_jws(admin_credential_claims, issuer_private, issuer_kid, "at+jwt")
        verified_admin_credential = verify_compact_jws(
            admin_credential,
            issuer_public,
            expected_kid=issuer_kid,
            expected_typ="at+jwt",
        ) or {}
        admin_result = verify_receipt(admin_envelope, verified_admin_credential, context("preview"))

        mechanically_valid = verify_receipt(
            envelope,
            verified_credential or {},
            context("preview", frozenset({"interactive_consent", "administrator_configured"})),
        )
        revocation_started = time.monotonic()
        revoked_handles.add(revocation_handle)
        after_revocation = verify_receipt(
            envelope,
            verified_credential or {},
            context("preview", frozenset({"interactive_consent", "administrator_configured"})),
        )
        revocation_latency_ms = (time.monotonic() - revocation_started) * 1000
        post_revocation_allowed = _opa_decision(
            opa_url,
            after_revocation.verdict is ReceiptVerdict.VERIFIED,
            witness,
            "preview",
            receipt_id,
        )

        proof_ok = proof_verifier(canonical_json(payload), envelope["proof"], issuer)
        checks = [
            _check("TRUSTED_ISSUER_PROVEN", proof_ok, "The detached Ed25519 JWS verifies under the caller-trusted receipt-issuer key."),
            _check(
                "HUMAN_AUTHORIZATION_WITNESSED",
                witness.authorization_mode == "interactive_consent",
                "The provider evidence records exact interactive preview authorization." if witness.authorization_mode == "interactive_consent" else "Only an administrator-configured relationship was observed; interactive human authorization was not proven.",
            ),
            _check("AGENT_IDENTITY_BOUND", credential_ok and verified_credential.get("sub") == witness.agent_id, "The verified action credential and receipt name the same agent identity."),
            _check("AGENT_KEY_BOUND", action_proof_valid and verified_credential.get("cnf", {}).get("jkt") == agent_jkt, "The agent proved possession of the key bound by the receipt and credential."),
            _check("CREDENTIAL_RECEIPT_BOUND", credential_ok and verified_credential.get("receipt_digest") == digest, "The signed action credential carries the exact signed-receipt digest."),
            _check("AUDIENCE_BOUND", credential_ok and "https://payments.example" in verified_credential.get("aud", []) and "https://payments.example" in payload["audience"], "Receipt and credential address the exercised payments gate."),
            _check("ALLOWED_ACTION_SUCCEEDS", allowed, "The fully verified preview path produced one allowed effect." if allowed else "Preview was safely denied because the required human witness was absent."),
            _check("FORBIDDEN_ACTION_BLOCKED", execute.verdict is ReceiptVerdict.REJECTED and not execute_allowed, "Execute was rejected before effect."),
            _check("RECEIPT_SWAP_BLOCKED", swap_result.verdict is ReceiptVerdict.REJECTED, "A newly signed but differently digested receipt could not be paired with the existing credential."),
            _check("UNAVAILABLE_REVOCATION_FAILS_CLOSED", unavailable_revocation.verdict is ReceiptVerdict.INDETERMINATE and not unavailable_allowed, "An unavailable revocation answer remained visibly indeterminate and produced no effect."),
            _check("ADMIN_LABEL_REJECTED_AS_CONSENT", admin_result.verdict is ReceiptVerdict.REJECTED, "A signed administrator-configured label did not satisfy an interactive-consent policy."),
            _check("REVOCATION_SUPPORTED", mechanically_valid.verdict is ReceiptVerdict.VERIFIED, "The receipt was valid before its receipt-specific handle was revoked."),
            _check("POST_REVOCATION_ACTION_BLOCKED", after_revocation.verdict is ReceiptVerdict.REJECTED and not post_revocation_allowed, "The next preview attempt was rejected after receipt revocation."),
            _check("FULL_PATH_AUDITABLE", bool(witness.evidence_refs) and bool(receipt_id) and bool(credential_claims["jti"]), "Provider witness references, receipt ID, credential ID, and gate outcomes form one reconstructable path."),
        ]

    completed = _now()
    passed_checks = sum(item["status"] == "PASS" for item in checks)
    return {
        "schema_version": "0.1",
        "experiment_id": "e002",
        "provider": witness.provider,
        "run_id": run_id,
        "started_at": _iso(started),
        "completed_at": _iso(completed),
        "authorization_mode_observed": witness.authorization_mode,
        "checks": checks,
        "metrics": {
            "REVOCATION_LATENCY_MS": revocation_latency_ms,
            "RECEIPT_LIFETIME_SECONDS": 300,
            "VERIFICATION_LATENCY_MS": verification_latency_ms,
            "EVIDENCE_COMPLETENESS_PERCENT": round(100 * passed_checks / len(checks), 1),
        },
        "evidence_refs": list(witness.evidence_refs) + [
            "local-receipt-issuer:detached-jws/receipt-id",
            "local-receipt-issuer:compact-jws/credential-id",
            "opa:decision/e002-allow-deny-revoke",
        ],
        "limitations": [
            witness.limitation,
            "The receipt issuer and short-lived action credential authority are benchmark-owned neutral components, not provider-native features.",
            "Provider bearer tokens, JWS values, signatures, private keys, and raw proofs are not retained.",
        ],
    }


def _render(result: dict[str, Any]) -> str:
    lines = [
        f"# E002 result: {result['provider']}",
        "",
        f"- Run: `{result['run_id']}`",
        f"- Authorization mode observed: `{result['authorization_mode_observed']}`",
        "",
        "| Output | Status | Evidence-led explanation |",
        "|---|---|---|",
    ]
    for item in result["checks"]:
        lines.append(f"| `{item['check']}` | **{item['status']}** | {item['detail']} |")
    lines.extend(["", "## Metrics", ""])
    for key, value in result["metrics"].items():
        lines.append(f"- `{key}`: `{value}`")
    lines.extend(["", "## Named limitations", ""])
    lines.extend(f"- {item}" for item in result["limitations"])
    lines.extend(["", "No raw token, credential, signature, proof, or private key is retained.", ""])
    return "\n".join(lines)


def _write(result: dict[str, Any], root: Path) -> tuple[Path, Path]:
    target = root / result["run_id"]
    target.mkdir(parents=True, exist_ok=False)
    json_path = target / "result.json"
    summary_path = target / "SUMMARY.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    summary_path.write_text(_render(result))
    return json_path, summary_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run E002 against one local provider fixture")
    parser.add_argument("--provider", choices=["keycloak", "zitadel"], required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("results/e002"))
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)
    witness = keycloak_witness() if args.provider == "keycloak" else zitadel_witness(f"e002-zitadel-witness-{uuid.uuid4()}")
    opa_url = "http://127.0.0.1:18181" if args.provider == "keycloak" else "http://127.0.0.1:28181"
    result = run_e002(witness, opa_url)
    print(_render(result))
    if not args.no_write:
        paths = _write(result, args.output_dir)
        print(f"Wrote {paths[0]} and {paths[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
