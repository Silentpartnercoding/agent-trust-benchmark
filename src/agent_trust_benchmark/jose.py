from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .receipt import canonical_json


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def generate_ed25519_keypair(directory: Path, name: str) -> tuple[Path, Path]:
    private_key = directory / f"{name}-private.pem"
    public_key = directory / f"{name}-public.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True,
        capture_output=True,
    )
    return private_key, public_key


def public_jwk_thumbprint(public_key: Path) -> str:
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    raw_ed25519_key = result.stdout[-32:]
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64(raw_ed25519_key)}
    return _b64(hashlib.sha256(canonical_json(jwk)).digest())


def _sign(value: bytes, private_key: Path) -> bytes:
    with tempfile.NamedTemporaryFile() as input_file:
        input_file.write(value)
        input_file.flush()
        return subprocess.run(
            [
                "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
                "-in", input_file.name,
            ],
            check=True,
            capture_output=True,
        ).stdout


def _verify(value: bytes, signature: bytes, public_key: Path) -> bool:
    with tempfile.NamedTemporaryFile() as signature_file, tempfile.NamedTemporaryFile() as input_file:
        signature_file.write(signature)
        signature_file.flush()
        input_file.write(value)
        input_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_key),
                "-sigfile",
                signature_file.name,
                "-in",
                input_file.name,
            ],
            capture_output=True,
        )
    return result.returncode == 0


def sign_detached_jws(payload: bytes, private_key: Path, kid: str, typ: str = "har+jws") -> str:
    protected = _b64(canonical_json({"alg": "EdDSA", "kid": kid, "typ": typ}))
    signing_input = f"{protected}.{_b64(payload)}".encode()
    return f"{protected}..{_b64(_sign(signing_input, private_key))}"


def verify_detached_jws(
    payload: bytes,
    proof: str,
    public_key: Path,
    *,
    expected_kid: str,
    expected_typ: str = "har+jws",
) -> bool:
    try:
        protected, empty_payload, encoded_signature = proof.split(".")
        header = json.loads(_unb64(protected))
        if empty_payload or header != {"alg": "EdDSA", "kid": expected_kid, "typ": expected_typ}:
            return False
        signing_input = f"{protected}.{_b64(payload)}".encode()
        return _verify(signing_input, _unb64(encoded_signature), public_key)
    except (ValueError, json.JSONDecodeError, OSError):
        return False


def sign_compact_jws(claims: dict[str, Any], private_key: Path, kid: str, typ: str) -> str:
    protected = _b64(canonical_json({"alg": "EdDSA", "kid": kid, "typ": typ}))
    payload = _b64(canonical_json(claims))
    signing_input = f"{protected}.{payload}".encode()
    return f"{protected}.{payload}.{_b64(_sign(signing_input, private_key))}"


def verify_compact_jws(
    token: str,
    public_key: Path,
    *,
    expected_kid: str,
    expected_typ: str,
) -> dict[str, Any] | None:
    try:
        protected, payload, encoded_signature = token.split(".")
        header = json.loads(_unb64(protected))
        if header != {"alg": "EdDSA", "kid": expected_kid, "typ": expected_typ}:
            return None
        if not _verify(f"{protected}.{payload}".encode(), _unb64(encoded_signature), public_key):
            return None
        value = json.loads(_unb64(payload))
        return value if isinstance(value, dict) else None
    except (ValueError, json.JSONDecodeError, OSError):
        return None


def sign_action_proof(statement: dict[str, Any], private_key: Path) -> str:
    return _b64(_sign(canonical_json(statement), private_key))


def verify_action_proof(statement: dict[str, Any], proof: str, public_key: Path) -> bool:
    try:
        return _verify(canonical_json(statement), _unb64(proof), public_key)
    except (ValueError, OSError):
        return False
