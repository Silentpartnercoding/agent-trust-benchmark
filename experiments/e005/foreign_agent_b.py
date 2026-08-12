#!/usr/bin/env python3
"""SDK-free foreign Agent B for E005.

Agent B treats both the mandate and its independent authority credential as
opaque byte strings. It proves possession of its bound key and presents both
artifacts to the enforcement gateway.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign(value: bytes, private_key: Path) -> bytes:
    with tempfile.NamedTemporaryFile() as source:
        source.write(value)
        source.flush()
        return subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key), "-in", source.name],
            check=True,
            capture_output=True,
        ).stdout


def compact_jws(claims: dict, private_key: Path, key_id: str) -> str:
    header = b64(canonical({"alg": "EdDSA", "kid": key_id, "typ": "atb-action+jwt"}))
    payload = b64(canonical(claims))
    signing_input = f"{header}.{payload}".encode()
    return f"{header}.{payload}.{b64(sign(signing_input, private_key))}"


def file_digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--mandate-file", type=Path, required=True)
    parser.add_argument("--executor-credential-file", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--action", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--body", default="{}")
    args = parser.parse_args()

    mandate = args.mandate_file.read_text().strip()
    executor_credential = args.executor_credential_file.read_text().strip()
    body = json.loads(args.body)
    statement = {
        "request_id": args.request_id,
        "mandate_digest": file_digest(mandate),
        "executor_credential_digest": file_digest(executor_credential),
        "audience": args.audience,
        "resource": args.resource,
        "action": args.action,
        "target": args.target,
        "body_digest": "sha256:" + hashlib.sha256(canonical(body)).hexdigest(),
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    request_body = canonical({
        "statement": statement,
        "proof": compact_jws(statement, args.private_key, args.key_id),
        "body": body,
    })
    request = urllib.request.Request(
        args.gateway,
        data=request_body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Mandate": mandate,
            "Executor-Credential": executor_credential,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            output = {"status": response.status, "body": json.load(response)}
    except urllib.error.HTTPError as error:
        output = {"status": error.code, "body": json.load(error)}
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
