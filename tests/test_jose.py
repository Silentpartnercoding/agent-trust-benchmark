from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_trust_benchmark.jose import (
    generate_ed25519_keypair,
    public_jwk_thumbprint,
    sign_action_proof,
    sign_compact_jws,
    sign_detached_jws,
    verify_action_proof,
    verify_compact_jws,
    verify_detached_jws,
)


class JoseTests(unittest.TestCase):
    def test_ed25519_detached_and_compact_jws_and_action_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key, public_key = generate_ed25519_keypair(Path(directory), "fixture")
            self.assertTrue(public_jwk_thumbprint(public_key))

            payload = b'{"hello":"world"}'
            detached = sign_detached_jws(payload, private_key, "issuer-key")
            self.assertTrue(verify_detached_jws(payload, detached, public_key, expected_kid="issuer-key"))
            self.assertFalse(verify_detached_jws(b'{"hello":"attacker"}', detached, public_key, expected_kid="issuer-key"))

            compact = sign_compact_jws({"sub": "agent"}, private_key, "issuer-key", "at+jwt")
            self.assertEqual(
                verify_compact_jws(compact, public_key, expected_kid="issuer-key", expected_typ="at+jwt"),
                {"sub": "agent"},
            )
            self.assertIsNone(verify_compact_jws(compact, public_key, expected_kid="wrong-key", expected_typ="at+jwt"))

            statement = {"nonce": "challenge", "target": "payments"}
            proof = sign_action_proof(statement, private_key)
            self.assertTrue(verify_action_proof(statement, proof, public_key))
            self.assertFalse(verify_action_proof({"nonce": "other", "target": "payments"}, proof, public_key))


if __name__ == "__main__":
    unittest.main()
