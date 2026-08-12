import os
import unittest
from unittest.mock import patch

from agent_trust_benchmark.experiment import run_e001
from agent_trust_benchmark.models import Status


class ProviderBoundaryTests(unittest.TestCase):
    @patch.dict(os.environ, {}, clear=True)
    def test_okta_is_blocked_without_external_access(self):
        result = run_e001("okta", "test-okta-blocked")
        self.assertTrue(all(check.status is Status.BLOCKED for check in result.checks))
        self.assertEqual(result.evidence, [])

    @patch.dict(os.environ, {}, clear=True)
    def test_entra_is_blocked_without_external_access(self):
        result = run_e001("entra", "test-entra-blocked")
        self.assertTrue(all(check.status is Status.BLOCKED for check in result.checks))
        self.assertEqual(result.evidence, [])

    def test_result_never_contains_common_secret_fields(self):
        serialized = str(run_e001("baseline", "test-no-secrets").to_dict()).lower()
        for forbidden in ("private_key", "client_secret", "access_token"):
            self.assertNotIn(forbidden, serialized)

    def test_normalized_events_have_required_public_fields(self):
        result = run_e001("baseline", "test-event-shape")
        required = {
            "schema_version", "provider", "experiment_id", "run_id",
            "event_type", "observed_at", "evidence_origin", "raw_evidence_ref",
        }
        for event in result.evidence:
            self.assertTrue(required.issubset(event))


if __name__ == "__main__":
    unittest.main()
