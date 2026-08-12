import base64
import json
import unittest

from agent_trust_benchmark.adapters.baseline import BaselineAdapter
from agent_trust_benchmark.experiment import run_e001
from agent_trust_benchmark.models import Status


class BaselineTests(unittest.TestCase):
    def test_e001_baseline_passes_every_binary_check(self):
        result = run_e001("baseline", "test-baseline")
        self.assertTrue(all(check.status is Status.PASS for check in result.checks))
        self.assertEqual(result.metrics["TOKEN_LIFETIME_SECONDS"], 300)
        self.assertEqual(result.metrics["EVIDENCE_COMPLETENESS_PERCENT"], 100.0)
        self.assertIsNotNone(result.metrics["REVOCATION_LATENCY_MS"])

    def test_forbidden_action_has_zero_effect(self):
        adapter = BaselineAdapter("test-forbidden")
        adapter.create_human(); adapter.create_agent(); adapter.delegate(); adapter.issue_credential()
        outcome = adapter.execute_forbidden_action()
        self.assertTrue(outcome.data["blocked"])
        self.assertEqual(outcome.data["effect_count"], 0)

    def test_tampered_credential_is_rejected(self):
        adapter = BaselineAdapter("test-tamper")
        adapter.create_human(); adapter.create_agent(); adapter.delegate(); adapter.issue_credential()
        body, signature = adapter.token.split(".")
        adapter._inspect()
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        payload["scope"].append("payments:execute")
        changed = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        adapter.token = f"{changed}.{signature}"
        outcome = adapter.execute_forbidden_action()
        self.assertTrue(outcome.data["blocked"])
        self.assertEqual(outcome.data["effect_count"], 0)

    def test_normalized_evidence_is_deduplicated(self):
        result = run_e001("baseline", "test-evidence-dedup")
        refs = [event["raw_evidence_ref"] for event in result.evidence]
        self.assertEqual(len(refs), len(set(refs)))


if __name__ == "__main__":
    unittest.main()
