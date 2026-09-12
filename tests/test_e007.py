import json
import tempfile
import unittest
from pathlib import Path

from agent_trust_benchmark.e007 import (
    COMPLETE_ARRANGEMENTS,
    EXPECTED_FAILURES,
    run_e007,
    write_e007,
)


class E007Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_e007()
        cls.by_name = {item["arrangement"]: item for item in cls.result["arrangements"]}

    def test_matrix_matches_preregistered_predictions(self):
        self.assertEqual(self.result["classification"], "SUPPORTED")
        self.assertTrue(self.result["instrument"]["predictions_matched"])
        self.assertTrue(self.result["instrument"]["complete_controls_passed"])
        self.assertEqual(set(self.by_name), set(EXPECTED_FAILURES))
        for name, expected in EXPECTED_FAILURES.items():
            self.assertEqual(set(self.by_name[name]["actual_failures"]), expected)

    def test_complete_controls_guard_every_path_without_default_deny(self):
        for name in COMPLETE_ARRANGEMENTS:
            arrangement = self.by_name[name]
            self.assertEqual(arrangement["actual_failures"], [])
            self.assertTrue(
                all(
                    request["status"] == 200 and request["effect_delta"] == 1
                    for request in arrangement["requests"]["entitled"]
                )
            )

    def test_resource_organization_is_loaded_from_the_fixed_object_store(self):
        for arrangement in self.result["arrangements"]:
            self.assertEqual(
                arrangement["direct_policy_decision"]["resource_org_source"],
                "object_store",
            )
            self.assertTrue(arrangement["guard_invocations"])
            self.assertTrue(
                all(
                    invocation["resource_org"] == "org-b"
                    for invocation in arrangement["guard_invocations"]
                )
            )

    def test_incomplete_wiring_has_the_frozen_effect_shape(self):
        verb = self.by_name["verb-asymmetric"]
        verb_outcomes = {
            item["label"]: (item["status"], item["effect_delta"])
            for item in verb["requests"]["out_of_scope"]
        }
        self.assertEqual(
            verb_outcomes,
            {"read": (200, 1), "write": (403, 0), "alias": (200, 1)},
        )
        for name in ("router-late-bypass", "middleware-late-bypass"):
            outcomes = {
                item["label"]: (item["status"], item["effect_delta"])
                for item in self.by_name[name]["requests"]["out_of_scope"]
            }
            self.assertEqual(
                outcomes,
                {"read": (403, 0), "write": (403, 0), "alias": (200, 1)},
            )

    def test_late_route_is_separate_later_and_reuses_read_handler(self):
        for arrangement in self.result["arrangements"]:
            inventory = arrangement["route_inventory"]
            canonical = next(
                route
                for route in inventory
                if route["method"] == "GET" and route["path"] == "/documents/doc-b1"
            )
            alias = next(
                route for route in inventory if route["path"].startswith("/legacy/")
            )
            self.assertGreater(
                alias["registration_order"], canonical["registration_order"]
            )
            self.assertNotEqual(
                alias["registration_module"], canonical["registration_module"]
            )
            self.assertEqual(alias["handler_slot"], canonical["handler_slot"])

    def test_writer_records_machine_and_human_results(self):
        with tempfile.TemporaryDirectory(prefix="atb-e007-test-") as directory:
            json_path, summary_path = write_e007(Path(directory))
            written = json.loads(json_path.read_text())
            self.assertEqual(written["classification"], "SUPPORTED")
            self.assertIn("Preregistration commit", summary_path.read_text())


if __name__ == "__main__":
    unittest.main()
