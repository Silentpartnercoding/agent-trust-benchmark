import unittest

from agent_trust_benchmark.e005 import run_e005


class E005Tests(unittest.TestCase):
    def test_cross_runtime_mandate_matrix(self):
        result = run_e005()
        self.assertEqual(result["passed"], result["total"])
        self.assertEqual(len(result["resource_effects"]), 1)
        self.assertEqual(result["resource_effects"][0]["action"], "archive_page")
        self.assertEqual(result["resource_effects"][0]["target"], "notion:page:123")
        self.assertFalse(result["foreign_agent"]["proprietary_sdk"])
        self.assertFalse(result["foreign_agent"]["mandate_parsing"])
        self.assertFalse(result["foreign_agent"]["executor_credential_parsing"])


if __name__ == "__main__":
    unittest.main()
