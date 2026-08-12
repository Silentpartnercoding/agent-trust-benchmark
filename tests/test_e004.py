import unittest

from agent_trust_benchmark.e004 import run_e004


class E004Tests(unittest.TestCase):
    def test_cross_runtime_delegation_matrix(self):
        result = run_e004()
        self.assertEqual(result["passed"], result["total"])
        self.assertEqual(len(result["resource_effects"]), 1)
        self.assertEqual(result["resource_effects"][0]["action"], "create_page")
        self.assertFalse(result["foreign_agent"]["proprietary_sdk"])


if __name__ == "__main__":
    unittest.main()
