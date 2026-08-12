from __future__ import annotations

import os
import unittest

from agent_trust_benchmark.experiment import run_e001
from agent_trust_benchmark.models import CheckId, Status


@unittest.skipUnless(os.environ.get("ATB_RUN_ZITADEL") == "1", "requires the local ZITADEL + OPA fixture")
class ZitadelOpaIntegrationTest(unittest.TestCase):
    def test_e001_exposes_the_human_binding_limit(self) -> None:
        result = run_e001("zitadel-opa")
        checks = {check.check: check for check in result.checks}
        self.assertEqual(checks[CheckId.HUMAN_ATTRIBUTION_PROVABLE].status, Status.FAIL)
        for check_id, check in checks.items():
            if check_id != CheckId.HUMAN_ATTRIBUTION_PROVABLE:
                self.assertEqual(check.status, Status.PASS, check.detail)


if __name__ == "__main__":
    unittest.main()
