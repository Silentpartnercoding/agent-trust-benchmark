import os
import unittest

from agent_trust_benchmark.experiment import run_e001
from agent_trust_benchmark.models import Status


@unittest.skipUnless(os.environ.get("ATB_RUN_CONTAINER_INTEGRATION") == "1", "container integration is opt-in")
class KeycloakOpaIntegrationTests(unittest.TestCase):
    def test_e001_composed_control(self):
        result = run_e001("keycloak-opa", "test-keycloak-opa")
        statuses = {check.check.value: check.status for check in result.checks}
        self.assertIs(statuses["DISTINCT_AGENT_IDENTITY"], Status.PASS)
        self.assertIs(statuses["SCOPE_VISIBLE"], Status.PASS)
        self.assertIs(statuses["ALLOWED_ACTION_SUCCEEDS"], Status.PASS)
        self.assertIs(statuses["FORBIDDEN_ACTION_BLOCKED"], Status.PASS)
        self.assertIs(statuses["ACTION_AUDITABLE"], Status.PASS)
        self.assertIs(statuses["POST_REVOCATION_ACTION_BLOCKED"], Status.PASS)


if __name__ == "__main__":
    unittest.main()
