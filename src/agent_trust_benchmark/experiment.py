from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from .adapters import (
    BaselineAdapter,
    EntraAdapter,
    KeycloakOpaAdapter,
    OktaAdapter,
    ZitadelOpaAdapter,
)
from .adapters.base import ProviderAdapter
from .models import CheckId, CheckResult, Observation, RunResult, Status


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


ADAPTERS: dict[str, type[ProviderAdapter]] = {
    "baseline": BaselineAdapter,
    "keycloak-opa": KeycloakOpaAdapter,
    "zitadel-opa": ZitadelOpaAdapter,
    "okta": OktaAdapter,
    "entra": EntraAdapter,
}


def _refs(observation: Observation) -> list[str]:
    return [event["raw_evidence_ref"] for event in observation.evidence]


def _derived(
    check: CheckId,
    observation: Observation,
    predicate: Callable[[dict], bool],
    pass_detail: str,
    fail_detail: str,
) -> CheckResult:
    if observation.status not in {Status.PASS, Status.FAIL}:
        return CheckResult(check, observation.status, observation.detail, _refs(observation))
    passed = predicate(observation.data)
    return CheckResult(check, Status.PASS if passed else Status.FAIL, pass_detail if passed else fail_detail, _refs(observation))


def run_e001(provider: str, run_id: str | None = None) -> RunResult:
    if provider not in ADAPTERS:
        raise ValueError(f"unknown provider: {provider}")
    run_id = run_id or f"e001-{provider}-{uuid.uuid4()}"
    started_at = _iso()
    adapter = ADAPTERS[provider](run_id)
    observations: list[Observation] = []
    try:
        human = adapter.create_human(); observations.append(human)
        agent = adapter.create_agent(); observations.append(agent)
        delegation = adapter.delegate(); observations.append(delegation)
        credential = adapter.issue_credential(); observations.append(credential)
        inspection = adapter.inspect_credential(); observations.append(inspection)
        allowed = adapter.execute_allowed_action(); observations.append(allowed)
        forbidden = adapter.execute_forbidden_action(); observations.append(forbidden)
        audit = adapter.get_audit_events(); observations.append(audit)
        revoked = adapter.revoke(); observations.append(revoked)
        after_revocation = adapter.execute_after_revocation(); observations.append(after_revocation)

        checks = [
            _derived(CheckId.DISTINCT_AGENT_IDENTITY, agent, lambda d: bool(d.get("distinct")), "The agent has a distinct identity.", "A distinct agent identity was not proven."),
            _derived(CheckId.DELEGATION_PROVABLE, delegation, lambda d: bool(d.get("provable")), "The human-to-agent delegation is provable.", "The delegation is not provable."),
            _derived(CheckId.SCOPE_VISIBLE, inspection, lambda d: "payments:preview" in d.get("scopes", []) or "tool:payments:preview" in d.get("scopes", []), "The granted preview scope is visible.", "The preview scope is not visible."),
            _derived(CheckId.ALLOWED_ACTION_SUCCEEDS, allowed, lambda d: d.get("allowed") is True and d.get("effect_count") == 1, "The allowed action succeeded exactly once.", "The allowed action did not succeed exactly once."),
            _derived(CheckId.FORBIDDEN_ACTION_BLOCKED, forbidden, lambda d: d.get("blocked") is True and d.get("effect_count") == 0, "The forbidden action was blocked before effect.", "The forbidden action was not safely blocked."),
            _derived(CheckId.HUMAN_ATTRIBUTION_PROVABLE, audit, lambda d: d.get("human_attribution") is True, "The action is attributable to the human principal.", "Human attribution was not proven."),
            _derived(CheckId.AGENT_ATTRIBUTION_PROVABLE, allowed if allowed.data.get("agent_attribution") is True else audit, lambda d: d.get("agent_attribution") is True, "The action is attributable to the authenticated agent identity at the exercised enforcement point.", "Agent attribution was not proven."),
            _derived(CheckId.ACTION_AUDITABLE, audit, lambda d: d.get("auditable") is True, "The action can be reconstructed from audit evidence.", "The action is not fully auditable."),
            _derived(CheckId.REVOCATION_SUPPORTED, revoked, lambda d: d.get("supported") is True, "The credential or delegation can be revoked.", "Revocation is not supported."),
            _derived(CheckId.POST_REVOCATION_ACTION_BLOCKED, after_revocation, lambda d: d.get("blocked") is True and d.get("effect_count") == 0, "The action was blocked after revocation.", "The action was not proven blocked after revocation."),
        ]

        definitive = sum(check.status in {Status.PASS, Status.FAIL} for check in checks)
        evidence = adapter.normalize_evidence(observations)
        limitations: list[str] = []
        if provider in {"okta", "entra"}:
            limitations.append("No vendor behavior was tested because required external tenant access was unavailable.")
        if provider == "keycloak-opa":
            limitations.append("Keycloak supplies identity and token evidence; OPA is the benchmark-owned enforcement point.")
            limitations.append("The fixture grant is administrator-configured, not an interactive consent record.")
            limitations.append("The fixture uses Keycloak Direct Access Grants to bind the human subject and confidential agent client in one token; this is a measurement mechanism, not a production recommendation.")
            limitations.append("Revocation uses the realm-wide not-before boundary, so the proven block is broader than revoking only this one delegation.")
        if provider == "zitadel-opa":
            limitations.append("ZITADEL supplies identity, grant, token, introspection, and change-history evidence; OPA is the benchmark-owned enforcement point.")
            limitations.append("The human-to-agent link is administrator-authored metadata, not interactive consent or a human claim cryptographically bound into the action token.")
            limitations.append("The opaque token is long-lived; the fast post-revocation block depends on online introspection at every exercised action.")

        return RunResult(
            schema_version="0.1",
            experiment_id="e001",
            provider=provider,
            run_id=run_id,
            started_at=started_at,
            completed_at=_iso(),
            checks=checks,
            metrics={
                "REVOCATION_LATENCY_MS": after_revocation.data.get("revocation_latency_ms"),
                "TOKEN_LIFETIME_SECONDS": credential.data.get("token_lifetime_seconds"),
                "EVIDENCE_COMPLETENESS_PERCENT": round(100 * definitive / len(checks), 1),
            },
            evidence=evidence,
            limitations=limitations,
        )
    finally:
        adapter.cleanup()
