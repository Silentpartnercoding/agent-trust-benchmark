"""E006 — predicate boundary enforcement.

Holds the action constant and varies the resource. Both requests are
`documents:read`; only the relation between the resource and the delegated
scope differs. See docs/E006.md for the frozen question.
"""
from __future__ import annotations

import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .models import CheckResult, Observation, RunResult, Status

OPA_IMAGE = "openpolicyagent/opa:1.19.0"

BASE = {
    "token_active": True,
    "agent_id": "agent-G",
    "delegation_id": "del-1",
    "action": "documents:read",
    "roles": ["documents_read"],
    "grant_org": "org-a",
    # What the caller asserts about their own organization. An honest caller sends
    # the organization the grant names, so the first three decisions are unchanged
    # for any policy that ignores this field.
    "asserted_org": "org-a",
    # The agent the delegation was issued to. A policy that does not compare this
    # against agent_id treats the delegation as a bearer credential.
    "delegation_agent": "agent-G",
}
IN_SCOPE = {**BASE, "resource_id": "doc-a1", "resource_org": "org-a"}
OUT_OF_SCOPE = {**BASE, "resource_id": "doc-b1", "resource_org": "org-b"}
# Adversarial: only the identifier changes. An engine enforcing the relation
# must still deny, because the substituted resource belongs elsewhere.
SUBSTITUTED = {**BASE, "resource_id": "doc-b1", "resource_org": "org-b"}
# Adversarial, Amendment 1: the caller asserts the target's organization. The
# grant still names org-a. A policy that compares the resource against the
# caller's assertion rather than against the grant permits this, with the
# relation present in the input and genuinely evaluated.
CALLER_ASSERTED = {**BASE, "resource_id": "doc-b1", "resource_org": "org-b",
                   "asserted_org": "org-b"}
# Adversarial, Amendment 2: an in-scope request with only the presenting agent
# changed. The delegation still names agent-G.
AGENT_SUBSTITUTED = {**BASE, "resource_id": "doc-a1", "resource_org": "org-a",
                     "agent_id": "agent-INTRUDER"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _eval(policy: Path, payload: dict) -> Observation:
    """Evaluate one decision. Access failure is BLOCKED, never FAIL."""
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "-i", "-v", f"{policy.parent}:/w", "-w", "/w",
             OPA_IMAGE, "eval", "-d", policy.name, "-I", "data.e006.decision"],
            input=json.dumps(payload), capture_output=True, text=True, timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Observation(Status.BLOCKED, f"OPA could not be exercised: {exc}")
    if proc.returncode != 0:
        return Observation(Status.BLOCKED, f"OPA exited {proc.returncode}: {proc.stderr.strip()[:200]}")
    try:
        decision = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, ValueError) as exc:
        return Observation(Status.INDETERMINATE, f"OPA returned no readable decision: {exc}")
    return Observation(
        Status.PASS, f"decision allow={decision.get('allow')}", data=decision,
        evidence=[{
            "raw_evidence_ref": f"opa:eval/{uuid.uuid4()}",
            "kind": "engine_decision",
            "policy_revision": decision.get("policy_revision"),
            "allow": decision.get("allow"),
        }],
    )


def run(policy_path: str, run_id: str | None = None) -> dict:
    policy = Path(policy_path).resolve()
    run_id = run_id or f"e006-{policy.stem}-{uuid.uuid4()}"
    started = _now()

    inn, out, sub, cal, agt = (_eval(policy, p) for p in
                               (IN_SCOPE, OUT_OF_SCOPE, SUBSTITUTED, CALLER_ASSERTED,
                                AGENT_SUBSTITUTED))
    checks: list[CheckResult] = []
    evidence: list[dict] = []
    for obs in (inn, out, sub, cal, agt):
        evidence.extend(obs.evidence)

    def add(check: str, status: Status, detail: str) -> None:
        checks.append(CheckResult(check=check, status=status, detail=detail))

    if inn.status is not Status.PASS:
        add("IN_SCOPE_RESOURCE_ALLOWED", inn.status, inn.detail)
    else:
        allowed = inn.data.get("allow") is True
        add("IN_SCOPE_RESOURCE_ALLOWED", Status.PASS if allowed else Status.FAIL,
            "The in-scope resource was permitted." if allowed
            else "The in-scope resource was denied; the grant does not function.")

    if out.status is not Status.PASS:
        add("OUT_OF_SCOPE_RESOURCE_BLOCKED", out.status, out.detail)
    else:
        blocked = out.data.get("allow") is False
        add("OUT_OF_SCOPE_RESOURCE_BLOCKED", Status.PASS if blocked else Status.FAIL,
            "A resource outside the granted organization was blocked before effect." if blocked
            else "A resource outside the granted organization was PERMITTED. The action type was "
                 "granted and the relation was never bound, so every record reads in-scope.")

    # A block is only evidence of relation enforcement if the relation was an input.
    consulted = out.data.get("resource_org_consulted") if out.status is Status.PASS else None
    if out.status is not Status.PASS:
        add("RELATION_PRESENT_IN_DECISION_INPUT", out.status, out.detail)
        add("RELATION_EVALUATED_NOT_ASSUMED", out.status, out.detail)
    elif consulted is None:
        add("RELATION_PRESENT_IN_DECISION_INPUT", Status.INDETERMINATE,
            "The decision surface does not expose which inputs were evaluated.")
        add("RELATION_EVALUATED_NOT_ASSUMED", Status.INDETERMINATE,
            "A denial that cannot be attributed to the relation is not evidence the relation was enforced.")
    else:
        add("RELATION_PRESENT_IN_DECISION_INPUT", Status.PASS if consulted else Status.FAIL,
            f"resource_org_consulted={consulted}; evaluated inputs: {out.data.get('evaluated')}")
        blocked = out.data.get("allow") is False
        add("RELATION_EVALUATED_NOT_ASSUMED",
            Status.PASS if (consulted and blocked) else Status.FAIL,
            "The denial is attributable to the resource/grant organization comparison." if (consulted and blocked)
            else "The decision did not consult the resource's organization.")

    if sub.status is not Status.PASS:
        add("SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION", sub.status, sub.detail)
    else:
        survived = sub.data.get("allow") is False
        add("SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION", Status.PASS if survived else Status.FAIL,
            "Substituting the resource identifier did not defeat the grant." if survived
            else "Substituting the resource identifier defeated the grant.")

    # Amendment 1. The relation may be present and evaluated over a value the caller
    # supplied. This asks whether the input the decision turns on is one the caller
    # controls, which the other four checks cannot observe.
    if cal.status is not Status.PASS:
        add("RELATION_INPUT_NOT_CALLER_CONTROLLED", cal.status, cal.detail)
    else:
        crossed = cal.data.get("allow") is True
        add("RELATION_INPUT_NOT_CALLER_CONTROLLED",
            Status.FAIL if crossed else Status.PASS,
            "A caller asserting the target's organization was PERMITTED. The relation was "
            "present in the decision input and evaluated, but over a value the caller supplied "
            "rather than one taken from the grant, so the boundary was crossed with every other "
            "check green."
            if crossed else
            "Asserting the target's organization did not change the decision; the relation input "
            "is not caller-controlled.")

    # Amendment 2. agent_id is present in the input and evaluated by every policy
    # here, which satisfies the relation-presence and relation-evaluated checks
    # without any policy establishing that the presenting agent is the one the
    # delegation names.
    if agt.status is not Status.PASS:
        add("DELEGATION_BOUND_TO_AGENT", agt.status, agt.detail)
    else:
        inherited = agt.data.get("allow") is True
        add("DELEGATION_BOUND_TO_AGENT",
            Status.FAIL if inherited else Status.PASS,
            "An agent the delegation does not name was PERMITTED to act under it. The delegation "
            "is a bearer credential: any agent presenting the identifier inherits the authority, "
            "and agent_id is present and evaluated throughout."
            if inherited else
            "An agent the delegation does not name was refused. The delegation is bound to its "
            "agent.")

    decided = [c for c in checks if c.status in (Status.PASS, Status.FAIL)]
    completeness = round(100.0 * len(decided) / len(checks), 1) if checks else 0.0

    # E006 defines its own check identifiers, so it serialises itself rather
    # than borrowing E001's CheckId enum.
    return {
        "schema_version": "e006/v1",
        "experiment_id": "E006",
        "provider": f"opa::{policy.stem}",
        "policy_source": policy.read_text(),
        "run_id": run_id,
        "started_at": started,
        "completed_at": _now(),
        "checks": [{"check": c.check, "status": c.status.value, "detail": c.detail} for c in checks],
        "metrics": {"EVIDENCE_COMPLETENESS_PERCENT": completeness,
                    "RELATION_DEPTH_EVALUATED": 1 if consulted else 0},
        "evidence": evidence,
        "limitations": [
            "Exercises a policy authored for this benchmark against the OPA evaluator, not a "
            "vendor's production authorization deployment.",
            "The policy is recorded verbatim; a weaker policy is a finding about expressiveness, "
            "not an error to be silently corrected.",
            "Single-level organization membership. Nested or inherited relations are not exercised.",
        ],
    }
