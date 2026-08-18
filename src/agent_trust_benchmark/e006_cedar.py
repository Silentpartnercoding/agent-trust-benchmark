"""E006 against Cedar — a second policy engine.

Cedar separates two things that Rego conflates, and the separation matters.
A Cedar *request* always carries principal, action and resource, so the resource
is structurally present. But a Cedar *policy* need not consult it: an unscoped
`permit(principal == .., action == .., resource)` grants the action over every
resource. Present is not the same as evaluated, and E006 reports them apart.
"""
from __future__ import annotations

import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

CEDAR = os.environ.get("ATB_CEDAR_BIN", str(Path.home() / ".cargo/bin/cedar"))
CHECKS = ("IN_SCOPE_RESOURCE_ALLOWED", "OUT_OF_SCOPE_RESOURCE_BLOCKED",
          "RELATION_PRESENT_IN_DECISION_INPUT", "RELATION_EVALUATED_NOT_ASSUMED",
          "SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _authorize(policy: Path, entities: Path, resource: str):
    """Return (allowed, raw) or (None, error) if Cedar could not be exercised."""
    try:
        proc = subprocess.run(
            [CEDAR, "authorize", "--policies", str(policy), "--entities", str(entities),
             "--principal", 'User::"G"', "--action", 'Action::"read"',
             "--resource", f'Document::"{resource}"'],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    out = (proc.stdout + proc.stderr).strip()
    if "ALLOW" in out.upper():
        return True, out
    if "DENY" in out.upper():
        return False, out
    return None, out


def run(policy_path: str, entities_path: str, run_id: str | None = None) -> dict:
    policy, entities = Path(policy_path).resolve(), Path(entities_path).resolve()
    run_id = run_id or f"e006-{policy.stem}-{uuid.uuid4()}"
    started = _now()
    checks: list[dict] = []
    evidence: list[dict] = []
    add = lambda c, s, d: checks.append({"check": c, "status": s, "detail": d})

    in_allowed, in_raw = _authorize(policy, entities, "doc-a1")
    out_allowed, out_raw = _authorize(policy, entities, "doc-b1")

    if in_allowed is None or out_allowed is None:
        for c in CHECKS:
            add(c, "BLOCKED_EXTERNAL_ACCESS",
                f"Cedar could not be exercised: {in_raw if in_allowed is None else out_raw}")
        return _result(run_id, started, policy, checks, evidence)

    for res, allowed in (("doc-a1", in_allowed), ("doc-b1", out_allowed)):
        evidence.append({"raw_evidence_ref": f"cedar:authorize/{uuid.uuid4()}",
                         "kind": "engine_decision", "resource": f'Document::"{res}"',
                         "decision": "ALLOW" if allowed else "DENY"})

    add("IN_SCOPE_RESOURCE_ALLOWED", "PASS" if in_allowed else "FAIL",
        "The in-scope document was permitted." if in_allowed
        else "The in-scope document was denied; the grant does not function.")
    add("OUT_OF_SCOPE_RESOURCE_BLOCKED", "PASS" if not out_allowed else "FAIL",
        "A document owned by another organization was denied." if not out_allowed
        else "A document outside the granted organization was PERMITTED. The action was "
             "constrained and the resource was not, so the owning organization was never consulted.")

    # A Cedar request always names a resource, whatever the policy does with it.
    add("RELATION_PRESENT_IN_DECISION_INPUT", "PASS",
        "Every Cedar request carries principal, action and resource, so the resource is "
        "structurally present in the decision input regardless of the policy.")

    # Behavioural, not static: if changing only the resource changes the decision,
    # the relation was evaluated. If it does not, the policy ignored it.
    evaluated = in_allowed and not out_allowed
    add("RELATION_EVALUATED_NOT_ASSUMED", "PASS" if evaluated else "FAIL",
        "Changing only the resource changed the decision, so the owning organization was "
        "evaluated rather than assumed." if evaluated
        else "Changing only the resource did not change the decision. The resource was present "
             "in the request but the policy did not consult it.")

    add("SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION", "PASS" if not out_allowed else "FAIL",
        "Substituting the document identifier did not defeat the grant." if not out_allowed
        else "Substituting the document identifier defeated the grant.")

    return _result(run_id, started, policy, checks, evidence)


def _result(run_id, started, policy, checks, evidence) -> dict:
    decided = [c for c in checks if c["status"] in ("PASS", "FAIL")]
    return {
        "schema_version": "e006/v1", "experiment_id": "E006",
        "provider": f"cedar::{policy.stem.replace('cedar-', '')}",
        "engine_class": "policy",
        "policy_source": policy.read_text() if policy.exists() else None,
        "run_id": run_id, "started_at": started, "completed_at": _now(),
        "checks": checks,
        "metrics": {
            "EVIDENCE_COMPLETENESS_PERCENT": round(100.0 * len(decided) / len(checks), 1) if checks else 0.0,
            "RELATION_DEPTH_EVALUATED": 1,
        },
        "evidence": evidence,
        "limitations": [
            "Exercises a policy authored for this benchmark against the Cedar CLI, not a "
            "vendor's production deployment.",
            "Cedar's request shape always includes a resource, so RELATION_PRESENT_IN_DECISION_INPUT "
            "passes even where the policy ignores it. RELATION_EVALUATED_NOT_ASSUMED is the check "
            "that separates the two, and it is decided behaviourally by substituting the resource.",
            "Single-level ownership via a resource attribute. Cedar entity hierarchies are not exercised.",
        ],
    }
