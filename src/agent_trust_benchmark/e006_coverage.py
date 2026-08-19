"""E006 Amendment 3: what the suite can detect the absence of.

For each condition in a reference policy's `allow` rule, generate a variant with
that single condition removed and run the full E006 check suite against it. A
condition is covered if at least one check moves to FAIL; undetected if every
check still passes.

This measures what the suite is entitled to claim it verifies. It cannot find a
property absent from the reference policy altogether — mutation coverage sees only
the removal of conditions that were written. Amendments 1 and 2 were both the other
case, and neither would have been caught here.
"""
from __future__ import annotations

import json
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .e006 import run


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conditions(policy_text: str) -> list[tuple[int, str]]:
    """Line numbers and text of the conditions inside the allow rule."""
    lines = policy_text.splitlines()
    out: list[tuple[int, str]] = []
    inside = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^allow\s+if\s*\{", stripped):
            inside = True
            continue
        if inside:
            if stripped == "}":
                break
            if stripped and not stripped.startswith("#"):
                out.append((i, stripped))
    return out


# An undetected condition is not automatically a defect, and reporting a bare
# coverage percentage without saying which kind each one is would overstate the
# problem. Classification is declared here rather than inferred, so it is
# auditable and so adding a condition forces a decision about it.
#
#   substantive    the condition enforces a security property the suite claims to
#                  verify, and its removal is genuinely undetected
#   by-design      the axis belongs to a different experiment and is fixed here
#   defensive      a non-emptiness or well-formedness guard over a value no input
#                  malforms; testing it is a judgement call, not an omission
CLASSIFICATION = {
    "input.token_active == true": "substantive",
    '"documents_read" in input.roles': "substantive",
    'input.action == "documents:read"': "by-design",
    'input.agent_id != ""': "defensive",
    'input.delegation_id != ""': "defensive",
    'input.resource_org != ""': "defensive",
}


def run_coverage(policy_path: str, run_id: str | None = None) -> dict:
    policy = Path(policy_path).resolve()
    run_id = run_id or f"e006-coverage-{policy.stem}-{uuid.uuid4()}"
    started = _now()
    text = policy.read_text()
    conds = _conditions(text)

    baseline = run(str(policy), run_id=f"{run_id}-baseline")
    baseline_fail = {c["check"] for c in baseline["checks"] if c["status"] == "FAIL"}

    rows = []
    lines = text.splitlines()
    for idx, cond in conds:
        variant = "\n".join(lines[:idx] + lines[idx + 1:]) + "\n"
        with tempfile.TemporaryDirectory() as td:
            # The policy directory is mounted into the engine, so the variant is
            # written to its own directory rather than beside the original.
            vpath = Path(td) / f"{policy.stem}-mutant.rego"
            vpath.write_text(variant)
            res = run(str(vpath), run_id=f"{run_id}-mut-{idx}")
        newly_failing = sorted(
            {c["check"] for c in res["checks"] if c["status"] == "FAIL"} - baseline_fail)
        blocked = [c["check"] for c in res["checks"] if c["status"].startswith("BLOCKED")]
        rows.append({
            "condition": cond,
            "line": idx + 1,
            "detected_by": newly_failing,
            "covered": bool(newly_failing),
            "classification": (None if newly_failing
                               else CLASSIFICATION.get(cond, "UNCLASSIFIED")),
            "blocked_checks": blocked,
        })

    covered = [r for r in rows if r["covered"]]
    substantive = [r for r in rows if r.get("classification") == "substantive"]
    unclassified = [r for r in rows if r.get("classification") == "UNCLASSIFIED"]
    return {
        "schema_version": "e006-coverage/v1",
        "experiment_id": "E006",
        "amendment": 3,
        "reference_policy": policy.name,
        "policy_source": text,
        "run_id": run_id,
        "started_at": started,
        "completed_at": _now(),
        "baseline_failing_checks": sorted(baseline_fail),
        "conditions": rows,
        "metrics": {
            "CONDITIONS_TOTAL": len(rows),
            "CONDITIONS_COVERED": len(covered),
            "CONDITION_COVERAGE_PERCENT": (
                round(100.0 * len(covered) / len(rows), 1) if rows else 0.0),
            "SUBSTANTIVE_GAPS": len(substantive),
            "UNCLASSIFIED_CONDITIONS": len(unclassified),
        },
        "substantive_gaps": [r["condition"] for r in substantive],
        "limitations": [
            "Mutation coverage reports which conditions present in the reference policy the "
            "suite detects the removal of. A property nobody wrote into the policy is invisible "
            "to it; both earlier amendments were that case.",
            "One condition is removed at a time. Interactions between two simultaneously absent "
            "conditions are not exercised.",
            "An undetected condition is not necessarily a defect, so CONDITION_COVERAGE_PERCENT "
            "must not be read alone. Each undetected condition is classified as substantive, "
            "by-design or defensive, and SUBSTANTIVE_GAPS is the number that represents a "
            "property this suite claims to verify and does not.",
            "This measures the benchmark's own fixtures. It is internal quality control and says "
            "nothing about how often any of these conditions are omitted in deployed systems. No "
            "result here is evidence about the world.",
        ],
    }
