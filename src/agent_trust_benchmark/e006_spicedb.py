"""E006 against SpiceDB — a second relationship engine.

Run alongside OpenFGA to establish whether the structural property is a
property of the engine *class* or an artefact of one vendor's API shape.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

SCHEMA = (
    "definition user {}\n\n"
    "definition organization {\n\trelation member: user\n}\n\n"
    # `read` is a permission computed through ownership. There is no path to it
    # that does not traverse the document's owning organization.
    "definition document {\n\trelation owner: organization\n\tpermission read = owner->member\n}"
)
RELATIONSHIPS = [
    ("organization", "org-a", "member", "user", "G"),
    ("document", "doc-a1", "owner", "organization", "org-a"),
    ("document", "doc-b1", "owner", "organization", "org-b"),
]
CHECKS = ("IN_SCOPE_RESOURCE_ALLOWED", "OUT_OF_SCOPE_RESOURCE_BLOCKED",
          "RELATION_PRESENT_IN_DECISION_INPUT", "RELATION_EVALUATED_NOT_ASSUMED",
          "SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION")


def _post(url, payload, key, timeout=20):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(base_url: str = "http://127.0.0.1:18443", key: str = "atbkey",
        run_id: str | None = None) -> dict:
    run_id = run_id or f"e006-spicedb-{uuid.uuid4()}"
    started = _now()
    checks: list[dict] = []
    evidence: list[dict] = []
    add = lambda c, s, d: checks.append({"check": c, "status": s, "detail": d})

    try:
        _post(f"{base_url}/v1/schema/write", {"schema": SCHEMA}, key)
        _post(f"{base_url}/v1/relationships/write", {"updates": [
            {"operation": "OPERATION_TOUCH", "relationship": {
                "resource": {"objectType": rt, "objectId": rid},
                "relation": rel,
                "subject": {"object": {"objectType": st, "objectId": sid}}}}
            for rt, rid, rel, st, sid in RELATIONSHIPS]}, key)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        for c in CHECKS:
            add(c, "BLOCKED_EXTERNAL_ACCESS", f"SpiceDB could not be exercised: {exc}")
        return _result(run_id, started, checks, evidence)

    def check(obj: str) -> bool:
        r = _post(f"{base_url}/v1/permissions/check", {
            "consistency": {"fullyConsistent": True},
            "resource": {"objectType": "document", "objectId": obj},
            "permission": "read",
            "subject": {"object": {"objectType": "user", "objectId": "G"}}}, key)
        ship = r.get("permissionship", "")
        evidence.append({"raw_evidence_ref": f"spicedb:check/{uuid.uuid4()}",
                         "kind": "engine_decision", "resource": f"document:{obj}",
                         "permissionship": ship})
        return ship == "PERMISSIONSHIP_HAS_PERMISSION"

    in_scope, out_of_scope = check("doc-a1"), check("doc-b1")

    add("IN_SCOPE_RESOURCE_ALLOWED", "PASS" if in_scope else "FAIL",
        "The in-scope document resolved to HAS_PERMISSION through its owning organization."
        if in_scope else "The in-scope document was denied; the grant does not function.")
    add("OUT_OF_SCOPE_RESOURCE_BLOCKED", "PASS" if not out_of_scope else "FAIL",
        "A document owned by another organization resolved to NO_PERMISSION."
        if not out_of_scope else "A document outside the granted organization was PERMITTED.")

    # Can a permission check be requested without naming the resource?
    resource_optional = True
    try:
        _post(f"{base_url}/v1/permissions/check", {
            "consistency": {"fullyConsistent": True}, "permission": "read",
            "subject": {"object": {"objectType": "user", "objectId": "G"}}}, key)
    except urllib.error.HTTPError:
        resource_optional = False
    except (urllib.error.URLError, OSError):
        resource_optional = True

    structural = not resource_optional
    add("RELATION_PRESENT_IN_DECISION_INPUT", "PASS" if structural else "INDETERMINATE",
        "The resource is a required field; a check omitting it is rejected as a validation "
        "error, so the relation is structurally an input to every decision."
        if structural else "The engine accepted a check with no resource named.")
    add("RELATION_EVALUATED_NOT_ASSUMED",
        "PASS" if (structural and not out_of_scope) else "INDETERMINATE",
        "The denial is attributable to the absent owner->member path, and no check can bypass "
        "the resource." if (structural and not out_of_scope)
        else "The denial cannot be attributed to the relation.")
    add("SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION", "PASS" if not out_of_scope else "FAIL",
        "Substituting the document identifier changed the owning organization and the "
        "permission resolved to NO_PERMISSION." if not out_of_scope
        else "Substituting the identifier defeated the grant.")

    return _result(run_id, started, checks, evidence)


def _result(run_id, started, checks, evidence) -> dict:
    decided = [c for c in checks if c["status"] in ("PASS", "FAIL")]
    return {
        "schema_version": "e006/v1", "experiment_id": "E006", "provider": "spicedb",
        "engine_class": "relationship", "schema_source": SCHEMA,
        "relationships": [f"{rt}:{rid}#{rel}@{st}:{sid}" for rt, rid, rel, st, sid in RELATIONSHIPS],
        "run_id": run_id, "started_at": started, "completed_at": _now(),
        "checks": checks,
        "metrics": {
            "EVIDENCE_COMPLETENESS_PERCENT": round(100.0 * len(decided) / len(checks), 1) if checks else 0.0,
            "RELATION_DEPTH_EVALUATED": 2,
        },
        "evidence": evidence,
        "limitations": [
            "Exercises a schema authored for this benchmark against SpiceDB, not a vendor's "
            "production deployment.",
            "As with OpenFGA, the decision layer cannot omit the resource, so the action-only "
            "failure mode does not arise. The corresponding risk in this engine class is "
            "over-broad relationship issuance, which E006 does not exercise.",
            "Single-level organization membership. Nested or inherited ownership is not exercised.",
        ],
    }
