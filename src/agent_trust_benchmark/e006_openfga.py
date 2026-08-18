"""E006 against OpenFGA — a relationship engine.

The contrast with a policy engine is the point. In Rego, "check the action and
ignore the resource" is a policy someone can write. In OpenFGA the resource is a
required parameter of every check, so the same mistake cannot be expressed at
the decision layer at all. Where that holds, the pass is *structural* rather
than a property of how a policy happened to be authored.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

MODEL = {
    "schema_version": "1.1",
    "type_definitions": [
        {"type": "user"},
        {"type": "organization", "relations": {"member": {"this": {}}},
         "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}},
        {"type": "document",
         "relations": {
             "owner": {"this": {}},
             # A document's reader is derived from membership of its owning
             # organization. The relation is the grant; there is no path that
             # reaches `reader` without traversing `owner`.
             "reader": {"tupleToUserset": {"tupleset": {"relation": "owner"},
                                           "computedUserset": {"relation": "member"}}}},
         "metadata": {"relations": {
             "owner": {"directly_related_user_types": [{"type": "organization"}]},
             "reader": {"directly_related_user_types": []}}}},
    ],
}
TUPLES = [
    {"user": "user:G", "relation": "member", "object": "organization:org-a"},
    {"user": "organization:org-a", "relation": "owner", "object": "document:doc-a1"},
    {"user": "organization:org-b", "relation": "owner", "object": "document:doc-b1"},
]


def _post(url: str, payload: dict, timeout: int = 20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run(base_url: str = "http://127.0.0.1:18090", run_id: str | None = None) -> dict:
    run_id = run_id or f"e006-openfga-{uuid.uuid4()}"
    started = _now()
    checks: list[dict] = []
    evidence: list[dict] = []

    def add(check: str, status: str, detail: str) -> None:
        checks.append({"check": check, "status": status, "detail": detail})

    try:
        store = _post(f"{base_url}/stores", {"name": f"e006-{uuid.uuid4().hex[:8]}"})["id"]
        model = _post(f"{base_url}/stores/{store}/authorization-models", MODEL)["authorization_model_id"]
        _post(f"{base_url}/stores/{store}/write",
              {"authorization_model_id": model, "writes": {"tuple_keys": TUPLES}})
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        for c in ("IN_SCOPE_RESOURCE_ALLOWED", "OUT_OF_SCOPE_RESOURCE_BLOCKED",
                  "RELATION_PRESENT_IN_DECISION_INPUT", "RELATION_EVALUATED_NOT_ASSUMED",
                  "SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION"):
            add(c, "BLOCKED_EXTERNAL_ACCESS", f"OpenFGA could not be exercised: {exc}")
        return _result(run_id, started, checks, evidence, None)

    def check(obj: str) -> bool:
        r = _post(f"{base_url}/stores/{store}/check",
                  {"authorization_model_id": model,
                   "tuple_key": {"user": "user:G", "relation": "reader", "object": f"document:{obj}"}})
        evidence.append({"raw_evidence_ref": f"openfga:check/{uuid.uuid4()}",
                         "kind": "engine_decision", "object": f"document:{obj}",
                         "allowed": r.get("allowed", False)})
        return bool(r.get("allowed", False))

    in_scope = check("doc-a1")
    out_of_scope = check("doc-b1")

    add("IN_SCOPE_RESOURCE_ALLOWED", "PASS" if in_scope else "FAIL",
        "The in-scope resource was permitted via its owning organization."
        if in_scope else "The in-scope resource was denied; the grant does not function.")
    add("OUT_OF_SCOPE_RESOURCE_BLOCKED", "PASS" if not out_of_scope else "FAIL",
        "A document owned by an organization the agent is not a member of was denied."
        if not out_of_scope else "A document outside the granted organization was PERMITTED.")

    # Structural probe: can a decision omit the resource at all?
    resource_optional = True
    try:
        _post(f"{base_url}/stores/{store}/check",
              {"authorization_model_id": model,
               "tuple_key": {"user": "user:G", "relation": "reader", "object": ""}})
    except urllib.error.HTTPError:
        resource_optional = False
    except (urllib.error.URLError, OSError):
        resource_optional = True

    add("RELATION_PRESENT_IN_DECISION_INPUT", "PASS" if not resource_optional else "INDETERMINATE",
        "The object is a required parameter of every check; a decision cannot be requested "
        "without naming the resource, so the relation is structurally an input."
        if not resource_optional else "The engine accepted a decision request with no resource named.")
    add("RELATION_EVALUATED_NOT_ASSUMED",
        "PASS" if (not resource_optional and not out_of_scope) else "INDETERMINATE",
        "The denial is attributable to the absent owner->member path, and no decision can bypass "
        "the resource." if (not resource_optional and not out_of_scope)
        else "The denial cannot be attributed to the relation.")
    add("SCOPE_SURVIVES_IDENTIFIER_SUBSTITUTION", "PASS" if not out_of_scope else "FAIL",
        "Substituting the document identifier changed the owning organization and the decision "
        "flipped to deny." if not out_of_scope else "Substituting the identifier defeated the grant.")

    return _result(run_id, started, checks, evidence, resource_optional)


def _result(run_id, started, checks, evidence, resource_optional) -> dict:
    decided = [c for c in checks if c["status"] in ("PASS", "FAIL")]
    return {
        "schema_version": "e006/v1",
        "experiment_id": "E006",
        "provider": "openfga",
        "engine_class": "relationship",
        "model_source": json.dumps(MODEL, indent=2),
        "tuples": TUPLES,
        "run_id": run_id,
        "started_at": started,
        "completed_at": _now(),
        "checks": checks,
        "metrics": {
            "EVIDENCE_COMPLETENESS_PERCENT": round(100.0 * len(decided) / len(checks), 1) if checks else 0.0,
            "RELATION_DEPTH_EVALUATED": 2,  # document -> owner(organization) -> member(user)
        },
        "evidence": evidence,
        "limitations": [
            "Exercises an authorization model authored for this benchmark against OpenFGA, not a "
            "vendor's production deployment.",
            "In a relationship engine the decision layer cannot omit the resource, so the "
            "action-only failure mode E006 was designed to detect does not arise here. The "
            "corresponding risk in this engine class is over-broad tuple issuance — granting a "
            "relation more widely than intended — which E006 does not exercise.",
            "Single-level organization membership. Nested or inherited ownership is not exercised.",
        ],
    }
