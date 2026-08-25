"""E007 — application enforcement-path coverage.

The policy is held correct and constant. Route, verb, and guard wiring vary.
See docs/E007.md and preregistration commit 717653f.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import e007_late_routes, e007_primary_routes

PREREGISTRATION_COMMIT = "717653f53e9b964026512bd3be5dc9ed5279c0f8"
OBJECT_ID = "doc-b1"
OBJECT_ORG = "org-b"
AGENT_ID = "agent-G"

CHECKS = (
    "POLICY_DENIES_OUT_OF_SCOPE_WHEN_CALLED",
    "OUT_OF_SCOPE_READ_BLOCKED_BEFORE_EFFECT",
    "OUT_OF_SCOPE_WRITE_BLOCKED_BEFORE_EFFECT",
    "OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT",
    "GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH",
    "ZERO_UNAUTHORIZED_EFFECTS",
    "ENTITLED_READ_ALLOWED",
    "ENTITLED_WRITE_ALLOWED",
    "ENTITLED_ALIAS_ALLOWED",
    "ROUTE_INVENTORY_COMPLETE",
    "LATE_REGISTRATION_COVERED",
)

COMPLETE_ARRANGEMENTS = {
    "router-complete",
    "middleware-complete",
    "decorator-complete",
    "handler-complete",
}

EXPECTED_FAILURES = {
    "router-complete": set(),
    "middleware-complete": set(),
    "decorator-complete": set(),
    "handler-complete": set(),
    "verb-asymmetric": {
        "OUT_OF_SCOPE_READ_BLOCKED_BEFORE_EFFECT",
        "OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT",
        "GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH",
        "ZERO_UNAUTHORIZED_EFFECTS",
        "LATE_REGISTRATION_COVERED",
    },
    "router-late-bypass": {
        "OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT",
        "GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH",
        "ZERO_UNAUTHORIZED_EFFECTS",
        "LATE_REGISTRATION_COVERED",
    },
    "middleware-late-bypass": {
        "OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT",
        "GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH",
        "ZERO_UNAUTHORIZED_EFFECTS",
        "LATE_REGISTRATION_COVERED",
    },
}


@dataclass(frozen=True)
class Request:
    request_id: str
    method: str
    path: str
    action: str
    grant_org: str
    resource_id: str = OBJECT_ID
    resource_org: str = OBJECT_ORG
    agent_id: str = AGENT_ID
    roles: tuple[str, ...] = ("documents:read", "documents:write")


@dataclass(frozen=True)
class Response:
    status: int
    decision: str
    reason: str


Handler = Callable[[Request], Response]


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    action: str
    handler: Handler
    handler_name: str
    handler_slot: int
    registration_module: str
    registration_order: int
    router_guarded: bool


class Policy:
    """One correct relation-aware policy, shared by every arrangement."""

    source = (
        "allow if action in roles and resource_org == grant_org; "
        "resource_org is loaded from the object store"
    )

    def evaluate(self, request: Request) -> dict[str, Any]:
        action_granted = request.action in request.roles
        relation_matches = request.resource_org == request.grant_org
        return {
            "allow": action_granted and relation_matches,
            "action_granted": action_granted,
            "relation_matches": relation_matches,
            "evaluated": ["action", "roles", "resource_org", "grant_org"],
            "resource_org_source": "object_store",
        }


class Guard:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self.invocations: list[dict[str, Any]] = []

    def authorize(self, request: Request, placement: str) -> Response | None:
        decision = self.policy.evaluate(request)
        self.invocations.append(
            {
                "request_id": request.request_id,
                "placement": placement,
                "action": request.action,
                "grant_org": request.grant_org,
                "resource_org": request.resource_org,
                "allow": decision["allow"],
                "evaluated": decision["evaluated"],
            }
        )
        if decision["allow"]:
            return None
        return Response(403, "deny", "resource outside delegated organization")


class State:
    def __init__(self) -> None:
        self.objects = {OBJECT_ID: {"org": OBJECT_ORG}}
        self.effects: list[dict[str, Any]] = []

    def resource_org(self, resource_id: str) -> str:
        return self.objects[resource_id]["org"]

    def effect(self, request: Request) -> Response:
        self.effects.append(
            {
                "request_id": request.request_id,
                "action": request.action,
                "resource_id": request.resource_id,
                "resource_org": request.resource_org,
                "grant_org": request.grant_org,
            }
        )
        return Response(200, "allow", "handler effect completed")


def _handler(state: State, guard: Guard | None = None) -> Handler:
    def handle(request: Request) -> Response:
        if guard is not None:
            denied = guard.authorize(request, "handler")
            if denied is not None:
                return denied
        return state.effect(request)

    return handle


def _decorated(handler: Handler, guard: Guard) -> Handler:
    def wrapped(request: Request) -> Response:
        denied = guard.authorize(request, "decorator")
        return denied if denied is not None else handler(request)

    return wrapped


class Application:
    def __init__(
        self,
        *,
        state: State,
        placement: str,
        guard: Guard,
        middleware_complete: bool = False,
    ) -> None:
        self.state = state
        self.placement = placement
        self.guard = guard
        self.middleware_complete = middleware_complete
        self.routes: list[Route] = []
        self._handler_slots: dict[int, int] = {}

    def add_route(
        self,
        method: str,
        path: str,
        action: str,
        handler: Handler,
        *,
        handler_name: str,
        registration_module: str,
        router_guarded: bool,
    ) -> None:
        object_id = id(handler)
        if object_id not in self._handler_slots:
            self._handler_slots[object_id] = len(self._handler_slots) + 1
        self.routes.append(
            Route(
                method=method,
                path=path,
                action=action,
                handler=handler,
                handler_name=handler_name,
                handler_slot=self._handler_slots[object_id],
                registration_module=registration_module,
                registration_order=len(self.routes) + 1,
                router_guarded=router_guarded,
            )
        )

    def dispatch(
        self,
        method: str,
        path: str,
        *,
        request_id: str,
        grant_org: str,
    ) -> Response:
        route = next(
            (
                candidate
                for candidate in self.routes
                if candidate.method == method and candidate.path == path
            ),
            None,
        )
        if route is None:
            return Response(404, "not_found", "route not registered")
        request = Request(
            request_id=request_id,
            method=method,
            path=path,
            action=route.action,
            grant_org=grant_org,
            resource_org=self.state.resource_org(OBJECT_ID),
        )
        if self.placement == "router" and route.router_guarded:
            denied = self.guard.authorize(request, "router")
            if denied is not None:
                return denied
        if self.placement == "middleware":
            covered = self.middleware_complete or path.startswith("/documents/")
            if covered:
                denied = self.guard.authorize(request, "middleware")
                if denied is not None:
                    return denied
        return route.handler(request)

    def inventory(self) -> list[dict[str, Any]]:
        return [
            {
                "method": route.method,
                "path": route.path,
                "action": route.action,
                "handler": route.handler_name,
                "handler_slot": route.handler_slot,
                "registration_module": route.registration_module,
                "registration_order": route.registration_order,
                "router_guarded": route.router_guarded,
            }
            for route in self.routes
        ]


def _build(name: str) -> tuple[Application, State, Guard, str]:
    policy = Policy()
    guard = Guard(policy)
    state = State()

    placement = {
        "router-complete": "router",
        "router-late-bypass": "router",
        "middleware-complete": "middleware",
        "middleware-late-bypass": "middleware",
        "decorator-complete": "decorator",
        "verb-asymmetric": "decorator",
        "handler-complete": "handler",
    }[name]
    app = Application(
        state=state,
        placement=placement,
        guard=guard,
        middleware_complete=name == "middleware-complete",
    )

    raw_read = _handler(state)
    raw_write = _handler(state)
    if name == "handler-complete":
        read_handler = _handler(state, guard)
        write_handler = _handler(state, guard)
    elif name == "decorator-complete":
        read_handler = _decorated(raw_read, guard)
        write_handler = _decorated(raw_write, guard)
    elif name == "verb-asymmetric":
        read_handler = raw_read
        write_handler = _decorated(raw_write, guard)
    else:
        read_handler = raw_read
        write_handler = raw_write

    router_primary = placement == "router"
    router_alias = router_primary and name != "router-late-bypass"
    e007_primary_routes.register_primary_routes(
        app,
        read_handler,
        write_handler,
        router_guarded=router_primary,
    )
    # Guard configuration and canonical registration precede this import-side
    # call. The alias declaration itself is in a separate source module.
    e007_late_routes.register_late_alias(
        app,
        read_handler,
        router_guarded=router_alias,
    )
    return app, state, guard, placement


def _guard_scope(name: str) -> str:
    return {
        "router-complete": "all_registered_routes",
        "router-late-bypass": "canonical_router_only",
        "middleware-complete": "application_wide",
        "middleware-late-bypass": "path_prefix:/documents/",
        "decorator-complete": "read_and_write_handlers",
        "verb-asymmetric": "write_handler_only",
        "handler-complete": "read_and_write_handlers",
    }[name]


REQUESTS = (
    ("read", "GET", "/documents/doc-b1"),
    ("write", "POST", "/documents/doc-b1"),
    ("alias", "GET", "/legacy/documents/doc-b1"),
)


def _exercise(
    app: Application,
    state: State,
    guard: Guard,
    *,
    label: str,
    method: str,
    path: str,
    grant_org: str,
) -> dict[str, Any]:
    request_id = f"{grant_org}-{label}"
    effect_before = len(state.effects)
    guard_before = len(guard.invocations)
    response = app.dispatch(
        method,
        path,
        request_id=request_id,
        grant_org=grant_org,
    )
    return {
        "label": label,
        "request_id": request_id,
        "method": method,
        "path": path,
        "grant_org": grant_org,
        "status": response.status,
        "decision": response.decision,
        "reason": response.reason,
        "guard_invoked": len(guard.invocations) == guard_before + 1,
        "effect_delta": len(state.effects) - effect_before,
    }


def _check(check: str, passed: bool, detail: str) -> dict[str, str]:
    return {"check": check, "outcome": "PASS" if passed else "FAIL", "detail": detail}


def _run_arrangement(name: str) -> dict[str, Any]:
    app, state, guard, placement = _build(name)
    policy = guard.policy
    direct = policy.evaluate(
        Request(
            request_id="direct-policy",
            method="GET",
            path="/documents/doc-b1",
            action="documents:read",
            grant_org="org-a",
            resource_org=state.resource_org(OBJECT_ID),
        )
    )
    unauthorized = [
        _exercise(
            app,
            state,
            guard,
            label=label,
            method=method,
            path=path,
            grant_org="org-a",
        )
        for label, method, path in REQUESTS
    ]
    unauthorized_effects = len(state.effects)
    entitled = [
        _exercise(
            app,
            state,
            guard,
            label=label,
            method=method,
            path=path,
            grant_org="org-b",
        )
        for label, method, path in REQUESTS
    ]
    inventory = app.inventory()
    by_label = {item["label"]: item for item in unauthorized}
    entitled_by_label = {item["label"]: item for item in entitled}
    guard_ids = {item["request_id"] for item in guard.invocations}
    unauthorized_ids = {item["request_id"] for item in unauthorized}

    canonical_read = next(
        item
        for item in inventory
        if item["path"] == "/documents/doc-b1" and item["method"] == "GET"
    )
    alias = next(item for item in inventory if item["path"].startswith("/legacy/"))
    inventory_complete = (
        len(inventory) == 3
        and alias["registration_order"] > canonical_read["registration_order"]
        and alias["registration_module"] != canonical_read["registration_module"]
        and alias["handler_slot"] == canonical_read["handler_slot"]
    )

    def blocked(label: str) -> bool:
        item = by_label[label]
        return item["status"] == 403 and item["effect_delta"] == 0

    def allowed(label: str) -> bool:
        item = entitled_by_label[label]
        return item["status"] == 200 and item["effect_delta"] == 1

    checks = [
        _check(
            "POLICY_DENIES_OUT_OF_SCOPE_WHEN_CALLED",
            direct["allow"] is False,
            "The shared policy directly denied org-a authority over the org-b object.",
        ),
        _check(
            "OUT_OF_SCOPE_READ_BLOCKED_BEFORE_EFFECT",
            blocked("read"),
            f"canonical read status={by_label['read']['status']} effect_delta={by_label['read']['effect_delta']}",
        ),
        _check(
            "OUT_OF_SCOPE_WRITE_BLOCKED_BEFORE_EFFECT",
            blocked("write"),
            f"canonical write status={by_label['write']['status']} effect_delta={by_label['write']['effect_delta']}",
        ),
        _check(
            "OUT_OF_SCOPE_ALIAS_BLOCKED_BEFORE_EFFECT",
            blocked("alias"),
            f"late alias status={by_label['alias']['status']} effect_delta={by_label['alias']['effect_delta']}",
        ),
        _check(
            "GUARD_INVOKED_ON_EVERY_OUT_OF_SCOPE_PATH",
            unauthorized_ids <= guard_ids,
            f"guarded={sorted(unauthorized_ids & guard_ids)} missing={sorted(unauthorized_ids - guard_ids)}",
        ),
        _check(
            "ZERO_UNAUTHORIZED_EFFECTS",
            unauthorized_effects == 0,
            f"unauthorized_effect_count={unauthorized_effects}",
        ),
        _check(
            "ENTITLED_READ_ALLOWED",
            allowed("read"),
            f"entitled read status={entitled_by_label['read']['status']} effect_delta={entitled_by_label['read']['effect_delta']}",
        ),
        _check(
            "ENTITLED_WRITE_ALLOWED",
            allowed("write"),
            f"entitled write status={entitled_by_label['write']['status']} effect_delta={entitled_by_label['write']['effect_delta']}",
        ),
        _check(
            "ENTITLED_ALIAS_ALLOWED",
            allowed("alias"),
            f"entitled alias status={entitled_by_label['alias']['status']} effect_delta={entitled_by_label['alias']['effect_delta']}",
        ),
        _check(
            "ROUTE_INVENTORY_COMPLETE",
            inventory_complete,
            "Three paths recorded; the later alias is in a separate module and reaches the canonical read handler.",
        ),
        _check(
            "LATE_REGISTRATION_COVERED",
            by_label["alias"]["guard_invoked"] and blocked("alias"),
            f"alias guard_invoked={by_label['alias']['guard_invoked']} status={by_label['alias']['status']}",
        ),
    ]
    actual_failures = {item["check"] for item in checks if item["outcome"] == "FAIL"}
    expected_failures = EXPECTED_FAILURES[name]
    return {
        "arrangement": name,
        "guard_placement": placement,
        "guard_scope": _guard_scope(name),
        "policy_source": policy.source,
        "policy_sha256": hashlib.sha256(policy.source.encode()).hexdigest(),
        "direct_policy_decision": direct,
        "checks": checks,
        "predicted_failures": sorted(expected_failures),
        "actual_failures": sorted(actual_failures),
        "prediction_matched": actual_failures == expected_failures,
        "requests": {
            "out_of_scope": unauthorized,
            "entitled": entitled,
        },
        "route_inventory": inventory,
        "guard_invocations": guard.invocations,
        "effects": state.effects,
    }


def run_e007(repository_root: Path | None = None) -> dict[str, Any]:
    root = repository_root or Path(__file__).resolve().parents[2]
    preregistration = root / "docs" / "E007.md"
    arrangements = [_run_arrangement(name) for name in EXPECTED_FAILURES]
    predictions_matched = all(item["prediction_matched"] for item in arrangements)
    complete_controls_passed = all(
        not item["actual_failures"]
        for item in arrangements
        if item["arrangement"] in COMPLETE_ARRANGEMENTS
    )
    return {
        "schema": "atb-e007-result/0.1",
        "experiment": "E007",
        "classification": "SUPPORTED"
        if predictions_matched and complete_controls_passed
        else "FAILED_PREDICTION",
        "preregistration": {
            "path": "docs/E007.md",
            "commit": PREREGISTRATION_COMMIT,
            "sha256": hashlib.sha256(preregistration.read_bytes()).hexdigest(),
        },
        "instrument": {
            "arrangement_count": len(arrangements),
            "predictions_matched": predictions_matched,
            "complete_controls_passed": complete_controls_passed,
        },
        "arrangements": arrangements,
        "limitations": [
            "Synthetic standard-library routing fixture; no production MCP implementation or web framework was measured.",
            "Expressibility and detectability are supported; prevalence is not measured.",
            "Entitled controls prevent default-deny false confidence but do not measure false-positive rate against an external labelled corpus.",
            "Reverse proxies, generated routes, service meshes, and direct resource bypasses are outside this fixture.",
        ],
    }


def write_e007(output: Path, repository_root: Path | None = None) -> tuple[Path, Path]:
    result = run_e007(repository_root)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "result.json"
    summary_path = output / "SUMMARY.md"
    json_path.write_text(json.dumps(result, indent=2) + "\n")
    rows = []
    for arrangement in result["arrangements"]:
        rows.append(
            "| {name} | {placement} | {expected} | {actual} | {matched} |".format(
                name=arrangement["arrangement"],
                placement=arrangement["guard_placement"],
                expected=", ".join(arrangement["predicted_failures"]) or "none",
                actual=", ".join(arrangement["actual_failures"]) or "none",
                matched="PASS" if arrangement["prediction_matched"] else "FAIL",
            )
        )
    summary_path.write_text(
        "# E007 result\n\n"
        f"**Verdict: {result['classification']}**\n\n"
        f"Preregistration commit: `{result['preregistration']['commit']}`\n\n"
        f"Preregistration SHA-256: `{result['preregistration']['sha256']}`\n\n"
        "| Arrangement | Placement | Predicted failures | Actual failures | Prediction |\n"
        "|---|---|---|---|---|\n"
        + "\n".join(rows)
        + "\n\n## Limits\n\n"
        + "\n".join(f"- {item}" for item in result["limitations"])
        + "\n"
    )
    return json_path, summary_path
