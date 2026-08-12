from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


VECTOR_SCHEMA = "atb-authority-relation-vector/0.1"
CASE_SCHEMA = "atb-authority-relation-case/0.1"
OUTPUT_SCHEMA = "atb-authority-relation-output/0.1"
RESULT_SCHEMA = "atb-authority-relations-result/0.1"
RELATIONS = {"DELEGATED", "INDEPENDENT", "NONE", "INVALID"}
REQUIRED_OUTPUT_KEYS = {
    "schema",
    "status",
    "vector_id",
    "requester",
    "actor",
    "request_authority_source",
    "request_authority_valid",
    "execution_authority_source",
    "immediate_authority_grantor",
    "execution_authority_valid",
    "authority_relation",
    "authorized",
    "reason",
}


class ConformanceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def _require_exact_keys(value: dict[str, Any], expected: set[str], where: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ConformanceError(
            f"{where} fields differ: missing={sorted(expected - actual)} "
            f"unexpected={sorted(actual - expected)}"
        )


def validate_output(value: Any, *, vector_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConformanceError("adapter output must be an object")
    _require_exact_keys(value, REQUIRED_OUTPUT_KEYS, "adapter output")
    if value["schema"] != OUTPUT_SCHEMA:
        raise ConformanceError("adapter output schema is unsupported")
    if value["status"] not in {"DECIDED", "UNSUPPORTED"}:
        raise ConformanceError("adapter output status is unsupported")
    if value["vector_id"] != vector_id:
        raise ConformanceError("adapter output vector_id does not match the case")
    for field in ("requester", "actor", "reason"):
        if not isinstance(value[field], str) or not value[field]:
            raise ConformanceError(f"adapter output {field} must be a non-empty string")
    for field in (
        "request_authority_source",
        "execution_authority_source",
        "immediate_authority_grantor",
    ):
        if value[field] is not None and (not isinstance(value[field], str) or not value[field]):
            raise ConformanceError(f"adapter output {field} must be null or a non-empty string")
    for field in ("request_authority_valid", "execution_authority_valid", "authorized"):
        if type(value[field]) is not bool:
            raise ConformanceError(f"adapter output {field} must be boolean")
    if value["authority_relation"] not in RELATIONS:
        raise ConformanceError("adapter output authority_relation is unsupported")
    return value


def validate_vector(value: Any, *, source: Path | None = None) -> dict[str, Any]:
    where = str(source) if source else "vector"
    if not isinstance(value, dict):
        raise ConformanceError(f"{where} must be an object")
    _require_exact_keys(
        value,
        {"schema", "vector_id", "title", "description", "observed", "expected"},
        where,
    )
    if value["schema"] != VECTOR_SCHEMA:
        raise ConformanceError(f"{where} has an unsupported schema")
    if not isinstance(value["vector_id"], str) or not value["vector_id"]:
        raise ConformanceError(f"{where} has an invalid vector_id")
    if not isinstance(value["title"], str) or not isinstance(value["description"], str):
        raise ConformanceError(f"{where} title and description must be strings")
    observed = value["observed"]
    if not isinstance(observed, dict):
        raise ConformanceError(f"{where} observed must be an object")
    _require_exact_keys(
        observed,
        {
            "requester",
            "actor",
            "requested_action",
            "claimed_relation",
            "request_authority",
            "execution_authority",
            "delegation",
        },
        f"{where} observed",
    )
    if observed["claimed_relation"] not in {"DELEGATED", "INDEPENDENT", "NONE"}:
        raise ConformanceError(f"{where} claimed_relation is unsupported")
    action = observed["requested_action"]
    if not isinstance(action, dict):
        raise ConformanceError(f"{where} requested_action must be an object")
    _require_exact_keys(action, {"resource", "action", "target"}, f"{where} requested_action")
    for field in ("requester", "actor"):
        if not isinstance(observed[field], str) or not observed[field]:
            raise ConformanceError(f"{where} {field} must be a non-empty string")
    for field in ("resource", "action", "target"):
        if not isinstance(action[field], str) or not action[field]:
            raise ConformanceError(f"{where} requested_action.{field} must be non-empty")
    for field in ("request_authority", "execution_authority"):
        evidence = observed[field]
        if not isinstance(evidence, dict):
            raise ConformanceError(f"{where} {field} must be an object")
        _require_exact_keys(
            evidence,
            {"status", "source", "subject", "kind", "action", "independently_issued"},
            f"{where} {field}",
        )
        if evidence["status"] not in {"VALID", "MISSING", "INVALID"}:
            raise ConformanceError(f"{where} {field}.status is unsupported")
        if evidence["kind"] not in {"REQUEST", "EXECUTION"}:
            raise ConformanceError(f"{where} {field}.kind is unsupported")
        if type(evidence["independently_issued"]) is not bool:
            raise ConformanceError(f"{where} {field}.independently_issued must be boolean")
    delegation = observed["delegation"]
    if not isinstance(delegation, dict):
        raise ConformanceError(f"{where} delegation must be an object")
    _require_exact_keys(
        delegation,
        {"status", "authority_source", "delegator", "delegatee", "action", "attenuated"},
        f"{where} delegation",
    )
    if delegation["status"] not in {"VALID", "MISSING", "INVALID"}:
        raise ConformanceError(f"{where} delegation.status is unsupported")
    if type(delegation["attenuated"]) is not bool:
        raise ConformanceError(f"{where} delegation.attenuated must be boolean")
    validate_output(value["expected"], vector_id=value["vector_id"])
    if value["expected"]["requester"] != observed["requester"]:
        raise ConformanceError(f"{where} expected requester differs from observed requester")
    if value["expected"]["actor"] != observed["actor"]:
        raise ConformanceError(f"{where} expected actor differs from observed actor")
    return value


def load_vectors(vector_dir: Path) -> list[dict[str, Any]]:
    paths = sorted(path for path in vector_dir.glob("*.json") if path.name != "schema.json")
    if not paths:
        raise ConformanceError(f"no vectors found in {vector_dir}")
    vectors = sorted(
        (validate_vector(json.loads(path.read_text()), source=path) for path in paths),
        key=lambda vector: vector["vector_id"],
    )
    ids = [vector["vector_id"] for vector in vectors]
    if len(ids) != len(set(ids)):
        raise ConformanceError("vector_id values must be unique")
    return vectors


def adapter_case(vector: dict[str, Any]) -> dict[str, Any]:
    """Return the black-box input without the expected oracle."""
    return {
        "schema": CASE_SCHEMA,
        "vector_id": vector["vector_id"],
        "title": vector["title"],
        "description": vector["description"],
        "observed": vector["observed"],
    }


def invoke_adapter(adapter: Path, case: dict[str, Any], *, timeout_seconds: float = 5) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(adapter)],
        input=canonical_json(case),
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode(errors="replace")[:500]
        raise ConformanceError(f"adapter exited {completed.returncode}: {stderr}")
    if len(completed.stdout) > 1_000_000:
        raise ConformanceError("adapter output exceeds 1 MB")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ConformanceError("adapter did not return exactly one JSON value") from exc
    return validate_output(value, vector_id=case["vector_id"])


def run_conformance(vector_dir: Path, adapters: list[Path]) -> dict[str, Any]:
    vectors = load_vectors(vector_dir)
    runs: list[dict[str, Any]] = []
    for adapter in adapters:
        cases: list[dict[str, Any]] = []
        for vector in vectors:
            case = adapter_case(vector)
            expected = vector["expected"]
            try:
                actual = invoke_adapter(adapter, case)
                mismatches = sorted(
                    field for field in REQUIRED_OUTPUT_KEYS if actual.get(field) != expected.get(field)
                )
                outcome = (
                    "UNSUPPORTED"
                    if actual["status"] == "UNSUPPORTED"
                    else "PASS" if not mismatches else "FAIL"
                )
                error = None
            except (ConformanceError, subprocess.TimeoutExpired) as exc:
                actual = None
                mismatches = []
                outcome = "ERROR"
                error = str(exc)
            cases.append(
                {
                    "vector_id": vector["vector_id"],
                    "case_hash": digest(case),
                    "expected_hash": digest(expected),
                    "outcome": outcome,
                    "mismatched_fields": mismatches,
                    "error": error,
                    "expected": expected,
                    "actual": actual,
                }
            )
        runs.append(
            {
                "adapter": adapter.name,
                "adapter_hash": "sha256:" + hashlib.sha256(adapter.read_bytes()).hexdigest(),
                "passed": sum(case["outcome"] == "PASS" for case in cases),
                "total": len(cases),
                "cases": cases,
            }
        )
    result = {
        "schema": RESULT_SCHEMA,
        "suite": "authority-relations-v0.1",
        "invariant": "REQUEST CAUSALITY MUST NOT IMPLY AUTHORITY PROVENANCE",
        "vector_count": len(vectors),
        "vector_manifest_hash": digest(
            [{"vector_id": vector["vector_id"], "hash": digest(vector)} for vector in vectors]
        ),
        "runs": runs,
        "claim_boundary": [
            "Synthetic black-box conformance evidence only.",
            "No external protocol or provider was tested.",
            "ALLOW is correct only when the authority relation and both required authority paths are correct.",
        ],
    }
    return {**result, "result_hash": digest(result)}


def render_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Authority Relations v0.1 result",
        "",
        f"**Invariant:** {result['invariant']}",
        "",
        "| Adapter | Passed | Total |",
        "|---|---:|---:|",
    ]
    for run in result["runs"]:
        lines.append(f"| `{run['adapter']}` | {run['passed']} | {run['total']} |")
    for run in result["runs"]:
        lines.extend(["", f"## {run['adapter']}", "", "| Vector | Outcome | Mismatch |", "|---|---|---|"])
        for case in run["cases"]:
            mismatch = ", ".join(case["mismatched_fields"]) or case["error"] or "—"
            lines.append(f"| {case['vector_id']} | {case['outcome']} | {mismatch} |")
    lines.extend(["", "## Claim boundary", ""])
    lines.extend(f"- {item}" for item in result["claim_boundary"])
    return "\n".join(lines) + "\n"


def write_conformance(
    output_dir: Path,
    *,
    vector_dir: Path,
    adapters: list[Path],
) -> tuple[Path, Path, dict[str, Any]]:
    result = run_conformance(vector_dir, adapters)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "result.json"
    markdown_path = output_dir / "SUMMARY.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(render_markdown(result))
    return json_path, markdown_path, result
