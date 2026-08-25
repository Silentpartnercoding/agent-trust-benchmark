from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


FIXTURE_ID = "CDX-AADP-INPUT-PROVENANCE-001"
RESULT_SCHEMA = "atb-input-provenance-result/0.1"
CLASSIFICATIONS = ("EXACT", "DERIVABLE", "AMBIGUOUS", "UNREPRESENTED")
CLASSIFICATION_RANK = {value: index for index, value in enumerate(CLASSIFICATIONS)}


class ProvenanceError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    """Canonical JSON for this fixture's JCS-safe value subset.

    The fixtures use ASCII object keys, strings, booleans, and integers only. For
    that subset, sorted compact JSON is byte-identical to RFC 8785 JCS.
    """

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load_document(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ProvenanceError(f"{path} must contain a JSON object")
    return value


def _find_component(document: dict[str, Any], bom_ref: str) -> dict[str, Any]:
    matches = [item for item in document.get("components", []) if item.get("bom-ref") == bom_ref]
    if len(matches) != 1:
        raise ProvenanceError(f"expected exactly one component with bom-ref {bom_ref!r}")
    return matches[0]


def _find_task(document: dict[str, Any], bom_ref: str = "task-aadp-decision") -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for formula in document.get("formulation", []):
        for workflow in formula.get("workflows", []):
            matches.extend(task for task in workflow.get("tasks", []) if task.get("bom-ref") == bom_ref)
    if len(matches) != 1:
        raise ProvenanceError(f"expected exactly one task with bom-ref {bom_ref!r}")
    return matches[0]


def _find_parameter(task: dict[str, Any], name: str) -> tuple[int, int, dict[str, Any], str | None]:
    matches: list[tuple[int, int, dict[str, Any], str | None]] = []
    for input_index, task_input in enumerate(task.get("inputs", [])):
        source = task_input.get("source", {}).get("ref")
        for parameter_index, parameter in enumerate(task_input.get("parameters", [])):
            if parameter.get("name") == name:
                matches.append((input_index, parameter_index, parameter, source))
    if len(matches) != 1:
        raise ProvenanceError(f"expected exactly one decision parameter named {name!r}")
    return matches[0]


def _party_refs(component: dict[str, Any]) -> set[str]:
    return {
        party["bom-ref"]
        for party in component.get("parties", [])
        if isinstance(party, dict) and isinstance(party.get("bom-ref"), str)
    }


def classify_document(document: dict[str, Any]) -> dict[str, Any]:
    task = _find_task(document)
    input_index, parameter_index, parameter, source_ref = _find_parameter(task, "organization")
    pointer = (
        "/formulation/0/workflows/0/tasks/0/inputs/"
        f"{input_index}/parameters/{parameter_index}/value"
    )
    exact_citations = [
        citation
        for citation in document.get("citations", [])
        if pointer in citation.get("pointers", [])
    ]

    party_refs: set[str] = set()
    if source_ref is not None:
        party_refs = _party_refs(_find_component(document, source_ref))

    matching = [
        citation
        for citation in exact_citations
        if citation.get("process") == task.get("bom-ref")
        and citation.get("attributedTo") in party_refs
    ]

    if source_ref is not None and matching:
        classification = "EXACT"
        attributed_to = matching[0]["attributedTo"]
    elif exact_citations:
        classification = "AMBIGUOUS"
        attributed_to = exact_citations[0].get("attributedTo")
    elif source_ref is not None:
        classification = "DERIVABLE"
        attributed_to = None
    else:
        classification = "UNREPRESENTED"
        attributed_to = None

    return {
        "classification": classification,
        "field": "organization",
        "value": parameter.get("value"),
        "pointer": pointer,
        "source_ref": source_ref,
        "attributed_to": attributed_to,
        "process_ref": task.get("bom-ref"),
    }


def verify_jss_signature(document: dict[str, Any]) -> bool:
    signatures = document.get("signatures")
    if not isinstance(signatures, list) or len(signatures) != 1:
        raise ProvenanceError("fixture must carry exactly one JSS signature")
    signature = signatures[0]
    if signature.get("algorithm") != "Ed25519" or signature.get("hash_algorithm") != "sha-256":
        raise ProvenanceError("fixture signature must use Ed25519 over a SHA-256 JSS digest")

    unsigned = copy.deepcopy(document)
    signature_value = unsigned["signatures"][0].pop("value", None)
    public_key = unsigned["signatures"][0].get("public_key")
    if not isinstance(signature_value, str) or not isinstance(public_key, str):
        raise ProvenanceError("fixture signature is missing its value or public key")

    digest = hashlib.sha256(canonical_json(unsigned)).digest()
    try:
        signature_bytes = base64.urlsafe_b64decode(signature_value + "=" * (-len(signature_value) % 4))
        public_key_der = base64.b64decode(public_key)
    except ValueError as exc:
        raise ProvenanceError("fixture signature encoding is invalid") from exc

    with tempfile.TemporaryDirectory(prefix="atb-input-provenance-") as temporary:
        temporary_path = Path(temporary)
        public_key_path = temporary_path / "public.der"
        digest_path = temporary_path / "digest.bin"
        signature_path = temporary_path / "signature.bin"
        public_key_path.write_bytes(public_key_der)
        digest_path.write_bytes(digest)
        signature_path.write_bytes(signature_bytes)
        completed = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(digest_path),
                "-sigfile",
                str(signature_path),
            ],
            capture_output=True,
            check=False,
        )
    return completed.returncode == 0


def _component_digest(document: dict[str, Any], bom_ref: str) -> str:
    component = _find_component(document, bom_ref)
    hashes = [item["content"] for item in component.get("hashes", []) if item.get("alg") == "SHA-256"]
    if len(hashes) != 1:
        raise ProvenanceError(f"component {bom_ref!r} must carry exactly one SHA-256 digest")
    return hashes[0]


def _verdict(document: dict[str, Any]) -> dict[str, Any]:
    task = _find_task(document)
    outputs = task.get("outputs", [])
    if len(outputs) != 1 or "data" not in outputs[0]:
        raise ProvenanceError("decision task must carry exactly one inline verdict output")
    try:
        value = json.loads(outputs[0]["data"]["content"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ProvenanceError("decision output is not valid inline JSON") from exc
    if not isinstance(value, dict):
        raise ProvenanceError("decision output must decode to an object")
    return value


def _non_provenance_projection(document: dict[str, Any]) -> dict[str, Any]:
    projected = copy.deepcopy(document)
    projected.pop("serialNumber", None)
    projected.pop("signatures", None)
    projected.pop("citations", None)
    task = _find_task(projected)
    input_index, _, _, _ = _find_parameter(task, "organization")
    task["inputs"][input_index].pop("source", None)
    return projected


def evaluate_pair(authority: dict[str, Any], caller: dict[str, Any]) -> dict[str, Any]:
    authority_result = classify_document(authority)
    caller_result = classify_document(caller)
    same_tool = _component_digest(authority, "tool-documents-read") == _component_digest(
        caller, "tool-documents-read"
    )
    same_policy = _component_digest(authority, "policy-input-provenance") == _component_digest(
        caller, "policy-input-provenance"
    )
    same_value = authority_result["value"] == caller_result["value"]
    same_verdict = _verdict(authority) == _verdict(caller)
    same_projection = canonical_json(_non_provenance_projection(authority)) == canonical_json(
        _non_provenance_projection(caller)
    )
    distinct_sources = authority_result["source_ref"] != caller_result["source_ref"]

    if not all((same_tool, same_policy, same_value, same_verdict, same_projection)):
        classification = "AMBIGUOUS"
    elif not distinct_sources:
        classification = "UNREPRESENTED"
    else:
        classification = max(
            (authority_result["classification"], caller_result["classification"]),
            key=CLASSIFICATION_RANK.__getitem__,
        )

    authority_signature_valid = verify_jss_signature(authority)
    caller_signature_valid = verify_jss_signature(caller)
    if not authority_signature_valid or not caller_signature_valid:
        raise ProvenanceError("one or both whole-record JSS signatures are invalid")

    return {
        "schema": RESULT_SCHEMA,
        "fixture_id": FIXTURE_ID,
        "classification": classification,
        "same_tool_digest": same_tool,
        "same_policy_digest": same_policy,
        "same_decision_input_value": same_value,
        "same_verdict": same_verdict,
        "same_non_provenance_projection": same_projection,
        "distinct_source_edges": distinct_sources,
        "whole_record_signatures_valid": True,
        "authority_sourced": authority_result,
        "caller_sourced": caller_result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Classify decision-input provenance in a CDX pair")
    parser.add_argument("authority_record", type=Path)
    parser.add_argument("caller_record", type=Path)
    parser.add_argument("--expect", choices=CLASSIFICATIONS)
    args = parser.parse_args(argv)
    result = evaluate_pair(load_document(args.authority_record), load_document(args.caller_record))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if args.expect is None or result["classification"] == args.expect else 1


if __name__ == "__main__":
    raise SystemExit(main())
