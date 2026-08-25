import copy
import hashlib
import json
from pathlib import Path

from agent_trust_benchmark.input_provenance import (
    classify_document,
    evaluate_pair,
    verify_jss_signature,
)


ROOT = Path(__file__).parents[1]
VECTOR_DIR = ROOT / "vectors/input-provenance-v0.1"
AUTHORITY_PATH = VECTOR_DIR / "authority-sourced.cdx.json"
CALLER_PATH = VECTOR_DIR / "caller-sourced.cdx.json"


def _load(path: Path):
    return json.loads(path.read_text())


def _pair():
    return _load(AUTHORITY_PATH), _load(CALLER_PATH)


def _organization_input(document):
    return document["formulation"][0]["workflows"][0]["tasks"][0]["inputs"][2]


def test_native_cyclonedx_pair_preserves_the_distinction_exactly():
    result = evaluate_pair(*_pair())
    assert result["classification"] == "EXACT"
    assert result["same_tool_digest"] is True
    assert result["same_policy_digest"] is True
    assert result["same_decision_input_value"] is True
    assert result["same_verdict"] is True
    assert result["same_non_provenance_projection"] is True
    assert result["distinct_source_edges"] is True
    assert result["whole_record_signatures_valid"] is True
    assert result["authority_sourced"]["source_ref"] == "authority-state"
    assert result["caller_sourced"]["source_ref"] == "caller-agent"


def test_structural_input_source_without_field_citation_is_only_derivable():
    authority, _ = _pair()
    authority.pop("citations")
    result = classify_document(authority)
    assert result["classification"] == "DERIVABLE"
    assert result["source_ref"] == "authority-state"


def test_process_only_field_citation_is_ambiguous_about_the_supplier():
    authority, _ = _pair()
    _organization_input(authority).pop("source")
    authority["citations"][0].pop("attributedTo")
    result = classify_document(authority)
    assert result["classification"] == "AMBIGUOUS"
    assert result["source_ref"] is None


def test_removing_both_provenance_edges_is_unrepresented():
    authority, _ = _pair()
    _organization_input(authority).pop("source")
    authority.pop("citations")
    result = classify_document(authority)
    assert result["classification"] == "UNREPRESENTED"


def test_both_whole_record_jss_signatures_are_cryptographically_valid():
    authority, caller = _pair()
    assert verify_jss_signature(authority) is True
    assert verify_jss_signature(caller) is True


def test_signature_detects_a_changed_decision_input_value():
    authority, _ = _pair()
    _organization_input(authority)["parameters"][0]["value"] = "org-a"
    assert verify_jss_signature(authority) is False


def test_component_digests_pin_the_published_tool_and_policy_bytes():
    authority, caller = _pair()
    expected = {
        "tool-documents-read": hashlib.sha256((VECTOR_DIR / "tool-definition.json").read_bytes()).hexdigest(),
        "policy-input-provenance": hashlib.sha256((VECTOR_DIR / "policy.rego").read_bytes()).hexdigest(),
    }
    for document in (authority, caller):
        actual = {
            component["bom-ref"]: component["hashes"][0]["content"]
            for component in document["components"]
            if component.get("bom-ref") in expected
        }
        assert actual == expected


def test_frozen_source_manifest_names_exact_upstream_versions():
    sources = _load(VECTOR_DIR / "frozen-sources.json")
    assert sources["aadp"]["draft"] == "draft-saha-aadp-01"
    assert sources["cyclonedx"]["commit"] == "1a950b106df221c30cf208b4ffad3e5e1303385f"
    assert sources["e006"]["commit"] == "dea23be5618625e1d40aba708ad62aae9934e7b5"


def test_exact_field_pointer_resolves_to_the_organization_value():
    for document in _pair():
        citation = document["citations"][0]
        assert citation["pointers"] == [
            "/formulation/0/workflows/0/tasks/0/inputs/2/parameters/0/value"
        ]
        assert _organization_input(document)["parameters"][0]["value"] == "org-b"


def test_only_the_provenance_edge_and_document_identity_differ_before_signing():
    authority, caller = _pair()
    for document in (authority, caller):
        document.pop("serialNumber")
        document.pop("signatures")
        document.pop("citations")
        _organization_input(document).pop("source")
    assert authority == caller
