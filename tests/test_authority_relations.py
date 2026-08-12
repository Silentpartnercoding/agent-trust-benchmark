import copy
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agent_trust_benchmark.authority_relations import (
    adapter_case,
    invoke_adapter,
    load_vectors,
    run_conformance,
)
from agent_trust_benchmark.authority_release import verify_release_manifest


ROOT = Path(__file__).parents[1]
VECTOR_DIR = ROOT / "vectors/authority-relations-v0.1"
DELEGATION_ONLY = ROOT / "adapters/delegation_only.py"
RELATION_AWARE = ROOT / "adapters/relation_aware.py"
RELEASE_MANIFEST = ROOT / "releases/authority-relations-v0.1.json"


def test_all_eight_vectors_validate_and_have_unique_ids():
    vectors = load_vectors(VECTOR_DIR)
    assert len(vectors) == 8
    assert len({vector["vector_id"] for vector in vectors}) == 8


def test_published_json_schema_accepts_every_vector():
    schema = json.loads((VECTOR_DIR / "schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for path in VECTOR_DIR.glob("*.json"):
        if path.name != "schema.json":
            validator.validate(json.loads(path.read_text()))


def test_adapter_never_receives_expected_oracle():
    vector = load_vectors(VECTOR_DIR)[0]
    case = adapter_case(vector)
    assert "expected" not in case
    assert "expected" not in json.dumps(case)
    assert case["schema"] == "atb-authority-relation-case/0.1"


def test_relation_aware_adapter_passes_all_vectors():
    result = run_conformance(VECTOR_DIR, [RELATION_AWARE])
    run = result["runs"][0]
    assert run["passed"] == 8
    assert run["total"] == 8
    assert all(case["outcome"] == "PASS" for case in run["cases"])


def test_delegation_only_adapter_is_discriminated_by_independent_authority():
    result = run_conformance(VECTOR_DIR, [DELEGATION_ONLY])
    run = result["runs"][0]
    cases = {case["vector_id"]: case for case in run["cases"]}
    assert run["passed"] < run["total"]
    assert cases["AR-001-VALID-DELEGATION"]["outcome"] == "PASS"
    assert cases["AR-002-VALID-MANDATE"]["outcome"] == "FAIL"
    assert cases["AR-008-PERMISSIONLESS-REQUEST"]["outcome"] == "FAIL"
    assert "derived_authority_relation" in cases["AR-002-VALID-MANDATE"]["mismatched_fields"]
    assert "execution_authority_source" in cases["AR-008-PERMISSIONLESS-REQUEST"]["mismatched_fields"]


def test_same_evidence_can_deny_or_allow_under_explicit_policy():
    vectors = {vector["vector_id"]: vector for vector in load_vectors(VECTOR_DIR)}
    required = vectors["AR-003-UNAUTHORIZED-REQUESTER"]
    permissionless = vectors["AR-008-PERMISSIONLESS-REQUEST"]
    assert required["observed"] == permissionless["observed"]
    assert required["policy"]["requester_authority"] == "REQUIRED"
    assert permissionless["policy"]["requester_authority"] == "NOT_REQUIRED"
    assert required["expected"]["derived_authority_relation"] == "INDEPENDENT"
    assert permissionless["expected"]["derived_authority_relation"] == "INDEPENDENT"
    assert required["expected"]["authorized"] is False
    assert permissionless["expected"]["authorized"] is True


def _rename_ids(value):
    replacements = {
        "agent-a": "request-agent-z9",
        "agent-b": "executor-q4",
        "principal-h": "root-principal-77",
        "workflow-policy-h": "workflow-source-52",
        "resource-admin-c": "resource-owner-18",
        "documents": "records",
        "archive": "seal",
        "doc:123": "record:987",
    }
    if isinstance(value, dict):
        return {key: _rename_ids(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_rename_ids(item) for item in value]
    return replacements.get(value, value)


def test_relation_aware_adapter_is_not_keyed_to_fixture_names(tmp_path):
    for index, vector in enumerate(load_vectors(VECTOR_DIR), start=1):
        transformed = _rename_ids(copy.deepcopy(vector))
        transformed["vector_id"] = f"MUTATED-{index:03d}"
        transformed["expected"]["vector_id"] = transformed["vector_id"]
        (tmp_path / f"case-{index:03d}.json").write_text(json.dumps(transformed))
    result = run_conformance(tmp_path, [RELATION_AWARE])
    assert result["runs"][0]["passed"] == 8
    assert "AR-00" not in RELATION_AWARE.read_text()


def test_request_only_authority_cannot_be_delegated_as_execution_authority():
    vector = next(
        item for item in load_vectors(VECTOR_DIR) if item["vector_id"] == "AR-001-VALID-DELEGATION"
    )
    case = copy.deepcopy(adapter_case(vector))
    case["observed"]["request_authority"]["kind"] = "REQUEST"
    actual = invoke_adapter(RELATION_AWARE, case)
    assert actual["derived_authority_relation"] == "NONE"
    assert actual["execution_authority_valid"] is False
    assert actual["authorized"] is False


def test_delegation_root_must_match_requesters_authority_source():
    vector = next(
        item for item in load_vectors(VECTOR_DIR) if item["vector_id"] == "AR-001-VALID-DELEGATION"
    )
    case = copy.deepcopy(adapter_case(vector))
    case["observed"]["delegation"]["authority_source"] = "unrelated-root"
    actual = invoke_adapter(RELATION_AWARE, case)
    assert actual["derived_authority_relation"] == "NONE"
    assert actual["execution_authority_valid"] is False
    assert actual["authorized"] is False


def test_machine_result_is_deterministic():
    first = run_conformance(VECTOR_DIR, [DELEGATION_ONLY, RELATION_AWARE])
    second = run_conformance(VECTOR_DIR, [DELEGATION_ONLY, RELATION_AWARE])
    assert first == second
    assert first["result_hash"].startswith("sha256:")


def test_unsupported_is_not_confused_with_deny_or_adapter_error(tmp_path):
    adapter = tmp_path / "unsupported.py"
    adapter.write_text(
        "import json,sys\n"
        "case=json.load(sys.stdin)\n"
        "o=case['observed'];p=case['policy']\n"
        "json.dump({'schema':'atb-authority-relation-output/0.1','status':'UNSUPPORTED',"
        "'vector_id':case['vector_id'],'requester':o['requester'],'actor':o['actor'],"
        "'evidence_status':'INCOMPLETE','declared_relation':o['declared_relation'],"
        "'declared_relation_matches':None,'request_authority_source':None,"
        "'request_authority_valid':False,'execution_authority_source':None,"
        "'immediate_authority_grantor':None,'execution_authority_valid':False,"
        "'derived_authority_relation':'NONE','policy_profile':p['profile'],"
        "'requester_authority_required':p['requester_authority']=='REQUIRED',"
        "'authorized':False,'reason':'UNSUPPORTED_RELATION'},sys.stdout)\n"
    )
    result = run_conformance(VECTOR_DIR, [adapter])
    assert result["runs"][0]["passed"] == 0
    assert {case["outcome"] for case in result["runs"][0]["cases"]} == {"UNSUPPORTED"}


def test_registry_contains_resolvable_candidate_entry():
    registry = json.loads((ROOT / "benchmark-registry.json").read_text())
    entries = {entry["id"]: entry for entry in registry["entries"]}
    candidate = entries["authority-relations-v0.1"]
    assert candidate["status"] == "frozen-candidate-conformance"
    assert (ROOT / candidate["protocol"]).is_file()
    assert (ROOT / candidate["vectors"]).is_dir()
    assert (ROOT / candidate["release_manifest"]).is_file()


def test_frozen_release_manifest_matches_all_published_artifacts():
    manifest = verify_release_manifest(RELEASE_MANIFEST, repository_root=ROOT)
    assert manifest["release_tag"] == "authority-relations-v0.1"
    assert manifest["vector_count"] == 8
    assert manifest["vector_manifest_hash"] == (
        "sha256:ffc2363895a77a62b5673366e334140d2682f436891f570b9bfb321bdfa4ade3"
    )


def test_frozen_release_rejects_vector_mutation(tmp_path):
    shutil.copytree(VECTOR_DIR, tmp_path / "vectors/authority-relations-v0.1", dirs_exist_ok=True)
    shutil.copytree(
        ROOT / "results/authority-relations-v0.1/reference",
        tmp_path / "results/authority-relations-v0.1/reference",
        dirs_exist_ok=True,
    )
    changed = tmp_path / "vectors/authority-relations-v0.1/delegation.json"
    vector = json.loads(changed.read_text())
    vector["description"] += " changed"
    changed.write_text(json.dumps(vector))
    with pytest.raises(ValueError, match="frozen vector hashes"):
        verify_release_manifest(RELEASE_MANIFEST, repository_root=tmp_path)


def test_external_submission_schema_accepts_minimal_submission():
    schema = json.loads(
        (ROOT / "schemas/authority-relations-submission-v0.1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        {
            "schema": "atb-authority-relations-submission/0.1",
            "suite": "authority-relations-v0.1",
            "release_tag": "authority-relations-v0.1",
            "vector_manifest_hash": "sha256:ffc2363895a77a62b5673366e334140d2682f436891f570b9bfb321bdfa4ade3",
            "implementation": {
                "name": "example-native-engine",
                "version": "1.0.0",
                "repository": "https://example.test/engine",
                "commit": "0123456789abcdef",
            },
            "run": {
                "timestamp": "2026-08-12T00:00:00Z",
                "runtime": "example 1.0",
                "command": "python -m agent_trust_benchmark authority-relations --adapter ./adapter",
            },
            "artifacts": {
                "result": {"path": "result.json", "sha256": "sha256:" + "0" * 64},
                "summary": {"path": "SUMMARY.md", "sha256": "sha256:" + "1" * 64},
            },
            "attestation": {
                "native_engine_used": True,
                "reference_adapter_imported": False,
                "expected_oracle_inspected": False,
                "notes": "",
            },
            "acceptance": {"state": "SUBMITTED", "assigned_by": None, "notes": ""},
        }
    )
