import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agent_trust_benchmark.authority_relations import adapter_case, load_vectors, run_conformance


ROOT = Path(__file__).parents[1]
VECTOR_DIR = ROOT / "vectors/authority-relations-v0.1"
DELEGATION_ONLY = ROOT / "adapters/delegation_only.py"
RELATION_AWARE = ROOT / "adapters/relation_aware.py"


def test_all_seven_vectors_validate_and_have_unique_ids():
    vectors = load_vectors(VECTOR_DIR)
    assert len(vectors) == 7
    assert len({vector["vector_id"] for vector in vectors}) == 7


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
    assert run["passed"] == 7
    assert run["total"] == 7
    assert all(case["outcome"] == "PASS" for case in run["cases"])


def test_delegation_only_adapter_is_discriminated_by_mandate():
    result = run_conformance(VECTOR_DIR, [DELEGATION_ONLY])
    run = result["runs"][0]
    cases = {case["vector_id"]: case for case in run["cases"]}
    assert run["passed"] < run["total"]
    assert cases["AR-001-VALID-DELEGATION"]["outcome"] == "PASS"
    assert cases["AR-002-VALID-MANDATE"]["outcome"] == "FAIL"
    assert "authority_relation" in cases["AR-002-VALID-MANDATE"]["mismatched_fields"]
    assert "execution_authority_source" in cases["AR-002-VALID-MANDATE"]["mismatched_fields"]


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
        "o=case['observed']\n"
        "json.dump({'schema':'atb-authority-relation-output/0.1','status':'UNSUPPORTED',"
        "'vector_id':case['vector_id'],'requester':o['requester'],'actor':o['actor'],"
        "'request_authority_source':None,'request_authority_valid':False,"
        "'execution_authority_source':None,'immediate_authority_grantor':None,"
        "'execution_authority_valid':False,'authority_relation':'NONE',"
        "'authorized':False,'reason':'UNSUPPORTED_RELATION'},sys.stdout)\n"
    )
    result = run_conformance(VECTOR_DIR, [adapter])
    assert result["runs"][0]["passed"] == 0
    assert {case["outcome"] for case in result["runs"][0]["cases"]} == {"UNSUPPORTED"}


def test_registry_contains_resolvable_candidate_entry():
    registry = json.loads((ROOT / "benchmark-registry.json").read_text())
    entries = {entry["id"]: entry for entry in registry["entries"]}
    candidate = entries["authority-relations-v0.1"]
    assert candidate["status"] == "candidate-conformance"
    assert (ROOT / candidate["protocol"]).is_file()
    assert (ROOT / candidate["vectors"]).is_dir()
