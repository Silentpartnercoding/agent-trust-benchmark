"""The registry is a hand-maintained index. These tests keep it honest.

Before this file, exactly one entry was under test and every other path could rot
unnoticed. These walk all of them.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = json.loads((ROOT / "benchmark-registry.json").read_text())

# Keys whose value is a repository-relative path.
PATH_KEYS = ("protocol", "result", "results", "vectors", "release_manifest")

KNOWN_STATUSES = {
    "development",
    "exploratory",
    "independent-compatibility-fixture",
    "frozen-candidate-conformance",
}


def test_registry_parses_and_declares_its_schema():
    assert REGISTRY["schema"] == "atb-benchmark-registry/0.1"
    assert REGISTRY["entries"]


def test_every_entry_has_an_id_and_a_known_status():
    for entry in REGISTRY["entries"]:
        assert entry.get("id"), entry
        assert entry.get("status") in KNOWN_STATUSES, (entry["id"], entry.get("status"))


def test_entry_ids_are_unique():
    ids = [entry["id"] for entry in REGISTRY["entries"]]
    assert len(ids) == len(set(ids)), ids


def test_every_declared_path_resolves():
    """The failure this exists to catch: an entry pointing at a file that moved."""
    missing = [
        (entry["id"], key, entry[key])
        for entry in REGISTRY["entries"]
        for key in PATH_KEYS
        if key in entry and not (ROOT / entry[key]).exists()
    ]
    assert not missing, missing


def test_result_is_a_file_and_results_is_a_directory():
    for entry in REGISTRY["entries"]:
        if "result" in entry:
            assert (ROOT / entry["result"]).is_file(), entry["id"]
        if "results" in entry:
            assert (ROOT / entry["results"]).is_dir(), entry["id"]


def test_every_experiment_protocol_in_docs_is_registered():
    """The failure this exists to catch: an experiment landing without an index entry,
    which is how E006 stayed absent while being cited externally."""
    on_disk = {
        match.group(0)
        for path in (ROOT / "docs").iterdir()
        if (match := re.match(r"E\d{3}(?=\.md$)", path.name))
    }
    registered = {entry["id"] for entry in REGISTRY["entries"]}
    assert not (on_disk - registered), sorted(on_disk - registered)
