from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .authority_relations import ConformanceError, digest, load_vectors


RELEASE_SCHEMA = "atb-frozen-release/0.1"


def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def verify_release_manifest(
    manifest_path: Path, *, repository_root: Path, vector_dir: Path | None = None
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text())
    required = {
        "schema",
        "suite",
        "release_tag",
        "status",
        "vector_count",
        "vector_manifest_hash",
        "vectors",
        "artifacts",
        "change_policy",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise ConformanceError("release manifest fields differ from atb-frozen-release/0.1")
    if manifest["schema"] != RELEASE_SCHEMA:
        raise ConformanceError("release manifest schema is unsupported")
    if manifest["suite"] != "authority-relations-v0.1":
        raise ConformanceError("release manifest suite is unsupported")

    vector_dir = vector_dir or repository_root / "vectors/authority-relations-v0.1"
    vectors = load_vectors(vector_dir)
    entries = [{"vector_id": vector["vector_id"], "hash": digest(vector)} for vector in vectors]
    if manifest["vector_count"] != len(vectors):
        raise ConformanceError("frozen vector count does not match release manifest")
    if manifest["vectors"] != entries:
        raise ConformanceError("frozen vector hashes do not match release manifest")
    if manifest["vector_manifest_hash"] != digest(entries):
        raise ConformanceError("frozen vector manifest hash does not match release manifest")

    expected_artifact_keys = {"vector_schema", "reference_result", "reference_summary"}
    if not isinstance(manifest["artifacts"], dict) or set(manifest["artifacts"]) != expected_artifact_keys:
        raise ConformanceError("release artifact inventory is invalid")
    for name, artifact in manifest["artifacts"].items():
        if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
            raise ConformanceError(f"release artifact {name} is invalid")
        path = repository_root / artifact["path"]
        if not path.is_file() or file_digest(path) != artifact["sha256"]:
            raise ConformanceError(f"release artifact {name} does not match its frozen hash")
    return manifest
