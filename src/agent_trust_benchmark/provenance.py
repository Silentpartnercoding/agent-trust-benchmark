"""Classify every result file by how it came to exist.

A run id says which run a result belongs to. It does not say whether the file was
emitted by the harness or written afterwards by hand, and both kinds have existed
in this repository in the same directory, in the same format, indistinguishable at
a glance.

Four E001 results were hand-authored records of live sessions. They were found on
2026-08-19 by inspecting timestamps by hand. This module makes that inspection
mechanical, so the finding is reproducible by anyone rather than remembered by
someone.

The signals are properties of the file, not claims about it:

  evidence_refs     write_result carries raw evidence references through from the
                    adapter's observations. A hand-authored file has none.
  timestamp_grain   machine timestamps carry sub-second precision. Whole-second
                    values are typed.
  elapsed           a run takes time. started_at == completed_at cannot happen.
  schema_fields     fields the emitting code does not produce (arm, provider_class,
                    related_party_disclosure) indicate authorship.

No single signal is conclusive. The verdict requires agreement, and anything
ambiguous is reported as such rather than guessed.
"""
from __future__ import annotations

import json
from pathlib import Path

# The signals below read E001's RunResult shape and E006's. They are meaningless
# against a result from an experiment that serialises something else, and a
# classifier that scores those anyway manufactures findings out of its own
# assumptions. Anything not listed here is reported NOT_APPLICABLE rather than
# judged.
# Schema strings that appear in result files but that no emitting code produces.
# RunResult hardcodes "0.1" and e006.py hardcodes "e006/v1". A file declaring
# anything else in a shape this check otherwise recognises was written by hand,
# and the author chose a version string that looks plausible. This is the single
# most reliable signal available, because it is a constant in the source rather
# than a property that can be produced accidentally.
NEVER_EMITTED_SCHEMAS = {
    "e001/v1": "RunResult emits schema_version '0.1'; 'e001/v1' has never been produced by it.",
}

KNOWN_SCHEMAS = {
    "0.1": {  # E001 RunResult
        "schema_version", "experiment_id", "provider", "run_id", "started_at",
        "completed_at", "checks", "evidence", "metrics", "limitations",
    },
    "e006/v1": {
        "schema_version", "experiment_id", "provider", "policy_source", "run_id",
        "started_at", "completed_at", "checks", "evidence", "metrics", "limitations",
    },
}


def _signals(doc: dict, expected: set[str]) -> dict:
    started, completed = doc.get("started_at", ""), doc.get("completed_at", "")
    extra = sorted(set(doc) - expected)
    return {
        "evidence_refs": len(doc.get("evidence") or []),
        "sub_second_timestamps": "." in started and "." in completed,
        "elapsed_nonzero": bool(started) and started != completed,
        "unexpected_fields": extra,
    }


def classify(result_path: Path) -> dict:
    try:
        doc = json.loads(result_path.read_text())
    except (OSError, ValueError) as exc:
        return {"run_id": result_path.parent.name, "verdict": "UNREADABLE",
                "detail": str(exc)[:120]}

    schema = doc.get("schema_version")
    if schema in NEVER_EMITTED_SCHEMAS:
        return {"run_id": doc.get("run_id", result_path.parent.name),
                "provider": doc.get("provider"), "verdict": "HAND_AUTHORED",
                "detail": NEVER_EMITTED_SCHEMAS[schema] + (
                    " The file records what someone concluded, not what a run produced."),
                "signals": {"schema_version": schema}}

    expected = KNOWN_SCHEMAS.get(schema)
    if expected is None:
        return {"run_id": doc.get("run_id", result_path.parent.name),
                "provider": doc.get("provider"), "verdict": "NOT_APPLICABLE",
                "detail": (
                    f"schema_version={schema!r} is not one this check understands. Its signals "
                    "are defined against the E001 and E006 result shapes and say nothing about "
                    "any other. Not judged."),
                "signals": {}}

    s = _signals(doc, expected)
    emitted_votes = [s["evidence_refs"] > 0, s["sub_second_timestamps"],
                     s["elapsed_nonzero"], not s["unexpected_fields"]]
    n = sum(emitted_votes)

    if n == 4:
        verdict, detail = "EMITTED", "All four signals agree: harness-emitted."
    elif n == 0:
        verdict, detail = "HAND_AUTHORED", (
            "No evidence references, whole-second timestamps, zero elapsed time, and fields the "
            "harness does not emit. This is a written record, not a run.")
    else:
        verdict, detail = "AMBIGUOUS", (
            f"{n} of 4 signals indicate emission. Inspect before relying on it; do not assume "
            "either way.")

    return {"run_id": doc.get("run_id", result_path.parent.name),
            "provider": doc.get("provider"), "verdict": verdict, "detail": detail,
            "signals": s}


def scan(results_root: Path) -> dict:
    rows = [classify(p) for p in sorted(results_root.rglob("result.json"))]
    by = {}
    for r in rows:
        by.setdefault(r["verdict"], []).append(r["run_id"])
    return {
        "results_root": str(results_root),
        "total": len(rows),
        "by_verdict": {k: sorted(v) for k, v in sorted(by.items())},
        "results": rows,
        "note": (
            "A HAND_AUTHORED verdict does not mean the observations are wrong. It means the file "
            "records what someone concluded rather than what a run produced, so it cannot be "
            "reproduced from this repository and should not be cited as a measurement without "
            "saying so."),
    }


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Classify each result file by how it came to exist.")
    ap.add_argument("results_root", nargs="?", default="results", type=Path)
    ap.add_argument("--json", action="store_true", help="emit the full report")
    args = ap.parse_args()

    report = scan(args.results_root)
    if args.json:
        print(json.dumps(report, indent=2))
        return 0

    print(f"scanned {report['total']} result files under {report['results_root']}\n")
    for verdict in ("HAND_AUTHORED", "AMBIGUOUS", "NOT_APPLICABLE", "UNREADABLE", "EMITTED"):
        ids = report["by_verdict"].get(verdict)
        if not ids:
            continue
        print(f"{verdict}  ({len(ids)})")
        if verdict != "EMITTED":
            for i in ids:
                print(f"    {i}")
        print()
    print(report["note"])
    # Hand-authored results are not an error condition. They are a disclosure
    # requirement, and the exit code says only whether any were found.
    return 1 if report["by_verdict"].get("HAND_AUTHORED") else 0


if __name__ == "__main__":
    raise SystemExit(_main())
