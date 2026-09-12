from __future__ import annotations

import argparse
from pathlib import Path

from .authority_relations import write_conformance
from .authority_release import verify_release_manifest
from .e004 import write_e004
from .e005 import write_e005
from .e007 import write_e007
from .experiment import ADAPTERS, run_e001
from .report import render_markdown, write_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="benchmark", description="Vendor-neutral agent trust benchmark"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("experiment", choices=["e001"])
    run.add_argument("--provider", choices=[*ADAPTERS, "all"], required=True)
    run.add_argument("--output-dir", type=Path, default=Path("results/e001"))
    run.add_argument("--no-write", action="store_true")
    e004 = subcommands.add_parser("e004")
    e004.add_argument("--output-dir", type=Path, default=Path("results/e004/latest"))
    e005 = subcommands.add_parser("e005")
    e005.add_argument("--output-dir", type=Path, default=Path("results/e005/latest"))
    e007 = subcommands.add_parser("e007")
    e007.add_argument("--output-dir", type=Path, default=Path("results/e007/latest"))
    relations = subcommands.add_parser("authority-relations")
    relations.add_argument(
        "--vector-dir", type=Path, default=Path("vectors/authority-relations-v0.1")
    )
    relations.add_argument(
        "--adapter",
        action="append",
        type=Path,
        dest="adapters",
        help="JSON stdin/stdout adapter; may be supplied more than once",
    )
    relations.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/authority-relations-v0.1/latest"),
    )
    relations.add_argument(
        "--release-manifest",
        type=Path,
        default=Path("releases/authority-relations-v0.1.json"),
        help="frozen release manifest verified before adapters run",
    )
    subcommands.add_parser("authority-relations-verify-release")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "e004":
        json_path, markdown_path = write_e004(args.output_dir)
        print(f"Wrote {json_path} and {markdown_path}")
        return 0
    if args.command == "e005":
        json_path, markdown_path = write_e005(args.output_dir)
        print(f"Wrote {json_path} and {markdown_path}")
        return 0
    if args.command == "e007":
        json_path, markdown_path = write_e007(args.output_dir)
        print(f"Wrote {json_path} and {markdown_path}")
        return 0
    if args.command == "authority-relations-verify-release":
        manifest = verify_release_manifest(
            Path("releases/authority-relations-v0.1.json"), repository_root=Path.cwd()
        )
        print(
            f"Verified {manifest['release_tag']} "
            f"({manifest['vector_count']} vectors, {manifest['vector_manifest_hash']})"
        )
        return 0
    if args.command == "authority-relations":
        manifest = verify_release_manifest(
            args.release_manifest,
            repository_root=Path.cwd(),
            vector_dir=args.vector_dir,
        )
        using_reference_controls = not args.adapters
        adapters = args.adapters or [
            Path("adapters/delegation_only.py"),
            Path("adapters/relation_aware.py"),
        ]
        json_path, markdown_path, result = write_conformance(
            args.output_dir, vector_dir=args.vector_dir, adapters=adapters
        )
        print(f"Wrote {json_path} and {markdown_path}")
        if result["vector_manifest_hash"] != manifest["vector_manifest_hash"]:
            raise RuntimeError("run result does not match the frozen vector manifest")
        if not using_reference_controls:
            return (
                0 if all(run["passed"] == run["total"] for run in result["runs"]) else 1
            )
        by_adapter = {run["adapter"]: run for run in result["runs"]}
        aware = by_adapter["relation_aware.py"]
        limited = by_adapter["delegation_only.py"]
        mandate = next(
            case
            for case in limited["cases"]
            if case["vector_id"] == "AR-002-VALID-MANDATE"
        )
        controls_discriminate = (
            aware["passed"] == aware["total"]
            and limited["passed"] < limited["total"]
            and mandate["outcome"] == "FAIL"
        )
        return 0 if controls_discriminate else 1
    providers = list(ADAPTERS) if args.provider == "all" else [args.provider]
    for provider in providers:
        result = run_e001(provider)
        print(render_markdown(result))
        if not args.no_write:
            json_path, markdown_path = write_result(result, args.output_dir)
            print(f"Wrote {json_path} and {markdown_path}")
    return 0
