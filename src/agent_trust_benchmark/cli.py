from __future__ import annotations

import argparse
from pathlib import Path

from .experiment import ADAPTERS, run_e001
from .e004 import write_e004
from .e005 import write_e005
from .report import render_markdown, write_result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="benchmark", description="Vendor-neutral agent trust benchmark")
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
    providers = list(ADAPTERS) if args.provider == "all" else [args.provider]
    for provider in providers:
        result = run_e001(provider)
        print(render_markdown(result))
        if not args.no_write:
            json_path, markdown_path = write_result(result, args.output_dir)
            print(f"Wrote {json_path} and {markdown_path}")
    return 0
