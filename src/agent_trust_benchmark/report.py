from __future__ import annotations

import json
from pathlib import Path

from .models import RunResult


def render_markdown(result: RunResult) -> str:
    lines = [
        f"# E001 result: {result.provider}",
        "",
        f"- Run: `{result.run_id}`",
        f"- Started: `{result.started_at}`",
        f"- Completed: `{result.completed_at}`",
        "",
        "| Output | Status | Evidence-led explanation |",
        "|---|---|---|",
    ]
    for check in result.checks:
        detail = check.detail.replace("|", "\\|")
        lines.append(f"| `{check.check.value}` | **{check.status.value}** | {detail} |")
    lines.extend(["", "## Metrics", ""])
    for key, value in result.metrics.items():
        lines.append(f"- `{key}`: `{value}`")
    if result.limitations:
        lines.extend(["", "## Named limitations", ""])
        lines.extend(f"- {item}" for item in result.limitations)
    lines.extend(["", "No raw credential, token, signature, or private key is included in this result.", ""])
    return "\n".join(lines)


def write_result(result: RunResult, output_root: Path) -> tuple[Path, Path]:
    target = output_root / result.run_id
    target.mkdir(parents=True, exist_ok=False)
    json_path = target / "result.json"
    markdown_path = target / "SUMMARY.md"
    json_path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n")
    markdown_path.write_text(render_markdown(result))
    return json_path, markdown_path
