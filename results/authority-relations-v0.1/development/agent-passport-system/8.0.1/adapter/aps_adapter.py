#!/usr/bin/env python3
"""ATB authority-relations-v0.1 entrypoint. The runner launches adapters with its own
Python interpreter, so this file only forwards stdin/stdout/stderr to the Node adapter
that calls the agent-passport-system SDK."""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
completed = subprocess.run(
    ["node", str(HERE / "aps_adapter.mjs")],
    input=sys.stdin.buffer.read(),
    capture_output=True,
    cwd=HERE,
    check=False,
)
sys.stderr.buffer.write(completed.stderr)
sys.stdout.buffer.write(completed.stdout)
sys.exit(completed.returncode)
