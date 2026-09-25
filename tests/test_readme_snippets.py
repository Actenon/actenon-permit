"""Execute the README's code snippets verbatim.

The README is the first thing an evaluator runs. A snippet that raises is a
false claim, so the hero quickstart is executed exactly as printed and its
documented output is asserted.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"


def _python_block_after(heading: str) -> str:
    text = README.read_text(encoding="utf-8")
    start = text.index(heading)
    match = re.search(r"```python\n(.*?)```", text[start:], re.DOTALL)
    assert match is not None, f"no python block after {heading!r}"
    return match.group(1)


def test_readme_hero_quickstart_runs_as_documented(tmp_path):
    snippet = _python_block_after("## Hero quickstart")
    env = dict(os.environ)
    # Keep the auto-generated dev signing key out of the real home dir.
    env["HOME"] = str(tmp_path)
    env.pop("ACTENON_SIGNING_KEY", None)
    proc = subprocess.run(
        [sys.executable, "-c", snippet],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    # The snippet's own comment documents the expected output.
    assert proc.stdout.strip() == "succeeded  final"
