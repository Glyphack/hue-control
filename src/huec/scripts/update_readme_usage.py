#!/usr/bin/env python3
"""Update README Usage section from top-level CLI help."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent.parent.parent
README_PATH = ROOT / "README.md"
CLI_PATH = ROOT / "src" / "huec" / "main.py"


def get_top_level_help() -> str:
    env = os.environ.copy()
    env["COLUMNS"] = "80"
    return subprocess.check_output(
        [sys.executable, str(CLI_PATH), "--help"],
        cwd=ROOT,
        env=env,
        text=True,
    ).rstrip()


def build_usage_section(help_text: str) -> list[str]:
    return [
        "## Usage",
        "",
        "```text",
        "uv run main.py --help",
        help_text,
        "```",
        "",
    ]


def find_usage_bounds(readme_text: str) -> tuple[int, int, list[str]]:
    tokens = MarkdownIt().parse(readme_text)
    lines = readme_text.splitlines()
    start = -1
    end = len(lines)

    for index, token in enumerate(tokens):
        if token.type != "heading_open" or token.tag != "h2":
            continue
        if index + 1 >= len(tokens) or tokens[index + 1].type != "inline":
            continue
        if tokens[index + 1].content.strip() != "Usage":
            continue
        assert token.map
        start = token.map[0]
        break

    if start < 0:
        raise RuntimeError("Could not find '## Usage' in README.md.")

    for token in tokens:
        if (
            token.type == "heading_open"
            and token.tag == "h2"
            and token.map
            and token.map[0] > start
        ):
            end = token.map[0]
            break

    return start, end, lines


def main() -> int:
    readme_text = README_PATH.read_text(encoding="utf-8")
    usage_lines = build_usage_section(get_top_level_help())
    start, end, lines = find_usage_bounds(readme_text)
    updated = "\n".join(lines[:start] + usage_lines + lines[end:]).rstrip() + "\n"

    if updated == readme_text:
        print("README usage section is up to date.")
        return 0

    README_PATH.write_text(updated, encoding="utf-8")
    print("Updated README usage section.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
