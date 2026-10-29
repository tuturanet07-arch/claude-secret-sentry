#!/usr/bin/env python3
"""Block obvious credential material in Claude Code file writes and edits."""
from __future__ import annotations

import json
import re
import sys
from typing import Any

# Pattern checks catch common formats, not every possible secret. Never include
# matched text in output or denial messages.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b")),
    (
        "credential assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
            r"\s*[:=]\s*['\"]?(?!your[-_ ]|replace[-_ ]|example|changeme|<)[A-Za-z0-9_./+=-]{16,}"
        ),
    ),
)


def scan(event: dict[str, Any]) -> str | None:
    if event.get("tool_name") not in {"Write", "Edit", "MultiEdit"}:
        return None
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return None

    # Inspect only proposed content, never a file already on disk.
    fields = ("content", "new_string", "new_contents")
    proposed = "\n".join(
        value for key in fields if isinstance((value := tool_input.get(key)), str)
    )
    for label, pattern in PATTERNS:
        if pattern.search(proposed):
            return label
    return None


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Fail open on malformed input to avoid breaking normal editing.
        return 0

    finding = scan(event) if isinstance(event, dict) else None
    if finding:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"Secret Sentry blocked this file change: it resembles {finding}. "
                    "Move the value to a local environment variable or secret manager."
                ),
            }
        }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
