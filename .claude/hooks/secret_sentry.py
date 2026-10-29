#!/usr/bin/env python3
"""Block common credential patterns in proposed Claude Code file edits."""
import json, re, sys
event=json.load(sys.stdin)
tool_input=event.get("tool_input", {}) if isinstance(event, dict) else {}
proposed="\n".join(value for key in ("content", "new_string", "new_contents") if isinstance((value := tool_input.get(key)), str)) if isinstance(event, dict) and event.get("tool_name") in {"Write", "Edit", "MultiEdit"} and isinstance(tool_input, dict) else ""
patterns=(("private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"), ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), ("OpenAI API key", r"\bsk-[A-Za-z0-9_-]{24,}\b"), ("credential assignment", r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*['\"]?(?!your[-_ ]|replace[-_ ]|example|changeme|<)[A-Za-z0-9_./+=-]{16,}"))
finding=next((label for label, pattern in patterns if re.search(pattern, proposed)), None)
print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": f"Secret Sentry blocked this file change: it resembles {finding}. Move the value to a local environment variable or secret manager."}})) if finding else None
