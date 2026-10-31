#!/usr/bin/env python3
"""Claude Code PreToolUse hook: scan any repo BEFORE Claude is allowed to clone it.

GREEN  -> clone continues normally
YELLOW -> you are asked to approve, with the findings shown
RED    -> the clone is blocked
"""
from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_url import scan_url  # noqa: E402


def find_clone_targets(command: str) -> list[tuple[str, str | None]]:
    """Find every `git clone <url>` / `gh repo clone <repo>` in a shell command."""
    targets = []
    for part in re.split(r"&&|\|\||;|\n|\|", command):
        try:
            words = shlex.split(part)
        except ValueError:
            words = part.split()
        if not words:
            continue
        # git [-c x=y ...] clone [opts] URL [dir]
        if "git" in words and "clone" in words:
            after = words[words.index("clone") + 1:]
            branch, i = None, 0
            while i < len(after):
                w = after[i]
                if w in ("-b", "--branch") and i + 1 < len(after):
                    branch = after[i + 1]; i += 2; continue
                if w.startswith("--branch="):
                    branch = w.split("=", 1)[1]; i += 1; continue
                if w in ("--depth", "-o", "--origin", "--reference", "-c", "--config",
                         "--template", "--separate-git-dir", "-j", "--jobs", "--filter"):
                    i += 2; continue
                if w.startswith("-"):
                    i += 1; continue
                targets.append((w, branch)); break
        # gh repo clone owner/repo [dir]
        elif len(words) >= 4 and words[0] == "gh" and words[1:3] == ["repo", "clone"]:
            targets.append((words[3], None))
    return targets


def respond(decision: str, reason: str) -> None:
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}))


def summarize(md: str, limit: int = 2500) -> str:
    return md if len(md) <= limit else md[:limit] + "\n…(report shortened)"


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0
    if event.get("tool_name") != "Bash":
        return 0
    command = (event.get("tool_input") or {}).get("command", "")
    targets = find_clone_targets(command)
    if not targets:
        return 0

    worst, reports = "GREEN", []
    rank = {"GREEN": 0, "YELLOW": 1, "ERROR": 1, "RED": 2}
    for url, branch in targets:
        level, md, _ = scan_url(url, branch)
        reports.append(md)
        if rank[level] > rank[worst]:
            worst = level

    joined = "\n\n".join(reports)
    if worst == "RED":
        respond("deny", "🛡️ Repo Gatekeeper BLOCKED this download - strong malware signs found. "
                        "Do not try another way to fetch this repo; tell the user what was found.\n\n"
                + summarize(joined))
    elif worst in ("YELLOW", "ERROR"):
        respond("ask", "🛡️ Repo Gatekeeper wants you to look first:\n\n" + summarize(joined))
    # GREEN: say nothing, the clone continues as normal.
    return 0


if __name__ == "__main__":
    sys.exit(main())
