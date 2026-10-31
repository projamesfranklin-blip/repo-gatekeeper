#!/usr/bin/env python3
"""Download a repo into a throwaway folder (without running anything) and scan it.

Usage:  python3 scan_url.py https://github.com/owner/repo [--branch NAME]
Exit codes match gatekeeper.py: 0 green, 1 yellow, 2 red, 3 could not download.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scanner"))
import gatekeeper as gk  # noqa: E402

URL_RE = re.compile(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[\w.-]+/[\w.-]+?(\.git)?/?$")
BRANCH_RE = re.compile(r"^[\w./-]+$")


def normalize(url: str) -> str | None:
    """Turn the many ways people write a repo address into https://host/owner/repo."""
    url = url.strip().strip("'\"")
    m = re.match(r"^git@(github\.com|gitlab\.com|bitbucket\.org):([\w.-]+)/([\w.-]+?)(\.git)?$", url)
    if m:
        url = f"https://{m.group(1)}/{m.group(2)}/{m.group(3)}"
    if re.match(r"^[\w.-]+/[\w.-]+$", url):  # gh shorthand: owner/repo
        url = f"https://github.com/{url}"
    if not URL_RE.match(url):
        return None
    url = url.rstrip("/")
    return url[:-4] if url.endswith(".git") else url


def scan_url(url: str, branch: str | None = None, timeout: int = 150) -> tuple[str, str, int]:
    """Returns (level, markdown_report, exit_code). level is GREEN/YELLOW/RED/ERROR."""
    clean = normalize(url)
    if not clean:
        return "ERROR", f"Gatekeeper could not understand the repo address: {url}", 3
    if branch and not BRANCH_RE.match(branch):
        return "ERROR", f"Unusual branch name: {branch}", 3

    tmp = tempfile.mkdtemp(prefix="gatekeeper-")
    target = os.path.join(tmp, "repo")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "clone", "--quiet", "--depth", "1", "--no-recurse-submodules"]
    if branch:
        cmd += ["--branch", branch]
    cmd += [clean, target]
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1", GIT_TERMINAL_PROMPT="0")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if r.returncode != 0:
            return "ERROR", f"Gatekeeper could not download {clean} to check it:\n{r.stderr.strip()[:500]}", 3
        findings, stats = gk.scan_repo(Path(target))
        level, _, code = gk.verdict(findings)
        return level, gk.to_markdown(clean, findings, stats), code
    except subprocess.TimeoutExpired:
        return "ERROR", f"Gatekeeper timed out downloading {clean}.", 3
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 3
    branch = None
    if "--branch" in sys.argv:
        i = sys.argv.index("--branch")
        branch = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
    _, md, code = scan_url(sys.argv[1], branch)
    print(md)
    return code


if __name__ == "__main__":
    sys.exit(main())
