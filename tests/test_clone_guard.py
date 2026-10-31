"""Tests for the Claude Code hook that guards `git clone`."""
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import clone_guard as cg  # noqa: E402
import scan_url as su  # noqa: E402


class FindTargets(unittest.TestCase):
    def test_plain_clone(self):
        self.assertEqual(cg.find_clone_targets("git clone https://github.com/a/b"),
                         [("https://github.com/a/b", None)])

    def test_options_branch_and_chain(self):
        cmd = "cd /tmp && git clone --depth 1 -b dev https://github.com/a/b.git mydir && ls"
        self.assertEqual(cg.find_clone_targets(cmd), [("https://github.com/a/b.git", "dev")])

    def test_gh_clone(self):
        self.assertEqual(cg.find_clone_targets("gh repo clone a/b"), [("a/b", None)])

    def test_not_a_clone(self):
        self.assertEqual(cg.find_clone_targets("git status && echo clone"), [])


class Normalize(unittest.TestCase):
    def test_forms(self):
        for raw in ["https://github.com/a/b", "https://github.com/a/b.git", "git@github.com:a/b.git", "a/b"]:
            self.assertEqual(su.normalize(raw), "https://github.com/a/b")

    def test_rejects_weird(self):
        for raw in ["https://evil.example/a/b", "file:///etc", "https://github.com/a/b;rm -rf /"]:
            self.assertIsNone(su.normalize(raw))


def run_hook(command, level):
    event = {"tool_name": "Bash", "tool_input": {"command": command}}
    out = io.StringIO()
    with mock.patch.object(cg, "scan_url", return_value=(level, f"report {level}", 0)), \
         mock.patch("sys.stdin", io.StringIO(json.dumps(event))), redirect_stdout(out):
        cg.main()
    return json.loads(out.getvalue())["hookSpecificOutput"] if out.getvalue() else None


class Decisions(unittest.TestCase):
    def test_red_blocks(self):
        self.assertEqual(run_hook("git clone https://github.com/a/b", "RED")["permissionDecision"], "deny")

    def test_yellow_asks(self):
        self.assertEqual(run_hook("git clone https://github.com/a/b", "YELLOW")["permissionDecision"], "ask")

    def test_download_error_asks(self):
        self.assertEqual(run_hook("git clone https://github.com/a/b", "ERROR")["permissionDecision"], "ask")

    def test_green_silent(self):
        self.assertIsNone(run_hook("git clone https://github.com/a/b", "GREEN"))

    def test_other_commands_ignored(self):
        self.assertIsNone(run_hook("ls -la", "RED"))


if __name__ == "__main__":
    unittest.main()
