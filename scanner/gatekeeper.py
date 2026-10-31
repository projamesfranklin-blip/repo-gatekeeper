#!/usr/bin/env python3
"""
Repo Gatekeeper - checks a downloaded repository for malware tricks
WITHOUT running any of its code. It only reads files as text/bytes.

Usage:
    python3 gatekeeper.py <path-to-cloned-repo> [--json out.json] [--markdown out.md]

Exit codes:
    0 = GREEN  (no warning signs found)
    1 = YELLOW (things a human should look at)
    2 = RED    (strong malware signs - do not run this repo)
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"
SEVERITY_ICON = {HIGH: "🔴", MEDIUM: "🟡", LOW: "⚪"}

MAX_TEXT_BYTES = 2_000_000  # skip reading huge files as text
SKIP_DIRS = {".git"}

BINARY_EXTS = {
    ".exe", ".dll", ".scr", ".msi", ".com", ".vbs", ".hta", ".lnk",
    ".so", ".dylib", ".bin", ".jar", ".apk", ".dmg", ".pkg",
}
WINDOWS_SCRIPT_EXTS = {".bat", ".cmd", ".ps1"}
SOURCE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".ps1",
               ".php", ".rb", ".lua", ".pl", ".go", ".rs", ".java", ".c", ".cpp", ".cs",
               ".bat", ".cmd", ".json", ".yml", ".yaml", ".toml", ".md", ".html"}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    file: str
    line: int
    snippet: str
    why: str


@dataclass
class Rule:
    category: str
    title: str
    severity: str
    pattern: re.Pattern
    why: str
    only_exts: set[str] | None = None
    only_names: set[str] | None = None


def rx(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Line-by-line text rules. Each rule = "if a line looks like this, flag it".
# ---------------------------------------------------------------------------
RULES: list[Rule] = [
    # --- Downloads code from the internet and runs it immediately ---
    Rule("Remote code", "Downloads a script and runs it", HIGH,
         rx(r"(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|"
            r"(curl|wget)\b[^\n|]*\|\s*(python|node|perl)\b|"
            r"iex\s*\(\s*(new-object\s+net\.webclient|iwr|invoke-webrequest)"),
         "Fetches code from a server and executes it - the server can send anything, any time."),
    # --- Hidden / encoded code being executed ---
    Rule("Obfuscation", "Runs hidden (base64-encoded) code", HIGH,
         rx(r"(eval|exec|Function)\s*\(\s*(atob|Buffer\.from|base64\.b64decode|"
            r"codecs\.decode|bytes\.fromhex|zlib\.decompress|marshal\.loads)|"
            r"base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|"
            r"powershell[^\n]*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}"),
         "Code is disguised so you can't read it, then executed. Legit projects rarely need this."),
    Rule("Obfuscation", "Builds code from character codes", MEDIUM,
         rx(r"(String\.fromCharCode\s*\((\s*\d+\s*,){15,}|(\\x[0-9a-f]{2}){30,})"),
         "Long chains of character codes are a common way to hide malicious strings."),
    # --- Steals credentials / data ---
    Rule("Data theft", "Touches saved passwords, keys, or crypto wallets", HIGH,
         rx(r"(\.ssh/id_(rsa|ed25519)|\.aws/credentials|Login Data|Local State|"
            r"Cookies\.sqlite|wallet\.dat|Exodus|Metamask|nkbihfbeogaeaoehlefnkodbefgpgknn|"
            r"\.config/gcloud|keychain-db|\.git-credentials|\.npmrc|discord.*Local Storage)"),
         "Malware 'stealers' read browser passwords, SSH keys, cloud keys, and crypto wallets."),
    Rule("Data theft", "Sends data to a Discord/Telegram bot", HIGH,
         rx(r"(discord(app)?\.com/api/webhooks/|api\.telegram\.org/bot)"),
         "Discord/Telegram webhooks are the #1 way stolen data is shipped to attackers."),
    Rule("Data theft", "Reads ALL environment variables and sends them out", MEDIUM,
         rx(r"(JSON\.stringify\(\s*process\.env\s*\)|"
            r"(dict\(\s*os\.environ\s*\)|os\.environ\.copy\(\))[^\n]*(post|send|request|urlopen))"),
         "Environment variables often hold API keys and tokens."),
    # --- Remote control of your computer ---
    Rule("Backdoor", "Opens a remote shell (reverse shell)", HIGH,
         rx(r"(/dev/tcp/\d|nc(at)?\s+(-\w+\s+)*-e\s+/bin/|bash\s+-i\s*>&|"
            r"socket\.socket\([^\n]*\)[^\n]*subprocess|pty\.spawn\(\s*['\"]/bin/(ba)?sh)"),
         "Gives an attacker a live command line on your machine."),
    Rule("Backdoor", "Installs itself to run at startup", MEDIUM,
         rx(r"(CurrentVersion\\\\?Run|LaunchAgents/|crontab\s+-|schtasks\s+/create|"
            r"systemctl\s+enable|\.bashrc|\.zshrc|Startup\\\\?)"),
         "Persistence: makes something run every time you log in or reboot."),
    # --- Crypto miners ---
    Rule("Crypto miner", "Cryptocurrency miner", HIGH,
         rx(r"(xmrig|stratum\+tcp://|coinhive|cryptonight|minexmr|nicehash)"),
         "Uses your computer's power to mine crypto for someone else."),
    # --- Sneaky install hooks ---
    Rule("Install hooks", "Runs a script automatically on install", MEDIUM,
         rx(r"\"(preinstall|install|postinstall|prepare)\"\s*:"),
         "Code here runs the moment you type 'npm install' - read it before installing.",
         only_names={"package.json"}),
    Rule("Install hooks", "setup.py runs commands or reaches the internet", MEDIUM,
         rx(r"(subprocess|os\.system|urllib|requests\.|socket|cmdclass)"),
         "Python packages can run code during 'pip install'.",
         only_names={"setup.py"}),
    Rule("Install hooks", "Editor auto-runs a task when the folder is opened", HIGH,
         rx(r"\"runOn\"\s*:\s*\"folderOpen\""),
         "Just OPENING this folder in VS Code/Cursor runs a command. Known attack trick.",
         only_names={"tasks.json"}),
    # --- AI agent traps (relevant if you open repos with Claude/Cursor/Copilot) ---
    Rule("AI agent trap", "Hidden instructions aimed at AI assistants", HIGH,
         rx(r"(ignore (all |any )?(previous|prior|above) instructions|"
            r"do not (tell|inform|mention to) the user|without asking the user|"
            r"you are now in (developer|god|jailbreak) mode|"
            r"silently (run|execute|send|upload))"),
         "Prompt injection: text that tries to trick your AI tool into doing something you didn't ask."),
    Rule("AI agent trap", "Pre-configured AI tool hooks / MCP servers", MEDIUM,
         rx(r"\"(hooks|mcpServers|command)\"\s*:"),
         "This repo ships settings that make your AI assistant run commands or connect to servers.",
         only_names={"settings.json", "settings.local.json", ".mcp.json", "mcp.json"}),
    # --- Exposed secrets (their problem, but a sign of a sloppy repo) ---
    Rule("Hygiene", "Private key or cloud key committed", LOW,
         rx(r"(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16})"),
         "Not dangerous to you, but shows the author is careless with security."),
]

# Characters that make code look different from what it does ("Trojan Source").
HIDDEN_UNICODE = re.compile("[‪-‮⁦-⁩​‌‍⁠﻿]")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8000]


def executable_magic(data: bytes) -> str | None:
    if data[:2] == b"MZ":
        return "Windows program (.exe/.dll)"
    if data[:4] == b"\x7fELF":
        return "Linux program (ELF)"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macOS program (Mach-O)"
    return None


def clip(s: str, n: int = 160) -> str:
    s = s.strip()
    return s if len(s) <= n else s[:n] + "…"


def scan_repo(root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    stats = {"files_scanned": 0, "files_skipped_large": 0}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            if path.is_symlink():
                target = os.readlink(path)
                if os.path.isabs(target) or ".." in Path(target).parts:
                    findings.append(Finding(MEDIUM, "Sneaky files", "Link points outside the repo",
                                            rel, 0, f"-> {target}",
                                            "Symlinks out of the project can be used to read or overwrite your files."))
                continue
            try:
                size = path.stat().st_size
                with open(path, "rb") as fh:
                    data = fh.read(MAX_TEXT_BYTES)
            except OSError:
                continue
            stats["files_scanned"] += 1
            ext = path.suffix.lower()

            magic = executable_magic(data)
            if magic or ext in BINARY_EXTS:
                findings.append(Finding(MEDIUM, "Sneaky files", "Ready-to-run program included",
                                        rel, 0, magic or f"{ext} file",
                                        "Source-code projects shouldn't need pre-built programs. You can't read what they do."))
            elif ext in WINDOWS_SCRIPT_EXTS:
                findings.append(Finding(LOW, "Sneaky files", "Windows script included", rel, 0, f"{ext} file",
                                        "Usually harmless build helpers, but read it before double-clicking."))
            if is_binary(data):
                continue
            if size > MAX_TEXT_BYTES:
                stats["files_skipped_large"] += 1

            text = data.decode("utf-8", errors="replace")
            for lineno, line in enumerate(text.splitlines(), 1):
                for rule in RULES:
                    if rule.only_names and name not in rule.only_names:
                        continue
                    if rule.only_exts and ext not in rule.only_exts:
                        continue
                    if rule.pattern.search(line):
                        findings.append(Finding(rule.severity, rule.category, rule.title,
                                                rel, lineno, clip(line), rule.why))
                if ext in SOURCE_EXTS and HIDDEN_UNICODE.search(line.lstrip("\ufeff") if lineno == 1 else line):
                    findings.append(Finding(HIGH, "Obfuscation", "Invisible characters hide what code really does",
                                            rel, lineno, clip(line.encode("unicode_escape").decode()),
                                            "'Trojan Source' trick: code looks safe on screen but runs differently."))
                if ext in SOURCE_EXTS and len(line) > 1000 and entropy(line) > 5.0 \
                        and not name.endswith((".min.js", ".min.mjs")):
                    findings.append(Finding(MEDIUM, "Obfuscation", "Huge scrambled line of code",
                                            rel, lineno, clip(line, 80),
                                            "Very long random-looking code lines often hide payloads."))

    # De-duplicate (same rule hitting same file many times -> keep first 5)
    seen: dict[tuple, int] = {}
    deduped = []
    for f in findings:
        key = (f.title, f.file)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] <= 5:
            deduped.append(f)
    order = {HIGH: 0, MEDIUM: 1, LOW: 2}
    deduped.sort(key=lambda f: (order[f.severity], f.category, f.file, f.line))
    return deduped, stats


def verdict(findings: list[Finding]) -> tuple[str, str, int]:
    if any(f.severity == HIGH for f in findings):
        return "RED", "🔴 DO NOT RUN - strong signs of malware or tricks", 2
    if any(f.severity == MEDIUM for f in findings):
        return "YELLOW", "🟡 REVIEW FIRST - look at the flagged files before using", 1
    return "GREEN", "🟢 LOOKS CLEAN - no warning signs found", 0


CATEGORIES = ["Remote code", "Obfuscation", "Data theft", "Backdoor", "Crypto miner",
              "Install hooks", "AI agent trap", "Sneaky files", "Hygiene"]


def to_markdown(target: str, findings: list[Finding], stats: dict) -> str:
    _, headline, _ = verdict(findings)
    out = [f"# Repo Gatekeeper report", "", f"**Repo:** `{target}`", "", f"## {headline}", ""]
    out += ["### Scorecard", "", "| Check | Result |", "|---|---|"]
    for cat in CATEGORIES:
        hits = [f for f in findings if f.category == cat]
        if not hits:
            icon = "🟢 clear"
        else:
            worst = min(hits, key=lambda f: {HIGH: 0, MEDIUM: 1, LOW: 2}[f.severity]).severity
            icon = f"{SEVERITY_ICON[worst]} {len(hits)} found"
        out.append(f"| {cat} | {icon} |")
    out += ["", f"_Scanned {stats['files_scanned']} files. No code from the repo was executed._", ""]
    if findings:
        out += ["### What was found", ""]
        for f in findings:
            loc = f"{f.file}:{f.line}" if f.line else f.file
            out += [f"<details><summary>{SEVERITY_ICON[f.severity]} <b>{f.title}</b> - <code>{loc}</code></summary>",
                    "", f"**Why it matters:** {f.why}", "", "```", f.snippet.replace("```", "ˋˋˋ"), "```",
                    "</details>", ""]
    out += ["---", "⚠️ A green result means no *known* tricks were found - not a guarantee. "
            "Only run code from people you trust, and prefer running it in a sandbox first."]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan a repo for malware tricks without running it.")
    ap.add_argument("path")
    ap.add_argument("--name", help="Display name for the report (e.g. the GitHub URL)")
    ap.add_argument("--json")
    ap.add_argument("--markdown")
    args = ap.parse_args()

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Not a folder: {root}", file=sys.stderr)
        return 3
    findings, stats = scan_repo(root)
    level, headline, code = verdict(findings)
    md = to_markdown(args.name or str(root), findings, stats)

    if args.markdown:
        Path(args.markdown).write_text(md, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps({"verdict": level, "stats": stats,
                                               "findings": [asdict(f) for f in findings]}, indent=2))
    print(md)
    return code


if __name__ == "__main__":
    sys.exit(main())
