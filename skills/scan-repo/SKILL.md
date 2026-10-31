---
name: scan-repo
description: Scan a GitHub/GitLab/Bitbucket repo for malware tricks (remote code, hidden code, data theft, backdoors, miners, install traps, AI-agent prompt injection) WITHOUT running it. Use when the user asks whether a repo is safe, wants to vet a repo, or before downloading/installing/opening someone else's code.
argument-hint: <repo-url> [--branch NAME]
---

# Scan a repo with Repo Gatekeeper

1. Run the scanner (it downloads to a throwaway folder, reads files only, then deletes it):

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/scan_url.py" $ARGUMENTS
   ```

   If `${CLAUDE_PLUGIN_ROOT}` is empty, locate the script with
   `find ~/.claude/plugins -name scan_url.py -path '*repo-gatekeeper*' | head -1`.

2. Show the user the verdict line first (🟢 / 🟡 / 🔴) and the scorecard table.
3. For each finding, explain in one plain-English sentence what it means and whether it looks
   like a real threat or a normal thing for this kind of project (e.g. a `postinstall` that just
   builds code is normal; one that downloads from an unknown server is not).
4. Exit code 2 (RED): tell the user NOT to download, install, or run the repo, and do not fetch it
   another way. Exit code 3: the download failed; say so and do not guess a verdict.
5. Remind the user that 🟢 means no known tricks were found, not a guarantee.
