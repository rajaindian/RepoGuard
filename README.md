# RepoGuard

**Scan any skill, plugin, or package before you install it. Know what it does before it runs on your machine.**

RepoGuard is a security scanner built for the age of AI agents. When you download a Claude Code skill, an MCP server, a VS Code extension, a GitHub Action, or any npm/pip package — RepoGuard scans it for malicious behavior and gives you a clear **RED / YELLOW / GREEN** verdict. No security expertise required. No API keys needed.

**Website:** [repoguard.org](https://repoguard.org)

---

## Why RepoGuard?

AI tools are making it easier than ever to discover and install skills, plugins, and packages. But every install is a trust decision — and most people can't read the code they're running.

- **Malicious skills** can read your files, steal API keys, and send them to a remote server
- **Compromised plugins** run install scripts that execute `curl | bash` on your machine
- **Typosquatted packages** look like popular libraries but contain data-stealing code
- **Obfuscated payloads** hide malicious logic behind base64 encoding and `eval()`

RepoGuard catches all of this — and explains it in plain English.

---

## Features

- **8 security rule categories** — covers data exfiltration, obfuscation, install scripts, backdoors, privacy violations, dependency risks, filesystem abuse, and supply-chain signals
- **Zero configuration** — no API keys, no accounts, no cloud services. Runs entirely locally.
- **JSON output** — pipe results to any AI tool (Claude Code, ChatGPT, etc.) for deeper review
- **PDF reports** — generates a detailed PDF with executive summary, per-category findings, and metadata
- **Terminal output** — colored risk bars, top findings, and a clear verdict at a glance
- **Two scan modes** — `strict` (catches everything) or `relaxed` (only high-confidence findings)
- **GitHub-aware** — fetches repo metadata (stars, age, fork status) to detect suspicious growth patterns
- **40+ file types supported** — JS, TS, Python, Go, Rust, Java, Ruby, PHP, shell scripts, config files, and more

---

## Quick Start

### Install

```bash
npm install -g repoguard
```

### Scan a GitHub repository

```bash
repoguard scan https://github.com/owner/repo
```

### Scan a local directory

```bash
repoguard scan ./path/to/project
```

### Scan a skill or plugin before installing

```bash
# Scan a Claude Code skill
repoguard scan https://github.com/author/some-claude-skill

# Scan an MCP server
repoguard scan https://github.com/author/mcp-server-xyz

# Scan any npm package source
repoguard scan https://github.com/author/some-package
```

### Get JSON output for AI review

Use `--json` to get machine-readable output that you can pipe to any AI tool:

```bash
repoguard scan https://github.com/author/skill --json
```

If you're using **Claude Code**, just ask it to run RepoGuard — Claude will scan the repo and review the findings for false positives, all without needing an API key.

---

## CLI Options

```
repoguard scan <target>

Arguments:
  target                GitHub URL or local directory path

Options:
  --mode <mode>         Scan sensitivity: strict (default) or relaxed
  --json                Output raw JSON (for piping to AI tools or other processors)
  --no-pdf              Skip PDF report generation
  --output <path>       Custom PDF output path
  --submit              Submit results to community database (coming soon)
```

---

## What It Detects

### Data Exfiltration
Reads sensitive files (`.env`, SSH keys, AWS credentials, `.npmrc`, browser cookies) and sends them to external servers via webhooks (Discord, Slack, Telegram) or HTTP POST requests.

### Obfuscation
Hides malicious behavior using `eval()`, `Function()`, base64/hex encoding, zero-width Unicode characters, high-entropy strings, or minified code blobs.

### Install Scripts
Dangerous package lifecycle hooks (`postinstall`, `preinstall`), `curl | bash` patterns, and `setup.py` scripts that execute system commands during installation.

### Backdoors
Reverse shells (`nc -e /bin/sh`, `net.Socket().connect()`), remote code execution via `fetch().eval()`, and unsanitized `child_process.exec()` calls.

### Privacy Violations
Unauthorized access to geolocation, clipboard, camera/microphone, canvas fingerprinting, keylogging, contact lists, tracking pixels, and beacon API usage.

### Dependency Risks
Typosquatting detection using Levenshtein distance against popular packages, and unpinned versions (`*`, `latest`) that could silently pull compromised releases.

### Filesystem Abuse
Path traversal (`../../`), access to system directories (`/etc/`, `C:\Windows`), privilege escalation (`sudo`, `chmod 777`), and writes to protected paths.

### Supply Chain Signals
Metadata-based analysis: suspicious star-to-age ratios, fork status warnings, and missing license files.

---

## How Scoring Works

Each category receives a **score from 0-10** based on:

```
score = sum of (severity_weight x confidence) per finding
```

| Severity | Weight |
|----------|--------|
| LOW      | 1      |
| MEDIUM   | 3      |
| HIGH     | 6      |
| CRITICAL | 10     |

The per-category score maps to a risk level:

| Score | Level  |
|-------|--------|
| 0     | NONE   |
| 1-3   | LOW    |
| 4-6   | MEDIUM |
| 7-10  | HIGH   |

**Final verdict:**
- **RED** — any category at HIGH level. Do not use this repository.
- **YELLOW** — any category at MEDIUM level. Review the flagged findings before using.
- **GREEN** — all categories at LOW or NONE. No significant risks detected.

---

## Example Output

```
  RepoGuard Report: sketchy-package
  Verdict: RED

  Data Exfiltration      █████████░  HIGH
  Obfuscated Code        ██████░░░░  MED
  Install Scripts        ████████░░  HIGH
  Backdoors              ░░░░░░░░░░  NONE
  Privacy Violations     ███░░░░░░░  LOW
  Dependency Risks       ░░░░░░░░░░  NONE
  Filesystem Access      █████░░░░░  MED
  Supply Chain Red Flags ██░░░░░░░░  LOW

  Top findings:
  ! postinstall script runs curl | bash  (package.json:8)
  ! Reads .env and POSTs to Discord webhook  (steal.js:12)
  * Base64-encoded payload passed to eval()  (utils.js:45)

  PDF report saved to ./repoguard-report-sketchy-package.pdf
```

---

## Using with AI Tools

RepoGuard does the heavy-lifting static analysis locally. For AI-powered false-positive filtering, use `--json` output with your favorite AI tool:

**With Claude Code:**
```bash
# Ask Claude to scan a skill before you install it
repoguard scan https://github.com/author/claude-skill --json
```

**With any LLM:**
```bash
repoguard scan ./downloaded-plugin --json > results.json
# Feed results.json to ChatGPT, Claude, Gemini, etc.
```

This design keeps RepoGuard dependency-free while letting you use any AI model for the review step.

---

## What Should You Scan?

- **Claude Code skills and plugins** before adding them to your workflow
- **MCP servers** before connecting them to your AI tools
- **VS Code / IDE extensions** (scan the source repo)
- **GitHub Actions** before adding them to your CI/CD
- **npm / pip / cargo packages** (scan the source repo before installing)
- **Any open-source repo** someone tells you to clone and run

---

## Development

```bash
# Clone the repo
git clone https://github.com/rajaindian/RepoGuard.git
cd RepoGuard

# Install dependencies
npm install

# Build
npm run build

# Run tests
npm test

# Type check
npm run lint
```

---

## Project Structure

```
src/
├── cli.ts              # CLI command definitions
├── scanner.ts          # Main scan orchestrator
├── index.ts            # Public API exports
├── input/
│   ├── handler.ts      # Input detection, cloning, validation
│   ├── github.ts       # GitHub API metadata fetching
│   └── constraints.ts  # Repo size/safety constraints
├── rules/
│   ├── engine.ts       # Rule engine (runs all modules)
│   ├── data-exfiltration.ts
│   ├── obfuscation.ts
│   ├── install-scripts.ts
│   ├── backdoors.ts
│   ├── privacy.ts
│   ├── dependencies.ts
│   ├── filesystem.ts
│   └── supply-chain.ts
├── scoring/
│   └── scorer.ts       # Scoring algorithm and verdict logic
└── output/
    ├── terminal.ts     # Colored terminal reports
    └── pdf.ts          # PDF report generation
```

---

## License

ISC
