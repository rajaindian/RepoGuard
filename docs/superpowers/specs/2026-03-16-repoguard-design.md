# RepoGuard - Design Specification

## Overview

RepoGuard is a security scanner that helps no-coders and vibecoders screen GitHub repositories for malicious code, data theft, privacy violations, and other risks before using them. It combines a static rule engine with AI-powered analysis (Claude) for comprehensive threat detection.

## Product Goals

- Protect non-technical users from malicious or risky GitHub repositories
- Provide clear, jargon-free security assessments with actionable recommendations
- Build a community trust layer for GitHub repos through aggregated scan results
- Work as both a Claude Code skill and a standalone CLI tool

## Target Users

No-coders and vibecoders who download code, templates, tools, and skills from GitHub without the expertise to review code for security risks themselves.

## Input

- **GitHub URL**: User provides a repo URL; tool clones to a temp directory, scans, and cleans up
- **Local path**: User points to an already-downloaded directory
- Auto-detection: the tool determines which input type based on format

### Input Constraints

- **Private repos**: Supported via the user's existing git credential helper (SSH keys, `gh auth`, git credential manager). No separate `--token` flag needed — if `git clone` works on the user's machine, RepoGuard works.
- **Shallow clone**: Always uses `--depth 1` to minimize download size and time
- **Repo size limit**: Skips repos exceeding 500MB or 50K files with a clear error message suggesting the user clone manually and use local path mode
- **Submodules**: Not recursively cloned by default. Flagged as a notice ("This repo has submodules that were not scanned")
- **LFS objects**: Not fetched. LFS pointers are noted but not resolved
- **Binary files**: Skipped for content analysis but flagged if executable binaries are found in unexpected locations (e.g., `.exe`, `.dll`, `.so` in a JavaScript project). Their presence counts toward the obfuscation/supply chain category
- **Symlinks**: Resolved only within the repo directory. Symlinks pointing outside the repo are flagged as suspicious and not followed
- **Empty repos**: Scan exits early with a "nothing to scan" message

## Architecture

### Three-Layer Design

```
INPUT LAYER  →  ANALYSIS ENGINE  →  OUTPUT LAYER
```

### Input Handler

- Detects if input is a URL or local path
- For URLs: clones repo to a temp directory, cleans up after scan
- For local paths: validates the directory exists and contains code
- Collects repo metadata from GitHub API if available (stars, age, contributors, fork info)

### Analysis Engine

#### Layer 1: Static Rule Engine

A set of rule modules covering all 8 risk categories. Each rule returns structured findings:

```typescript
interface Finding {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: RiskCategory;
  file: string;
  line: number;
  description: string;
  evidence: string;
  confidence: number; // 0-1
}
```

Rules are defined in config files so they can be extended without code changes. Rules are bundled with the npm package; new rules ship with tool updates.

**Network requirements**: The static engine runs locally except for: dependency vulnerability lookups (OSV API), and GitHub API calls for repo metadata. If network is unavailable, these checks are skipped and the report notes which checks were incomplete.

Components:
- **Pattern matcher**: Regex-based rules for known malicious patterns
- **Entropy analyzer**: Detects encoded payloads via Shannon entropy
- **File scanner**: Identifies sensitive file access patterns
- **Dependency checker**: Cross-references against OSV / advisory databases
- **Metadata analyzer**: Evaluates repo age, stars, contributor patterns

#### Layer 2: AI Review (Claude)

- Receives: static findings + repo code (packed via Repomix for token efficiency)
- Validates/filters static findings (reduces false positives)
- Performs holistic intent analysis of the codebase
- Generates plain-English explanations for each finding
- Produces severity scores and final verdict
- **Default model**: Claude Sonnet (balance of speed, cost, and quality). User can override via `--model` flag or `REPOGUARD_MODEL` env var
- **Large repo strategy**: If packed output exceeds context window, prioritize: (1) files flagged by static engine, (2) entry points and install scripts, (3) files matching high-risk patterns. Remaining files get static-only analysis
- **Graceful degradation**: If no API key is available, tool works with static engine only and warns user that analysis is partial

### Output Layer

Three output targets:

1. **Terminal summary**: Traffic light verdict + top findings + category risk bars
2. **PDF report**: Full detailed report with executive summary, per-category findings, and repo metadata
3. **Community submission**: Optional submission of findings to community trust database (no source code leaves the machine)

## Security Check Categories

### 1. Data Exfiltration & Theft
- Code that reads sensitive files (`.env`, credentials, SSH keys, browser cookies/passwords, wallet files)
- Outbound HTTP/network calls to non-standard endpoints (especially POST requests with file/env data)
- Webhook URLs (Discord, Slack, Telegram bots) used as data sinks
- Hardcoded IP addresses or suspicious domains

### 2. Obfuscated / Hidden Code
- Base64-encoded strings that decode to code or URLs
- Hex-encoded payloads
- `eval()`, `exec()`, `Function()` with dynamically constructed strings
- Minified code in repos where everything else is readable
- Unicode tricks / zero-width characters hiding code
- High-entropy strings (likely encoded payloads)

### 3. Malicious Install/Build Scripts
- `postinstall`, `preinstall` scripts in `package.json` that run code
- `setup.py` / `setup.cfg` with code execution during install
- Build scripts that download and execute remote code
- Makefiles or shell scripts with unexpected behavior (curl | bash patterns)

### 4. Backdoors & Remote Code Execution
- Reverse shells or socket connections to external servers
- Code that downloads and executes remote payloads at runtime
- Hidden API endpoints or admin routes with no authentication
- Cron jobs or scheduled tasks that phone home

### 5. Privacy Violations
- Tracking pixels / analytics without disclosure
- Code collecting device fingerprints, geolocation, contacts
- Clipboard monitoring or keylogging patterns
- Camera/microphone access requests without clear purpose
- Data sent to third parties without consent mechanisms

### 6. Dependency Risks
- Known vulnerabilities via OSV / GitHub Advisory Database
- Typosquatting detection (packages named similar to popular ones)
- Pinned vs unpinned dependency versions
- Dependencies with very low download counts or recent ownership transfers
- Excessive permissions requested by dependencies

### 7. Filesystem & System Access
- Code that reads/writes outside its own directory
- Access to system directories, browser profiles, credential stores
- Attempts to modify system configuration
- Privilege escalation patterns (sudo, admin requests)

### 8. Supply Chain Red Flags
- Repository freshness vs star count mismatch (10K stars, created last week)
- Contributor patterns (single anonymous contributor)
- Recent suspicious commits (last commit adds obfuscated code to otherwise clean repo)
- Forked from known repo but with unexplained modifications
- Missing or permissive license (legal risk)

## Scoring System

Each of the 8 risk categories gets a score from 0-10:

| Score | Level | Meaning |
|-------|-------|---------|
| 0 | NONE | No issues detected |
| 1-3 | LOW | Minor concerns, likely safe |
| 4-6 | MEDIUM | Worth reviewing before using |
| 7-10 | HIGH | Significant risk detected |

**Overall verdict** derived from category scores:
- **GREEN**: All categories LOW or NONE
- **YELLOW**: Any category MEDIUM, none HIGH
- **RED**: Any category HIGH

## False Positive Strategy

- Default mode: **strict** (err on side of caution, flag anything remotely suspicious)
- Optional mode: **relaxed** (only flag findings with confidence >= 0.7)
- AI layer helps filter false positives from the static engine by understanding context and intent

### Confidence Score Usage

The `confidence` field (0-1) on each finding is used as follows:
- **Strict mode**: All findings shown regardless of confidence, but confidence is displayed so users can gauge reliability
- **Relaxed mode**: Only findings with confidence >= 0.7 are included in the report
- **Scoring**: Category scores are weighted by confidence — a HIGH severity finding at 0.3 confidence contributes less to the category score than one at 0.9
- **AI refinement**: The AI layer adjusts confidence scores from the static engine based on contextual analysis

## User Experience

### Claude Code Skill

```
/repoguard https://github.com/someone/cool-tool
```

Outputs:
1. Progress indicators for each scan phase
2. Terminal summary with traffic light verdict, category risk bars, and top findings in plain English
3. Recommendation (use / use with caution / do not use)
4. PDF report auto-saved to current directory
5. Optional prompt to submit findings to community database

### Standalone CLI

```bash
# Install
npm install -g repoguard

# Scan a GitHub repo
repoguard scan https://github.com/someone/cool-tool

# Scan local directory
repoguard scan ./my-downloaded-project

# Relaxed mode
repoguard scan ./project --mode relaxed

# Auto-submit to community
repoguard scan ./project --submit

# Check community ratings
repoguard lookup https://github.com/someone/cool-tool

# Static analysis only (no AI, no API key needed)
repoguard scan ./project --no-ai
```

## Terminal Output Format

```
╔══════════════════════════════════════════╗
║  RepoGuard Report: someone/cool-tool     ║
╠══════════════════════════════════════════╣
║  Verdict:  RED - HIGH RISK               ║
╠══════════════════════════════════════════╣
║                                          ║
║  Data Exfiltration      ██████████  HIGH  ║
║  Obfuscated Code        ██████░░░░  MED   ║
║  Install Scripts        ████░░░░░░  LOW   ║
║  Backdoors              ░░░░░░░░░░  NONE  ║
║  Privacy Violations     ██████████  HIGH  ║
║  Dependency Risks       ████░░░░░░  LOW   ║
║  Filesystem Access      ██████░░░░  MED   ║
║  Supply Chain Red Flags ████░░░░░░  LOW   ║
║                                          ║
╠══════════════════════════════════════════╣
║  Top Findings:                           ║
║                                          ║
║  ! src/utils/analytics.js sends your     ║
║    .env file contents to an external     ║
║    server (webhook.evil.com)             ║
║                                          ║
║  ! lib/helper.min.js contains            ║
║    obfuscated code that doesn't match    ║
║    the rest of the codebase              ║
║                                          ║
║  * postinstall script runs a curl        ║
║    command that downloads remote code    ║
║                                          ║
╠══════════════════════════════════════════╣
║  Recommendation: DO NOT USE this repo.   ║
║  Multiple high-confidence indicators of  ║
║  intentional data theft detected.        ║
╚══════════════════════════════════════════╝

Full PDF report saved to: ./repoguard-report-cool-tool.pdf
```

## PDF Report Structure

- **Page 1 - Executive Summary**: Traffic light verdict, category risk bars (visual), top 3 findings in plain English, recommendation
- **Pages 2-N - Detailed Findings**: One section per risk category. Each finding shows: what was found (plain English), where (file + line), why it's risky, severity, confidence level
- **Final Page - Repo Metadata**: Stars, age, contributors, fork status, dependency count and vulnerability summary, scan timestamp and mode

## Community Trust Database

### Submission Data

No source code is submitted. Note: `findings_summary` may contain file paths and domain names from the scanned repo, which is necessary for the community to understand what was found. Users are shown the exact payload before submission and can opt out. Submitted data:

```json
{
  "repo_url": "https://github.com/someone/cool-tool",
  "scan_timestamp": "2026-03-16T18:00:00Z",
  "verdict": "RED",
  "category_scores": {
    "data_exfiltration": 9,
    "obfuscated_code": 6,
    "install_scripts": 3,
    "backdoors": 0,
    "privacy_violations": 8,
    "dependency_risks": 3,
    "filesystem_access": 5,
    "supply_chain": 2
  },
  "findings_summary": ["Sends .env to external server", "Obfuscated code in helper.min.js"],
  "scan_mode": "strict",
  "ai_used": true,
  "tool_version": "1.0.0"
}
```

### Community Features

- **Aggregated trust scores**: Multiple scans of the same repo build confidence. Trust score is a weighted average — not easily gamed by a single submission
- **Anti-gaming measures**: Rate limiting per IP, submissions weighted by scanner history (consistent scanners get higher weight), anomaly detection for sudden verdict changes, minimum scan count before publishing a trust score
- **Search/lookup**: Anyone can check if a repo has been scanned and see aggregated results
- **Rated directory**: Repos ranked by trust score, searchable by URL

### Community API (Phase 2)

The community website and API will be built as a separate phase after the core scanner is stable. In Phase 1, `--submit` and `lookup` commands will display a "coming soon" message with a link to follow for updates.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| CLI tool | Node.js (TypeScript) |
| Rule engine | Custom modules, regex + file analysis |
| Dependency checking | OSV API, npm audit, pip-audit |
| AI layer | Claude API via Anthropic SDK |
| Repo packing | Repomix |
| PDF generation | pdfkit (lightweight, no Chromium dependency) |
| Claude Code skill | Skill wrapper calling the CLI |
| Community API | REST API (Phase 2) |

## Phasing

### Phase 1: Core Scanner
- Input handler (GitHub URL + local path)
- Static rule engine (all 8 categories)
- AI review layer (Claude integration)
- Terminal output with traffic light verdict
- PDF report generation
- CLI tool published to npm

### Phase 2: Claude Code Skill
- Skill wrapper for the CLI
- Integrated into Claude Code workflow
- Progress indicators and formatted output

### Phase 3: Community Trust Database
- REST API for submission and lookup
- Aggregated trust scoring
- `--submit` and `lookup` commands activated
- Community website for browsing ratings

## Language / Ecosystem Scope

Phase 1 focuses on language-agnostic pattern detection that works across all codebases. Ecosystem-specific checks included in Phase 1:

- **JavaScript/TypeScript**: `package.json` script analysis, npm dependency checks
- **Python**: `setup.py`/`pyproject.toml` analysis, pip dependency checks

Future phases may add: Go, Rust, Ruby, PHP, Java/Kotlin. Unknown file types are still scanned by the pattern matcher and entropy analyzer — only ecosystem-specific dependency/build script checks are language-gated.

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Invalid/404 GitHub URL | Clear error: "Repository not found. Check the URL and try again." |
| Clone fails (network, auth) | Error with suggestion: "Clone failed. If this is a private repo, ensure your git credentials are configured." |
| Repo exceeds size limit | Error: "This repo is too large for remote scanning (>500MB). Clone it locally and use: `repoguard scan ./path`" |
| Claude API error/timeout | Falls back to static-only analysis with notice: "AI review unavailable. Results are based on static analysis only." |
| OSV API unavailable | Skips dependency vuln check, notes it in report: "Dependency vulnerability check skipped (service unavailable)" |
| Disk full during clone | Error: "Not enough disk space to clone this repository." Cleans up partial clone |
| Malicious filenames (path traversal) | Filenames are sanitized before any filesystem operation. Suspicious filenames are themselves flagged as a finding |

## Success Criteria

- Detects known malicious patterns with > 90% recall in strict mode
- False positive rate < 20% in strict mode, < 5% in relaxed mode
- Scan completes within 3 minutes for repos under 10K files
- PDF report is understandable by someone with zero coding experience
- Community database accumulates scan data and surfaces accurate trust scores
