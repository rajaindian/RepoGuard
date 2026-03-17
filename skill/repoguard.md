---
name: repoguard
description: Scan a GitHub repository or local directory for security risks, malicious code, data theft, and privacy violations. Use when a user wants to check if a repo is safe before using it.
---

# RepoGuard Security Scanner

Scan the target for security risks using the RepoGuard CLI.

## Usage
The user provides a GitHub URL or local path. Run:

```bash
npx repoguard scan "<target>" --mode strict
```

If the user has ANTHROPIC_API_KEY set, AI review will be included automatically.
If not, add `--no-ai` for static-only analysis.

Display the terminal output to the user. The PDF report is auto-saved.

If the user asks about a specific finding, explain it in plain English.
