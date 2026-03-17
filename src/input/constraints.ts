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

  function hasSuspiciousName(name: string): boolean {
    return name.includes('..') || name.includes('\0') || /[\x00-\x1f]/.test(name);
  }

  function walk(dir: string): void {
    const entries = readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;

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
        continue;
      }

      if (lstat.isDirectory()) {
        walk(fullPath);
        continue;
      }

      fileCount++;
      totalSizeBytes += lstat.size;

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

  const gitmodulesPath = join(resolve(repoPath), '.gitmodules');
  if (existsSync(gitmodulesPath)) {
    warnings.push('This repo has submodules that were not scanned.');
  }

  const gitattrsPath = join(resolve(repoPath), '.gitattributes');
  if (existsSync(gitattrsPath)) {
    try {
      const attrs = readFileSync(gitattrsPath, 'utf8');
      if (attrs.includes('filter=lfs')) {
        warnings.push('This repo uses Git LFS. LFS objects were not fetched or scanned.');
      }
    } catch { /* skip */ }
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
