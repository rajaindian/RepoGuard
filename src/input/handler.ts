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
    if (parent.includes('repoguard-')) {
      rmSync(parent, { recursive: true, force: true });
    }
  } catch {
    // Best effort cleanup
  }
}
