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
        const isTextLike = TEXT_EXTENSIONS.has(ext) || ext === '';
        if (!isTextLike) continue;
        if (stat.size > 1_000_000) continue;

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
