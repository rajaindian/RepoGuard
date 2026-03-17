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

export async function scanBackdoors(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    const content = file.content;

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
