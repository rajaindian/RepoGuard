import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

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
