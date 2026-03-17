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
