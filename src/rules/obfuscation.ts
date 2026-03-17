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
