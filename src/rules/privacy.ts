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
