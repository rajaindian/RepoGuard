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
        // Invalid JSON
      }
    }

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
