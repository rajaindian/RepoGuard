import type { FileEntry } from './engine.js';
import type { Finding, RepoMetadata } from './types.js';
import { RiskCategory, Severity } from './types.js';

export function analyzeSupplyChain(
  metadata: Partial<RepoMetadata>,
  files: FileEntry[]
): Finding[] {
  const findings: Finding[] = [];

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

export async function scanSupplyChain(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  return analyzeSupplyChain({}, files);
}
