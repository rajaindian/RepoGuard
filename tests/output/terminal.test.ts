import { describe, it, expect } from 'vitest';
import { renderTerminalReport } from '../../src/output/terminal.js';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { ScanResult } from '../../src/rules/types.js';

function makeScanResult(verdict: Verdict): ScanResult {
  return {
    repoMetadata: { localPath: '/repo' },
    findings: verdict === Verdict.RED ? [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'steal.js', line: 1,
      description: 'Sends .env to external server',
      evidence: 'fetch(...)', confidence: 0.9,
    }] : [],
    categoryScores: Object.values(RiskCategory).map(cat => ({
      category: cat,
      score: verdict === Verdict.RED && cat === RiskCategory.DATA_EXFILTRATION ? 9 : 0,
      level: (verdict === Verdict.RED && cat === RiskCategory.DATA_EXFILTRATION ? 'HIGH' : 'NONE') as any,
      findings: [],
    })),
    verdict,
    summary: 'Test summary',
    recommendation: 'Test recommendation',
    scanTimestamp: new Date().toISOString(),
    scanMode: 'strict',
    aiUsed: false,
  };
}

describe('renderTerminalReport', () => {
  it('includes the verdict', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('GREEN');
  });

  it('includes category names', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('Data Exfiltration');
    expect(output).toContain('Obfuscated Code');
  });

  it('includes findings for RED verdicts', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.RED));
    expect(output).toContain('RED');
    expect(output).toContain('Sends .env');
  });

  it('includes recommendation', () => {
    const output = renderTerminalReport(makeScanResult(Verdict.GREEN));
    expect(output).toContain('Test recommendation');
  });
});
