import { describe, it, expect } from 'vitest';
import { calculateCategoryScores, determineVerdict } from '../../src/scoring/scorer.js';
import { RiskCategory, Severity, Verdict } from '../../src/rules/types.js';
import type { Finding } from '../../src/rules/types.js';

describe('calculateCategoryScores', () => {
  it('returns 0 for categories with no findings', () => {
    const scores = calculateCategoryScores([], 'strict');
    expect(scores.every(s => s.score === 0)).toBe(true);
    expect(scores.every(s => s.level === 'NONE')).toBe(true);
  });

  it('scores higher for HIGH severity + high confidence', () => {
    const findings: Finding[] = [{
      severity: Severity.HIGH,
      category: RiskCategory.DATA_EXFILTRATION,
      file: 'test.js', line: 1,
      description: 'test', evidence: 'test',
      confidence: 0.95,
    }];
    const scores = calculateCategoryScores(findings, 'strict');
    const dataScore = scores.find(s => s.category === RiskCategory.DATA_EXFILTRATION);
    expect(dataScore!.score).toBeGreaterThanOrEqual(5);
  });

  it('filters low-confidence findings in relaxed mode', () => {
    const findings: Finding[] = [{
      severity: Severity.HIGH,
      category: RiskCategory.OBFUSCATION,
      file: 'test.js', line: 1,
      description: 'test', evidence: 'test',
      confidence: 0.3,
    }];
    const scores = calculateCategoryScores(findings, 'relaxed');
    const obfScore = scores.find(s => s.category === RiskCategory.OBFUSCATION);
    expect(obfScore!.score).toBe(0);
  });
});

describe('determineVerdict', () => {
  it('returns GREEN when all scores are low', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 1, level: 'LOW' as const, findings: [],
    }));
    expect(determineVerdict(scores)).toBe(Verdict.GREEN);
  });

  it('returns YELLOW when any score is medium', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    }));
    scores[0] = { ...scores[0], score: 5, level: 'MEDIUM' };
    expect(determineVerdict(scores)).toBe(Verdict.YELLOW);
  });

  it('returns RED when any score is high', () => {
    const scores = Object.values(RiskCategory).map(cat => ({
      category: cat, score: 0, level: 'NONE' as const, findings: [],
    }));
    scores[0] = { ...scores[0], score: 8, level: 'HIGH' };
    expect(determineVerdict(scores)).toBe(Verdict.RED);
  });
});
