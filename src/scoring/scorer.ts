import { RiskCategory, Severity, Verdict } from '../rules/types.js';
import type { Finding, CategoryScore } from '../rules/types.js';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  [Severity.LOW]: 1,
  [Severity.MEDIUM]: 3,
  [Severity.HIGH]: 6,
  [Severity.CRITICAL]: 10,
};

export function calculateCategoryScores(
  findings: Finding[],
  mode: 'strict' | 'relaxed'
): CategoryScore[] {
  const categories = Object.values(RiskCategory);

  return categories.map(category => {
    let categoryFindings = findings.filter(f => f.category === category);

    // In relaxed mode, filter out low-confidence findings
    if (mode === 'relaxed') {
      categoryFindings = categoryFindings.filter(f => f.confidence >= 0.7);
    }

    if (categoryFindings.length === 0) {
      return { category, score: 0, level: 'NONE' as const, findings: [] };
    }

    // Score = sum of (severity_weight * confidence), capped at 10
    const rawScore = categoryFindings.reduce((sum, f) => {
      return sum + SEVERITY_WEIGHTS[f.severity] * f.confidence;
    }, 0);

    const score = Math.min(10, Math.round(rawScore));
    const level = score === 0 ? 'NONE' : score <= 3 ? 'LOW' : score <= 6 ? 'MEDIUM' : 'HIGH';

    return { category, score, level: level as CategoryScore['level'], findings: categoryFindings };
  });
}

export function determineVerdict(scores: CategoryScore[]): Verdict {
  if (scores.some(s => s.level === 'HIGH')) return Verdict.RED;
  if (scores.some(s => s.level === 'MEDIUM')) return Verdict.YELLOW;
  return Verdict.GREEN;
}
