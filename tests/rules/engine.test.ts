import { describe, it, expect } from 'vitest';
import { RuleEngine } from '../../src/rules/engine.js';
import { RiskCategory } from '../../src/rules/types.js';

describe('RuleEngine', () => {
  it('runs all registered rule modules against a repo path', async () => {
    const engine = new RuleEngine();
    const findings = await engine.scan('tests/fixtures/safe-repo');
    expect(Array.isArray(findings)).toBe(true);
  });

  it('finds issues in malicious repos', async () => {
    const engine = new RuleEngine();
    const findings = await engine.scan('tests/fixtures/malicious-repo');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.category === RiskCategory.DATA_EXFILTRATION)).toBe(true);
  });
});
