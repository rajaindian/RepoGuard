import { describe, it, expect } from 'vitest';
import { AIReviewer } from '../../src/ai/reviewer.js';

describe('AIReviewer', () => {
  it('returns null when no API key is configured', async () => {
    const reviewer = new AIReviewer(undefined);
    const result = await reviewer.review([], 'packed content');
    expect(result).toBeNull();
  });

  it('builds the correct prompt structure', () => {
    const reviewer = new AIReviewer('test-key');
    const prompt = reviewer.buildPrompt(
      [{ severity: 'HIGH', category: 'data_exfiltration', file: 'test.js', line: 1, description: 'test', evidence: 'test', confidence: 0.8 }] as any[],
      'const x = 1;'
    );
    expect(prompt).toContain('security review');
    expect(prompt).toContain('data_exfiltration');
    expect(prompt).toContain('const x = 1');
  });
});
