import { describe, it, expect } from 'vitest';
import { scan } from '../src/scanner.js';

describe('scan', () => {
  it('scans a safe local repo and returns GREEN', async () => {
    const result = await scan('tests/fixtures/safe-repo', { mode: 'strict', ai: false });
    expect(result.verdict).toBe('GREEN');
    expect(result.findings.length).toBe(0);
  });

  it('scans a malicious local repo and returns RED', async () => {
    const result = await scan('tests/fixtures/malicious-repo', { mode: 'strict', ai: false });
    expect(result.verdict).toBe('RED');
    expect(result.findings.length).toBeGreaterThan(0);
  });
});
