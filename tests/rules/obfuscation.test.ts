import { describe, it, expect } from 'vitest';
import { scanObfuscation, calculateEntropy } from '../../src/rules/obfuscation.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: relativePath.split('.').pop() || '' };
}

describe('calculateEntropy', () => {
  it('returns low entropy for simple strings', () => {
    expect(calculateEntropy('aaaaaaaaaa')).toBeLessThan(2);
  });

  it('returns high entropy for random-looking strings', () => {
    expect(calculateEntropy('aB3$kL9!mN2@pQ5')).toBeGreaterThan(3.5);
  });
});

describe('scanObfuscation', () => {
  it('flags eval with dynamic strings', async () => {
    const files = [makeFile('evil.js', `eval(atob('Y29uc29sZS5sb2coImhhY2tlZCIp'));`)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags base64 encoded payloads', async () => {
    const files = [makeFile('payload.js', `
      const code = Buffer.from('Y29uc29sZS5sb2coImhhY2tlZCIp', 'base64').toString();
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags hex encoded strings', async () => {
    const files = [makeFile('hex.js', `
      const cmd = '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70';
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags high-entropy strings', async () => {
    const files = [makeFile('sus.js', `
      const token = 'aK3m$9Lp!nQ2@wR5xB7cD0eF8gH1iJ4kM6oP3sT9uV2yA5bC8dE1fG4hI7jK0lN3qR6tU9wX2zA5';
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.some(f => f.description.includes('entropy'))).toBe(true);
  });

  it('does not flag normal code', async () => {
    const files = [makeFile('normal.js', `
      const name = 'hello world';
      console.log(name);
    `)];
    const findings = await scanObfuscation('/repo', files);
    expect(findings.length).toBe(0);
  });
});
