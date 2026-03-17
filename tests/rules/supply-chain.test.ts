import { describe, it, expect } from 'vitest';
import { analyzeSupplyChain } from '../../src/rules/supply-chain.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';
import type { RepoMetadata } from '../../src/rules/types.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '' };
}

describe('analyzeSupplyChain', () => {
  it('flags star/age mismatch', () => {
    const metadata: Partial<RepoMetadata> = {
      stars: 10000,
      age: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    };
    const findings = analyzeSupplyChain(metadata, []);
    expect(findings.some(f => f.description.includes('star'))).toBe(true);
  });

  it('flags missing license', () => {
    const files = [makeFile('package.json', '{}')];
    const findings = analyzeSupplyChain({}, files);
    expect(findings.some(f => f.description.includes('license'))).toBe(true);
  });

  it('does not flag repos with license', () => {
    const files = [makeFile('LICENSE', 'MIT License...')];
    const findings = analyzeSupplyChain({}, files);
    expect(findings.every(f => !f.description.includes('license'))).toBe(true);
  });
});
