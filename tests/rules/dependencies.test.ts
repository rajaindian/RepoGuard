import { describe, it, expect } from 'vitest';
import { scanDependencies, detectTyposquatting } from '../../src/rules/dependencies.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.json' };
}

describe('detectTyposquatting', () => {
  it('flags packages similar to popular ones', () => {
    expect(detectTyposquatting('lodahs')).toBe(true);
    expect(detectTyposquatting('expres')).toBe(true);
    expect(detectTyposquatting('chalkk')).toBe(true);
  });

  it('allows legitimate popular packages', () => {
    expect(detectTyposquatting('lodash')).toBe(false);
    expect(detectTyposquatting('express')).toBe(false);
    expect(detectTyposquatting('react')).toBe(false);
  });
});

describe('scanDependencies', () => {
  it('flags unpinned dependency versions', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      dependencies: { 'some-pkg': '*' },
    }))];
    const findings = await scanDependencies('/repo', files);
    expect(findings.some(f => f.description.includes('unpinned'))).toBe(true);
  });

  it('flags typosquatting candidates', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      dependencies: { 'lodahs': '^1.0.0' },
    }))];
    const findings = await scanDependencies('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });
});
