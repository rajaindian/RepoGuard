import { describe, it, expect } from 'vitest';
import { checkConstraints, isBinaryFile, isSuspiciousSymlink } from '../../src/input/constraints.js';

describe('isBinaryFile', () => {
  it('flags .exe files', () => {
    expect(isBinaryFile('helper.exe')).toBe(true);
  });

  it('flags .dll files', () => {
    expect(isBinaryFile('lib.dll')).toBe(true);
  });

  it('allows .js files', () => {
    expect(isBinaryFile('index.js')).toBe(false);
  });

  it('allows .py files', () => {
    expect(isBinaryFile('main.py')).toBe(false);
  });
});

describe('isSuspiciousSymlink', () => {
  it('flags symlinks pointing outside repo', () => {
    expect(isSuspiciousSymlink('/repo', '/etc/passwd')).toBe(true);
  });

  it('allows symlinks within repo', () => {
    expect(isSuspiciousSymlink('/repo', '/repo/src/utils.js')).toBe(false);
  });
});

describe('checkConstraints', () => {
  it('passes for small repos', async () => {
    const result = await checkConstraints('tests/fixtures/safe-repo');
    expect(result.passed).toBe(true);
  });
});
