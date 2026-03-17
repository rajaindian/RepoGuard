import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, unlinkSync } from 'node:fs';

describe('E2E: repoguard scan', () => {
  it('scans safe repo and exits 0', () => {
    const result = execSync(
      'node dist/bin/repoguard.js scan tests/fixtures/safe-repo',
      { encoding: 'utf8' }
    );
    expect(result).toContain('GREEN');
  });

  it('scans malicious repo and exits 1', () => {
    try {
      execSync(
        'node dist/bin/repoguard.js scan tests/fixtures/malicious-repo',
        { encoding: 'utf8' }
      );
      expect.fail('Should have exited with code 1');
    } catch (error: any) {
      expect(error.status).toBe(1);
      expect(error.stdout).toContain('RED');
    }
  });

  it('generates a PDF report', () => {
    const pdfPath = './test-report.pdf';
    try {
      execSync(
        `node dist/bin/repoguard.js scan tests/fixtures/safe-repo --output ${pdfPath}`,
        { encoding: 'utf8' }
      );
      expect(existsSync(pdfPath)).toBe(true);
    } finally {
      if (existsSync(pdfPath)) unlinkSync(pdfPath);
    }
  });

  it('outputs JSON with --json flag', () => {
    const result = execSync(
      'node dist/bin/repoguard.js scan tests/fixtures/safe-repo --json',
      { encoding: 'utf8' }
    );
    const parsed = JSON.parse(result);
    expect(parsed.verdict).toBe('GREEN');
    expect(parsed.findings).toBeDefined();
    expect(parsed.categoryScores).toBeDefined();
  });

  it('shows coming soon for --submit', () => {
    const result = execSync(
      'node dist/bin/repoguard.js scan tests/fixtures/safe-repo --submit',
      { encoding: 'utf8' }
    );
    expect(result).toContain('coming soon');
  });

  it('shows coming soon for lookup', () => {
    const result = execSync(
      'node dist/bin/repoguard.js lookup https://github.com/test/repo',
      { encoding: 'utf8' }
    );
    expect(result).toContain('coming soon');
  });
});
