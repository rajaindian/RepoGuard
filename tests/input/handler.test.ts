import { describe, it, expect } from 'vitest';
import { detectInputType, validateLocalPath } from '../../src/input/handler.js';

describe('detectInputType', () => {
  it('detects GitHub HTTPS URLs', () => {
    expect(detectInputType('https://github.com/user/repo')).toBe('url');
  });

  it('detects GitHub SSH URLs', () => {
    expect(detectInputType('git@github.com:user/repo.git')).toBe('url');
  });

  it('detects local paths', () => {
    expect(detectInputType('./my-project')).toBe('local');
    expect(detectInputType('/home/user/project')).toBe('local');
    expect(detectInputType('C:\\Users\\project')).toBe('local');
  });

  it('throws on empty input', () => {
    expect(() => detectInputType('')).toThrow();
  });

  it('treats bare names as local paths', () => {
    expect(detectInputType('my-project')).toBe('local');
  });
});

describe('validateLocalPath', () => {
  it('accepts a directory with files', async () => {
    const result = await validateLocalPath('tests/fixtures/safe-repo');
    expect(result.valid).toBe(true);
  });

  it('rejects non-existent paths', async () => {
    const result = await validateLocalPath('/nonexistent/path/xyz');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('does not exist');
  });
});
