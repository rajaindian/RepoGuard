import { describe, it, expect } from 'vitest';
import { scanFilesystem } from '../../src/rules/filesystem.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanFilesystem', () => {
  it('flags path traversal reads', async () => {
    const files = [makeFile('hack.js', `fs.readFileSync('../../../etc/passwd');`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.FILESYSTEM);
  });

  it('flags access to browser profile paths', async () => {
    const files = [makeFile('steal.js', `
      const chromeDir = process.env.HOME + '/.config/google-chrome/Default/Login Data';
      const db = readFileSync(chromeDir);
    `)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags sudo/privilege escalation', async () => {
    const files = [makeFile('install.sh', `#!/bin/bash\nsudo chmod 777 /etc/crontab`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags writing to system directories', async () => {
    const files = [makeFile('backdoor.js', `fs.writeFileSync('/usr/local/bin/update', payload);`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal file operations', async () => {
    const files = [makeFile('app.js', `fs.readFileSync('./config.json');`)];
    const findings = await scanFilesystem('/repo', files);
    expect(findings.length).toBe(0);
  });
});
