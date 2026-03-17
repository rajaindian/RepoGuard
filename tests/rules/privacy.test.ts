import { describe, it, expect } from 'vitest';
import { scanPrivacy } from '../../src/rules/privacy.js';
import { RiskCategory } from '../../src/rules/types.js';
import type { FileEntry } from '../../src/rules/engine.js';

function makeFile(relativePath: string, content: string): FileEntry {
  return { relativePath, absolutePath: `/repo/${relativePath}`, content, extension: '.js' };
}

describe('scanPrivacy', () => {
  it('flags geolocation access', async () => {
    const files = [makeFile('track.js', `navigator.geolocation.getCurrentPosition(pos => sendToServer(pos));`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags clipboard monitoring', async () => {
    const files = [makeFile('spy.js', `navigator.clipboard.readText().then(text => exfiltrate(text));`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags camera/microphone access', async () => {
    const files = [makeFile('media.js', `navigator.mediaDevices.getUserMedia({ video: true, audio: true });`)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('flags fingerprinting patterns', async () => {
    const files = [makeFile('fp.js', `
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.fillText('fingerprint', 10, 10);
      const hash = canvas.toDataURL();
    `)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBeGreaterThan(0);
  });

  it('does not flag normal DOM usage', async () => {
    const files = [makeFile('app.js', `
      document.getElementById('app').textContent = 'Hello';
    `)];
    const findings = await scanPrivacy('/repo', files);
    expect(findings.length).toBe(0);
  });
});
