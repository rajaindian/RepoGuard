import type { FileEntry } from './engine.js';
import type { Finding } from './types.js';
import { RiskCategory, Severity } from './types.js';

const POPULAR_PACKAGES = [
  'react', 'express', 'lodash', 'axios', 'chalk', 'commander', 'webpack',
  'typescript', 'next', 'vue', 'angular', 'moment', 'request', 'debug',
  'fs-extra', 'glob', 'minimist', 'yargs', 'inquirer', 'dotenv',
  'uuid', 'semver', 'mkdirp', 'rimraf', 'async', 'underscore',
  'bluebird', 'cheerio', 'colors', 'body-parser', 'cors', 'mongoose',
  'socket.io', 'jsonwebtoken', 'bcrypt', 'nodemon', 'eslint', 'prettier',
  'jest', 'mocha', 'chai', 'puppeteer', 'sharp', 'multer', 'passport',
];

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
    Array(b.length + 1).fill(0)
  );
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)
      );
    }
  }
  return dp[a.length][b.length];
}

export function detectTyposquatting(packageName: string): boolean {
  if (POPULAR_PACKAGES.includes(packageName)) return false;
  return POPULAR_PACKAGES.some(popular => {
    const dist = levenshtein(packageName, popular);
    return dist > 0 && dist <= 2 && packageName.length >= popular.length - 2;
  });
}

const UNPINNED_VERSIONS = ['*', 'latest', ''];

export async function scanDependencies(
  _repoPath: string,
  files: FileEntry[]
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const file of files) {
    if (!file.relativePath.endsWith('package.json')) continue;

    try {
      const pkg = JSON.parse(file.content);
      const allDeps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (detectTyposquatting(name)) {
          const similar = POPULAR_PACKAGES.find(p => levenshtein(name, p) <= 2);
          findings.push({
            severity: Severity.HIGH,
            category: RiskCategory.DEPENDENCIES,
            file: file.relativePath,
            line: 0,
            description: `Package "${name}" looks like a typosquat of "${similar}". Typosquatting is a common attack vector.`,
            evidence: `"${name}": "${version}"`,
            confidence: 0.8,
          });
        }

        if (UNPINNED_VERSIONS.includes(String(version))) {
          findings.push({
            severity: Severity.MEDIUM,
            category: RiskCategory.DEPENDENCIES,
            file: file.relativePath,
            line: 0,
            description: `Dependency "${name}" has an unpinned version ("${version}"). This could pull in a compromised future version.`,
            evidence: `"${name}": "${version}"`,
            confidence: 0.7,
          });
        }
      }
    } catch {
      // Invalid JSON
    }
  }

  return findings;
}
