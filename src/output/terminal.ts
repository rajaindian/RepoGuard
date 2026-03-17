import chalk from 'chalk';
import type { ScanResult, CategoryScore } from '../rules/types.js';
import { Verdict, RiskCategory } from '../rules/types.js';

const CATEGORY_LABELS: Record<string, string> = {
  [RiskCategory.DATA_EXFILTRATION]: 'Data Exfiltration',
  [RiskCategory.OBFUSCATION]: 'Obfuscated Code',
  [RiskCategory.INSTALL_SCRIPTS]: 'Install Scripts',
  [RiskCategory.BACKDOORS]: 'Backdoors',
  [RiskCategory.PRIVACY]: 'Privacy Violations',
  [RiskCategory.DEPENDENCIES]: 'Dependency Risks',
  [RiskCategory.FILESYSTEM]: 'Filesystem Access',
  [RiskCategory.SUPPLY_CHAIN]: 'Supply Chain Red Flags',
};

function verdictColor(verdict: Verdict): (text: string) => string {
  switch (verdict) {
    case Verdict.GREEN: return chalk.green;
    case Verdict.YELLOW: return chalk.yellow;
    case Verdict.RED: return chalk.red;
  }
}

function scoreBar(score: number): string {
  const filled = Math.round(score);
  const empty = 10 - filled;
  return '\u2588'.repeat(filled) + '\u2591'.repeat(empty);
}

function levelLabel(level: string): string {
  switch (level) {
    case 'HIGH': return chalk.red('HIGH');
    case 'MEDIUM': return chalk.yellow('MED ');
    case 'LOW': return chalk.green('LOW ');
    default: return chalk.gray('NONE');
  }
}

export function renderTerminalReport(result: ScanResult): string {
  const lines: string[] = [];
  const colorFn = verdictColor(result.verdict);
  const repoName = result.repoMetadata.url?.split('/').pop() || result.repoMetadata.localPath.split(/[/\\]/).pop() || 'repo';

  lines.push('');
  lines.push(colorFn(`  RepoGuard Report: ${repoName}`));
  lines.push(colorFn(`  Verdict: ${result.verdict}`));
  lines.push('');

  // Category bars
  for (const score of result.categoryScores) {
    const label = (CATEGORY_LABELS[score.category] || score.category).padEnd(22);
    lines.push(`  ${label} ${scoreBar(score.score)}  ${levelLabel(score.level)}`);
  }

  // Top findings
  const topFindings = result.findings
    .sort((a, b) => b.confidence - a.confidence)
    .slice(0, 3);

  if (topFindings.length > 0) {
    lines.push('');
    lines.push('  Top Findings:');
    lines.push('');
    for (const f of topFindings) {
      const icon = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? chalk.red('!') : chalk.yellow('*');
      lines.push(`  ${icon} ${f.description}`);
      if (f.file) lines.push(`    ${chalk.gray(`${f.file}:${f.line}`)}`);
      lines.push('');
    }
  }

  lines.push(`  Recommendation: ${result.recommendation}`);
  lines.push('');

  return lines.join('\n');
}
