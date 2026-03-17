import { Command } from 'commander';
import { scan } from './scanner.js';
import { renderTerminalReport } from './output/terminal.js';
import { generatePDF } from './output/pdf.js';

export function run(): void {
  const program = new Command();

  program
    .name('repoguard')
    .description('Security scanner for GitHub repositories')
    .version('1.0.0');

  program
    .command('scan <target>')
    .description('Scan a GitHub repo URL or local directory')
    .option('--mode <mode>', 'Scan mode: strict or relaxed', 'strict')
    .option('--no-ai', 'Skip AI review (static analysis only)')
    .option('--model <model>', 'Claude model to use (or set REPOGUARD_MODEL env var)', process.env.REPOGUARD_MODEL || 'claude-sonnet-4-6')
    .option('--submit', 'Submit results to community database')
    .option('--output <path>', 'Custom PDF output path')
    .action(async (target, options) => {
      try {
        const apiKey = process.env.ANTHROPIC_API_KEY;
        const result = await scan(target, {
          mode: options.mode,
          ai: options.ai !== false && !!apiKey,
          apiKey,
          model: options.model,
        });

        // Terminal output
        console.log(renderTerminalReport(result));

        // PDF output
        const repoName = target.split('/').pop()?.replace('.git', '') || 'repo';
        const pdfPath = options.output || `./repoguard-report-${repoName}.pdf`;
        await generatePDF(result, pdfPath);
        console.log(`\nFull PDF report saved to: ${pdfPath}`);

        // Community submission
        if (options.submit) {
          console.log('\nCommunity submission is coming soon! Follow https://github.com/repoguard for updates.');
        }

        // Exit with non-zero if RED
        if (result.verdict === 'RED') process.exit(1);
      } catch (error) {
        console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
        process.exit(2);
      }
    });

  program
    .command('lookup <url>')
    .description('Check community ratings for a repository')
    .action((_url) => {
      console.log('Community lookup is coming soon! Follow https://github.com/repoguard for updates.');
    });

  program.parse();
}
