import PDFDocument from 'pdfkit';
import { createWriteStream } from 'node:fs';
import type { ScanResult, CategoryScore, Finding } from '../rules/types.js';
import { RiskCategory, Verdict } from '../rules/types.js';

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

const VERDICT_COLORS: Record<string, string> = {
  [Verdict.GREEN]: '#22c55e',
  [Verdict.YELLOW]: '#eab308',
  [Verdict.RED]: '#ef4444',
};

export async function generatePDF(result: ScanResult, outputPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50 });
    const stream = createWriteStream(outputPath);
    doc.pipe(stream);

    // === Page 1: Executive Summary ===
    doc.fontSize(24).text('RepoGuard Security Report', { align: 'center' });
    doc.moveDown();

    // Verdict
    const verdictColor = VERDICT_COLORS[result.verdict] || '#666';
    doc.fontSize(18).fillColor(verdictColor)
      .text(`Verdict: ${result.verdict}`, { align: 'center' });
    doc.fillColor('#000');
    doc.moveDown();

    // Summary
    doc.fontSize(12).text(result.summary);
    doc.moveDown();

    // Category scores
    doc.fontSize(14).text('Risk Categories', { underline: true });
    doc.moveDown(0.5);

    for (const score of result.categoryScores) {
      const label = CATEGORY_LABELS[score.category] || score.category;
      doc.fontSize(10).text(`${label}: ${score.score}/10 (${score.level})`);
    }
    doc.moveDown();

    // Top findings
    const topFindings = result.findings
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 3);

    if (topFindings.length > 0) {
      doc.fontSize(14).text('Top Findings', { underline: true });
      doc.moveDown(0.5);
      for (const f of topFindings) {
        doc.fontSize(10)
          .text(`[${f.severity}] ${f.description}`)
          .text(`  File: ${f.file}:${f.line}`, { indent: 10 })
          .moveDown(0.5);
      }
    }

    // Recommendation
    doc.moveDown();
    doc.fontSize(12).fillColor(verdictColor)
      .text(`Recommendation: ${result.recommendation}`);
    doc.fillColor('#000');

    // === Pages 2-N: Detailed Findings ===
    const categoriesWithFindings = result.categoryScores.filter(s => s.findings.length > 0);

    for (const catScore of categoriesWithFindings) {
      doc.addPage();
      const label = CATEGORY_LABELS[catScore.category] || catScore.category;
      doc.fontSize(16).text(`${label} (Score: ${catScore.score}/10)`);
      doc.moveDown();

      for (const finding of catScore.findings) {
        doc.fontSize(10)
          .text(`Severity: ${finding.severity} | Confidence: ${(finding.confidence * 100).toFixed(0)}%`)
          .text(finding.description)
          .text(`File: ${finding.file}:${finding.line}`, { indent: 10 })
          .text(`Evidence: ${finding.evidence.substring(0, 200)}`, { indent: 10 })
          .moveDown();
      }
    }

    // === Final Page: Metadata ===
    doc.addPage();
    doc.fontSize(16).text('Repository Metadata');
    doc.moveDown();
    doc.fontSize(10);
    if (result.repoMetadata.url) doc.text(`URL: ${result.repoMetadata.url}`);
    if (result.repoMetadata.stars !== undefined) doc.text(`Stars: ${result.repoMetadata.stars}`);
    if (result.repoMetadata.age) doc.text(`Created: ${result.repoMetadata.age}`);
    if (result.repoMetadata.contributors) doc.text(`Contributors: ${result.repoMetadata.contributors}`);
    if (result.repoMetadata.isFork) doc.text(`Fork of: ${result.repoMetadata.forkedFrom || 'unknown'}`);
    doc.text(`Scan Mode: ${result.scanMode}`);
    doc.text(`AI Used: ${result.aiUsed ? 'Yes' : 'No'}`);
    doc.text(`Scan Time: ${result.scanTimestamp}`);

    doc.end();
    stream.on('finish', resolve);
    stream.on('error', reject);
  });
}
