import { detectInputType, validateLocalPath, cloneRepo, cleanupClone } from './input/handler.js';
import { checkConstraints } from './input/constraints.js';
import { fetchGitHubMetadata } from './input/github.js';
import { RuleEngine } from './rules/engine.js';
import { analyzeSupplyChain } from './rules/supply-chain.js';
import { calculateCategoryScores, determineVerdict } from './scoring/scorer.js';
import type { ScanResult, RepoMetadata } from './rules/types.js';

interface ScanOptions {
  mode: 'strict' | 'relaxed';
}

export async function scan(input: string, options: ScanOptions): Promise<ScanResult> {
  // 1. Resolve input (clone if URL, validate if local)
  const inputType = detectInputType(input);
  let repoPath: string;
  let shouldCleanup = false;

  if (inputType === 'url') {
    repoPath = cloneRepo(input);
    shouldCleanup = true;
  } else {
    const validation = await validateLocalPath(input);
    if (!validation.valid) throw new Error(validation.error);
    repoPath = validation.resolvedPath;
  }

  try {
    // 2. Check constraints
    const constraints = await checkConstraints(repoPath);
    if (!constraints.passed) throw new Error(constraints.error);

    // 3. Fetch GitHub metadata if URL was provided
    let metadata: RepoMetadata = { localPath: repoPath, url: inputType === 'url' ? input : undefined };
    if (inputType === 'url') {
      const ghMeta = await fetchGitHubMetadata(input);
      metadata = { ...metadata, ...ghMeta };
    }

    // 4. Run static rule engine
    const engine = new RuleEngine();
    const files = await engine.collectFiles(repoPath);
    const engineFindings = await engine.scan(repoPath);

    // 5. Run supply chain analysis with metadata
    const supplyChainFindings = analyzeSupplyChain(metadata, files);

    const findings = [...constraints.findings, ...engineFindings, ...supplyChainFindings];

    // 6. Score
    const categoryScores = calculateCategoryScores(findings, options.mode);
    const verdict = determineVerdict(categoryScores);

    // 7. Generate summary
    const topFindings = findings
      .sort((a, b) => b.confidence - a.confidence)
      .slice(0, 3)
      .map(f => f.description);
    const summary = topFindings.join(' ') || 'No significant issues detected.';

    const recommendation = verdict === 'GREEN'
      ? 'This repository appears safe to use.'
      : verdict === 'YELLOW'
        ? 'Review the flagged items before using this repository.'
        : 'DO NOT USE this repository. Significant risks detected.';

    return {
      repoMetadata: metadata,
      findings,
      categoryScores,
      verdict,
      summary,
      recommendation,
      scanTimestamp: new Date().toISOString(),
      scanMode: options.mode,
      aiUsed: false,
    };
  } finally {
    if (shouldCleanup) cleanupClone(repoPath);
  }
}
