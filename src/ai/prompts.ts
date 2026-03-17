import type { Finding } from '../rules/types.js';

export const SYSTEM_PROMPT = `You are a security analyst reviewing a codebase for malicious code, data theft, privacy violations, and other risks. You are given:
1. Findings from a static analysis tool
2. The full source code of the repository

Your job is to:
- Validate or dismiss each static finding (reduce false positives)
- Identify any additional risks the static tool missed
- Provide a plain-English summary suitable for a non-technical user
- Give a clear recommendation: "safe to use", "use with caution", or "do not use"

Respond with valid JSON matching this schema:
{
  "refinedFindings": [{ "severity": "LOW|MEDIUM|HIGH|CRITICAL", "category": "...", "file": "...", "line": 0, "description": "...", "evidence": "...", "confidence": 0.0 }],
  "summary": "Plain English summary for non-technical users",
  "recommendation": "One sentence recommendation"
}`;

export function buildUserPrompt(findings: Finding[], packedCode: string): string {
  const findingsJson = JSON.stringify(findings, null, 2);
  return `## Static Analysis Findings

\`\`\`json
${findingsJson}
\`\`\`

## Repository Source Code

\`\`\`
${packedCode}
\`\`\`

Please perform your security review and return your analysis as JSON.`;
}
