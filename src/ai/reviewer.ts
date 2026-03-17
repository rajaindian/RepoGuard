import Anthropic from '@anthropic-ai/sdk';
import type { Finding } from '../rules/types.js';
import { SYSTEM_PROMPT, buildUserPrompt } from './prompts.js';

export interface AIReviewResult {
  refinedFindings: Finding[];
  summary: string;
  recommendation: string;
}

export class AIReviewer {
  private client: Anthropic | null;
  private model: string;

  constructor(apiKey: string | undefined, model?: string) {
    this.client = apiKey ? new Anthropic({ apiKey }) : null;
    this.model = model || process.env.REPOGUARD_MODEL || 'claude-sonnet-4-6';
  }

  buildPrompt(findings: Finding[], packedCode: string): string {
    return buildUserPrompt(findings as any[], packedCode);
  }

  async review(findings: Finding[], repoPath: string): Promise<AIReviewResult | null> {
    if (!this.client) return null;

    try {
      // Pack repo using Repomix
      const packedCode = await this.packRepo(repoPath, findings);

      const response = await this.client.messages.create({
        model: this.model,
        max_tokens: 4096,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: this.buildPrompt(findings, packedCode) }],
      });

      const text = response.content
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('');

      // Extract JSON from response (may be wrapped in markdown code blocks)
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) return null;

      const parsed = JSON.parse(jsonMatch[0]) as AIReviewResult;
      return parsed;
    } catch (error) {
      console.warn(`AI review unavailable: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  private async packRepo(repoPath: string, findings: Finding[]): Promise<string> {
    try {
      const { pack } = await import('repomix');
      const result = await pack({
        input: { path: repoPath },
        output: { style: 'plain' },
      });

      // If packed output is too large (>100K tokens ~400KB), truncate
      if (result && result.length > 400_000) {
        return result.substring(0, 400_000) + '\n[... truncated for token limits]';
      }

      return result || '[Failed to pack repository]';
    } catch {
      return '[Repomix packing failed — AI review will be based on findings only]';
    }
  }
}
