import type { RepoMetadata } from '../rules/types.js';

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  const httpsMatch = url.match(/github\.com\/([^/]+)\/([^/.\s]+)/);
  if (httpsMatch) return { owner: httpsMatch[1], repo: httpsMatch[2] };
  const sshMatch = url.match(/git@github\.com:([^/]+)\/([^/.\s]+)/);
  if (sshMatch) return { owner: sshMatch[1], repo: sshMatch[2] };
  return null;
}

export async function fetchGitHubMetadata(url: string): Promise<Partial<RepoMetadata>> {
  const parsed = parseGitHubUrl(url);
  if (!parsed) return {};

  try {
    const response = await fetch(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}`,
      { headers: { 'Accept': 'application/vnd.github.v3+json' }, signal: AbortSignal.timeout(10_000) }
    );
    if (!response.ok) return {};

    const data = await response.json() as any;
    return {
      stars: data.stargazers_count,
      age: data.created_at,
      contributors: undefined,
      isFork: data.fork,
      forkedFrom: data.parent?.full_name,
      defaultBranch: data.default_branch,
    };
  } catch {
    return {};
  }
}
