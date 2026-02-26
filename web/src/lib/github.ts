/**
 * GitHub REST API client.
 * All requests use the GitHub Contents/Trees/Commits APIs.
 */

import type { TreeEntry, GitHubCommit } from "../types/index.js";

const API_BASE = "https://api.github.com";

interface FetchOptions {
  token: string;
  signal?: AbortSignal;
}

async function ghFetch<T>(
  path: string,
  opts: FetchOptions,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${opts.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: opts.signal,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status}: ${path} - ${body}`);
  }
  return res.json() as Promise<T>;
}

/** Get the full recursive tree for a repo. */
export async function getTree(
  owner: string,
  repo: string,
  sha: string,
  opts: FetchOptions,
): Promise<TreeEntry[]> {
  const data = await ghFetch<{
    tree: TreeEntry[];
    truncated: boolean;
  }>(`/repos/${owner}/${repo}/git/trees/${sha}?recursive=1`, opts);
  return data.tree;
}

/** Get the default branch SHA. */
export async function getDefaultBranchSHA(
  owner: string,
  repo: string,
  opts: FetchOptions,
): Promise<{ branch: string; sha: string }> {
  const data = await ghFetch<{ default_branch: string }>(
    `/repos/${owner}/${repo}`,
    opts,
  );
  const branch = data.default_branch;
  const ref = await ghFetch<{ object: { sha: string } }>(
    `/repos/${owner}/${repo}/git/ref/heads/${branch}`,
    opts,
  );
  return { branch, sha: ref.object.sha };
}

/** Get file contents (base64-encoded) from the Contents API. */
export async function getFileContent(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  opts: FetchOptions,
): Promise<string> {
  const data = await ghFetch<{ content: string; encoding: string }>(
    `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`,
    opts,
  );
  if (data.encoding !== "base64") {
    throw new Error(`unexpected encoding: ${data.encoding}`);
  }
  // GitHub returns base64 with newlines
  return data.content.replace(/\n/g, "");
}

/** Get raw file content as text via the raw API. */
export async function getRawFileContent(
  owner: string,
  repo: string,
  path: string,
  ref: string,
  opts: FetchOptions,
): Promise<string> {
  const res = await fetch(
    `${API_BASE}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${ref}`,
    {
      headers: {
        Authorization: `Bearer ${opts.token}`,
        Accept: "application/vnd.github.raw+json",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: opts.signal,
    },
  );
  if (!res.ok) {
    throw new Error(`GitHub raw fetch ${res.status}: ${path}`);
  }
  return res.text();
}

/** Get commit history. */
export async function getCommits(
  owner: string,
  repo: string,
  page: number,
  opts: FetchOptions,
): Promise<GitHubCommit[]> {
  return ghFetch<GitHubCommit[]>(
    `/repos/${owner}/${repo}/commits?per_page=30&page=${page}`,
    opts,
  );
}

/** Create or update a file via the Contents API. */
export async function createOrUpdateFile(
  owner: string,
  repo: string,
  path: string,
  content: string,
  message: string,
  branch: string,
  sha: string | null,
  opts: FetchOptions,
): Promise<void> {
  const body: Record<string, string> = {
    message,
    content: btoa(content),
    branch,
  };
  if (sha) body["sha"] = sha;

  const res = await fetch(
    `${API_BASE}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
    {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${opts.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      signal: opts.signal,
    },
  );
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub create file ${res.status}: ${text}`);
  }
}

/** Create a branch from a given SHA. */
export async function createBranch(
  owner: string,
  repo: string,
  branchName: string,
  fromSha: string,
  opts: FetchOptions,
): Promise<void> {
  const res = await fetch(
    `${API_BASE}/repos/${owner}/${repo}/git/refs`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${opts.token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        ref: `refs/heads/${branchName}`,
        sha: fromSha,
      }),
      signal: opts.signal,
    },
  );
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub create branch ${res.status}: ${text}`);
  }
}

/** Create a pull request. */
export async function createPullRequest(
  owner: string,
  repo: string,
  title: string,
  body: string,
  head: string,
  base: string,
  opts: FetchOptions,
): Promise<string> {
  const res = await fetch(`${API_BASE}/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${opts.token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ title, body, head, base }),
    signal: opts.signal,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`GitHub create PR ${res.status}: ${text}`);
  }
  const result = (await res.json()) as { html_url: string };
  return result.html_url;
}
