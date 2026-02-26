import { useState, useCallback } from "react";
import {
  getTree,
  getDefaultBranchSHA,
  getRawFileContent,
  getCommits,
} from "../lib/github.js";
import type {
  TreeNode,
  TreeEntry,
  GitHubCommit,
} from "../types/index.js";

/** Build a nested tree from flat GitHub tree entries. */
function buildTree(entries: TreeEntry[]): TreeNode[] {
  const root: TreeNode[] = [];
  const dirs = new Map<string, TreeNode>();

  // Sort so directories come before their children
  const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));

  for (const entry of sorted) {
    const parts = entry.path.split("/");
    const name = parts[parts.length - 1]!;
    const parentPath = parts.slice(0, -1).join("/");

    const node: TreeNode = {
      name,
      path: entry.path,
      type: entry.type === "tree" ? "dir" : "file",
      children: entry.type === "tree" ? [] : undefined,
    };

    if (entry.type === "tree") {
      dirs.set(entry.path, node);
    }

    if (parentPath === "") {
      root.push(node);
    } else {
      const parent = dirs.get(parentPath);
      parent?.children?.push(node);
    }
  }

  return root;
}

export function useRepo(token: string | null) {
  const [tree, setTree] = useState<TreeNode[] | null>(null);
  const [ref, setRef] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [commits, setCommits] = useState<GitHubCommit[]>([]);

  const loadRepo = useCallback(
    async (owner: string, repo: string) => {
      if (!token) return;
      setLoading(true);
      setError(null);
      try {
        const { sha } = await getDefaultBranchSHA(owner, repo, { token });
        setRef(sha);
        const entries = await getTree(owner, repo, sha, { token });
        setTree(buildTree(entries));
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load repo");
      } finally {
        setLoading(false);
      }
    },
    [token],
  );

  const loadFile = useCallback(
    async (owner: string, repo: string, path: string): Promise<string> => {
      if (!token) throw new Error("Not authenticated");
      return getRawFileContent(owner, repo, path, ref, { token });
    },
    [token, ref],
  );

  const loadCommits = useCallback(
    async (owner: string, repo: string, page = 1) => {
      if (!token) return;
      try {
        const data = await getCommits(owner, repo, page, { token });
        setCommits((prev) => (page === 1 ? data : [...prev, ...data]));
      } catch {
        // Silently fail for commits
      }
    },
    [token],
  );

  return {
    tree,
    ref,
    loading,
    error,
    commits,
    loadRepo,
    loadFile,
    loadCommits,
  };
}
