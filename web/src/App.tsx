import { useState, useCallback, useEffect, useRef } from "react";
import { useAuth } from "./hooks/useAuth.js";
import { useRepo } from "./hooks/useRepo.js";
import { useCrypto } from "./hooks/useCrypto.js";
import { AuthGate } from "./components/AuthGate.js";
import { RepoSelector } from "./components/RepoSelector.js";
import { Layout } from "./components/Layout.js";
import { FileTree } from "./components/FileTree.js";
import { FileViewer } from "./components/FileViewer.js";
import { CommitLog } from "./components/CommitLog.js";
import { MemberList } from "./components/MemberList.js";
import { JoinFlow } from "./components/JoinFlow.js";
import { getRawFileContent } from "./lib/github.js";
import { b64Decode } from "./lib/base64.js";
import { parseMemberTOML } from "./lib/mlsgit.js";
import type { View, MemberInfo } from "./types/index.js";

export function App() {
  const { token, setToken, logout, isLoggedIn } = useAuth();
  const [view, setView] = useState<View>(
    isLoggedIn ? { kind: "select-repo" } : { kind: "login" },
  );
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [tab, setTab] = useState<"files" | "commits" | "members">("files");
  const [members, setMembers] = useState<Map<string, MemberInfo>>(new Map());
  const [commitPage, setCommitPage] = useState(1);

  const owner = view.kind === "viewer" ? view.owner : "";
  const repo = view.kind === "viewer" ? view.repo : "";

  const { tree, loading, error, commits, loadRepo, loadFile, loadCommits } =
    useRepo(token);
  const {
    unlocked,
    initFromWelcome,
    unlockFromStore,
    hasStoredState,
    decryptFile,
  } = useCrypto();

  const [hasStored, setHasStored] = useState(false);
  const checkedRef = useRef(false);

  // Check for stored state when entering viewer
  useEffect(() => {
    if (view.kind === "viewer" && !checkedRef.current) {
      checkedRef.current = true;
      hasStoredState(`${view.owner}/${view.repo}`).then(setHasStored);
    }
  }, [view, hasStoredState]);

  const handleLogin = useCallback(
    (t: string) => {
      setToken(t);
      setView({ kind: "select-repo" });
    },
    [setToken],
  );

  const handleSelectRepo = useCallback(
    (o: string, r: string) => {
      setView({ kind: "viewer", owner: o, repo: r });
      setSelectedFile(null);
      setTab("files");
      checkedRef.current = false;
      loadRepo(o, r);
      loadCommits(o, r, 1);
    },
    [loadRepo, loadCommits],
  );

  const handleLogout = useCallback(() => {
    logout();
    setView({ kind: "login" });
  }, [logout]);

  const handleBack = useCallback(() => {
    setView({ kind: "select-repo" });
    setSelectedFile(null);
  }, []);

  // Load members from .mlsgit/members/
  useEffect(() => {
    if (view.kind !== "viewer" || !token || !tree) return;
    const memberNodes = tree.find((n) => n.path === ".mlsgit")
      ?.children?.find((n) => n.name === "members")?.children;
    if (!memberNodes) return;

    const tomlFiles = memberNodes.filter((n) => n.name.endsWith(".toml"));

    Promise.all(
      tomlFiles.map(async (n) => {
        try {
          const content = await getRawFileContent(
            view.owner,
            view.repo,
            n.path,
            "HEAD",
            { token },
          );
          const id = n.name.replace(".toml", "");
          return [id, parseMemberTOML(content)] as const;
        } catch {
          return null;
        }
      }),
    ).then((results) => {
      const map = new Map<string, MemberInfo>();
      for (const r of results) {
        if (r) map.set(r[0], r[1]);
      }
      setMembers(map);
    });
  }, [view, token, tree]);

  // Get archive data for crypto
  const loadArchiveData = useCallback(async (): Promise<Uint8Array | null> => {
    if (!token || view.kind !== "viewer") return null;
    try {
      const b64 = await getRawFileContent(
        view.owner,
        view.repo,
        ".mlsgit/epoch_keys.b64",
        "HEAD",
        { token },
      );
      return b64Decode(b64.trim());
    } catch {
      return null;
    }
  }, [token, view]);

  const handleUnlock = useCallback(
    async (rawSecret: Uint8Array, epoch: number) => {
      const archiveData = await loadArchiveData();
      await initFromWelcome(rawSecret, epoch, archiveData);
    },
    [initFromWelcome, loadArchiveData],
  );

  const handleUnlockFromStore = useCallback(
    async (passphrase: string): Promise<boolean> => {
      if (view.kind !== "viewer") return false;
      const archiveData = await loadArchiveData();
      return unlockFromStore(
        `${view.owner}/${view.repo}`,
        passphrase,
        archiveData,
      );
    },
    [view, unlockFromStore, loadArchiveData],
  );

  const handleDecryptFile = useCallback(
    async (ciphertext: string, filePath: string): Promise<string | null> => {
      if (!token || view.kind !== "viewer") return ciphertext;

      const getMemberTOML = async (author: string): Promise<string> => {
        return getRawFileContent(
          view.owner,
          view.repo,
          `.mlsgit/members/${author}.toml`,
          "HEAD",
          { token },
        );
      };

      return decryptFile(ciphertext, filePath, getMemberTOML);
    },
    [token, view, decryptFile],
  );

  // Route views
  if (view.kind === "login") {
    return <AuthGate onToken={handleLogin} />;
  }

  if (view.kind === "select-repo") {
    return <RepoSelector onSelect={handleSelectRepo} onLogout={handleLogout} />;
  }

  // Viewer
  const sidebar = (
    <div>
      <div style={tabBarStyles.bar}>
        {(["files", "commits", "members"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              ...tabBarStyles.tab,
              ...(tab === t ? tabBarStyles.active : {}),
            }}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      {tab === "files" && tree && (
        <FileTree
          nodes={tree}
          onSelectFile={setSelectedFile}
          selectedPath={selectedFile}
        />
      )}
      {tab === "commits" && (
        <CommitLog
          commits={commits}
          onLoadMore={() => {
            const next = commitPage + 1;
            setCommitPage(next);
            loadCommits(owner, repo, next);
          }}
        />
      )}
      {tab === "members" && <MemberList members={members} />}
    </div>
  );

  const content = (() => {
    if (loading) {
      return (
        <div style={{ padding: 40, textAlign: "center", color: "#656d76" }}>
          Loading repository...
        </div>
      );
    }
    if (error) {
      return (
        <div style={{ padding: 40, textAlign: "center", color: "#cf222e" }}>
          {error}
        </div>
      );
    }
    if (!unlocked) {
      return (
        <JoinFlow
          owner={owner}
          repo={repo}
          onUnlock={handleUnlock}
          hasStoredState={hasStored}
          onUnlockFromStore={handleUnlockFromStore}
        />
      );
    }
    if (selectedFile) {
      return (
        <FileViewer
          key={selectedFile}
          path={selectedFile}
          loadContent={() => loadFile(owner, repo, selectedFile)}
          decryptContent={handleDecryptFile}
        />
      );
    }
    return (
      <div style={{ padding: 40, textAlign: "center", color: "#656d76" }}>
        Select a file from the tree to view its contents.
      </div>
    );
  })();

  return (
    <Layout
      sidebar={sidebar}
      content={content}
      owner={owner}
      repo={repo}
      onBack={handleBack}
      onLogout={handleLogout}
    />
  );
}

const tabBarStyles: Record<string, React.CSSProperties> = {
  bar: {
    display: "flex",
    borderBottom: "1px solid #d0d7de",
  },
  tab: {
    flex: 1,
    padding: "10px 8px",
    border: "none",
    background: "none",
    cursor: "pointer",
    fontSize: 12,
    fontWeight: 500,
    color: "#656d76",
    borderBottom: "2px solid transparent",
  },
  active: {
    color: "#24292f",
    borderBottomColor: "#fd8c73",
  },
};
