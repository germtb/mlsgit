import type { ReactNode } from "react";

interface LayoutProps {
  sidebar: ReactNode;
  content: ReactNode;
  owner: string;
  repo: string;
  onBack: () => void;
  onLogout: () => void;
}

export function Layout({
  sidebar,
  content,
  owner,
  repo,
  onBack,
  onLogout,
}: LayoutProps) {
  return (
    <div style={styles.wrapper}>
      <header style={styles.header}>
        <div style={styles.headerLeft}>
          <button onClick={onBack} style={styles.backBtn}>
            ← Repos
          </button>
          <span style={styles.repoName}>
            {owner}/{repo}
          </span>
        </div>
        <button onClick={onLogout} style={styles.logoutBtn}>
          Sign Out
        </button>
      </header>
      <div style={styles.body}>
        <aside style={styles.sidebar}>{sidebar}</aside>
        <main style={styles.content}>{content}</main>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    height: "100vh",
  },
  header: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "8px 16px",
    background: "#24292f",
    color: "#fff",
    fontSize: 14,
  },
  headerLeft: {
    display: "flex",
    alignItems: "center",
    gap: 12,
  },
  backBtn: {
    background: "none",
    border: "none",
    color: "#8b949e",
    cursor: "pointer",
    fontSize: 13,
  },
  repoName: {
    fontWeight: 600,
  },
  logoutBtn: {
    background: "none",
    border: "none",
    color: "#8b949e",
    cursor: "pointer",
    fontSize: 13,
  },
  body: {
    display: "flex",
    flex: 1,
    overflow: "hidden",
  },
  sidebar: {
    width: 280,
    borderRight: "1px solid #d0d7de",
    background: "#fff",
    overflow: "auto",
  },
  content: {
    flex: 1,
    overflow: "auto",
    background: "#fff",
  },
};
