import type { GitHubCommit } from "../types/index.js";

interface CommitLogProps {
  commits: GitHubCommit[];
  onLoadMore: () => void;
}

export function CommitLog({ commits, onLoadMore }: CommitLogProps) {
  if (commits.length === 0) {
    return <div style={styles.empty}>No commits loaded</div>;
  }

  return (
    <div style={styles.wrapper}>
      <h3 style={styles.title}>Commits</h3>
      <div style={styles.list}>
        {commits.map((c) => (
          <div key={c.sha} style={styles.item}>
            <div style={styles.message}>
              {c.commit.message.split("\n")[0]}
            </div>
            <div style={styles.meta}>
              <span>{c.commit.author.name}</span>
              <span style={styles.sha}>{c.sha.substring(0, 7)}</span>
              <span style={styles.date}>
                {new Date(c.commit.author.date).toLocaleDateString()}
              </span>
            </div>
          </div>
        ))}
      </div>
      <button onClick={onLoadMore} style={styles.loadMore}>
        Load more
      </button>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    padding: 16,
  },
  title: {
    fontSize: 16,
    fontWeight: 600,
    marginBottom: 12,
  },
  list: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  item: {
    padding: 12,
    border: "1px solid #d0d7de",
    borderRadius: 6,
  },
  message: {
    fontSize: 14,
    fontWeight: 500,
    marginBottom: 4,
  },
  meta: {
    display: "flex",
    gap: 12,
    fontSize: 12,
    color: "#656d76",
  },
  sha: {
    fontFamily: "monospace",
  },
  date: {
    marginLeft: "auto",
  },
  empty: {
    padding: 40,
    textAlign: "center",
    color: "#656d76",
  },
  loadMore: {
    marginTop: 12,
    padding: "8px 16px",
    background: "#f6f8fa",
    border: "1px solid #d0d7de",
    borderRadius: 6,
    cursor: "pointer",
    fontSize: 13,
    width: "100%",
  },
};
