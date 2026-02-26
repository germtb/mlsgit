import { useState } from "react";

interface RepoSelectorProps {
  onSelect: (owner: string, repo: string) => void;
  onLogout: () => void;
}

export function RepoSelector({ onSelect, onLogout }: RepoSelectorProps) {
  const [input, setInput] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const parts = input.trim().split("/");
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      setError("Enter as owner/repo (e.g. alice/my-project)");
      return;
    }
    setError("");
    onSelect(parts[0], parts[1]);
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>Select Repository</h2>
        <form onSubmit={handleSubmit} style={styles.form}>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="owner/repo"
            style={styles.input}
            autoFocus
          />
          {error && <p style={styles.error}>{error}</p>}
          <button type="submit" style={styles.button} disabled={!input.trim()}>
            Open Repository
          </button>
        </form>
        <button onClick={onLogout} style={styles.logout}>
          Sign Out
        </button>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    minHeight: "100vh",
    padding: 20,
  },
  card: {
    background: "#fff",
    borderRadius: 8,
    padding: 40,
    maxWidth: 440,
    width: "100%",
    boxShadow: "0 1px 3px rgba(0,0,0,0.12)",
    border: "1px solid #d0d7de",
  },
  title: {
    fontSize: 20,
    fontWeight: 600,
    marginBottom: 16,
  },
  form: {
    display: "flex",
    flexDirection: "column" as const,
    gap: 12,
  },
  input: {
    padding: "8px 12px",
    border: "1px solid #d0d7de",
    borderRadius: 6,
    fontSize: 14,
  },
  error: {
    color: "#cf222e",
    fontSize: 13,
  },
  button: {
    padding: "10px 16px",
    background: "#2da44e",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    fontSize: 14,
    fontWeight: 500,
    cursor: "pointer",
  },
  logout: {
    marginTop: 16,
    background: "none",
    border: "none",
    color: "#656d76",
    cursor: "pointer",
    fontSize: 13,
    textDecoration: "underline",
  },
};
