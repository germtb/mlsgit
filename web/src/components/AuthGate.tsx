import { useState } from "react";

interface AuthGateProps {
  onToken: (token: string) => void;
}

/**
 * GitHub authentication gate.
 * Accepts a personal access token (PAT) for API access.
 * A full OAuth flow would require a backend redirect URI.
 */
export function AuthGate({ onToken }: AuthGateProps) {
  const [token, setToken] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (token.trim()) {
      onToken(token.trim());
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>MLSGit Viewer</h1>
        <p style={styles.subtitle}>
          Browse and decrypt MLSGit-encrypted repositories
        </p>
        <form onSubmit={handleSubmit} style={styles.form}>
          <label style={styles.label}>
            GitHub Personal Access Token
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="ghp_..."
              style={styles.input}
              autoFocus
            />
          </label>
          <p style={styles.hint}>
            Needs <code>repo</code> scope for private repos.
          </p>
          <button type="submit" style={styles.button} disabled={!token.trim()}>
            Sign In
          </button>
        </form>
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
    fontSize: 24,
    fontWeight: 600,
    marginBottom: 8,
  },
  subtitle: {
    color: "#656d76",
    marginBottom: 24,
    fontSize: 14,
  },
  form: {
    display: "flex",
    flexDirection: "column" as const,
    gap: 12,
  },
  label: {
    display: "flex",
    flexDirection: "column" as const,
    gap: 6,
    fontSize: 14,
    fontWeight: 500,
  },
  input: {
    padding: "8px 12px",
    border: "1px solid #d0d7de",
    borderRadius: 6,
    fontSize: 14,
    fontFamily: "monospace",
  },
  hint: {
    fontSize: 12,
    color: "#656d76",
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
    marginTop: 8,
  },
};
