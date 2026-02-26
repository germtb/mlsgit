import { useState } from "react";

interface JoinFlowProps {
  owner: string;
  repo: string;
  onUnlock: (rawSecret: Uint8Array, epoch: number) => Promise<void>;
  hasStoredState: boolean;
  onUnlockFromStore: (passphrase: string) => Promise<boolean>;
}

/**
 * Join flow wizard.
 * For now, supports:
 * 1. Unlocking from stored state with passphrase
 * 2. Entering a raw epoch secret (from Welcome) manually
 *
 * Full join flow (key generation + PR) is a future enhancement.
 */
export function JoinFlow({
  owner,
  repo,
  onUnlock,
  hasStoredState,
  onUnlockFromStore,
}: JoinFlowProps) {
  const [mode, setMode] = useState<"choose" | "passphrase" | "manual">(
    "choose",
  );
  const [passphrase, setPassphrase] = useState("");
  const [secretInput, setSecretInput] = useState("");
  const [epochInput, setEpochInput] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handlePassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const ok = await onUnlockFromStore(passphrase);
      if (!ok) setError("Wrong passphrase or no stored data");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unlock failed");
    } finally {
      setLoading(false);
    }
  };

  const handleManual = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const secret = Uint8Array.from(atob(secretInput), (c) =>
        c.charCodeAt(0),
      );
      const epoch = parseInt(epochInput, 10);
      if (secret.length !== 32) {
        setError("Secret must be 32 bytes (base64-encoded)");
        return;
      }
      if (isNaN(epoch) || epoch < 0) {
        setError("Invalid epoch number");
        return;
      }
      await onUnlock(secret, epoch);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to unlock");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h2 style={styles.title}>
          Unlock {owner}/{repo}
        </h2>
        <p style={styles.subtitle}>
          You need an epoch secret to decrypt files in this repository.
        </p>

        {mode === "choose" && (
          <div style={styles.choices}>
            {hasStoredState && (
              <button
                style={styles.choiceBtn}
                onClick={() => setMode("passphrase")}
              >
                Unlock with passphrase
                <span style={styles.choiceDesc}>
                  Use a previously saved passphrase
                </span>
              </button>
            )}
            <button
              style={styles.choiceBtn}
              onClick={() => setMode("manual")}
            >
              Enter epoch secret
              <span style={styles.choiceDesc}>
                Paste base64-encoded secret from Welcome
              </span>
            </button>
          </div>
        )}

        {mode === "passphrase" && (
          <form onSubmit={handlePassphrase} style={styles.form}>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase"
              style={styles.input}
              autoFocus
            />
            {error && <p style={styles.error}>{error}</p>}
            <div style={styles.buttons}>
              <button
                type="button"
                style={styles.backBtn}
                onClick={() => {
                  setMode("choose");
                  setError("");
                }}
              >
                Back
              </button>
              <button type="submit" style={styles.submitBtn} disabled={loading}>
                {loading ? "Unlocking..." : "Unlock"}
              </button>
            </div>
          </form>
        )}

        {mode === "manual" && (
          <form onSubmit={handleManual} style={styles.form}>
            <label style={styles.label}>
              Epoch secret (base64)
              <input
                type="text"
                value={secretInput}
                onChange={(e) => setSecretInput(e.target.value)}
                placeholder="Base64-encoded 32-byte secret"
                style={styles.input}
                autoFocus
              />
            </label>
            <label style={styles.label}>
              Epoch number
              <input
                type="number"
                value={epochInput}
                onChange={(e) => setEpochInput(e.target.value)}
                placeholder="0"
                style={styles.input}
              />
            </label>
            {error && <p style={styles.error}>{error}</p>}
            <div style={styles.buttons}>
              <button
                type="button"
                style={styles.backBtn}
                onClick={() => {
                  setMode("choose");
                  setError("");
                }}
              >
                Back
              </button>
              <button type="submit" style={styles.submitBtn} disabled={loading}>
                {loading ? "Unlocking..." : "Unlock"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
    padding: 40,
  },
  card: {
    background: "#fff",
    borderRadius: 8,
    padding: 32,
    maxWidth: 480,
    width: "100%",
    border: "1px solid #d0d7de",
  },
  title: {
    fontSize: 20,
    fontWeight: 600,
    marginBottom: 8,
  },
  subtitle: {
    color: "#656d76",
    fontSize: 14,
    marginBottom: 20,
  },
  choices: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
  },
  choiceBtn: {
    display: "flex",
    flexDirection: "column",
    alignItems: "flex-start",
    padding: 16,
    border: "1px solid #d0d7de",
    borderRadius: 6,
    background: "#f6f8fa",
    cursor: "pointer",
    fontSize: 14,
    fontWeight: 500,
    textAlign: "left",
  },
  choiceDesc: {
    fontSize: 12,
    color: "#656d76",
    fontWeight: 400,
    marginTop: 4,
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: 12,
  },
  label: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    fontSize: 13,
    fontWeight: 500,
  },
  input: {
    padding: "8px 12px",
    border: "1px solid #d0d7de",
    borderRadius: 6,
    fontSize: 14,
    fontFamily: "monospace",
  },
  error: {
    color: "#cf222e",
    fontSize: 13,
  },
  buttons: {
    display: "flex",
    gap: 8,
    marginTop: 8,
  },
  backBtn: {
    padding: "8px 16px",
    background: "#f6f8fa",
    border: "1px solid #d0d7de",
    borderRadius: 6,
    cursor: "pointer",
    fontSize: 13,
  },
  submitBtn: {
    flex: 1,
    padding: "8px 16px",
    background: "#2da44e",
    color: "#fff",
    border: "none",
    borderRadius: 6,
    cursor: "pointer",
    fontSize: 13,
    fontWeight: 500,
  },
};
