import { useEffect, useState } from "react";
import hljs from "highlight.js";
import "highlight.js/styles/github.min.css";

interface FileViewerProps {
  path: string;
  loadContent: () => Promise<string>;
  decryptContent: (
    ciphertext: string,
    filePath: string,
  ) => Promise<string | null>;
}

export function FileViewer({
  path,
  loadContent,
  decryptContent,
}: FileViewerProps) {
  const [content, setContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [encrypted, setEncrypted] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setContent(null);
    setEncrypted(false);

    (async () => {
      try {
        const raw = await loadContent();

        if (cancelled) return;

        // Try to decrypt
        const decrypted = await decryptContent(raw, path);
        if (cancelled) return;

        if (decrypted !== null && decrypted !== raw) {
          setEncrypted(true);
          setContent(decrypted);
        } else {
          setContent(raw);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load file");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [path, loadContent, decryptContent]);

  if (loading) {
    return (
      <div style={styles.center}>
        <span style={styles.spinner}>Decrypting...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.center}>
        <span style={styles.error}>{error}</span>
      </div>
    );
  }

  const ext = path.split(".").pop() ?? "";
  let highlighted = content ?? "";
  try {
    if (hljs.getLanguage(ext)) {
      highlighted = hljs.highlight(content ?? "", { language: ext }).value;
    } else {
      highlighted = hljs.highlightAuto(content ?? "").value;
    }
  } catch {
    // Fall back to plain text
  }

  return (
    <div style={styles.wrapper}>
      <div style={styles.header}>
        <span style={styles.path}>{path}</span>
        {encrypted && <span style={styles.badge}>Decrypted</span>}
      </div>
      <pre
        style={styles.code}
        dangerouslySetInnerHTML={{ __html: highlighted }}
      />
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  wrapper: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
  },
  header: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    padding: "8px 16px",
    borderBottom: "1px solid #d0d7de",
    background: "#f6f8fa",
    fontSize: 13,
  },
  path: {
    fontFamily: "monospace",
    fontWeight: 600,
  },
  badge: {
    background: "#ddf4ff",
    color: "#0969da",
    padding: "2px 8px",
    borderRadius: 12,
    fontSize: 11,
    fontWeight: 600,
  },
  code: {
    flex: 1,
    overflow: "auto",
    padding: 16,
    margin: 0,
    fontSize: 13,
    fontFamily: "'SF Mono', Menlo, Consolas, monospace",
    lineHeight: 1.5,
    whiteSpace: "pre-wrap",
    wordWrap: "break-word",
  },
  center: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    height: "100%",
    padding: 40,
  },
  spinner: {
    color: "#656d76",
    fontSize: 14,
  },
  error: {
    color: "#cf222e",
    fontSize: 14,
  },
};
