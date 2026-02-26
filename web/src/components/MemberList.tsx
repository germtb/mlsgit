import type { MemberInfo } from "../types/index.js";

interface MemberListProps {
  members: Map<string, MemberInfo>;
}

export function MemberList({ members }: MemberListProps) {
  if (members.size === 0) {
    return <div style={styles.empty}>No members loaded</div>;
  }

  return (
    <div style={styles.wrapper}>
      <h3 style={styles.title}>Members ({members.size})</h3>
      <div style={styles.list}>
        {Array.from(members.entries()).map(([id, info]) => (
          <div key={id} style={styles.item}>
            <div style={styles.name}>{info.name}</div>
            <div style={styles.meta}>
              <span style={styles.id}>{id}</span>
              <span>Joined epoch {info.joinedEpoch}</span>
              {info.addedBy && <span>Added by {info.addedBy}</span>}
            </div>
          </div>
        ))}
      </div>
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
  name: {
    fontSize: 14,
    fontWeight: 600,
    marginBottom: 4,
  },
  meta: {
    display: "flex",
    gap: 12,
    fontSize: 12,
    color: "#656d76",
  },
  id: {
    fontFamily: "monospace",
  },
  empty: {
    padding: 40,
    textAlign: "center",
    color: "#656d76",
  },
};
