import { useState } from "react";
import type { TreeNode } from "../types/index.js";

interface FileTreeProps {
  nodes: TreeNode[];
  onSelectFile: (path: string) => void;
  selectedPath: string | null;
}

export function FileTree({ nodes, onSelectFile, selectedPath }: FileTreeProps) {
  return (
    <div style={{ padding: "8px 0" }}>
      {nodes.map((node) => (
        <TreeItem
          key={node.path}
          node={node}
          depth={0}
          onSelectFile={onSelectFile}
          selectedPath={selectedPath}
        />
      ))}
    </div>
  );
}

interface TreeItemProps {
  node: TreeNode;
  depth: number;
  onSelectFile: (path: string) => void;
  selectedPath: string | null;
}

function TreeItem({ node, depth, onSelectFile, selectedPath }: TreeItemProps) {
  const [expanded, setExpanded] = useState(depth < 1);
  const isDir = node.type === "dir";
  const isSelected = node.path === selectedPath;

  const handleClick = () => {
    if (isDir) {
      setExpanded(!expanded);
    } else {
      onSelectFile(node.path);
    }
  };

  return (
    <>
      <div
        onClick={handleClick}
        style={{
          padding: "4px 12px",
          paddingLeft: 12 + depth * 16,
          cursor: "pointer",
          fontSize: 13,
          fontFamily: "monospace",
          background: isSelected ? "#ddf4ff" : "transparent",
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
        onMouseEnter={(e) => {
          if (!isSelected) e.currentTarget.style.background = "#f6f8fa";
        }}
        onMouseLeave={(e) => {
          if (!isSelected) e.currentTarget.style.background = "transparent";
        }}
      >
        <span style={{ width: 16, textAlign: "center", flexShrink: 0 }}>
          {isDir ? (expanded ? "▾" : "▸") : ""}
        </span>
        <span style={{ color: isDir ? "#0969da" : "#24292f" }}>
          {node.name}
        </span>
      </div>
      {isDir && expanded && node.children && (
        <>
          {node.children.map((child) => (
            <TreeItem
              key={child.path}
              node={child}
              depth={depth + 1}
              onSelectFile={onSelectFile}
              selectedPath={selectedPath}
            />
          ))}
        </>
      )}
    </>
  );
}
