/** A single delta record in the ciphertext chain. */
export interface DeltaRecord {
  epoch: number;
  seq: number;
  iv: Uint8Array;
  ct: Uint8Array;
  sig: Uint8Array;
  author: string;
  prev_hash: string;
  file_path: string;
}

/** JSON wire format for DeltaRecord (base64url-encoded byte fields). */
export interface DeltaRecordJSON {
  epoch: number;
  seq: number;
  iv: string;
  ct: string;
  sig: string;
  author: string;
  prev_hash: string;
  file_path: string;
}

/** Welcome data sent to a new member joining the group. */
export interface WelcomeData {
  group_id: string;
  epoch: number;
  epoch_secret: string; // base64
  members: MemberEntry[];
  leaf_index: number;
}

/** A member in the MLS group state. */
export interface MemberEntry {
  sig_pub: string;
  init_pub: string;
  active: boolean;
}

/** Committed group state (no epoch_secret). */
export interface CommittedGroupState {
  group_id: string;
  epoch: number;
  members: MemberEntry[];
}

/** Member info from .mlsgit/members/*.toml */
export interface MemberInfo {
  name: string;
  publicKey: string;
  joinedEpoch: number;
  addedBy: string;
}

/** A file or directory entry from the GitHub Trees API. */
export interface TreeEntry {
  path: string;
  mode: string;
  type: "blob" | "tree";
  sha: string;
  size?: number;
}

/** A tree node for the file browser. */
export interface TreeNode {
  name: string;
  path: string;
  type: "file" | "dir";
  children?: TreeNode[];
}

/** A commit from the GitHub API. */
export interface GitHubCommit {
  sha: string;
  commit: {
    message: string;
    author: {
      name: string;
      date: string;
    };
  };
}

/** Epoch key archive: epoch number -> base64-encoded exported secret. */
export type EpochArchive = Map<number, Uint8Array>;

/** Crypto state for a repo. */
export interface CryptoState {
  rawEpochSecret: Uint8Array;
  epoch: number;
  archive: EpochArchive;
}

/** App-level view state. */
export type View =
  | { kind: "login" }
  | { kind: "select-repo" }
  | { kind: "viewer"; owner: string; repo: string };
