/**
 * MLSGit decryption pipeline for the browser.
 * Parses ciphertext chains, decrypts base blocks and deltas,
 * verifies signatures and hash chains.
 */

import { diff_match_patch } from "diff-match-patch";
import { b64UrlDecode, b64Decode } from "./base64.js";
import {
  deriveFileKey,
  aesGcmDecrypt,
  sha256Hex,
  verifyEd25519,
  advanceEpochSecret,
  exportEpochSecret,
  deriveArchiveKey,
} from "./crypto.js";
import type {
  DeltaRecord,
  DeltaRecordJSON,
  EpochArchive,
  MemberInfo,
} from "../types/index.js";

const DELTA_SEPARATOR = "\n---MLSGIT-DELTA---\n";

const dmp = new diff_match_patch();

/** Parse a base64url-encoded DeltaRecord. */
export function parseDeltaRecord(b64Block: string): DeltaRecord {
  const jsonBytes = b64UrlDecode(b64Block);
  const obj: DeltaRecordJSON = JSON.parse(
    new TextDecoder().decode(jsonBytes),
  );
  return {
    epoch: obj.epoch,
    seq: obj.seq,
    iv: b64UrlDecode(obj.iv),
    ct: b64UrlDecode(obj.ct),
    sig: b64UrlDecode(obj.sig),
    author: obj.author,
    prev_hash: obj.prev_hash,
    file_path: obj.file_path,
  };
}

/** Type for epoch secret lookup. */
export type GetEpochSecret = (epoch: number) => Promise<Uint8Array>;

/** Type for public key lookup. */
export type GetPublicKey = (author: string) => Promise<Uint8Array>;

/**
 * Decrypt a full ciphertext chain (base block + deltas).
 * Returns the final plaintext string.
 */
export async function decryptChain(
  ciphertext: string,
  getEpochSecret: GetEpochSecret,
  filePath: string,
  getPublicKey: GetPublicKey,
): Promise<string> {
  const blocks = ciphertext.split(DELTA_SEPARATOR);
  if (blocks.length === 0 || blocks[0] === "") {
    throw new Error("empty ciphertext");
  }

  // Decrypt base block
  const baseRecord = parseDeltaRecord(blocks[0]!);
  const basePath = baseRecord.file_path || filePath;

  const baseEpochSecret = await getEpochSecret(baseRecord.epoch);
  const baseKey = await deriveFileKey(baseEpochSecret, basePath, baseRecord.epoch);

  // Verify signature
  const pubKey = await getPublicKey(baseRecord.author);
  const sigData = new Uint8Array([...baseRecord.iv, ...baseRecord.ct]);
  const sigValid = await verifyEd25519(pubKey, sigData, baseRecord.sig);
  if (!sigValid) {
    throw new Error(
      `signature verification failed on base block (author=${baseRecord.author})`,
    );
  }

  const basePlaintext = await aesGcmDecrypt(baseKey, baseRecord.iv, baseRecord.ct);
  let text = new TextDecoder().decode(basePlaintext);

  // Verify hash chain and apply deltas
  let prevContent = blocks[0]!;
  for (let i = 1; i < blocks.length; i++) {
    const record = parseDeltaRecord(blocks[i]!);

    const expectedHash = await sha256Hex(prevContent);
    if (record.prev_hash !== expectedHash) {
      throw new Error(`hash chain broken at delta ${i}`);
    }

    const deltaPath = record.file_path || filePath;
    const deltaEpochSecret = await getEpochSecret(record.epoch);
    const deltaKey = await deriveFileKey(
      deltaEpochSecret,
      deltaPath,
      record.epoch,
    );

    const deltaPub = await getPublicKey(record.author);
    const deltaSigData = new Uint8Array([...record.iv, ...record.ct]);
    const deltaSigValid = await verifyEd25519(
      deltaPub,
      deltaSigData,
      record.sig,
    );
    if (!deltaSigValid) {
      throw new Error(
        `signature verification failed on delta ${i} (author=${record.author})`,
      );
    }

    const deltaBytes = await aesGcmDecrypt(deltaKey, record.iv, record.ct);
    const deltaText = new TextDecoder().decode(deltaBytes);

    // Apply diff-match-patch delta
    const patches = dmp.patch_fromText(deltaText);
    const [result] = dmp.patch_apply(patches, text);
    text = result;

    prevContent = prevContent + DELTA_SEPARATOR + blocks[i]!;
  }

  return text;
}

/**
 * Decrypt the epoch key archive.
 * The archive is AES-GCM encrypted under a key derived from the exported epoch secret.
 * Format: nonce (12 bytes) || ciphertext+tag
 * Plaintext is JSON: { "0": "<b64url secret>", "1": "<b64url secret>", ... }
 */
export async function decryptArchive(
  data: Uint8Array,
  exportedEpochSecret: Uint8Array,
): Promise<EpochArchive> {
  const IV_SIZE = 12;
  if (data.length < IV_SIZE) {
    throw new Error("archive data too short");
  }
  const nonce = data.slice(0, IV_SIZE);
  const ct = data.slice(IV_SIZE);
  const archiveKey = await deriveArchiveKey(exportedEpochSecret);
  const plaintext = await aesGcmDecrypt(archiveKey, nonce, ct);
  const json: Record<string, string> = JSON.parse(
    new TextDecoder().decode(plaintext),
  );

  const archive: EpochArchive = new Map();
  for (const [epochStr, secretB64] of Object.entries(json)) {
    const epoch = parseInt(epochStr, 10);
    const secret = b64UrlDecode(secretB64);
    archive.set(epoch, secret);
  }
  return archive;
}

/**
 * Parse a Welcome message (standard base64 of JSON).
 */
export function parseWelcome(b64: string): {
  groupId: string;
  epoch: number;
  epochSecret: Uint8Array;
  leafIndex: number;
} {
  const json = JSON.parse(
    new TextDecoder().decode(b64Decode(b64)),
  );
  return {
    groupId: json.group_id,
    epoch: json.epoch,
    epochSecret: b64Decode(json.epoch_secret),
    leafIndex: json.leaf_index,
  };
}

/**
 * Check if data looks like MLSGit ciphertext.
 * Matches Go's LooksCritCiphertext.
 */
export function looksCritCiphertext(data: string): boolean {
  let firstBlock = data;
  const idx = data.indexOf(DELTA_SEPARATOR);
  if (idx >= 0) {
    firstBlock = data.substring(0, idx);
  }
  firstBlock = firstBlock.trim();
  if (!firstBlock) return false;

  try {
    const jsonBytes = b64UrlDecode(firstBlock);
    const obj = JSON.parse(new TextDecoder().decode(jsonBytes));
    return "epoch" in obj && "ct" in obj && "iv" in obj;
  } catch {
    return false;
  }
}

/**
 * Parse a member TOML file. Simplified parser for the specific format.
 */
export function parseMemberTOML(toml: string): MemberInfo {
  // Parse the specific format used by mlsgit member TOML files
  const nameMatch = toml.match(/name\s*=\s*"([^"]*)"/);
  const epochMatch = toml.match(/joined_epoch\s*=\s*(\d+)/);
  const addedByMatch = toml.match(/added_by\s*=\s*"([^"]*)"/);

  // Extract PEM public key (multi-line string between triple quotes)
  const pemMatch = toml.match(
    /public_key\s*=\s*"""\s*([\s\S]*?)"""/,
  );

  return {
    name: nameMatch?.[1] ?? "",
    publicKey: pemMatch?.[1]?.trim() ?? "",
    joinedEpoch: epochMatch?.[1] ? parseInt(epochMatch[1], 10) : 0,
    addedBy: addedByMatch?.[1] ?? "",
  };
}

/**
 * Build an epoch secret lookup function from an archive and a raw epoch secret.
 * Can ratchet forward from the known raw secret to derive secrets for future epochs.
 */
export async function buildEpochSecretLookup(
  archive: EpochArchive,
  rawSecret: Uint8Array,
  currentEpoch: number,
): Promise<GetEpochSecret> {
  // Cache of raw secrets by epoch for ratcheting
  const rawSecrets = new Map<number, Uint8Array>();
  rawSecrets.set(currentEpoch, rawSecret);

  return async (epoch: number): Promise<Uint8Array> => {
    // Check archive first (contains exported secrets)
    const archived = archive.get(epoch);
    if (archived) return archived;

    // Ratchet forward from the closest known raw secret
    let closestEpoch = -1;
    for (const e of rawSecrets.keys()) {
      if (e <= epoch && e > closestEpoch) closestEpoch = e;
    }

    if (closestEpoch < 0) {
      throw new Error(`no secret available for epoch ${epoch}`);
    }

    let secret = rawSecrets.get(closestEpoch)!;
    for (let e = closestEpoch; e < epoch; e++) {
      secret = await advanceEpochSecret(secret, e);
      rawSecrets.set(e + 1, secret);
    }

    const exported = await exportEpochSecret(secret);
    archive.set(epoch, exported);
    return exported;
  };
}
