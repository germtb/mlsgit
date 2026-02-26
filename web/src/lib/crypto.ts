/**
 * WebCrypto wrappers matching the Go mlsgit implementation exactly.
 *
 * Key derivation chain:
 *   Raw epoch secret (32 bytes)
 *     ├── advanceEpochSecret(): HKDF(raw, salt=epoch_be64, info="mlsgit-epoch-advance")
 *     └── exportEpochSecret(): HKDF(raw, salt=nil, info="mlsgit-epoch-secret")
 *           └── deriveFileKey(): HKDF(exported, salt=filePath, info="mlsgit-file-key"||epoch_be64)
 */

const encoder = new TextEncoder();

// Helper type to satisfy TS 5.7+ strict Uint8Array/BufferSource checks
type Bytes = BufferSource;
function buf(a: Uint8Array): Bytes {
  return a as Bytes;
}

/** Convert a number to an 8-byte big-endian Uint8Array. */
function uint64BE(n: number): Uint8Array {
  const b = new Uint8Array(8);
  const hi = Math.floor(n / 0x100000000);
  const lo = n >>> 0;
  b[0] = (hi >>> 24) & 0xff;
  b[1] = (hi >>> 16) & 0xff;
  b[2] = (hi >>> 8) & 0xff;
  b[3] = hi & 0xff;
  b[4] = (lo >>> 24) & 0xff;
  b[5] = (lo >>> 16) & 0xff;
  b[6] = (lo >>> 8) & 0xff;
  b[7] = lo & 0xff;
  return b;
}

/** Concatenate multiple Uint8Arrays. */
function concat(...arrays: Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const a of arrays) totalLen += a.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

/**
 * HKDF-SHA256 key derivation.
 * Matches Go's hkdf.New(sha256.New, ikm, salt, info) + io.ReadFull(r, out).
 */
async function hkdfDerive(
  ikm: Uint8Array,
  salt: Uint8Array | null,
  info: Uint8Array,
  length: number,
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    buf(ikm),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: buf(salt ?? new Uint8Array(0)),
      info: buf(info),
    },
    keyMaterial,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Derive a per-file AES-256 key from the exported epoch secret.
 * key = HKDF-SHA256(secret=epochSecret, salt=filePath, info="mlsgit-file-key"||epoch_be64)
 */
export async function deriveFileKey(
  epochSecret: Uint8Array,
  filePath: string,
  epoch: number,
): Promise<CryptoKey> {
  const salt = encoder.encode(filePath);
  const info = concat(encoder.encode("mlsgit-file-key"), uint64BE(epoch));
  const rawKey = await hkdfDerive(epochSecret, salt, info, 32);
  return crypto.subtle.importKey("raw", buf(rawKey), "AES-GCM", false, [
    "decrypt",
  ]);
}

/**
 * Derive the raw 32-byte file key bytes (for testing).
 */
export async function deriveFileKeyBytes(
  epochSecret: Uint8Array,
  filePath: string,
  epoch: number,
): Promise<Uint8Array> {
  const salt = encoder.encode(filePath);
  const info = concat(encoder.encode("mlsgit-file-key"), uint64BE(epoch));
  return hkdfDerive(epochSecret, salt, info, 32);
}

/**
 * AES-256-GCM decrypt. Matches Go's gcm.Open(nil, nonce, ciphertext, nil).
 * The ciphertext includes the 16-byte GCM tag appended at the end.
 */
export async function aesGcmDecrypt(
  key: CryptoKey,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buf(nonce) },
    key,
    buf(ciphertext),
  );
  return new Uint8Array(plaintext);
}

/** SHA-256 hash, returned as hex string. */
export async function sha256Hex(data: string): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(data),
  );
  const bytes = new Uint8Array(hash);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Advance the raw epoch secret by one epoch (deterministic HKDF ratchet).
 * newSecret = HKDF(oldSecret, salt=epoch_be64, info="mlsgit-epoch-advance")
 * Then epoch increments.
 */
export async function advanceEpochSecret(
  rawSecret: Uint8Array,
  currentEpoch: number,
): Promise<Uint8Array> {
  const salt = uint64BE(currentEpoch);
  const info = encoder.encode("mlsgit-epoch-advance");
  return hkdfDerive(rawSecret, salt, info, 32);
}

/**
 * Export the epoch secret for file encryption.
 * exported = HKDF(rawSecret, salt=nil, info="mlsgit-epoch-secret")
 */
export async function exportEpochSecret(
  rawSecret: Uint8Array,
): Promise<Uint8Array> {
  const info = encoder.encode("mlsgit-epoch-secret");
  return hkdfDerive(rawSecret, null, info, 32);
}

/**
 * Verify an Ed25519 signature.
 * Returns true if the signature is valid.
 */
export async function verifyEd25519(
  pubKeyBytes: Uint8Array,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      buf(pubKeyBytes),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return crypto.subtle.verify("Ed25519", key, buf(signature), buf(data));
  } catch {
    return false;
  }
}

/**
 * Derive the archive encryption key from the exported epoch secret.
 * Same as DeriveFileKey with filePath="mlsgit-archive" and epoch=0.
 */
export async function deriveArchiveKey(
  exportedEpochSecret: Uint8Array,
): Promise<CryptoKey> {
  return deriveFileKey(exportedEpochSecret, "mlsgit-archive", 0);
}
