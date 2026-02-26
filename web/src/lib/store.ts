/**
 * IndexedDB-based encrypted key storage.
 * Keys are encrypted with a user passphrase via PBKDF2 + AES-GCM.
 */

const DB_NAME = "mlsgit-keys";
const DB_VERSION = 1;
const STORE_NAME = "repos";

interface StoredEntry {
  repoKey: string; // "owner/repo"
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

interface KeyData {
  rawEpochSecret: Uint8Array;
  epoch: number;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "repoKey" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function derivePassphraseKey(
  passphrase: string,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Save key data for a repo, encrypted with passphrase. */
export async function saveKeyData(
  repoKey: string,
  data: KeyData,
  passphrase: string,
): Promise<void> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePassphraseKey(passphrase, salt);

  const plaintext = new TextEncoder().encode(
    JSON.stringify({
      rawEpochSecret: Array.from(data.rawEpochSecret),
      epoch: data.epoch,
    }),
  );

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext),
  );

  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  const entry: StoredEntry = { repoKey, salt, iv, ciphertext };
  store.put(entry);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

/** Load key data for a repo, decrypting with passphrase. */
export async function loadKeyData(
  repoKey: string,
  passphrase: string,
): Promise<KeyData | null> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const entry = await new Promise<StoredEntry | undefined>(
    (resolve, reject) => {
      const req = store.get(repoKey);
      req.onsuccess = () => resolve(req.result as StoredEntry | undefined);
      req.onerror = () => reject(req.error);
    },
  );
  db.close();

  if (!entry) return null;

  const key = await derivePassphraseKey(passphrase, entry.salt);
  try {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: entry.iv as BufferSource },
      key,
      entry.ciphertext as BufferSource,
    );
    const data = JSON.parse(new TextDecoder().decode(plaintext)) as {
      rawEpochSecret: number[];
      epoch: number;
    };
    return {
      rawEpochSecret: new Uint8Array(data.rawEpochSecret),
      epoch: data.epoch,
    };
  } catch {
    return null; // Wrong passphrase
  }
}

/** Check if we have stored key data for a repo. */
export async function hasKeyData(repoKey: string): Promise<boolean> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readonly");
  const store = tx.objectStore(STORE_NAME);
  const count = await new Promise<number>((resolve, reject) => {
    const req = store.count(repoKey);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return count > 0;
}

/** Delete stored key data for a repo. */
export async function deleteKeyData(repoKey: string): Promise<void> {
  const db = await openDB();
  const tx = db.transaction(STORE_NAME, "readwrite");
  const store = tx.objectStore(STORE_NAME);
  store.delete(repoKey);
  await new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}
