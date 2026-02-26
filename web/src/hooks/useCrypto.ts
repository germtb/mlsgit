import { useState, useCallback } from "react";
import { b64Decode } from "../lib/base64.js";
import {
  exportEpochSecret,
} from "../lib/crypto.js";
import {
  decryptChain,
  decryptArchive,
  looksCritCiphertext,
  parseMemberTOML,
  buildEpochSecretLookup,
} from "../lib/mlsgit.js";
import type { EpochArchive, CryptoState } from "../types/index.js";
import { saveKeyData, loadKeyData, hasKeyData } from "../lib/store.js";

export function useCrypto() {
  const [cryptoState, setCryptoState] = useState<CryptoState | null>(null);
  const [unlocked, setUnlocked] = useState(false);

  /** Initialize crypto state from a Welcome message. */
  const initFromWelcome = useCallback(
    async (
      rawEpochSecret: Uint8Array,
      epoch: number,
      archiveData: Uint8Array | null,
    ) => {
      const exported = await exportEpochSecret(rawEpochSecret);
      let archive: EpochArchive = new Map();

      if (archiveData) {
        try {
          archive = await decryptArchive(archiveData, exported);
        } catch {
          // Can't decrypt archive, start fresh
        }
      }

      // Ensure current epoch is in archive
      if (!archive.has(epoch)) {
        archive.set(epoch, exported);
      }

      setCryptoState({ rawEpochSecret, epoch, archive });
      setUnlocked(true);
    },
    [],
  );

  /** Try to unlock from IndexedDB. */
  const unlockFromStore = useCallback(
    async (
      repoKey: string,
      passphrase: string,
      archiveData: Uint8Array | null,
    ): Promise<boolean> => {
      const data = await loadKeyData(repoKey, passphrase);
      if (!data) return false;
      await initFromWelcome(data.rawEpochSecret, data.epoch, archiveData);
      return true;
    },
    [initFromWelcome],
  );

  /** Save current crypto state to IndexedDB. */
  const saveToStore = useCallback(
    async (repoKey: string, passphrase: string) => {
      if (!cryptoState) return;
      await saveKeyData(
        repoKey,
        {
          rawEpochSecret: cryptoState.rawEpochSecret,
          epoch: cryptoState.epoch,
        },
        passphrase,
      );
    },
    [cryptoState],
  );

  /** Check if there's stored crypto state for a repo. */
  const hasStoredState = useCallback(async (repoKey: string) => {
    return hasKeyData(repoKey);
  }, []);

  /** Decrypt a file. */
  const decryptFile = useCallback(
    async (
      ciphertext: string,
      filePath: string,
      getMemberTOML: (author: string) => Promise<string>,
    ): Promise<string | null> => {
      if (!cryptoState) return null;
      if (!looksCritCiphertext(ciphertext)) return ciphertext;

      const getEpochSecret = await buildEpochSecretLookup(
        cryptoState.archive,
        cryptoState.rawEpochSecret,
        cryptoState.epoch,
      );

      // Cache parsed member public keys
      const pubKeyCache = new Map<string, Uint8Array>();
      const getPublicKey = async (author: string): Promise<Uint8Array> => {
        const cached = pubKeyCache.get(author);
        if (cached) return cached;

        const toml = await getMemberTOML(author);
        const info = parseMemberTOML(toml);
        // Extract the raw Ed25519 public key from PEM
        const pubKey = pemToRawEd25519(info.publicKey);
        pubKeyCache.set(author, pubKey);
        return pubKey;
      };

      return decryptChain(ciphertext, getEpochSecret, filePath, getPublicKey);
    },
    [cryptoState],
  );

  return {
    cryptoState,
    unlocked,
    initFromWelcome,
    unlockFromStore,
    saveToStore,
    hasStoredState,
    decryptFile,
  };
}

/** Extract raw 32-byte Ed25519 public key from PEM format. */
function pemToRawEd25519(pem: string): Uint8Array {
  const lines = pem
    .split("\n")
    .filter((l) => !l.startsWith("-----") && l.trim() !== "");
  const der = b64Decode(lines.join(""));
  // Ed25519 public key DER is 44 bytes: 12-byte header + 32-byte key
  // The last 32 bytes are the raw key
  if (der.length === 44) {
    return der.slice(12);
  }
  // Fallback: if it's already 32 bytes
  if (der.length === 32) {
    return der;
  }
  // Try to find the key in the DER structure
  // OID for Ed25519 is 06 03 2b 65 70
  // After the OID sequence, there's a BIT STRING with the key
  return der.slice(der.length - 32);
}
