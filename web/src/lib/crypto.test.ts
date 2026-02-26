import { describe, it, expect } from "vitest";
import {
  deriveFileKeyBytes,
  advanceEpochSecret,
  exportEpochSecret,
} from "./crypto.js";

/** Convert hex string to Uint8Array. */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Convert Uint8Array to hex string. */
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Test vectors from Go implementation (TestPrintTestVectors)
const RAW_SECRET = hexToBytes(
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
);
const EXPORTED_SECRET = hexToBytes(
  "441cb3e22e4c95e66e844ed3969ac84e1781a02b55488161a65e525c2a7d8c58",
);

describe("crypto", () => {
  describe("exportEpochSecret", () => {
    it("matches Go test vector", async () => {
      const exported = await exportEpochSecret(RAW_SECRET);
      expect(bytesToHex(exported)).toBe(
        "441cb3e22e4c95e66e844ed3969ac84e1781a02b55488161a65e525c2a7d8c58",
      );
    });
  });

  describe("deriveFileKey", () => {
    it("matches Go test vector for test.txt epoch=0", async () => {
      const key = await deriveFileKeyBytes(EXPORTED_SECRET, "test.txt", 0);
      expect(bytesToHex(key)).toBe(
        "2945a9d5f7e22cef16e0a12fe76e05856f352816063b36733d142e4889215d44",
      );
    });

    it("matches Go test vector for src/main.go epoch=1", async () => {
      const key = await deriveFileKeyBytes(EXPORTED_SECRET, "src/main.go", 1);
      expect(bytesToHex(key)).toBe(
        "e09f687f41b7a56de5516e2cbe155ad3e947be085c57f41df1f7e53ab34aae5d",
      );
    });

    it("derives different keys for different paths", async () => {
      const key1 = await deriveFileKeyBytes(EXPORTED_SECRET, "a.txt", 0);
      const key2 = await deriveFileKeyBytes(EXPORTED_SECRET, "b.txt", 0);
      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });

    it("derives different keys for different epochs", async () => {
      const key1 = await deriveFileKeyBytes(EXPORTED_SECRET, "test.txt", 0);
      const key2 = await deriveFileKeyBytes(EXPORTED_SECRET, "test.txt", 1);
      expect(bytesToHex(key1)).not.toBe(bytesToHex(key2));
    });
  });

  describe("advanceEpochSecret", () => {
    it("matches Go test vector for epoch 0->1", async () => {
      const advanced = await advanceEpochSecret(RAW_SECRET, 0);
      expect(bytesToHex(advanced)).toBe(
        "d78e3e93c151a3015503710f54c3b861289cf7675aabdb3304afb41439376995",
      );
    });

    it("matches Go test vector for epoch 1->2", async () => {
      const epoch1Secret = hexToBytes(
        "d78e3e93c151a3015503710f54c3b861289cf7675aabdb3304afb41439376995",
      );
      const advanced = await advanceEpochSecret(epoch1Secret, 1);
      expect(bytesToHex(advanced)).toBe(
        "fb8945a2a2742859b88ac7d985c037adf3ffdfaa69001c1bcb41b6fb3f6b7066",
      );
    });

    it("ratchet is deterministic", async () => {
      const a = await advanceEpochSecret(RAW_SECRET, 0);
      const b = await advanceEpochSecret(RAW_SECRET, 0);
      expect(bytesToHex(a)).toBe(bytesToHex(b));
    });
  });

  describe("archive key", () => {
    it("matches Go test vector", async () => {
      const key = await deriveFileKeyBytes(
        EXPORTED_SECRET,
        "mlsgit-archive",
        0,
      );
      expect(bytesToHex(key)).toBe(
        "7da368b69b10f385356c325fc92d303b02f28eaeb1381a13f2c016c3d115fbb8",
      );
    });
  });
});
