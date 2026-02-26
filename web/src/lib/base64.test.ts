import { describe, it, expect } from "vitest";
import { b64Encode, b64Decode, b64UrlEncode, b64UrlDecode } from "./base64.js";

describe("base64", () => {
  describe("standard encoding", () => {
    it("encodes empty", () => {
      expect(b64Encode(new Uint8Array([]))).toBe("");
    });

    it("encodes hello", () => {
      const data = new TextEncoder().encode("hello");
      expect(b64Encode(data)).toBe("aGVsbG8=");
    });

    it("roundtrips", () => {
      const data = new Uint8Array([0, 1, 2, 255, 254, 253]);
      expect(b64Decode(b64Encode(data))).toEqual(data);
    });
  });

  describe("URL-safe encoding", () => {
    it("encodes without padding", () => {
      const data = new Uint8Array([0, 1, 2]);
      const encoded = b64UrlEncode(data);
      expect(encoded).not.toContain("=");
      expect(encoded).not.toContain("+");
      expect(encoded).not.toContain("/");
    });

    it("roundtrips", () => {
      const data = new Uint8Array([63, 64, 65, 255, 0, 128]);
      expect(b64UrlDecode(b64UrlEncode(data))).toEqual(data);
    });

    it("decodes with or without padding", () => {
      // Use 2 bytes so standard base64 has padding (AA== for [0,0])
      const data = new Uint8Array([0, 0]);
      const withoutPad = b64UrlEncode(data); // "AAA"
      const withPad = withoutPad + "="; // "AAA=" — valid padded form
      expect(b64UrlDecode(withoutPad)).toEqual(data);
      expect(b64UrlDecode(withPad)).toEqual(data);
    });
  });
});
