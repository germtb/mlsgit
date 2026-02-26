import { describe, it, expect } from "vitest";
import { looksCritCiphertext, parseMemberTOML } from "./mlsgit.js";

describe("mlsgit", () => {
  describe("looksCritCiphertext", () => {
    it("returns true for valid ciphertext", () => {
      // URL-safe base64 of JSON with epoch, ct, iv fields
      const json = JSON.stringify({ epoch: 0, ct: "abc", iv: "def", seq: 0 });
      const b64 = btoa(json)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      expect(looksCritCiphertext(b64)).toBe(true);
    });

    it("returns false for plain text", () => {
      expect(looksCritCiphertext("hello world")).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(looksCritCiphertext("")).toBe(false);
    });

    it("returns false for partial JSON", () => {
      const json = JSON.stringify({ epoch: 0 });
      const b64 = btoa(json)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      expect(looksCritCiphertext(b64)).toBe(false);
    });
  });

  describe("parseMemberTOML", () => {
    it("parses member TOML", () => {
      const toml = `[member]
name = "alice"
public_key = """
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA...
-----END PUBLIC KEY-----
"""
joined_epoch = 0
added_by = "self"
`;
      const info = parseMemberTOML(toml);
      expect(info.name).toBe("alice");
      expect(info.joinedEpoch).toBe(0);
      expect(info.addedBy).toBe("self");
      expect(info.publicKey).toContain("BEGIN PUBLIC KEY");
    });
  });
});
