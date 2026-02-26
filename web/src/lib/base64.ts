/** Standard base64 encode (with padding). */
export function b64Encode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary);
}

/** Standard base64 decode. */
export function b64Decode(s: string): Uint8Array {
  const binary = atob(s);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** URL-safe base64 encode (no padding, matching Go's RawURLEncoding). */
export function b64UrlEncode(data: Uint8Array): string {
  return b64Encode(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** URL-safe base64 decode (handles with or without padding). */
export function b64UrlDecode(s: string): Uint8Array {
  // Restore standard base64 chars and add padding
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return b64Decode(b64);
}
