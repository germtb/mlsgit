// Package crypto provides cryptographic primitives for mlsgit.
package crypto

import (
	"encoding/base64"
)

// B64Encode encodes data to base64. When urlSafe is true, uses URL-safe alphabet
// without padding (matching Python's urlsafe_b64encode().rstrip(b"=")).
// When false, uses standard alphabet with padding.
func B64Encode(data []byte, urlSafe bool) string {
	if urlSafe {
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// B64Decode decodes a base64 string. When urlSafe is true, expects URL-safe
// alphabet (padding optional). When false, expects standard alphabet.
func B64Decode(s string, urlSafe bool) ([]byte, error) {
	if urlSafe {
		// RawURLEncoding handles no-padding; try it first.
		// If the input has padding, use URLEncoding instead.
		if len(s)%4 != 0 {
			return base64.RawURLEncoding.DecodeString(s)
		}
		// Could be padded or exactly aligned without padding.
		// Try standard URL encoding with padding first.
		if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
			return decoded, nil
		}
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.StdEncoding.DecodeString(s)
}
