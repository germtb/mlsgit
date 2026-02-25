package delta

import (
	"crypto/ed25519"
	"fmt"
)

// Compact decrypts the full chain and re-encrypts as a single base block.
// Used when the delta chain exceeds the compaction threshold or after member removal.
func Compact(
	ciphertext string,
	getEpochSecret EpochSecretFunc,
	newEpochSecret []byte,
	filePath string,
	newEpoch int,
	author string,
	privateKey ed25519.PrivateKey,
	getPublicKey PublicKeyFunc,
) (string, error) {
	plaintext, err := DecryptChain(ciphertext, getEpochSecret, filePath, getPublicKey)
	if err != nil {
		return "", fmt.Errorf("compact decrypt: %w", err)
	}
	return EncryptBaseBlock(plaintext, newEpochSecret, filePath, newEpoch, author, privateKey)
}
