package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// AESKeySize is the key size for AES-256.
	AESKeySize = 32
	// IVSize is the GCM recommended nonce size.
	IVSize = 12
	// TagSize is the GCM authentication tag size.
	TagSize = 16
)

// DeriveFileKey derives a per-file AES-256 key from the MLS epoch secret.
//
// key = HKDF-SHA-256(secret=epochSecret, salt=filePath, info="mlsgit-file-key"||epoch_be64)
//
// This matches the Python implementation:
//
//	HKDF(master=epochSecret, key_len=32, salt=filePath.encode(), hashmod=SHA256,
//	     context=b"mlsgit-file-key" + epoch.to_bytes(8, "big"))
func DeriveFileKey(epochSecret []byte, filePath string, epoch int) []byte {
	salt := []byte(filePath)
	info := make([]byte, len("mlsgit-file-key")+8)
	copy(info, "mlsgit-file-key")
	binary.BigEndian.PutUint64(info[len("mlsgit-file-key"):], uint64(epoch))

	hkdfReader := hkdf.New(sha256.New, epochSecret, salt, info)
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		panic(fmt.Sprintf("hkdf: %v", err))
	}
	return key
}

// AESGCMEncrypt encrypts plaintext with AES-256-GCM using a random nonce.
// Returns (nonce, ciphertext||tag).
func AESGCMEncrypt(key, plaintext []byte) (nonce, ct []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("gcm: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("random nonce: %w", err)
	}
	ct = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ct, nil
}

// AESGCMDecrypt decrypts ciphertext with AES-256-GCM.
// The ciphertext must include the 16-byte authentication tag appended
// by AESGCMEncrypt.
func AESGCMDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, fmt.Errorf("ciphertext too short (missing GCM tag)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm decrypt: %w", err)
	}
	return plaintext, nil
}
