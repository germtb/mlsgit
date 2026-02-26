package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// x25519KeySize is the size of an X25519 public or private key.
	x25519KeySize = 32
	// eciesOverhead is the minimum ciphertext length: ephPub(32) + nonce(12) + GCM tag(16).
	eciesOverhead = x25519KeySize + IVSize + TagSize
)

// EncryptWelcome encrypts a Welcome message for a recipient using ECIES:
//
//	1. Generate ephemeral X25519 keypair
//	2. ECDH: shared = X25519(ephPriv, recipientPub)
//	3. KDF:  HKDF-SHA256(shared, salt=nil, info="mlsgit-welcome") -> 32-byte AES key
//	4. Encrypt: AES-GCM(aesKey, plaintext)
//	5. Return: ephPub(32) || nonce(12) || ciphertext+tag
func EncryptWelcome(recipientPub, plaintext []byte) ([]byte, error) {
	if len(recipientPub) != x25519KeySize {
		return nil, fmt.Errorf("recipient public key must be %d bytes", x25519KeySize)
	}

	// Generate ephemeral X25519 keypair
	ephPriv := make([]byte, x25519KeySize)
	if _, err := rand.Read(ephPriv); err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive ephemeral public key: %w", err)
	}

	// ECDH
	shared, err := curve25519.X25519(ephPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// KDF
	aesKey, err := deriveWelcomeKey(shared)
	if err != nil {
		return nil, err
	}

	// Encrypt
	nonce, ct, err := AESGCMEncrypt(aesKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// ephPub || nonce || ct+tag
	out := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptWelcome decrypts a Welcome message encrypted with EncryptWelcome.
func DecryptWelcome(recipientPriv, encrypted []byte) ([]byte, error) {
	if len(encrypted) < eciesOverhead {
		return nil, fmt.Errorf("encrypted welcome too short: %d bytes (minimum %d)", len(encrypted), eciesOverhead)
	}

	// Split
	ephPub := encrypted[:x25519KeySize]
	nonce := encrypted[x25519KeySize : x25519KeySize+IVSize]
	ct := encrypted[x25519KeySize+IVSize:]

	// ECDH
	shared, err := curve25519.X25519(recipientPriv, ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	// KDF
	aesKey, err := deriveWelcomeKey(shared)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, err := AESGCMDecrypt(aesKey, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// deriveWelcomeKey derives an AES-256 key from a DH shared secret for Welcome encryption.
func deriveWelcomeKey(shared []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, nil, []byte("mlsgit-welcome"))
	key := make([]byte, AESKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}
