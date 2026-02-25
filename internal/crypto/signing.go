package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/youmark/pkcs8"
)

const (
	// PassphraseEnv is the environment variable that supplies the key passphrase.
	PassphraseEnv = "MLSGIT_PASSPHRASE"
)

// GenerateKeypair generates an Ed25519 key pair.
func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519 keygen: %w", err)
	}
	return priv, pub, nil
}

// PrivateKeyToPEM serializes a private key to PEM (PKCS8), optionally encrypted.
func PrivateKeyToPEM(key ed25519.PrivateKey, passphrase []byte) (string, error) {
	if len(passphrase) > 0 {
		pemBlock, err := pkcs8.MarshalPrivateKey(key, passphrase, nil)
		if err != nil {
			return "", fmt.Errorf("marshal encrypted private key: %w", err)
		}
		return string(pem.EncodeToMemory(&pem.Block{
			Type:  "ENCRYPTED PRIVATE KEY",
			Bytes: pemBlock,
		})), nil
	}
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})), nil
}

// PublicKeyToPEM serializes a public key to PEM (SPKI/SubjectPublicKeyInfo).
func PublicKeyToPEM(key ed25519.PublicKey) (string, error) {
	spkiBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: spkiBytes,
	})), nil
}

// LoadPrivateKey loads a private key from PEM.
// If passphrase is nil, tries the MLSGIT_PASSPHRASE environment variable.
// Falls back to no password for unencrypted keys.
func LoadPrivateKey(pemStr string, passphrase []byte) (ed25519.PrivateKey, error) {
	if passphrase == nil {
		passphrase = getPassphraseFromEnv()
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passphrase)
		if err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not Ed25519")
		}
		return edKey, nil
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}

// LoadPublicKey loads a public key from PEM.
func LoadPublicKey(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519")
	}
	return edKey, nil
}

// Sign signs data with Ed25519.
func Sign(privateKey ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(privateKey, data)
}

// Verify verifies an Ed25519 signature. Returns true on success.
func Verify(publicKey ed25519.PublicKey, data, signature []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

// PublicKeyFingerprint returns a hex SHA-256 fingerprint of the public key PEM (first 16 chars).
func PublicKeyFingerprint(publicKey ed25519.PublicKey) (string, error) {
	pemStr, err := PublicKeyToPEM(publicKey)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(pemStr))
	return fmt.Sprintf("%x", h)[:16], nil
}

func getPassphraseFromEnv() []byte {
	val := os.Getenv(PassphraseEnv)
	if val != "" {
		return []byte(val)
	}
	return nil
}
