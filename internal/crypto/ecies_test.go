package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func generateX25519Keypair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestEncryptDecryptWelcome(t *testing.T) {
	priv, pub := generateX25519Keypair(t)
	plaintext := []byte(`{"group_id":"test","epoch":1,"epoch_secret":"AAAA"}`)

	encrypted, err := EncryptWelcome(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Must be longer than plaintext (has overhead)
	if len(encrypted) <= len(plaintext) {
		t.Errorf("encrypted (%d) should be longer than plaintext (%d)", len(encrypted), len(plaintext))
	}

	decrypted, err := DecryptWelcome(priv, encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptWelcomeWrongKey(t *testing.T) {
	_, pub := generateX25519Keypair(t)
	wrongPriv, _ := generateX25519Keypair(t)

	plaintext := []byte("secret welcome data")
	encrypted, err := EncryptWelcome(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptWelcome(wrongPriv, encrypted)
	if err == nil {
		t.Fatal("decryption with wrong key should fail")
	}
}

func TestDecryptWelcomeTampered(t *testing.T) {
	priv, pub := generateX25519Keypair(t)
	plaintext := []byte("secret welcome data")

	encrypted, err := EncryptWelcome(pub, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a bit in the ciphertext portion (after ephPub + nonce)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[len(tampered)-1] ^= 0x01

	_, err = DecryptWelcome(priv, tampered)
	if err == nil {
		t.Fatal("decryption of tampered ciphertext should fail")
	}
}

func TestDecryptWelcomeTooShort(t *testing.T) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}

	// Less than minimum: 32 (ephPub) + 12 (nonce) + 16 (tag) = 60
	short := make([]byte, 59)
	_, err := DecryptWelcome(priv, short)
	if err == nil {
		t.Fatal("decryption of too-short data should fail")
	}
}
