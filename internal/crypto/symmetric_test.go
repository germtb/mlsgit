package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveFileKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	key1 := DeriveFileKey(secret, "test.txt", 0)
	key2 := DeriveFileKey(secret, "test.txt", 0)

	if len(key1) != AESKeySize {
		t.Errorf("key length = %d, want %d", len(key1), AESKeySize)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("same inputs must produce same key")
	}
}

func TestDeriveFileKeyDifferentPaths(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	key1 := DeriveFileKey(secret, "file1.txt", 0)
	key2 := DeriveFileKey(secret, "file2.txt", 0)

	if bytes.Equal(key1, key2) {
		t.Error("different paths must produce different keys")
	}
}

func TestDeriveFileKeyDifferentEpochs(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	key1 := DeriveFileKey(secret, "test.txt", 0)
	key2 := DeriveFileKey(secret, "test.txt", 1)

	if bytes.Equal(key1, key2) {
		t.Error("different epochs must produce different keys")
	}
}

func TestDeriveFileKeyDifferentSecrets(t *testing.T) {
	secret1 := bytes.Repeat([]byte{0x42}, 32)
	secret2 := bytes.Repeat([]byte{0x43}, 32)
	key1 := DeriveFileKey(secret1, "test.txt", 0)
	key2 := DeriveFileKey(secret2, "test.txt", 0)

	if bytes.Equal(key1, key2) {
		t.Error("different secrets must produce different keys")
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, AESKeySize)
	plaintext := []byte("hello, encrypted world!")

	nonce, ct, err := AESGCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatalf("AESGCMEncrypt error: %v", err)
	}
	if len(nonce) != IVSize {
		t.Errorf("nonce size = %d, want %d", len(nonce), IVSize)
	}

	decrypted, err := AESGCMDecrypt(key, nonce, ct)
	if err != nil {
		t.Fatalf("AESGCMDecrypt error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMDecryptTampered(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, AESKeySize)
	plaintext := []byte("test data")

	nonce, ct, err := AESGCMEncrypt(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext
	ct[0] ^= 0xFF
	_, err = AESGCMDecrypt(key, nonce, ct)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestAESGCMDecryptWrongKey(t *testing.T) {
	key1 := bytes.Repeat([]byte{0xAB}, AESKeySize)
	key2 := bytes.Repeat([]byte{0xCD}, AESKeySize)
	plaintext := []byte("test data")

	nonce, ct, err := AESGCMEncrypt(key1, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	_, err = AESGCMDecrypt(key2, nonce, ct)
	if err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestAESGCMDecryptTooShort(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, AESKeySize)
	_, err := AESGCMDecrypt(key, make([]byte, IVSize), make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestAESGCMEncryptEmpty(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, AESKeySize)
	nonce, ct, err := AESGCMEncrypt(key, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := AESGCMDecrypt(key, nonce, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}
