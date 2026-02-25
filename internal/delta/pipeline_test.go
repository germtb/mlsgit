package delta

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func makeTestKeys(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestDeltaRecordRoundtrip(t *testing.T) {
	priv, _ := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	ct, err := EncryptBaseBlock([]byte("hello"), secret, "test.txt", 0, "alice", priv)
	if err != nil {
		t.Fatal(err)
	}

	record, err := DeltaRecordFromB64(ct)
	if err != nil {
		t.Fatal(err)
	}

	if record.Epoch != 0 {
		t.Errorf("Epoch = %d, want 0", record.Epoch)
	}
	if record.Seq != 0 {
		t.Errorf("Seq = %d, want 0", record.Seq)
	}
	if record.Author != "alice" {
		t.Errorf("Author = %q, want %q", record.Author, "alice")
	}
	if record.PrevHash != "" {
		t.Errorf("PrevHash = %q, want empty", record.PrevHash)
	}
	if record.FilePath != "test.txt" {
		t.Errorf("FilePath = %q, want %q", record.FilePath, "test.txt")
	}

	// Re-encode should produce same structure
	reEncoded := record.ToB64()
	reParsed, err := DeltaRecordFromB64(reEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if reParsed.Epoch != record.Epoch || reParsed.Author != record.Author {
		t.Error("re-encoded record doesn't match")
	}
}

func TestEncryptDecryptBaseBlock(t *testing.T) {
	priv, pub := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("hello, encrypted world!")

	ct, err := EncryptBaseBlock(plaintext, secret, "test.txt", 0, "alice", priv)
	if err != nil {
		t.Fatal(err)
	}

	getSecret := func(epoch int) ([]byte, error) { return secret, nil }
	getKey := func(author string) (ed25519.PublicKey, error) { return pub, nil }

	decrypted, err := DecryptChain(ct, getSecret, "test.txt", getKey)
	if err != nil {
		t.Fatalf("DecryptChain error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptDeltaChain(t *testing.T) {
	priv, pub := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	// Base block
	ct, err := EncryptBaseBlock([]byte("version 1"), secret, "test.txt", 0, "alice", priv)
	if err != nil {
		t.Fatal(err)
	}

	// Delta 1
	delta1 := ComputeDelta("version 1", "version 2")
	ct, err = EncryptDelta(delta1, secret, "test.txt", 0, 1, "alice", priv, ct)
	if err != nil {
		t.Fatal(err)
	}

	// Delta 2
	delta2 := ComputeDelta("version 2", "version 3")
	ct, err = EncryptDelta(delta2, secret, "test.txt", 0, 2, "alice", priv, ct)
	if err != nil {
		t.Fatal(err)
	}

	getSecret := func(epoch int) ([]byte, error) { return secret, nil }
	getKey := func(author string) (ed25519.PublicKey, error) { return pub, nil }

	decrypted, err := DecryptChain(ct, getSecret, "test.txt", getKey)
	if err != nil {
		t.Fatalf("DecryptChain error: %v", err)
	}
	if string(decrypted) != "version 3" {
		t.Errorf("decrypted = %q, want %q", decrypted, "version 3")
	}
}

func TestCountDeltas(t *testing.T) {
	priv, _ := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	ct, _ := EncryptBaseBlock([]byte("v1"), secret, "test.txt", 0, "alice", priv)
	if CountDeltas(ct) != 0 {
		t.Errorf("base block count = %d, want 0", CountDeltas(ct))
	}

	delta := ComputeDelta("v1", "v2")
	ct, _ = EncryptDelta(delta, secret, "test.txt", 0, 1, "alice", priv, ct)
	if CountDeltas(ct) != 1 {
		t.Errorf("one delta count = %d, want 1", CountDeltas(ct))
	}

	delta2 := ComputeDelta("v2", "v3")
	ct, _ = EncryptDelta(delta2, secret, "test.txt", 0, 2, "alice", priv, ct)
	if CountDeltas(ct) != 2 {
		t.Errorf("two delta count = %d, want 2", CountDeltas(ct))
	}
}

func TestDecryptChainBrokenHash(t *testing.T) {
	priv, pub := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	ct, _ := EncryptBaseBlock([]byte("v1"), secret, "test.txt", 0, "alice", priv)
	delta := ComputeDelta("v1", "v2")
	ct, _ = EncryptDelta(delta, secret, "test.txt", 0, 1, "alice", priv, ct)

	// Tamper with the base block portion to break hash chain
	// Replace first char
	tampered := "X" + ct[1:]

	getSecret := func(epoch int) ([]byte, error) { return secret, nil }
	getKey := func(author string) (ed25519.PublicKey, error) { return pub, nil }

	_, err := DecryptChain(tampered, getSecret, "test.txt", getKey)
	if err == nil {
		t.Fatal("expected error for broken hash chain")
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	priv, pub := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	ct, err := EncryptBaseBlock([]byte(""), secret, "test.txt", 0, "alice", priv)
	if err != nil {
		t.Fatal(err)
	}

	getSecret := func(epoch int) ([]byte, error) { return secret, nil }
	getKey := func(author string) (ed25519.PublicKey, error) { return pub, nil }

	decrypted, err := DecryptChain(ct, getSecret, "test.txt", getKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty, got %d bytes", len(decrypted))
	}
}
