package mls

import (
	"bytes"
	"testing"
)

func TestEpochKeyArchiveRoundtrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)

	archive := NewWithSecret(0, secret)
	archive.Add(1, bytes.Repeat([]byte{0x43}, 32))

	encrypted, err := archive.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptArchive(encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}

	if !decrypted.Has(0) {
		t.Error("epoch 0 missing after roundtrip")
	}
	if !decrypted.Has(1) {
		t.Error("epoch 1 missing after roundtrip")
	}

	s0, _ := decrypted.Get(0)
	if !bytes.Equal(s0, secret) {
		t.Error("epoch 0 secret mismatch")
	}
}

func TestEpochKeyArchiveEpochList(t *testing.T) {
	archive := NewEpochKeyArchive()
	archive.Add(5, []byte("five"))
	archive.Add(2, []byte("two"))
	archive.Add(0, []byte("zero"))

	epochs := archive.Epochs()
	if len(epochs) != 3 {
		t.Fatalf("len = %d, want 3", len(epochs))
	}
	if epochs[0] != 0 || epochs[1] != 2 || epochs[2] != 5 {
		t.Errorf("epochs = %v, want [0 2 5]", epochs)
	}
}

func TestEpochKeyArchiveLatestEpoch(t *testing.T) {
	archive := NewEpochKeyArchive()
	if archive.LatestEpoch() != -1 {
		t.Errorf("empty archive latest = %d, want -1", archive.LatestEpoch())
	}

	archive.Add(0, []byte("zero"))
	archive.Add(3, []byte("three"))
	if archive.LatestEpoch() != 3 {
		t.Errorf("latest = %d, want 3", archive.LatestEpoch())
	}
}

func TestEpochKeyArchiveGetMissing(t *testing.T) {
	archive := NewEpochKeyArchive()
	_, err := archive.Get(42)
	if err == nil {
		t.Fatal("expected error for missing epoch")
	}
}

func TestEpochKeyArchiveDecryptWrongKey(t *testing.T) {
	secret1 := bytes.Repeat([]byte{0x42}, 32)
	secret2 := bytes.Repeat([]byte{0x43}, 32)

	archive := NewWithSecret(0, secret1)
	encrypted, _ := archive.Encrypt(secret1)

	_, err := DecryptArchive(encrypted, secret2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestEpochKeyArchiveMultipleEpochs(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	archive := NewEpochKeyArchive()

	for i := 0; i < 10; i++ {
		s := bytes.Repeat([]byte{byte(i)}, 32)
		archive.Add(i, s)
	}

	encrypted, err := archive.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptArchive(encrypted, secret)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		s, err := decrypted.Get(i)
		if err != nil {
			t.Fatalf("epoch %d missing: %v", i, err)
		}
		expected := bytes.Repeat([]byte{byte(i)}, 32)
		if !bytes.Equal(s, expected) {
			t.Errorf("epoch %d secret mismatch", i)
		}
	}
}
