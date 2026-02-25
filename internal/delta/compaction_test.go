package delta

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestCompact(t *testing.T) {
	priv, pub := makeTestKeys(t)
	secret := bytes.Repeat([]byte{0x42}, 32)

	// Build a chain with multiple deltas
	ct, _ := EncryptBaseBlock([]byte("version 1"), secret, "test.txt", 0, "alice", priv)
	for i := 2; i <= 5; i++ {
		old := "version " + string(rune('0'+i-1))
		new := "version " + string(rune('0'+i))
		delta := ComputeDelta(old, new)
		ct, _ = EncryptDelta(delta, secret, "test.txt", 0, i-1, "alice", priv, ct)
	}

	if CountDeltas(ct) != 4 {
		t.Fatalf("expected 4 deltas before compaction, got %d", CountDeltas(ct))
	}

	getSecret := func(epoch int) ([]byte, error) { return secret, nil }
	getKey := func(author string) (ed25519.PublicKey, error) { return pub, nil }

	newSecret := bytes.Repeat([]byte{0x43}, 32)
	compacted, err := Compact(ct, getSecret, newSecret, "test.txt", 1, "alice", priv, getKey)
	if err != nil {
		t.Fatalf("Compact error: %v", err)
	}

	if CountDeltas(compacted) != 0 {
		t.Errorf("compacted should have 0 deltas, got %d", CountDeltas(compacted))
	}

	// Decrypt compacted version
	getNewSecret := func(epoch int) ([]byte, error) {
		if epoch == 1 {
			return newSecret, nil
		}
		return secret, nil
	}

	decrypted, err := DecryptChain(compacted, getNewSecret, "test.txt", getKey)
	if err != nil {
		t.Fatalf("DecryptChain after compact error: %v", err)
	}
	if string(decrypted) != "version 5" {
		t.Errorf("decrypted = %q, want %q", decrypted, "version 5")
	}
}
