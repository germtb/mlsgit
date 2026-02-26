package mls

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func TestCreateGroup(t *testing.T) {
	keys, err := GenerateMLSKeys()
	if err != nil {
		t.Fatal(err)
	}

	g, err := Create([]byte("test-group"), []byte("alice"), keys)
	if err != nil {
		t.Fatal(err)
	}

	if g.Epoch() != 0 {
		t.Errorf("Epoch = %d, want 0", g.Epoch())
	}
	if g.MemberCount() != 1 {
		t.Errorf("MemberCount = %d, want 1", g.MemberCount())
	}
	if g.OwnLeafIndex() != 0 {
		t.Errorf("OwnLeafIndex = %d, want 0", g.OwnLeafIndex())
	}
}

func TestExportEpochSecret(t *testing.T) {
	keys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), keys)

	secret1 := g.ExportEpochSecret()
	secret2 := g.ExportEpochSecret()

	if len(secret1) != 32 {
		t.Errorf("secret length = %d, want 32", len(secret1))
	}
	// Same epoch should give same secret
	if !bytes.Equal(secret1, secret2) {
		t.Fatal("same epoch should produce same secret")
	}
}

func TestGroupSerializeDeserialize(t *testing.T) {
	keys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), keys)

	data, err := g.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	g2, err := FromBytes(data, keys.SigPriv, keys.InitPriv)
	if err != nil {
		t.Fatal(err)
	}

	if g2.Epoch() != g.Epoch() {
		t.Errorf("Epoch = %d, want %d", g2.Epoch(), g.Epoch())
	}
	if g2.MemberCount() != g.MemberCount() {
		t.Errorf("MemberCount = %d, want %d", g2.MemberCount(), g.MemberCount())
	}
}

func TestAddMember(t *testing.T) {
	aliceKeys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)

	_, welcomeBytes, err := g.AddMember(kp)
	if err != nil {
		t.Fatal(err)
	}

	if g.Epoch() != 1 {
		t.Errorf("Epoch after add = %d, want 1", g.Epoch())
	}
	if g.MemberCount() != 2 {
		t.Errorf("MemberCount after add = %d, want 2", g.MemberCount())
	}

	// Bob joins from welcome
	bobGroup, err := JoinFromWelcome(welcomeBytes, bobKeys)
	if err != nil {
		t.Fatal(err)
	}
	if bobGroup.Epoch() != 1 {
		t.Errorf("Bob's epoch = %d, want 1", bobGroup.Epoch())
	}
	if bobGroup.OwnLeafIndex() != 1 {
		t.Errorf("Bob's leaf index = %d, want 1", bobGroup.OwnLeafIndex())
	}

	// Both should derive same epoch secret
	aliceSecret := g.ExportEpochSecret()
	bobSecret := bobGroup.ExportEpochSecret()
	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Fatal("epoch secrets should match after join")
	}
}

func TestRemoveMember(t *testing.T) {
	aliceKeys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	g.AddMember(kp)

	if g.MemberCount() != 2 {
		t.Fatalf("expected 2 members, got %d", g.MemberCount())
	}

	_, err := g.RemoveMember(1)
	if err != nil {
		t.Fatal(err)
	}

	if g.Epoch() != 2 {
		t.Errorf("Epoch after remove = %d, want 2", g.Epoch())
	}
	if g.MemberCount() != 1 {
		t.Errorf("MemberCount after remove = %d, want 1", g.MemberCount())
	}
}

func TestRemoveSelfFails(t *testing.T) {
	keys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), keys)

	_, err := g.RemoveMember(0)
	if err == nil {
		t.Fatal("expected error removing self")
	}
}

func TestToCommittedBytesExcludesSecret(t *testing.T) {
	keys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), keys)

	committed, err := g.ToCommittedBytes()
	if err != nil {
		t.Fatal(err)
	}

	// Parse and verify epoch_secret is not present
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(committed, &obj); err != nil {
		t.Fatal(err)
	}
	if _, found := obj["epoch_secret"]; found {
		t.Error("ToCommittedBytes should not include epoch_secret")
	}
	if _, found := obj["own_leaf_index"]; found {
		t.Error("ToCommittedBytes should not include own_leaf_index")
	}
	// But should include group_id, epoch, members
	if _, found := obj["group_id"]; !found {
		t.Error("ToCommittedBytes should include group_id")
	}
	if _, found := obj["epoch"]; !found {
		t.Error("ToCommittedBytes should include epoch")
	}
	if _, found := obj["members"]; !found {
		t.Error("ToCommittedBytes should include members")
	}
}

func TestSyncFromCommittedRatchet(t *testing.T) {
	// Alice creates group, adds Bob -> epoch advances to 1
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	_, welcomeBytes, err := alice.AddMember(kp)
	if err != nil {
		t.Fatal(err)
	}

	// Bob joins from Welcome at epoch 1
	_, err = JoinFromWelcome(welcomeBytes, bobKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Test the ratchet with a controlled scenario:
	// Create a new group, serialize committed state, have another instance sync
	keys1, _ := GenerateMLSKeys()
	g1, _ := Create([]byte("test-group"), []byte("alice"), keys1)
	secret0 := g1.ExportEpochSecret()

	// Clone g1's state at epoch 0
	g1Bytes, _ := g1.ToBytes()
	g2, _ := FromBytes(g1Bytes, keys1.SigPriv, keys1.InitPriv)

	// g1 adds a member -> advances to epoch 1
	bobKeys2, _ := GenerateMLSKeys()
	kp2 := BuildKeyPackage([]byte("bob"), bobKeys2)
	_, _, _ = g1.AddMember(kp2)

	// g1 is now at epoch 1. Get committed bytes (no secret)
	committedBytes, _ := g1.ToCommittedBytes()

	// g2 is still at epoch 0. Sync from committed state.
	updated := g2.SyncFromCommitted(committedBytes)
	if !updated {
		t.Fatal("SyncFromCommitted should return true")
	}
	if g2.Epoch() != 1 {
		t.Errorf("after sync, epoch = %d, want 1", g2.Epoch())
	}

	// Both g1 and g2 should derive the same epoch secret
	secret1_g1 := g1.ExportEpochSecret()
	secret1_g2 := g2.ExportEpochSecret()
	if !bytes.Equal(secret1_g1, secret1_g2) {
		t.Error("epoch secrets should match after ratchet-based sync")
	}

	// Verify the secret actually changed from epoch 0
	if bytes.Equal(secret0, secret1_g1) {
		t.Error("epoch secret should differ after epoch advance")
	}
}

func TestSyncFromCommittedBackwardCompat(t *testing.T) {
	// Test that old-format JSON (containing epoch_secret and own_leaf_index)
	// is accepted by the new SyncFromCommitted.
	keys, _ := GenerateMLSKeys()
	g1, _ := Create([]byte("test-group"), []byte("alice"), keys)

	// Clone at epoch 0
	g1Bytes, _ := g1.ToBytes()
	g2, _ := FromBytes(g1Bytes, keys.SigPriv, keys.InitPriv)

	// g1 adds a member
	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	g1.AddMember(kp)

	// Serialize old format (full state with epoch_secret)
	oldFormatBytes, _ := g1.ToBytes()

	// g2 syncs from old format - should still work via ratchet
	updated := g2.SyncFromCommitted(oldFormatBytes)
	if !updated {
		t.Fatal("SyncFromCommitted should accept old format")
	}
	if g2.Epoch() != g1.Epoch() {
		t.Errorf("epoch mismatch: g2=%d, g1=%d", g2.Epoch(), g1.Epoch())
	}
	// Epoch secrets should match because ratchet is deterministic for adds
	if !bytes.Equal(g1.ExportEpochSecret(), g2.ExportEpochSecret()) {
		t.Error("epoch secrets should match with old format sync")
	}
}

func TestApplyCommitRatchet(t *testing.T) {
	// Test that ApplyCommit works with the committed format
	keys, _ := GenerateMLSKeys()
	g1, _ := Create([]byte("test-group"), []byte("alice"), keys)

	// Clone at epoch 0
	g1Bytes, _ := g1.ToBytes()
	g2, _ := FromBytes(g1Bytes, keys.SigPriv, keys.InitPriv)

	// g1 adds a member -> epoch 1
	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	commitBytes, _, _ := g1.AddMember(kp)

	// commitBytes is now in committed format (no epoch_secret)
	var obj map[string]json.RawMessage
	json.Unmarshal(commitBytes, &obj)
	if _, found := obj["epoch_secret"]; found {
		t.Error("commit bytes should not contain epoch_secret")
	}

	// g2 applies the commit
	if err := g2.ApplyCommit(commitBytes); err != nil {
		t.Fatal(err)
	}
	if g2.Epoch() != 1 {
		t.Errorf("after apply, epoch = %d, want 1", g2.Epoch())
	}
	if !bytes.Equal(g1.ExportEpochSecret(), g2.ExportEpochSecret()) {
		t.Error("epoch secrets should match after ApplyCommit with ratchet")
	}
}

func TestEpochSecretChangesAfterAdvance(t *testing.T) {
	aliceKeys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)
	secret0 := g.ExportEpochSecret()

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	g.AddMember(kp)
	secret1 := g.ExportEpochSecret()

	if bytes.Equal(secret0, secret1) {
		t.Error("epoch secrets should differ after epoch advance")
	}
}

// --- DH-based rekeying tests ---

func TestRemovalForwardSecrecy(t *testing.T) {
	// This is the critical test: a removed member MUST NOT be able to derive
	// the new epoch secret by applying the old deterministic HKDF ratchet.
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)
	_, welcomeBytes, _ := alice.AddMember(kp) // epoch 1

	bob, _ := JoinFromWelcome(welcomeBytes, bobKeys)

	// Capture Bob's state before removal
	bobEpochSecret := make([]byte, len(bob.state.EpochSecret))
	copy(bobEpochSecret, bob.state.EpochSecret)
	bobEpoch := bob.state.Epoch

	// Alice removes Bob
	alice.RemoveMember(1) // epoch 2

	// Bob tries the old deterministic ratchet: HKDF(oldSecret, epoch, info)
	// This is what the old code would compute — and it MUST NOT work.
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, bobEpoch)
	r := hkdf.New(sha256.New, bobEpochSecret, epochBytes, []byte("mlsgit-epoch-advance"))
	bobGuess := make([]byte, 32)
	io.ReadFull(r, bobGuess)

	// Export what Bob would get if his guess were correct
	bobGuessedExport := exportSecret(bobGuess, []byte("mlsgit-epoch-secret"), nil, 32)

	// Alice's actual epoch secret
	aliceSecret := alice.ExportEpochSecret()

	if bytes.Equal(aliceSecret, bobGuessedExport) {
		t.Fatal("SECURITY FAILURE: removed member can derive the new epoch secret via deterministic ratchet")
	}

	// Also verify the raw epoch secrets differ
	if bytes.Equal(bobGuess, alice.state.EpochSecret) {
		t.Fatal("SECURITY FAILURE: deterministic ratchet produces the same raw epoch secret")
	}
}

func TestSyncAfterRemoval(t *testing.T) {
	// Test that remaining members can sync via DH after a removal.
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	bkp := BuildKeyPackage([]byte("bob"), bobKeys)
	_, _, _ = alice.AddMember(bkp) // epoch 1

	charlieKeys, _ := GenerateMLSKeys()
	ckp := BuildKeyPackage([]byte("charlie"), charlieKeys)
	_, cwelcomeBytes, _ := alice.AddMember(ckp) // epoch 2

	charlie, _ := JoinFromWelcome(cwelcomeBytes, charlieKeys)

	// Alice removes Bob at epoch 3 (DH-based)
	_, err := alice.RemoveMember(1)
	if err != nil {
		t.Fatal(err)
	}
	if alice.Epoch() != 3 {
		t.Fatalf("alice epoch = %d, want 3", alice.Epoch())
	}

	// Charlie syncs from committed state
	committedBytes, _ := alice.ToCommittedBytes()
	updated := charlie.SyncFromCommitted(committedBytes)
	if !updated {
		t.Fatal("SyncFromCommitted should return true")
	}
	if charlie.Epoch() != 3 {
		t.Errorf("charlie epoch = %d, want 3", charlie.Epoch())
	}

	// Alice and Charlie should have the same epoch secret
	if !bytes.Equal(alice.ExportEpochSecret(), charlie.ExportEpochSecret()) {
		t.Error("epoch secrets should match after DH-based sync")
	}
}

func TestSyncMultipleRemovalsOffline(t *testing.T) {
	// Test that a member offline during multiple removals can catch up.
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	bkp := BuildKeyPackage([]byte("bob"), bobKeys)
	alice.AddMember(bkp) // epoch 1

	charlieKeys, _ := GenerateMLSKeys()
	ckp := BuildKeyPackage([]byte("charlie"), charlieKeys)
	alice.AddMember(ckp) // epoch 2

	daveKeys, _ := GenerateMLSKeys()
	dkp := BuildKeyPackage([]byte("dave"), daveKeys)
	_, dwelcomeBytes, _ := alice.AddMember(dkp) // epoch 3

	dave, _ := JoinFromWelcome(dwelcomeBytes, daveKeys)

	// Dave goes offline. Alice removes Bob then Charlie.
	alice.RemoveMember(1) // epoch 4 (DH)
	alice.RemoveMember(2) // epoch 5 (DH)

	// Dave comes back and syncs (skipping 2 DH-based transitions)
	committedBytes, _ := alice.ToCommittedBytes()
	updated := dave.SyncFromCommitted(committedBytes)
	if !updated {
		t.Fatal("SyncFromCommitted should return true")
	}
	if dave.Epoch() != 5 {
		t.Errorf("dave epoch = %d, want 5", dave.Epoch())
	}
	if !bytes.Equal(alice.ExportEpochSecret(), dave.ExportEpochSecret()) {
		t.Error("epoch secrets should match after multi-removal catch-up")
	}
}

func TestApplyCommitAfterRemoval(t *testing.T) {
	// Test ApplyCommit with DH-based removal
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	bkp := BuildKeyPackage([]byte("bob"), bobKeys)
	alice.AddMember(bkp) // epoch 1

	charlieKeys, _ := GenerateMLSKeys()
	ckp := BuildKeyPackage([]byte("charlie"), charlieKeys)
	_, cwelcomeBytes, _ := alice.AddMember(ckp) // epoch 2

	charlie, _ := JoinFromWelcome(cwelcomeBytes, charlieKeys)

	// Alice removes Bob
	commitBytes, _ := alice.RemoveMember(1) // epoch 3

	// Charlie applies the commit
	if err := charlie.ApplyCommit(commitBytes); err != nil {
		t.Fatal(err)
	}
	if charlie.Epoch() != 3 {
		t.Errorf("charlie epoch = %d, want 3", charlie.Epoch())
	}
	if !bytes.Equal(alice.ExportEpochSecret(), charlie.ExportEpochSecret()) {
		t.Error("epoch secrets should match after ApplyCommit with DH removal")
	}
}

func TestUpdateEncapsPropagateViaWelcome(t *testing.T) {
	// Test that encaps from prior removals are included in Welcome messages.
	aliceKeys, _ := GenerateMLSKeys()
	alice, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	bkp := BuildKeyPackage([]byte("bob"), bobKeys)
	alice.AddMember(bkp) // epoch 1

	// Remove Bob (creates DH encap)
	alice.RemoveMember(1) // epoch 2

	// Add Charlie (Welcome should include the encap from the removal)
	charlieKeys, _ := GenerateMLSKeys()
	ckp := BuildKeyPackage([]byte("charlie"), charlieKeys)
	_, encryptedWelcome, _ := alice.AddMember(ckp) // epoch 3

	// Welcome is encrypted, so we decrypt it to verify encaps are present
	charlie, err := JoinFromWelcome(encryptedWelcome, charlieKeys)
	if err != nil {
		t.Fatal(err)
	}

	// Verify Charlie got the encaps
	if len(charlie.state.UpdateEncaps) == 0 {
		t.Error("Charlie should have encaps from Welcome")
	}
}

func TestWelcomeIsEncrypted(t *testing.T) {
	aliceKeys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), aliceKeys)

	bobKeys, _ := GenerateMLSKeys()
	kp := BuildKeyPackage([]byte("bob"), bobKeys)

	_, welcomeBytes, err := g.AddMember(kp)
	if err != nil {
		t.Fatal(err)
	}

	// The returned bytes should NOT be parseable as plaintext JSON
	var w WelcomeData
	if json.Unmarshal(welcomeBytes, &w) == nil {
		t.Error("welcome should be encrypted, not plaintext JSON")
	}
}

func TestInitPubIsX25519(t *testing.T) {
	// Verify that InitPub is a real X25519 public key, not SHA-256(InitPriv)
	keys, _ := GenerateMLSKeys()

	// If InitPub were SHA-256(InitPriv), this would match
	import_sha256 := func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	}
	sha256Pub := import_sha256(keys.InitPriv)

	if bytes.Equal(keys.InitPub, sha256Pub) {
		t.Fatal("InitPub should be X25519(InitPriv, basepoint), not SHA-256(InitPriv)")
	}

	// InitPub should be 32 bytes
	if len(keys.InitPub) != 32 {
		t.Errorf("InitPub length = %d, want 32", len(keys.InitPub))
	}
}
