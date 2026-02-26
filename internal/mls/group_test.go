package mls

import (
	"bytes"
	"encoding/json"
	"testing"
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
	for i := range secret1 {
		if secret1[i] != secret2[i] {
			t.Fatal("same epoch should produce same secret")
		}
	}
}

func TestGroupSerializeDeserialize(t *testing.T) {
	keys, _ := GenerateMLSKeys()
	g, _ := Create([]byte("test-group"), []byte("alice"), keys)

	data, err := g.ToBytes()
	if err != nil {
		t.Fatal(err)
	}

	g2, err := FromBytes(data, keys.SigPriv)
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
	for i := range aliceSecret {
		if aliceSecret[i] != bobSecret[i] {
			t.Fatal("epoch secrets should match after join")
		}
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
	commitBytes, welcomeBytes, err := alice.AddMember(kp)
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
	g2, _ := FromBytes(g1Bytes, keys1.SigPriv)

	// g1 adds a member -> advances to epoch 1
	bobKeys2, _ := GenerateMLSKeys()
	kp2 := BuildKeyPackage([]byte("bob"), bobKeys2)
	_, _, _ = g1.AddMember(kp2)

	// g1 is now at epoch 1. Get committed bytes (no secret)
	_ = commitBytes // unused from earlier
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
	// The old format is just a full groupState JSON; the new code deserializes
	// into committedGroupState which ignores unknown fields.
	keys, _ := GenerateMLSKeys()
	g1, _ := Create([]byte("test-group"), []byte("alice"), keys)

	// Clone at epoch 0
	g1Bytes, _ := g1.ToBytes()
	g2, _ := FromBytes(g1Bytes, keys.SigPriv)

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
	// Epoch secrets should match because ratchet is deterministic
	if !bytes.Equal(g1.ExportEpochSecret(), g2.ExportEpochSecret()) {
		t.Error("epoch secrets should match with old format sync")
	}
}

func TestApplyCommitRatchet(t *testing.T) {
	// Test that ApplyCommit works with the new committed format
	keys, _ := GenerateMLSKeys()
	g1, _ := Create([]byte("test-group"), []byte("alice"), keys)

	// Clone at epoch 0
	g1Bytes, _ := g1.ToBytes()
	g2, _ := FromBytes(g1Bytes, keys.SigPriv)

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

	// Secrets should differ across epochs
	same := true
	for i := range secret0 {
		if secret0[i] != secret1[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("epoch secrets should differ after epoch advance")
	}
}
