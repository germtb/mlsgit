package mls

import (
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
