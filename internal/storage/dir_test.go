package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func setupTestPaths(t *testing.T) MLSGitPaths {
	t.Helper()
	tmp := t.TempDir()
	// Create .git dir so paths work
	os.MkdirAll(filepath.Join(tmp, ".git"), 0o755)
	paths := MLSGitPaths{Root: tmp}
	if err := paths.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestIdentityRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	if err := WriteIdentity(paths, "abc123", "alice"); err != nil {
		t.Fatal(err)
	}

	memberID, name, err := ReadIdentity(paths)
	if err != nil {
		t.Fatal(err)
	}
	if memberID != "abc123" {
		t.Errorf("memberID = %q, want %q", memberID, "abc123")
	}
	if name != "alice" {
		t.Errorf("name = %q, want %q", name, "alice")
	}
}

func TestMemberTOMLRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	pubPEM := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtest\n-----END PUBLIC KEY-----"

	if err := WriteMemberTOML(paths, "abc123", "alice", pubPEM, 0, "self"); err != nil {
		t.Fatal(err)
	}

	info, err := ReadMemberTOML(paths.MemberTOML("abc123"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Name != "alice" {
		t.Errorf("Name = %q, want %q", info.Name, "alice")
	}
	if info.PublicKey != pubPEM {
		t.Errorf("PublicKey mismatch:\ngot:  %q\nwant: %q", info.PublicKey, pubPEM)
	}
	if info.JoinedEpoch != 0 {
		t.Errorf("JoinedEpoch = %d, want 0", info.JoinedEpoch)
	}
}

func TestEpochTOMLRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	if err := WriteEpochTOML(paths, 5); err != nil {
		t.Fatal(err)
	}

	epoch, err := ReadEpochTOML(paths)
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 5 {
		t.Errorf("epoch = %d, want 5", epoch)
	}
}

func TestGroupStateRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	state := []byte("test group state bytes")

	if err := WriteGroupState(paths, state); err != nil {
		t.Fatal(err)
	}

	read, err := ReadGroupState(paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(state) {
		t.Errorf("state mismatch")
	}
}

func TestLocalMLSStateRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	state := []byte{0x01, 0x02, 0x03, 0xFF}

	if err := WriteLocalMLSState(paths, state); err != nil {
		t.Fatal(err)
	}

	read, err := ReadLocalMLSState(paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(state) {
		t.Errorf("mls state mismatch")
	}
}

func TestEpochKeysRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	data := []byte("encrypted epoch keys data")

	if err := WriteEpochKeys(paths, data); err != nil {
		t.Fatal(err)
	}

	read, err := ReadEpochKeys(paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(data) {
		t.Errorf("epoch keys mismatch")
	}
}

func TestWelcomeRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	welcome := []byte("welcome message bytes")

	if err := WriteWelcome(paths, "abc123", welcome); err != nil {
		t.Fatal(err)
	}

	read, err := ReadWelcome(paths, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != string(welcome) {
		t.Errorf("welcome mismatch")
	}
}

func TestPendingRequestRoundtrip(t *testing.T) {
	paths := setupTestPaths(t)
	if err := WritePendingRequest(paths, "abc123", "bob", "pubkey-pem", "keypackage-b64"); err != nil {
		t.Fatal(err)
	}

	info, err := ReadPendingRequest(paths.PendingRequest("abc123"))
	if err != nil {
		t.Fatal(err)
	}
	if info.MemberID != "abc123" {
		t.Errorf("MemberID = %q, want %q", info.MemberID, "abc123")
	}
	if info.Name != "bob" {
		t.Errorf("Name = %q, want %q", info.Name, "bob")
	}
}

func TestListMemberIDs(t *testing.T) {
	paths := setupTestPaths(t)
	WriteMemberTOML(paths, "bbb", "bob", "key", 0, "self")
	WriteMemberTOML(paths, "aaa", "alice", "key", 0, "self")

	ids, err := ListMemberIDs(paths)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("len = %d, want 2", len(ids))
	}
	if ids[0] != "aaa" || ids[1] != "bbb" {
		t.Errorf("ids = %v, want [aaa bbb]", ids)
	}
}
