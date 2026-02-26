package filter

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/delta"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
)

// setupFilterTest creates a test environment with a fully initialized mlsgit state.
func setupFilterTest(t *testing.T) (storage.MLSGitPaths, *mls.MLSGitGroup, *mls.EpochKeyArchive) {
	t.Helper()
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, ".git"), 0o755)
	paths := storage.MLSGitPaths{Root: tmp}
	paths.EnsureDirs()

	// Set passphrase env to empty for testing
	os.Setenv(crypto.PassphraseEnv, "")
	t.Cleanup(func() { os.Unsetenv(crypto.PassphraseEnv) })

	// Generate keys
	signingPriv, signingPub, _ := crypto.GenerateKeypair()
	pubPEM, _ := crypto.PublicKeyToPEM(signingPub)

	// Generate MLS keys and create group
	mlsKeys, _ := mls.GenerateMLSKeys()
	memberID := "test123456ab"

	group, _ := mls.Create([]byte("test-group"), []byte("tester"), mlsKeys)

	// Write identity
	storage.WriteIdentity(paths, memberID, "tester")

	// Write private key (unencrypted)
	privPEM, _ := crypto.PrivateKeyToPEM(signingPriv, nil)
	os.WriteFile(paths.PrivateKey(), []byte(privPEM), 0o644)

	// Save MLS state
	groupBytes, _ := group.ToBytes()
	combined := make([]byte, 32+len(groupBytes))
	copy(combined[:32], mlsKeys.SigPriv.Seed())
	copy(combined[32:], groupBytes)
	storage.WriteLocalMLSState(paths, combined)

	// Save init_priv.bin for DH operations
	os.WriteFile(paths.LocalDir()+"/init_priv.bin", mlsKeys.InitPriv, 0o600)

	// Save config
	cfg := config.DefaultConfig()
	os.WriteFile(paths.ConfigTOML(), []byte(cfg.ToTOML()), 0o644)

	// Save epoch archive
	epochSecret := group.ExportEpochSecret()
	archive := mls.NewWithSecret(group.Epoch(), epochSecret)
	archiveData, _ := archive.Encrypt(epochSecret)
	storage.WriteEpochKeys(paths, archiveData)

	// Write member TOML
	storage.WriteMemberTOML(paths, memberID, "tester", pubPEM, 0, "self")

	// Write epoch TOML
	storage.WriteEpochTOML(paths, group.Epoch())

	return paths, group, archive
}

func TestCleanSmudgeRoundtrip(t *testing.T) {
	paths, _, _ := setupFilterTest(t)
	plaintext := []byte("hello, encrypted world!")

	ct, err := Clean("test.txt", plaintext, paths)
	if err != nil {
		t.Fatalf("Clean error: %v", err)
	}
	if string(ct) == string(plaintext) {
		t.Fatal("Clean should produce different output than plaintext")
	}

	decrypted, err := Smudge("test.txt", ct, paths)
	if err != nil {
		t.Fatalf("Smudge error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("Smudge result = %q, want %q", decrypted, plaintext)
	}
}

func TestCleanCacheHit(t *testing.T) {
	paths, _, _ := setupFilterTest(t)
	plaintext := []byte("cached content")

	ct1, _ := Clean("test.txt", plaintext, paths)
	ct2, _ := Clean("test.txt", plaintext, paths)

	if string(ct1) != string(ct2) {
		t.Error("same plaintext should return same ciphertext from cache")
	}
}

func TestCleanDelta(t *testing.T) {
	paths, _, _ := setupFilterTest(t)

	// First write
	ct1, _ := Clean("test.txt", []byte("version 1"), paths)
	if delta.CountDeltas(string(ct1)) != 0 {
		t.Error("first write should be base block")
	}

	// Second write (should create delta)
	ct2, _ := Clean("test.txt", []byte("version 2"), paths)
	if delta.CountDeltas(string(ct2)) != 1 {
		t.Errorf("second write should have 1 delta, got %d", delta.CountDeltas(string(ct2)))
	}

	// Smudge should decrypt the chain
	decrypted, _ := Smudge("test.txt", ct2, paths)
	if string(decrypted) != "version 2" {
		t.Errorf("smudge = %q, want %q", decrypted, "version 2")
	}
}

func TestSmudgePassthroughNonCiphertext(t *testing.T) {
	paths, _, _ := setupFilterTest(t)

	// Non-ciphertext should pass through
	plain := []byte("this is not encrypted")
	result, err := Smudge("test.txt", plain, paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(plain) {
		t.Error("non-ciphertext should pass through unchanged")
	}
}

func TestSmudgePassthroughNoState(t *testing.T) {
	tmp := t.TempDir()
	os.MkdirAll(filepath.Join(tmp, ".git"), 0o755)
	paths := storage.MLSGitPaths{Root: tmp}
	paths.EnsureDirs()

	data := []byte("any data")
	result, err := Smudge("test.txt", data, paths)
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(data) {
		t.Error("should pass through when no MLS state")
	}
}

func TestLooksCritCiphertext(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	secret := make([]byte, 32)
	ct, _ := delta.EncryptBaseBlock([]byte("test"), secret, "test.txt", 0, "alice", priv)

	if !LooksCritCiphertext(ct) {
		t.Error("valid ciphertext should be recognized")
	}

	if LooksCritCiphertext("not encrypted") {
		t.Error("plain text should not be recognized")
	}

	if LooksCritCiphertext("") {
		t.Error("empty string should not be recognized")
	}
}
