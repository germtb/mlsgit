package crypto

import (
	"bytes"
	"testing"
)

func TestComputeFileHash(t *testing.T) {
	hash1 := ComputeFileHash("test.txt", []byte("hello"))
	hash2 := ComputeFileHash("test.txt", []byte("hello"))
	hash3 := ComputeFileHash("other.txt", []byte("hello"))
	hash4 := ComputeFileHash("test.txt", []byte("world"))

	if !bytes.Equal(hash1, hash2) {
		t.Error("same inputs must produce same hash")
	}
	if bytes.Equal(hash1, hash3) {
		t.Error("different paths must produce different hashes")
	}
	if bytes.Equal(hash1, hash4) {
		t.Error("different content must produce different hashes")
	}
	if len(hash1) != 32 {
		t.Errorf("hash length = %d, want 32", len(hash1))
	}
}

func TestComputeMerkleRootEmpty(t *testing.T) {
	root := ComputeMerkleRoot(nil)
	if root != "" {
		t.Errorf("empty tree root = %q, want empty string", root)
	}
}

func TestComputeMerkleRootSingleFile(t *testing.T) {
	hash := ComputeFileHash("test.txt", []byte("hello"))
	root := ComputeMerkleRoot([]FileHash{{Path: "test.txt", Hash: hash}})

	if root == "" {
		t.Error("single file root should not be empty")
	}
	if len(root) != 64 {
		t.Errorf("root hash hex length = %d, want 64", len(root))
	}
}

func TestComputeMerkleRootDeterministic(t *testing.T) {
	hashes := []FileHash{
		{Path: "b.txt", Hash: ComputeFileHash("b.txt", []byte("b"))},
		{Path: "a.txt", Hash: ComputeFileHash("a.txt", []byte("a"))},
	}
	root1 := ComputeMerkleRoot(hashes)

	// Reversed input order should produce same root (sorted internally)
	hashes2 := []FileHash{
		{Path: "a.txt", Hash: ComputeFileHash("a.txt", []byte("a"))},
		{Path: "b.txt", Hash: ComputeFileHash("b.txt", []byte("b"))},
	}
	root2 := ComputeMerkleRoot(hashes2)

	if root1 != root2 {
		t.Errorf("roots differ: %q vs %q", root1, root2)
	}
}

func TestComputeMerkleRootOddNodes(t *testing.T) {
	hashes := []FileHash{
		{Path: "a.txt", Hash: ComputeFileHash("a.txt", []byte("a"))},
		{Path: "b.txt", Hash: ComputeFileHash("b.txt", []byte("b"))},
		{Path: "c.txt", Hash: ComputeFileHash("c.txt", []byte("c"))},
	}
	root := ComputeMerkleRoot(hashes)
	if root == "" {
		t.Error("odd node root should not be empty")
	}
}

func TestSignVerifyMerkleRoot(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	rootHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	sig := SignMerkleRoot(rootHash, priv)

	if !VerifyMerkleRoot(rootHash, sig, pub) {
		t.Error("valid signature rejected")
	}
	if VerifyMerkleRoot("tampered", sig, pub) {
		t.Error("tampered root should be rejected")
	}
}

func TestMerkleManifestTOMLRoundtrip(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	manifest := MerkleManifest{
		RootHash:  "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
		Signature: Sign(priv, []byte("test")),
		Author:    "abc123def456",
		Epoch:     5,
		FileCount: 10,
	}

	text := manifest.ToTOML()
	parsed, err := MerkleManifestFromTOML(text)
	if err != nil {
		t.Fatalf("MerkleManifestFromTOML error: %v", err)
	}

	if parsed.RootHash != manifest.RootHash {
		t.Errorf("RootHash = %q, want %q", parsed.RootHash, manifest.RootHash)
	}
	if !bytes.Equal(parsed.Signature, manifest.Signature) {
		t.Error("Signature mismatch")
	}
	if parsed.Author != manifest.Author {
		t.Errorf("Author = %q, want %q", parsed.Author, manifest.Author)
	}
	if parsed.Epoch != manifest.Epoch {
		t.Errorf("Epoch = %d, want %d", parsed.Epoch, manifest.Epoch)
	}
	if parsed.FileCount != manifest.FileCount {
		t.Errorf("FileCount = %d, want %d", parsed.FileCount, manifest.FileCount)
	}
}
