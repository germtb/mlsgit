package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/BurntSushi/toml"
)

// ComputeFileHash computes a Merkle leaf hash: SHA-256(path || SHA-256(ciphertext)).
func ComputeFileHash(filePath string, ciphertext []byte) []byte {
	ctHash := sha256.Sum256(ciphertext)
	combined := append([]byte(filePath), ctHash[:]...)
	h := sha256.Sum256(combined)
	return h[:]
}

// FileHash pairs a file path with its leaf hash.
type FileHash struct {
	Path string
	Hash []byte
}

// ComputeMerkleRoot computes the Merkle root from a list of FileHash entries.
// Files are sorted by path for deterministic ordering. Odd nodes are paired
// with themselves. Returns the hex-encoded root hash, or empty string for an empty tree.
func ComputeMerkleRoot(fileHashes []FileHash) string {
	if len(fileHashes) == 0 {
		return ""
	}

	// Sort by path for determinism
	sort.Slice(fileHashes, func(i, j int) bool {
		return fileHashes[i].Path < fileHashes[j].Path
	})

	nodes := make([][]byte, len(fileHashes))
	for i, fh := range fileHashes {
		nodes[i] = fh.Hash
	}

	for len(nodes) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			right := left
			if i+1 < len(nodes) {
				right = nodes[i+1]
			}
			combined := append(left, right...)
			h := sha256.Sum256(combined)
			nextLevel = append(nextLevel, h[:])
		}
		nodes = nextLevel
	}

	return fmt.Sprintf("%x", nodes[0])
}

// SignMerkleRoot signs a Merkle root hash with Ed25519.
func SignMerkleRoot(rootHash string, privateKey ed25519.PrivateKey) []byte {
	return Sign(privateKey, []byte(rootHash))
}

// VerifyMerkleRoot verifies an Ed25519 signature on a Merkle root hash.
func VerifyMerkleRoot(rootHash string, signature []byte, publicKey ed25519.PublicKey) bool {
	return Verify(publicKey, []byte(rootHash), signature)
}

// MerkleManifest is the signed Merkle root manifest stored in .mlsgit/merkle.toml.
type MerkleManifest struct {
	RootHash  string
	Signature []byte
	Author    string
	Epoch     int
	FileCount int
}

// ToTOML serializes the manifest to TOML format matching the Python output.
func (m MerkleManifest) ToTOML() string {
	sigB64 := B64Encode(m.Signature, false)
	return fmt.Sprintf("[merkle]\nroot_hash = %q\nsignature = %q\nauthor = %q\nepoch = %d\nfile_count = %d\n",
		m.RootHash, sigB64, m.Author, m.Epoch, m.FileCount)
}

// MerkleManifestFromTOML parses a MerkleManifest from TOML text.
func MerkleManifestFromTOML(text string) (MerkleManifest, error) {
	type merkleSection struct {
		RootHash  string `toml:"root_hash"`
		Signature string `toml:"signature"`
		Author    string `toml:"author"`
		Epoch     int    `toml:"epoch"`
		FileCount int    `toml:"file_count"`
	}
	type wrapper struct {
		Merkle merkleSection `toml:"merkle"`
	}

	var w wrapper
	if _, err := toml.Decode(text, &w); err != nil {
		return MerkleManifest{}, fmt.Errorf("parsing merkle TOML: %w", err)
	}

	sig, err := B64Decode(w.Merkle.Signature, false)
	if err != nil {
		return MerkleManifest{}, fmt.Errorf("decoding signature: %w", err)
	}

	return MerkleManifest{
		RootHash:  w.Merkle.RootHash,
		Signature: sig,
		Author:    w.Merkle.Author,
		Epoch:     w.Merkle.Epoch,
		FileCount: w.Merkle.FileCount,
	}, nil
}
