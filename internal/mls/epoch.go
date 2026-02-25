package mls

import (
	"encoding/json"
	"fmt"

	"github.com/germtb/mlsgit/internal/crypto"
)

const archiveKeyLabel = "mlsgit-archive"

// EpochKeyArchive manages a collection of epoch secrets keyed by epoch number.
type EpochKeyArchive struct {
	keys map[int][]byte
}

// NewEpochKeyArchive creates an empty archive.
func NewEpochKeyArchive() *EpochKeyArchive {
	return &EpochKeyArchive{keys: make(map[int][]byte)}
}

// NewWithSecret creates a new archive with a single epoch secret.
func NewWithSecret(epoch int, secret []byte) *EpochKeyArchive {
	a := NewEpochKeyArchive()
	a.Add(epoch, secret)
	return a
}

// Add records the secret for an epoch.
func (a *EpochKeyArchive) Add(epoch int, secret []byte) {
	a.keys[epoch] = secret
}

// Get retrieves the secret for an epoch.
func (a *EpochKeyArchive) Get(epoch int) ([]byte, error) {
	s, ok := a.keys[epoch]
	if !ok {
		return nil, fmt.Errorf("epoch %d not in archive", epoch)
	}
	return s, nil
}

// Has returns true if the epoch is in the archive.
func (a *EpochKeyArchive) Has(epoch int) bool {
	_, ok := a.keys[epoch]
	return ok
}

// Epochs returns sorted epoch numbers.
func (a *EpochKeyArchive) Epochs() []int {
	epochs := make([]int, 0, len(a.keys))
	for k := range a.keys {
		epochs = append(epochs, k)
	}
	// Simple insertion sort (small lists)
	for i := 1; i < len(epochs); i++ {
		for j := i; j > 0 && epochs[j-1] > epochs[j]; j-- {
			epochs[j-1], epochs[j] = epochs[j], epochs[j-1]
		}
	}
	return epochs
}

// LatestEpoch returns the highest epoch number, or -1 if empty.
func (a *EpochKeyArchive) LatestEpoch() int {
	if len(a.keys) == 0 {
		return -1
	}
	max := -1
	for k := range a.keys {
		if k > max {
			max = k
		}
	}
	return max
}

func (a *EpochKeyArchive) toJSONBytes() []byte {
	obj := make(map[string]string)
	for k, v := range a.keys {
		obj[fmt.Sprintf("%d", k)] = crypto.B64Encode(v, true)
	}
	data, _ := json.Marshal(obj)
	return data
}

func epochKeyArchiveFromJSON(data []byte) (*EpochKeyArchive, error) {
	var obj map[string]string
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, fmt.Errorf("unmarshal epoch archive: %w", err)
	}
	a := NewEpochKeyArchive()
	for k, v := range obj {
		var epoch int
		if _, err := fmt.Sscanf(k, "%d", &epoch); err != nil {
			return nil, fmt.Errorf("parse epoch key %q: %w", k, err)
		}
		secret, err := crypto.B64Decode(v, true)
		if err != nil {
			return nil, fmt.Errorf("decode epoch secret: %w", err)
		}
		a.keys[epoch] = secret
	}
	return a, nil
}

func deriveArchiveKey(epochSecret []byte) []byte {
	return crypto.DeriveFileKey(epochSecret, archiveKeyLabel, 0)
}

// Encrypt encrypts the archive under a key derived from the epoch secret.
// Returns ciphertext bytes (nonce || ciphertext || tag).
func (a *EpochKeyArchive) Encrypt(currentEpochSecret []byte) ([]byte, error) {
	plaintext := a.toJSONBytes()
	archiveKey := deriveArchiveKey(currentEpochSecret)
	nonce, ct, err := crypto.AESGCMEncrypt(archiveKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt archive: %w", err)
	}
	return append(nonce, ct...), nil
}

// DecryptArchive decrypts the archive using a key derived from the epoch secret.
func DecryptArchive(data []byte, epochSecret []byte) (*EpochKeyArchive, error) {
	archiveKey := deriveArchiveKey(epochSecret)
	if len(data) < crypto.IVSize {
		return nil, fmt.Errorf("archive data too short")
	}
	nonce := data[:crypto.IVSize]
	ct := data[crypto.IVSize:]
	plaintext, err := crypto.AESGCMDecrypt(archiveKey, nonce, ct)
	if err != nil {
		return nil, fmt.Errorf("decrypt archive: %w", err)
	}
	return epochKeyArchiveFromJSON(plaintext)
}
