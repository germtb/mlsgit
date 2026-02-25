package delta

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
)

// DeltaRecord is one encrypted delta (or base) block in the ciphertext chain.
type DeltaRecord struct {
	Epoch    int    `json:"epoch"`
	Seq      int    `json:"seq"`
	IV       []byte `json:"-"`
	CT       []byte `json:"-"`
	Sig      []byte `json:"-"`
	Author   string `json:"author"`
	PrevHash string `json:"prev_hash"`
	FilePath string `json:"file_path"`
}

// deltaRecordJSON is the JSON wire format with base64 encoded byte fields.
type deltaRecordJSON struct {
	Epoch    int    `json:"epoch"`
	Seq      int    `json:"seq"`
	IV       string `json:"iv"`
	CT       string `json:"ct"`
	Sig      string `json:"sig"`
	Author   string `json:"author"`
	PrevHash string `json:"prev_hash"`
	FilePath string `json:"file_path"`
}

// ToB64 serializes to a base64-encoded JSON string (url-safe b64 of JSON, matching Python).
func (r DeltaRecord) ToB64() string {
	obj := deltaRecordJSON{
		Epoch:    r.Epoch,
		Seq:      r.Seq,
		IV:       crypto.B64Encode(r.IV, true),
		CT:       crypto.B64Encode(r.CT, true),
		Sig:      crypto.B64Encode(r.Sig, true),
		Author:   r.Author,
		PrevHash: r.PrevHash,
		FilePath: r.FilePath,
	}
	jsonBytes, _ := json.Marshal(obj)
	return crypto.B64Encode(jsonBytes, true)
}

// DeltaRecordFromB64 deserializes from a base64-encoded JSON string.
func DeltaRecordFromB64(b64Str string) (DeltaRecord, error) {
	jsonBytes, err := crypto.B64Decode(b64Str, true)
	if err != nil {
		return DeltaRecord{}, fmt.Errorf("b64 decode record: %w", err)
	}
	var obj deltaRecordJSON
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return DeltaRecord{}, fmt.Errorf("json unmarshal record: %w", err)
	}
	iv, err := crypto.B64Decode(obj.IV, true)
	if err != nil {
		return DeltaRecord{}, fmt.Errorf("decode iv: %w", err)
	}
	ct, err := crypto.B64Decode(obj.CT, true)
	if err != nil {
		return DeltaRecord{}, fmt.Errorf("decode ct: %w", err)
	}
	sig, err := crypto.B64Decode(obj.Sig, true)
	if err != nil {
		return DeltaRecord{}, fmt.Errorf("decode sig: %w", err)
	}
	return DeltaRecord{
		Epoch:    obj.Epoch,
		Seq:      obj.Seq,
		IV:       iv,
		CT:       ct,
		Sig:      sig,
		Author:   obj.Author,
		PrevHash: obj.PrevHash,
		FilePath: obj.FilePath,
	}, nil
}

func hashPrefix(data string) string {
	h := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", h)
}

// EncryptBaseBlock encrypts a full plaintext as the initial base block.
// Returns the full ciphertext string (a single base64-encoded DeltaRecord).
func EncryptBaseBlock(
	plaintext []byte,
	epochSecret []byte,
	filePath string,
	epoch int,
	author string,
	privateKey ed25519.PrivateKey,
) (string, error) {
	key := crypto.DeriveFileKey(epochSecret, filePath, epoch)
	iv, ct, err := crypto.AESGCMEncrypt(key, plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypt base block: %w", err)
	}
	sigData := append(iv, ct...)
	sig := crypto.Sign(privateKey, sigData)
	record := DeltaRecord{
		Epoch:    epoch,
		Seq:      0,
		IV:       iv,
		CT:       ct,
		Sig:      sig,
		Author:   author,
		PrevHash: "",
		FilePath: filePath,
	}
	return record.ToB64(), nil
}

// EncryptDelta encrypts a delta and appends it to the existing ciphertext chain.
// Returns the full ciphertext string (old ciphertext + separator + new record).
func EncryptDelta(
	deltaText string,
	epochSecret []byte,
	filePath string,
	epoch int,
	seq int,
	author string,
	privateKey ed25519.PrivateKey,
	prevCiphertext string,
) (string, error) {
	key := crypto.DeriveFileKey(epochSecret, filePath, epoch)
	iv, ct, err := crypto.AESGCMEncrypt(key, []byte(deltaText))
	if err != nil {
		return "", fmt.Errorf("encrypt delta: %w", err)
	}
	sigData := append(iv, ct...)
	sig := crypto.Sign(privateKey, sigData)
	prevHash := hashPrefix(prevCiphertext)
	record := DeltaRecord{
		Epoch:    epoch,
		Seq:      seq,
		IV:       iv,
		CT:       ct,
		Sig:      sig,
		Author:   author,
		PrevHash: prevHash,
		FilePath: filePath,
	}
	return prevCiphertext + config.DeltaSeparator + record.ToB64(), nil
}

// EpochSecretFunc retrieves the epoch secret for a given epoch.
type EpochSecretFunc func(epoch int) ([]byte, error)

// PublicKeyFunc retrieves the public signing key for a given author.
type PublicKeyFunc func(author string) (ed25519.PublicKey, error)

// DecryptChain decrypts a full ciphertext chain (base block + deltas).
// Returns the final plaintext as bytes.
func DecryptChain(
	ciphertext string,
	getEpochSecret EpochSecretFunc,
	filePath string,
	getPublicKey PublicKeyFunc,
) ([]byte, error) {
	blocks := strings.Split(ciphertext, config.DeltaSeparator)
	if len(blocks) == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}

	// Decrypt base block
	baseRecord, err := DeltaRecordFromB64(blocks[0])
	if err != nil {
		return nil, fmt.Errorf("parse base block: %w", err)
	}

	basePath := baseRecord.FilePath
	if basePath == "" {
		basePath = filePath
	}

	baseEpochSecret, err := getEpochSecret(baseRecord.Epoch)
	if err != nil {
		return nil, fmt.Errorf("get epoch secret for base: %w", err)
	}
	baseKey := crypto.DeriveFileKey(baseEpochSecret, basePath, baseRecord.Epoch)

	pub, err := getPublicKey(baseRecord.Author)
	if err != nil {
		return nil, fmt.Errorf("get public key for base: %w", err)
	}
	sigData := append(baseRecord.IV, baseRecord.CT...)
	if !crypto.Verify(pub, sigData, baseRecord.Sig) {
		return nil, fmt.Errorf("signature verification failed on base block (author=%s)", baseRecord.Author)
	}

	plaintext, err := crypto.AESGCMDecrypt(baseKey, baseRecord.IV, baseRecord.CT)
	if err != nil {
		return nil, fmt.Errorf("decrypt base block: %w", err)
	}
	text := string(plaintext)

	// Verify hash chain and apply deltas
	prevContent := blocks[0]
	for i := 1; i < len(blocks); i++ {
		record, err := DeltaRecordFromB64(blocks[i])
		if err != nil {
			return nil, fmt.Errorf("parse delta %d: %w", i, err)
		}

		expectedHash := hashPrefix(prevContent)
		if record.PrevHash != expectedHash {
			return nil, fmt.Errorf("hash chain broken at delta %d", i)
		}

		deltaPath := record.FilePath
		if deltaPath == "" {
			deltaPath = filePath
		}

		deltaEpochSecret, err := getEpochSecret(record.Epoch)
		if err != nil {
			return nil, fmt.Errorf("get epoch secret for delta %d: %w", i, err)
		}
		deltaKey := crypto.DeriveFileKey(deltaEpochSecret, deltaPath, record.Epoch)

		pub, err := getPublicKey(record.Author)
		if err != nil {
			return nil, fmt.Errorf("get public key for delta %d: %w", i, err)
		}
		sigData := append(record.IV, record.CT...)
		if !crypto.Verify(pub, sigData, record.Sig) {
			return nil, fmt.Errorf("signature verification failed on delta %d (author=%s)", i, record.Author)
		}

		deltaBytes, err := crypto.AESGCMDecrypt(deltaKey, record.IV, record.CT)
		if err != nil {
			return nil, fmt.Errorf("decrypt delta %d: %w", i, err)
		}

		text, err = ApplyDelta(text, string(deltaBytes))
		if err != nil {
			return nil, fmt.Errorf("apply delta %d: %w", i, err)
		}

		prevContent = prevContent + config.DeltaSeparator + blocks[i]
	}

	return []byte(text), nil
}

// CountDeltas returns the number of delta blocks (excluding the base block).
func CountDeltas(ciphertext string) int {
	return strings.Count(ciphertext, config.DeltaSeparator)
}
