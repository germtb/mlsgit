// Package filter implements the git clean/smudge filter for mlsgit.
package filter

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/delta"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
)

// FilterState holds all state needed for filter operations.
type FilterState struct {
	MemberID   string
	Name       string
	SigningKey ed25519.PrivateKey
	Group     *mls.MLSGitGroup
	Archive   *mls.EpochKeyArchive
	Config    config.MLSGitConfig
}

// LoadState loads all state needed for filter operations.
// Returns nil if local MLS state is missing (user hasn't joined yet).
func LoadState(paths storage.MLSGitPaths) (*FilterState, error) {
	// Check if MLS state exists
	if _, err := os.Stat(paths.MLSState()); os.IsNotExist(err) {
		return nil, nil
	}

	memberID, name, err := storage.ReadIdentity(paths)
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}

	// Load Ed25519 signing key
	pemData, err := os.ReadFile(paths.PrivateKey())
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	signingPriv, err := crypto.LoadPrivateKey(string(pemData), nil)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	// Load MLS group state
	mlsStateBytes, err := storage.ReadLocalMLSState(paths)
	if err != nil {
		return nil, fmt.Errorf("read mls state: %w", err)
	}
	sigPrivRaw := mlsStateBytes[:32]
	groupState := mlsStateBytes[32:]
	mlsgitGroup, err := mls.FromBytes(groupState, ed25519.NewKeyFromSeed(sigPrivRaw))
	if err != nil {
		return nil, fmt.Errorf("restore group: %w", err)
	}

	// Sync from committed state if it's ahead (e.g., after pulling)
	if committedBytes, readErr := storage.ReadGroupState(paths); readErr == nil {
		if mlsgitGroup.SyncFromCommitted(committedBytes) {
			newGroupBytes, _ := mlsgitGroup.ToBytes()
			combined := make([]byte, 32+len(newGroupBytes))
			copy(combined[:32], sigPrivRaw)
			copy(combined[32:], newGroupBytes)
			storage.WriteLocalMLSState(paths, combined)
		}
	}

	// Load epoch key archive
	epochSecret := mlsgitGroup.ExportEpochSecret()
	var archive *mls.EpochKeyArchive

	archiveData, err := storage.ReadEpochKeys(paths)
	if err != nil {
		if os.IsNotExist(err) {
			archive = mls.NewWithSecret(mlsgitGroup.Epoch(), epochSecret)
		} else {
			return nil, fmt.Errorf("read epoch keys: %w", err)
		}
	} else {
		archive, err = mls.DecryptArchive(archiveData, epochSecret)
		if err != nil {
			return nil, fmt.Errorf("decrypt epoch archive: %w", err)
		}
	}

	// Ensure current epoch is in the archive
	epoch := mlsgitGroup.Epoch()
	if !archive.Has(epoch) {
		archive.Add(epoch, epochSecret)
	}

	// Load config
	cfgData, err := os.ReadFile(paths.ConfigTOML())
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := config.ConfigFromTOML(string(cfgData))
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &FilterState{
		MemberID:   memberID,
		Name:       name,
		SigningKey: signingPriv,
		Group:     mlsgitGroup,
		Archive:   archive,
		Config:    cfg,
	}, nil
}

// getPublicKeyForAuthor loads the public signing key for a given author from members/.
func getPublicKeyForAuthor(paths storage.MLSGitPaths, author string) (ed25519.PublicKey, error) {
	memberPath := paths.MemberTOML(author)
	info, err := storage.ReadMemberTOML(memberPath)
	if err != nil {
		return nil, fmt.Errorf("member TOML not found for author %q: %w", author, err)
	}
	return crypto.LoadPublicKey(info.PublicKey)
}

// LooksCritCiphertext returns true if data appears to be an MLSGit ciphertext chain.
func LooksCritCiphertext(data string) bool {
	firstBlock := data
	if idx := indexOf(data, config.DeltaSeparator); idx >= 0 {
		firstBlock = data[:idx]
	}
	firstBlock = trimSpace(firstBlock)
	if firstBlock == "" {
		return false
	}

	jsonBytes, err := crypto.B64Decode(firstBlock, true)
	if err != nil {
		return false
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &obj); err != nil {
		return false
	}
	_, hasEpoch := obj["epoch"]
	_, hasCT := obj["ct"]
	_, hasIV := obj["iv"]
	return hasEpoch && hasCT && hasIV
}

// Clean is the clean filter: plaintext -> ciphertext.
func Clean(filePath string, stdinData []byte, paths storage.MLSGitPaths) ([]byte, error) {
	state, err := LoadState(paths)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return stdinData, nil
	}

	epoch := state.Group.Epoch()
	epochSecret, _ := state.Archive.Get(epoch)

	cache := storage.NewFilterCache(paths)

	// Check cache: same plaintext -> return cached ciphertext
	cachedPlain := cache.GetPlaintext(filePath)
	cachedCT, hasCachedCT := cache.GetCiphertext(filePath)

	if cachedPlain != nil && bytesEqual(cachedPlain, stdinData) && hasCachedCT {
		return []byte(cachedCT), nil
	}

	var ct string
	if cachedPlain == nil || !hasCachedCT {
		// First add or cache miss: encrypt full plaintext as base block
		ct, err = delta.EncryptBaseBlock(stdinData, epochSecret, filePath, epoch, state.MemberID, state.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt base block: %w", err)
		}
	} else {
		// Compute delta from old to new plaintext
		oldText := string(cachedPlain)
		newText := string(stdinData)
		deltaText := delta.ComputeDelta(oldText, newText)

		nDeltas := delta.CountDeltas(cachedCT)
		if nDeltas >= state.Config.CompactionThreshold {
			ct, err = delta.EncryptBaseBlock(stdinData, epochSecret, filePath, epoch, state.MemberID, state.SigningKey)
			if err != nil {
				return nil, fmt.Errorf("encrypt compacted base: %w", err)
			}
		} else {
			ct, err = delta.EncryptDelta(deltaText, epochSecret, filePath, epoch,
				nDeltas+1, state.MemberID, state.SigningKey, cachedCT)
			if err != nil {
				return nil, fmt.Errorf("encrypt delta: %w", err)
			}
		}
	}

	cache.Put(filePath, stdinData, ct)
	return []byte(ct), nil
}

// Smudge is the smudge filter: ciphertext -> plaintext.
func Smudge(filePath string, stdinData []byte, paths storage.MLSGitPaths) ([]byte, error) {
	state, err := LoadState(paths)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return stdinData, nil
	}

	ciphertext := string(stdinData)

	if !LooksCritCiphertext(ciphertext) {
		return stdinData, nil
	}

	getEpochSecret := func(epoch int) ([]byte, error) {
		return state.Archive.Get(epoch)
	}
	getPublicKey := func(author string) (ed25519.PublicKey, error) {
		return getPublicKeyForAuthor(paths, author)
	}

	plaintext, err := delta.DecryptChain(ciphertext, getEpochSecret, filePath, getPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt chain: %w", err)
	}

	cache := storage.NewFilterCache(paths)
	cache.Put(filePath, plaintext, ciphertext)

	return plaintext, nil
}

// helpers

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
