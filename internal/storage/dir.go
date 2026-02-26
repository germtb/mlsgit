package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/germtb/mlsgit/internal/crypto"
)

// --- Identity helpers ---

// WriteIdentity writes the local identity file.
func WriteIdentity(paths MLSGitPaths, memberID, name string) error {
	content := fmt.Sprintf("[identity]\nmember_id = %q\nname = %q\n", memberID, name)
	return os.WriteFile(paths.IdentityTOML(), []byte(content), 0o644)
}

// ReadIdentity reads local identity -> {"member_id": ..., "name": ...}.
func ReadIdentity(paths MLSGitPaths) (memberID, name string, err error) {
	data, err := os.ReadFile(paths.IdentityTOML())
	if err != nil {
		return "", "", err
	}
	type identitySection struct {
		MemberID string `toml:"member_id"`
		Name     string `toml:"name"`
	}
	type wrapper struct {
		Identity identitySection `toml:"identity"`
	}
	var w wrapper
	if _, err := toml.Decode(string(data), &w); err != nil {
		return "", "", fmt.Errorf("parse identity TOML: %w", err)
	}
	return w.Identity.MemberID, w.Identity.Name, nil
}

// --- Member helpers ---

// WriteMemberTOML writes a member info file in .mlsgit/members/.
func WriteMemberTOML(paths MLSGitPaths, memberID, name, publicKeyPEM string, joinedEpoch int, addedBy string) error {
	content := fmt.Sprintf("[member]\nname = %q\npublic_key = \"\"\"\n%s\n\"\"\"\njoined_epoch = %d\nadded_by = %q\n",
		name, publicKeyPEM, joinedEpoch, addedBy)
	return os.WriteFile(paths.MemberTOML(memberID), []byte(content), 0o644)
}

// MemberInfo holds parsed member data.
type MemberInfo struct {
	Name        string
	PublicKey   string
	JoinedEpoch int
	AddedBy     string
}

// ReadMemberTOML parses a member TOML file.
func ReadMemberTOML(path string) (MemberInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MemberInfo{}, err
	}
	type memberSection struct {
		Name        string `toml:"name"`
		PublicKey   string `toml:"public_key"`
		JoinedEpoch int    `toml:"joined_epoch"`
		AddedBy     string `toml:"added_by"`
	}
	type wrapper struct {
		Member memberSection `toml:"member"`
	}
	var w wrapper
	if _, err := toml.Decode(string(data), &w); err != nil {
		return MemberInfo{}, fmt.Errorf("parse member TOML: %w", err)
	}
	return MemberInfo{
		Name:        w.Member.Name,
		PublicKey:   strings.TrimSpace(w.Member.PublicKey),
		JoinedEpoch: w.Member.JoinedEpoch,
		AddedBy:     w.Member.AddedBy,
	}, nil
}

// --- Epoch helpers ---

// WriteEpochTOML writes epoch.toml with the current epoch.
func WriteEpochTOML(paths MLSGitPaths, epoch int) error {
	content := fmt.Sprintf("[epoch]\ncurrent = %d\n", epoch)
	return os.WriteFile(paths.EpochTOML(), []byte(content), 0o644)
}

// ReadEpochTOML reads epoch.toml -> current epoch number.
func ReadEpochTOML(paths MLSGitPaths) (int, error) {
	data, err := os.ReadFile(paths.EpochTOML())
	if err != nil {
		return 0, err
	}
	type epochSection struct {
		Current int `toml:"current"`
	}
	type wrapper struct {
		Epoch epochSection `toml:"epoch"`
	}
	var w wrapper
	if _, err := toml.Decode(string(data), &w); err != nil {
		return 0, fmt.Errorf("parse epoch TOML: %w", err)
	}
	return w.Epoch.Current, nil
}

// --- Pending request helpers ---

// WritePendingRequest writes a pending join request file.
func WritePendingRequest(paths MLSGitPaths, memberID, name, publicKeyPEM, keypackageB64 string) error {
	content := fmt.Sprintf(
		"[request]\nmember_id = %q\nname = %q\npublic_key = \"\"\"\n%s\n\"\"\"\nkeypackage = \"\"\"\n%s\n\"\"\"\ntimestamp = %d\n",
		memberID, name, publicKeyPEM, keypackageB64, time.Now().Unix())
	return os.WriteFile(paths.PendingRequest(memberID), []byte(content), 0o644)
}

// PendingRequestInfo holds parsed pending request data.
type PendingRequestInfo struct {
	MemberID   string
	Name       string
	PublicKey  string
	Keypackage string
	Timestamp  int64
}

// ReadPendingRequest parses a pending request TOML file.
func ReadPendingRequest(path string) (PendingRequestInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PendingRequestInfo{}, err
	}
	type requestSection struct {
		MemberID   string `toml:"member_id"`
		Name       string `toml:"name"`
		PublicKey  string `toml:"public_key"`
		Keypackage string `toml:"keypackage"`
		Timestamp  int64  `toml:"timestamp"`
	}
	type wrapper struct {
		Request requestSection `toml:"request"`
	}
	var w wrapper
	if _, err := toml.Decode(string(data), &w); err != nil {
		return PendingRequestInfo{}, fmt.Errorf("parse request TOML: %w", err)
	}
	return PendingRequestInfo{
		MemberID:   w.Request.MemberID,
		Name:       w.Request.Name,
		PublicKey:  strings.TrimSpace(w.Request.PublicKey),
		Keypackage: strings.TrimSpace(w.Request.Keypackage),
		Timestamp:  w.Request.Timestamp,
	}, nil
}

// --- MLS state helpers ---

// WriteGroupState writes MLS group state as base64 to .mlsgit/group/state.b64.
func WriteGroupState(paths MLSGitPaths, stateBytes []byte) error {
	return os.WriteFile(paths.GroupState(), []byte(crypto.B64Encode(stateBytes, false)), 0o644)
}

// ReadGroupState reads MLS group state from .mlsgit/group/state.b64.
func ReadGroupState(paths MLSGitPaths) ([]byte, error) {
	data, err := os.ReadFile(paths.GroupState())
	if err != nil {
		return nil, err
	}
	return crypto.B64Decode(strings.TrimSpace(string(data)), false)
}

// WriteLocalMLSState writes local MLS ratchet state to .git/mlsgit/mls_state.bin.
func WriteLocalMLSState(paths MLSGitPaths, stateBytes []byte) error {
	return os.WriteFile(paths.MLSState(), stateBytes, 0o600)
}

// ReadLocalMLSState reads local MLS ratchet state from .git/mlsgit/mls_state.bin.
func ReadLocalMLSState(paths MLSGitPaths) ([]byte, error) {
	return os.ReadFile(paths.MLSState())
}

// WriteWelcome writes a Welcome message for a member.
func WriteWelcome(paths MLSGitPaths, memberID string, welcomeBytes []byte) error {
	return os.WriteFile(paths.WelcomeFile(memberID),
		[]byte(crypto.B64Encode(welcomeBytes, false)), 0o644)
}

// ReadWelcome reads a Welcome message for a member.
func ReadWelcome(paths MLSGitPaths, memberID string) ([]byte, error) {
	data, err := os.ReadFile(paths.WelcomeFile(memberID))
	if err != nil {
		return nil, err
	}
	return crypto.B64Decode(strings.TrimSpace(string(data)), false)
}

// --- Merkle manifest ---

// WriteMerkleManifest writes the Merkle manifest to .mlsgit/merkle.toml.
func WriteMerkleManifest(paths MLSGitPaths, manifest crypto.MerkleManifest) error {
	return os.WriteFile(paths.MerkleTOML(), []byte(manifest.ToTOML()), 0o644)
}

// ReadMerkleManifest reads the Merkle manifest from .mlsgit/merkle.toml.
func ReadMerkleManifest(paths MLSGitPaths) (crypto.MerkleManifest, error) {
	data, err := os.ReadFile(paths.MerkleTOML())
	if err != nil {
		return crypto.MerkleManifest{}, err
	}
	return crypto.MerkleManifestFromTOML(string(data))
}

// --- Epoch key archive ---

// WriteEpochKeys writes the encrypted epoch key archive.
func WriteEpochKeys(paths MLSGitPaths, data []byte) error {
	return os.WriteFile(paths.EpochKeys(), []byte(crypto.B64Encode(data, false)), 0o644)
}

// ReadEpochKeys reads the encrypted epoch key archive.
func ReadEpochKeys(paths MLSGitPaths) ([]byte, error) {
	data, err := os.ReadFile(paths.EpochKeys())
	if err != nil {
		return nil, err
	}
	return crypto.B64Decode(strings.TrimSpace(string(data)), false)
}

// --- Member listing helpers ---

// ListMemberIDs returns sorted member IDs from the members directory.
func ListMemberIDs(paths MLSGitPaths) ([]string, error) {
	entries, err := os.ReadDir(paths.MembersDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".toml") {
			ids = append(ids, strings.TrimSuffix(e.Name(), ".toml"))
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// ListPendingRequests returns paths to pending request files.
func ListPendingRequests(paths MLSGitPaths) ([]string, error) {
	entries, err := os.ReadDir(paths.PendingDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var requests []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".request.toml") {
			requests = append(requests, filepath.Join(paths.PendingDir(), e.Name()))
		}
	}
	sort.Strings(requests)
	return requests, nil
}

// --- WriteEpochTOMLFull writes epoch.toml with an optional epoch->commit mapping ---

// WriteEpochTOMLWithMapping writes epoch.toml with the current epoch and optional mapping.
func WriteEpochTOMLWithMapping(paths MLSGitPaths, epoch int, mapping map[int]string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "[epoch]\ncurrent = %d\n", epoch)
	if len(mapping) > 0 {
		b.WriteString("\n[epoch.commits]\n")
		keys := make([]int, 0, len(mapping))
		for k := range mapping {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "%s = %q\n", strconv.Itoa(k), mapping[k])
		}
	}
	return os.WriteFile(paths.EpochTOML(), []byte(b.String()), 0o644)
}
