// Package mls implements MLS group management for mlsgit.
//
// This is a self-contained implementation providing MLS-like semantics
// (epoch advancement, epoch secret derivation, member add/remove)
// using Ed25519 + HKDF. It can be replaced with a forked emersion/go-mls
// once that library exposes the required methods (Epoch, ExportSecret,
// Marshal/Unmarshal, Remove).
package mls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// MLSKeys bundles keys generated for an MLS member.
type MLSKeys struct {
	SigPriv  ed25519.PrivateKey // Ed25519 signing private key
	SigPub   ed25519.PublicKey  // Ed25519 signing public key
	InitPriv []byte             // X25519-like init private key (32 bytes)
	InitPub  []byte             // X25519-like init public key (32 bytes)
}

// GenerateMLSKeys generates all keys needed for MLS membership.
func GenerateMLSKeys() (MLSKeys, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return MLSKeys{}, fmt.Errorf("generate ed25519: %w", err)
	}
	initPriv := make([]byte, 32)
	if _, err := rand.Read(initPriv); err != nil {
		return MLSKeys{}, fmt.Errorf("generate init key: %w", err)
	}
	// Derive "public" init key (for KeyPackage; simplified)
	h := sha256.Sum256(initPriv)
	initPub := h[:]

	return MLSKeys{
		SigPriv:  priv,
		SigPub:   pub,
		InitPriv: initPriv,
		InitPub:  initPub,
	}, nil
}

// KeyPackageData holds the serializable key package for a member.
type KeyPackageData struct {
	Identity []byte `json:"identity"`
	SigPub   []byte `json:"sig_pub"`
	InitPub  []byte `json:"init_pub"`
}

// BuildKeyPackage builds a serializable key package.
func BuildKeyPackage(identity []byte, keys MLSKeys) KeyPackageData {
	return KeyPackageData{
		Identity: identity,
		SigPub:   keys.SigPub,
		InitPub:  keys.InitPub,
	}
}

// groupState is the serializable internal state.
type groupState struct {
	GroupID      []byte          `json:"group_id"`
	Epoch        uint64          `json:"epoch"`
	EpochSecret  []byte          `json:"epoch_secret"`
	Members      []memberEntry   `json:"members"`
	OwnLeafIndex int             `json:"own_leaf_index"`
}

type memberEntry struct {
	SigPub  []byte `json:"sig_pub"`
	InitPub []byte `json:"init_pub"`
	Active  bool   `json:"active"`
}

// WelcomeData holds the data sent to a new member joining the group.
type WelcomeData struct {
	GroupID     []byte        `json:"group_id"`
	Epoch       uint64        `json:"epoch"`
	EpochSecret []byte        `json:"epoch_secret"`
	Members     []memberEntry `json:"members"`
	LeafIndex   int           `json:"leaf_index"`
}

// MLSGitGroup wraps MLS group state for mlsgit's needs.
type MLSGitGroup struct {
	state  groupState
	sigKey ed25519.PrivateKey
}

// Create creates a new MLS group with the creator as the sole member.
func Create(groupID, identity []byte, keys MLSKeys) (*MLSGitGroup, error) {
	// Generate initial epoch secret
	epochSecret := make([]byte, 32)
	if _, err := rand.Read(epochSecret); err != nil {
		return nil, fmt.Errorf("generate epoch secret: %w", err)
	}

	g := &MLSGitGroup{
		state: groupState{
			GroupID:     groupID,
			Epoch:       0,
			EpochSecret: epochSecret,
			Members: []memberEntry{{
				SigPub:  keys.SigPub,
				InitPub: keys.InitPub,
				Active:  true,
			}},
			OwnLeafIndex: 0,
		},
		sigKey: keys.SigPriv,
	}
	return g, nil
}

// JoinFromWelcome joins an existing group from a Welcome message.
func JoinFromWelcome(welcomeBytes []byte, keys MLSKeys) (*MLSGitGroup, error) {
	var w WelcomeData
	if err := json.Unmarshal(welcomeBytes, &w); err != nil {
		return nil, fmt.Errorf("unmarshal welcome: %w", err)
	}

	g := &MLSGitGroup{
		state: groupState{
			GroupID:      w.GroupID,
			Epoch:        w.Epoch,
			EpochSecret:  w.EpochSecret,
			Members:      w.Members,
			OwnLeafIndex: w.LeafIndex,
		},
		sigKey: keys.SigPriv,
	}
	return g, nil
}

// FromBytes restores group from serialized state.
func FromBytes(data []byte, sigPriv ed25519.PrivateKey) (*MLSGitGroup, error) {
	var s groupState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal group state: %w", err)
	}
	return &MLSGitGroup{state: s, sigKey: sigPriv}, nil
}

// ToBytes serializes group state.
func (g *MLSGitGroup) ToBytes() ([]byte, error) {
	return json.Marshal(g.state)
}

// Epoch returns the current epoch number.
func (g *MLSGitGroup) Epoch() int {
	return int(g.state.Epoch)
}

// MemberCount returns the number of active members.
func (g *MLSGitGroup) MemberCount() int {
	count := 0
	for _, m := range g.state.Members {
		if m.Active {
			count++
		}
	}
	return count
}

// OwnLeafIndex returns this member's leaf index.
func (g *MLSGitGroup) OwnLeafIndex() int {
	return g.state.OwnLeafIndex
}

// SigPriv returns the signing private key (raw 32 bytes seed).
func (g *MLSGitGroup) SigPriv() []byte {
	return g.sigKey.Seed()
}

// ExportEpochSecret derives the epoch application secret for file encryption.
// label="mlsgit-epoch-secret", context="", length=32
func (g *MLSGitGroup) ExportEpochSecret() []byte {
	return exportSecret(g.state.EpochSecret, []byte("mlsgit-epoch-secret"), nil, 32)
}

func exportSecret(epochSecret, label, context []byte, length int) []byte {
	info := append(label, context...)
	r := hkdf.New(sha256.New, epochSecret, nil, info)
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		panic(fmt.Sprintf("hkdf export: %v", err))
	}
	return out
}

// advanceEpoch derives a new epoch secret and increments the epoch counter.
func (g *MLSGitGroup) advanceEpoch() {
	// Derive new epoch secret: HKDF(old_secret, salt=epoch_bytes, info="mlsgit-epoch-advance")
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, g.state.Epoch)
	r := hkdf.New(sha256.New, g.state.EpochSecret, epochBytes, []byte("mlsgit-epoch-advance"))
	newSecret := make([]byte, 32)
	if _, err := io.ReadFull(r, newSecret); err != nil {
		panic(fmt.Sprintf("hkdf advance: %v", err))
	}
	g.state.EpochSecret = newSecret
	g.state.Epoch++
}

// AddMember adds a member to the group. Returns (commitBytes, welcomeBytes).
// The epoch advances after this operation.
func (g *MLSGitGroup) AddMember(kp KeyPackageData) ([]byte, []byte, error) {
	newLeafIndex := len(g.state.Members)
	g.state.Members = append(g.state.Members, memberEntry{
		SigPub:  kp.SigPub,
		InitPub: kp.InitPub,
		Active:  true,
	})

	g.advanceEpoch()

	// Create Welcome for the new member
	welcome := WelcomeData{
		GroupID:     g.state.GroupID,
		Epoch:       g.state.Epoch,
		EpochSecret: g.state.EpochSecret,
		Members:     g.state.Members,
		LeafIndex:   newLeafIndex,
	}
	welcomeBytes, err := json.Marshal(welcome)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal welcome: %w", err)
	}

	// Commit is the serialized new state (for other existing members)
	commitBytes, err := json.Marshal(g.state)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal commit: %w", err)
	}

	return commitBytes, welcomeBytes, nil
}

// RemoveMember removes a member by leaf index. Returns commitBytes.
// The epoch advances after this operation.
func (g *MLSGitGroup) RemoveMember(leafIndex int) ([]byte, error) {
	if leafIndex < 0 || leafIndex >= len(g.state.Members) {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, len(g.state.Members))
	}
	if leafIndex == g.state.OwnLeafIndex {
		return nil, fmt.Errorf("cannot remove self")
	}

	g.state.Members[leafIndex].Active = false
	g.advanceEpoch()

	commitBytes, err := json.Marshal(g.state)
	if err != nil {
		return nil, fmt.Errorf("marshal commit: %w", err)
	}
	return commitBytes, nil
}

// ApplyCommit applies a commit received from another member.
func (g *MLSGitGroup) ApplyCommit(commitBytes []byte) error {
	var newState groupState
	if err := json.Unmarshal(commitBytes, &newState); err != nil {
		return fmt.Errorf("unmarshal commit: %w", err)
	}
	g.state = newState
	return nil
}

// SyncFromCommitted updates the group state from the committed state bytes
// (e.g., after pulling changes from remote). This preserves the local
// OwnLeafIndex and signing key. Returns true if the state was updated.
func (g *MLSGitGroup) SyncFromCommitted(committedBytes []byte) bool {
	var committed groupState
	if err := json.Unmarshal(committedBytes, &committed); err != nil {
		return false
	}
	if committed.Epoch <= g.state.Epoch {
		return false // already up to date
	}
	ownLeaf := g.state.OwnLeafIndex
	// Don't sync if we were removed
	if ownLeaf >= len(committed.Members) || !committed.Members[ownLeaf].Active {
		return false
	}
	g.state = committed
	g.state.OwnLeafIndex = ownLeaf
	return true
}
