// Package mls implements MLS group management for mlsgit.
//
// This is a self-contained implementation providing MLS-like semantics
// (epoch advancement, epoch secret derivation, member add/remove)
// using Ed25519 for signing, X25519 for DH-based rekeying, and HKDF
// for key derivation. Member removal uses DH encapsulation to ensure
// forward secrecy: removed members cannot derive future epoch secrets.
package mls

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	mlscrypto "github.com/germtb/mlsgit/internal/crypto"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// MLSKeys bundles keys generated for an MLS member.
type MLSKeys struct {
	SigPriv  ed25519.PrivateKey // Ed25519 signing private key
	SigPub   ed25519.PublicKey  // Ed25519 signing public key
	InitPriv []byte             // X25519 private key (32 bytes)
	InitPub  []byte             // X25519 public key (32 bytes)
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
	// Derive X25519 public key via scalar base multiplication
	initPub, err := curve25519.X25519(initPriv, curve25519.Basepoint)
	if err != nil {
		return MLSKeys{}, fmt.Errorf("derive x25519 public key: %w", err)
	}

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

// updateEncap holds DH-based key encapsulation data for a single epoch
// transition. Produced during RemoveMember, consumed during sync.
type updateEncap struct {
	FromEpoch uint64       `json:"from_epoch"` // epoch BEFORE the transition
	EphPub    []byte       `json:"eph_pub"`    // ephemeral X25519 public key
	Entries   []encapEntry `json:"entries"`     // per-member encrypted update secrets
}

// encapEntry holds the encrypted update secret for a single member.
type encapEntry struct {
	LeafIndex  int    `json:"leaf_index"`
	Ciphertext []byte `json:"ciphertext"` // nonce || AES-GCM(update_secret)
}

// groupState is the serializable internal state.
type groupState struct {
	GroupID      []byte        `json:"group_id"`
	Epoch        uint64        `json:"epoch"`
	EpochSecret  []byte        `json:"epoch_secret"`
	Members      []memberEntry `json:"members"`
	OwnLeafIndex int           `json:"own_leaf_index"`
	UpdateEncaps []updateEncap `json:"update_encaps,omitempty"`
}

type memberEntry struct {
	SigPub  []byte `json:"sig_pub"`
	InitPub []byte `json:"init_pub"`
	Active  bool   `json:"active"`
}

// committedGroupState is the subset of group state that is safe to commit
// to git. It deliberately excludes EpochSecret and OwnLeafIndex.
// UpdateEncaps are included so other members can perform DH-based sync
// after removals.
type committedGroupState struct {
	GroupID      []byte        `json:"group_id"`
	Epoch        uint64        `json:"epoch"`
	Members      []memberEntry `json:"members"`
	UpdateEncaps []updateEncap `json:"update_encaps,omitempty"`
}

// WelcomeData holds the data sent to a new member joining the group.
type WelcomeData struct {
	GroupID      []byte        `json:"group_id"`
	Epoch        uint64        `json:"epoch"`
	EpochSecret  []byte        `json:"epoch_secret"`
	Members      []memberEntry `json:"members"`
	LeafIndex    int           `json:"leaf_index"`
	UpdateEncaps []updateEncap `json:"update_encaps,omitempty"`
}

// MLSGitGroup wraps MLS group state for mlsgit's needs.
type MLSGitGroup struct {
	state    groupState
	sigKey   ed25519.PrivateKey
	initPriv []byte // X25519 private key for DH operations during sync
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
		sigKey:   keys.SigPriv,
		initPriv: keys.InitPriv,
	}
	return g, nil
}

// JoinFromWelcome joins an existing group from an encrypted Welcome message.
func JoinFromWelcome(encryptedWelcome []byte, keys MLSKeys) (*MLSGitGroup, error) {
	// Decrypt the Welcome using our InitPriv
	welcomeBytes, err := mlscrypto.DecryptWelcome(keys.InitPriv, encryptedWelcome)
	if err != nil {
		return nil, fmt.Errorf("decrypt welcome: %w", err)
	}

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
			UpdateEncaps: w.UpdateEncaps,
		},
		sigKey:   keys.SigPriv,
		initPriv: keys.InitPriv,
	}
	return g, nil
}

// FromBytes restores group from serialized state.
func FromBytes(data []byte, sigPriv ed25519.PrivateKey, initPriv []byte) (*MLSGitGroup, error) {
	var s groupState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("unmarshal group state: %w", err)
	}
	return &MLSGitGroup{state: s, sigKey: sigPriv, initPriv: initPriv}, nil
}

// ToBytes serializes group state (including epoch secret, for local storage only).
func (g *MLSGitGroup) ToBytes() ([]byte, error) {
	return json.Marshal(g.state)
}

// ToCommittedBytes serializes the group state for committing to git.
// The output deliberately excludes EpochSecret and OwnLeafIndex so that
// anyone with repo read access cannot derive file encryption keys.
// UpdateEncaps are included so other members can perform DH-based sync.
func (g *MLSGitGroup) ToCommittedBytes() ([]byte, error) {
	return json.Marshal(committedGroupState{
		GroupID:      g.state.GroupID,
		Epoch:        g.state.Epoch,
		Members:      g.state.Members,
		UpdateEncaps: g.state.UpdateEncaps,
	})
}

// FindLeafIndex returns the leaf index for a member identified by their InitPub.
// Returns -1 if not found.
func (g *MLSGitGroup) FindLeafIndex(initPub []byte) int {
	for i, m := range g.state.Members {
		if m.Active && len(m.InitPub) == len(initPub) {
			match := true
			for j := range m.InitPub {
				if m.InitPub[j] != initPub[j] {
					match = false
					break
				}
			}
			if match {
				return i
			}
		}
	}
	return -1
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

// advanceEpoch performs a deterministic epoch advance.
// Used for add operations where no member is being excluded.
func (g *MLSGitGroup) advanceEpoch() {
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

// advanceEpochDH performs a DH-based epoch advance for member removal.
// It generates a fresh update secret, encrypts it to each remaining active
// member using X25519 DH, and mixes it into the epoch derivation. This
// ensures removed members cannot derive the new epoch secret.
func (g *MLSGitGroup) advanceEpochDH() error {
	// Generate fresh update secret (the entropy a removed member can't obtain)
	updateSecret := make([]byte, 32)
	if _, err := rand.Read(updateSecret); err != nil {
		return fmt.Errorf("generate update secret: %w", err)
	}

	// Generate ephemeral X25519 keypair
	ephPriv := make([]byte, 32)
	if _, err := rand.Read(ephPriv); err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPub, err := curve25519.X25519(ephPriv, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive ephemeral public key: %w", err)
	}

	// Encrypt updateSecret for each remaining active member
	var entries []encapEntry
	for i, m := range g.state.Members {
		if !m.Active {
			continue
		}
		shared, err := curve25519.X25519(ephPriv, m.InitPub)
		if err != nil {
			return fmt.Errorf("dh with member %d: %w", i, err)
		}
		encKey := deriveEncapKey(shared, g.state.Epoch)
		nonce, ct, err := mlscrypto.AESGCMEncrypt(encKey, updateSecret)
		if err != nil {
			return fmt.Errorf("encrypt update secret for member %d: %w", i, err)
		}
		entries = append(entries, encapEntry{
			LeafIndex:  i,
			Ciphertext: append(nonce, ct...),
		})
	}

	// Record the encapsulation
	g.state.UpdateEncaps = append(g.state.UpdateEncaps, updateEncap{
		FromEpoch: g.state.Epoch,
		EphPub:    ephPub,
		Entries:   entries,
	})

	// Derive new epoch secret: HKDF(oldSecret || updateSecret, epoch, info)
	// The updateSecret provides entropy that the removed member cannot obtain.
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, g.state.Epoch)
	ikm := make([]byte, 64)
	copy(ikm[:32], g.state.EpochSecret)
	copy(ikm[32:], updateSecret)
	r := hkdf.New(sha256.New, ikm, epochBytes, []byte("mlsgit-epoch-advance"))
	newSecret := make([]byte, 32)
	if _, err := io.ReadFull(r, newSecret); err != nil {
		panic(fmt.Sprintf("hkdf advance: %v", err))
	}
	g.state.EpochSecret = newSecret
	g.state.Epoch++
	return nil
}

// deriveEncapKey derives an AES-256 encryption key from a DH shared secret.
func deriveEncapKey(dhShared []byte, epoch uint64) []byte {
	epochBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(epochBytes, epoch)
	r := hkdf.New(sha256.New, dhShared, epochBytes, []byte("mlsgit-encap"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("hkdf encap key: %v", err))
	}
	return key
}

// advanceOneEpoch advances the epoch by one step, using DH decapsulation
// if an encap exists for the current epoch, or deterministic HKDF otherwise.
func (g *MLSGitGroup) advanceOneEpoch(encaps []updateEncap) error {
	for _, enc := range encaps {
		if enc.FromEpoch == g.state.Epoch {
			return g.applyDHAdvance(enc)
		}
	}
	// No DH encap — deterministic advance (add operation)
	g.advanceEpoch()
	return nil
}

// applyDHAdvance decrypts a DH encapsulation and advances the epoch.
func (g *MLSGitGroup) applyDHAdvance(enc updateEncap) error {
	for _, e := range enc.Entries {
		if e.LeafIndex == g.state.OwnLeafIndex {
			// DH: shared = X25519(ourInitPriv, ephPub)
			shared, err := curve25519.X25519(g.initPriv, enc.EphPub)
			if err != nil {
				return fmt.Errorf("dh: %w", err)
			}
			decKey := deriveEncapKey(shared, g.state.Epoch)

			if len(e.Ciphertext) < mlscrypto.IVSize {
				return fmt.Errorf("encap ciphertext too short")
			}
			nonce := e.Ciphertext[:mlscrypto.IVSize]
			ct := e.Ciphertext[mlscrypto.IVSize:]
			updateSecret, err := mlscrypto.AESGCMDecrypt(decKey, nonce, ct)
			if err != nil {
				return fmt.Errorf("decrypt update secret: %w", err)
			}

			// Derive new epoch secret: HKDF(oldSecret || updateSecret, epoch, info)
			epochBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(epochBytes, g.state.Epoch)
			ikm := make([]byte, 64)
			copy(ikm[:32], g.state.EpochSecret)
			copy(ikm[32:], updateSecret)
			r := hkdf.New(sha256.New, ikm, epochBytes, []byte("mlsgit-epoch-advance"))
			newSecret := make([]byte, 32)
			if _, err := io.ReadFull(r, newSecret); err != nil {
				panic(fmt.Sprintf("hkdf advance: %v", err))
			}
			g.state.EpochSecret = newSecret
			g.state.Epoch++
			return nil
		}
	}
	return fmt.Errorf("no encap entry for leaf %d at epoch %d", g.state.OwnLeafIndex, g.state.Epoch)
}

// AddMember adds a member to the group. Returns (commitBytes, welcomeBytes).
// The epoch advances deterministically after this operation.
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
		GroupID:      g.state.GroupID,
		Epoch:        g.state.Epoch,
		EpochSecret:  g.state.EpochSecret,
		Members:      g.state.Members,
		LeafIndex:    newLeafIndex,
		UpdateEncaps: g.state.UpdateEncaps,
	}
	welcomeBytes, err := json.Marshal(welcome)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal welcome: %w", err)
	}

	// Encrypt the Welcome under the new member's InitPub
	encryptedWelcome, err := mlscrypto.EncryptWelcome(kp.InitPub, welcomeBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt welcome: %w", err)
	}

	// Commit is the committed state (without epoch secret, for other existing members)
	commitBytes, err := g.ToCommittedBytes()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal commit: %w", err)
	}

	return commitBytes, encryptedWelcome, nil
}

// RemoveMember removes a member by leaf index. Returns commitBytes.
// The epoch advances using DH-based rekeying to ensure the removed member
// cannot derive the new epoch secret.
func (g *MLSGitGroup) RemoveMember(leafIndex int) ([]byte, error) {
	if leafIndex < 0 || leafIndex >= len(g.state.Members) {
		return nil, fmt.Errorf("leaf index %d out of range [0, %d)", leafIndex, len(g.state.Members))
	}
	if leafIndex == g.state.OwnLeafIndex {
		return nil, fmt.Errorf("cannot remove self")
	}

	g.state.Members[leafIndex].Active = false

	if err := g.advanceEpochDH(); err != nil {
		return nil, fmt.Errorf("advance epoch: %w", err)
	}

	commitBytes, err := g.ToCommittedBytes()
	if err != nil {
		return nil, fmt.Errorf("marshal commit: %w", err)
	}
	return commitBytes, nil
}

// ApplyCommit applies a commit received from another member.
// Uses DH decapsulation for removal-based transitions and deterministic
// HKDF for add-based transitions.
func (g *MLSGitGroup) ApplyCommit(commitBytes []byte) error {
	var committed committedGroupState
	if err := json.Unmarshal(commitBytes, &committed); err != nil {
		return fmt.Errorf("unmarshal commit: %w", err)
	}
	if committed.Epoch <= g.state.Epoch {
		return nil // already up to date
	}
	// Ratchet forward from current epoch to committed epoch
	for g.state.Epoch < committed.Epoch {
		if err := g.advanceOneEpoch(committed.UpdateEncaps); err != nil {
			return fmt.Errorf("advance to epoch %d: %w", g.state.Epoch+1, err)
		}
	}
	g.state.GroupID = committed.GroupID
	g.state.Members = committed.Members
	g.state.UpdateEncaps = committed.UpdateEncaps
	return nil
}

// SyncFromCommitted updates the group state from the committed state bytes
// (e.g., after pulling changes from remote). The committed state does not
// contain the epoch secret, so we derive it using DH decapsulation for
// removal transitions or deterministic HKDF for add transitions.
// Preserves OwnLeafIndex and signing key. Returns true if the state was updated.
func (g *MLSGitGroup) SyncFromCommitted(committedBytes []byte) bool {
	var committed committedGroupState
	if err := json.Unmarshal(committedBytes, &committed); err != nil {
		return false
	}
	if committed.Epoch < g.state.Epoch {
		return false
	}
	// Pick up encaps even if epoch matches (ensures propagation to all members)
	if committed.Epoch == g.state.Epoch {
		if len(committed.UpdateEncaps) > len(g.state.UpdateEncaps) {
			g.state.UpdateEncaps = committed.UpdateEncaps
			return true
		}
		return false
	}
	ownLeaf := g.state.OwnLeafIndex
	// Don't sync if we were removed
	if ownLeaf >= len(committed.Members) || !committed.Members[ownLeaf].Active {
		return false
	}
	// Ratchet local epoch secret forward to reach the committed epoch
	for g.state.Epoch < committed.Epoch {
		if err := g.advanceOneEpoch(committed.UpdateEncaps); err != nil {
			return false
		}
	}
	g.state.GroupID = committed.GroupID
	g.state.Members = committed.Members
	g.state.OwnLeafIndex = ownLeaf
	g.state.UpdateEncaps = committed.UpdateEncaps
	return true
}
