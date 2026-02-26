package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
)

func generateMemberID(name string) string {
	raw := fmt.Sprintf("%s-%f", name, float64(time.Now().UnixNano())/1e9)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h)[:12]
}

func promptPassphrase(confirm bool) ([]byte, error) {
	env := os.Getenv(crypto.PassphraseEnv)
	if env != "" {
		return []byte(env), nil
	}
	// If env var is set but empty, means no passphrase
	if _, ok := os.LookupEnv(crypto.PassphraseEnv); ok {
		return nil, nil
	}

	fmt.Print("Key passphrase (empty for no encryption): ")
	var pw string
	fmt.Scanln(&pw)
	if pw == "" {
		return nil, nil
	}
	if confirm {
		fmt.Print("Confirm passphrase: ")
		var pw2 string
		fmt.Scanln(&pw2)
		if pw != pw2 {
			return nil, fmt.Errorf("passphrases do not match")
		}
	}
	return []byte(pw), nil
}

func saveMLSState(paths storage.MLSGitPaths, group *mls.MLSGitGroup) error {
	groupBytes, err := group.ToBytes()
	if err != nil {
		return err
	}
	combined := make([]byte, 32+len(groupBytes))
	copy(combined[:32], group.SigPriv())
	copy(combined[32:], groupBytes)
	return storage.WriteLocalMLSState(paths, combined)
}

func loadMLSGitGroup(paths storage.MLSGitPaths) (*mls.MLSGitGroup, error) {
	data, err := storage.ReadLocalMLSState(paths)
	if err != nil {
		return nil, err
	}
	sigPriv := data[:32]
	groupBytes := data[32:]
	group, err := mls.FromBytes(groupBytes, ed25519.NewKeyFromSeed(sigPriv))
	if err != nil {
		return nil, err
	}

	// Sync from committed state if it's ahead (e.g., after pulling)
	if committedBytes, readErr := storage.ReadGroupState(paths); readErr == nil {
		if group.SyncFromCommitted(committedBytes) {
			newGroupBytes, _ := group.ToBytes()
			combined := make([]byte, 32+len(newGroupBytes))
			copy(combined[:32], sigPriv)
			copy(combined[32:], newGroupBytes)
			storage.WriteLocalMLSState(paths, combined)
		}
	}

	return group, nil
}

func loadEpochArchive(paths storage.MLSGitPaths, group *mls.MLSGitGroup) (*mls.EpochKeyArchive, error) {
	epoch := group.Epoch()
	epochSecret := group.ExportEpochSecret()

	archiveData, err := storage.ReadEpochKeys(paths)
	if err != nil {
		if os.IsNotExist(err) {
			return mls.NewWithSecret(epoch, epochSecret), nil
		}
		return nil, err
	}
	archive, err := mls.DecryptArchive(archiveData, epochSecret)
	if err != nil {
		return nil, err
	}
	if !archive.Has(epoch) {
		archive.Add(epoch, epochSecret)
	}
	return archive, nil
}

func saveGroupAndArchive(paths storage.MLSGitPaths, group *mls.MLSGitGroup, archive *mls.EpochKeyArchive) error {
	newEpochSecret := group.ExportEpochSecret()
	archive.Add(group.Epoch(), newEpochSecret)

	archiveData, err := archive.Encrypt(newEpochSecret)
	if err != nil {
		return fmt.Errorf("encrypt archive: %w", err)
	}
	if err := storage.WriteEpochKeys(paths, archiveData); err != nil {
		return err
	}
	if err := storage.WriteEpochTOML(paths, group.Epoch()); err != nil {
		return err
	}

	committedBytes, err := group.ToCommittedBytes()
	if err != nil {
		return err
	}
	if err := storage.WriteGroupState(paths, committedBytes); err != nil {
		return err
	}
	return saveMLSState(paths, group)
}

func collectFileHashes(root string) ([]crypto.FileHash, error) {
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}

	var hashes []crypto.FileHash
	for _, f := range strings.Split(string(out), "\x00") {
		if f == "" || strings.HasPrefix(f, ".mlsgit/") || f == ".gitattributes" || f == ".gitignore" {
			continue
		}
		blob := exec.Command("git", "show", ":"+f)
		blob.Dir = root
		blobOut, err := blob.Output()
		if err != nil {
			continue
		}
		hash := crypto.ComputeFileHash(f, blobOut)
		hashes = append(hashes, crypto.FileHash{Path: f, Hash: hash})
	}
	return hashes, nil
}

func installFilterConfig(root string) error {
	gitConfig := filepath.Join(root, ".git", "config")
	data, err := os.ReadFile(gitConfig)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	configText := string(data)
	if strings.Contains(configText, `[filter "mlsgit"]`) {
		return nil
	}

	binary := resolveFilterBinary()
	block := fmt.Sprintf("\n[filter \"mlsgit\"]\n\tclean = %s filter clean %%f\n\tsmudge = %s filter smudge %%f\n\trequired = true\n",
		binary, binary)

	return os.WriteFile(gitConfig, []byte(configText+block), 0o644)
}

func resolveFilterBinary() string {
	// Look for mlsgit binary next to the current executable
	exe, err := os.Executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(exe), "mlsgit")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	// Check PATH
	found, err := exec.LookPath("mlsgit")
	if err == nil {
		return found
	}

	return "mlsgit"
}

func getRootAndPaths() (string, storage.MLSGitPaths, error) {
	root, err := config.FindGitRoot("")
	if err != nil {
		return "", storage.MLSGitPaths{}, fmt.Errorf("not inside a git repository")
	}
	return root, storage.MLSGitPaths{Root: root}, nil
}
