package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var initName string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize mlsgit in the current git repository",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().StringVar(&initName, "name", "", "Your display name for the group")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	root, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	if _, err := os.Stat(paths.MLSGitDir()); err == nil {
		return fmt.Errorf(".mlsgit/ already exists. MLSGit is already initialized")
	}

	if initName == "" {
		fmt.Print("Your name: ")
		fmt.Scanln(&initName)
	}

	// 1. Create directory structure
	if err := paths.EnsureDirs(); err != nil {
		return fmt.Errorf("create dirs: %w", err)
	}

	// 2. Generate Ed25519 key pair for signing deltas
	passphrase, err := promptPassphrase(true)
	if err != nil {
		return err
	}
	signingPriv, signingPub, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	privPEM, err := crypto.PrivateKeyToPEM(signingPriv, passphrase)
	if err != nil {
		return err
	}
	if err := os.WriteFile(paths.PrivateKey(), []byte(privPEM), 0o600); err != nil {
		return err
	}
	pubPEM, err := crypto.PublicKeyToPEM(signingPub)
	if err != nil {
		return err
	}

	// 3. Generate MLS keys and create group
	mlsKeys, err := mls.GenerateMLSKeys()
	if err != nil {
		return err
	}
	memberID := generateMemberID(initName)

	groupIDHash := sha256.Sum256([]byte(root))
	groupID := []byte(fmt.Sprintf("mlsgit-%x", groupIDHash)[:24])
	mlsgitGroup, err := mls.Create(groupID, []byte(initName), mlsKeys)
	if err != nil {
		return err
	}

	// 4. Save local state
	if err := storage.WriteIdentity(paths, memberID, initName); err != nil {
		return err
	}
	if err := saveMLSState(paths, mlsgitGroup); err != nil {
		return err
	}

	// Save init_priv for Welcome processing
	if err := os.WriteFile(
		paths.LocalDir()+"/init_priv.bin", mlsKeys.InitPriv, 0o600,
	); err != nil {
		return err
	}

	// 5. Write committed files
	cfg := config.DefaultConfig()
	if err := os.WriteFile(paths.ConfigTOML(), []byte(cfg.ToTOML()), 0o644); err != nil {
		return err
	}
	if err := storage.WriteEpochTOML(paths, mlsgitGroup.Epoch()); err != nil {
		return err
	}
	if err := storage.WriteMemberTOML(paths, memberID, initName, pubPEM, mlsgitGroup.Epoch(), "self"); err != nil {
		return err
	}

	// Save KeyPackage
	kp := mls.BuildKeyPackage([]byte(initName), mlsKeys)
	kpBytes, _ := json.Marshal(kp)
	kpB64 := crypto.B64Encode(kpBytes, false)
	if err := os.WriteFile(paths.MemberKeypackage(memberID), []byte(kpB64), 0o644); err != nil {
		return err
	}

	// Save group state (committed)
	groupBytes, _ := mlsgitGroup.ToBytes()
	if err := storage.WriteGroupState(paths, groupBytes); err != nil {
		return err
	}

	// Save epoch key archive
	epochSecret := mlsgitGroup.ExportEpochSecret()
	archive := mls.NewWithSecret(mlsgitGroup.Epoch(), epochSecret)
	archiveData, err := archive.Encrypt(epochSecret)
	if err != nil {
		return err
	}
	if err := storage.WriteEpochKeys(paths, archiveData); err != nil {
		return err
	}

	// 6. Install clean/smudge filter into .git/config
	if err := installFilterConfig(root); err != nil {
		return fmt.Errorf("install filter: %w", err)
	}

	// 7. Create .gitattributes at repo root
	if err := os.WriteFile(paths.RootGitattributes(), []byte(
		"* filter=mlsgit diff=mlsgit\n"+
			".gitattributes filter= diff=\n"+
			".gitignore filter= diff=\n",
	), 0o644); err != nil {
		return err
	}

	// 8. Create .mlsgit/.gitattributes to exclude from encryption
	if err := os.WriteFile(paths.MLSGitGitattributes(), []byte("* -filter\n"), 0o644); err != nil {
		return err
	}

	// 9. Update .gitignore
	gitignorePath := paths.Gitignore()
	gitignore := ""
	if data, err := os.ReadFile(gitignorePath); err == nil {
		gitignore = string(data)
	}
	var linesToAdd []string
	for _, pattern := range []string{".git/mlsgit/", "*.plain", "*.ct"} {
		if !strings.Contains(gitignore, pattern) {
			linesToAdd = append(linesToAdd, pattern)
		}
	}
	if len(linesToAdd) > 0 {
		if gitignore != "" && !strings.HasSuffix(gitignore, "\n") {
			gitignore += "\n"
		}
		gitignore += strings.Join(linesToAdd, "\n") + "\n"
		if err := os.WriteFile(gitignorePath, []byte(gitignore), 0o644); err != nil {
			return err
		}
	}

	fp, _ := crypto.PublicKeyFingerprint(signingPub)
	fmt.Printf("MLSGit initialized for '%s' (member ID: %s)\n", initName, memberID)
	fmt.Printf("Epoch: %d\n", mlsgitGroup.Epoch())
	fmt.Printf("Public key fingerprint: %s\n", fp)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  git add . && git commit -m 'init mlsgit'")

	return nil
}
