package cli

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var joinName string

var joinCmd = &cobra.Command{
	Use:   "join",
	Short: "Join an mlsgit-enabled repository",
	Long: `Run once to create a join request (then commit and open a PR).
Run again after your request is approved to decrypt the repo.`,
	RunE: runJoin,
}

func init() {
	joinCmd.Flags().StringVar(&joinName, "name", "", "Your display name for the group")
	rootCmd.AddCommand(joinCmd)
}

func runJoin(cmd *cobra.Command, args []string) error {
	root, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	if _, err := os.Stat(paths.MLSGitDir()); os.IsNotExist(err) {
		return fmt.Errorf(".mlsgit/ not found. This repo is not mlsgit-enabled")
	}

	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	installFilterConfig(root)

	// Already joined
	if _, err := os.Stat(paths.MLSState()); err == nil {
		fmt.Println("You are already a member of this group.")
		return nil
	}

	// Identity exists -> check for Welcome
	if _, err := os.Stat(paths.IdentityTOML()); err == nil {
		return processWelcome(paths, root)
	}

	// Fresh join: create request
	if joinName == "" {
		fmt.Print("Your name: ")
		fmt.Scanln(&joinName)
	}

	// 1. Generate Ed25519 key pair
	signingPriv, signingPub, err := crypto.GenerateKeypair()
	if err != nil {
		return err
	}
	privPEM, err := crypto.PrivateKeyToPEM(signingPriv)
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

	// 2. Generate MLS keys
	mlsKeys, err := mls.GenerateMLSKeys()
	if err != nil {
		return err
	}
	memberID := generateMemberID(joinName)

	kp := mls.BuildKeyPackage([]byte(joinName), mlsKeys)
	kpBytes, _ := json.Marshal(kp)
	kpB64 := crypto.B64Encode(kpBytes, false)

	// Save identity and keys locally
	storage.WriteIdentity(paths, memberID, joinName)
	os.WriteFile(paths.LocalDir()+"/init_priv.bin", mlsKeys.InitPriv, 0o600)
	os.WriteFile(paths.LocalDir()+"/sig_priv.bin", mlsKeys.SigPriv.Seed(), 0o600)

	// 3. Write pending request
	if err := storage.WritePendingRequest(paths, memberID, joinName, pubPEM, kpB64); err != nil {
		return err
	}

	// 4. Create welcome branch
	branchName := "welcome/" + memberID
	branchCmd := exec.Command("git", "checkout", "-b", branchName)
	branchCmd.Dir = root
	if out, err := branchCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create welcome branch: %w\n%s", err, out)
	}

	fp, _ := crypto.PublicKeyFingerprint(signingPub)
	fmt.Printf("Join request created for '%s' (member ID: %s)\n", joinName, memberID)
	fmt.Printf("Public key fingerprint: %s\n", fp)
	fmt.Printf("Branch: %s\n", branchName)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  git add .mlsgit/pending/ && git commit -m 'request to join: %s'\n", joinName)
	fmt.Printf("  git push -u origin %s\n", branchName)
	fmt.Println()
	fmt.Println("After your request is approved and you pull, run 'mlsgit join' again.")

	return nil
}

func processWelcome(paths storage.MLSGitPaths, root string) error {
	memberID, _, err := storage.ReadIdentity(paths)
	if err != nil {
		return err
	}

	welcomePath := paths.WelcomeFile(memberID)
	if _, err := os.Stat(welcomePath); os.IsNotExist(err) {
		fmt.Println("Waiting for approval. No Welcome message found yet.")
		fmt.Println("Ask an existing member to run 'mlsgit add <your-id>' and push.")
		return nil
	}

	// Load Welcome
	welcomeBytes, err := storage.ReadWelcome(paths, memberID)
	if err != nil {
		return fmt.Errorf("read welcome: %w", err)
	}

	// Load keys saved during initial join
	initPriv, err := os.ReadFile(paths.LocalDir() + "/init_priv.bin")
	if err != nil {
		return fmt.Errorf("read init_priv: %w (run 'mlsgit join' to create a request first)", err)
	}
	sigPrivSeed, err := os.ReadFile(paths.LocalDir() + "/sig_priv.bin")
	if err != nil {
		return fmt.Errorf("read sig_priv: %w", err)
	}

	// Reconstruct MLS keys
	sigPriv := ed25519.NewKeyFromSeed(sigPrivSeed)
	sigPub := sigPriv.Public().(ed25519.PublicKey)
	keys := mls.MLSKeys{
		SigPriv:  sigPriv,
		SigPub:   sigPub,
		InitPriv: initPriv,
		InitPub:  nil,
	}

	mlsgitGroup, err := mls.JoinFromWelcome(welcomeBytes, keys)
	if err != nil {
		return fmt.Errorf("join from welcome: %w", err)
	}

	// Save MLS state
	if err := saveMLSState(paths, mlsgitGroup); err != nil {
		return err
	}

	// Load epoch key archive
	epochSecret := mlsgitGroup.ExportEpochSecret()
	archiveData, err := storage.ReadEpochKeys(paths)
	if err == nil {
		archive, err := mls.DecryptArchive(archiveData, epochSecret)
		if err != nil {
			fmt.Printf("Warning: could not load epoch key archive: %v\n", err)
			fmt.Println("You may not be able to decrypt historical files.")
		} else {
			fmt.Printf("Loaded epoch key archive with %d epoch(s).\n", len(archive.Epochs()))
		}
	}

	fmt.Println("Successfully joined the group!")
	fmt.Printf("Epoch: %d\n", mlsgitGroup.Epoch())
	fmt.Printf("Members: %d\n", mlsgitGroup.MemberCount())

	// Delete the Welcome file (it contains the encrypted epoch secret)
	os.Remove(welcomePath)
	os.Remove(paths.WelcomeDir()) // remove empty welcome dir

	// Determine the main branch for merge
	mainBranch := getMainBranch(root)
	currentBranch := getCurrentBranch(root)
	welcomeBranch := "welcome/" + memberID

	// If we're on the welcome branch, merge to main
	if currentBranch == welcomeBranch {
		// Stage and commit the Welcome deletion on the welcome branch
		stageCmd := exec.Command("git", "add", "-A")
		stageCmd.Dir = root
		stageCmd.CombinedOutput()

		commitCmd := exec.Command("git", "commit", "-m", "process welcome: "+memberID)
		commitCmd.Dir = root
		commitCmd.CombinedOutput()

		// Merge main into the welcome branch (usually a no-op since welcome is based on main)
		mergeCmd := exec.Command("git", "merge", "--no-edit", mainBranch)
		mergeCmd.Dir = root
		mergeCmd.CombinedOutput()

		// Belt-and-suspenders: ensure welcome file is not in the index
		rmCmd := exec.Command("git", "rm", "--cached", "--ignore-unmatch", paths.WelcomeFile(memberID))
		rmCmd.Dir = root
		rmCmd.CombinedOutput()

		// If there are staged changes after rm, commit them
		commitRmCmd := exec.Command("git", "diff", "--cached", "--quiet")
		commitRmCmd.Dir = root
		if err := commitRmCmd.Run(); err != nil {
			amendCmd := exec.Command("git", "commit", "-m", "add member: "+memberID)
			amendCmd.Dir = root
			amendCmd.CombinedOutput()
		}

		// Move main branch to current commit without checkout (avoids smudge filter)
		branchCmd := exec.Command("git", "branch", "-f", mainBranch, "HEAD")
		branchCmd.Dir = root
		if out, err := branchCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("move %s to HEAD: %w\n%s", mainBranch, err, out)
		}

		// Switch to main (same commit, so no files change, no smudge filter runs)
		checkoutCmd := exec.Command("git", "checkout", mainBranch)
		checkoutCmd.Dir = root
		if out, err := checkoutCmd.CombinedOutput(); err != nil {
			return fmt.Errorf("checkout %s: %w\n%s", mainBranch, err, out)
		}
	}

	// Force re-checkout to decrypt all files
	fmt.Println("Decrypting working tree...")
	lsCmd := exec.Command("git", "ls-files", "-z")
	lsCmd.Dir = root
	lsOut, _ := lsCmd.Output()
	for _, f := range strings.Split(string(lsOut), "\x00") {
		if f != "" && !strings.HasPrefix(f, ".mlsgit/") {
			fp := root + "/" + f
			os.Remove(fp)
		}
	}
	checkoutCmd := exec.Command("git", "checkout", "--", ".")
	checkoutCmd.Dir = root
	checkoutCmd.Run()
	fmt.Println("Done. All files decrypted.")

	return nil
}
