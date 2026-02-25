package cli

import (
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the repository Merkle root against the manifest",
	RunE:  runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	root, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	if _, err := os.Stat(paths.MerkleTOML()); os.IsNotExist(err) {
		return fmt.Errorf("no merkle.toml found. Run 'mlsgit seal' first")
	}

	manifest, err := storage.ReadMerkleManifest(paths)
	if err != nil {
		return err
	}

	// Load the author's public key
	authorPath := paths.MemberTOML(manifest.Author)
	if _, err := os.Stat(authorPath); os.IsNotExist(err) {
		return fmt.Errorf("member TOML not found for author '%s'", manifest.Author)
	}

	memberInfo, err := storage.ReadMemberTOML(authorPath)
	if err != nil {
		return err
	}
	pubKey, err := crypto.LoadPublicKey(memberInfo.PublicKey)
	if err != nil {
		return err
	}

	fileHashes, err := collectFileHashes(root)
	if err != nil {
		return err
	}
	computedRoot := crypto.ComputeMerkleRoot(fileHashes)

	if computedRoot != manifest.RootHash {
		fmt.Println("FAILED: Merkle root mismatch.")
		fmt.Printf("  Expected: %s...\n", manifest.RootHash[:16])
		fmt.Printf("  Computed: %s...\n", computedRoot[:16])
		os.Exit(1)
	}

	if !crypto.VerifyMerkleRoot(manifest.RootHash, manifest.Signature, pubKey) {
		fmt.Println("FAILED: Signature verification failed.")
		os.Exit(1)
	}

	fmt.Println("OK: Repository integrity verified.")
	fmt.Printf("  Root:   %s...\n", manifest.RootHash[:16])
	fmt.Printf("  Author: %s\n", manifest.Author)
	fmt.Printf("  Epoch:  %d\n", manifest.Epoch)
	fmt.Printf("  Files:  %d\n", manifest.FileCount)

	return nil
}
