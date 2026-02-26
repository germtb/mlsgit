package cli

import (
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Compute a Merkle root over all encrypted files and sign it",
	RunE:  runSeal,
}

func init() {
	rootCmd.AddCommand(sealCmd)
}

func runSeal(cmd *cobra.Command, args []string) error {
	root, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	if _, err := os.Stat(paths.MLSState()); os.IsNotExist(err) {
		return fmt.Errorf("no local MLS state. Run 'mlsgit join' first")
	}

	memberID, _, err := storage.ReadIdentity(paths)
	if err != nil {
		return err
	}

	pemData, err := os.ReadFile(paths.PrivateKey())
	if err != nil {
		return err
	}
	signingPriv, err := crypto.LoadPrivateKey(string(pemData))
	if err != nil {
		return err
	}

	mlsgitGroup, err := loadMLSGitGroup(paths)
	if err != nil {
		return err
	}
	epoch := mlsgitGroup.Epoch()

	fileHashes, err := collectFileHashes(root)
	if err != nil {
		return err
	}
	rootHash := crypto.ComputeMerkleRoot(fileHashes)
	if rootHash == "" {
		return fmt.Errorf("no encrypted files found")
	}

	sig := crypto.SignMerkleRoot(rootHash, signingPriv)

	manifest := crypto.MerkleManifest{
		RootHash:  rootHash,
		Signature: sig,
		Author:    memberID,
		Epoch:     epoch,
		FileCount: len(fileHashes),
	}
	if err := storage.WriteMerkleManifest(paths, manifest); err != nil {
		return err
	}

	fmt.Printf("Merkle root: %s...\n", rootHash[:16])
	fmt.Printf("Signed by: %s\n", memberID)
	fmt.Printf("Files: %d\n", len(fileHashes))
	fmt.Println("Manifest written to .mlsgit/merkle.toml")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  git add .mlsgit/merkle.toml && git commit -m 'seal repository'")

	return nil
}
