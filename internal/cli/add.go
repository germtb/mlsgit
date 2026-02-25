package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/mls"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{
	Use:   "add [member-id]",
	Short: "Approve a pending join request and add the member to the group",
	Args:  cobra.ExactArgs(1),
	RunE:  runAdd,
}

func init() {
	rootCmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	memberID := args[0]
	_, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	// 1. Read pending request
	reqPath := paths.PendingRequest(memberID)
	if _, err := os.Stat(reqPath); os.IsNotExist(err) {
		return fmt.Errorf("no pending request for member '%s'", memberID)
	}

	info, err := storage.ReadPendingRequest(reqPath)
	if err != nil {
		return err
	}
	name := info.Name
	pubPEM := info.PublicKey
	kpB64 := info.Keypackage

	if kpB64 == "" {
		return fmt.Errorf("request is missing KeyPackage data")
	}

	// 2. Deserialize KeyPackage
	kpBytes, err := crypto.B64Decode(kpB64, false)
	if err != nil {
		return fmt.Errorf("decode keypackage: %w", err)
	}
	var keyPackage mls.KeyPackageData
	if err := json.Unmarshal(kpBytes, &keyPackage); err != nil {
		return fmt.Errorf("unmarshal keypackage: %w", err)
	}

	// 3. Load MLS group and epoch archive
	mlsgitGroup, err := loadMLSGitGroup(paths)
	if err != nil {
		return err
	}
	oldEpoch := mlsgitGroup.Epoch()
	archive, err := loadEpochArchive(paths, mlsgitGroup)
	if err != nil {
		return err
	}

	// 4. Add member to MLS group (advances epoch)
	_, welcomeBytes, err := mlsgitGroup.AddMember(keyPackage)
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	newEpoch := mlsgitGroup.Epoch()

	fmt.Printf("MLS epoch advanced: %d -> %d\n", oldEpoch, newEpoch)

	// 5. Write Welcome message
	if err := storage.WriteWelcome(paths, memberID, welcomeBytes); err != nil {
		return err
	}

	// 6. Move request to members/
	myID, _, _ := storage.ReadIdentity(paths)
	if err := storage.WriteMemberTOML(paths, memberID, name, pubPEM, newEpoch, myID); err != nil {
		return err
	}

	// Save KeyPackage
	os.WriteFile(paths.MemberKeypackage(memberID), []byte(kpB64), 0o644)

	// Delete pending request
	os.Remove(reqPath)

	// 7. Persist all state
	if err := saveGroupAndArchive(paths, mlsgitGroup, archive); err != nil {
		return err
	}

	// 8. Invalidate filter cache
	cache := storage.NewFilterCache(paths)
	cache.InvalidateAll()

	fmt.Printf("Member '%s' (%s) added to the group.\n", name, memberID)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  git add . && git commit -m 'add member: %s'\n", name)
	fmt.Println("  Then push so the new member can pull and join.")

	return nil
}
