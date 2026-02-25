package cli

import (
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove [member-id]",
	Short: "Remove a member from the group",
	Args:  cobra.ExactArgs(1),
	RunE:  runRemove,
}

func init() {
	rootCmd.AddCommand(removeCmd)
}

func runRemove(cmd *cobra.Command, args []string) error {
	memberID := args[0]
	_, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	// 1. Verify member exists
	memberPath := paths.MemberTOML(memberID)
	if _, err := os.Stat(memberPath); os.IsNotExist(err) {
		return fmt.Errorf("member '%s' not found", memberID)
	}

	info, err := storage.ReadMemberTOML(memberPath)
	if err != nil {
		return err
	}
	name := info.Name

	// 2. Load MLS group
	mlsgitGroup, err := loadMLSGitGroup(paths)
	if err != nil {
		return err
	}
	myID, _, _ := storage.ReadIdentity(paths)
	if memberID == myID {
		return fmt.Errorf("cannot remove yourself")
	}

	// 3. Find the member's leaf index
	memberIDs, _ := storage.ListMemberIDs(paths)
	leafIndex := -1
	for i, mid := range memberIDs {
		if mid == memberID {
			leafIndex = i
			break
		}
	}
	if leafIndex < 0 {
		return fmt.Errorf("member '%s' not found in members list", memberID)
	}

	oldEpoch := mlsgitGroup.Epoch()
	archive, err := loadEpochArchive(paths, mlsgitGroup)
	if err != nil {
		return err
	}

	// 4. Remove member from MLS group (advances epoch)
	_, err = mlsgitGroup.RemoveMember(leafIndex)
	if err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	newEpoch := mlsgitGroup.Epoch()

	fmt.Printf("MLS epoch advanced: %d -> %d\n", oldEpoch, newEpoch)

	// 5. Delete member files
	os.Remove(memberPath)
	kpPath := paths.MemberKeypackage(memberID)
	os.Remove(kpPath)
	welcomePath := paths.WelcomeFile(memberID)
	os.Remove(welcomePath)

	// 6. Persist all state
	if err := saveGroupAndArchive(paths, mlsgitGroup, archive); err != nil {
		return err
	}

	fmt.Printf("Member '%s' (%s) removed from the group.\n", name, memberID)
	fmt.Println("New files will be encrypted under the new epoch key.")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  git add . && git commit -m 'remove member: %s'\n", name)
	fmt.Println("  Then push.")

	return nil
}
