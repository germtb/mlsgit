package cli

import (
	"fmt"
	"os"

	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var lsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List members of the group",
	RunE:  runLs,
}

func init() {
	rootCmd.AddCommand(lsCmd)
}

func runLs(cmd *cobra.Command, args []string) error {
	_, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	memberIDs, err := storage.ListMemberIDs(paths)
	if err != nil || len(memberIDs) == 0 {
		fmt.Println("No members.")
		return nil
	}

	// Identify current user
	var ownID string
	if _, err := os.Stat(paths.IdentityTOML()); err == nil {
		ownID, _, _ = storage.ReadIdentity(paths)
	}

	fmt.Printf("Members (%d):\n\n", len(memberIDs))
	for _, mid := range memberIDs {
		info, err := storage.ReadMemberTOML(paths.MemberTOML(mid))
		if err != nil {
			continue
		}
		marker := ""
		if mid == ownID {
			marker = "  (you)"
		}
		fmt.Printf("  %s [%s] joined at epoch %d%s\n", info.Name, mid, info.JoinedEpoch, marker)
	}

	// Show pending requests count
	pendingReqs, _ := storage.ListPendingRequests(paths)
	if len(pendingReqs) > 0 {
		fmt.Printf("\n  + %d pending request(s) -- run 'mlsgit review' to see them.\n", len(pendingReqs))
	}

	return nil
}
