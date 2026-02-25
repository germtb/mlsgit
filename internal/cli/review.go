package cli

import (
	"fmt"
	"time"

	"github.com/germtb/mlsgit/internal/crypto"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "List pending join requests",
	RunE:  runReview,
}

func init() {
	rootCmd.AddCommand(reviewCmd)
}

func runReview(cmd *cobra.Command, args []string) error {
	_, paths, err := getRootAndPaths()
	if err != nil {
		return err
	}

	requests, err := storage.ListPendingRequests(paths)
	if err != nil {
		return err
	}

	if len(requests) == 0 {
		fmt.Println("No pending requests.")
		return nil
	}

	fmt.Printf("Pending join requests (%d):\n\n", len(requests))
	for _, reqPath := range requests {
		info, err := storage.ReadPendingRequest(reqPath)
		if err != nil {
			continue
		}

		tsStr := "unknown"
		if info.Timestamp > 0 {
			tsStr = time.Unix(info.Timestamp, 0).Format("2006-01-02 15:04")
		}

		fmt.Printf("  ID:   %s\n", info.MemberID)
		fmt.Printf("  Name: %s\n", info.Name)
		fmt.Printf("  Date: %s\n", tsStr)

		if info.PublicKey != "" {
			pub, err := crypto.LoadPublicKey(info.PublicKey)
			if err == nil {
				fp, _ := crypto.PublicKeyFingerprint(pub)
				fmt.Printf("  Key:  %s\n", fp)
			} else {
				fmt.Println("  Key:  (could not parse)")
			}
		}
		fmt.Println()
	}

	fmt.Println("Run 'mlsgit add <member-id>' to approve a request.")
	return nil
}
