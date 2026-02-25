// Package cli implements the mlsgit command-line interface using Cobra.
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/germtb/mlsgit/internal/config"
	"github.com/germtb/mlsgit/internal/filter"
	"github.com/germtb/mlsgit/internal/storage"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "mlsgit",
	Short: "End-to-end encrypted git via MLS + delta encryption",
}

// filterCmd is the hidden filter subcommand.
var filterCmd = &cobra.Command{
	Use:    "filter",
	Short:  "Git clean/smudge filter",
	Hidden: true,
}

var filterCleanCmd = &cobra.Command{
	Use:   "clean [filepath]",
	Short: "Clean filter (encrypt)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}

		root, err := config.FindGitRoot("")
		if err != nil {
			// Pass through if not in a git repo
			os.Stdout.Write(stdinData)
			return nil
		}
		paths := storage.MLSGitPaths{Root: root}

		result, err := filter.Clean(filePath, stdinData, paths)
		if err != nil {
			return err
		}
		os.Stdout.Write(result)
		return nil
	},
}

var filterSmudgeCmd = &cobra.Command{
	Use:   "smudge [filepath]",
	Short: "Smudge filter (decrypt)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		filePath := args[0]
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}

		root, err := config.FindGitRoot("")
		if err != nil {
			os.Stdout.Write(stdinData)
			return nil
		}
		paths := storage.MLSGitPaths{Root: root}

		result, err := filter.Smudge(filePath, stdinData, paths)
		if err != nil {
			return err
		}
		os.Stdout.Write(result)
		return nil
	},
}

func init() {
	filterCmd.AddCommand(filterCleanCmd, filterSmudgeCmd)
	rootCmd.AddCommand(filterCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
