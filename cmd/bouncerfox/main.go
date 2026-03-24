package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "bf",
		Short:   "BouncerFox — AI agent config scanner",
		Version: version,
	}

	scanCmd := &cobra.Command{
		Use:   "scan [path]",
		Short: "Scan files for security and quality issues",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("scan not yet implemented")
			return nil
		},
	}

	rootCmd.AddCommand(scanCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}
