package main

import (
	"fmt"
	"os"

	"github.com/0xsequence/authcontrol"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "authcontrol",
	Short: "Access Keys CLI",
	Long:  `A command line interface for managing access keys.`,
}

var accessKeyCmd = &cobra.Command{
	Use:   "access-key",
	Short: "Manage access keys",
	Long:  `Generate and decode access key.`,
}

var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "Decode an access key",
	Long:  `Decode an access key to retrieve the project ID.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("access key is required")
		}
		accessKey := authcontrol.AccessKey(args[0])
		var (
			projectID uint64
			version   byte
			errs      []error
		)
		for _, e := range authcontrol.SupportedEncodings {
			id, err := e.Decode(accessKey)
			if err != nil {
				errs = append(errs, fmt.Errorf("decode v%d: %w", e.Version(), err))
				continue
			}
			projectID = id
			version = e.Version()
			break
		}

		if len(errs) == len(authcontrol.SupportedEncodings) {
			return fmt.Errorf("failed to decode access key: %v", errs)
		}
		fmt.Println("Version:  ", version)
		fmt.Println("Project:  ", projectID)
		fmt.Println("AccessKey:", accessKey)
		return nil
	},
}

func init() {
	accessKeyCmd.AddCommand(decodeCmd)
	rootCmd.AddCommand(accessKeyCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
