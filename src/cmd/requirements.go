package cmd

import (
	"github.com/evilsocket/opensnitch/daemon/core"
	"github.com/spf13/cobra"
)

var requirementsCmd = &cobra.Command{
	Use:   "check-requirements",
	Short: "Check system requirements",
	Long:  `Check system requirements for incompatibilities.`,
	Run: func(cmd *cobra.Command, args []string) {
		core.CheckSysRequirements()
	},
	Version: "0.0.1-beta",
}
