package cmd

import (
	"fmt"
	"strings"

	"github.com/gostor/gotgt/pkg/api/client"
	"github.com/spf13/cobra"
)

func NewCommand(cli *client.Client) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "citadm",
		Short: "Gotgt is a very fast and stable SCSI target framework",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
		},
	}
	cmd.AddCommand(
		newCreateCommand(cli),
		newRemoveCommand(cli),
		newListCommand(cli),
		newVersionCommand(cli),
	)
	return cmd
}

// NoArgs validate args and returns an error if there are any args
func NoArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}

	if cmd.HasSubCommands() {
		return fmt.Errorf("\n" + strings.TrimRight(cmd.UsageString(), "\n"))
	}

	return fmt.Errorf(
		"\"%s\" accepts no argument(s).\n",
		cmd.CommandPath(),
	)
}
