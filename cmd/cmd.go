/*
Copyright 2016 The GoStor Authors All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"strings"

	"github.com/gostor/gotgt/pkg/api/client"
	"github.com/spf13/cobra"
)

func NewCommand(cli *client.Client) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "gotgt",
		Short: "Gotgt is a very fast and stable SCSI target framework",
		Long:  ``,
		Run: func(cmd *cobra.Command, args []string) {
			// Do Stuff Here
		},
	}
	cmd.AddCommand(
		newDaemonCommand(cli),
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
