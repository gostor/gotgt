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

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/api/client"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

func newCreateCommand(cli *client.Client) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "create",
		Short: "Create a new object",
		Long:  `All software has versions. This is Gotgt 's`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(cmd.UsageString())
		},
	}
	cmd.AddCommand(
		newCreateTargetCmd(cli),
		newCreateLuCmd(cli),
	)
	return cmd
}

func newCreateTargetCmd(cli *client.Client) *cobra.Command {
	opts := api.TargetCreateRequest{}
	var cmd = &cobra.Command{
		Use:   "target",
		Short: "Create a new target into gotgt",
		Long:  `All software has versions. This is Gotgt 's`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf(
					"\"%s\" accepts no argument(s).\n",
					cmd.CommandPath(),
				)
			}
			return createTarget(cli, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.Name, "name", "", "Specify target name")

	return cmd

}

func newCreateLuCmd(cli *client.Client) *cobra.Command {
	opts := api.LuCreateRequest{}
	var cmd = &cobra.Command{
		Use:   "lu",
		Short: "Create a new LU into gotgt",
		Long:  `Create a new Logical Unit and map it to a target`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := NoArgs(cmd, args); err != nil {
				return err
			}
			return createLu(cli, opts)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&opts.TargetName, "target", "", "Specify target name")
	flags.Uint64Var(&opts.LUN, "lun", 0, "Specify LUN number")
	flags.Uint64Var(&opts.DeviceID, "device-id", 0, "Specify device ID")
	flags.StringVar(&opts.Path, "path", "", "Specify backing store path (e.g., file:/tmp/disk.img)")
	flags.UintVar(&opts.BlockShift, "block-shift", 9, "Specify block shift (default 9 = 512 bytes)")
	return cmd
}

func createTarget(cli *client.Client, opts api.TargetCreateRequest) error {
	tgt, err := cli.TargetCreate(context.Background(), opts)
	if err != nil {
		return err
	}
	if tgt == nil {
		return fmt.Errorf("target creation returned nil")
	}
	fmt.Printf("Target %s successfully created\n", tgt.Name)
	return nil
}

func createLu(cli *client.Client, opts api.LuCreateRequest) error {
	if opts.TargetName == "" {
		return fmt.Errorf("target name is required (--target)")
	}
	if opts.Path == "" {
		return fmt.Errorf("backing store path is required (--path)")
	}
	err := cli.LuCreate(context.Background(), opts)
	if err != nil {
		return err
	}
	fmt.Printf("LU %d successfully created on target %s\n", opts.LUN, opts.TargetName)
	return nil
}
