package client

import (
	"github.com/gostor/gotgt/pkg/api"
	"golang.org/x/net/context"
)

// LuRemove removes a LU from a target in the SCSI Target.
func (cli *Client) LuRemove(ctx context.Context, options api.LuRemoveOptions) error {
	resp, err := cli.post(ctx, "/lu/delete", nil, options, nil)
	ensureReaderClosed(resp)
	return err
}
