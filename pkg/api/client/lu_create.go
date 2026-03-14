package client

import (
	"github.com/gostor/gotgt/pkg/api"
	"golang.org/x/net/context"
)

// LuCreate creates a LU in the SCSI Target.
func (cli *Client) LuCreate(ctx context.Context, options api.LuCreateRequest) error {
	resp, err := cli.post(ctx, "/lu/create", nil, options, nil)
	ensureReaderClosed(resp)
	return err
}
