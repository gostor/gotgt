package client

import (
	"encoding/json"
	"net/url"

	"github.com/gostor/gotgt/pkg/api"
	"golang.org/x/net/context"
)

// TpgtList lists TPGTs for a target in the SCSI Target.
func (cli *Client) TpgtList(ctx context.Context, options api.TpgtListOptions) ([]api.TpgtInfo, error) {
	var tpgts []api.TpgtInfo
	query := url.Values{}
	if options.TargetName != "" {
		query.Set("target", options.TargetName)
	}
	resp, err := cli.get(ctx, "/target/tpgt/list", query, nil)
	if err != nil {
		return tpgts, err
	}
	err = json.NewDecoder(resp.body).Decode(&tpgts)
	ensureReaderClosed(resp)
	return tpgts, err
}
