package client

import (
	"encoding/json"
	"net/url"

	"github.com/gostor/gotgt/pkg/api"
	"golang.org/x/net/context"
)

// LuList lists LUs for a target in the SCSI Target.
func (cli *Client) LuList(ctx context.Context, options api.LuListOptions) ([]api.LuInfo, error) {
	var lus []api.LuInfo
	query := url.Values{}
	if options.TargetName != "" {
		query.Set("target", options.TargetName)
	}
	resp, err := cli.get(ctx, "/lu/list", query, nil)
	if err != nil {
		return lus, err
	}
	err = json.NewDecoder(resp.body).Decode(&lus)
	ensureReaderClosed(resp)
	return lus, err
}
