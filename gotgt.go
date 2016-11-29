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

// SCSI target command line
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/docker/go-connections/sockets"
	"github.com/gostor/gotgt/cmd"
	"github.com/gostor/gotgt/pkg/api/client"
	"github.com/gostor/gotgt/pkg/version"
)

func main() {

	host := "tcp://127.0.0.1:23457"
	httpClient, err := newHTTPClient(host)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	cli, err := client.NewClient(host, version.Version, httpClient, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	if err := cmd.NewCommand(cli).Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func newHTTPClient(host string) (*http.Client, error) {
	tr := &http.Transport{
		TLSClientConfig: nil,
	}
	proto, addr, _, err := client.ParseHost(host)
	if err != nil {
		return nil, err
	}

	sockets.ConfigureTransport(tr, proto, addr)

	return &http.Client{
		Transport: tr,
	}, nil
}
