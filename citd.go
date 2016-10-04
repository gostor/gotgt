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

// SCSI target daemon
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strings"
	"syscall"

	"github.com/golang/glog"
	"github.com/gostor/gotgt/pkg/apiserver"
	"github.com/gostor/gotgt/pkg/config"
	"github.com/gostor/gotgt/pkg/port"
	_ "github.com/gostor/gotgt/pkg/port/iscsit"
	"github.com/gostor/gotgt/pkg/scsi"
	_ "github.com/gostor/gotgt/pkg/scsi/backingstore"
)

func main() {

	flHelp := flag.Bool("help", false, "Print help message for Hyperd daemon")
	flHost := flag.String("host", "tcp://127.0.0.1:23457", "Host for SCSI target daemon")
	flDriver := flag.String("driver", "iscsi", "SCSI low level driver")
	flag.Usage = func() { *flHelp = true }
	flag.Parse()
	flag.Set("logtostderr", "true")
	if *flHelp == true {
		fmt.Println(`Usage:
  xxxd [OPTIONS]

Application Options:
  --host=""                 Host for SCSI target daemon
  --driver=iscsi            SCSI low level driver

Help Options:
  -h, --help                Show this help message
`)
		return
	}

	config, err := config.Load(config.ConfigDir())
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}

	err = scsi.InitSCSILUMap(config)
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}

	service := scsi.NewSCSITargetService()
	t, err := port.NewTargetService(*flDriver, service)
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}
	iscsit := reflect.ValueOf(t)
	// create a new target
	for tgtname, tgt := range config.Targets {
		create := iscsit.MethodByName("NewTarget")
		create.Call([]reflect.Value{reflect.ValueOf(tgtname),
			reflect.ValueOf(tgt.Portals)})
	}

	runtime.GOMAXPROCS(runtime.NumCPU())
	// run a service
	run := iscsit.MethodByName("Run")
	go run.Call([]reflect.Value{})

	serverConfig := &apiserver.Config{
		Addrs: []apiserver.Addr{},
	}
	//hosts := []string{"unix:///var/run/gotgt.sock"}
	hosts := []string{}
	if *flHost != "" {
		hosts = append(hosts, *flHost)
	}
	for _, protoAddr := range hosts {
		protoAddrParts := strings.SplitN(protoAddr, "://", 2)
		if len(protoAddrParts) != 2 {
			glog.Errorf("bad format %s, expected PROTO://ADDR", protoAddr)
			return
		}
		serverConfig.Addrs = append(serverConfig.Addrs, apiserver.Addr{Proto: protoAddrParts[0], Addr: protoAddrParts[1]})
	}

	s, err := apiserver.New(serverConfig)
	if err != nil {
		glog.Errorf(err.Error())
		return
	}
	s.InitRouters()
	// The serve API routine never exits unless an error occurs
	// We need to start it as a goroutine and wait on it so
	// daemon doesn't exit
	serveAPIWait := make(chan error)
	go s.Wait(serveAPIWait)

	stopAll := make(chan os.Signal, 1)
	signal.Notify(stopAll, syscall.SIGINT, syscall.SIGTERM)

	// Daemon is fully initialized and handling API traffic
	// Wait for serve API job to complete
	select {
	case errAPI := <-serveAPIWait:
		// If we have an error here it is unique to API (as daemonErr would have
		// exited the daemon process above)
		if errAPI != nil {
			glog.Warningf("Shutting down due to ServeAPI error: %v", errAPI)
		}
	case <-stopAll:
		break
	}
	s.Close()
}
