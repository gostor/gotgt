/*
Copyright 2015 The GoStor Authors All rights reserved.

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
	"net"
	"os"
	"reflect"

	"github.com/golang/glog"
	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/scsi"
)

func main() {
	l, err := net.Listen("tcp", ":3260")
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}
	defer l.Close()
	t, err := scsi.NewTarget(0, "iscsi", "test-iscsi-target")
	if err != nil {
		glog.Error(err)
		os.Exit(1)
	}
	conns := make(map[string]net.Conn)

	for {
		glog.Info("Listening ...")
		conn, err := l.Accept()
		checkError(err, "Accept")
		glog.Info("Accepting ...")
		conns[conn.RemoteAddr().String()] = conn
		// start a new thread to do with this command
		go Handler(conn, t)
	}
}

func checkError(err error, info string) (res bool) {

	if err != nil {
		glog.Error(info + "  " + err.Error())
		return false
	}
	return true
}

func Handler(conn net.Conn, tgt *api.SCSITarget) {

	glog.Infof("connection is connected from %s...\n", conn.RemoteAddr().String())

	buf := make([]byte, 1024)
	for {
		lenght, err := conn.Read(buf)
		if checkError(err, "Connection") == false {
			conn.Close()
			break
		}
		if lenght > 0 {
			buf[lenght] = 0
		}
		v := reflect.ValueOf(tgt.SCSITargetDriver)
		iscsit := v.MethodByName("ProcessCommand")
		in := make([]reflect.Value, 1)
		in[0] = reflect.ValueOf(buf[0:lenght])
		res := iscsit.Call(in)[0]
		b := res.Bytes()
		glog.Infof("%s\n", string(b))
		conn.Write(b)
	}
}
