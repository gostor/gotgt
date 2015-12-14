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

// SCSI target command line
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gostor/gotgt/pkg/version"
)

type AdminMode int
type AdminOperation int

const (
	OP_NEW = iota
	OP_DELETE
	OP_SHOW
	OP_BIND
	OP_UNBIND
	OP_UPDATE
	OP_STATS
	OP_START
	OP_STOP
)

const (
	MODE_SYSTEM = iota
	MODE_TARGET
	MODE_DEVICE
	MODE_PORTAL
	MODE_LLD

	MODE_SESSION
	MODE_CONNECTION
	MODE_ACCOUNT
)

type AdminRequest struct {
	Mode        AdminMode
	Operation   AdminOperation
	LLD         string
	Length      uint32
	TID         int32
	SID         uint64
	Lun         uint64
	Cid         uint64
	host_no     uint32
	device_type uint32
	ac_dir      uint32
	pack        uint32
	force       uint32
}

func main() {
	// define options
	//var req AdminRequest
	flDebug := flag.Bool("debug", false, "Debug mode")
	flHelp := flag.Bool("help", false, "Help Message")
	flVersion := flag.Bool("version", false, "Version message")
	flLLD := flag.String("lld", "", "Low level device")
	flOperation := flag.String("op", "", "Operation")
	flMode := flag.String("mode", "", "")
	flTID := flag.String("tid", "", "")
	flSID := flag.String("sid", "", "")
	flCID := flag.String("cid", "", "")
	flLUN := flag.String("lun", "", "")
	flName := flag.String("name", "", "")
	flValue := flag.String("value", "", "")
	flBS := flag.String("backing-store", "", "")
	flTarget := flag.String("target", "", "")
	flInitiatorName := flag.String("initiator-name", "", "")
	flInitiatorAddress := flag.String("initiator-address", "", "")
	flUser := flag.String("user", "", "")
	flPassword := flag.String("password", "", "")
	flHost := flag.String("host", "", "")
	flForce := flag.Bool("force", false, "")
	flDeviceType := flag.String("devicetype", "", "")

	flag.Usage = func() { usage(0) }
	flag.Parse()
	if *flHelp {
		usage(0)
	}
	if *flVersion {
		showVersion()
	}

	_ = flDebug
	_ = flLLD
	_ = flOperation
	_ = flMode
	_ = flTID
	_ = flSID
	_ = flCID
	_ = flLUN
	_ = flName
	_ = flValue
	_ = flBS
	_ = flTarget
	_ = flInitiatorName
	_ = flInitiatorAddress
	_ = flUser
	_ = flPassword
	_ = flHost
	_ = flForce
	_ = flDeviceType
}

func usage(status int) {
	if status != 0 {
		fmt.Fprintf(os.Stderr, "Try `%s --help' for more information.\n", os.Args[0])
		os.Exit(status)
	}

	var helpMessage = `Linux SCSI Target administration utility, version %s
Usage: %s [OPTIONS]

Application Options: 
	--lld <driver> --mode target --op new --tid <id> --targetname <name>
		add a new target with <id> and <name>. <id> must not be zero.
	--lld <driver> --mode target --op delete [--force] --tid <id>
		delete the specific target with <id>.
		With force option, the specific target is deleted
		even if there is an activity.
	--lld <driver> --mode target --op show
		show all the targets.
	--lld <driver> --mode target --op show --tid <id>
		show the specific target's parameters.
	--lld <driver> --mode target --op update --tid <id> --name <param> --value <value>
		change the target parameters of the target with <id>.
	--lld <driver> --mode target --op bind --tid <id> --initiator-address <address>
	--lld <driver> --mode target --op bind --tid <id> --initiator-name <name>
		enable the target to accept the specific initiators.
	--lld <driver> --mode target --op unbind --tid <id> --initiator-address <address>
	--lld <driver> --mode target --op unbind --tid <id> --initiator-name <name>
		disable the specific permitted initiators.
	--lld <driver> --mode logicalunit --op new --tid <id> --lun <lun>
	--backing-store <path> --bstype <type> --bsopts <bs options> --bsoflags <options>
		add a new logical unit with <lun> to the specific
		target with <id>. The logical unit is offered
		to the initiators. <path> must be block device files
		(including LVM and RAID devices) or regular files.
		bstype option is optional.
		bsopts are specific to the bstype.
		bsoflags supported options are sync and direct
		(sync:direct for both).
	--lld <driver> --mode logicalunit --op delete --tid <id> --lun <lun>
		delete the specific logical unit with <lun> that
		the target with <id> has.
	--lld <driver> --mode account --op new --user <name> --password <pass>
		add a new account with <name> and <pass>.
	--lld <driver> --mode account --op delete --user <name>
		delete the specific account having <name>.
	--lld <driver> --mode account --op bind --tid <id> --user <name> [--outgoing]
		add the specific account having <name> to
		the specific target with <id>.
		<user> could be <IncomingUser> or <OutgoingUser>.
		If you use --outgoing option, the account will
		be added as an outgoing account.
	--lld <driver> --mode account --op unbind --tid <id> --user <name> [--outgoing]
		delete the specific account having <name> from specific
		target. The --outgoing option must be added if you
		delete an outgoing account.
	--lld <driver> --mode lld --op start
		Start the specified lld without restarting the tgtd process.
	--control-port <port> use control port <port>

Help Options:
	--help
		display this help and exit

Report bugs via <https://github.com/gostor/gotgt/issues>.

`

	fmt.Printf(helpMessage, version.VERSION, os.Args[0])
	os.Exit(0)
}

func showVersion() {
	fmt.Printf("%s\n", version.VERSION)
	os.Exit(0)
}
