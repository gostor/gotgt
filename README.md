## gotgt [![Build Status](https://travis-ci.org/gostor/gotgt.svg)](https://travis-ci.org/gostor/gotgt)

Cloud Integrated SCSI Target framework, this includes two binaries, one is `citadm` which is command line to config and control, the other is `citd` which is a target daemon.

```
# citadm --help
Linux SCSI Target administration utility, version 0.1
Usage: ./citadm [OPTIONS]

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

```
