## gotgt [![Build Status](https://travis-ci.org/gostor/gotgt.svg)](https://travis-ci.org/gostor/gotgt)

Simple Golang SCSI Target framework, this includes two binaries, one is `citadm` which is command line to config and control, the other is `citd` which is a target daemon.

## Build

```
$ mkdir -p $GOPATH/src/github.com/gostor/
$ cd $GOPATH/src/github.com/gostor/
$ git clone https://github.com/gostor/gotgt gotgt
$ cd gotgt
$ ./autogen.sh
$ ./configure
$ make
```

## How to use

Currenty, there is lack of commands to operate the target and LU, however you can init the target/LU with config file in `~/.gotgt/config.json`, such as:

```
{
  "storages":[
    {
      "deviceID":1000,
      "path":"file:/var/tmp/disk.img",
      "online":true
    }
  ],
  "iscsiportals":[
    {
      "id":0,
      "portal":"127.0.0.1:3260"
    }
  ],
  "iscsitargets":{
    "iqn.2016-09.com.gotgt.gostor:02:example-tgt-0":{
      "tpgts":{
        "1":[0]
      },
      "luns":{
        "0":1000
      }
    }
  }
}

```

> Note: make sure file `/var/tmp/disk.img` is existed, you can use `dd` to create it.

## Test

You can test this with [open-iscsi](http://www.open-iscsi.com/) or [libiscsi](https://github.com/gostor/libiscsi).

## Roadmap
* Auth (p3)
* Login Process (p2)
* ACL (Access control) (p3)
* SCSI Task Management (p3)
* iSCSI Task Management (p3)
* SCSI Command Queue (p2)
* More SCSI commands
	* SPC3/SAM2
	* Page83(Inquiry) (orzhang, p1)
	* Page0 (Inquiry) (orzhang, p1)
	* Define Device UUID
	* More SCSI flags (carmark, p1)
	* Read8,16 (carmark, p1)
	* Verify (carmark, p1)
	* Support `Target Group` and `Target Port` (p3)
* Refactor (carmark, p1)
* Command Line (carmark, p1)
* More Backstore Plugins(such as `ceph` and `raw device`) (orzhang, p1)
* Redirect iSCSI Target (orzhang, p2)
* Homepage (p3)
* More test cases (p2)
* Docker image (p3)

## Contributing

Want to help build gotgt? Check out our [contributing documentation](./CONTRIBUTING.md).
