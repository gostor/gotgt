## gotgt [![Build Status](https://travis-ci.org/gostor/gotgt.svg)](https://travis-ci.org/gostor/gotgt)

gotgt is a simple SCSI Target framework implemented by golang, built for performance and density..

### What is SCSI?
Small Computer System Interface (SCSI) is a set of standards for physically connecting and transferring data between computers and peripheral devices. The SCSI standards define commands, protocols, electrical and optical interfaces. SCSI is most commonly used for hard disk drives and tape drives, but it can connect a wide range of other devices, including scanners and CD drives, although not all controllers can handle all devices.

### What is iSCSI?
The iSCSI is an acronym for Internet Small Computer Systems Interface, an Internet Protocol (IP)-based storage networking standard for linking data storage facilities. In a nutshell, it provides block-level access to storage devices over a TCP/IP network.



## Getting started
Currently, the gotgt is under heavy development, so there is no any release binaries so far, you have to build it from source.

There is a only on binary name `gotgt`, you can start a daemon via `gotgt daemon` and control it via `gotgt list/create/rm`.

### Build
You will need to make sure that you have Go installed on your system and the `gotgt` repository is cloned in your $GOPATH.

```
$ mkdir -p $GOPATH/src/github.com/gostor/
$ cd $GOPATH/src/github.com/gostor/
$ git clone https://github.com/gostor/gotgt gotgt
$ cd gotgt
$ ./autogen.sh
$ ./configure
$ make
```

### How to use

Now, there is lack of commands to operate the target and LU, however you can init the target/LU with config file in `~/.gotgt/config.json`, you may find a example at [here](./examples/config.json).
Please note, if you want use that exmaple, you have to make sure file `/var/tmp/disk.img` is existed.

### Test

You can test this with [open-iscsi](http://www.open-iscsi.com/) or [libiscsi](https://github.com/gostor/libiscsi).

## Performance

TBD

## Roadmap

The current roadmap and milestones for alpha and beta completion are in the github issues on this repository. Please refer to these issues for what is being worked on and completed for the various stages of development.

## Contributing

Want to help build gotgt? Check out our [contributing documentation](./CONTRIBUTING.md).
