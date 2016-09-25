## gotgt [![Build Status](https://travis-ci.org/gostor/gotgt.svg)](https://travis-ci.org/gostor/gotgt)

Simple Golang SCSI Target framework, this includes two binaries, one is `citadm` which is command line to config and control, the other is `citd` which is a target daemon.

## Build

```
$ mkdir $GOPATH/gotstor/
$ cd $GOPATH/gostor/
$ git clone https://github.com/gostor/gotgt gotgt
$ cd gotgt
$ ./autogen.sh
$ ./configure
$ make
```

## Test

You can test this with [libiscsi](https://github.com/gostor/libiscsi).

### build the test tool of libiscsi

```
$ git clone https://github.com/gostor/libiscsi
$ cd libiscsi
$ ./autogen.sh
$ ./configure
$ make
```

### start the gotgt daemon

```
$ ./citd
```

### begin the test

```
$ ./iscsi-test-cu -v iscsi://127.0.0.1:3260/iqn.test.haha/0
```
