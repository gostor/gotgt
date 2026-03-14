## gotgt 

![Build Status](https://github.com/gostor/gotgt/actions/workflows/gotgt.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache%202-blue)
![Go Report Card](https://goreportcard.com/badge/github.com/gostor/gotgt)

The gotgt project is a simple SCSI Target framework implemented in golang built for performance and density.
Very briefly, this iSCSI/SCSI target Go implementation can be included/imported as a library to allow upper layer iSCSI clients to communicate to the actual SCSI devices. The target configuration is static with a json file for the time being. The core functionality of this target library provides the iSCSI/SCSI protocol services. A simple flat file based LUN target implementation is provided with plug-in interface. In the future, a formal plugin mechanism will be provided and supported to work with more sophisticated backend storage arrays.

### What is SCSI?
Small Computer System Interface (SCSI) is a set of standards for physically connecting and transferring data between computers and peripheral devices. The SCSI standards define commands, protocols, electrical and optical interfaces. SCSI is most commonly used for hard disk drives and tape drives, but it can connect a wide range of other devices, including scanners and CD drives, although not all controllers can handle all devices.

### What is iSCSI?
The iSCSI is an acronym for Internet Small Computer Systems Interface, an Internet Protocol (IP)-based storage networking standard for linking data storage facilities. In a nutshell, it provides block-level access to storage devices over a TCP/IP network.



## Getting started
Currently, the gotgt is under heavy development, so there is no any release binaries so far, you have to build it from source.

There is a only one binary name `gotgt`, you can start a daemon via `gotgt daemon` and control it via `gotgt list/create/rm`.

### Build
You will need to make sure that you have Go installed on your system and the automake package is installed also. The `gotgt` repository should be cloned in your $GOPATH.

```
$ git clone https://github.com/gostor/gotgt
$ cd gotgt
$ make
```

### How to use

Now, there is lack of commands to operate the target and LU, however you can init the target/LU with config file in `~/.gotgt/config.json`, you may find a example at [here](./examples/config.json).
Please note, if you want use that example, you have to make sure file `/var/tmp/disk.img` exists.

### A quick overview of the source code

The source code repository is right now organized into two main portions, i.e., the cmd and the pkg directories.

The cmd directory implementation is intended to manage targets, LUNs and TPGTs, which includes create, remove and list actions. It provides these functionalities through a daemon. In the future, when fully enhanced and implemented, it would take RESTful syntax as well.

The pkg directory has three main pieces, i.e., the API interface, the SCSI layer and the iSCSI target layer. The API interface provides management services such as create and remove targets. The iSCSI target layer implements the protocol required to receive and transmit iSCSI PDU's, and communicates with the SCSI layer to carry out SCSI commands and processing.
The SCSI layer implements the SCSI SPC and SBC standards that talks to the SCSI devices attached to the target library.

Note that the examples directory is intended to show static configurations that serve as the backend storage. The simplest configuration has one LUN and one flat file behind the LUN in question. This json configuration file is read once at the beginning of the iSCSI target library instantiation.

## Performance Optimizations

gotgt includes several performance optimizations for high-throughput and low-latency storage workloads:

### 1. NUMA-Aware Memory Allocation

For multi-socket systems, gotgt can optimize memory allocation to use NUMA-local memory, reducing cross-socket memory access latency.

**Features:**
- Automatic NUMA topology detection
- NUMA-local buffer pools for I/O operations
- Thread pinning to specific NUMA nodes
- Configurable per-node buffer pool sizing

**Configuration:**
```json
{
    "performance": {
        "enableNUMA": true,
        "numaBufferPoolSize": 1024,
        "numaBufferSize": 262144
    },
    "storages": [
        {
            "deviceID": 1000,
            "path": "/var/tmp/disk.img",
            "online": true,
            "backendType": "file",
            "enableNUMA": true,
            "numaNode": 0
        }
    ]
}
```

### 2. io_uring Backend Storage (Linux 5.1+)

On Linux systems with kernel 5.1 or later, gotgt can use io_uring for high-performance asynchronous I/O, bypassing the traditional Linux AIO interface.

**Features:**
- Asynchronous I/O using io_uring
- Reduced system call overhead
- Better performance for high queue depth workloads
- Automatic fallback to standard I/O on older kernels

**Requirements:**
- Linux kernel 5.1 or later
- x86_64, ARM64, or other supported architectures

**Configuration:**
```json
{
    "performance": {
        "enableIoUring": true,
        "ioUringQueueDepth": 4096
    },
    "storages": [
        {
            "deviceID": 1000,
            "path": "/var/tmp/disk.img",
            "online": true,
            "backendType": "iouring",
            "ioUringQueueDepth": 4096
        }
    ]
}
```

**Backend Type Options:**
- `file` - Standard file I/O (default)
- `iouring` - io_uring-based I/O (Linux 5.1+)

### 3. Object Pooling

The iSCSI protocol layer uses sync.Pool for efficient object reuse:
- ISCSICommand object pooling to reduce GC pressure
- Buffer pooling for protocol header processing
- NUMA-aware buffer allocation for data operations

### 4. Combined High-Performance Configuration Example

For maximum performance, combine both NUMA and io_uring:

```json
{
  "storages": [
    {
      "deviceID": 1000,
      "path": "/var/tmp/disk.img",
      "online": true,
      "backendType": "iouring",
      "enableNUMA": true,
      "numaNode": 0,
      "ioUringQueueDepth": 4096
    }
  ],
  "iscsiportals": [
    {
      "id": 0,
      "portal": "192.168.1.100:3260"
    }
  ],
  "iscsitargets": {
    "iqn.2024-01.com.gotgt:fast-storage": {
      "tpgts": { "1": [0] },
      "luns": { "1": 1000 }
    }
  },
  "performance": {
    "enableNUMA": true,
    "enableIoUring": true,
    "ioUringQueueDepth": 4096,
    "numaBufferPoolSize": 1024,
    "numaBufferSize": 262144
  }
}
```

### 5. Performance Tuning Tips

1. **NUMA Optimization**: On multi-socket systems, ensure the iSCSI target threads run on the same NUMA node as the storage devices
2. **Queue Depth**: For NVMe or fast SSDs, increase `ioUringQueueDepth` to 4096 or higher
3. **Buffer Sizes**: Match `numaBufferSize` to your typical I/O size (e.g., 64KB, 128KB, 256KB)
4. **CPU Pinning**: Use `numaNode` to pin storage backends to specific NUMA nodes

### 6. Benchmarking

Use fio to benchmark performance:
```bash
fio --name=iscsi-test --ioengine=libaio --iodepth=32 \
    --rw=randread --bs=4k --direct=1 --size=1G \
    --filename=/dev/sdX
```

For more details, see [PERFORMANCE_OPTIMIZATIONS.md](./docs/PERFORMANCE_OPTIMIZATIONS.md).

## Test

You can test this with [open-iscsi](http://www.open-iscsi.com/) or [libiscsi](https://github.com/gostor/libiscsi).
For more information and example test scripts, please refer to the [test directory](./test).

### SCSI Commands Support

For a complete list of supported SCSI commands, see [SCSI_COMMANDS.md](./docs/SCSI_COMMANDS.md).

## Roadmap

The current roadmap and milestones for alpha and beta completion are in the github issues on this repository. Please refer to these issues for what is being worked on and completed for the various stages of development.

## Contributing

Want to help build gotgt? Check out our [contributing documentation](./CONTRIBUTING.md).
