# Performance Optimizations for gotgt

This document describes the performance optimizations implemented for gotgt, focusing on NUMA-aware memory allocation and io_uring backend storage support.

## Overview

Two major performance optimizations have been implemented:

1. **NUMA-Aware Memory Allocation** - Optimizes memory access patterns on multi-socket systems
2. **io_uring Backend Storage** - Provides high-performance asynchronous I/O on Linux 5.1+

## 1. NUMA-Aware Memory Allocation

### What is NUMA?

Non-Uniform Memory Access (NUMA) is a memory design used in multi-processor systems where the memory access time depends on the memory location relative to the processor. Under NUMA, a processor can access its own local memory faster than non-local memory (memory local to another processor or memory shared between processors).

### Implementation

The NUMA support is implemented in `pkg/util/numa/`:

- **Topology Detection** (`numa.go`, `numa_linux.go`): Automatically detects NUMA topology using `/sys/devices/system/node/` filesystem
- **NUMA-Local Buffer Pool** (`pool.go`): Provides buffer pools that allocate memory from local NUMA nodes
- **Thread Pinning** (`numa_linux.go`): Allows threads to be pinned to specific NUMA nodes

### Key Components

#### NUMABufferPool

```go
pool := numa.NewNUMABufferPool(&numa.BufferPoolConfig{
    BufferSize:      256 * 1024,  // 256KB buffers
    PerNodePoolSize: 1024,        // 1024 buffers per node
    EnableNUMA:      true,
})

buf := pool.Get()  // Get buffer from local NUMA node
// use buffer...
pool.Put(buf)      // Return buffer to pool
```

#### Thread Pinning

```go
// Pin current goroutine to NUMA node 0
numa.PinThreadToNode(0)
defer numa.UnpinThread()

// Or use RunOnNode for a function
numa.RunOnNode(0, func() {
    // This function runs on NUMA node 0
})
```

### Performance Benefits

- Reduced memory latency by accessing local NUMA nodes
- Better cache utilization
- Reduced cross-socket traffic
- Predictable performance on multi-socket systems

### Configuration

Enable NUMA support in the configuration file:

```json
{
  "performance": {
    "enableNUMA": true,
    "numaBufferPoolSize": 1024,
    "numaBufferSize": 262144
  }
}
```

## 2. io_uring Backend Storage

### What is io_uring?

io_uring is a Linux kernel interface for asynchronous I/O that was introduced in Linux 5.1. It provides a highly efficient interface for submitting and completing I/O operations with minimal system call overhead.

### Benefits of io_uring

- Reduced system call overhead (batching of operations)
- Lower latency for I/O operations
- Higher throughput especially for high queue depth workloads
- Better CPU efficiency

### Implementation

The io_uring backend is implemented in `pkg/scsi/backingstore/iouring/`:

- **Async I/O Operations**: Read, Write, and Fsync using io_uring
- **Queue Management**: Configurable queue depth
- **Fallback Support**: Automatically falls back to regular I/O on older kernels

### Usage

Enable io_uring in the storage configuration:

```json
{
  "storages": [
    {
      "deviceID": 1000,
      "path": "/var/tmp/disk.img",
      "online": true,
      "backendType": "iouring",
      "ioUringQueueDepth": 4096
    }
  ],
  "performance": {
    "enableIoUring": true,
    "ioUringQueueDepth": 4096
  }
}
```

### Backend Type Options

- `file` - Standard synchronous file I/O (default)
- `iouring` - io_uring-based asynchronous I/O (Linux 5.1+)

### Requirements

- Linux kernel 5.1 or later
- x86_64, ARM64, or other supported architectures
- O_DIRECT support recommended for best performance

## 3. Combined Configuration Example

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

## 4. Performance Tuning Guide

### NUMA Tuning

1. **Determine NUMA Topology**:
   ```bash
   numactl --hardware
   lscpu | grep NUMA
   ```

2. **Align Network and Storage**:
   - Ensure network interfaces are on the same NUMA node as the iSCSI process
   - Place storage devices on the same NUMA node if possible

3. **Buffer Pool Sizing**:
   - `numaBufferPoolSize`: Number of buffers per node (default: 1024)
   - `numaBufferSize`: Size of each buffer (default: 256KB)
   - Size based on expected concurrent I/O and I/O size

### io_uring Tuning

1. **Queue Depth**:
   - Higher queue depth = better throughput, higher latency
   - Lower queue depth = lower latency, lower throughput
   - Typical values: 128-4096 depending on workload

2. **I/O Size**:
   - Match application I/O size for best efficiency
   - Use direct I/O (O_DIRECT) to bypass page cache if appropriate

3. **System Limits**:
   ```bash
   # Check current limits
   ulimit -a
   
   # Increase if needed (in /etc/security/limits.conf)
   * soft nofile 1048576
   * hard nofile 1048576
   ```

## 5. Benchmarking

Use the following tools to benchmark performance:

1. **fio** (Flexible I/O Tester):
   ```bash
   fio --name=iscsi-test --ioengine=libaio --iodepth=32 \
       --rw=randread --bs=4k --direct=1 --size=1G \
       --filename=/dev/sdX
   ```

2. **iperf3** (for network bandwidth):
   ```bash
   iperf3 -c <target-ip> -p 3260
   ```

3. **iscsi-perf** (if available from libiscsi)

## 6. Troubleshooting

### NUMA Issues

- Check if NUMA is available: `numa.Available()`
- Verify topology detection: Check logs for NUMA node count
- Thread pinning failures: Ensure sufficient privileges (CAP_SYS_NICE)

### io_uring Issues

- Kernel version check: `uname -r` (must be 5.1+)
- io_uring availability: Check if `/proc/sys/kernel/io_uring_disabled` exists
- Permission issues: Ensure user has appropriate file permissions

## 7. Future Enhancements

Potential future optimizations:

1. **DPDK Support** - Kernel-bypass networking for iSCSI
2. **SPDK Integration** - User-space NVMe driver support
3. **CPU Affinity Configuration** - Fine-grained CPU pinning
4. **Memory Interleaving** - Automatic memory interleaving policies
5. **Adaptive Buffer Sizing** - Dynamic buffer pool sizing based on workload

## References

- [io_uring by Jens Axboe](https://kernel.dk/io_uring.pdf)
- [NUMA FAQ](https://www.kernel.org/doc/html/latest/vm/numa.html)
- [iSCSI RFC 7143](https://tools.ietf.org/html/rfc7143)
