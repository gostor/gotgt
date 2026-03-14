//go:build linux
// +build linux

/*
Copyright 2024 The GoStor Authors All rights reserved.

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

// Package iouring provides an io_uring-based backing store for high-performance
// asynchronous I/O operations on Linux 5.1+ systems.
package iouring

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/scsi"
)

const (
	IoUringBackingStorage = "iouring"

	// Default queue depth for io_uring
	DefaultQueueDepth = 4096

	// Minimum kernel version required (5.1)
	MinKernelMajor = 5
	MinKernelMinor = 1
)

// io_uring constants (from linux/io_uring.h)
const (
	IORING_SETUP_IOPOLL     = 1 << 0
	IORING_SETUP_SQPOLL     = 1 << 1
	IORING_SETUP_SQ_AFF     = 1 << 2
	IORING_SETUP_CQSIZE     = 1 << 3
	IORING_SETUP_CLAMP      = 1 << 4
	IORING_SETUP_ATTACH_WQ  = 1 << 5
	IORING_SETUP_R_DISABLED = 1 << 6

	IORING_FSYNC_DATASYNC = 1 << 0

	IORING_TIMEOUT_ABS = 1 << 0

	IORING_OFF_SQ_RING = 0
	IORING_OFF_CQ_RING = 0x8000000
	IORING_OFF_SQES    = 0x10000000

	IORING_OP_NOP             = 0
	IORING_OP_READV           = 1
	IORING_OP_WRITEV          = 2
	IORING_OP_FSYNC           = 3
	IORING_OP_READ_FIXED      = 4
	IORING_OP_WRITE_FIXED     = 5
	IORING_OP_POLL_ADD        = 6
	IORING_OP_POLL_REMOVE     = 7
	IORING_OP_SYNC_FILE_RANGE = 8
	IORING_OP_SENDMSG         = 9
	IORING_OP_RECVMSG         = 10
	IORING_OP_TIMEOUT         = 11
	IORING_OP_TIMEOUT_REMOVE  = 12
	IORING_OP_ACCEPT          = 13
	IORING_OP_ASYNC_CANCEL    = 14
	IORING_OP_LINK_TIMEOUT    = 15
	IORING_OP_CONNECT         = 16
	IORING_OP_FALLOCATE       = 17
	IORING_OP_OPENAT          = 18
	IORING_OP_CLOSE           = 19
	IORING_OP_FILES_UPDATE    = 20
	IORING_OP_STATX           = 21
	IORING_OP_READ            = 22
	IORING_OP_WRITE           = 23
	IORING_OP_FADVISE         = 24
	IORING_OP_MADVISE         = 25
	IORING_OP_SEND            = 26
	IORING_OP_RECV            = 27
	IORING_OP_OPENAT2         = 28
	IORING_OP_EPOLL_CTL       = 29
	IORING_OP_SPLICE          = 30
	IORING_OP_PROVIDE_BUFFERS = 31
	IORING_OP_REMOVE_BUFFERS  = 32
	IORING_OP_TEE             = 33
	IORING_OP_SHUTDOWN        = 34
	IORING_OP_RENAMEAT        = 35
	IORING_OP_UNLINKAT        = 36
	IORING_OP_MKDIRAT         = 37
	IORING_OP_SYMLINKAT       = 38
	IORING_OP_LINKAT          = 39
	IORING_OP_MSG_RING        = 40
	IORING_OP_FSETXATTR       = 41
	IORING_OP_SETXATTR        = 42
	IORING_OP_FGETXATTR       = 43
	IORING_OP_GETXATTR        = 44
	IORING_OP_SOCKET          = 45
	IORING_OP_URING_CMD       = 46
	IORING_OP_SEND_ZC         = 47
	IORING_OP_SENDMSG_ZC      = 48

	IORING_CQE_F_BUFFER = 1 << 0
	IORING_CQE_F_MORE   = 1 << 1
)

// io_uring structures
// Note: These are simplified structures for the operations we need
type ioUring struct {
	fd       int
	sq       *ioUringSq
	cq       *ioUringCq
	flags    uint32
	ringSize int
}

type ioUringSq struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	flags       *uint32
	dropped     *uint32
	array       *uint32
	sqes        []ioSqringEntry
}

type ioUringCq struct {
	head        *uint32
	tail        *uint32
	ringMask    *uint32
	ringEntries *uint32
	overflow    *uint32
	cqes        []ioCqringEntry
}

type ioSqringEntry struct {
	opcode   uint8
	flags    uint8
	ioprio   uint16
	fd       int32
	off      uint64
	addr     uint64
	len      uint32
	userData uint64
}

type ioCqringEntry struct {
	userData uint64
	res      int32
	flags    uint32
}

type ioUringParams struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCPU  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32
	sqOff        ioSqringOffsets
	cqOff        ioCqringOffsets
}

type ioSqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	resv2       uint64
}

type ioCqringOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	resv2       uint64
}

type ioUringCqe struct {
	userData uint64
	res      int32
	flags    uint32
}

var ioUringEnabled = false

func init() {
	if isKernelVersionSupported() {
		ioUringEnabled = true
		scsi.RegisterBackingStore(IoUringBackingStorage, newIOUringBackingStore)
		log.Info("io_uring backing store registered (kernel supports io_uring)")
	} else {
		log.Info("io_uring backing store not available (requires Linux 5.1+)")
	}
}

func isKernelVersionSupported() bool {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return false
	}

	// Parse kernel version (simplified)
	// Format is typically "5.15.0-generic"
	major := int(uname.Release[0] - '0')
	minor := int(uname.Release[2] - '0')

	if major > MinKernelMajor {
		return true
	}
	if major == MinKernelMajor && minor >= MinKernelMinor {
		return true
	}
	return false
}

// IOUringBackingStore implements BackingStore using io_uring
type IOUringBackingStore struct {
	scsi.BaseBackingStore
	file       *os.File
	ring       *ioUring
	queueDepth int

	// Synchronization
	submitMu sync.Mutex

	// Statistics
	opsSubmitted uint64
	opsCompleted uint64
}

func newIOUringBackingStore() (api.BackingStore, error) {
	return &IOUringBackingStore{
		BaseBackingStore: scsi.BaseBackingStore{
			Name:            IoUringBackingStorage,
			DataSize:        0,
			OflagsSupported: 0,
		},
		queueDepth: DefaultQueueDepth,
	}, nil
}

// Open opens the backing file and initializes io_uring
func (bs *IOUringBackingStore) Open(dev *api.SCSILu, path string) error {
	var mode os.FileMode

	finfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode = finfo.Mode()

	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_DIRECT, os.ModePerm)
	if err != nil {
		// Try without O_DIRECT if not supported
		f, err = os.OpenFile(path, os.O_RDWR, os.ModePerm)
		if err != nil {
			return err
		}
	}

	if (mode & os.ModeDevice) != 0 {
		pos, err := f.Seek(0, os.SEEK_END)
		if err != nil {
			f.Close()
			return err
		}
		bs.DataSize = uint64(pos)
	} else {
		bs.DataSize = uint64(finfo.Size())
	}

	bs.file = f

	// Initialize io_uring
	ring, err := bs.initIOUring()
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to initialize io_uring: %v", err)
	}
	bs.ring = ring

	log.Infof("io_uring backing store opened: %s (queue depth: %d)", path, bs.queueDepth)
	return nil
}

func (bs *IOUringBackingStore) initIOUring() (*ioUring, error) {
	params := &ioUringParams{}

	// Setup io_uring
	fd, _, errno := syscall.Syscall(425, // __NR_io_uring_setup
		uintptr(bs.queueDepth),
		uintptr(unsafe.Pointer(params)),
		0)

	if errno != 0 {
		return nil, fmt.Errorf("io_uring_setup failed: %v", errno)
	}

	ring := &ioUring{
		fd:       int(fd),
		ringSize: int(params.sqEntries),
		flags:    params.flags,
	}

	// Map the submission queue ring
	sqRingSize := params.sqOff.array + params.sqEntries*uint32(unsafe.Sizeof(uint32(0)))
	cqRingSize := params.cqOff.cqes + params.cqEntries*uint32(unsafe.Sizeof(ioCqringEntry{}))

	if params.features&1 != 0 { // IORING_FEAT_SINGLE_MMAP
		if cqRingSize > sqRingSize {
			sqRingSize = cqRingSize
		}
		cqRingSize = sqRingSize
	}

	// mmap submission queue
	sqPtr, _, errno := syscall.Syscall6(syscall.SYS_MMAP,
		0,
		uintptr(sqRingSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd),
		uintptr(IORING_OFF_SQ_RING))

	if errno != 0 {
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap sq ring failed: %v", errno)
	}

	sqBase := sqPtr

	// mmap completion queue (if not single mmap)
	var cqPtr uintptr
	if params.features&1 != 0 {
		cqPtr = sqPtr
	} else {
		cqPtr, _, errno = syscall.Syscall6(syscall.SYS_MMAP,
			0,
			uintptr(cqRingSize),
			syscall.PROT_READ|syscall.PROT_WRITE,
			syscall.MAP_SHARED|syscall.MAP_POPULATE,
			uintptr(fd),
			uintptr(IORING_OFF_CQ_RING))

		if errno != 0 {
			syscall.Syscall(syscall.SYS_MUNMAP, sqPtr, uintptr(sqRingSize), 0)
			syscall.Close(int(fd))
			return nil, fmt.Errorf("mmap cq ring failed: %v", errno)
		}
	}

	cqBase := cqPtr

	// mmap SQEs
	sqeSize := uint32(unsafe.Sizeof(ioSqringEntry{}))
	sqePtr, _, errno := syscall.Syscall6(syscall.SYS_MMAP,
		0,
		uintptr(uint32(bs.queueDepth)*sqeSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
		uintptr(fd),
		uintptr(IORING_OFF_SQES))

	if errno != 0 {
		syscall.Syscall(syscall.SYS_MUNMAP, sqPtr, uintptr(sqRingSize), 0)
		if cqPtr != sqPtr {
			syscall.Syscall(syscall.SYS_MUNMAP, cqPtr, uintptr(cqRingSize), 0)
		}
		syscall.Close(int(fd))
		return nil, fmt.Errorf("mmap sqes failed: %v", errno)
	}

	// Setup submission queue
	sq := &ioUringSq{
		head:        (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.head))),
		tail:        (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.tail))),
		ringMask:    (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.ringMask))),
		ringEntries: (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.ringEntries))),
		flags:       (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.flags))),
		dropped:     (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.dropped))),
		array:       (*uint32)(unsafe.Pointer(sqBase + uintptr(params.sqOff.array))),
		sqes:        make([]ioSqringEntry, bs.queueDepth),
	}
	copy(unsafe.Slice((*ioSqringEntry)(unsafe.Pointer(sqePtr)), bs.queueDepth), sq.sqes)

	// Setup completion queue
	cq := &ioUringCq{
		head:        (*uint32)(unsafe.Pointer(cqBase + uintptr(params.cqOff.head))),
		tail:        (*uint32)(unsafe.Pointer(cqBase + uintptr(params.cqOff.tail))),
		ringMask:    (*uint32)(unsafe.Pointer(cqBase + uintptr(params.cqOff.ringMask))),
		ringEntries: (*uint32)(unsafe.Pointer(cqBase + uintptr(params.cqOff.ringEntries))),
		overflow:    (*uint32)(unsafe.Pointer(cqBase + uintptr(params.cqOff.overflow))),
		cqes:        make([]ioCqringEntry, params.cqEntries),
	}
	copy(unsafe.Slice((*ioCqringEntry)(unsafe.Pointer(cqBase+uintptr(params.cqOff.cqes))), params.cqEntries), cq.cqes)

	ring.sq = sq
	ring.cq = cq

	return ring, nil
}

// Close closes the backing file and io_uring
func (bs *IOUringBackingStore) Close(dev *api.SCSILu) error {
	if bs.ring != nil {
		bs.closeIOUring()
		bs.ring = nil
	}
	if bs.file != nil {
		return bs.file.Close()
	}
	return nil
}

func (bs *IOUringBackingStore) closeIOUring() {
	if bs.ring != nil && bs.ring.fd >= 0 {
		syscall.Close(bs.ring.fd)
	}
}

// Init initializes the backing store
func (bs *IOUringBackingStore) Init(dev *api.SCSILu, Opts string) error {
	return nil
}

// Exit exits the backing store
func (bs *IOUringBackingStore) Exit(dev *api.SCSILu) error {
	return nil
}

// Size returns the size of the backing store
func (bs *IOUringBackingStore) Size(dev *api.SCSILu) uint64 {
	return bs.DataSize
}

// Read reads data from the backing file using io_uring
func (bs *IOUringBackingStore) Read(offset, tl int64) ([]byte, error) {
	if bs.file == nil {
		return nil, fmt.Errorf("backing store is not open")
	}

	buf := make([]byte, tl)

	// Prepare read operation
	bs.submitMu.Lock()
	defer bs.submitMu.Unlock()

	// Get next SQE
	sqe := bs.getSqe()
	if sqe == nil {
		// Ring is full, submit pending operations first
		if err := bs.submit(); err != nil {
			return nil, err
		}
		sqe = bs.getSqe()
		if sqe == nil {
			return nil, fmt.Errorf("io_uring queue full")
		}
	}

	// Setup read operation
	*sqe = ioSqringEntry{
		opcode:   IORING_OP_READ,
		fd:       int32(bs.file.Fd()),
		off:      uint64(offset),
		addr:     uint64(uintptr(unsafe.Pointer(&buf[0]))),
		len:      uint32(tl),
		userData: 1, // 1 = read operation
	}

	// Submit and wait for completion
	if err := bs.submitAndWait(1); err != nil {
		return nil, err
	}

	// Get completion
	cqe, err := bs.getCqe()
	if err != nil {
		return nil, err
	}

	if cqe.res < 0 {
		return nil, fmt.Errorf("read failed: %d", cqe.res)
	}

	atomic.AddUint64(&bs.opsCompleted, 1)

	return buf[:cqe.res], nil
}

// Write writes data to the backing file using io_uring
func (bs *IOUringBackingStore) Write(wbuf []byte, offset int64) error {
	if bs.file == nil {
		return fmt.Errorf("backing store is not open")
	}

	bs.submitMu.Lock()
	defer bs.submitMu.Unlock()

	// Get next SQE
	sqe := bs.getSqe()
	if sqe == nil {
		if err := bs.submit(); err != nil {
			return err
		}
		sqe = bs.getSqe()
		if sqe == nil {
			return fmt.Errorf("io_uring queue full")
		}
	}

	// Setup write operation
	*sqe = ioSqringEntry{
		opcode:   IORING_OP_WRITE,
		fd:       int32(bs.file.Fd()),
		off:      uint64(offset),
		addr:     uint64(uintptr(unsafe.Pointer(&wbuf[0]))),
		len:      uint32(len(wbuf)),
		userData: 2, // 2 = write operation
	}

	// Submit and wait for completion
	if err := bs.submitAndWait(1); err != nil {
		return err
	}

	// Get completion
	cqe, err := bs.getCqe()
	if err != nil {
		return err
	}

	if cqe.res < 0 {
		return fmt.Errorf("write failed: %d", cqe.res)
	}

	if cqe.res != int32(len(wbuf)) {
		return fmt.Errorf("short write: %d != %d", cqe.res, len(wbuf))
	}

	atomic.AddUint64(&bs.opsCompleted, 1)
	return nil
}

// DataSync syncs data to disk using io_uring
func (bs *IOUringBackingStore) DataSync(offset, tl int64) error {
	if bs.file == nil {
		return fmt.Errorf("backing store is not open")
	}

	bs.submitMu.Lock()
	defer bs.submitMu.Unlock()

	sqe := bs.getSqe()
	if sqe == nil {
		if err := bs.submit(); err != nil {
			return err
		}
		sqe = bs.getSqe()
		if sqe == nil {
			return fmt.Errorf("io_uring queue full")
		}
	}

	*sqe = ioSqringEntry{
		opcode:   IORING_OP_FSYNC,
		fd:       int32(bs.file.Fd()),
		len:      IORING_FSYNC_DATASYNC,
		userData: 3, // 3 = fsync operation
	}

	if err := bs.submitAndWait(1); err != nil {
		return err
	}

	cqe, err := bs.getCqe()
	if err != nil {
		return err
	}

	if cqe.res < 0 {
		return fmt.Errorf("fsync failed: %d", cqe.res)
	}

	atomic.AddUint64(&bs.opsCompleted, 1)
	return nil
}

// DataAdvise provides advice about data access patterns
func (bs *IOUringBackingStore) DataAdvise(offset, length int64, advise uint32) error {
	if bs.file == nil {
		return fmt.Errorf("backing store is not open")
	}

	// Use posix_fadvise via syscall
	_, _, errno := syscall.Syscall6(syscall.SYS_FADVISE64, uintptr(bs.file.Fd()), uintptr(offset), uintptr(length), uintptr(advise), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// Unmap is a no-op for file-based storage
func (bs *IOUringBackingStore) Unmap([]api.UnmapBlockDescriptor) error {
	return nil
}

// getSqe gets the next available submission queue entry
func (bs *IOUringBackingStore) getSqe() *ioSqringEntry {
	sq := bs.ring.sq
	tail := atomic.LoadUint32(sq.tail)
	next := tail + 1

	if next-atomic.LoadUint32(sq.head) > uint32(bs.ring.ringSize) {
		return nil // Queue is full
	}

	idx := tail & *sq.ringMask
	return &sq.sqes[idx]
}

// submit submits pending SQEs to the kernel
func (bs *IOUringBackingStore) submit() error {
	if bs.ring == nil {
		return fmt.Errorf("io_uring not initialized")
	}

	// Update tail
	atomic.StoreUint32(bs.ring.sq.tail, atomic.LoadUint32(bs.ring.sq.tail)+1)

	// Submit using io_uring_enter syscall
	_, _, errno := syscall.Syscall6(426, // __NR_io_uring_enter
		uintptr(bs.ring.fd),
		uintptr(1), // submit 1 operation
		0,          // min complete
		0,          // flags
		0, 0)

	if errno != 0 {
		return fmt.Errorf("io_uring_enter failed: %v", errno)
	}

	atomic.AddUint64(&bs.opsSubmitted, 1)
	return nil
}

// submitAndWait submits operations and waits for completions
func (bs *IOUringBackingStore) submitAndWait(minComplete uint32) error {
	if bs.ring == nil {
		return fmt.Errorf("io_uring not initialized")
	}

	// Update tail
	atomic.StoreUint32(bs.ring.sq.tail, atomic.LoadUint32(bs.ring.sq.tail)+1)

	// Submit and wait
	_, _, errno := syscall.Syscall6(426, // __NR_io_uring_enter
		uintptr(bs.ring.fd),
		uintptr(1),           // submit 1 operation
		uintptr(minComplete), // min complete
		0,                    // flags
		0, 0)

	if errno != 0 {
		return fmt.Errorf("io_uring_enter failed: %v", errno)
	}

	return nil
}

// getCqe gets a completion queue entry
func (bs *IOUringBackingStore) getCqe() (*ioCqringEntry, error) {
	cq := bs.ring.cq

	// Wait for completion
	for atomic.LoadUint32(cq.head) == atomic.LoadUint32(cq.tail) {
		// Spin-wait for completion
		runtime.Gosched()
	}

	head := atomic.LoadUint32(cq.head)
	idx := head & *cq.ringMask
	cqe := &cq.cqes[idx]

	// Update head
	atomic.StoreUint32(cq.head, head+1)

	return cqe, nil
}

// Stats returns io_uring statistics
func (bs *IOUringBackingStore) Stats() (submitted, completed uint64) {
	return atomic.LoadUint64(&bs.opsSubmitted), atomic.LoadUint64(&bs.opsCompleted)
}

// Available returns true if io_uring is available on this system
func Available() bool {
	return ioUringEnabled
}
