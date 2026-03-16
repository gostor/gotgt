/*
Copyright 2017 The GoStor Authors All rights reserved.

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

package backingstore

import (
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gostor/gotgt/pkg/api"
	"github.com/gostor/gotgt/pkg/scsi"
	"github.com/gostor/gotgt/pkg/util"
)

const (
	FileBackingStorage = "file"
)

func init() {
	scsi.RegisterBackingStore(FileBackingStorage, new)
}

type FileBackingStore struct {
	scsi.BaseBackingStore
	file *os.File
}

func new() (api.BackingStore, error) {
	return &FileBackingStore{
		BaseBackingStore: scsi.BaseBackingStore{
			Name:            FileBackingStorage,
			DataSize:        0,
			OflagsSupported: 0,
		},
	}, nil
}

// parseStoragePath parses a storage path that may include backend type prefix
// Format: [backend_type:]path
// Examples:
//   - /var/tmp/disk.img (default file backend)
//   - file:/var/tmp/disk.img (explicit file backend)
//   - iouring:/var/tmp/disk.img (io_uring backend on Linux 5.1+)
func parseStoragePath(path string) (backendType, filePath string) {
	if idx := strings.Index(path, ":"); idx > 0 {
		possibleType := path[:idx]
		// Check if it's a known backend type
		switch possibleType {
		case "file", "iouring", "ceph", "null", "RemBs", "s3":
			return possibleType, path[idx+1:]
		}
	}
	// Default to file backend
	return "file", path
}

func (bs *FileBackingStore) Open(dev *api.SCSILu, path string) error {
	var mode os.FileMode

	// Parse backend type and actual path
	backendType, filePath := parseStoragePath(path)
	_ = backendType // file backend ignores this

	finfo, err := os.Stat(filePath)
	if err != nil {
		return err
	} else {
		// determine file type
		mode = finfo.Mode()
	}

	f, err := os.OpenFile(filePath, os.O_RDWR, os.ModePerm)

	if err == nil {
		// block device filesize needs to be treated differently
		if (mode & os.ModeDevice) != 0 {
			pos, err := f.Seek(0, io.SeekEnd)
			if err != nil {
				return err
			}
			bs.DataSize = uint64(pos)
		} else {
			if finfo == nil {
				log.Infof("finfo is nil")
			}
			bs.DataSize = uint64(finfo.Size())
		}
	}

	bs.file = f
	return err
}

func (bs *FileBackingStore) Close(dev *api.SCSILu) error {
	return bs.file.Close()
}

func (bs *FileBackingStore) Init(dev *api.SCSILu, Opts string) error {
	return nil
}

func (bs *FileBackingStore) Exit(dev *api.SCSILu) error {
	return nil
}

func (bs *FileBackingStore) Size(dev *api.SCSILu) uint64 {
	return bs.DataSize
}

func (bs *FileBackingStore) Read(offset, tl int64) ([]byte, error) {
	if bs.file == nil {
		return nil, fmt.Errorf("Backend store is nil")
	}
	tmpbuf := make([]byte, tl)
	length, err := bs.file.ReadAt(tmpbuf, offset)
	if err != nil {
		return nil, err
	}
	if length != len(tmpbuf) {
		return nil, fmt.Errorf("read is not same length of length")
	}
	return tmpbuf, nil
}

// ReadAt reads directly into the provided buffer, avoiding allocation.
func (bs *FileBackingStore) ReadAt(buf []byte, offset int64) (int, error) {
	if bs.file == nil {
		return 0, fmt.Errorf("Backend store is nil")
	}
	return bs.file.ReadAt(buf, offset)
}

func (bs *FileBackingStore) Write(wbuf []byte, offset int64) error {
	length, err := bs.file.WriteAt(wbuf, offset)
	if err != nil {
		log.Error(err)
		return err
	}
	if length != len(wbuf) {
		return fmt.Errorf("write is not same length of length")
	}
	return nil
}

func (bs *FileBackingStore) DataSync(offset, tl int64) error {
	return util.Fdatasync(bs.file)
}

func (bs *FileBackingStore) DataAdvise(offset, length int64, advise uint32) error {
	return util.Fadvise(bs.file, offset, length, advise)
}

// unmapZeroBufSize is the size of the reusable zero buffer for unmap operations.
const unmapZeroBufSize = 1 << 20 // 1MB

// unmapZeroBuf is a pre-allocated zero buffer shared across unmap calls.
var unmapZeroBuf = make([]byte, unmapZeroBufSize)

func (bs *FileBackingStore) Unmap(descriptors []api.UnmapBlockDescriptor) error {
	for _, desc := range descriptors {
		remaining := desc.TL
		off := int64(desc.Offset)
		for remaining > 0 {
			writeLen := remaining
			if writeLen > unmapZeroBufSize {
				writeLen = unmapZeroBufSize
			}
			if _, err := bs.file.WriteAt(unmapZeroBuf[:writeLen], off); err != nil {
				return err
			}
			off += int64(writeLen)
			remaining -= writeLen
		}
	}
	return nil
}
