/*
Copyright 2016 The GoStor Authors All rights reserved.

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

// Package util provides some basic util functions.
package util

import (
	"encoding/binary"
	"os"
	"syscall"
)

type KeyValue struct {
	Key   string
	Value string
}

func GetUnalignedUint16(u8 []uint8) uint16 {
	return binary.BigEndian.Uint16(u8)
}

func GetUnalignedUint32(u8 []uint8) uint32 {
	return binary.BigEndian.Uint32(u8)
}

func GetUnalignedUint64(u8 []uint8) uint64 {
	return binary.BigEndian.Uint64(u8)
}

// ParseKVText parses iSCSI key value data.
func ParseKVText(txt []byte) map[string]string {
	m := make(map[string]string)
	var kv, sep int
	var key string
	for i := 0; i < len(txt); i++ {
		if txt[i] == '=' {
			if key == "" {
				sep = i
				key = string(txt[kv:sep])
			}
			continue
		}
		if txt[i] == 0 && key != "" {
			m[key] = string(txt[sep+1 : i])
			key = ""
			kv = i + 1
		}
	}
	return m
}

func MarshalKVText(kv []KeyValue) []byte {
	var data []byte
	for _, v := range kv {
		data = append(data, []byte(v.Key)...)
		data = append(data, '=')
		data = append(data, []byte(v.Value)...)
		data = append(data, 0)
	}
	return data
}

// MarshalUint16 returns big-endian encoding of i as a new 2-byte slice.
// Deprecated: Use MarshalUint16To or binary.BigEndian.PutUint16 for zero-allocation.
func MarshalUint16(i uint16) []byte {
	var data [2]byte
	binary.BigEndian.PutUint16(data[:], i)
	return data[:]
}

// MarshalUint32 returns big-endian encoding of i as a new 4-byte slice.
// Deprecated: Use MarshalUint32To or binary.BigEndian.PutUint32 for zero-allocation.
func MarshalUint32(i uint32) []byte {
	var data [4]byte
	binary.BigEndian.PutUint32(data[:], i)
	return data[:]
}

// MarshalUint32To writes big-endian encoding of i into buf, which must be at least 4 bytes.
// This is a zero-allocation alternative to MarshalUint32.
func MarshalUint32To(buf []byte, i uint32) {
	binary.BigEndian.PutUint32(buf, i)
}

func MarshalUint64(v uint64) []byte {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], v)
	return data[:]
}

// MarshalUint64To writes big-endian encoding of v into buf, which must be at least 8 bytes.
// This is a zero-allocation alternative for partial writes.
func MarshalUint64To(buf []byte, v uint64) {
	binary.BigEndian.PutUint64(buf, v)
}

func StringToByte(str string, align int, maxlength int) []byte {
	var (
		data   []byte
		data2  []byte
		length int
		d      int
	)

	data = []byte(str)
	length = len(data)
	d = align - (length % align)

	if (length + d) > maxlength {
		data = ([]byte(str))[0:maxlength]
		return data
	} else {
		data2 = make([]byte, length+d)
		copy(data2, data)
		return data2
	}
}

const (
	POSIX_FADV_NORMAL = iota
	POSIX_FADV_RANDOM
	POSIX_FADV_SEQUENTIAL
	POSIX_FADV_WILLNEED
	POSIX_FADV_DONTNEED
	POSIX_FADV_NOREUSE
)

func Fadvise(file *os.File, off, length int64, advise uint32) error {
	// syscall.SYS_FADVISE64 = 221
	_, _, err := syscall.Syscall6(221, file.Fd(), uintptr(off), uintptr(length), uintptr(advise), 0, 0)
	if err != 0 {
		return err
	}
	return nil
}
