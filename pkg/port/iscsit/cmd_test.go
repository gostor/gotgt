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

package iscsit

import (
	"testing"
	"unsafe"
)

func TestGetPutCommand(t *testing.T) {
	// Test getting command object
	cmd1 := getCommand()
	if cmd1 == nil {
		t.Fatal("getCommand() returned nil")
	}

	// Set some values
	cmd1.TaskTag = 12345
	cmd1.DataLen = 100
	cmd1.ExpCmdSN = 999

	// Put back to pool
	putCommand(cmd1)

	// Get again, verify if reused (may be reset)
	cmd2 := getCommand()
	if cmd2 == nil {
		t.Fatal("getCommand() returned nil after put")
	}

	// Put back
	putCommand(cmd2)

	// Test nil doesn't panic
	putCommand(nil)
}

func TestGetPutBuffer(t *testing.T) {
	// Test getting buffer
	buf1 := getBuffer()
	if buf1 == nil {
		t.Fatal("getBuffer() returned nil")
	}
	if len(buf1) != BHS_SIZE {
		t.Errorf("expected buffer size %d, got %d", BHS_SIZE, len(buf1))
	}

	// Modify buffer content
	for i := range buf1 {
		buf1[i] = byte(i % 256)
	}

	// Put back to pool
	putBuffer(buf1)

	// Get again
	buf2 := getBuffer()
	if buf2 == nil {
		t.Fatal("getBuffer() returned nil after put")
	}
	if len(buf2) != BHS_SIZE {
		t.Errorf("expected buffer size %d, got %d", BHS_SIZE, len(buf2))
	}

	putBuffer(buf2)

	// Test small buffer won't be put into pool
	smallBuf := make([]byte, 10)
	putBuffer(smallBuf) // Should not panic

	// Test nil doesn't panic
	putBuffer(nil)
}

func TestBufferPoolReuse(t *testing.T) {
	// Get buffer and record address
	buf1 := getBuffer()
	ptr1 := uintptr(unsafe.Pointer(&buf1[0]))
	putBuffer(buf1)

	// Get again, verify if reuse is possible (not guaranteed)
	buf2 := getBuffer()
	ptr2 := uintptr(unsafe.Pointer(&buf2[0]))
	putBuffer(buf2)

	// If reused, addresses should be the same
	// If not reused, it's fine, this is a performance test
	t.Logf("First buffer pointer: %x, Second buffer pointer: %x, reused: %v",
		ptr1, ptr2, ptr1 == ptr2)
}

func BenchmarkGetPutCommand(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cmd := getCommand()
			cmd.TaskTag = 1
			putCommand(cmd)
		}
	})
}

func BenchmarkGetPutBuffer(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := getBuffer()
			buf[0] = 1
			putBuffer(buf)
		}
	})
}

// BenchmarkAllocCommand 对比：不使用 pool 直接创建
func BenchmarkAllocCommand(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cmd := &ISCSICommand{}
			cmd.TaskTag = 1
			_ = cmd
		}
	})
}

// BenchmarkAllocBuffer 对比：不使用 pool 直接创建
func BenchmarkAllocBuffer(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := make([]byte, BHS_SIZE)
			buf[0] = 1
			_ = buf
		}
	})
}
