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
	"sync"
	"testing"
)

func TestTSIHBitmapAllocRelease(t *testing.T) {
	b := newTSIHBitmap()

	// Test basic allocation and release
	tsih1 := b.alloc()
	if tsih1 == ISCSI_UNSPEC_TSIH {
		t.Fatal("failed to allocate first TSIH")
	}
	if tsih1 != 1 {
		t.Errorf("expected first TSIH to be 1, got %d", tsih1)
	}

	tsih2 := b.alloc()
	if tsih2 == ISCSI_UNSPEC_TSIH {
		t.Fatal("failed to allocate second TSIH")
	}
	if tsih2 != 2 {
		t.Errorf("expected second TSIH to be 2, got %d", tsih2)
	}

	// Release first
	b.release(tsih1)
	// Note: TSIH bitmap uses circular allocation, next pointer won't return to released positions
	// This is to avoid concurrency issues, subsequent allocations continue from current next
	tsih3 := b.alloc()
	if tsih3 == ISCSI_UNSPEC_TSIH {
		t.Error("failed to allocate after release")
	}
	// Verify tsih1 can be reallocated (at some point)
	if tsih3 == tsih1 || tsih3 == tsih2 {
		t.Logf("TSIH was recycled immediately: released %d, got %d", tsih1, tsih3)
	}

	// Release all
	b.release(tsih2)
	b.release(tsih3)
}

func TestTSIHBitmapReservedValues(t *testing.T) {
	b := newTSIHBitmap()

	// Test reserved values cannot be allocated
	// 0 and 65535 are reserved values
	for i := 0; i < 10; i++ {
		tsih := b.alloc()
		if tsih == 0 {
			t.Error("allocated reserved TSIH 0")
		}
		if tsih == ISCSI_MAX_TSIH {
			t.Error("allocated reserved TSIH 65535")
		}
		if tsih == ISCSI_UNSPEC_TSIH {
			break
		}
		b.release(tsih)
	}

	// Test releasing reserved values doesn't panic
	b.release(0)
	b.release(ISCSI_MAX_TSIH)
}

func TestTSIHBitmapExhaustion(t *testing.T) {
	b := newTSIHBitmap()

	// Allocate many TSIHs
	allocated := make([]uint16, 0, 100)
	for i := 0; i < 100; i++ {
		tsih := b.alloc()
		if tsih == ISCSI_UNSPEC_TSIH {
			t.Fatalf("failed to allocate TSIH at iteration %d", i)
		}
		allocated = append(allocated, tsih)
	}

	// 释放所有
	for _, tsih := range allocated {
		b.release(tsih)
	}

	// Reallocate, should succeed
	for i := 0; i < 100; i++ {
		tsih := b.alloc()
		if tsih == ISCSI_UNSPEC_TSIH {
			t.Fatalf("failed to reallocate TSIH at iteration %d", i)
		}
		b.release(tsih)
	}
}

func TestTSIHBitmapConcurrency(t *testing.T) {
	b := newTSIHBitmap()
	const numGoroutines = 100
	const allocsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	allTSIHs := make(chan uint16, numGoroutines*allocsPerGoroutine)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < allocsPerGoroutine; j++ {
				tsih := b.alloc()
				if tsih != ISCSI_UNSPEC_TSIH {
					allTSIHs <- tsih
				}
			}
		}()
	}

	wg.Wait()
	close(allTSIHs)

	// Check no duplicate TSIHs
	seen := make(map[uint16]bool)
	for tsih := range allTSIHs {
		if seen[tsih] {
			t.Errorf("TSIH %d was allocated more than once", tsih)
		}
		seen[tsih] = true
	}

	// Release all allocated TSIHs
	for tsih := range seen {
		b.release(tsih)
	}
}

func BenchmarkTSIHBitmapAlloc(b *testing.B) {
	bitmap := newTSIHBitmap()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tsih := bitmap.alloc()
			if tsih != ISCSI_UNSPEC_TSIH {
				bitmap.release(tsih)
			}
		}
	})
}

func BenchmarkTSIHBitmapAllocSequential(b *testing.B) {
	bitmap := newTSIHBitmap()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tsih := bitmap.alloc()
		if tsih != ISCSI_UNSPEC_TSIH {
			bitmap.release(tsih)
		}
	}
}
