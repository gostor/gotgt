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

package numa

import (
	"testing"
)

func TestTopologyDetection(t *testing.T) {
	topology := GetTopology()
	if topology == nil {
		t.Fatal("GetTopology returned nil")
	}

	if topology.NumNodes < 1 {
		t.Errorf("Expected at least 1 NUMA node, got %d", topology.NumNodes)
	}

	if len(topology.Nodes) == 0 {
		t.Error("No NUMA nodes found in topology")
	}
}

func TestBufferPool(t *testing.T) {
	pool := NewNUMABufferPool(&BufferPoolConfig{
		BufferSize:      4096,
		PerNodePoolSize: 10,
		EnableNUMA:      false, // Disable NUMA for test
	})

	if pool == nil {
		t.Fatal("NewNUMABufferPool returned nil")
	}

	// Test Get/Put
	buf := pool.Get()
	if len(buf) != 4096 {
		t.Errorf("Expected buffer size 4096, got %d", len(buf))
	}

	pool.Put(buf)

	// Test stats
	stats := pool.Stats()
	if stats.Gets == 0 {
		t.Error("Expected Gets > 0")
	}
	if stats.Puts == 0 {
		t.Error("Expected Puts > 0")
	}
}

func TestBufferPoolMultipleSizes(t *testing.T) {
	pool := NewNUMABufferPool(&BufferPoolConfig{
		BufferSize:      8192,
		PerNodePoolSize: 5,
		EnableNUMA:      false,
	})

	// Get multiple buffers
	var buffers [][]byte
	for i := 0; i < 10; i++ {
		buf := pool.Get()
		buffers = append(buffers, buf)
	}

	// Put all back
	for _, buf := range buffers {
		pool.Put(buf)
	}

	stats := pool.Stats()
	if stats.Gets != 10 {
		t.Errorf("Expected 10 gets, got %d", stats.Gets)
	}
	if stats.Puts != 10 {
		t.Errorf("Expected 10 puts, got %d", stats.Puts)
	}
}

func TestAvailable(t *testing.T) {
	// Just verify the function doesn't panic
	_ = Available()
}

func TestNumNodes(t *testing.T) {
	n := NumNodes()
	if n < 1 {
		t.Errorf("Expected at least 1 node, got %d", n)
	}
}
