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

// Package numa provides NUMA-aware utilities for multi-socket systems.
// This package enables memory allocation optimization and thread binding
// for better performance on NUMA architectures.
package numa

import (
	"fmt"
	"runtime"
	"sync"
)

// NodeID represents a NUMA node identifier
type NodeID int

// NodeInfo contains information about a NUMA node
type NodeInfo struct {
	ID             NodeID
	CPUs           []int    // CPU cores on this node
	TotalMemory    uint64   // Total memory in bytes
	FreeMemory     uint64   // Free memory in bytes
	DistanceToNode []uint32 // Distance to other nodes (lower is closer)
}

// Topology represents the NUMA topology of the system
type Topology struct {
	Nodes        map[NodeID]*NodeInfo
	NumNodes     int
	CPUToNodeMap map[int]NodeID
	mu           sync.RWMutex
}

var (
	globalTopology     *Topology
	globalTopologyOnce sync.Once
	numaAvailable      bool
)

// Available returns true if NUMA support is available on this system
func Available() bool {
	return numaAvailable
}

// GetTopology returns the NUMA topology of the system
func GetTopology() *Topology {
	globalTopologyOnce.Do(func() {
		globalTopology = detectTopology()
	})
	return globalTopology
}

// detectTopology detects the NUMA topology of the system
// This is a placeholder that will be implemented per-platform
func detectTopology() *Topology {
	topology := &Topology{
		Nodes:        make(map[NodeID]*NodeInfo),
		CPUToNodeMap: make(map[int]NodeID),
	}

	// Try to detect using platform-specific methods
	if err := detectLinuxTopology(topology); err != nil {
		// Fall back to single-node topology
		topology.NumNodes = 1
		topology.Nodes[0] = &NodeInfo{
			ID:          0,
			CPUs:        makeRange(0, runtime.NumCPU()),
			TotalMemory: 0, // Unknown
			FreeMemory:  0, // Unknown
		}
		for i := 0; i < runtime.NumCPU(); i++ {
			topology.CPUToNodeMap[i] = 0
		}
		numaAvailable = false
	} else {
		numaAvailable = topology.NumNodes > 1
	}

	return topology
}

// makeRange creates a slice of integers from start to end
func makeRange(start, end int) []int {
	result := make([]int, end-start)
	for i := range result {
		result[i] = start + i
	}
	return result
}

// GetNodeForCPU returns the NUMA node ID for a given CPU
func (t *Topology) GetNodeForCPU(cpu int) (NodeID, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	node, ok := t.CPUToNodeMap[cpu]
	return node, ok
}

// GetNode returns information about a specific NUMA node
func (t *Topology) GetNode(id NodeID) (*NodeInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	node, ok := t.Nodes[id]
	return node, ok
}

// GetCurrentNode returns the NUMA node of the current thread
func GetCurrentNode() (NodeID, error) {
	return getCurrentNodeImpl()
}

// PreferredNode represents a preferred NUMA node for memory allocation
type PreferredNode struct {
	nodeID NodeID
}

// SetPreferredNode sets the preferred NUMA node for the current thread
func SetPreferredNode(node NodeID) (*PreferredNode, error) {
	return setPreferredNodeImpl(node)
}

// Revert restores the previous NUMA policy
func (p *PreferredNode) Revert() error {
	return revertPreferredNodeImpl(p)
}

// MemoryPolicy represents memory allocation policies
type MemoryPolicy int

const (
	// MPDefault uses the default memory policy
	MPDefault MemoryPolicy = iota
	// MPBind binds memory allocation to specific nodes
	MPBind
	// MPPreferred prefers memory allocation from specific nodes
	MPPreferred
	// MPInterleave interleaves memory across nodes
	MPInterleave
)

// SetMemoryPolicy sets the memory policy for the current thread
func SetMemoryPolicy(policy MemoryPolicy, nodes []NodeID) error {
	return setMemoryPolicyImpl(policy, nodes)
}

// AllocateOnNode allocates memory on a specific NUMA node
func AllocateOnNode(size int, node NodeID) ([]byte, error) {
	return allocateOnNodeImpl(size, node)
}

// LocalAlloc allocates memory on the local NUMA node
func LocalAlloc(size int) ([]byte, error) {
	node, err := GetCurrentNode()
	if err != nil {
		// Fall back to regular allocation
		return make([]byte, size), nil
	}
	return AllocateOnNode(size, node)
}

// NodeLocalPool is a memory pool that allocates from a specific NUMA node
type NodeLocalPool struct {
	nodeID NodeID
	pool   sync.Pool
	size   int
}

// NewNodeLocalPool creates a new NUMA-local memory pool
func NewNodeLocalPool(size int, node NodeID) *NodeLocalPool {
	return &NodeLocalPool{
		nodeID: node,
		size:   size,
		pool: sync.Pool{
			New: func() interface{} {
				buf, err := AllocateOnNode(size, node)
				if err != nil {
					// Fall back to regular allocation
					return make([]byte, size)
				}
				return buf
			},
		},
	}
}

// Get returns a buffer from the pool
func (p *NodeLocalPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool
func (p *NodeLocalPool) Put(buf []byte) {
	if buf != nil && len(buf) >= p.size {
		p.pool.Put(buf[:p.size])
	}
}

// Close releases all resources associated with the pool
func (p *NodeLocalPool) Close() error {
	// In Go, sync.Pool doesn't have a Close method
	// The memory will be garbage collected eventually
	return nil
}

// NodeScheduler schedules tasks on specific NUMA nodes
type NodeScheduler struct {
	topology *Topology
	mu       sync.RWMutex
}

// NewNodeScheduler creates a new NUMA-aware scheduler
func NewNodeScheduler() *NodeScheduler {
	return &NodeScheduler{
		topology: GetTopology(),
	}
}

// ScheduleOnNode schedules a function to run on a specific NUMA node
func (s *NodeScheduler) ScheduleOnNode(node NodeID, fn func()) error {
	nodeInfo, ok := s.topology.GetNode(node)
	if !ok {
		return fmt.Errorf("NUMA node %d not found", node)
	}

	if len(nodeInfo.CPUs) == 0 {
		return fmt.Errorf("NUMA node %d has no CPUs", node)
	}

	return scheduleOnNodeImpl(nodeInfo.CPUs[0], fn)
}

// GetPreferredNodeForCurrentThread returns the preferred NUMA node
// based on current thread's affinity
func GetPreferredNodeForCurrentThread() NodeID {
	return getPreferredNodeForCurrentThreadImpl()
}

// NumNodes returns the number of NUMA nodes in the system
func NumNodes() int {
	return GetTopology().NumNodes
}
