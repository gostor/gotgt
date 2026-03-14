//go:build !linux
// +build !linux

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
	"fmt"
	"runtime"
)

func detectLinuxTopology(topology *Topology) error {
	return fmt.Errorf("NUMA not supported on this platform")
}

func getCurrentNodeImpl() (NodeID, error) {
	return 0, fmt.Errorf("NUMA not supported on this platform")
}

func setPreferredNodeImpl(node NodeID) (*PreferredNode, error) {
	return nil, fmt.Errorf("NUMA not supported on this platform")
}

func revertPreferredNodeImpl(p *PreferredNode) error {
	return fmt.Errorf("NUMA not supported on this platform")
}

func setMemoryPolicyImpl(policy MemoryPolicy, nodes []NodeID) error {
	return fmt.Errorf("NUMA not supported on this platform")
}

func allocateOnNodeImpl(size int, node NodeID) ([]byte, error) {
	return make([]byte, size), nil
}

func scheduleOnNodeImpl(cpu int, fn func()) error {
	fn()
	return nil
}

func getPreferredNodeForCurrentThreadImpl() NodeID {
	return 0
}

// PinThreadToNode pins the current goroutine's OS thread to a specific NUMA node
// Stub implementation - does nothing on non-Linux platforms
func PinThreadToNode(node NodeID) error {
	return nil
}

// UnpinThread releases the current goroutine's OS thread from NUMA binding
// Stub implementation - does nothing on non-Linux platforms
func UnpinThread() {}

// RunOnNode runs a function with the current goroutine pinned to a specific NUMA node
// Stub implementation - just runs the function on non-Linux platforms
func RunOnNode(node NodeID, fn func()) error {
	fn()
	return nil
}

// createSingleNodeTopology creates a single-node topology for non-NUMA systems
func createSingleNodeTopology(topology *Topology) {
	numCPU := runtime.NumCPU()
	cpus := make([]int, numCPU)
	for i := 0; i < numCPU; i++ {
		cpus[i] = i
		topology.CPUToNodeMap[i] = 0
	}

	topology.NumNodes = 1
	topology.Nodes[0] = &NodeInfo{
		ID:             0,
		CPUs:           cpus,
		TotalMemory:    0,
		FreeMemory:     0,
		DistanceToNode: []uint32{10},
	}
}
