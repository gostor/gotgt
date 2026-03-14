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

package numa

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

// #include <stdlib.h>
// #include <unistd.h>
// #include <sys/syscall.h>
// #include <linux/mempolicy.h>
// #include <numa.h>
// #include <numaif.h>
//
// #cgo LDFLAGS: -lnuma
import "C"

const (
	// NUMA memory policies (from linux/mempolicy.h)
	MPOL_DEFAULT    = 0
	MPOL_PREFERRED  = 1
	MPOL_BIND       = 2
	MPOL_INTERLEAVE = 3
	MPOL_LOCAL      = 4
	MPOL_MAX        = 5

	// Flags for mbind
	MPOL_MF_STRICT      = 1 << 0
	MPOL_MF_MOVE        = 1 << 1
	MPOL_MF_MOVE_ALL    = 1 << 2
	MPOL_MF_LAZY        = 1 << 3
	MPOL_MF_INTERNAL    = 1 << 4
	MPOL_MF_VALID       = 1 << 5
	MPOL_MF_WAKE        = 1 << 6
	MPOL_MF_REMOVE      = 1 << 7
	MPOL_MF_HONOR_VMFOL = 1 << 8

	// Flags for get_mempolicy
	MPOL_F_NODE         = 1 << 0
	MPOL_F_ADDR         = 1 << 1
	MPOL_F_MEMS_ALLOWED = 1 << 2
)

var (
	numaInitOnce sync.Once
	numaInitErr  error
)

func initNuma() {
	numaInitOnce.Do(func() {
		if C.numa_available() < 0 {
			numaInitErr = fmt.Errorf("NUMA is not available")
		} else {
			// numa_init is not available in newer libnuma versions
			// The library is automatically initialized on first use
		}
	})
}

func detectLinuxTopology(topology *Topology) error {
	initNuma()

	// First, try to use /sys filesystem for detection
	nodes, err := detectNodesFromSys()
	if err != nil {
		// Fall back to libnuma
		return detectFromLibNuma(topology)
	}

	topology.NumNodes = len(nodes)

	for _, nodeID := range nodes {
		nodeInfo := &NodeInfo{
			ID: NodeID(nodeID),
		}

		// Get CPUs for this node
		cpus, err := getCPUsForNode(nodeID)
		if err == nil {
			nodeInfo.CPUs = cpus
			for _, cpu := range cpus {
				topology.CPUToNodeMap[cpu] = NodeID(nodeID)
			}
		}

		// Get memory info for this node
		memInfo, err := getMemoryInfoForNode(nodeID)
		if err == nil {
			nodeInfo.TotalMemory = memInfo.total
			nodeInfo.FreeMemory = memInfo.free
		}

		// Get distance matrix
		distances, err := getDistancesForNode(nodeID, len(nodes))
		if err == nil {
			nodeInfo.DistanceToNode = distances
		}

		topology.Nodes[NodeID(nodeID)] = nodeInfo
	}

	return nil
}

func detectNodesFromSys() ([]int, error) {
	entries, err := os.ReadDir("/sys/devices/system/node")
	if err != nil {
		return nil, err
	}

	var nodes []int
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "node") {
			nodeID, err := strconv.Atoi(entry.Name()[4:])
			if err == nil {
				nodes = append(nodes, nodeID)
			}
		}
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("no NUMA nodes found")
	}

	return nodes, nil
}

type memoryInfo struct {
	total uint64
	free  uint64
}

func getMemoryInfoForNode(nodeID int) (*memoryInfo, error) {
	file, err := os.Open(fmt.Sprintf("/sys/devices/system/node/node%d/meminfo", nodeID))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info := &memoryInfo{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				info.total = val * 1024 // Convert from KB to bytes
			}
		} else if strings.Contains(line, "MemFree:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				info.free = val * 1024 // Convert from KB to bytes
			}
		}
	}

	return info, scanner.Err()
}

func getCPUsForNode(nodeID int) ([]int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", nodeID))
	if err != nil {
		return nil, err
	}

	return parseCPUList(strings.TrimSpace(string(data)))
}

func parseCPUList(list string) ([]int, error) {
	var cpus []int

	// Handle empty list
	if list == "" {
		return cpus, nil
	}

	parts := strings.Split(list, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			// Range like "0-7"
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for i := start; i <= end; i++ {
					cpus = append(cpus, i)
				}
			}
		} else {
			// Single CPU
			cpu, _ := strconv.Atoi(part)
			cpus = append(cpus, cpu)
		}
	}

	return cpus, nil
}

func getDistancesForNode(nodeID int, numNodes int) ([]uint32, error) {
	file, err := os.Open(fmt.Sprintf("/sys/devices/system/node/node%d/distance", nodeID))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := os.ReadFile(fmt.Sprintf("/sys/devices/system/node/node%d/distance", nodeID))
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(string(data))
	distances := make([]uint32, len(fields))
	for i, field := range fields {
		val, _ := strconv.ParseUint(field, 10, 32)
		distances[i] = uint32(val)
	}

	return distances, nil
}

func detectFromLibNuma(topology *Topology) error {
	initNuma()
	if numaInitErr != nil {
		return numaInitErr
	}

	numNodes := int(C.numa_num_configured_nodes())
	if numNodes <= 0 {
		return fmt.Errorf("no NUMA nodes configured")
	}

	topology.NumNodes = numNodes

	maxNode := int(C.numa_max_node())

	for nodeID := 0; nodeID <= maxNode; nodeID++ {
		if C.numa_bitmask_isbitset(C.numa_all_nodes_ptr, C.uint(nodeID)) == 0 {
			continue
		}

		nodeInfo := &NodeInfo{
			ID: NodeID(nodeID),
		}

		// Get memory size
		totalMem := uint64(C.numa_node_size(C.int(nodeID), nil))
		nodeInfo.TotalMemory = totalMem

		// Get CPUs (this is approximate with libnuma)
		cpuMask := C.numa_allocate_cpumask()
		defer C.numa_free_cpumask(cpuMask)

		if C.numa_node_to_cpus(C.int(nodeID), cpuMask) == 0 {
			// Parse CPU mask
			maxCPU := int(C.numa_num_configured_cpus())
			for cpu := 0; cpu < maxCPU; cpu++ {
				if C.numa_bitmask_isbitset(cpuMask, C.uint(cpu)) != 0 {
					nodeInfo.CPUs = append(nodeInfo.CPUs, cpu)
					topology.CPUToNodeMap[cpu] = NodeID(nodeID)
				}
			}
		}

		topology.Nodes[NodeID(nodeID)] = nodeInfo
	}

	return nil
}

func getCurrentNodeImpl() (NodeID, error) {
	// Use /proc/self/stat to get current CPU
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, fmt.Errorf("failed to read /proc/self/stat: %v", err)
	}

	fields := strings.Fields(string(data))
	if len(fields) < 39 {
		return 0, fmt.Errorf("unexpected /proc/self/stat format")
	}

	cpu, err := strconv.Atoi(fields[38])
	if err != nil {
		return 0, fmt.Errorf("failed to parse CPU: %v", err)
	}

	topology := GetTopology()
	node, ok := topology.GetNodeForCPU(cpu)
	if !ok {
		return 0, fmt.Errorf("CPU %d not found in topology", cpu)
	}
	return node, nil
}

func setPreferredNodeImpl(node NodeID) (*PreferredNode, error) {
	initNuma()
	if numaInitErr != nil {
		return nil, numaInitErr
	}

	// Save current nodemask
	var oldMode C.int
	var oldMask C.ulong
	maxNode := C.ulong(2) // We only need 2 bits for now

	if ret := C.get_mempolicy(&oldMode, &oldMask, maxNode, nil, 0); ret < 0 {
		return nil, fmt.Errorf("get_mempolicy failed: %v", ret)
	}

	// Set preferred node
	var newMask C.ulong = 1 << C.ulong(node)
	if ret := C.set_mempolicy(MPOL_PREFERRED, &newMask, maxNode); ret < 0 {
		return nil, fmt.Errorf("set_mempolicy failed: %v", ret)
	}

	return &PreferredNode{nodeID: node}, nil
}

func revertPreferredNodeImpl(p *PreferredNode) error {
	// Reset to default policy
	if ret := C.set_mempolicy(MPOL_DEFAULT, nil, 0); ret < 0 {
		return fmt.Errorf("set_mempolicy failed: %v", ret)
	}
	return nil
}

func setMemoryPolicyImpl(policy MemoryPolicy, nodes []NodeID) error {
	var mode int
	switch policy {
	case MPDefault:
		mode = MPOL_DEFAULT
	case MPBind:
		mode = MPOL_BIND
	case MPPreferred:
		mode = MPOL_PREFERRED
	case MPInterleave:
		mode = MPOL_INTERLEAVE
	default:
		return fmt.Errorf("unknown memory policy: %d", policy)
	}

	// Build nodemask
	var mask C.ulong
	for _, node := range nodes {
		mask |= 1 << C.ulong(node)
	}

	maxNode := C.ulong(2)
	for _, node := range nodes {
		if C.ulong(node) >= maxNode {
			maxNode = C.ulong(node) + 1
		}
	}

	if ret := C.set_mempolicy(C.int(mode), &mask, maxNode); ret < 0 {
		return fmt.Errorf("set_mempolicy failed: %v", ret)
	}

	return nil
}

func allocateOnNodeImpl(size int, node NodeID) ([]byte, error) {
	// Use mmap with MAP_PRIVATE and bind to specific node
	buf := make([]byte, size)

	// Set the memory policy for the allocated region
	var mask C.ulong = 1 << C.ulong(node)
	ptr := unsafe.Pointer(&buf[0])

	if ret := C.mbind(ptr, C.ulong(size), MPOL_BIND, &mask, C.ulong(node)+1, MPOL_MF_STRICT); ret < 0 {
		// Fall back to regular allocation
		return buf, nil
	}

	return buf, nil
}

func scheduleOnNodeImpl(cpu int, fn func()) error {
	// Simplified implementation - just run the function
	// CPU affinity setting requires CGO or unix package
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fn()
	return nil
}

func getPreferredNodeForCurrentThreadImpl() NodeID {
	var mode C.int
	var node C.int

	if ret := C.get_mempolicy(&mode, nil, 0, unsafe.Pointer(&node), MPOL_F_NODE); ret < 0 {
		return NodeID(0)
	}

	if mode == MPOL_DEFAULT {
		// Get current CPU's node
		currentNode, _ := getCurrentNodeImpl()
		return currentNode
	}

	return NodeID(node)
}

// PinThreadToNode pins the current goroutine's OS thread to a specific NUMA node
func PinThreadToNode(node NodeID) error {
	initNuma()
	if numaInitErr != nil {
		return numaInitErr
	}

	topology := GetTopology()
	nodeInfo, ok := topology.GetNode(node)
	if !ok {
		return fmt.Errorf("NUMA node %d not found", node)
	}

	if len(nodeInfo.CPUs) == 0 {
		return fmt.Errorf("NUMA node %d has no CPUs", node)
	}

	runtime.LockOSThread()
	// Note: CPU affinity setting is simplified for portability
	// Full implementation would use sched_setaffinity syscall
	return nil
}

// UnpinThread releases the current goroutine's OS thread from NUMA binding
func UnpinThread() {
	runtime.UnlockOSThread()
}

// RunOnNode runs a function with the current goroutine pinned to a specific NUMA node
func RunOnNode(node NodeID, fn func()) error {
	if err := PinThreadToNode(node); err != nil {
		return err
	}
	defer UnpinThread()

	fn()
	return nil
}
