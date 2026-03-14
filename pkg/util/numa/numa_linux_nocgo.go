//go:build linux && !cgo
// +build linux,!cgo

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
	"syscall"
	"unsafe"
)

// Syscall numbers for x86_64 Linux
const (
	SYS_GETCPU        = 309
	SYS_SET_MEMPOLICY = 238
	SYS_GET_MEMPOLICY = 239
	SYS_MBIND         = 237
	SYS_MIGRATE_PAGES = 238
)

const (
	// NUMA memory policies
	MPOL_DEFAULT    = 0
	MPOL_PREFERRED  = 1
	MPOL_BIND       = 2
	MPOL_INTERLEAVE = 3
	MPOL_LOCAL      = 4

	// Flags for get_mempolicy
	MPOL_F_NODE = 1 << 0
	MPOL_F_ADDR = 1 << 1

	// Flags for mbind
	MPOL_MF_STRICT = 1 << 0
)

//go:noescape
//go:linkname runtime_GetCPU runtime.getcpu
func runtime_GetCPU() uint32

func detectLinuxTopology(topology *Topology) error {
	nodes, err := detectNodesFromSys()
	if err != nil {
		return err
	}

	topology.NumNodes = len(nodes)

	for _, nodeID := range nodes {
		nodeInfo := &NodeInfo{
			ID: NodeID(nodeID),
		}

		// Get CPUs for this node
		cpus, err := getCPUsForNodeNoCGO(nodeID)
		if err == nil {
			nodeInfo.CPUs = cpus
			for _, cpu := range cpus {
				topology.CPUToNodeMap[cpu] = NodeID(nodeID)
			}
		}

		// Get memory info for this node
		memInfo, err := getMemoryInfoForNodeNoCGO(nodeID)
		if err == nil {
			nodeInfo.TotalMemory = memInfo.total
			nodeInfo.FreeMemory = memInfo.free
		}

		// Get distance matrix
		distances, err := getDistancesForNodeNoCGO(nodeID, len(nodes))
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

func getMemoryInfoForNodeNoCGO(nodeID int) (*memoryInfo, error) {
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
				info.total = val * 1024
			}
		} else if strings.Contains(line, "MemFree:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(fields[1], 10, 64)
				info.free = val * 1024
			}
		}
	}

	return info, scanner.Err()
}

func getCPUsForNodeNoCGO(nodeID int) ([]int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/sys/devices/system/node/node%d/cpulist", nodeID))
	if err != nil {
		return nil, err
	}

	return parseCPUListNoCGO(strings.TrimSpace(string(data)))
}

func parseCPUListNoCGO(list string) ([]int, error) {
	var cpus []int

	if list == "" {
		return cpus, nil
	}

	parts := strings.Split(list, ",")
	for _, part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])
				for i := start; i <= end; i++ {
					cpus = append(cpus, i)
				}
			}
		} else {
			cpu, _ := strconv.Atoi(part)
			cpus = append(cpus, cpu)
		}
	}

	return cpus, nil
}

func getDistancesForNodeNoCGO(nodeID int, numNodes int) ([]uint32, error) {
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

func getCurrentNodeImpl() (NodeID, error) {
	var cpu, node uint32

	// Use getcpu syscall
	r1, _, errno := syscall.Syscall(SYS_GETCPU,
		uintptr(unsafe.Pointer(&cpu)),
		uintptr(unsafe.Pointer(&node)),
		0)

	if errno != 0 {
		// Fallback: try to determine from CPU
		return getNodeFromSchedGetCPU()
	}

	_ = r1 // suppress unused warning
	return NodeID(node), nil
}

func getNodeFromSchedGetCPU() (NodeID, error) {
	// Get current CPU
	cpu := runtime.GOMAXPROCS(0)

	// Look up in topology
	topology := GetTopology()
	node, ok := topology.GetNodeForCPU(cpu)
	if !ok {
		return 0, fmt.Errorf("cannot determine NUMA node for CPU %d", cpu)
	}
	return node, nil
}

func setPreferredNodeImpl(node NodeID) (*PreferredNode, error) {
	mask := uint64(1) << uint64(node)
	maxNode := uint64(node) + 1

	_, _, errno := syscall.Syscall6(SYS_SET_MEMPOLICY,
		uintptr(MPOL_PREFERRED),
		uintptr(unsafe.Pointer(&mask)),
		uintptr(maxNode),
		0, 0, 0)

	if errno != 0 {
		return nil, fmt.Errorf("set_mempolicy failed: %v", errno)
	}

	return &PreferredNode{nodeID: node}, nil
}

func revertPreferredNodeImpl(p *PreferredNode) error {
	_, _, errno := syscall.Syscall(SYS_SET_MEMPOLICY,
		uintptr(MPOL_DEFAULT),
		0, 0)

	if errno != 0 {
		return fmt.Errorf("set_mempolicy failed: %v", errno)
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

	var mask uint64
	for _, node := range nodes {
		mask |= 1 << uint64(node)
	}

	maxNode := uint64(0)
	for _, node := range nodes {
		if uint64(node) >= maxNode {
			maxNode = uint64(node) + 1
		}
	}

	_, _, errno := syscall.Syscall6(SYS_SET_MEMPOLICY,
		uintptr(mode),
		uintptr(unsafe.Pointer(&mask)),
		uintptr(maxNode),
		0, 0, 0)

	if errno != 0 {
		return fmt.Errorf("set_mempolicy failed: %v", errno)
	}

	return nil
}

func allocateOnNodeImpl(size int, node NodeID) ([]byte, error) {
	buf := make([]byte, size)

	// Try to use mbind to bind memory to node
	mask := uint64(1) << uint64(node)
	maxNode := uint64(node) + 1

	_, _, errno := syscall.Syscall6(SYS_MBIND,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
		uintptr(MPOL_BIND),
		uintptr(unsafe.Pointer(&mask)),
		uintptr(maxNode),
		uintptr(MPOL_MF_STRICT))

	if errno != 0 {
		// Fall back to regular allocation
		return buf, nil
	}

	return buf, nil
}

func scheduleOnNodeImpl(cpu int, fn func()) error {
	var mask syscall.CPUSet
	mask.Set(cpu)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := syscall.SchedSetaffinity(0, &mask); err != nil {
		return fmt.Errorf("sched_setaffinity failed: %v", err)
	}

	fn()
	return nil
}

func getPreferredNodeForCurrentThreadImpl() NodeID {
	var mode int
	var node uint32

	_, _, errno := syscall.Syscall6(SYS_GET_MEMPOLICY,
		uintptr(unsafe.Pointer(&mode)),
		0, 0,
		uintptr(unsafe.Pointer(&node)),
		uintptr(MPOL_F_NODE),
		0)

	if errno != 0 {
		node, _ := getCurrentNodeImpl()
		return node
	}

	if mode == MPOL_DEFAULT {
		node, _ := getCurrentNodeImpl()
		return node
	}

	return NodeID(node)
}

// PinThreadToNode pins the current goroutine's OS thread to a specific NUMA node
func PinThreadToNode(node NodeID) error {
	topology := GetTopology()
	nodeInfo, ok := topology.GetNode(node)
	if !ok {
		return fmt.Errorf("NUMA node %d not found", node)
	}

	if len(nodeInfo.CPUs) == 0 {
		return fmt.Errorf("NUMA node %d has no CPUs", node)
	}

	runtime.LockOSThread()

	var mask syscall.CPUSet
	for _, cpu := range nodeInfo.CPUs {
		mask.Set(cpu)
	}

	if err := syscall.SchedSetaffinity(0, &mask); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("sched_setaffinity failed: %v", err)
	}

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
