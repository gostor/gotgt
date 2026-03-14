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
	"context"
	"sync"
	"sync/atomic"
)

// BufferPoolConfig configures NUMA-aware buffer pools
type BufferPoolConfig struct {
	// BufferSize is the size of each buffer
	BufferSize int
	// PerNodePoolSize is the number of buffers to preallocate per node
	PerNodePoolSize int
	// EnableNUMA enables NUMA-aware allocation
	EnableNUMA bool
}

// DefaultBufferPoolConfig returns a default configuration
func DefaultBufferPoolConfig() *BufferPoolConfig {
	return &BufferPoolConfig{
		BufferSize:      256 * 1024, // 256KB buffers for I/O
		PerNodePoolSize: 1024,       // 1024 buffers per node
		EnableNUMA:      true,
	}
}

// NUMABufferPool provides NUMA-aware buffer pooling
type NUMABufferPool struct {
	config    *BufferPoolConfig
	topology  *Topology
	nodePools map[NodeID]*sync.Pool
	stats     *PoolStats

	// Fallback pool for when NUMA is not available or disabled
	fallbackPool *sync.Pool

	mu sync.RWMutex
}

// PoolStats tracks buffer pool statistics
type PoolStats struct {
	Gets         uint64
	Puts         uint64
	Misses       uint64
	NodeLocalHit uint64
	NUMAHit      uint64
}

// NewNUMABufferPool creates a new NUMA-aware buffer pool
func NewNUMABufferPool(config *BufferPoolConfig) *NUMABufferPool {
	if config == nil {
		config = DefaultBufferPoolConfig()
	}

	pool := &NUMABufferPool{
		config:    config,
		topology:  GetTopology(),
		nodePools: make(map[NodeID]*sync.Pool),
		stats:     &PoolStats{},
	}

	// Initialize fallback pool
	pool.fallbackPool = &sync.Pool{
		New: func() interface{} {
			atomic.AddUint64(&pool.stats.Misses, 1)
			return make([]byte, config.BufferSize)
		},
	}

	// Initialize NUMA pools if enabled and available
	if config.EnableNUMA && Available() && pool.topology.NumNodes > 1 {
		for nodeID := range pool.topology.Nodes {
			pool.nodePools[nodeID] = pool.createNodePool(nodeID)
		}
	}

	return pool
}

// createNodePool creates a buffer pool for a specific NUMA node
func (p *NUMABufferPool) createNodePool(node NodeID) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			atomic.AddUint64(&p.stats.Misses, 1)

			// Try NUMA-local allocation first
			if p.config.EnableNUMA && Available() {
				buf, err := AllocateOnNode(p.config.BufferSize, node)
				if err == nil {
					atomic.AddUint64(&p.stats.NUMAHit, 1)
					return buf
				}
			}

			// Fall back to regular allocation
			return make([]byte, p.config.BufferSize)
		},
	}
}

// Get returns a buffer from the pool, preferably from the local NUMA node
func (p *NUMABufferPool) Get() []byte {
	atomic.AddUint64(&p.stats.Gets, 1)

	// Try to get from the local NUMA node first
	if p.config.EnableNUMA && Available() && len(p.nodePools) > 0 {
		if node, err := GetCurrentNode(); err == nil {
			if nodePool, ok := p.nodePools[node]; ok {
				buf := nodePool.Get().([]byte)
				atomic.AddUint64(&p.stats.NodeLocalHit, 1)
				return buf[:p.config.BufferSize]
			}
		}
	}

	// Fall back to the fallback pool
	return p.fallbackPool.Get().([]byte)[:p.config.BufferSize]
}

// Put returns a buffer to the pool, preferably to its local NUMA node
func (p *NUMABufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	atomic.AddUint64(&p.stats.Puts, 1)

	// Resize buffer to full size before returning to pool
	if cap(buf) < p.config.BufferSize {
		// Buffer is too small, discard it
		return
	}
	buf = buf[:p.config.BufferSize]

	// Try to return to the local NUMA node pool
	if p.config.EnableNUMA && Available() && len(p.nodePools) > 0 {
		if node, err := GetCurrentNode(); err == nil {
			if nodePool, ok := p.nodePools[node]; ok {
				nodePool.Put(buf)
				return
			}
		}
	}

	// Fall back to the fallback pool
	p.fallbackPool.Put(buf)
}

// GetForNode returns a buffer from a specific NUMA node's pool
func (p *NUMABufferPool) GetForNode(node NodeID) []byte {
	atomic.AddUint64(&p.stats.Gets, 1)

	if nodePool, ok := p.nodePools[node]; ok {
		return nodePool.Get().([]byte)[:p.config.BufferSize]
	}

	return p.fallbackPool.Get().([]byte)[:p.config.BufferSize]
}

// PutForNode returns a buffer to a specific NUMA node's pool
func (p *NUMABufferPool) PutForNode(node NodeID, buf []byte) {
	if buf == nil {
		return
	}

	atomic.AddUint64(&p.stats.Puts, 1)

	if cap(buf) < p.config.BufferSize {
		return
	}
	buf = buf[:p.config.BufferSize]

	if nodePool, ok := p.nodePools[node]; ok {
		nodePool.Put(buf)
		return
	}

	p.fallbackPool.Put(buf)
}

// Stats returns current pool statistics
func (p *NUMABufferPool) Stats() PoolStats {
	return PoolStats{
		Gets:         atomic.LoadUint64(&p.stats.Gets),
		Puts:         atomic.LoadUint64(&p.stats.Puts),
		Misses:       atomic.LoadUint64(&p.stats.Misses),
		NodeLocalHit: atomic.LoadUint64(&p.stats.NodeLocalHit),
		NUMAHit:      atomic.LoadUint64(&p.stats.NUMAHit),
	}
}

// GetConfig returns the pool configuration
func (p *NUMABufferPool) GetConfig() *BufferPoolConfig {
	return p.config
}

// Close releases all resources associated with the pool
func (p *NUMABufferPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Clear all pools
	p.nodePools = make(map[NodeID]*sync.Pool)
	p.fallbackPool = nil

	return nil
}

// SizeAwarePool is a buffer pool that can handle multiple buffer sizes
type SizeAwarePool struct {
	pools map[int]*NUMABufferPool
	mu    sync.RWMutex
}

// NewSizeAwarePool creates a new size-aware buffer pool
func NewSizeAwarePool(sizes []int, enableNUMA bool) *SizeAwarePool {
	sap := &SizeAwarePool{
		pools: make(map[int]*NUMABufferPool),
	}

	for _, size := range sizes {
		sap.pools[size] = NewNUMABufferPool(&BufferPoolConfig{
			BufferSize:      size,
			PerNodePoolSize: 1024,
			EnableNUMA:      enableNUMA,
		})
	}

	return sap
}

// Get returns a buffer of the specified size
func (sap *SizeAwarePool) Get(size int) []byte {
	sap.mu.RLock()
	pool, ok := sap.pools[size]
	sap.mu.RUnlock()

	if ok {
		return pool.Get()
	}

	// No pool for this size, allocate directly
	return make([]byte, size)
}

// Put returns a buffer to the appropriate pool
func (sap *SizeAwarePool) Put(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)

	sap.mu.RLock()
	pool, ok := sap.pools[size]
	sap.mu.RUnlock()

	if ok {
		pool.Put(buf)
	}
	// If no pool for this size, let GC handle it
}

// PinningAllocator allocates buffers while the goroutine is pinned to a NUMA node
type PinningAllocator struct {
	pool *NUMABufferPool
}

// NewPinningAllocator creates a new pinning allocator
func NewPinningAllocator(pool *NUMABufferPool) *PinningAllocator {
	return &PinningAllocator{pool: pool}
}

// Allocate allocates a buffer while pinned to the current NUMA node
func (pa *PinningAllocator) Allocate() []byte {
	return pa.pool.Get()
}

// AllocateOnNode allocates a buffer while pinned to a specific NUMA node
func (pa *PinningAllocator) AllocateOnNode(node NodeID) ([]byte, error) {
	var buf []byte
	err := RunOnNode(node, func() {
		buf = pa.pool.GetForNode(node)
	})
	return buf, err
}

// Global pools for common buffer sizes
var (
	globalPools     map[int]*NUMABufferPool
	globalPoolsOnce sync.Once
	globalPoolsMu   sync.RWMutex
)

// InitGlobalPools initializes global buffer pools
func InitGlobalPools(sizes []int, enableNUMA bool) {
	globalPoolsOnce.Do(func() {
		globalPools = make(map[int]*NUMABufferPool)
		for _, size := range sizes {
			globalPools[size] = NewNUMABufferPool(&BufferPoolConfig{
				BufferSize:      size,
				PerNodePoolSize: 1024,
				EnableNUMA:      enableNUMA,
			})
		}
	})
}

// GetBuffer gets a buffer from the global pool
func GetBuffer(size int) []byte {
	globalPoolsMu.RLock()
	pool, ok := globalPools[size]
	globalPoolsMu.RUnlock()

	if ok {
		return pool.Get()
	}
	return make([]byte, size)
}

// PutBuffer returns a buffer to the global pool
func PutBuffer(buf []byte) {
	if buf == nil {
		return
	}

	size := cap(buf)

	globalPoolsMu.RLock()
	pool, ok := globalPools[size]
	globalPoolsMu.RUnlock()

	if ok {
		pool.Put(buf)
	}
}

// WorkerPool is a pool of workers that are pinned to specific NUMA nodes
type WorkerPool struct {
	size      int
	numaNode  NodeID
	workQueue chan func()
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewWorkerPool creates a new NUMA-aware worker pool
func NewWorkerPool(size int, node NodeID) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	wp := &WorkerPool{
		size:      size,
		numaNode:  node,
		workQueue: make(chan func(), size*2),
		ctx:       ctx,
		cancel:    cancel,
	}

	// Start workers
	for i := 0; i < size; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}

	return wp
}

func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	// Pin to NUMA node
	if Available() {
		PinThreadToNode(wp.numaNode)
		defer UnpinThread()
	}

	for {
		select {
		case work := <-wp.workQueue:
			if work != nil {
				work()
			}
		case <-wp.ctx.Done():
			return
		}
	}
}

// Submit submits work to the worker pool
func (wp *WorkerPool) Submit(work func()) bool {
	select {
	case wp.workQueue <- work:
		return true
	case <-wp.ctx.Done():
		return false
	default:
		return false
	}
}

// Stop stops the worker pool
func (wp *WorkerPool) Stop() {
	wp.cancel()
	wp.wg.Wait()
	close(wp.workQueue)
}
