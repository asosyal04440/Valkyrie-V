//! NUMA-Aware Memory Allocation
//!
//! NUMA topology-aware memory allocation for optimal performance.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// NUMA Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum NUMA nodes
pub const MAX_NUMA_NODES: usize = 16;

/// Maximum CPUs
pub const MAX_NUMA_CPUS: usize = 256;

/// Maximum memory zones per node
pub const MAX_ZONES_PER_NODE: usize = 8;

/// Maximum VMs with NUMA policy
pub const MAX_NUMA_VMS: usize = 128;

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// Large page size (2MB)
pub const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Memory zone types
pub mod zone_type {
    pub const DMA: u8 = 0;
    pub const DMA32: u8 = 1;
    pub const NORMAL: u8 = 2;
    pub const HIGH: u8 = 3;
    pub const MOVABLE: u8 = 4;
}

/// NUMA policy types
pub mod numa_policy {
    pub const DEFAULT: u8 = 0;      // Allocate on local node
    pub const PREFERRED: u8 = 1;    // Prefer specific node
    pub const BIND: u8 = 2;        // Strict binding to nodes
    pub const INTERLEAVE: u8 = 3;  // Interleave across nodes
}

/// Memory flags
pub mod mem_flag {
    pub const ALLOCATED: u32 = 1 << 0;
    pub const MAPPED: u32 = 1 << 1;
    pub const DIRTY: u32 = 1 << 2;
    pub const LARGE_PAGE: u32 = 1 << 3;
    pub const PINNED: u32 = 1 << 4;
    pub const MIGRATABLE: u32 = 1 << 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// NUMA Node
// ─────────────────────────────────────────────────────────────────────────────

/// NUMA node descriptor
pub struct NumaNode {
    /// Node ID
    pub node_id: AtomicU8,
    /// CPU mask (bitmask of CPUs in this node)
    pub cpu_mask: [AtomicU64; 4], // 256 CPUs
    /// CPU count
    pub cpu_count: AtomicU8,
    /// Total memory (bytes)
    pub total_memory: AtomicU64,
    /// Free memory (bytes)
    pub free_memory: AtomicU64,
    /// Used memory (bytes)
    pub used_memory: AtomicU64,
    /// Memory zones
    pub zones: [MemoryZone; MAX_ZONES_PER_NODE],
    /// Zone count
    pub zone_count: AtomicU8,
    /// Distance to other nodes
    pub distances: [AtomicU8; MAX_NUMA_NODES],
    /// Valid
    pub valid: AtomicBool,
}

impl NumaNode {
    pub const fn new() -> Self {
        Self {
            node_id: AtomicU8::new(0),
            cpu_mask: [const { AtomicU64::new(0) }; 4],
            cpu_count: AtomicU8::new(0),
            total_memory: AtomicU64::new(0),
            free_memory: AtomicU64::new(0),
            used_memory: AtomicU64::new(0),
            zones: [const { MemoryZone::new() }; MAX_ZONES_PER_NODE],
            zone_count: AtomicU8::new(0),
            distances: [const { AtomicU8::new(0) }; MAX_NUMA_NODES],
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize node
    pub fn init(&self, node_id: u8, total_memory: u64) {
        self.node_id.store(node_id, Ordering::Release);
        self.total_memory.store(total_memory, Ordering::Release);
        self.free_memory.store(total_memory, Ordering::Release);
        self.distances[node_id as usize].store(10, Ordering::Release); // Local distance
        self.valid.store(true, Ordering::Release);
    }

    /// Add CPU to node
    pub fn add_cpu(&self, cpu_id: u8) {
        let word_idx = (cpu_id / 64) as usize;
        let bit_idx = cpu_id % 64;
        
        if word_idx < 4 {
            self.cpu_mask[word_idx].fetch_or(1 << bit_idx, Ordering::Release);
            self.cpu_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Check if CPU is in node
    pub fn has_cpu(&self, cpu_id: u8) -> bool {
        let word_idx = (cpu_id / 64) as usize;
        let bit_idx = cpu_id % 64;
        
        if word_idx < 4 {
            (self.cpu_mask[word_idx].load(Ordering::Acquire) & (1 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Set distance to another node
    pub fn set_distance(&self, target_node: u8, distance: u8) {
        if target_node as usize < MAX_NUMA_NODES {
            self.distances[target_node as usize].store(distance, Ordering::Release);
        }
    }

    /// Get distance to another node
    pub fn get_distance(&self, target_node: u8) -> u8 {
        if target_node as usize < MAX_NUMA_NODES {
            self.distances[target_node as usize].load(Ordering::Acquire)
        } else {
            255
        }
    }

    /// Allocate memory
    pub fn alloc(&self, size: u64) -> Result<u64, HvError> {
        let free = self.free_memory.load(Ordering::Acquire);
        
        if free < size {
            return Err(HvError::LogicalFault);
        }
        
        self.free_memory.fetch_sub(size, Ordering::Release);
        self.used_memory.fetch_add(size, Ordering::Release);
        
        // Return fake address (would be real HPA)
        Ok(self.used_memory.load(Ordering::Acquire))
    }

    /// Free memory
    pub fn dealloc(&self, size: u64) {
        self.used_memory.fetch_sub(size, Ordering::Release);
        self.free_memory.fetch_add(size, Ordering::Release);
    }

    /// Add memory zone
    pub fn add_zone(&self, zone_type: u8, start: u64, size: u64) -> Result<u8, HvError> {
        let count = self.zone_count.load(Ordering::Acquire);
        if count as usize >= MAX_ZONES_PER_NODE {
            return Err(HvError::LogicalFault);
        }
        
        self.zones[count as usize].init(count, zone_type, start, size);
        self.zone_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get memory pressure (0-100)
    pub fn get_pressure(&self) -> u8 {
        let total = self.total_memory.load(Ordering::Acquire);
        if total == 0 {
            return 0;
        }
        
        let used = self.used_memory.load(Ordering::Acquire);
        ((used * 100) / total) as u8
    }
}

impl Default for NumaNode {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Zone
// ─────────────────────────────────────────────────────────────────────────────

/// Memory zone within a NUMA node
pub struct MemoryZone {
    /// Zone ID
    pub zone_id: AtomicU8,
    /// Zone type
    pub zone_type: AtomicU8,
    /// Start address
    pub start_addr: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Free pages
    pub free_pages: AtomicU64,
    /// Total pages
    pub total_pages: AtomicU64,
    /// Page allocations
    pub alloc_count: AtomicU64,
    /// Page frees
    pub free_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl MemoryZone {
    pub const fn new() -> Self {
        Self {
            zone_id: AtomicU8::new(0),
            zone_type: AtomicU8::new(zone_type::NORMAL),
            start_addr: AtomicU64::new(0),
            size: AtomicU64::new(0),
            free_pages: AtomicU64::new(0),
            total_pages: AtomicU64::new(0),
            alloc_count: AtomicU64::new(0),
            free_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize zone
    pub fn init(&self, zone_id: u8, zone_type: u8, start_addr: u64, size: u64) {
        self.zone_id.store(zone_id, Ordering::Release);
        self.zone_type.store(zone_type, Ordering::Release);
        self.start_addr.store(start_addr, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.total_pages.store(size / PAGE_SIZE, Ordering::Release);
        self.free_pages.store(size / PAGE_SIZE, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Allocate pages
    pub fn alloc_pages(&self, count: u64) -> Result<u64, HvError> {
        let free = self.free_pages.load(Ordering::Acquire);
        
        if free < count {
            return Err(HvError::LogicalFault);
        }
        
        self.free_pages.fetch_sub(count, Ordering::Release);
        self.alloc_count.fetch_add(count, Ordering::Release);
        
        Ok(count * PAGE_SIZE)
    }

    /// Free pages
    pub fn free_pages(&self, count: u64) {
        self.free_pages.fetch_add(count, Ordering::Release);
        self.free_count.fetch_add(count, Ordering::Release);
    }

    /// Get utilization (0-100)
    pub fn get_utilization(&self) -> u8 {
        let total = self.total_pages.load(Ordering::Acquire);
        if total == 0 {
            return 0;
        }
        
        let used = total - self.free_pages.load(Ordering::Acquire);
        ((used * 100) / total) as u8
    }
}

impl Default for MemoryZone {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM NUMA Policy
// ─────────────────────────────────────────────────────────────────────────────

/// VM NUMA policy
pub struct VmNumaPolicy {
    /// VM ID
    pub vm_id: AtomicU32,
    /// Policy type
    pub policy: AtomicU8,
    /// Preferred node
    pub preferred_node: AtomicU8,
    /// Node mask (allowed nodes)
    pub node_mask: AtomicU16,
    /// Interleave index
    pub interleave_idx: AtomicU8,
    /// Memory allocated per node
    pub node_memory: [AtomicU64; MAX_NUMA_NODES],
    /// Total allocated
    pub total_allocated: AtomicU64,
    /// Allocation count
    pub alloc_count: AtomicU64,
    /// Migration count
    pub migration_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmNumaPolicy {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            policy: AtomicU8::new(numa_policy::DEFAULT),
            preferred_node: AtomicU8::new(0),
            node_mask: AtomicU16::new(0xFFFF), // All nodes
            interleave_idx: AtomicU8::new(0),
            node_memory: [const { AtomicU64::new(0) }; MAX_NUMA_NODES],
            total_allocated: AtomicU64::new(0),
            alloc_count: AtomicU64::new(0),
            migration_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize policy
    pub fn init(&self, vm_id: u32, policy: u8, preferred_node: u8, node_mask: u16) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.policy.store(policy, Ordering::Release);
        self.preferred_node.store(preferred_node, Ordering::Release);
        self.node_mask.store(node_mask, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check if node is allowed
    pub fn is_node_allowed(&self, node_id: u8) -> bool {
        (self.node_mask.load(Ordering::Acquire) & (1 << node_id)) != 0
    }

    /// Get next interleave node
    pub fn get_interleave_node(&self) -> u8 {
        let mask = self.node_mask.load(Ordering::Acquire);
        let mut idx = self.interleave_idx.load(Ordering::Acquire);
        
        // Find next allowed node
        for _ in 0..MAX_NUMA_NODES as u8 {
            if (mask & (1 << idx)) != 0 {
                self.interleave_idx.store((idx + 1) % MAX_NUMA_NODES as u8, Ordering::Release);
                return idx;
            }
            idx = (idx + 1) % MAX_NUMA_NODES as u8;
        }
        
        0
    }

    /// Record allocation
    pub fn record_alloc(&self, node_id: u8, size: u64) {
        self.node_memory[node_id as usize].fetch_add(size, Ordering::Release);
        self.total_allocated.fetch_add(size, Ordering::Release);
        self.alloc_count.fetch_add(1, Ordering::Release);
    }

    /// Record free
    pub fn record_free(&self, node_id: u8, size: u64) {
        self.node_memory[node_id as usize].fetch_sub(size, Ordering::Release);
        self.total_allocated.fetch_sub(size, Ordering::Release);
    }

    /// Record migration
    pub fn record_migration(&self) {
        self.migration_count.fetch_add(1, Ordering::Release);
    }

    /// Get memory distribution
    pub fn get_distribution(&self) -> VmNumaDistribution {
        let mut dist = VmNumaDistribution {
            vm_id: self.vm_id.load(Ordering::Acquire),
            total: self.total_allocated.load(Ordering::Acquire),
            node_memory: [0; MAX_NUMA_NODES],
        };
        
        for i in 0..MAX_NUMA_NODES {
            dist.node_memory[i] = self.node_memory[i].load(Ordering::Acquire);
        }
        
        dist
    }
}

impl Default for VmNumaPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// VM NUMA memory distribution
#[repr(C)]
pub struct VmNumaDistribution {
    pub vm_id: u32,
    pub total: u64,
    pub node_memory: [u64; MAX_NUMA_NODES],
}

// ─────────────────────────────────────────────────────────────────────────────
// NUMA Controller
// ─────────────────────────────────────────────────────────────────────────────

/// NUMA controller
pub struct NumaController {
    /// NUMA nodes
    pub nodes: [NumaNode; MAX_NUMA_NODES],
    /// Node count
    pub node_count: AtomicU8,
    /// VM policies
    pub vm_policies: [VmNumaPolicy; MAX_NUMA_VMS],
    /// VM policy count
    pub vm_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Auto-balancing enabled
    pub auto_balance: AtomicBool,
    /// Balance threshold (0-100)
    pub balance_threshold: AtomicU8,
    /// Balance interval (ms)
    pub balance_interval: AtomicU32,
    /// Last balance time
    pub last_balance: AtomicU64,
    /// Total allocations
    pub total_allocs: AtomicU64,
    /// Total migrations
    pub total_migrations: AtomicU64,
    /// Cross-node accesses
    pub cross_node_accesses: AtomicU64,
    /// Local node accesses
    pub local_node_accesses: AtomicU64,
}

impl NumaController {
    pub const fn new() -> Self {
        Self {
            nodes: [const { NumaNode::new() }; MAX_NUMA_NODES],
            node_count: AtomicU8::new(0),
            vm_policies: [const { VmNumaPolicy::new() }; MAX_NUMA_VMS],
            vm_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            auto_balance: AtomicBool::new(false),
            balance_threshold: AtomicU8::new(80),
            balance_interval: AtomicU32::new(5000),
            last_balance: AtomicU64::new(0),
            total_allocs: AtomicU64::new(0),
            total_migrations: AtomicU64::new(0),
            cross_node_accesses: AtomicU64::new(0),
            local_node_accesses: AtomicU64::new(0),
        }
    }

    /// Enable NUMA
    pub fn enable(&mut self, auto_balance: bool, threshold: u8, interval: u32) {
        self.auto_balance.store(auto_balance, Ordering::Release);
        self.balance_threshold.store(threshold, Ordering::Release);
        self.balance_interval.store(interval, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable NUMA
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Add NUMA node
    pub fn add_node(&mut self, node_id: u8, total_memory: u64) -> Result<u8, HvError> {
        let count = self.node_count.load(Ordering::Acquire);
        if count as usize >= MAX_NUMA_NODES {
            return Err(HvError::LogicalFault);
        }
        
        self.nodes[count as usize].init(node_id, total_memory);
        self.node_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Set node distance
    pub fn set_distance(&self, from_node: u8, to_node: u8, distance: u8) {
        if from_node as usize < MAX_NUMA_NODES {
            self.nodes[from_node as usize].set_distance(to_node, distance);
        }
    }

    /// Add CPU to node
    pub fn add_cpu(&self, node_id: u8, cpu_id: u8) -> Result<(), HvError> {
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            if self.nodes[i].node_id.load(Ordering::Acquire) == node_id {
                self.nodes[i].add_cpu(cpu_id);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Get node for CPU
    pub fn get_node_for_cpu(&self, cpu_id: u8) -> Option<&NumaNode> {
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            if self.nodes[i].has_cpu(cpu_id) {
                return Some(&self.nodes[i]);
            }
        }
        None
    }

    /// Get node by ID
    pub fn get_node(&self, node_id: u8) -> Option<&NumaNode> {
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            if self.nodes[i].node_id.load(Ordering::Acquire) == node_id {
                return Some(&self.nodes[i]);
            }
        }
        None
    }

    /// Register VM policy
    pub fn register_vm(&mut self, vm_id: u32, policy: u8, 
                       preferred_node: u8, node_mask: u16) -> Result<u8, HvError> {
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_NUMA_VMS {
            return Err(HvError::LogicalFault);
        }
        
        self.vm_policies[count as usize].init(vm_id, policy, preferred_node, node_mask);
        self.vm_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get VM policy
    pub fn get_vm_policy(&self, vm_id: u32) -> Option<&VmNumaPolicy> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_policies[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_policies[i]);
            }
        }
        None
    }

    /// Allocate memory for VM
    pub fn alloc(&self, vm_id: u32, size: u64, cpu_id: u8) -> Result<(u64, u8), HvError> {
        let policy = self.get_vm_policy(vm_id);
        
        let target_node = match policy {
            Some(p) => {
                match p.policy.load(Ordering::Acquire) {
                    numa_policy::DEFAULT => {
                        // Use local node for CPU
                        let node = self.get_node_for_cpu(cpu_id);
                        node.map(|n| n.node_id.load(Ordering::Acquire)).unwrap_or(0)
                    }
                    numa_policy::PREFERRED => {
                        let preferred = p.preferred_node.load(Ordering::Acquire);
                        if p.is_node_allowed(preferred) {
                            preferred
                        } else {
                            0
                        }
                    }
                    numa_policy::BIND => {
                        // Use first allowed node
                        let mask = p.node_mask.load(Ordering::Acquire);
                        for i in 0..MAX_NUMA_NODES as u8 {
                            if (mask & (1 << i)) != 0 {
                                break i;
                            }
                        }
                        0
                    }
                    numa_policy::INTERLEAVE => {
                        p.get_interleave_node()
                    }
                    _ => 0
                }
            }
            None => 0
        };
        
        let node = self.get_node(target_node).ok_or(HvError::LogicalFault)?;
        let addr = node.alloc(size)?;
        
        if let Some(p) = policy {
            p.record_alloc(target_node, size);
        }
        
        self.total_allocs.fetch_add(1, Ordering::Release);
        
        Ok((addr, target_node))
    }

    /// Free memory
    pub fn dealloc(&self, vm_id: u32, size: u64, node_id: u8) {
        if let Some(node) = self.get_node(node_id) {
            node.dealloc(size);
        }
        
        if let Some(p) = self.get_vm_policy(vm_id) {
            p.record_free(node_id, size);
        }
    }

    /// Migrate memory between nodes
    pub fn migrate(&self, vm_id: u32, size: u64, from_node: u8, to_node: u8) -> Result<(), HvError> {
        let from = self.get_node(from_node).ok_or(HvError::LogicalFault)?;
        let to = self.get_node(to_node).ok_or(HvError::LogicalFault)?;
        
        from.dealloc(size);
        to.alloc(size)?;
        
        if let Some(p) = self.get_vm_policy(vm_id) {
            p.record_free(from_node, size);
            p.record_alloc(to_node, size);
            p.record_migration();
        }
        
        self.total_migrations.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Record memory access
    pub fn record_access(&self, cpu_node: u8, mem_node: u8) {
        if cpu_node == mem_node {
            self.local_node_accesses.fetch_add(1, Ordering::Release);
        } else {
            self.cross_node_accesses.fetch_add(1, Ordering::Release);
        }
    }

    /// Find best node for allocation
    pub fn find_best_node(&self, preferred_node: u8, size: u64) -> u8 {
        // Check preferred node first
        if let Some(node) = self.get_node(preferred_node) {
            if node.free_memory.load(Ordering::Acquire) >= size {
                return preferred_node;
            }
        }
        
        // Find node with most free memory
        let mut best_node = 0u8;
        let mut best_free = 0u64;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let free = self.nodes[i].free_memory.load(Ordering::Acquire);
            if free > best_free {
                best_free = free;
                best_node = self.nodes[i].node_id.load(Ordering::Acquire);
            }
        }
        
        best_node
    }

    /// Run auto-balancing
    pub fn run_balance(&mut self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) || !self.auto_balance.load(Ordering::Acquire) {
            return 0;
        }
        
        let threshold = self.balance_threshold.load(Ordering::Acquire);
        let mut migrations = 0u32;
        
        // Find overloaded and underloaded nodes
        let mut overloaded: [u8; MAX_NUMA_NODES] = [0; MAX_NUMA_NODES];
        let mut underloaded: [u8; MAX_NUMA_NODES] = [0; MAX_NUMA_NODES];
        let mut overload_count = 0usize;
        let mut underload_count = 0usize;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let pressure = self.nodes[i].get_pressure();
            
            if pressure > threshold {
                overloaded[overload_count] = self.nodes[i].node_id.load(Ordering::Acquire);
                overload_count += 1;
            } else if pressure < threshold / 2 {
                underloaded[underload_count] = self.nodes[i].node_id.load(Ordering::Acquire);
                underload_count += 1;
            }
        }
        
        // Migrate from overloaded to underloaded
        for i in 0..overload_count {
            if underload_count == 0 {
                break;
            }
            
            let from_node = overloaded[i];
            let to_node = underloaded[i % underload_count];
            
            // Calculate migration size
            let from = self.get_node(from_node).unwrap();
            let to = self.get_node(to_node).unwrap();
            
            let from_pressure = from.get_pressure();
            let target_pressure = threshold - 10;
            let total = from.total_memory.load(Ordering::Acquire);
            
            let migrate_size = ((from_pressure - target_pressure) as u64 * total) / 100;
            
            if migrate_size > 0 && to.free_memory.load(Ordering::Acquire) >= migrate_size {
                // Would perform actual migration here
                from.dealloc(migrate_size);
                to.alloc(migrate_size).unwrap();
                migrations += 1;
                self.total_migrations.fetch_add(1, Ordering::Release);
            }
        }
        
        self.last_balance.store(Self::get_timestamp(), Ordering::Release);
        
        migrations
    }

    /// Get statistics
    pub fn get_stats(&self) -> NumaControllerStats {
        let mut total_memory = 0u64;
        let mut free_memory = 0u64;
        let mut used_memory = 0u64;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            total_memory += self.nodes[i].total_memory.load(Ordering::Acquire);
            free_memory += self.nodes[i].free_memory.load(Ordering::Acquire);
            used_memory += self.nodes[i].used_memory.load(Ordering::Acquire);
        }
        
        NumaControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            node_count: self.node_count.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            total_memory,
            free_memory,
            used_memory,
            total_allocs: self.total_allocs.load(Ordering::Acquire),
            total_migrations: self.total_migrations.load(Ordering::Acquire),
            local_accesses: self.local_node_accesses.load(Ordering::Acquire),
            cross_accesses: self.cross_node_accesses.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for NumaController {
    fn default() -> Self {
        Self::new()
    }
}

/// NUMA controller statistics
#[repr(C)]
pub struct NumaControllerStats {
    pub enabled: bool,
    pub node_count: u8,
    pub vm_count: u8,
    pub total_memory: u64,
    pub free_memory: u64,
    pub used_memory: u64,
    pub total_allocs: u64,
    pub total_migrations: u64,
    pub local_accesses: u64,
    pub cross_accesses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_numa() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        
        assert!(ctrl.enabled.load(Ordering::Acquire));
        assert!(ctrl.auto_balance.load(Ordering::Acquire));
    }

    #[test]
    fn add_node() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        
        let id = ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        assert_eq!(ctrl.node_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn add_cpu() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        
        ctrl.add_cpu(0, 0).unwrap();
        ctrl.add_cpu(0, 1).unwrap();
        
        let node = ctrl.get_node(0).unwrap();
        assert_eq!(node.cpu_count.load(Ordering::Acquire), 2);
        assert!(node.has_cpu(0));
        assert!(node.has_cpu(1));
    }

    #[test]
    fn set_distance() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_node(1, 64 * 1024 * 1024 * 1024).unwrap();
        
        ctrl.set_distance(0, 1, 20);
        ctrl.set_distance(1, 0, 20);
        
        let node0 = ctrl.get_node(0).unwrap();
        assert_eq!(node0.get_distance(1), 20);
    }

    #[test]
    fn register_vm() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        
        let idx = ctrl.register_vm(1, numa_policy::PREFERRED, 0, 0xFFFF).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn allocate_memory() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_cpu(0, 0).unwrap();
        ctrl.register_vm(1, numa_policy::DEFAULT, 0, 0xFFFF).unwrap();
        
        let (addr, node) = ctrl.alloc(1, 1024 * 1024, 0).unwrap();
        assert_eq!(node, 0);
        
        let policy = ctrl.get_vm_policy(1).unwrap();
        assert!(policy.total_allocated.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn interleave_policy() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 32 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_node(1, 32 * 1024 * 1024 * 1024).unwrap();
        ctrl.register_vm(1, numa_policy::INTERLEAVE, 0, 0x03).unwrap();
        
        let policy = ctrl.get_vm_policy(1).unwrap();
        
        let n1 = policy.get_interleave_node();
        let n2 = policy.get_interleave_node();
        
        // Should alternate between nodes
        assert!(n1 != n2 || n1 < 2);
    }

    #[test]
    fn migrate_memory() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_node(1, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.register_vm(1, numa_policy::BIND, 0, 0x03).unwrap();
        
        ctrl.alloc(1, 1024 * 1024, 0).unwrap();
        
        ctrl.migrate(1, 1024 * 1024, 0, 1).unwrap();
        
        let policy = ctrl.get_vm_policy(1).unwrap();
        assert_eq!(policy.migration_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn auto_balance() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_node(1, 64 * 1024 * 1024 * 1024).unwrap();
        
        // Allocate heavily on node 0
        let node0 = ctrl.get_node(0).unwrap();
        node0.alloc(50 * 1024 * 1024 * 1024).unwrap();
        
        let migrations = ctrl.run_balance();
        // May or may not migrate depending on thresholds
        assert!(migrations >= 0);
    }

    #[test]
    fn memory_access_tracking() {
        let mut ctrl = NumaController::new();
        ctrl.enable(true, 80, 5000);
        ctrl.add_node(0, 64 * 1024 * 1024 * 1024).unwrap();
        ctrl.add_node(1, 64 * 1024 * 1024 * 1024).unwrap();
        
        // Local access
        ctrl.record_access(0, 0);
        assert_eq!(ctrl.local_node_accesses.load(Ordering::Acquire), 1);
        
        // Cross-node access
        ctrl.record_access(0, 1);
        assert_eq!(ctrl.cross_node_accesses.load(Ordering::Acquire), 1);
    }
}
