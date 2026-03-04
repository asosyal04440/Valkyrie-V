//! Fault Tolerance - Checkpointing and High Availability
//!
//! VM checkpoint/restore with HA failover support.
//! Consistent snapshots and coordinated recovery.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Checkpoint types
pub mod ckpt_type {
    pub const FULL: u8 = 0;
    pub const INCREMENTAL: u8 = 1;
    pub const DIFFERENTIAL: u8 = 2;
}

/// Checkpoint states
pub mod ckpt_state {
    pub const NONE: u8 = 0;
    pub const CREATING: u8 = 1;
    pub const CREATED: u8 = 2;
    pub const RESTORING: u8 = 3;
    pub const FAILED: u8 = 4;
}

/// Maximum checkpoints per VM
pub const MAX_CHECKPOINTS: usize = 32;
/// Maximum snapshot size (256 MB)
pub const MAX_SNAPSHOT_SIZE: usize = 256 * 1024 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Structures
// ─────────────────────────────────────────────────────────────────────────────

/// Checkpoint metadata
#[repr(C)]
pub struct CheckpointMeta {
    /// Checkpoint ID
    pub id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Checkpoint type
    pub ckpt_type: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// Creation timestamp
    pub timestamp: AtomicU64,
    /// Parent checkpoint ID (for incremental)
    pub parent_id: AtomicU32,
    /// Memory size
    pub memory_size: AtomicU64,
    /// Compressed size
    pub compressed_size: AtomicU64,
    /// CPU state size
    pub cpu_state_size: AtomicU32,
    /// Device state size
    pub device_state_size: AtomicU32,
    /// Checksum (CRC32)
    pub checksum: AtomicU32,
    /// Valid flag
    pub valid: AtomicBool,
}

impl CheckpointMeta {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            ckpt_type: AtomicU8::new(ckpt_type::FULL),
            state: AtomicU8::new(ckpt_state::NONE),
            timestamp: AtomicU64::new(0),
            parent_id: AtomicU32::new(0),
            memory_size: AtomicU64::new(0),
            compressed_size: AtomicU64::new(0),
            cpu_state_size: AtomicU32::new(0),
            device_state_size: AtomicU32::new(0),
            checksum: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

/// Snapshot header
#[repr(C)]
pub struct SnapshotHeader {
    /// Magic number
    pub magic: u32,
    /// Version
    pub version: u32,
    /// VM ID
    pub vm_id: u32,
    /// Checkpoint ID
    pub ckpt_id: u32,
    /// Creation timestamp
    pub timestamp: u64,
    /// Total size
    pub total_size: u64,
    /// Memory region count
    pub mem_region_count: u32,
    /// vCPU count
    pub vcpu_count: u32,
    /// Device count
    pub device_count: u32,
    /// Flags
    pub flags: u32,
    /// Compression type
    pub compression: u8,
    /// Encryption type
    pub encryption: u8,
    /// Reserved
    pub reserved: [u8; 2],
}

/// Snapshot magic number
pub const SNAPSHOT_MAGIC: u32 = 0x564D534E; // "VMSN"
/// Snapshot version
pub const SNAPSHOT_VERSION: u32 = 1;

// ─────────────────────────────────────────────────────────────────────────────
// Checkpoint Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Checkpoint controller
pub struct CheckpointController {
    /// Checkpoints array
    pub checkpoints: [CheckpointMeta; MAX_CHECKPOINTS],
    /// Current checkpoint ID
    pub current_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Auto-checkpoint enabled
    pub auto_enabled: AtomicBool,
    /// Auto-checkpoint interval (ms)
    pub auto_interval: AtomicU32,
    /// Last checkpoint timestamp
    pub last_timestamp: AtomicU64,
    /// Maximum checkpoints to keep
    pub max_keep: AtomicU8,
    /// Compression enabled
    pub compression: AtomicBool,
    /// Encryption enabled
    pub encryption: AtomicBool,
    /// Encryption key handle
    pub enc_key: AtomicU64,
    /// Storage backend handle
    pub storage_handle: AtomicU64,
}

impl CheckpointController {
    pub const fn new() -> Self {
        Self {
            checkpoints: [const { CheckpointMeta::new() }; MAX_CHECKPOINTS],
            current_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            auto_enabled: AtomicBool::new(false),
            auto_interval: AtomicU32::new(60000), // 1 minute
            last_timestamp: AtomicU64::new(0),
            max_keep: AtomicU8::new(5),
            compression: AtomicBool::new(true),
            encryption: AtomicBool::new(false),
            enc_key: AtomicU64::new(0),
            storage_handle: AtomicU64::new(0),
        }
    }

    /// Initialize for VM
    pub fn init(&mut self, vm_id: u32, storage_handle: u64) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.storage_handle.store(storage_handle, Ordering::Release);
    }

    /// Create full checkpoint
    pub fn create_full(&mut self) -> Result<u32, HvError> {
        let ckpt_id = self.allocate_checkpoint()?;
        
        let ckpt = &self.checkpoints[ckpt_id as usize];
        ckpt.id.store(ckpt_id, Ordering::Release);
        ckpt.vm_id.store(self.vm_id.load(Ordering::Acquire), Ordering::Release);
        ckpt.ckpt_type.store(ckpt_type::FULL, Ordering::Release);
        ckpt.state.store(ckpt_state::CREATING, Ordering::Release);
        ckpt.parent_id.store(0, Ordering::Release);
        
        // Pause VM for consistent snapshot
        // Would call vm_pause() here
        
        let timestamp = Self::get_timestamp();
        ckpt.timestamp.store(timestamp, Ordering::Release);
        
        // Capture memory state
        let mem_size = self.capture_memory()?;
        ckpt.memory_size.store(mem_size, Ordering::Release);
        
        // Capture CPU state
        let cpu_size = self.capture_cpu_state()?;
        ckpt.cpu_state_size.store(cpu_size, Ordering::Release);
        
        // Capture device state
        let dev_size = self.capture_device_state()?;
        ckpt.device_state_size.store(dev_size, Ordering::Release);
        
        // Compress if enabled
        let compressed_size = if self.compression.load(Ordering::Acquire) {
            self.compress_checkpoint(ckpt_id)?
        } else {
            mem_size + cpu_size as u64 + dev_size as u64
        };
        ckpt.compressed_size.store(compressed_size, Ordering::Release);
        
        // Calculate checksum
        let checksum = self.calculate_checksum(ckpt_id);
        ckpt.checksum.store(checksum, Ordering::Release);
        
        // Resume VM
        // Would call vm_resume() here
        
        ckpt.state.store(ckpt_state::CREATED, Ordering::Release);
        ckpt.valid.store(true, Ordering::Release);
        
        self.last_timestamp.store(timestamp, Ordering::Release);
        self.current_id.store(ckpt_id, Ordering::Release);
        
        // Cleanup old checkpoints
        self.cleanup_old_checkpoints();
        
        Ok(ckpt_id)
    }

    /// Create incremental checkpoint
    pub fn create_incremental(&mut self) -> Result<u32, HvError> {
        let parent_id = self.current_id.load(Ordering::Acquire);
        if parent_id == 0 {
            // No parent, create full checkpoint instead
            return self.create_full();
        }
        
        let ckpt_id = self.allocate_checkpoint()?;
        
        let ckpt = &self.checkpoints[ckpt_id as usize];
        ckpt.id.store(ckpt_id, Ordering::Release);
        ckpt.vm_id.store(self.vm_id.load(Ordering::Acquire), Ordering::Release);
        ckpt.ckpt_type.store(ckpt_type::INCREMENTAL, Ordering::Release);
        ckpt.state.store(ckpt_state::CREATING, Ordering::Release);
        ckpt.parent_id.store(parent_id, Ordering::Release);
        
        // Capture only changed memory (dirty pages)
        let mem_size = self.capture_dirty_memory(parent_id)?;
        ckpt.memory_size.store(mem_size, Ordering::Release);
        
        let cpu_size = self.capture_cpu_state()?;
        ckpt.cpu_state_size.store(cpu_size, Ordering::Release);
        
        let dev_size = self.capture_device_state()?;
        ckpt.device_state_size.store(dev_size, Ordering::Release);
        
        ckpt.state.store(ckpt_state::CREATED, Ordering::Release);
        ckpt.valid.store(true, Ordering::Release);
        
        self.current_id.store(ckpt_id, Ordering::Release);
        
        Ok(ckpt_id)
    }

    /// Restore from checkpoint
    pub fn restore(&mut self, ckpt_id: u32) -> Result<(), HvError> {
        if ckpt_id as usize >= MAX_CHECKPOINTS {
            return Err(HvError::LogicalFault);
        }
        
        // Extract all needed values first to avoid borrow conflicts
        let (valid, is_incremental, stored_checksum) = {
            let ckpt = &self.checkpoints[ckpt_id as usize];
            let valid = ckpt.valid.load(Ordering::Acquire);
            let is_incremental = ckpt.ckpt_type.load(Ordering::Acquire) == ckpt_type::INCREMENTAL;
            let stored_checksum = ckpt.checksum.load(Ordering::Acquire);
            (valid, is_incremental, stored_checksum)
        };
        
        if !valid {
            return Err(HvError::LogicalFault);
        }
        
        self.checkpoints[ckpt_id as usize].state.store(ckpt_state::RESTORING, Ordering::Release);
        
        // Verify checksum
        let calc_checksum = self.calculate_checksum(ckpt_id);
        if stored_checksum != calc_checksum {
            self.checkpoints[ckpt_id as usize].state.store(ckpt_state::FAILED, Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        // For incremental, restore chain
        if is_incremental {
            self.restore_chain(ckpt_id)?;
        } else {
            // Full checkpoint restore
            self.restore_memory(ckpt_id)?;
            self.restore_cpu_state(ckpt_id)?;
            self.restore_device_state(ckpt_id)?;
        }
        
        self.checkpoints[ckpt_id as usize].state.store(ckpt_state::CREATED, Ordering::Release);
        
        Ok(())
    }

    /// Restore checkpoint chain (for incremental)
    fn restore_chain(&mut self, ckpt_id: u32) -> Result<(), HvError> {
        // Build restore chain
        let mut chain = [0u32; MAX_CHECKPOINTS];
        let mut chain_len = 0;
        let mut current = ckpt_id;
        
        while current != 0 && chain_len < MAX_CHECKPOINTS {
            chain[chain_len] = current;
            chain_len += 1;
            
            let ckpt = &self.checkpoints[current as usize];
            current = ckpt.parent_id.load(Ordering::Acquire);
        }
        
        // Restore in reverse order (oldest first)
        for i in (0..chain_len).rev() {
            let id = chain[i];
            let ckpt = &self.checkpoints[id as usize];
            
            if ckpt.ckpt_type.load(Ordering::Acquire) == ckpt_type::FULL {
                self.restore_memory(id)?;
            } else {
                self.restore_dirty_memory(id)?;
            }
            
            self.restore_cpu_state(id)?;
            self.restore_device_state(id)?;
        }
        
        Ok(())
    }

    /// Delete checkpoint
    pub fn delete(&mut self, ckpt_id: u32) -> Result<(), HvError> {
        if ckpt_id as usize >= MAX_CHECKPOINTS {
            return Err(HvError::LogicalFault);
        }
        
        let ckpt = &self.checkpoints[ckpt_id as usize];
        if !ckpt.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Check if other checkpoints depend on this one
        for i in 0..MAX_CHECKPOINTS {
            if i == ckpt_id as usize {
                continue; // Skip self
            }
            let other = &self.checkpoints[i];
            if other.valid.load(Ordering::Acquire) && 
               other.parent_id.load(Ordering::Acquire) == ckpt_id {
                return Err(HvError::LogicalFault); // Has dependents
            }
        }
        
        // Free storage
        self.free_checkpoint_storage(ckpt_id)?;
        
        // Invalidate
        ckpt.valid.store(false, Ordering::Release);
        ckpt.state.store(ckpt_state::NONE, Ordering::Release);
        
        Ok(())
    }

    /// Allocate checkpoint slot
    fn allocate_checkpoint(&self) -> Result<u32, HvError> {
        for i in 0..MAX_CHECKPOINTS {
            let ckpt = &self.checkpoints[i];
            if !ckpt.valid.load(Ordering::Acquire) {
                return Ok(i as u32);
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Cleanup old checkpoints
    fn cleanup_old_checkpoints(&mut self) {
        let max_keep = self.max_keep.load(Ordering::Acquire) as usize;
        let mut count = 0;
        
        // Count valid checkpoints
        for ckpt in &self.checkpoints {
            if ckpt.valid.load(Ordering::Acquire) {
                count += 1;
            }
        }
        
        // Delete oldest if over limit
        while count > max_keep {
            let mut oldest_id = 0;
            let mut oldest_ts = u64::MAX;
            
            for i in 0..MAX_CHECKPOINTS {
                let ckpt = &self.checkpoints[i];
                if ckpt.valid.load(Ordering::Acquire) {
                    let ts = ckpt.timestamp.load(Ordering::Acquire);
                    if ts < oldest_ts {
                        oldest_ts = ts;
                        oldest_id = i;
                    }
                }
            }
            
            // Check if can delete (no dependents)
            let can_delete = self.checkpoints.iter().all(|c| {
                !c.valid.load(Ordering::Acquire) || 
                c.parent_id.load(Ordering::Acquire) != oldest_id as u32
            });
            
            if can_delete {
                let _ = self.delete(oldest_id as u32);
                count -= 1;
            } else {
                break;
            }
        }
    }

    // Placeholder implementations for actual capture/restore
    fn capture_memory(&self) -> Result<u64, HvError> { Ok(0) }
    fn capture_dirty_memory(&self, _parent: u32) -> Result<u64, HvError> { Ok(0) }
    fn capture_cpu_state(&self) -> Result<u32, HvError> { Ok(0) }
    fn capture_device_state(&self) -> Result<u32, HvError> { Ok(0) }
    fn compress_checkpoint(&self, _id: u32) -> Result<u64, HvError> { Ok(0) }
    fn calculate_checksum(&self, _id: u32) -> u32 { 0 }
    fn restore_memory(&self, _id: u32) -> Result<(), HvError> { Ok(()) }
    fn restore_dirty_memory(&self, _id: u32) -> Result<(), HvError> { Ok(()) }
    fn restore_cpu_state(&self, _id: u32) -> Result<(), HvError> { Ok(()) }
    fn restore_device_state(&self, _id: u32) -> Result<(), HvError> { Ok(()) }
    fn free_checkpoint_storage(&self, _id: u32) -> Result<(), HvError> { Ok(()) }
    fn get_timestamp() -> u64 { 0 }
}

impl Default for CheckpointController {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// High Availability Failover
// ─────────────────────────────────────────────────────────────────────────────

/// HA node states
pub mod ha_state {
    pub const UNKNOWN: u8 = 0;
    pub const ACTIVE: u8 = 1;
    pub const STANDBY: u8 = 2;
    pub const FAILED: u8 = 3;
    pub const MAINTENANCE: u8 = 4;
}

/// HA failover modes
pub mod ha_mode {
    pub const ACTIVE_PASSIVE: u8 = 0;
    pub const ACTIVE_ACTIVE: u8 = 1;
}

/// HA node info
#[repr(C)]
pub struct HaNode {
    /// Node ID
    pub node_id: AtomicU32,
    /// Node state
    pub state: AtomicU8,
    /// Heartbeat timestamp
    pub heartbeat: AtomicU64,
    /// Priority (lower = higher priority)
    pub priority: AtomicU8,
    /// Node address
    pub address: AtomicU64,
    /// VMs hosted
    pub vm_count: AtomicU16,
    /// Resources available
    pub cpu_available: AtomicU32,
    pub mem_available: AtomicU64,
}

impl HaNode {
    pub const fn new() -> Self {
        Self {
            node_id: AtomicU32::new(0),
            state: AtomicU8::new(ha_state::UNKNOWN),
            heartbeat: AtomicU64::new(0),
            priority: AtomicU8::new(0),
            address: AtomicU64::new(0),
            vm_count: AtomicU16::new(0),
            cpu_available: AtomicU32::new(0),
            mem_available: AtomicU64::new(0),
        }
    }
}

/// Maximum HA nodes
pub const MAX_HA_NODES: usize = 16;

/// HA Controller
pub struct HaController {
    /// Local node ID
    pub local_node_id: AtomicU32,
    /// Failover mode
    pub mode: AtomicU8,
    /// Heartbeat interval (ms)
    pub heartbeat_interval: AtomicU32,
    /// Heartbeat timeout (ms)
    pub heartbeat_timeout: AtomicU32,
    /// Nodes array
    pub nodes: [HaNode; MAX_HA_NODES],
    /// Node count
    pub node_count: AtomicU8,
    /// Primary node ID
    pub primary_node: AtomicU32,
    /// Failover in progress
    pub failover_in_progress: AtomicBool,
    /// Automatic failover enabled
    pub auto_failover: AtomicBool,
    /// VM placement policy
    pub placement_policy: AtomicU8,
}

impl HaController {
    pub const fn new() -> Self {
        Self {
            local_node_id: AtomicU32::new(0),
            mode: AtomicU8::new(ha_mode::ACTIVE_PASSIVE),
            heartbeat_interval: AtomicU32::new(1000),
            heartbeat_timeout: AtomicU32::new(5000),
            nodes: [const { HaNode::new() }; MAX_HA_NODES],
            node_count: AtomicU8::new(0),
            primary_node: AtomicU32::new(0),
            failover_in_progress: AtomicBool::new(false),
            auto_failover: AtomicBool::new(true),
            placement_policy: AtomicU8::new(0),
        }
    }

    /// Initialize HA cluster
    pub fn init_cluster(&mut self, local_id: u32, mode: u8) {
        self.local_node_id.store(local_id, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
        self.primary_node.store(local_id, Ordering::Release);
    }

    /// Add node to cluster
    pub fn add_node(&mut self, node_id: u32, address: u64, priority: u8) -> Result<(), HvError> {
        let count = self.node_count.load(Ordering::Acquire) as usize;
        if count >= MAX_HA_NODES {
            return Err(HvError::LogicalFault);
        }
        
        let node = &self.nodes[count];
        node.node_id.store(node_id, Ordering::Release);
        node.address.store(address, Ordering::Release);
        node.priority.store(priority, Ordering::Release);
        node.state.store(ha_state::STANDBY, Ordering::Release);
        
        self.node_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Update heartbeat
    pub fn update_heartbeat(&self, node_id: u32) {
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            if node.node_id.load(Ordering::Acquire) == node_id {
                node.heartbeat.store(Self::get_timestamp(), Ordering::Release);
                break;
            }
        }
    }

    /// Check node health
    pub fn check_health(&self) -> [u32; 16] {
        let now = Self::get_timestamp();
        let timeout = self.heartbeat_timeout.load(Ordering::Acquire) as u64;
        let mut failed: [u32; 16] = [0; 16];
        let mut count = 0;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            let last_hb = node.heartbeat.load(Ordering::Acquire);
            
            if now - last_hb > timeout {
                node.state.store(ha_state::FAILED, Ordering::Release);
                if count < 16 {
                    failed[count] = node.node_id.load(Ordering::Acquire);
                    count += 1;
                }
            }
        }
        
        failed
    }

    /// Initiate failover
    pub fn failover(&mut self, failed_node: u32) -> Result<u32, HvError> {
        if self.failover_in_progress.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.failover_in_progress.store(true, Ordering::Release);
        
        // Find best standby node
        let mut best_node = 0u32;
        let mut best_priority = u8::MAX;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            if node.state.load(Ordering::Acquire) == ha_state::STANDBY ||
               node.state.load(Ordering::Acquire) == ha_state::ACTIVE {
                let priority = node.priority.load(Ordering::Acquire);
                if priority < best_priority {
                    best_priority = priority;
                    best_node = node.node_id.load(Ordering::Acquire);
                }
            }
        }
        
        if best_node == 0 {
            self.failover_in_progress.store(false, Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        // Mark failed node
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            if node.node_id.load(Ordering::Acquire) == failed_node {
                node.state.store(ha_state::FAILED, Ordering::Release);
            }
        }
        
        // Promote standby
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            if node.node_id.load(Ordering::Acquire) == best_node {
                node.state.store(ha_state::ACTIVE, Ordering::Release);
            }
        }
        
        self.primary_node.store(best_node, Ordering::Release);
        self.failover_in_progress.store(false, Ordering::Release);
        
        Ok(best_node)
    }

    /// Get standby nodes
    pub fn get_standby_nodes(&self) -> [u32; 16] {
        let mut standbys: [u32; 16] = [0; 16];
        let mut count = 0;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            let node = &self.nodes[i];
            if node.state.load(Ordering::Acquire) == ha_state::STANDBY {
                if count < 16 {
                    standbys[count] = node.node_id.load(Ordering::Acquire);
                    count += 1;
                }
            }
        }
        
        standbys
    }

    /// Get cluster status
    pub fn get_status(&self) -> HaClusterStatus {
        let mut active_count = 0u8;
        let mut standby_count = 0u8;
        let mut failed_count = 0u8;
        
        for i in 0..self.node_count.load(Ordering::Acquire) as usize {
            match self.nodes[i].state.load(Ordering::Acquire) {
                ha_state::ACTIVE => active_count += 1,
                ha_state::STANDBY => standby_count += 1,
                ha_state::FAILED => failed_count += 1,
                _ => {}
            }
        }
        
        HaClusterStatus {
            primary_node: self.primary_node.load(Ordering::Acquire),
            active_nodes: active_count,
            standby_nodes: standby_count,
            failed_nodes: failed_count,
            failover_in_progress: self.failover_in_progress.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for HaController {
    fn default() -> Self {
        Self::new()
    }
}

/// HA cluster status
#[repr(C)]
pub struct HaClusterStatus {
    pub primary_node: u32,
    pub active_nodes: u8,
    pub standby_nodes: u8,
    pub failed_nodes: u8,
    pub failover_in_progress: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_create() {
        let mut ctrl = CheckpointController::new();
        ctrl.init(1, 0x1000);
        
        let id = ctrl.create_full().unwrap();
        // ID can be 0 (first slot), verify checkpoint is valid
        assert!(ctrl.checkpoints[id as usize].valid.load(Ordering::Acquire));
    }

    #[test]
    fn checkpoint_delete() {
        let mut ctrl = CheckpointController::new();
        ctrl.init(1, 0x1000);
        
        let id = ctrl.create_full().unwrap();
        ctrl.delete(id).unwrap();
        assert!(!ctrl.checkpoints[id as usize].valid.load(Ordering::Acquire));
    }

    #[test]
    fn ha_cluster() {
        let mut ha = HaController::new();
        ha.init_cluster(1, ha_mode::ACTIVE_PASSIVE);
        
        ha.add_node(2, 0x12345678, 10).unwrap();
        ha.add_node(3, 0x87654321, 20).unwrap();
        
        assert_eq!(ha.node_count.load(Ordering::Acquire), 2);
    }

    #[test]
    fn ha_failover() {
        let mut ha = HaController::new();
        ha.init_cluster(1, ha_mode::ACTIVE_PASSIVE);
        ha.add_node(2, 0x12345678, 10).unwrap();
        
        let new_primary = ha.failover(1).unwrap();
        assert_eq!(new_primary, 2);
    }
}
