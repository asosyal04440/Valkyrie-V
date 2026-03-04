//! Incremental Snapshot CBT Enhancement
//!
//! Changed Block Tracking (CBT) for efficient incremental snapshots.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// CBT Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum VMs with CBT
#[cfg(not(test))]
pub const MAX_CBT_VMS: usize = 128;
/// Maximum VMs with CBT (reduced for tests)
#[cfg(test)]
pub const MAX_CBT_VMS: usize = 4;

/// Maximum snapshots per VM
#[cfg(not(test))]
pub const MAX_SNAPSHOTS: usize = 32;
/// Maximum snapshots per VM (reduced for tests)
#[cfg(test)]
pub const MAX_SNAPSHOTS: usize = 4;

/// Maximum change regions per snapshot
#[cfg(not(test))]
pub const MAX_CHANGE_REGIONS: usize = 4096;
/// Maximum change regions per snapshot (reduced for tests)
#[cfg(test)]
pub const MAX_CHANGE_REGIONS: usize = 16;

/// Maximum bitmap size (pages)
#[cfg(not(test))]
pub const MAX_BITMAP_PAGES: usize = 262144; // 1GB with 4KB pages
/// Maximum bitmap size (reduced for tests)
#[cfg(test)]
pub const MAX_BITMAP_PAGES: usize = 64;

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// Snapshot states
pub mod snapshot_state {
    pub const CREATING: u8 = 0;
    pub const READY: u8 = 1;
    pub const ACTIVE: u8 = 2;
    pub const DELETING: u8 = 3;
    pub const MERGING: u8 = 4;
    pub const ERROR: u8 = 5;
}

/// CBT modes
pub mod cbt_mode {
    pub const DISABLED: u8 = 0;
    pub const BITMAP: u8 = 1;      // Bitmap-based tracking
    pub const LOG: u8 = 2;         // Log-based tracking
    pub const HYBRID: u8 = 3;      // Hybrid approach
}

/// Change types
pub mod change_type {
    pub const NONE: u8 = 0;
    pub const WRITE: u8 = 1;
    pub const ALLOC: u8 = 2;
    pub const FREE: u8 = 3;
    pub const TRIM: u8 = 4;
    pub const ZERO: u8 = 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// Change Region
// ─────────────────────────────────────────────────────────────────────────────

/// Changed region descriptor
pub struct ChangeRegion {
    /// Region ID
    pub region_id: AtomicU32,
    /// Start LBA (logical block address)
    pub start_lba: AtomicU64,
    /// Length in sectors
    pub length: AtomicU32,
    /// Change type
    pub change_type: AtomicU8,
    /// First seen snapshot ID
    pub first_snapshot: AtomicU32,
    /// Last seen snapshot ID
    pub last_snapshot: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl ChangeRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU32::new(0),
            start_lba: AtomicU64::new(0),
            length: AtomicU32::new(0),
            change_type: AtomicU8::new(change_type::NONE),
            first_snapshot: AtomicU32::new(0),
            last_snapshot: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u32, start_lba: u64, length: u32, change_type: u8) {
        self.region_id.store(region_id, Ordering::Release);
        self.start_lba.store(start_lba, Ordering::Release);
        self.length.store(length, Ordering::Release);
        self.change_type.store(change_type, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set snapshot range
    pub fn set_snapshots(&self, first: u32, last: u32) {
        self.first_snapshot.store(first, Ordering::Release);
        self.last_snapshot.store(last, Ordering::Release);
    }

    /// Merge with another region
    pub fn merge(&self, other: &ChangeRegion) -> bool {
        let self_start = self.start_lba.load(Ordering::Acquire);
        let self_len = self.length.load(Ordering::Acquire);
        let other_start = other.start_lba.load(Ordering::Acquire);
        let other_len = other.length.load(Ordering::Acquire);
        
        // Check if adjacent or overlapping
        if other_start >= self_start && other_start <= self_start + self_len as u64 {
            let new_end = (self_start + self_len as u64).max(other_start + other_len as u64);
            self.length.store((new_end - self_start) as u32, Ordering::Release);
            return true;
        }
        
        false
    }
}

impl Default for ChangeRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bitmap Block
// ─────────────────────────────────────────────────────────────────────────────

/// Bitmap block (64 pages = 256KB tracked per block)
pub struct BitmapBlock {
    /// Block ID
    pub block_id: AtomicU32,
    /// Bitmap data (each bit = one page)
    pub bitmap: [AtomicU64; 64], // 64 * 64 bits = 4096 pages = 16MB
    /// Set bit count
    pub set_count: AtomicU16,
    /// Valid
    pub valid: AtomicBool,
}

impl BitmapBlock {
    pub const fn new() -> Self {
        Self {
            block_id: AtomicU32::new(0),
            bitmap: [const { AtomicU64::new(0) }; 64],
            set_count: AtomicU16::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize block
    pub fn init(&self, block_id: u32) {
        self.block_id.store(block_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set bit for page
    pub fn set_bit(&self, page_in_block: u32) -> bool {
        if page_in_block >= 4096 {
            return false;
        }
        
        let word_idx = (page_in_block / 64) as usize;
        let bit_idx = page_in_block % 64;
        
        let old = self.bitmap[word_idx].fetch_or(1 << bit_idx, Ordering::Release);
        
        if old & (1 << bit_idx) == 0 {
            self.set_count.fetch_add(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Clear bit for page
    pub fn clear_bit(&self, page_in_block: u32) -> bool {
        if page_in_block >= 4096 {
            return false;
        }
        
        let word_idx = (page_in_block / 64) as usize;
        let bit_idx = page_in_block % 64;
        
        let old = self.bitmap[word_idx].fetch_and(!(1 << bit_idx), Ordering::Release);
        
        if old & (1 << bit_idx) != 0 {
            self.set_count.fetch_sub(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Check bit
    pub fn is_set(&self, page_in_block: u32) -> bool {
        if page_in_block >= 4096 {
            return false;
        }
        
        let word_idx = (page_in_block / 64) as usize;
        let bit_idx = page_in_block % 64;
        
        (self.bitmap[word_idx].load(Ordering::Acquire) & (1 << bit_idx)) != 0
    }

    /// Clear all
    pub fn clear_all(&self) {
        for i in 0..64 {
            self.bitmap[i].store(0, Ordering::Release);
        }
        self.set_count.store(0, Ordering::Release);
    }

    /// Get set pages
    pub fn get_set_pages(&self, pages: &mut [u32; 4096]) -> u32 {
        let mut count = 0u32;
        
        for word_idx in 0..64 {
            let word = self.bitmap[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            
            for bit_idx in 0..64 {
                if word & (1 << bit_idx) != 0 {
                    pages[count as usize] = (word_idx * 64 + bit_idx) as u32;
                    count += 1;
                    if count >= 4096 {
                        return count;
                    }
                }
            }
        }
        
        count
    }
}

impl Default for BitmapBlock {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot descriptor
pub struct Snapshot {
    /// Snapshot ID
    pub snapshot_id: AtomicU32,
    /// Parent snapshot ID
    pub parent_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// State
    pub state: AtomicU8,
    /// Creation timestamp
    pub created: AtomicU64,
    /// Change regions
    pub regions: [ChangeRegion; MAX_CHANGE_REGIONS],
    /// Region count
    pub region_count: AtomicU32,
    /// Changed bytes
    pub changed_bytes: AtomicU64,
    /// Changed sectors
    pub changed_sectors: AtomicU64,
    /// Bitmap blocks
    pub bitmap: [BitmapBlock; 64], // 64 * 16MB = 1GB tracked
    /// Bitmap block count
    pub bitmap_count: AtomicU8,
    /// Is incremental
    pub incremental: AtomicBool,
    /// Consistent (quiesced)
    pub consistent: AtomicBool,
    /// Description hash
    pub desc_hash: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl Snapshot {
    pub const fn new() -> Self {
        Self {
            snapshot_id: AtomicU32::new(0),
            parent_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            state: AtomicU8::new(snapshot_state::CREATING),
            created: AtomicU64::new(0),
            regions: [const { ChangeRegion::new() }; MAX_CHANGE_REGIONS],
            region_count: AtomicU32::new(0),
            changed_bytes: AtomicU64::new(0),
            changed_sectors: AtomicU64::new(0),
            bitmap: [const { BitmapBlock::new() }; 64],
            bitmap_count: AtomicU8::new(0),
            incremental: AtomicBool::new(true),
            consistent: AtomicBool::new(false),
            desc_hash: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize snapshot
    pub fn init(&self, snapshot_id: u32, parent_id: u32, vm_id: u32, incremental: bool) {
        self.snapshot_id.store(snapshot_id, Ordering::Release);
        self.parent_id.store(parent_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.incremental.store(incremental, Ordering::Release);
        self.created.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Mark as ready
    pub fn set_ready(&self) {
        self.state.store(snapshot_state::READY, Ordering::Release);
    }

    /// Mark as active
    pub fn set_active(&self) {
        self.state.store(snapshot_state::ACTIVE, Ordering::Release);
    }

    /// Mark as consistent
    pub fn set_consistent(&self) {
        self.consistent.store(true, Ordering::Release);
    }

    /// Record change (bitmap)
    pub fn record_change_bitmap(&self, lba: u64, sector_count: u32) {
        // Convert LBA to page
        let page = lba / 8; // Assuming 4KB pages, 512 byte sectors
        let block_idx = (page / 4096) as usize;
        let page_in_block = (page % 4096) as u32;
        
        if block_idx >= 64 {
            return;
        }
        
        // Initialize block if needed
        let block = &self.bitmap[block_idx];
        if !block.valid.load(Ordering::Acquire) {
            block.init(block_idx as u32);
            self.bitmap_count.fetch_add(1, Ordering::Release);
        }
        
        // Set bits for all pages in range
        let pages = (sector_count + 7) / 8;
        for i in 0..pages {
            if block.set_bit(page_in_block + i) {
                self.changed_bytes.fetch_add(PAGE_SIZE, Ordering::Release);
            }
        }
        
        self.changed_sectors.fetch_add(sector_count as u64, Ordering::Release);
    }

    /// Record change (region)
    pub fn record_change_region(&self, lba: u64, sector_count: u32, change_type: u8) {
        let count = self.region_count.load(Ordering::Acquire);
        
        // Try to merge with last region
        if count > 0 {
            let last = &self.regions[(count - 1) as usize];
            let last_lba = last.start_lba.load(Ordering::Acquire);
            let last_len = last.length.load(Ordering::Acquire);
            let last_type = last.change_type.load(Ordering::Acquire);
            
            if last_type == change_type && 
               lba == last_lba + last_len as u64 {
                // Extend last region
                last.length.fetch_add(sector_count, Ordering::Release);
                self.changed_sectors.fetch_add(sector_count as u64, Ordering::Release);
                return;
            }
        }
        
        // Create new region
        if count as usize >= MAX_CHANGE_REGIONS {
            return;
        }
        
        let region = &self.regions[count as usize];
        region.init(count, lba, sector_count, change_type);
        region.set_snapshots(self.snapshot_id.load(Ordering::Acquire), 
                             self.snapshot_id.load(Ordering::Acquire));
        
        self.region_count.fetch_add(1, Ordering::Release);
        self.changed_sectors.fetch_add(sector_count as u64, Ordering::Release);
    }

    /// Get changes since parent
    pub fn get_changes(&self, changes: &mut [ChangeRegion]) -> u32 {
        let count = self.region_count.load(Ordering::Acquire);
        let copy_count = count.min(changes.len() as u32);
        
        for i in 0..copy_count as usize {
            let src = &self.regions[i];
            changes[i].region_id.store(src.region_id.load(Ordering::Acquire), Ordering::Release);
            changes[i].start_lba.store(src.start_lba.load(Ordering::Acquire), Ordering::Release);
            changes[i].length.store(src.length.load(Ordering::Acquire), Ordering::Release);
            changes[i].change_type.store(src.change_type.load(Ordering::Acquire), Ordering::Release);
            changes[i].valid.store(true, Ordering::Release);
        }
        
        copy_count
    }

    /// Get changed pages from bitmap
    pub fn get_changed_pages(&self, pages: &mut [u64], max_pages: u32) -> u32 {
        let mut count = 0u32;
        
        for block_idx in 0..self.bitmap_count.load(Ordering::Acquire) as usize {
            let block = &self.bitmap[block_idx];
            if !block.valid.load(Ordering::Acquire) {
                continue;
            }
            
            let mut block_pages = [0u32; 4096];
            let block_count = block.get_set_pages(&mut block_pages);
            
            for i in 0..block_count as usize {
                if count >= max_pages {
                    return count;
                }
                
                pages[count as usize] = (block_idx as u64 * 4096 + block_pages[i] as u64) * PAGE_SIZE;
                count += 1;
            }
        }
        
        count
    }

    /// Merge with parent
    pub fn merge_parent(&self, parent: &Snapshot) -> u32 {
        let mut merged = 0u32;
        
        // Merge regions
        for i in 0..parent.region_count.load(Ordering::Acquire) as usize {
            let parent_region = &parent.regions[i];
            let count = self.region_count.load(Ordering::Acquire);
            
            if count as usize >= MAX_CHANGE_REGIONS {
                break;
            }
            
            // Copy parent region
            let region = &self.regions[count as usize];
            region.init(
                count,
                parent_region.start_lba.load(Ordering::Acquire),
                parent_region.length.load(Ordering::Acquire),
                parent_region.change_type.load(Ordering::Acquire)
            );
            region.set_snapshots(
                parent_region.first_snapshot.load(Ordering::Acquire),
                parent_region.last_snapshot.load(Ordering::Acquire)
            );
            
            self.region_count.fetch_add(1, Ordering::Release);
            merged += 1;
        }
        
        merged
    }

    /// Clear bitmap
    pub fn clear_bitmap(&self) {
        for i in 0..self.bitmap_count.load(Ordering::Acquire) as usize {
            self.bitmap[i].clear_all();
        }
        self.bitmap_count.store(0, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM CBT State
// ─────────────────────────────────────────────────────────────────────────────

/// VM CBT state
pub struct VmCbtState {
    /// VM ID
    pub vm_id: AtomicU32,
    /// CBT mode
    pub cbt_mode: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Snapshots
    pub snapshots: [Snapshot; MAX_SNAPSHOTS],
    /// Snapshot count
    pub snapshot_count: AtomicU8,
    /// Current active snapshot ID
    pub active_snapshot: AtomicU32,
    /// Base snapshot ID
    pub base_snapshot: AtomicU32,
    /// Total disk size
    pub disk_size: AtomicU64,
    /// Total changed bytes
    pub total_changed: AtomicU64,
    /// Total snapshots created
    pub total_snapshots: AtomicU64,
    /// Last snapshot time
    pub last_snapshot: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmCbtState {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            cbt_mode: AtomicU8::new(cbt_mode::BITMAP),
            enabled: AtomicBool::new(false),
            snapshots: [const { Snapshot::new() }; MAX_SNAPSHOTS],
            snapshot_count: AtomicU8::new(0),
            active_snapshot: AtomicU32::new(0),
            base_snapshot: AtomicU32::new(0),
            disk_size: AtomicU64::new(0),
            total_changed: AtomicU64::new(0),
            total_snapshots: AtomicU64::new(0),
            last_snapshot: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize VM CBT
    pub fn init(&self, vm_id: u32, disk_size: u64, mode: u8) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.disk_size.store(disk_size, Ordering::Release);
        self.cbt_mode.store(mode, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Create snapshot
    pub fn create_snapshot(&self, incremental: bool) -> Result<u32, HvError> {
        let count = self.snapshot_count.load(Ordering::Acquire);
        if count as usize >= MAX_SNAPSHOTS {
            return Err(HvError::LogicalFault);
        }
        
        let snapshot_id = count as u32 + 1;
        let parent_id = if incremental && count > 0 {
            self.active_snapshot.load(Ordering::Acquire)
        } else {
            0
        };
        
        let snapshot = &self.snapshots[count as usize];
        snapshot.init(snapshot_id, parent_id, self.vm_id.load(Ordering::Acquire), incremental);
        snapshot.set_ready();
        
        // Deactivate previous snapshot
        if count > 0 {
            let prev = &self.snapshots[(count - 1) as usize];
            prev.state.store(snapshot_state::READY, Ordering::Release);
        }
        
        snapshot.set_active();
        
        self.active_snapshot.store(snapshot_id, Ordering::Release);
        self.snapshot_count.fetch_add(1, Ordering::Release);
        self.total_snapshots.fetch_add(1, Ordering::Release);
        self.last_snapshot.store(Self::get_timestamp(), Ordering::Release);
        
        if count == 0 {
            self.base_snapshot.store(snapshot_id, Ordering::Release);
        }
        
        Ok(snapshot_id)
    }

    /// Get snapshot
    pub fn get_snapshot(&self, snapshot_id: u32) -> Option<&Snapshot> {
        for i in 0..self.snapshot_count.load(Ordering::Acquire) as usize {
            if self.snapshots[i].snapshot_id.load(Ordering::Acquire) == snapshot_id {
                return Some(&self.snapshots[i]);
            }
        }
        None
    }

    /// Record write
    pub fn record_write(&self, lba: u64, sector_count: u32) {
        let active_id = self.active_snapshot.load(Ordering::Acquire);
        if active_id == 0 {
            return;
        }
        
        if let Some(snapshot) = self.get_snapshot(active_id) {
            match self.cbt_mode.load(Ordering::Acquire) {
                cbt_mode::BITMAP | cbt_mode::HYBRID => {
                    snapshot.record_change_bitmap(lba, sector_count);
                }
                cbt_mode::LOG => {
                    snapshot.record_change_region(lba, sector_count, change_type::WRITE);
                }
                _ => {}
            }
            
            self.total_changed.fetch_add(sector_count as u64 * 512, Ordering::Release);
        }
    }

    /// Get incremental changes
    pub fn get_incremental(&self, from_snapshot: u32, to_snapshot: u32) -> Result<Vec<ChangeRegion>, HvError> {
        let mut changes = Vec::new();
        
        // Find snapshot range
        let mut found = false;
        for i in 0..self.snapshot_count.load(Ordering::Acquire) as usize {
            let snapshot = &self.snapshots[i];
            let id = snapshot.snapshot_id.load(Ordering::Acquire);
            
            if id == from_snapshot {
                found = true;
            }
            
            if found {
                // Get changes from this snapshot
                for j in 0..snapshot.region_count.load(Ordering::Acquire) as usize {
                    let region = &snapshot.regions[j];
                    let mut change = ChangeRegion::new();
                    change.init(
                        changes.len() as u32,
                        region.start_lba.load(Ordering::Acquire),
                        region.length.load(Ordering::Acquire),
                        region.change_type.load(Ordering::Acquire)
                    );
                    changes.push(change);
                }
            }
            
            if id == to_snapshot {
                break;
            }
        }
        
        Ok(changes)
    }

    /// Delete snapshot
    pub fn delete_snapshot(&self, snapshot_id: u32) -> Result<(), HvError> {
        let snapshot = self.get_snapshot(snapshot_id).ok_or(HvError::LogicalFault)?;
        
        // Can't delete active snapshot
        if snapshot.state.load(Ordering::Acquire) == snapshot_state::ACTIVE {
            return Err(HvError::LogicalFault);
        }
        
        // Can't delete base snapshot if others exist
        if snapshot_id == self.base_snapshot.load(Ordering::Acquire) &&
           self.snapshot_count.load(Ordering::Acquire) > 1 {
            return Err(HvError::LogicalFault);
        }
        
        snapshot.state.store(snapshot_state::DELETING, Ordering::Release);
        snapshot.valid.store(false, Ordering::Release);
        
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> VmCbtStats {
        VmCbtStats {
            vm_id: self.vm_id.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
            cbt_mode: self.cbt_mode.load(Ordering::Acquire),
            snapshot_count: self.snapshot_count.load(Ordering::Acquire),
            active_snapshot: self.active_snapshot.load(Ordering::Acquire),
            total_changed: self.total_changed.load(Ordering::Acquire),
            total_snapshots: self.total_snapshots.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VmCbtState {
    fn default() -> Self {
        Self::new()
    }
}

/// VM CBT statistics
#[repr(C)]
pub struct VmCbtStats {
    pub vm_id: u32,
    pub enabled: bool,
    pub cbt_mode: u8,
    pub snapshot_count: u8,
    pub active_snapshot: u32,
    pub total_changed: u64,
    pub total_snapshots: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// CBT Controller
// ─────────────────────────────────────────────────────────────────────────────

/// CBT controller
pub struct CbtController {
    /// VM states
    pub vm_states: [VmCbtState; MAX_CBT_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Default CBT mode
    pub default_mode: AtomicU8,
    /// Max snapshots per VM
    pub max_snapshots: AtomicU8,
    /// Auto-consistency (quiesce before snapshot)
    pub auto_consistency: AtomicBool,
    /// Total VMs with CBT
    pub total_vms: AtomicU64,
    /// Total snapshots
    pub total_snapshots: AtomicU64,
    /// Total changed bytes
    pub total_changed: AtomicU64,
    /// Total bytes backed up
    pub total_backed_up: AtomicU64,
}

impl CbtController {
    pub const fn new() -> Self {
        Self {
            vm_states: [const { VmCbtState::new() }; MAX_CBT_VMS],
            vm_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            default_mode: AtomicU8::new(cbt_mode::BITMAP),
            max_snapshots: AtomicU8::new(MAX_SNAPSHOTS as u8),
            auto_consistency: AtomicBool::new(true),
            total_vms: AtomicU64::new(0),
            total_snapshots: AtomicU64::new(0),
            total_changed: AtomicU64::new(0),
            total_backed_up: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, default_mode: u8, auto_consistency: bool) {
        self.default_mode.store(default_mode, Ordering::Release);
        self.auto_consistency.store(auto_consistency, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM
    pub fn register_vm(&mut self, vm_id: u32, disk_size: u64, 
                       mode: Option<u8>) -> Result<u8, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_CBT_VMS {
            return Err(HvError::LogicalFault);
        }
        
        let cbt_mode = mode.unwrap_or(self.default_mode.load(Ordering::Acquire));
        
        let vm_state = &self.vm_states[count as usize];
        vm_state.init(vm_id, disk_size, cbt_mode);
        
        self.vm_count.fetch_add(1, Ordering::Release);
        self.total_vms.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get VM state
    pub fn get_vm_state(&self, vm_id: u32) -> Option<&VmCbtState> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_states[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_states[i]);
            }
        }
        None
    }

    /// Create snapshot
    pub fn create_snapshot(&self, vm_id: u32, incremental: bool) -> Result<u32, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        
        if !vm_state.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let snapshot_id = vm_state.create_snapshot(incremental)?;
        
        self.total_snapshots.fetch_add(1, Ordering::Release);
        
        Ok(snapshot_id)
    }

    /// Record write
    pub fn record_write(&self, vm_id: u32, lba: u64, sector_count: u32) {
        if let Some(vm_state) = self.get_vm_state(vm_id) {
            vm_state.record_write(lba, sector_count);
            self.total_changed.fetch_add(sector_count as u64 * 512, Ordering::Release);
        }
    }

    /// Get incremental changes
    pub fn get_incremental(&self, vm_id: u32, from: u32, to: u32) -> Result<Vec<ChangeRegion>, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.get_incremental(from, to)
    }

    /// Delete snapshot
    pub fn delete_snapshot(&self, vm_id: u32, snapshot_id: u32) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.delete_snapshot(snapshot_id)
    }

    /// Quiesce VM (for consistent snapshot)
    pub fn quiesce_vm(&self, vm_id: u32) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        
        // Would pause I/O, flush caches, etc.
        let active_id = vm_state.active_snapshot.load(Ordering::Acquire);
        if active_id > 0 {
            if let Some(snapshot) = vm_state.get_snapshot(active_id) {
                snapshot.set_consistent();
            }
        }
        
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> CbtControllerStats {
        CbtControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            total_vms: self.total_vms.load(Ordering::Acquire),
            total_snapshots: self.total_snapshots.load(Ordering::Acquire),
            total_changed: self.total_changed.load(Ordering::Acquire),
            total_backed_up: self.total_backed_up.load(Ordering::Acquire),
        }
    }
}

impl Default for CbtController {
    fn default() -> Self {
        Self::new()
    }
}

/// CBT controller statistics
#[repr(C)]
pub struct CbtControllerStats {
    pub enabled: bool,
    pub vm_count: u8,
    pub total_vms: u64,
    pub total_snapshots: u64,
    pub total_changed: u64,
    pub total_backed_up: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vm() {
        let mut ctrl = CbtController::new();
        ctrl.enable(cbt_mode::BITMAP, true);
        
        let idx = ctrl.register_vm(1, 100 * 1024 * 1024 * 1024, None).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn create_snapshot() {
        let mut ctrl = CbtController::new();
        ctrl.enable(cbt_mode::BITMAP, true);
        ctrl.register_vm(1, 100 * 1024 * 1024 * 1024, None).unwrap();
        
        let id = ctrl.create_snapshot(1, false).unwrap();
        assert!(id > 0);
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.snapshot_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn record_write() {
        let mut ctrl = CbtController::new();
        ctrl.enable(cbt_mode::LOG, true);
        ctrl.register_vm(1, 100 * 1024 * 1024 * 1024, None).unwrap();
        ctrl.create_snapshot(1, false).unwrap();
        
        ctrl.record_write(1, 1000, 8); // 8 sectors = 4KB
        
        let vm = ctrl.get_vm_state(1).unwrap();
        let snapshot = vm.get_snapshot(1).unwrap();
        assert!(snapshot.region_count.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn bitmap_tracking() {
        let mut ctrl = CbtController::new();
        ctrl.enable(cbt_mode::BITMAP, true);
        ctrl.register_vm(1, 100 * 1024 * 1024 * 1024, None).unwrap();
        ctrl.create_snapshot(1, false).unwrap();
        
        ctrl.record_write(1, 0, 8); // First page
        ctrl.record_write(1, 4096 * 8, 8); // Page 4096
        
        let vm = ctrl.get_vm_state(1).unwrap();
        let snapshot = vm.get_snapshot(1).unwrap();
        assert!(snapshot.bitmap_count.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn incremental_snapshot() {
        let mut ctrl = CbtController::new();
        ctrl.enable(cbt_mode::LOG, true);
        ctrl.register_vm(1, 100 * 1024 * 1024 * 1024, None).unwrap();
        
        let id1 = ctrl.create_snapshot(1, false).unwrap(); // Base
        ctrl.record_write(1, 1000, 8);
        
        let id2 = ctrl.create_snapshot(1, true).unwrap(); // Incremental
        ctrl.record_write(1, 2000, 8);
        
        let changes = ctrl.get_incremental(1, id1, id2).unwrap();
        assert!(!changes.is_empty());
    }

    #[test]
    fn bitmap_block() {
        let block = BitmapBlock::new();
        block.init(0);
        
        assert!(block.set_bit(0));
        assert!(block.set_bit(100));
        assert!(block.set_bit(4095));
        
        assert!(block.is_set(0));
        assert!(block.is_set(100));
        assert!(!block.is_set(50));
        
        assert_eq!(block.set_count.load(Ordering::Acquire), 3);
    }

    #[test]
    fn change_region_merge() {
        let r1 = ChangeRegion::new();
        r1.init(0, 1000, 8, change_type::WRITE);
        
        let r2 = ChangeRegion::new();
        r2.init(1, 1008, 8, change_type::WRITE);
        
        assert!(r1.merge(&r2));
        assert_eq!(r1.length.load(Ordering::Acquire), 16);
    }
}
