//! Live Snapshot Optimization
//!
//! Non-disruptive VM snapshots with minimal pause time using iterative pre-copy.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Live Snapshot Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum concurrent live snapshots
pub const MAX_LIVE_SNAPSHOTS: usize = 64;

/// Maximum memory regions
pub const MAX_MEM_REGIONS: usize = 32;

/// Maximum dirty pages tracked
pub const MAX_DIRTY_PAGES: usize = 262144; // 1GB with 4KB pages

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// Default iteration threshold (pages)
pub const DEFAULT_ITER_THRESHOLD: u32 = 256;

/// Default max iterations
pub const DEFAULT_MAX_ITERATIONS: u8 = 10;

/// Default bandwidth limit (MB/s)
pub const DEFAULT_BANDWIDTH: u32 = 1000;

/// Snapshot phases
pub mod snap_phase {
    pub const INIT: u8 = 0;
    pub const PRECOPY: u8 = 1;
    pub const STOP_AND_COPY: u8 = 2;
    pub const COMPLETED: u8 = 3;
    pub const FAILED: u8 = 4;
    pub const CANCELLED: u8 = 5;
}

/// Transfer states
pub mod transfer_state {
    pub const PENDING: u8 = 0;
    pub const IN_PROGRESS: u8 = 1;
    pub const COMPLETED: u8 = 2;
    pub const FAILED: u8 = 3;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dirty Page Tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Dirty page bitmap
pub struct DirtyBitmap {
    /// Bitmap words
    pub bitmap: [AtomicU64; 4096], // 4096 * 64 = 262144 pages = 1GB
    /// Set bit count
    pub set_count: AtomicU32,
    /// Generation (incremented on clear)
    pub generation: AtomicU64,
}

impl DirtyBitmap {
    pub const fn new() -> Self {
        Self {
            bitmap: [const { AtomicU64::new(0) }; 4096],
            set_count: AtomicU32::new(0),
            generation: AtomicU64::new(0),
        }
    }

    /// Mark page dirty
    pub fn mark_dirty(&self, page_idx: u32) -> bool {
        if page_idx >= MAX_DIRTY_PAGES as u32 {
            return false;
        }
        
        let word_idx = (page_idx / 64) as usize;
        let bit_idx = page_idx % 64;
        
        let old = self.bitmap[word_idx].fetch_or(1 << bit_idx, Ordering::Release);
        
        if old & (1 << bit_idx) == 0 {
            self.set_count.fetch_add(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Clear page
    pub fn clear_page(&self, page_idx: u32) -> bool {
        if page_idx >= MAX_DIRTY_PAGES as u32 {
            return false;
        }
        
        let word_idx = (page_idx / 64) as usize;
        let bit_idx = page_idx % 64;
        
        let old = self.bitmap[word_idx].fetch_and(!(1 << bit_idx), Ordering::Release);
        
        if old & (1 << bit_idx) != 0 {
            self.set_count.fetch_sub(1, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Check if dirty
    pub fn is_dirty(&self, page_idx: u32) -> bool {
        if page_idx >= MAX_DIRTY_PAGES as u32 {
            return false;
        }
        
        let word_idx = (page_idx / 64) as usize;
        let bit_idx = page_idx % 64;
        
        (self.bitmap[word_idx].load(Ordering::Acquire) & (1 << bit_idx)) != 0
    }

    /// Get dirty page count
    pub fn get_dirty_count(&self) -> u32 {
        self.set_count.load(Ordering::Acquire)
    }

    /// Clear all
    pub fn clear_all(&self) {
        for i in 0..4096 {
            self.bitmap[i].store(0, Ordering::Release);
        }
        self.set_count.store(0, Ordering::Release);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Get dirty pages list
    pub fn get_dirty_pages(&self, pages: &mut [u32], max_count: u32) -> u32 {
        let mut count = 0u32;
        
        for word_idx in 0..4096 {
            let word = self.bitmap[word_idx].load(Ordering::Acquire);
            if word == 0 {
                continue;
            }
            
            for bit_idx in 0..64 {
                if word & (1 << bit_idx) != 0 {
                    if count >= max_count {
                        return count;
                    }
                    pages[count as usize] = (word_idx * 64 + bit_idx) as u32;
                    count += 1;
                }
            }
        }
        
        count
    }
}

impl Default for DirtyBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Region
// ─────────────────────────────────────────────────────────────────────────────

/// Memory region for snapshot
pub struct MemRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Start GPA
    pub gpa_start: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Page count
    pub page_count: AtomicU32,
    /// Pages transferred
    pub pages_transferred: AtomicU32,
    /// Bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Dirty bitmap
    pub dirty_bitmap: DirtyBitmap,
    /// Valid
    pub valid: AtomicBool,
}

impl MemRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            gpa_start: AtomicU64::new(0),
            size: AtomicU64::new(0),
            page_count: AtomicU32::new(0),
            pages_transferred: AtomicU32::new(0),
            bytes_transferred: AtomicU64::new(0),
            dirty_bitmap: DirtyBitmap::new(),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, gpa_start: u64, size: u64) {
        self.region_id.store(region_id, Ordering::Release);
        self.gpa_start.store(gpa_start, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.page_count.store((size / PAGE_SIZE) as u32, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Get page index for GPA
    pub fn get_page_idx(&self, gpa: u64) -> Option<u32> {
        let start = self.gpa_start.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        if gpa < start || gpa >= start + size {
            return None;
        }
        
        Some(((gpa - start) / PAGE_SIZE) as u32)
    }

    /// Mark page dirty
    pub fn mark_dirty(&self, gpa: u64) -> bool {
        let page_idx = self.get_page_idx(gpa)?;
        self.dirty_bitmap.mark_dirty(page_idx)
    }

    /// Get dirty count
    pub fn get_dirty_count(&self) -> u32 {
        self.dirty_bitmap.get_dirty_count()
    }

    /// Record transfer
    pub fn record_transfer(&self, pages: u32, bytes: u64) {
        self.pages_transferred.fetch_add(pages, Ordering::Release);
        self.bytes_transferred.fetch_add(bytes, Ordering::Release);
    }
}

impl Default for MemRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Transfer Progress
// ─────────────────────────────────────────────────────────────────────────────

/// Transfer progress tracking
pub struct TransferProgress {
    /// Total bytes to transfer
    pub total_bytes: AtomicU64,
    /// Bytes transferred
    pub transferred: AtomicU64,
    /// Bytes remaining
    pub remaining: AtomicU64,
    /// Pages transferred
    pub pages_transferred: AtomicU64,
    /// Pages remaining
    pub pages_remaining: AtomicU64,
    /// Transfer rate (bytes/sec)
    pub rate: AtomicU64,
    /// Estimated time remaining (ms)
    pub eta_ms: AtomicU64,
    /// Compression ratio (x1000)
    pub compression_ratio: AtomicU32,
    /// State
    pub state: AtomicU8,
}

impl TransferProgress {
    pub const fn new() -> Self {
        Self {
            total_bytes: AtomicU64::new(0),
            transferred: AtomicU64::new(0),
            remaining: AtomicU64::new(0),
            pages_transferred: AtomicU64::new(0),
            pages_remaining: AtomicU64::new(0),
            rate: AtomicU64::new(0),
            eta_ms: AtomicU64::new(0),
            compression_ratio: AtomicU32::new(1000), // 1.0x
            state: AtomicU8::new(transfer_state::PENDING),
        }
    }

    /// Initialize progress
    pub fn init(&self, total_bytes: u64, total_pages: u64) {
        self.total_bytes.store(total_bytes, Ordering::Release);
        self.remaining.store(total_bytes, Ordering::Release);
        self.pages_remaining.store(total_pages, Ordering::Release);
    }

    /// Update progress
    pub fn update(&self, bytes: u64, pages: u64, rate: u64) {
        self.transferred.fetch_add(bytes, Ordering::Release);
        self.pages_transferred.fetch_add(pages, Ordering::Release);
        self.remaining.fetch_sub(bytes.min(self.remaining.load(Ordering::Acquire)), Ordering::Release);
        self.pages_remaining.fetch_sub(pages.min(self.pages_remaining.load(Ordering::Acquire)), Ordering::Release);
        self.rate.store(rate, Ordering::Release);
        
        // Calculate ETA
        if rate > 0 {
            let remaining = self.remaining.load(Ordering::Acquire);
            self.eta_ms.store(remaining * 1000 / rate, Ordering::Release);
        }
    }

    /// Get completion percentage
    pub fn get_pct(&self) -> u8 {
        let total = self.total_bytes.load(Ordering::Acquire);
        if total == 0 {
            return 0;
        }
        
        let transferred = self.transferred.load(Ordering::Acquire);
        ((transferred * 100) / total) as u8
    }

    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.remaining.load(Ordering::Acquire) == 0
    }
}

impl Default for TransferProgress {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Live Snapshot
// ─────────────────────────────────────────────────────────────────────────────

/// Live snapshot state
pub struct LiveSnapshot {
    /// Snapshot ID
    pub snapshot_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Phase
    pub phase: AtomicU8,
    /// Iteration count
    pub iteration: AtomicU8,
    /// Max iterations
    pub max_iterations: AtomicU8,
    /// Iteration threshold (pages)
    pub iter_threshold: AtomicU32,
    /// Memory regions
    pub regions: [MemRegion; MAX_MEM_REGIONS],
    /// Region count
    pub region_count: AtomicU8,
    /// Transfer progress
    pub progress: TransferProgress,
    /// Bandwidth limit (MB/s)
    pub bandwidth_limit: AtomicU32,
    /// Pause time (ns)
    pub pause_time: AtomicU64,
    /// Total downtime (ns)
    pub total_downtime: AtomicU64,
    /// Start time
    pub start_time: AtomicU64,
    /// End time
    pub end_time: AtomicU64,
    /// Pre-copy time
    pub precopy_time: AtomicU64,
    /// Stop-and-copy time
    pub stopcopy_time: AtomicU64,
    /// Compression enabled
    pub compression: AtomicBool,
    /// Compression ratio (x1000)
    pub compression_ratio: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl LiveSnapshot {
    pub const fn new() -> Self {
        Self {
            snapshot_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            phase: AtomicU8::new(snap_phase::INIT),
            iteration: AtomicU8::new(0),
            max_iterations: AtomicU8::new(DEFAULT_MAX_ITERATIONS),
            iter_threshold: AtomicU32::new(DEFAULT_ITER_THRESHOLD),
            regions: [const { MemRegion::new() }; MAX_MEM_REGIONS],
            region_count: AtomicU8::new(0),
            progress: TransferProgress::new(),
            bandwidth_limit: AtomicU32::new(DEFAULT_BANDWIDTH),
            pause_time: AtomicU64::new(0),
            total_downtime: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
            end_time: AtomicU64::new(0),
            precopy_time: AtomicU64::new(0),
            stopcopy_time: AtomicU64::new(0),
            compression: AtomicBool::new(true),
            compression_ratio: AtomicU32::new(1000),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize snapshot
    pub fn init(&self, snapshot_id: u32, vm_id: u32, max_iterations: u8, 
                iter_threshold: u32, bandwidth: u32, compression: bool) {
        self.snapshot_id.store(snapshot_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.max_iterations.store(max_iterations, Ordering::Release);
        self.iter_threshold.store(iter_threshold, Ordering::Release);
        self.bandwidth_limit.store(bandwidth, Ordering::Release);
        self.compression.store(compression, Ordering::Release);
        self.start_time.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add memory region
    pub fn add_region(&self, gpa_start: u64, size: u64) -> Result<u8, HvError> {
        let count = self.region_count.load(Ordering::Acquire);
        if count as usize >= MAX_MEM_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.regions[count as usize].init(count, gpa_start, size);
        self.region_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Initialize progress
    pub fn init_progress(&self) {
        let mut total_bytes = 0u64;
        let mut total_pages = 0u64;
        
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            total_bytes += self.regions[i].size.load(Ordering::Acquire);
            total_pages += self.regions[i].page_count.load(Ordering::Acquire) as u64;
        }
        
        self.progress.init(total_bytes, total_pages);
    }

    /// Start pre-copy phase
    pub fn start_precopy(&self) {
        self.phase.store(snap_phase::PRECOPY, Ordering::Release);
        self.iteration.store(1, Ordering::Release);
    }

    /// Run one pre-copy iteration
    pub fn run_precopy_iteration(&self) -> u32 {
        let mut total_dirty = 0u32;
        
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            let dirty_count = region.get_dirty_count();
            
            if dirty_count == 0 {
                continue;
            }
            
            // Would transfer dirty pages here
            total_dirty += dirty_count;
            
            // Record transfer
            region.record_transfer(dirty_count, dirty_count as u64 * PAGE_SIZE);
            region.dirty_bitmap.clear_all();
        }
        
        self.iteration.fetch_add(1, Ordering::Release);
        total_dirty
    }

    /// Check if ready for stop-and-copy
    pub fn is_ready_for_stop(&self) -> bool {
        let mut total_dirty = 0u32;
        
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            total_dirty += self.regions[i].get_dirty_count();
        }
        
        // Ready if dirty pages below threshold or max iterations reached
        total_dirty <= self.iter_threshold.load(Ordering::Acquire) ||
        self.iteration.load(Ordering::Acquire) >= self.max_iterations.load(Ordering::Acquire)
    }

    /// Start stop-and-copy phase
    pub fn start_stop_and_copy(&self) {
        self.phase.store(snap_phase::STOP_AND_COPY, Ordering::Release);
        self.pause_time.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Complete stop-and-copy
    pub fn complete_stop_and_copy(&self) {
        let now = Self::get_timestamp();
        let pause = self.pause_time.load(Ordering::Acquire);
        
        self.stopcopy_time.store(now - pause, Ordering::Release);
        self.total_downtime.store(now - pause, Ordering::Release);
        self.end_time.store(now, Ordering::Release);
        self.phase.store(snap_phase::COMPLETED, Ordering::Release);
    }

    /// Cancel snapshot
    pub fn cancel(&self) {
        self.phase.store(snap_phase::CANCELLED, Ordering::Release);
        self.end_time.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Mark page dirty
    pub fn mark_dirty(&self, gpa: u64) {
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            if self.regions[i].mark_dirty(gpa) {
                break;
            }
        }
    }

    /// Get total dirty pages
    pub fn get_total_dirty(&self) -> u32 {
        let mut total = 0u32;
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            total += self.regions[i].get_dirty_count();
        }
        total
    }

    /// Get statistics
    pub fn get_stats(&self) -> LiveSnapStats {
        LiveSnapStats {
            snapshot_id: self.snapshot_id.load(Ordering::Acquire),
            vm_id: self.vm_id.load(Ordering::Acquire),
            phase: self.phase.load(Ordering::Acquire),
            iteration: self.iteration.load(Ordering::Acquire),
            region_count: self.region_count.load(Ordering::Acquire),
            progress_pct: self.progress.get_pct(),
            total_downtime_ns: self.total_downtime.load(Ordering::Acquire),
            pause_time_ns: self.pause_time.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for LiveSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Live snapshot statistics
#[repr(C)]
pub struct LiveSnapStats {
    pub snapshot_id: u32,
    pub vm_id: u32,
    pub phase: u8,
    pub iteration: u8,
    pub region_count: u8,
    pub progress_pct: u8,
    pub total_downtime_ns: u64,
    pub pause_time_ns: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Live Snapshot Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Live snapshot controller
pub struct LiveSnapController {
    /// Active snapshots
    pub snapshots: [LiveSnapshot; MAX_LIVE_SNAPSHOTS],
    /// Snapshot count
    pub snapshot_count: AtomicU8,
    /// Next snapshot ID
    pub next_snapshot_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Default max iterations
    pub default_max_iter: AtomicU8,
    /// Default iteration threshold
    pub default_iter_threshold: AtomicU32,
    /// Default bandwidth (MB/s)
    pub default_bandwidth: AtomicU32,
    /// Default compression
    pub default_compression: AtomicBool,
    /// Max pause time target (ms)
    pub max_pause_target: AtomicU32,
    /// Total snapshots created
    pub total_snapshots: AtomicU64,
    /// Total snapshots completed
    pub total_completed: AtomicU64,
    /// Total snapshots failed
    pub total_failed: AtomicU64,
    /// Total downtime (ns)
    pub total_downtime: AtomicU64,
    /// Average downtime (ns)
    pub avg_downtime: AtomicU64,
}

impl LiveSnapController {
    pub const fn new() -> Self {
        Self {
            snapshots: [const { LiveSnapshot::new() }; MAX_LIVE_SNAPSHOTS],
            snapshot_count: AtomicU8::new(0),
            next_snapshot_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            default_max_iter: AtomicU8::new(DEFAULT_MAX_ITERATIONS),
            default_iter_threshold: AtomicU32::new(DEFAULT_ITER_THRESHOLD),
            default_bandwidth: AtomicU32::new(DEFAULT_BANDWIDTH),
            default_compression: AtomicBool::new(true),
            max_pause_target: AtomicU32::new(100), // 100ms
            total_snapshots: AtomicU64::new(0),
            total_completed: AtomicU64::new(0),
            total_failed: AtomicU64::new(0),
            total_downtime: AtomicU64::new(0),
            avg_downtime: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, max_iter: u8, iter_threshold: u32, 
                  bandwidth: u32, compression: bool, max_pause: u32) {
        self.default_max_iter.store(max_iter, Ordering::Release);
        self.default_iter_threshold.store(iter_threshold, Ordering::Release);
        self.default_bandwidth.store(bandwidth, Ordering::Release);
        self.default_compression.store(compression, Ordering::Release);
        self.max_pause_target.store(max_pause, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Create live snapshot
    pub fn create_snapshot(&mut self, vm_id: u32, regions: &[(u64, u64)]) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.snapshot_count.load(Ordering::Acquire);
        if count as usize >= MAX_LIVE_SNAPSHOTS {
            return Err(HvError::LogicalFault);
        }
        
        let snapshot_id = self.next_snapshot_id.fetch_add(1, Ordering::Release);
        let snapshot = &self.snapshots[count as usize];
        
        snapshot.init(
            snapshot_id,
            vm_id,
            self.default_max_iter.load(Ordering::Acquire),
            self.default_iter_threshold.load(Ordering::Acquire),
            self.default_bandwidth.load(Ordering::Acquire),
            self.default_compression.load(Ordering::Acquire)
        );
        
        // Add memory regions
        for &(gpa_start, size) in regions {
            snapshot.add_region(gpa_start, size)?;
        }
        
        snapshot.init_progress();
        snapshot.start_precopy();
        
        self.snapshot_count.fetch_add(1, Ordering::Release);
        self.total_snapshots.fetch_add(1, Ordering::Release);
        
        Ok(snapshot_id)
    }

    /// Get snapshot
    pub fn get_snapshot(&self, snapshot_id: u32) -> Option<&LiveSnapshot> {
        for i in 0..self.snapshot_count.load(Ordering::Acquire) as usize {
            if self.snapshots[i].snapshot_id.load(Ordering::Acquire) == snapshot_id {
                return Some(&self.snapshots[i]);
            }
        }
        None
    }

    /// Run pre-copy iteration
    pub fn run_precopy(&self, snapshot_id: u32) -> Result<u32, HvError> {
        let snapshot = self.get_snapshot(snapshot_id).ok_or(HvError::LogicalFault)?;
        
        if snapshot.phase.load(Ordering::Acquire) != snap_phase::PRECOPY {
            return Err(HvError::LogicalFault);
        }
        
        let dirty_pages = snapshot.run_precopy_iteration();
        
        // Check if ready for stop-and-copy
        if snapshot.is_ready_for_stop() {
            snapshot.start_stop_and_copy();
        }
        
        Ok(dirty_pages)
    }

    /// Run stop-and-copy
    pub fn run_stop_and_copy(&self, snapshot_id: u32) -> Result<(), HvError> {
        let snapshot = self.get_snapshot(snapshot_id).ok_or(HvError::LogicalFault)?;
        
        if snapshot.phase.load(Ordering::Acquire) != snap_phase::STOP_AND_COPY {
            return Err(HvError::LogicalFault);
        }
        
        // Transfer remaining dirty pages
        for i in 0..snapshot.region_count.load(Ordering::Acquire) as usize {
            let region = &snapshot.regions[i];
            let dirty_count = region.get_dirty_count();
            
            if dirty_count > 0 {
                region.record_transfer(dirty_count, dirty_count as u64 * PAGE_SIZE);
                region.dirty_bitmap.clear_all();
            }
        }
        
        snapshot.complete_stop_and_copy();
        
        // Update statistics
        self.total_completed.fetch_add(1, Ordering::Release);
        let downtime = snapshot.total_downtime.load(Ordering::Acquire);
        self.total_downtime.fetch_add(downtime, Ordering::Release);
        
        let completed = self.total_completed.load(Ordering::Acquire);
        let total = self.total_downtime.load(Ordering::Acquire);
        self.avg_downtime.store(total / completed, Ordering::Release);
        
        Ok(())
    }

    /// Cancel snapshot
    pub fn cancel_snapshot(&self, snapshot_id: u32) -> Result<(), HvError> {
        let snapshot = self.get_snapshot(snapshot_id).ok_or(HvError::LogicalFault)?;
        
        let phase = snapshot.phase.load(Ordering::Acquire);
        if phase == snap_phase::COMPLETED || phase == snap_phase::FAILED {
            return Err(HvError::LogicalFault);
        }
        
        snapshot.cancel();
        self.total_failed.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Mark page dirty
    pub fn mark_dirty(&self, vm_id: u32, gpa: u64) {
        for i in 0..self.snapshot_count.load(Ordering::Acquire) as usize {
            let snapshot = &self.snapshots[i];
            if snapshot.vm_id.load(Ordering::Acquire) == vm_id &&
               snapshot.phase.load(Ordering::Acquire) == snap_phase::PRECOPY {
                snapshot.mark_dirty(gpa);
            }
        }
    }

    /// Get active snapshots for VM
    pub fn get_active_for_vm(&self, vm_id: u32) -> u8 {
        let mut count = 0u8;
        for i in 0..self.snapshot_count.load(Ordering::Acquire) as usize {
            let snapshot = &self.snapshots[i];
            if snapshot.vm_id.load(Ordering::Acquire) == vm_id &&
               snapshot.phase.load(Ordering::Acquire) == snap_phase::PRECOPY {
                count += 1;
            }
        }
        count
    }

    /// Get statistics
    pub fn get_stats(&self) -> LiveSnapControllerStats {
        LiveSnapControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            snapshot_count: self.snapshot_count.load(Ordering::Acquire),
            total_snapshots: self.total_snapshots.load(Ordering::Acquire),
            total_completed: self.total_completed.load(Ordering::Acquire),
            total_failed: self.total_failed.load(Ordering::Acquire),
            avg_downtime_ns: self.avg_downtime.load(Ordering::Acquire),
            max_pause_target_ms: self.max_pause_target.load(Ordering::Acquire),
        }
    }
}

impl Default for LiveSnapController {
    fn default() -> Self {
        Self::new()
    }
}

/// Live snapshot controller statistics
#[repr(C)]
pub struct LiveSnapControllerStats {
    pub enabled: bool,
    pub snapshot_count: u8,
    pub total_snapshots: u64,
    pub total_completed: u64,
    pub total_failed: u64,
    pub avg_downtime_ns: u64,
    pub max_pause_target_ms: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_snapshot() {
        let mut ctrl = LiveSnapController::new();
        ctrl.enable(10, 256, 1000, true, 100);
        
        let id = ctrl.create_snapshot(1, &[(0x80000000, 128 * 1024 * 1024)]).unwrap();
        assert!(id > 0);
        assert_eq!(ctrl.snapshot_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn precopy_iteration() {
        let mut ctrl = LiveSnapController::new();
        ctrl.enable(10, 256, 1000, true, 100);
        
        let id = ctrl.create_snapshot(1, &[(0x80000000, 128 * 1024 * 1024)]).unwrap();
        
        // Mark some pages dirty
        ctrl.mark_dirty(1, 0x80000000);
        ctrl.mark_dirty(1, 0x80001000);
        ctrl.mark_dirty(1, 0x80002000);
        
        let dirty = ctrl.run_precopy(id).unwrap();
        assert!(dirty > 0);
        
        let snapshot = ctrl.get_snapshot(id).unwrap();
        assert!(snapshot.iteration.load(Ordering::Acquire) >= 2);
    }

    #[test]
    fn stop_and_copy() {
        let mut ctrl = LiveSnapController::new();
        ctrl.enable(10, 256, 1000, true, 100);
        
        let id = ctrl.create_snapshot(1, &[(0x80000000, 128 * 1024 * 1024)]).unwrap();
        
        // Run until ready for stop
        loop {
            ctrl.run_precopy(id).unwrap();
            let snapshot = ctrl.get_snapshot(id).unwrap();
            if snapshot.phase.load(Ordering::Acquire) == snap_phase::STOP_AND_COPY {
                break;
            }
        }
        
        ctrl.run_stop_and_copy(id).unwrap();
        
        let snapshot = ctrl.get_snapshot(id).unwrap();
        assert_eq!(snapshot.phase.load(Ordering::Acquire), snap_phase::COMPLETED);
    }

    #[test]
    fn cancel_snapshot() {
        let mut ctrl = LiveSnapController::new();
        ctrl.enable(10, 256, 1000, true, 100);
        
        let id = ctrl.create_snapshot(1, &[(0x80000000, 128 * 1024 * 1024)]).unwrap();
        
        ctrl.cancel_snapshot(id).unwrap();
        
        let snapshot = ctrl.get_snapshot(id).unwrap();
        assert_eq!(snapshot.phase.load(Ordering::Acquire), snap_phase::CANCELLED);
    }

    #[test]
    fn dirty_bitmap() {
        let bitmap = DirtyBitmap::new();
        
        assert!(bitmap.mark_dirty(0));
        assert!(bitmap.mark_dirty(100));
        assert!(bitmap.mark_dirty(1000));
        
        assert!(bitmap.is_dirty(0));
        assert!(bitmap.is_dirty(100));
        assert!(!bitmap.is_dirty(50));
        
        assert_eq!(bitmap.get_dirty_count(), 3);
        
        bitmap.clear_all();
        assert_eq!(bitmap.get_dirty_count(), 0);
    }

    #[test]
    fn transfer_progress() {
        let progress = TransferProgress::new();
        progress.init(1024 * 1024 * 1024, 262144); // 1GB
        
        progress.update(100 * 1024 * 1024, 25600, 100 * 1024 * 1024);
        
        assert_eq!(progress.get_pct(), 9);
        assert!(!progress.is_complete());
    }

    #[test]
    fn iteration_threshold() {
        let mut ctrl = LiveSnapController::new();
        ctrl.enable(10, 10, 1000, true, 100); // Threshold: 10 pages
        
        let id = ctrl.create_snapshot(1, &[(0x80000000, 128 * 1024 * 1024)]).unwrap();
        
        // Mark few pages dirty
        for i in 0..5 {
            ctrl.mark_dirty(1, 0x80000000 + i * 4096);
        }
        
        ctrl.run_precopy(id).unwrap();
        
        // Should be ready for stop-and-copy (below threshold)
        let snapshot = ctrl.get_snapshot(id).unwrap();
        assert!(snapshot.is_ready_for_stop());
    }
}
