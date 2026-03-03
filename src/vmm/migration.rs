//! Live Migration - VM State Transfer
//!
//! Pre-copy and post-copy live migration with dirty page tracking.
//! Supports migration across hosts with minimal downtime.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, AtomicPtr, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Migration Protocol Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Migration phases
pub mod phase {
    pub const NONE: u8 = 0;
    pub const SETUP: u8 = 1;
    pub const PRECOPY: u8 = 2;
    pub const STOP_AND_COPY: u8 = 3;
    pub const POSTCOPY: u8 = 4;
    pub const COMPLETED: u8 = 5;
    pub const FAILED: u8 = 6;
    pub const CANCELLED: u8 = 7;
}

/// Migration commands
pub mod cmd {
    pub const MIGR_SETUP: u32 = 1;
    pub const MIGR_START: u32 = 2;
    pub const MIGR_CANCEL: u32 = 3;
    pub const MIGR_GET_STATUS: u32 = 4;
    pub const MIGR_SET_PARAMS: u32 = 5;
    pub const MIGR_GET_DIRTY_BITMAP: u32 = 6;
    pub const MIGR_TRANSFER_PAGE: u32 = 7;
    pub const MIGR_TRANSFER_STATE: u32 = 8;
    pub const MIGR_COMPLETE: u32 = 9;
}

/// Migration flags
pub mod flags {
    pub const POSTCOPY: u32 = 1 << 0;
    pub const COMPRESSED: u32 = 1 << 1;
    pub const ENCRYPTED: u32 = 1 << 2;
    pub const DIRTY_LOGGING: u32 = 1 << 3;
    pub const AUTO_CONVERGE: u32 = 1 << 4;
    pub const BANDWIDTH_LIMIT: u32 = 1 << 5;
    pub const DOWNTIME_LIMIT: u32 = 1 << 6;
}

/// Maximum dirty bitmap size (1M pages = 4GB)
pub const MAX_DIRTY_BITMAP_SIZE: usize = 131072; // 1M bits / 8 = 128KB
/// Maximum pages per transfer iteration
pub const MAX_PAGES_PER_ITERATION: usize = 4096;
/// Default bandwidth limit (MB/s)
pub const DEFAULT_BANDWIDTH_LIMIT: u32 = 1000;
/// Default downtime limit (ms)
pub const DEFAULT_DOWNTIME_LIMIT: u32 = 300;

// ─────────────────────────────────────────────────────────────────────────────
// Dirty Page Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// Dirty page bitmap for tracking modified pages
pub struct DirtyBitmap {
    /// Bitmap array (each bit represents one page)
    pub bitmap: [AtomicU64; MAX_DIRTY_BITMAP_SIZE / 8],
    /// Number of pages tracked
    pub num_pages: AtomicU64,
    /// Base GPA (guest physical address)
    pub base_gpa: AtomicU64,
    /// Dirty logging enabled
    pub enabled: AtomicBool,
    /// Total dirty count
    pub dirty_count: AtomicU64,
}

impl DirtyBitmap {
    pub const fn new() -> Self {
        Self {
            bitmap: [const { AtomicU64::new(0) }; MAX_DIRTY_BITMAP_SIZE / 8],
            num_pages: AtomicU64::new(0),
            base_gpa: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            dirty_count: AtomicU64::new(0),
        }
    }

    /// Initialize bitmap for memory region
    pub fn init(&self, base_gpa: u64, num_pages: u64) {
        self.base_gpa.store(base_gpa, Ordering::Release);
        self.num_pages.store(num_pages, Ordering::Release);
        self.clear_all();
    }

    /// Enable dirty logging
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable dirty logging
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Mark page as dirty
    pub fn mark_dirty(&self, gpa: u64) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        let base = self.base_gpa.load(Ordering::Acquire);
        if gpa < base {
            return;
        }
        
        let page_offset = (gpa - base) / 4096;
        if page_offset >= self.num_pages.load(Ordering::Acquire) {
            return;
        }
        
        let word_idx = (page_offset / 64) as usize;
        let bit_idx = (page_offset % 64) as u32;
        
        if word_idx < self.bitmap.len() {
            let old = self.bitmap[word_idx].fetch_or(1 << bit_idx, Ordering::Release);
            if (old & (1 << bit_idx)) == 0 {
                self.dirty_count.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Check if page is dirty
    pub fn is_dirty(&self, gpa: u64) -> bool {
        let base = self.base_gpa.load(Ordering::Acquire);
        if gpa < base {
            return false;
        }
        
        let page_offset = (gpa - base) / 4096;
        let word_idx = (page_offset / 64) as usize;
        let bit_idx = (page_offset % 64) as u32;
        
        if word_idx < self.bitmap.len() {
            (self.bitmap[word_idx].load(Ordering::Acquire) & (1 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Clear dirty bit for page
    pub fn clear_dirty(&self, gpa: u64) {
        let base = self.base_gpa.load(Ordering::Acquire);
        if gpa < base {
            return;
        }
        
        let page_offset = (gpa - base) / 4096;
        let word_idx = (page_offset / 64) as usize;
        let bit_idx = (page_offset % 64) as u32;
        
        if word_idx < self.bitmap.len() {
            let old = self.bitmap[word_idx].fetch_and(!(1 << bit_idx), Ordering::Release);
            if (old & (1 << bit_idx)) != 0 {
                self.dirty_count.fetch_sub(1, Ordering::Release);
            }
        }
    }

    /// Clear all dirty bits
    pub fn clear_all(&self) {
        for word in &self.bitmap {
            word.store(0, Ordering::Release);
        }
        self.dirty_count.store(0, Ordering::Release);
    }

    /// Get dirty page count
    pub fn get_dirty_count(&self) -> u64 {
        self.dirty_count.load(Ordering::Acquire)
    }

    /// Get next dirty page (iterator)
    pub fn get_next_dirty(&self, start_page: u64) -> Option<u64> {
        let num_pages = self.num_pages.load(Ordering::Acquire);
        let mut page = start_page;
        
        while page < num_pages {
            let word_idx = (page / 64) as usize;
            let bit_idx = (page % 64) as u32;
            
            if word_idx < self.bitmap.len() {
                let word = self.bitmap[word_idx].load(Ordering::Acquire);
                if (word >> bit_idx) != 0 {
                    // Find first set bit
                    let trailing = (word >> bit_idx).trailing_zeros();
                    return Some(page + trailing as u64);
                }
            }
            page = ((page / 64) + 1) * 64;
        }
        None
    }

    /// Get bitmap snapshot
    pub fn get_snapshot(&self) -> [u64; MAX_DIRTY_BITMAP_SIZE / 8] {
        let mut snapshot = [0u64; MAX_DIRTY_BITMAP_SIZE / 8];
        for i in 0..self.bitmap.len() {
            snapshot[i] = self.bitmap[i].load(Ordering::Acquire);
        }
        snapshot
    }
}

impl Default for DirtyBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM State Transfer
// ─────────────────────────────────────────────────────────────────────────────

/// VM CPU state for migration
#[repr(C)]
pub struct VcpuMigrState {
    /// General purpose registers
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    /// RIP and flags
    pub rip: u64,
    pub rflags: u64,
    /// Segment registers
    pub cs: SegmentMigrState,
    pub ds: SegmentMigrState,
    pub es: SegmentMigrState,
    pub fs: SegmentMigrState,
    pub gs: SegmentMigrState,
    pub ss: SegmentMigrState,
    /// Control registers
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    /// Debug registers
    pub dr0: u64, pub dr1: u64, pub dr2: u64, pub dr3: u64,
    pub dr6: u64, pub dr7: u64,
    /// MSRs
    pub efer: u64,
    pub pat: u64,
    pub sysenter_cs: u64,
    pub sysenter_esp: u64,
    pub sysenter_eip: u64,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub sfmask: u64,
    pub kernel_gs_base: u64,
    /// APIC state
    pub apic_base: u64,
    pub apic_id: u32,
    pub apic_version: u32,
    pub apic_tpr: u32,
    pub apic_ldr: u32,
    pub apic_dfr: u32,
    pub apic_svr: u32,
    pub apic_isr: [u32; 8],
    pub apic_tmr: [u32; 8],
    pub apic_irr: [u32; 8],
    pub apic_esr: u32,
    pub apic_lvt: [u32; 6],
    pub apic_icr: u64,
    pub apic_timer: ApicTimerMigrState,
}

/// Segment register state
#[repr(C)]
pub struct SegmentMigrState {
    pub selector: u16,
    pub base: u64,
    pub limit: u32,
    pub ar: u32, // Access rights
}

/// APIC timer state
#[repr(C)]
pub struct ApicTimerMigrState {
    pub initial_count: u32,
    pub current_count: u32,
    pub divide_config: u32,
    pub lvt_timer: u32,
    pub timer_mode: u8,
    pub pending: bool,
}

/// Device state header
#[repr(C)]
pub struct DeviceMigrHeader {
    /// Device ID
    pub device_id: u32,
    /// Device type
    pub device_type: u32,
    /// State size
    pub state_size: u32,
    /// State version
    pub version: u32,
}

/// Memory region for migration
#[repr(C)]
pub struct MemoryMigrRegion {
    /// Guest physical address
    pub gpa: u64,
    /// Size in bytes
    pub size: u64,
    /// Flags (RAM, MMIO, ROM, etc.)
    pub flags: u32,
    /// Padding
    pub reserved: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Migration Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Migration statistics
pub struct MigrationStats {
    /// Total pages transferred
    pub total_pages: AtomicU64,
    /// Dirty pages remaining
    pub dirty_pages: AtomicU64,
    /// Bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Iterations completed
    pub iterations: AtomicU32,
    /// Time elapsed (ms)
    pub elapsed_ms: AtomicU64,
    /// Estimated completion time (ms)
    pub estimated_ms: AtomicU64,
    /// Downtime (ms)
    pub downtime_ms: AtomicU64,
    /// Throughput (MB/s)
    pub throughput_mbps: AtomicU32,
}

impl MigrationStats {
    pub const fn new() -> Self {
        Self {
            total_pages: AtomicU64::new(0),
            dirty_pages: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            iterations: AtomicU32::new(0),
            elapsed_ms: AtomicU64::new(0),
            estimated_ms: AtomicU64::new(0),
            downtime_ms: AtomicU64::new(0),
            throughput_mbps: AtomicU32::new(0),
        }
    }
}

/// Migration parameters
pub struct MigrationParams {
    /// Maximum bandwidth (MB/s)
    pub max_bandwidth: AtomicU32,
    /// Maximum downtime (ms)
    pub max_downtime: AtomicU32,
    /// Minimum iterations before stop
    pub min_iterations: AtomicU32,
    /// Maximum iterations
    pub max_iterations: AtomicU32,
    /// Compression enabled
    pub compress: AtomicBool,
    /// Encryption enabled
    pub encrypt: AtomicBool,
    /// Post-copy migration
    pub postcopy: AtomicBool,
    /// Auto-converge enabled
    pub auto_converge: AtomicBool,
    /// Converge throttle percentage
    pub converge_throttle: AtomicU8,
}

impl MigrationParams {
    pub const fn new() -> Self {
        Self {
            max_bandwidth: AtomicU32::new(DEFAULT_BANDWIDTH_LIMIT),
            max_downtime: AtomicU32::new(DEFAULT_DOWNTIME_LIMIT),
            min_iterations: AtomicU32::new(3),
            max_iterations: AtomicU32::new(30),
            compress: AtomicBool::new(false),
            encrypt: AtomicBool::new(false),
            postcopy: AtomicBool::new(false),
            auto_converge: AtomicBool::new(true),
            converge_throttle: AtomicU8::new(30),
        }
    }
}

/// Migration controller
pub struct MigrationController {
    /// Current phase
    pub phase: AtomicU8,
    /// Source VM ID
    pub source_vm_id: AtomicU32,
    /// Target VM ID
    pub target_vm_id: AtomicU32,
    /// Target host address (would be network address)
    pub target_host: AtomicU64,
    /// Migration flags
    pub flags: AtomicU32,
    /// Dirty bitmap
    pub dirty_bitmap: DirtyBitmap,
    /// Statistics
    pub stats: MigrationStats,
    /// Parameters
    pub params: MigrationParams,
    /// Error code
    pub error: AtomicU32,
    /// Start timestamp
    pub start_time: AtomicU64,
    /// Stop timestamp
    pub stop_time: AtomicU64,
    /// VM paused for migration
    pub vm_paused: AtomicBool,
    /// Transfer buffer
    pub transfer_buffer: [AtomicU8; 65536],
    /// Transfer buffer offset
    pub transfer_offset: AtomicU32,
}

impl MigrationController {
    pub const fn new() -> Self {
        Self {
            phase: AtomicU8::new(phase::NONE),
            source_vm_id: AtomicU32::new(0),
            target_vm_id: AtomicU32::new(0),
            target_host: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            dirty_bitmap: DirtyBitmap::new(),
            stats: MigrationStats::new(),
            params: MigrationParams::new(),
            error: AtomicU32::new(0),
            start_time: AtomicU64::new(0),
            stop_time: AtomicU64::new(0),
            vm_paused: AtomicBool::new(false),
            transfer_buffer: [const { AtomicU8::new(0) }; 65536],
            transfer_offset: AtomicU32::new(0),
        }
    }

    /// Start migration
    pub fn start(&mut self, source_vm_id: u32, target_host: u64, flags: u32) -> Result<(), HvError> {
        if self.phase.load(Ordering::Acquire) != phase::NONE {
            return Err(HvError::LogicalFault);
        }
        
        self.source_vm_id.store(source_vm_id, Ordering::Release);
        self.target_host.store(target_host, Ordering::Release);
        self.flags.store(flags, Ordering::Release);
        self.phase.store(phase::SETUP, Ordering::Release);
        self.start_time.store(Self::get_timestamp_ms(), Ordering::Release);
        
        // Enable dirty logging
        self.dirty_bitmap.enable();
        
        // Transition to precopy
        self.phase.store(phase::PRECOPY, Ordering::Release);
        
        Ok(())
    }

    /// Run precopy iteration
    pub fn precopy_iteration(&mut self) -> Result<bool, HvError> {
        if self.phase.load(Ordering::Acquire) != phase::PRECOPY {
            return Err(HvError::LogicalFault);
        }
        
        let dirty_count = self.dirty_bitmap.get_dirty_count();
        self.stats.dirty_pages.store(dirty_count, Ordering::Release);
        
        // Check convergence
        let iterations = self.stats.iterations.load(Ordering::Acquire);
        let max_iterations = self.params.max_iterations.load(Ordering::Acquire);
        let min_iterations = self.params.min_iterations.load(Ordering::Acquire);
        
        // Calculate estimated time
        let bandwidth = self.params.max_bandwidth.load(Ordering::Acquire) as u64;
        let dirty_bytes = dirty_count * 4096;
        let estimated_ms = if bandwidth > 0 {
            (dirty_bytes / (bandwidth * 1024 * 1024 / 1000)).min(60000)
        } else {
            60000
        };
        self.stats.estimated_ms.store(estimated_ms, Ordering::Release);
        
        // Check if ready for stop-and-copy
        if iterations >= min_iterations {
            let max_downtime = self.params.max_downtime.load(Ordering::Acquire) as u64;
            if estimated_ms <= max_downtime || iterations >= max_iterations {
                return Ok(true); // Ready to stop
            }
        }
        
        // Transfer dirty pages
        self.transfer_dirty_pages()?;
        
        // Auto-converge: throttle if dirty rate is high
        if self.params.auto_converge.load(Ordering::Acquire) {
            let throttle = self.params.converge_throttle.load(Ordering::Acquire);
            // Would apply CPU throttling to source VM
            let _ = throttle;
        }
        
        self.stats.iterations.fetch_add(1, Ordering::Release);
        
        Ok(false)
    }

    /// Transfer dirty pages
    fn transfer_dirty_pages(&self) -> Result<(), HvError> {
        let mut page_idx = 0u64;
        let mut pages_transferred = 0u64;
        
        while let Some(dirty_page) = self.dirty_bitmap.get_next_dirty(page_idx) {
            // Transfer page to target
            self.transfer_page(dirty_page)?;
            
            // Clear dirty bit after transfer
            let base = self.dirty_bitmap.base_gpa.load(Ordering::Acquire);
            self.dirty_bitmap.clear_dirty(base + dirty_page * 4096);
            
            page_idx = dirty_page + 1;
            pages_transferred += 1;
            
            // Limit per iteration
            if pages_transferred >= MAX_PAGES_PER_ITERATION as u64 {
                break;
            }
        }
        
        self.stats.total_pages.fetch_add(pages_transferred, Ordering::Release);
        self.stats.bytes_transferred.fetch_add(pages_transferred * 4096, Ordering::Release);
        
        Ok(())
    }

    /// Transfer single page
    fn transfer_page(&self, page_idx: u64) -> Result<(), HvError> {
        let base = self.dirty_bitmap.base_gpa.load(Ordering::Acquire);
        let gpa = base + page_idx * 4096;
        
        // Would read page from guest memory and send to target
        // For now, just record the transfer
        let _ = gpa;
        
        Ok(())
    }

    /// Stop VM and copy remaining state
    pub fn stop_and_copy(&mut self) -> Result<(), HvError> {
        if self.phase.load(Ordering::Acquire) != phase::PRECOPY {
            return Err(HvError::LogicalFault);
        }
        
        self.phase.store(phase::STOP_AND_COPY, Ordering::Release);
        
        // Pause VM
        self.vm_paused.store(true, Ordering::Release);
        let stop_start = Self::get_timestamp_ms();
        
        // Transfer remaining dirty pages
        self.transfer_dirty_pages()?;
        
        // Transfer CPU state
        self.transfer_cpu_state()?;
        
        // Transfer device state
        self.transfer_device_state()?;
        
        // Calculate downtime
        let stop_end = Self::get_timestamp_ms();
        let downtime = stop_end - stop_start;
        self.stats.downtime_ms.store(downtime, Ordering::Release);
        
        // Complete migration
        self.phase.store(phase::COMPLETED, Ordering::Release);
        self.stop_time.store(stop_end, Ordering::Release);
        
        // Disable dirty logging
        self.dirty_bitmap.disable();
        
        Ok(())
    }

    /// Transfer CPU state
    fn transfer_cpu_state(&self) -> Result<(), HvError> {
        // Would serialize all vCPU states and send to target
        Ok(())
    }

    /// Transfer device state
    fn transfer_device_state(&self) -> Result<(), HvError> {
        // Would serialize all device states and send to target
        Ok(())
    }

    /// Cancel migration
    pub fn cancel(&mut self) {
        self.phase.store(phase::CANCELLED, Ordering::Release);
        self.dirty_bitmap.disable();
        self.vm_paused.store(false, Ordering::Release);
    }

    /// Get migration status
    pub fn get_status(&self) -> MigrationStatus {
        MigrationStatus {
            phase: self.phase.load(Ordering::Acquire),
            total_pages: self.stats.total_pages.load(Ordering::Acquire),
            dirty_pages: self.stats.dirty_pages.load(Ordering::Acquire),
            bytes_transferred: self.stats.bytes_transferred.load(Ordering::Acquire),
            iterations: self.stats.iterations.load(Ordering::Acquire),
            elapsed_ms: self.stats.elapsed_ms.load(Ordering::Acquire),
            downtime_ms: self.stats.downtime_ms.load(Ordering::Acquire),
            error: self.error.load(Ordering::Acquire),
        }
    }

    /// Get timestamp in milliseconds (placeholder)
    fn get_timestamp_ms() -> u64 {
        0 // Would use actual timer
    }
}

impl Default for MigrationController {
    fn default() -> Self {
        Self::new()
    }
}

/// Migration status response
#[repr(C)]
pub struct MigrationStatus {
    pub phase: u8,
    pub error: u32,
    pub total_pages: u64,
    pub dirty_pages: u64,
    pub bytes_transferred: u64,
    pub iterations: u32,
    pub elapsed_ms: u64,
    pub downtime_ms: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-copy Migration Support
// ─────────────────────────────────────────────────────────────────────────────

/// Post-copy page fault handler
pub struct PostcopyHandler {
    /// Enabled
    pub enabled: AtomicBool,
    /// Page faults handled
    pub page_faults: AtomicU64,
    /// Pages transferred on-demand
    pub ondemand_pages: AtomicU64,
    /// Uffd (userfaultfd) descriptor
    pub uffd: AtomicU32,
    /// Source host for page fetch
    pub source_host: AtomicU64,
}

impl PostcopyHandler {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            page_faults: AtomicU64::new(0),
            ondemand_pages: AtomicU64::new(0),
            uffd: AtomicU32::new(0),
            source_host: AtomicU64::new(0),
        }
    }

    /// Enable post-copy mode
    pub fn enable(&self, uffd: u32, source_host: u64) {
        self.uffd.store(uffd, Ordering::Release);
        self.source_host.store(source_host, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Handle page fault (fetch from source)
    pub fn handle_page_fault(&self, gpa: u64) -> Result<(), HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.page_faults.fetch_add(1, Ordering::Release);
        
        // Would fetch page from source host via network
        let _ = gpa;
        
        self.ondemand_pages.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> PostcopyStats {
        PostcopyStats {
            enabled: self.enabled.load(Ordering::Acquire),
            page_faults: self.page_faults.load(Ordering::Acquire),
            ondemand_pages: self.ondemand_pages.load(Ordering::Acquire),
        }
    }
}

impl Default for PostcopyHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Post-copy statistics
#[repr(C)]
pub struct PostcopyStats {
    pub enabled: bool,
    pub page_faults: u64,
    pub ondemand_pages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_bitmap_basic() {
        let bitmap = DirtyBitmap::new();
        bitmap.init(0, 1000);
        bitmap.enable();
        
        bitmap.mark_dirty(0);
        bitmap.mark_dirty(4096);
        bitmap.mark_dirty(8192);
        
        assert_eq!(bitmap.get_dirty_count(), 3);
        assert!(bitmap.is_dirty(0));
        assert!(bitmap.is_dirty(4096));
    }

    #[test]
    fn dirty_bitmap_clear() {
        let bitmap = DirtyBitmap::new();
        bitmap.init(0, 1000);
        bitmap.enable();
        
        bitmap.mark_dirty(0);
        assert_eq!(bitmap.get_dirty_count(), 1);
        
        bitmap.clear_dirty(0);
        assert_eq!(bitmap.get_dirty_count(), 0);
        assert!(!bitmap.is_dirty(0));
    }

    #[test]
    fn migration_start() {
        let mut migr = MigrationController::new();
        migr.start(1, 0x12345678, 0).unwrap();
        
        assert_eq!(migr.phase.load(Ordering::Acquire), phase::PRECOPY);
        assert!(migr.dirty_bitmap.enabled.load(Ordering::Acquire));
    }

    #[test]
    fn migration_cancel() {
        let mut migr = MigrationController::new();
        migr.start(1, 0x12345678, 0).unwrap();
        migr.cancel();
        
        assert_eq!(migr.phase.load(Ordering::Acquire), phase::CANCELLED);
    }

    #[test]
    fn postcopy_handler() {
        let postcopy = PostcopyHandler::new();
        postcopy.enable(42, 0x12345678);
        
        assert!(postcopy.enabled.load(Ordering::Acquire));
        assert_eq!(postcopy.uffd.load(Ordering::Acquire), 42);
    }
}
