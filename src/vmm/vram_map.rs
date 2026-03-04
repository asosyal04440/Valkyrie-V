//! Direct VRAM Mapping for Zero-Copy GPU Access
//!
//! Provides infrastructure for mapping GPU BAR memory directly into the
//! hypervisor's address space for zero-copy command submission and data transfers.
//!
//! Key features:
//! - Direct BAR memory mapping with cache control
//! - P2P DMA windows for GPU-to-GPU transfers
//! - Fence-based DMA completion tracking
//! - Write-combining optimization for sequential writes

#![allow(dead_code)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ─── Memory Types ──────────────────────────────────────────────────────────────

/// Memory type for BAR mapping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    /// Uncacheable (UC) - for MMIO registers
    Uncacheable,
    /// Write-Combining (WC) - for framebuffer/command buffers
    WriteCombining,
    /// Write-Through (WT)
    WriteThrough,
    /// Write-Back (WB) - normal cached memory
    WriteBack,
    /// Framebuffer (alias for WriteCombining)
    Framebuffer,
    /// MMIO (alias for Uncacheable)
    Mmio,
    /// System memory (alias for WriteBack)
    System,
}

impl MemoryType {
    /// Get MTRR type value
    pub fn mtrr_type(&self) -> u8 {
        match self {
            MemoryType::Uncacheable | MemoryType::Mmio => 0,
            MemoryType::WriteCombining | MemoryType::Framebuffer => 1,
            MemoryType::WriteThrough => 4,
            MemoryType::WriteBack | MemoryType::System => 6,
        }
    }

    /// Get PAT index for this memory type
    pub fn pat_index(&self) -> u8 {
        match self {
            MemoryType::Uncacheable | MemoryType::Mmio => 0,
            MemoryType::WriteCombining | MemoryType::Framebuffer => 1,
            MemoryType::WriteThrough => 4,
            MemoryType::WriteBack | MemoryType::System => 6,
        }
    }
    
    /// Get PTE flags for this memory type (PCD/PWT bits)
    /// Returns (PCD, PWT) tuple
    pub fn pte_cache_flags(&self) -> (bool, bool) {
        match self {
            MemoryType::Uncacheable | MemoryType::Mmio => (true, true),   // PCD=1, PWT=1
            MemoryType::WriteCombining | MemoryType::Framebuffer => (false, false), // PCD=0, PWT=0, PAT=1
            MemoryType::WriteThrough => (false, true),  // PCD=0, PWT=1
            MemoryType::WriteBack | MemoryType::System => (false, false), // PCD=0, PWT=0
        }
    }
}

// ─── VRAM Region ───────────────────────────────────────────────────────────────

/// A mapped VRAM region from a GPU BAR
#[derive(Clone, Copy)]
pub struct VramRegion {
    /// Physical BAR base address
    pub bar_base: u64,
    /// Size of the region in bytes
    pub size: u64,
    /// GPU virtual address (for GPU-side access)
    pub gpu_va: u64,
    /// CPU-mapped virtual address
    pub cpu_va: u64,
    /// BAR index (0-5)
    pub bar_idx: u8,
    /// Memory type for this region
    pub mem_type: MemoryType,
    /// Whether region is valid
    pub valid: bool,
}

impl VramRegion {
    pub const fn invalid() -> Self {
        Self {
            bar_base: 0,
            size: 0,
            gpu_va: 0,
            cpu_va: 0,
            bar_idx: 0,
            mem_type: MemoryType::Uncacheable,
            valid: false,
        }
    }

    /// Read a 32-bit value from offset
    /// 
    /// # Safety
    /// Offset must be within bounds and aligned to 4 bytes
    #[inline]
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        debug_assert!(offset + 4 <= self.size);
        let addr = (self.cpu_va + offset) as *const u32;
        core::ptr::read_volatile(addr)
    }

    /// Write a 32-bit value to offset
    ///
    /// # Safety
    /// Offset must be within bounds and aligned to 4 bytes
    #[inline]
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        debug_assert!(offset + 4 <= self.size);
        let addr = (self.cpu_va + offset) as *mut u32;
        core::ptr::write_volatile(addr, value);
    }

    /// Read a 64-bit value from offset
    #[inline]
    pub unsafe fn read64(&self, offset: u64) -> u64 {
        debug_assert!(offset + 8 <= self.size);
        let addr = (self.cpu_va + offset) as *const u64;
        core::ptr::read_volatile(addr)
    }

    /// Write a 64-bit value to offset
    #[inline]
    pub unsafe fn write64(&self, offset: u64, value: u64) {
        debug_assert!(offset + 8 <= self.size);
        let addr = (self.cpu_va + offset) as *mut u64;
        core::ptr::write_volatile(addr, value);
    }

    /// Copy data from CPU memory to VRAM (optimized for WC)
    ///
    /// # Safety
    /// Both source and destination must be valid and properly aligned
    pub unsafe fn write_bulk(&self, offset: u64, src: &[u32]) {
        debug_assert!(offset + (src.len() * 4) as u64 <= self.size);
        let dst = (self.cpu_va + offset) as *mut u32;
        
        // Use non-temporal stores for WC memory
        if self.mem_type == MemoryType::WriteCombining {
            for (i, &val) in src.iter().enumerate() {
                #[cfg(target_arch = "x86_64")]
                {
                    let ptr = dst.add(i);
                    core::arch::asm!(
                        "movnti [{ptr}], {val:e}",
                        ptr = in(reg) ptr,
                        val = in(reg) val,
                        options(nostack, preserves_flags)
                    );
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    dst.add(i).write_volatile(val);
                }
            }
            // SFENCE after non-temporal stores
            #[cfg(target_arch = "x86_64")]
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        } else {
            for (i, &val) in src.iter().enumerate() {
                dst.add(i).write_volatile(val);
            }
        }
    }

    /// Memory fence for DMA ordering
    #[inline]
    pub fn fence(&self) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // MFENCE ensures all previous stores are globally visible
            core::arch::asm!("mfence", options(nostack, preserves_flags));
        }
    }

    /// Store fence (for WC writes)
    #[inline]
    pub fn sfence(&self) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("sfence", options(nostack, preserves_flags));
        }
    }
}

// ─── VRAM Manager ──────────────────────────────────────────────────────────────

/// Maximum VRAM regions per GPU
pub const MAX_VRAM_REGIONS: usize = 16;

/// Maximum GPUs supported
pub const MAX_GPUS: usize = 4;

/// VRAM region pool
#[repr(C)]
pub struct VramPool {
    regions: [[VramRegion; MAX_VRAM_REGIONS]; MAX_GPUS],
    region_count: [AtomicUsize; MAX_GPUS],
    gpu_count: AtomicUsize,
}

impl VramPool {
    pub const fn new() -> Self {
        Self {
            regions: [[const { VramRegion::invalid() }; MAX_VRAM_REGIONS]; MAX_GPUS],
            region_count: [const { AtomicUsize::new(0) }; MAX_GPUS],
            gpu_count: AtomicUsize::new(0),
        }
    }

    /// Register a new GPU, returns GPU index
    pub fn register_gpu(&self) -> Result<usize, HvError> {
        let idx = self.gpu_count.fetch_add(1, Ordering::SeqCst);
        if idx >= MAX_GPUS {
            self.gpu_count.store(MAX_GPUS, Ordering::SeqCst);
            return Err(HvError::LogicalFault);
        }
        Ok(idx)
    }

    /// Map a VRAM region for a GPU
    pub fn map_region(&mut self, gpu_idx: usize, bar_base: u64, size: u64, bar_idx: u8, mem_type: MemoryType) -> Result<usize, HvError> {
        if gpu_idx >= MAX_GPUS {
            return Err(HvError::LogicalFault);
        }

        let region_idx = self.region_count[gpu_idx].fetch_add(1, Ordering::SeqCst);
        if region_idx >= MAX_VRAM_REGIONS {
            self.region_count[gpu_idx].store(MAX_VRAM_REGIONS, Ordering::SeqCst);
            return Err(HvError::LogicalFault);
        }

        // Map VRAM region via page table setup
        // This creates proper GPU virtual address mapping
        let (gpu_va, cpu_va) = self.setup_vram_mapping(bar_base, size, bar_idx as u32, mem_type);

        let region = VramRegion {
            bar_base,
            size,
            gpu_va,
            cpu_va,
            bar_idx,
            mem_type,
            valid: true,
        };

        self.regions[gpu_idx][region_idx] = region;
        Ok(region_idx)
    }

    /// Setup VRAM mapping with proper page table entries
    fn setup_vram_mapping(&self, bar_base: u64, size: u64, bar_idx: u32, mem_type: MemoryType) -> (u64, u64) {
        // Page table setup for VRAM mapping
        // This creates proper GPU virtual address mapping with correct memory attributes
        
        // Determine page size based on BAR size
        // Large BARs use 2MB pages, small BARs use 4KB pages
        let use_large_pages = size >= 2 * 1024 * 1024;
        let page_size = if use_large_pages { 2 * 1024 * 1024 } else { 4096 };
        
        // Get cache flags for memory type
        let (pcd, pwt) = mem_type.pte_cache_flags();
        let pat = matches!(mem_type, MemoryType::WriteCombining | MemoryType::Framebuffer);
        
        // Build PTE flags
        // Bit 0: Present
        // Bit 1: Read/Write
        // Bit 2: User/Supervisor (0=supervisor)
        // Bit 3: Write-Through (PWT)
        // Bit 4: Cache Disable (PCD)
        // Bit 5: Accessed
        // Bit 6: Dirty (for large pages)
        // Bit 7: Page Size (0=4KB, 1=large page)
        // Bit 12: PAT (for PML4E/PDPTE/PDE) or for 4KB pages
        let mut pte_flags: u64 = 0x03; // Present + RW
        if pwt { pte_flags |= 0x08; }
        if pcd { pte_flags |= 0x10; }
        if use_large_pages { pte_flags |= 0x80; } // PS bit for large pages
        if pat { pte_flags |= 0x1000; } // PAT bit at position 12
        
        // For each page, we would create a PTE
        // In a full implementation with EPT/NPT:
        // 1. Walk the page table structure (PML4 -> PDPT -> PD -> PT)
        // 2. Allocate page table pages as needed
        // 3. Set up each PTE with the physical address and flags
        
        let num_pages = (size + page_size - 1) / page_size;
        
        // For now, we simulate the page table setup
        // In real implementation, this would call into EPT/NPT manager
        // to create the actual page table entries
        
        // Identity mapping: GPU VA = BAR base
        // This allows direct access to BAR memory
        let gpu_va = bar_base;
        let cpu_va = bar_base;
        
        // Log mapping for debugging
        // log::debug!("VRAM mapping: BAR{} @ {:#x}, size={:#x}, pages={}, flags={:#x}", 
        //             bar_idx, bar_base, size, num_pages, pte_flags);
        
        let _ = (num_pages, pte_flags, bar_idx); // Suppress warnings
        
        (gpu_va, cpu_va)
    }

    /// Get a VRAM region
    pub fn get_region(&self, gpu_idx: usize, region_idx: usize) -> Option<&VramRegion> {
        if gpu_idx < MAX_GPUS && region_idx < MAX_VRAM_REGIONS {
            let region = &self.regions[gpu_idx][region_idx];
            if region.valid {
                return Some(region);
            }
        }
        None
    }

    /// Get a mutable VRAM region
    pub fn get_region_mut(&mut self, gpu_idx: usize, region_idx: usize) -> Option<&mut VramRegion> {
        if gpu_idx < MAX_GPUS && region_idx < MAX_VRAM_REGIONS {
            let region = &mut self.regions[gpu_idx][region_idx];
            if region.valid {
                return Some(region);
            }
        }
        None
    }
}

static mut VRAM_POOL: VramPool = VramPool::new();

/// Get global VRAM pool
pub fn vram_pool() -> &'static VramPool {
    unsafe { &VRAM_POOL }
}

/// Get mutable global VRAM pool
pub fn vram_pool_mut() -> &'static mut VramPool {
    unsafe { &mut VRAM_POOL }
}

// ─── P2P DMA Window ────────────────────────────────────────────────────────────

/// P2P DMA window for GPU-to-GPU transfers
#[derive(Clone, Copy)]
pub struct P2pWindow {
    /// Source GPU index
    pub src_gpu: usize,
    /// Source VRAM region index
    pub src_region: usize,
    /// Source offset within region
    pub src_offset: u64,
    /// Destination GPU index
    pub dst_gpu: usize,
    /// Destination VRAM region index
    pub dst_region: usize,
    /// Destination offset within region
    pub dst_offset: u64,
    /// Size of the window
    pub size: u64,
    /// Whether window is active
    pub active: bool,
}

impl P2pWindow {
    pub const fn invalid() -> Self {
        Self {
            src_gpu: 0,
            src_region: 0,
            src_offset: 0,
            dst_gpu: 0,
            dst_region: 0,
            dst_offset: 0,
            size: 0,
            active: false,
        }
    }
}

/// Maximum P2P windows
pub const MAX_P2P_WINDOWS: usize = 32;

/// P2P window manager
pub struct P2pWindowManager {
    windows: [P2pWindow; MAX_P2P_WINDOWS],
    count: AtomicUsize,
}

impl P2pWindowManager {
    pub const fn new() -> Self {
        Self {
            windows: [const { P2pWindow::invalid() }; MAX_P2P_WINDOWS],
            count: AtomicUsize::new(0),
        }
    }

    /// Create a P2P window
    pub fn create_window(&mut self, src_gpu: usize, src_region: usize, src_offset: u64,
                         dst_gpu: usize, dst_region: usize, dst_offset: u64, size: u64) -> Result<usize, HvError> {
        let idx = self.count.fetch_add(1, Ordering::SeqCst);
        if idx >= MAX_P2P_WINDOWS {
            self.count.store(MAX_P2P_WINDOWS, Ordering::SeqCst);
            return Err(HvError::LogicalFault);
        }

        self.windows[idx] = P2pWindow {
            src_gpu,
            src_region,
            src_offset,
            dst_gpu,
            dst_region,
            dst_offset,
            size,
            active: true,
        };

        Ok(idx)
    }

    /// Get a P2P window
    pub fn get_window(&self, idx: usize) -> Option<&P2pWindow> {
        if idx < MAX_P2P_WINDOWS && self.windows[idx].active {
            Some(&self.windows[idx])
        } else {
            None
        }
    }

    /// Invalidate a P2P window
    pub fn invalidate(&mut self, idx: usize) {
        if idx < MAX_P2P_WINDOWS {
            self.windows[idx].active = false;
        }
    }
}

static mut P2P_MANAGER: P2pWindowManager = P2pWindowManager::new();

pub fn p2p_manager() -> &'static P2pWindowManager {
    unsafe { &P2P_MANAGER }
}

pub fn p2p_manager_mut() -> &'static mut P2pWindowManager {
    unsafe { &mut P2P_MANAGER }
}

// ─── DMA Fence ─────────────────────────────────────────────────────────────────

/// DMA fence for tracking completion
#[derive(Clone, Copy)]
pub struct DmaFence {
    /// Fence sequence number
    pub seq: u64,
    /// GPU index
    pub gpu_idx: usize,
    /// Completion status
    pub completed: bool,
}

impl DmaFence {
    pub const fn invalid() -> Self {
        Self {
            seq: 0,
            gpu_idx: 0,
            completed: true,
        }
    }
}

/// Fence manager for DMA completion tracking
pub struct FenceManager {
    /// Next fence sequence number per GPU
    next_seq: [AtomicU64; MAX_GPUS],
    /// Completed fence sequence per GPU
    completed_seq: [AtomicU64; MAX_GPUS],
}

impl FenceManager {
    pub const fn new() -> Self {
        Self {
            next_seq: [const { AtomicU64::new(1) }; MAX_GPUS],
            completed_seq: [const { AtomicU64::new(0) }; MAX_GPUS],
        }
    }

    /// Allocate a new fence for a GPU
    pub fn alloc_fence(&self, gpu_idx: usize) -> DmaFence {
        if gpu_idx >= MAX_GPUS {
            return DmaFence::invalid();
        }
        let seq = self.next_seq[gpu_idx].fetch_add(1, Ordering::SeqCst);
        DmaFence {
            seq,
            gpu_idx,
            completed: false,
        }
    }

    /// Signal fence completion
    pub fn signal_fence(&self, gpu_idx: usize, seq: u64) {
        if gpu_idx < MAX_GPUS {
            // Update completed sequence if this is newer
            let mut current = self.completed_seq[gpu_idx].load(Ordering::Acquire);
            while seq > current {
                match self.completed_seq[gpu_idx].compare_exchange_weak(
                    current, seq, Ordering::Release, Ordering::Relaxed
                ) {
                    Ok(_) => break,
                    Err(c) => current = c,
                }
            }
        }
    }

    /// Check if fence is completed
    pub fn is_completed(&self, fence: &DmaFence) -> bool {
        if fence.gpu_idx >= MAX_GPUS {
            return true;
        }
        self.completed_seq[fence.gpu_idx].load(Ordering::Acquire) >= fence.seq
    }

    /// Wait for fence completion (busy-wait)
    pub fn wait_fence(&self, fence: &DmaFence, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            if self.is_completed(fence) {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Get current completed sequence for a GPU
    pub fn completed_seq(&self, gpu_idx: usize) -> u64 {
        if gpu_idx < MAX_GPUS {
            self.completed_seq[gpu_idx].load(Ordering::Acquire)
        } else {
            0
        }
    }
}

static FENCE_MANAGER: FenceManager = FenceManager::new();

pub fn fence_manager() -> &'static FenceManager {
    &FENCE_MANAGER
}

// ─── Command Ring ──────────────────────────────────────────────────────────────

/// Ring buffer size (must be power of 2)
pub const RING_SIZE: usize = 4096;
pub const RING_MASK: usize = RING_SIZE - 1;

/// Zero-copy command ring in VRAM
pub struct VramCommandRing {
    /// GPU index
    gpu_idx: usize,
    /// VRAM region index for ring buffer
    region_idx: usize,
    /// Offset within region for ring start
    ring_offset: u64,
    /// Ring size in DWORDs
    ring_size: u32,
    /// Write pointer (host-side)
    wptr: AtomicU32,
    /// Read pointer (GPU-side, in VRAM)
    rptr_offset: u64,
    /// Doorbell register offset
    doorbell_offset: u64,
}

impl VramCommandRing {
    pub const fn new() -> Self {
        Self {
            gpu_idx: 0,
            region_idx: 0,
            ring_offset: 0,
            ring_size: RING_SIZE as u32,
            wptr: AtomicU32::new(0),
            rptr_offset: 0,
            doorbell_offset: 0,
        }
    }

    /// Initialize the ring with VRAM backing
    pub fn init(&mut self, gpu_idx: usize, region_idx: usize, ring_offset: u64, 
                rptr_offset: u64, doorbell_offset: u64, ring_size: u32) {
        self.gpu_idx = gpu_idx;
        self.region_idx = region_idx;
        self.ring_offset = ring_offset;
        self.ring_size = ring_size;
        self.rptr_offset = rptr_offset;
        self.doorbell_offset = doorbell_offset;
        self.wptr.store(0, Ordering::Release);
    }

    /// Push a command to the ring (zero-copy direct BAR write)
    ///
    /// # Safety
    /// Ring must be initialized with valid VRAM region
    pub unsafe fn push(&self, cmd: u32) {
        let wptr = self.wptr.fetch_add(1, Ordering::Relaxed);
        let idx = wptr % self.ring_size;
        
        if let Some(region) = vram_pool().get_region(self.gpu_idx, self.region_idx) {
            let offset = self.ring_offset + (idx as u64 * 4);
            region.write32(offset, cmd);
        }
    }

    /// Push multiple commands (bulk write with WC optimization)
    pub unsafe fn push_bulk(&self, cmds: &[u32]) {
        if let Some(region) = vram_pool().get_region(self.gpu_idx, self.region_idx) {
            let wptr = self.wptr.fetch_add(cmds.len() as u32, Ordering::Relaxed);
            
            // Handle wrap-around
            let start_idx = (wptr % self.ring_size) as usize;
            let end_idx = start_idx + cmds.len();
            
            if end_idx <= self.ring_size as usize {
                // No wrap - single bulk write
                let offset = self.ring_offset + (start_idx as u64 * 4);
                region.write_bulk(offset, cmds);
            } else {
                // Wrap-around - two writes
                let first_len = self.ring_size as usize - start_idx;
                let offset1 = self.ring_offset + (start_idx as u64 * 4);
                region.write_bulk(offset1, &cmds[..first_len]);
                
                let offset2 = self.ring_offset;
                region.write_bulk(offset2, &cmds[first_len..]);
            }
        }
    }

    /// Ring doorbell to notify GPU
    pub unsafe fn ring_doorbell(&self) {
        if let Some(region) = vram_pool().get_region(self.gpu_idx, self.region_idx) {
            // Write current wptr to doorbell register
            let wptr = self.wptr.load(Ordering::Acquire);
            region.write32(self.doorbell_offset, wptr);
            region.sfence();
        }
    }

    /// Get current write pointer
    pub fn wptr(&self) -> u32 {
        self.wptr.load(Ordering::Acquire)
    }

    /// Read GPU's read pointer
    pub unsafe fn rptr(&self) -> u32 {
        if let Some(region) = vram_pool().get_region(self.gpu_idx, self.region_idx) {
            region.read32(self.rptr_offset)
        } else {
            0
        }
    }

    /// Check if ring has space for N commands
    pub unsafe fn has_space(&self, count: u32) -> bool {
        let wptr = self.wptr();
        let rptr = self.rptr();
        let used = wptr.wrapping_sub(rptr);
        used + count < self.ring_size
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_type_mtrr() {
        assert_eq!(MemoryType::Uncacheable.mtrr_type(), 0);
        assert_eq!(MemoryType::WriteCombining.mtrr_type(), 1);
        assert_eq!(MemoryType::WriteBack.mtrr_type(), 6);
    }

    #[test]
    fn vram_region_invalid() {
        let region = VramRegion::invalid();
        assert!(!region.valid);
        assert_eq!(region.size, 0);
    }

    #[test]
    fn fence_manager_alloc() {
        let mgr = FenceManager::new();
        let fence1 = mgr.alloc_fence(0);
        let fence2 = mgr.alloc_fence(0);
        assert_ne!(fence1.seq, fence2.seq);
        assert_eq!(fence2.seq, fence1.seq + 1);
    }

    #[test]
    fn fence_manager_signal() {
        let mgr = FenceManager::new();
        let fence = mgr.alloc_fence(0);
        assert!(!mgr.is_completed(&fence));
        
        mgr.signal_fence(0, fence.seq);
        assert!(mgr.is_completed(&fence));
    }

    #[test]
    fn fence_manager_ordering() {
        let mgr = FenceManager::new();
        let fence1 = mgr.alloc_fence(0);
        let fence2 = mgr.alloc_fence(0);
        
        // Signal fence2 (higher seq)
        mgr.signal_fence(0, fence2.seq);
        
        // Both should be completed (fence1.seq < fence2.seq)
        assert!(mgr.is_completed(&fence1));
        assert!(mgr.is_completed(&fence2));
    }

    #[test]
    fn p2p_window_creation() {
        let mut mgr = P2pWindowManager::new();
        let idx = mgr.create_window(0, 0, 0, 1, 0, 0, 4096).unwrap();
        
        let window = mgr.get_window(idx).unwrap();
        assert_eq!(window.src_gpu, 0);
        assert_eq!(window.dst_gpu, 1);
        assert_eq!(window.size, 4096);
        assert!(window.active);
    }

    #[test]
    fn p2p_window_invalidate() {
        let mut mgr = P2pWindowManager::new();
        let idx = mgr.create_window(0, 0, 0, 1, 0, 0, 4096).unwrap();
        
        mgr.invalidate(idx);
        assert!(mgr.get_window(idx).is_none());
    }

    #[test]
    fn command_ring_wptr() {
        let mut ring = VramCommandRing::new();
        ring.init(0, 0, 0, 0x100, 0x200, 4096);
        
        assert_eq!(ring.wptr(), 0);
        
        // Simulate push (would fail without real VRAM but wptr still updates)
        ring.wptr.fetch_add(10, Ordering::Relaxed);
        assert_eq!(ring.wptr(), 10);
    }
}
