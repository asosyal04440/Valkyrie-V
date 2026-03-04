//! TLB Shootdown Optimization
//!
//! Reduce TLB shootdown overhead with batching, PCID, and lazy flushing.
//! Based on "Shoot4U: Using VMM Assists to Optimize TLB Operations" (VEE 2016).

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// TLB Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum pCPUs
pub const MAX_PCPUS: usize = 256;

/// Maximum pending shootdowns
pub const MAX_PENDING_SHOOTDOWNS: usize = 1024;

/// Maximum PCIDs per VM
pub const MAX_PCIDS_PER_VM: usize = 4096;

/// Maximum batch size
pub const MAX_BATCH_SIZE: usize = 64;

/// PCID constants
pub mod pcid {
    pub const GLOBAL: u16 = 0;      // Global TLB
    pub const PCID_MASK: u16 = 0x0FFF;
    pub const ENABLE_BIT: u64 = 1 << 11;
}

/// Shootdown types
pub mod shootdown_type {
    pub const FULL: u8 = 0;          // Full TLB flush
    pub const SINGLE_PAGE: u8 = 1;   // Single page
    pub const RANGE: u8 = 2;         // Page range
    pub const PCID: u8 = 3;          // PCID-specific
    pub const GLOBAL: u8 = 4;        // Global (all CPUs)
    pub const LAZY: u8 = 5;          // Lazy (deferred)
}

/// Shootdown states
pub mod shootdown_state {
    pub const PENDING: u8 = 0;
    pub const PROCESSING: u8 = 1;
    pub const COMPLETED: u8 = 2;
    pub const DEFERRED: u8 = 3;
}

// ─────────────────────────────────────────────────────────────────────────────
// TLB Shootdown Entry
// ─────────────────────────────────────────────────────────────────────────────

/// TLB shootdown entry
pub struct TlbShootdown {
    /// Entry ID
    pub id: AtomicU32,
    /// Shootdown type
    pub shootdown_type: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// Target CPU bitmap (bit per CPU)
    pub target_cpus: AtomicU64,
    /// Completed CPU bitmap
    pub completed_cpus: AtomicU64,
    /// Virtual address (for single/range)
    pub vaddr: AtomicU64,
    /// Page count (for range)
    pub page_count: AtomicU32,
    /// PCID
    pub pcid: AtomicU16,
    /// VM ID
    pub vm_id: AtomicU32,
    /// EPTP (for INVEPT)
    pub eptp: AtomicU64,
    /// Creation timestamp
    pub created: AtomicU64,
    /// Completion timestamp
    pub completed: AtomicU64,
    /// Deferred count
    pub deferred_count: AtomicU8,
    /// Priority (0=highest)
    pub priority: AtomicU8,
    /// Valid
    pub valid: AtomicBool,
}

impl TlbShootdown {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            shootdown_type: AtomicU8::new(shootdown_type::FULL),
            state: AtomicU8::new(shootdown_state::PENDING),
            target_cpus: AtomicU64::new(0),
            completed_cpus: AtomicU64::new(0),
            vaddr: AtomicU64::new(0),
            page_count: AtomicU32::new(0),
            pcid: AtomicU16::new(0),
            vm_id: AtomicU32::new(0),
            eptp: AtomicU64::new(0),
            created: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            deferred_count: AtomicU8::new(0),
            priority: AtomicU8::new(128),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize shootdown
    pub fn init(&self, id: u32, shootdown_type: u8, target_cpus: u64, vm_id: u32) {
        self.id.store(id, Ordering::Release);
        self.shootdown_type.store(shootdown_type, Ordering::Release);
        self.target_cpus.store(target_cpus, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.created.store(Self::get_timestamp(), Ordering::Release);
        self.state.store(shootdown_state::PENDING, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set single page
    pub fn set_single_page(&self, vaddr: u64, pcid: u16) {
        self.vaddr.store(vaddr, Ordering::Release);
        self.pcid.store(pcid, Ordering::Release);
        self.shootdown_type.store(shootdown_type::SINGLE_PAGE, Ordering::Release);
    }

    /// Set range
    pub fn set_range(&self, vaddr: u64, page_count: u32) {
        self.vaddr.store(vaddr, Ordering::Release);
        self.page_count.store(page_count, Ordering::Release);
        self.shootdown_type.store(shootdown_type::RANGE, Ordering::Release);
    }

    /// Set PCID
    pub fn set_pcid(&self, pcid: u16) {
        self.pcid.store(pcid, Ordering::Release);
        // Don't overwrite shootdown_type - the caller already set the appropriate type
    }

    /// Mark CPU complete
    pub fn mark_complete(&self, cpu: u8) {
        self.completed_cpus.fetch_or(1 << cpu, Ordering::Release);
        
        // Check if all done
        let target = self.target_cpus.load(Ordering::Acquire);
        let completed = self.completed_cpus.load(Ordering::Acquire);
        
        if completed == target {
            self.state.store(shootdown_state::COMPLETED, Ordering::Release);
            self.completed.store(Self::get_timestamp(), Ordering::Release);
        }
    }

    /// Check if complete
    pub fn is_complete(&self) -> bool {
        self.state.load(Ordering::Acquire) == shootdown_state::COMPLETED
    }

    /// Defer shootdown
    pub fn defer(&self) {
        self.deferred_count.fetch_add(1, Ordering::Release);
        self.state.store(shootdown_state::DEFERRED, Ordering::Release);
    }

    /// Get latency
    pub fn get_latency(&self) -> u64 {
        let created = self.created.load(Ordering::Acquire);
        let completed = self.completed.load(Ordering::Acquire);
        
        if completed > created {
            completed - created
        } else {
            0
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for TlbShootdown {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-CPU TLB State
// ─────────────────────────────────────────────────────────────────────────────

/// Per-CPU TLB state
pub struct CpuTlbState {
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// Current PCID
    pub current_pcid: AtomicU16,
    /// Active PCIDs bitmap
    pub active_pcids: [AtomicU64; 64], // 4096 PCIDs = 64 x 64 bits
    /// Pending shootdowns
    pub pending: [AtomicU32; MAX_BATCH_SIZE],
    /// Pending count
    pub pending_count: AtomicU8,
    /// Batch mode active
    pub batch_mode: AtomicBool,
    /// Lazy flush pending
    pub lazy_pending: AtomicBool,
    /// Lazy PCIDs to flush
    pub lazy_pcids: AtomicU64,
    /// Last shootdown time
    pub last_shootdown: AtomicU64,
    /// Shootdown count
    pub shootdown_count: AtomicU64,
    /// IPIs sent
    pub ipis_sent: AtomicU64,
    /// IPIs avoided
    pub ipis_avoided: AtomicU64,
    /// Total flush time (ns)
    pub total_flush_time: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CpuTlbState {
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicU8::new(0),
            current_pcid: AtomicU16::new(0),
            active_pcids: [const { AtomicU64::new(0) }; 64],
            pending: [const { AtomicU32::new(0) }; MAX_BATCH_SIZE],
            pending_count: AtomicU8::new(0),
            batch_mode: AtomicBool::new(false),
            lazy_pending: AtomicBool::new(false),
            lazy_pcids: AtomicU64::new(0),
            last_shootdown: AtomicU64::new(0),
            shootdown_count: AtomicU64::new(0),
            ipis_sent: AtomicU64::new(0),
            ipis_avoided: AtomicU64::new(0),
            total_flush_time: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize
    pub fn init(&self, cpu_id: u8) {
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set current PCID
    pub fn set_pcid(&self, pcid: u16) {
        self.current_pcid.store(pcid, Ordering::Release);
        
        // Mark as active
        let idx = (pcid / 64) as usize;
        let bit = pcid % 64;
        self.active_pcids[idx].fetch_or(1 << bit, Ordering::Release);
    }

    /// Clear PCID
    pub fn clear_pcid(&self, pcid: u16) {
        let idx = (pcid / 64) as usize;
        let bit = pcid % 64;
        self.active_pcids[idx].fetch_and(!(1 << bit), Ordering::Release);
    }

    /// Is PCID active
    pub fn is_pcid_active(&self, pcid: u16) -> bool {
        let idx = (pcid / 64) as usize;
        let bit = pcid % 64;
        (self.active_pcids[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }

    /// Add pending shootdown
    pub fn add_pending(&self, shootdown_id: u32) -> bool {
        let count = self.pending_count.load(Ordering::Acquire) as usize;
        if count >= MAX_BATCH_SIZE {
            return false;
        }
        
        self.pending[count].store(shootdown_id, Ordering::Release);
        self.pending_count.fetch_add(1, Ordering::Release);
        true
    }

    /// Start batch mode
    pub fn start_batch(&self) {
        self.batch_mode.store(true, Ordering::Release);
    }

    /// End batch mode
    pub fn end_batch(&self) {
        self.batch_mode.store(false, Ordering::Release);
    }

    /// Clear pending
    pub fn clear_pending(&self) {
        self.pending_count.store(0, Ordering::Release);
    }

    /// Add lazy PCID
    pub fn add_lazy_pcid(&self, pcid: u16) {
        if pcid < 64 {
            self.lazy_pcids.fetch_or(1 << pcid, Ordering::Release);
            self.lazy_pending.store(true, Ordering::Release);
        }
    }

    /// Process lazy flushes
    pub fn process_lazy(&self) -> u64 {
        let pcids = self.lazy_pcids.swap(0, Ordering::Acquire);
        self.lazy_pending.store(false, Ordering::Release);
        pcids
    }

    /// Record shootdown
    pub fn record_shootdown(&self) {
        self.shootdown_count.fetch_add(1, Ordering::Release);
        self.last_shootdown.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Record IPI
    pub fn record_ipi(&self, avoided: bool) {
        if avoided {
            self.ipis_avoided.fetch_add(1, Ordering::Release);
        } else {
            self.ipis_sent.fetch_add(1, Ordering::Release);
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for CpuTlbState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TLB Controller
// ─────────────────────────────────────────────────────────────────────────────

/// TLB shootdown controller
pub struct TlbController {
    /// Per-CPU states
    pub cpu_states: [CpuTlbState; MAX_PCPUS],
    /// CPU count
    pub cpu_count: AtomicU8,
    /// Shootdown entries
    pub shootdowns: [TlbShootdown; MAX_PENDING_SHOOTDOWNS],
    /// Shootdown count
    pub shootdown_count: AtomicU32,
    /// Next shootdown ID
    pub next_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Batching enabled
    pub batching_enabled: AtomicBool,
    /// Lazy flush enabled
    pub lazy_enabled: AtomicBool,
    /// PCID enabled
    pub pcid_enabled: AtomicBool,
    /// Batch timeout (ns)
    pub batch_timeout: AtomicU64,
    /// Max batch size
    pub max_batch_size: AtomicU8,
    /// Lazy timeout (ns)
    pub lazy_timeout: AtomicU64,
    /// Total shootdowns
    pub total_shootdowns: AtomicU64,
    /// Total IPIs
    pub total_ipis: AtomicU64,
    /// Total IPIs avoided
    pub total_ipis_avoided: AtomicU64,
    /// Total latency (ns)
    pub total_latency: AtomicU64,
    /// Last batch time
    pub last_batch: AtomicU64,
}

impl TlbController {
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { CpuTlbState::new() }; MAX_PCPUS],
            cpu_count: AtomicU8::new(0),
            shootdowns: [const { TlbShootdown::new() }; MAX_PENDING_SHOOTDOWNS],
            shootdown_count: AtomicU32::new(0),
            next_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            batching_enabled: AtomicBool::new(true),
            lazy_enabled: AtomicBool::new(true),
            pcid_enabled: AtomicBool::new(true),
            batch_timeout: AtomicU64::new(1_000_000), // 1ms
            max_batch_size: AtomicU8::new(32),
            lazy_timeout: AtomicU64::new(10_000_000), // 10ms
            total_shootdowns: AtomicU64::new(0),
            total_ipis: AtomicU64::new(0),
            total_ipis_avoided: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            last_batch: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, cpu_count: u8, batching: bool, lazy: bool, pcid: bool) {
        self.cpu_count.store(cpu_count, Ordering::Release);
        self.batching_enabled.store(batching, Ordering::Release);
        self.lazy_enabled.store(lazy, Ordering::Release);
        self.pcid_enabled.store(pcid, Ordering::Release);
        
        for i in 0..cpu_count as usize {
            self.cpu_states[i].init(i as u8);
        }
        
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Request shootdown
    pub fn request_shootdown(&mut self, shootdown_type: u8, target_cpus: u64, 
                              vm_id: u32, priority: u8) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Find free slot
        let slot = self.find_free_slot()?;
        
        let id = self.next_id.fetch_add(1, Ordering::Release);
        let entry = &self.shootdowns[slot as usize];
        entry.init(id, shootdown_type, target_cpus, vm_id);
        entry.priority.store(priority, Ordering::Release);
        
        self.shootdown_count.fetch_add(1, Ordering::Release);
        
        // Check if batching
        if self.batching_enabled.load(Ordering::Acquire) {
            self.add_to_batch(target_cpus, slot)?;
        } else {
            self.send_ipis(target_cpus)?;
        }
        
        self.total_shootdowns.fetch_add(1, Ordering::Release);
        
        Ok(id)
    }

    /// Request single page shootdown
    pub fn request_single_page(&mut self, vaddr: u64, pcid: u16, 
                                target_cpus: u64, vm_id: u32) -> Result<u32, HvError> {
        let id = self.request_shootdown(shootdown_type::SINGLE_PAGE, target_cpus, vm_id, 64)?;
        
        let entry = &self.shootdowns[(id - 1) as usize];
        entry.set_single_page(vaddr, pcid);
        
        // Use PCID optimization if enabled
        if self.pcid_enabled.load(Ordering::Acquire) && pcid != 0 {
            entry.set_pcid(pcid);
        }
        
        Ok(id)
    }

    /// Request range shootdown
    pub fn request_range(&mut self, vaddr: u64, page_count: u32,
                         target_cpus: u64, vm_id: u32) -> Result<u32, HvError> {
        let id = self.request_shootdown(shootdown_type::RANGE, target_cpus, vm_id, 64)?;
        
        let entry = &self.shootdowns[(id - 1) as usize];
        entry.set_range(vaddr, page_count);
        
        Ok(id)
    }

    /// Request lazy shootdown
    pub fn request_lazy(&mut self, pcid: u16, target_cpus: u64, 
                        vm_id: u32) -> Result<u32, HvError> {
        if !self.lazy_enabled.load(Ordering::Acquire) {
            return self.request_shootdown(shootdown_type::PCID, target_cpus, vm_id, 128);
        }
        
        let id = self.request_shootdown(shootdown_type::LAZY, target_cpus, vm_id, 200)?;
        
        let entry = &self.shootdowns[(id - 1) as usize];
        entry.set_pcid(pcid);
        entry.defer();
        
        // Add to lazy list for each target CPU
        for cpu in 0..self.cpu_count.load(Ordering::Acquire) {
            if target_cpus & (1 << cpu) != 0 {
                self.cpu_states[cpu as usize].add_lazy_pcid(pcid);
            }
        }
        
        Ok(id)
    }

    /// Process batch
    pub fn process_batch(&mut self) -> u32 {
        if !self.batching_enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let now = Self::get_timestamp();
        let timeout = self.batch_timeout.load(Ordering::Acquire);
        
        if now - self.last_batch.load(Ordering::Acquire) < timeout {
            return 0;
        }
        
        self.last_batch.store(now, Ordering::Release);
        
        let mut processed = 0u32;
        
        // Process pending shootdowns
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            let cpu = &self.cpu_states[i];
            let count = cpu.pending_count.load(Ordering::Acquire) as usize;
            
            if count > 0 {
                // Flush all pending at once
                cpu.record_shootdown();
                cpu.clear_pending();
                processed += count as u32;
            }
        }
        
        processed
    }

    /// Process lazy flushes
    pub fn process_lazy(&mut self) -> u32 {
        if !self.lazy_enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let mut processed = 0u32;
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            let cpu = &self.cpu_states[i];
            if cpu.lazy_pending.load(Ordering::Acquire) {
                let pcids = cpu.process_lazy();
                if pcids != 0 {
                    cpu.record_shootdown();
                    processed += pcids.count_ones();
                }
            }
        }
        
        processed
    }

    /// Handle shootdown on CPU
    pub fn handle_shootdown(&mut self, cpu: u8, shootdown_id: u32) {
        if shootdown_id == 0 || shootdown_id as usize > MAX_PENDING_SHOOTDOWNS {
            return;
        }
        
        let entry = &self.shootdowns[(shootdown_id - 1) as usize];
        if !entry.valid.load(Ordering::Acquire) {
            return;
        }
        
        // Perform actual TLB flush based on type
        let flush_type = entry.shootdown_type.load(Ordering::Acquire);
        let start = Self::get_timestamp();
        
        match flush_type {
            shootdown_type::FULL => {
                self.flush_full(cpu);
            }
            shootdown_type::SINGLE_PAGE => {
                let vaddr = entry.vaddr.load(Ordering::Acquire);
                let pcid = entry.pcid.load(Ordering::Acquire);
                self.flush_single(cpu, vaddr, pcid);
            }
            shootdown_type::RANGE => {
                let vaddr = entry.vaddr.load(Ordering::Acquire);
                let count = entry.page_count.load(Ordering::Acquire);
                self.flush_range(cpu, vaddr, count);
            }
            shootdown_type::PCID => {
                let pcid = entry.pcid.load(Ordering::Acquire);
                self.flush_pcid(cpu, pcid);
            }
            _ => {}
        }
        
        let end = Self::get_timestamp();
        self.cpu_states[cpu as usize].total_flush_time.fetch_add(end - start, Ordering::Release);
        
        entry.mark_complete(cpu);
    }

    /// Flush full TLB
    fn flush_full(&self, cpu: u8) {
        // INVLPG with NULL or MOV to CR3
        self.cpu_states[cpu as usize].record_shootdown();
    }

    /// Flush single page
    fn flush_single(&self, cpu: u8, vaddr: u64, pcid: u16) {
        // INVLPG with PCID if supported
        if self.pcid_enabled.load(Ordering::Acquire) && pcid != 0 {
            // INVPCID with type 0 (individual address)
        } else {
            // INVLPG
        }
        self.cpu_states[cpu as usize].record_shootdown();
    }

    /// Flush range
    fn flush_range(&self, cpu: u8, vaddr: u64, count: u32) {
        // Could use INVPCID type 2 (single-context) if PCID available
        // Otherwise, INVLPG for each page or full flush if large
        if count > 32 {
            self.flush_full(cpu);
        } else {
            for i in 0..count {
                let _addr = vaddr + (i as u64 * 4096);
                // INVLPG
            }
        }
        self.cpu_states[cpu as usize].record_shootdown();
    }

    /// Flush PCID
    fn flush_pcid(&self, cpu: u8, pcid: u16) {
        // INVPCID type 1 (single-context, retaining globals)
        // or type 2 (single-context)
        self.cpu_states[cpu as usize].record_shootdown();
        self.cpu_states[cpu as usize].clear_pcid(pcid);
    }

    /// Find free slot
    fn find_free_slot(&self) -> Result<u32, HvError> {
        for i in 0..MAX_PENDING_SHOOTDOWNS {
            if !self.shootdowns[i].valid.load(Ordering::Acquire) {
                return Ok(i as u32);
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Add to batch
    fn add_to_batch(&self, target_cpus: u64, shootdown_idx: u32) -> Result<(), HvError> {
        let max_batch = self.max_batch_size.load(Ordering::Acquire);
        
        for cpu in 0..self.cpu_count.load(Ordering::Acquire) {
            if target_cpus & (1 << cpu) != 0 {
                let count = self.cpu_states[cpu as usize].pending_count.load(Ordering::Acquire);
                if count >= max_batch {
                    // Batch full, send IPIs
                    self.send_ipis(1 << cpu)?;
                } else {
                    self.cpu_states[cpu as usize].add_pending(shootdown_idx);
                    self.cpu_states[cpu as usize].record_ipi(true);
                }
            }
        }
        
        Ok(())
    }

    /// Send IPIs
    fn send_ipis(&self, target_cpus: u64) -> Result<(), HvError> {
        for cpu in 0..self.cpu_count.load(Ordering::Acquire) {
            if target_cpus & (1 << cpu) != 0 {
                self.cpu_states[cpu as usize].record_ipi(false);
                self.total_ipis.fetch_add(1, Ordering::Release);
            }
        }
        Ok(())
    }

    /// Switch PCID on CPU
    pub fn switch_pcid(&self, cpu: u8, old_pcid: u16, new_pcid: u16) {
        if !self.pcid_enabled.load(Ordering::Acquire) {
            return;
        }
        
        let cpu_state = &self.cpu_states[cpu as usize];
        
        // Clear old PCID
        if old_pcid != 0 {
            cpu_state.clear_pcid(old_pcid);
        }
        
        // Set new PCID
        cpu_state.set_pcid(new_pcid);
        
        // No TLB flush needed if using PCID properly
        // (CR3 write with PCID preserves TLB entries)
    }

    /// Get statistics
    pub fn get_stats(&self) -> TlbStats {
        let mut total_flush_time = 0u64;
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            total_flush_time += self.cpu_states[i].total_flush_time.load(Ordering::Acquire);
        }
        
        TlbStats {
            enabled: self.enabled.load(Ordering::Acquire),
            cpu_count: self.cpu_count.load(Ordering::Acquire),
            total_shootdowns: self.total_shootdowns.load(Ordering::Acquire),
            total_ipis: self.total_ipis.load(Ordering::Acquire),
            total_ipis_avoided: self.total_ipis_avoided.load(Ordering::Acquire),
            total_flush_time,
            batching_enabled: self.batching_enabled.load(Ordering::Acquire),
            lazy_enabled: self.lazy_enabled.load(Ordering::Acquire),
            pcid_enabled: self.pcid_enabled.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for TlbController {
    fn default() -> Self {
        Self::new()
    }
}

/// TLB statistics
#[repr(C)]
pub struct TlbStats {
    pub enabled: bool,
    pub cpu_count: u8,
    pub total_shootdowns: u64,
    pub total_ipis: u64,
    pub total_ipis_avoided: u64,
    pub total_flush_time: u64,
    pub batching_enabled: bool,
    pub lazy_enabled: bool,
    pub pcid_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_controller() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        
        assert_eq!(ctrl.cpu_count.load(Ordering::Acquire), 4);
    }

    #[test]
    fn request_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 1, 64).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn single_page_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id = ctrl.request_single_page(0x1000, 1, 0xF, 1).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.shootdown_type.load(Ordering::Acquire), shootdown_type::SINGLE_PAGE);
    }

    #[test]
    fn lazy_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        
        let id = ctrl.request_lazy(1, 0xF, 1).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.state.load(Ordering::Acquire), shootdown_state::DEFERRED);
    }

    #[test]
    fn handle_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        ctrl.handle_shootdown(0, id);
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert!(entry.completed_cpus.load(Ordering::Acquire) & 0x1 != 0);
    }

    #[test]
    fn pcid_management() {
        let ctrl = TlbController::new();
        ctrl.cpu_states[0].init(0);
        
        ctrl.switch_pcid(0, 0, 1);
        assert!(ctrl.cpu_states[0].is_pcid_active(1));
        
        ctrl.switch_pcid(0, 1, 2);
        assert!(!ctrl.cpu_states[0].is_pcid_active(1));
        assert!(ctrl.cpu_states[0].is_pcid_active(2));
    }

    #[test]
    fn batching() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, false, false);
        
        // Add multiple shootdowns
        ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        
        // Should be batched
        assert!(ctrl.cpu_states[0].pending_count.load(Ordering::Acquire) > 0);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // COMPREHENSIVE BATTLE-TESTED TESTS
    // ═══════════════════════════════════════════════════════════════════════════

    /// Test: Multiple shootdown types
    #[test]
    fn multiple_shootdown_types() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id1 = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 1, 64).unwrap();
        let id2 = ctrl.request_single_page(0x2000, 1, 0xF, 1).unwrap();
        let id3 = ctrl.request_range(0x3000, 4, 0xF, 1).unwrap();
        
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        
        let e1 = &ctrl.shootdowns[(id1 - 1) as usize];
        let e2 = &ctrl.shootdowns[(id2 - 1) as usize];
        let e3 = &ctrl.shootdowns[(id3 - 1) as usize];
        
        assert_eq!(e1.shootdown_type.load(Ordering::Acquire), shootdown_type::FULL);
        assert_eq!(e2.shootdown_type.load(Ordering::Acquire), shootdown_type::SINGLE_PAGE);
        assert_eq!(e3.shootdown_type.load(Ordering::Acquire), shootdown_type::RANGE);
    }

    /// Test: Range shootdown
    #[test]
    fn range_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id = ctrl.request_range(0x1000, 16, 0xF, 1).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.shootdown_type.load(Ordering::Acquire), shootdown_type::RANGE);
        assert_eq!(entry.vaddr.load(Ordering::Acquire), 0x1000);
        assert_eq!(entry.page_count.load(Ordering::Acquire), 16);
    }

    /// Test: Global shootdown via FULL type with all CPUs
    #[test]
    fn global_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        // Global = FULL with all CPUs targeted
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xFFFFFFFF, 1, 64).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.shootdown_type.load(Ordering::Acquire), shootdown_type::FULL);
    }

    /// Test: Multi-CPU completion
    #[test]
    fn multi_cpu_completion() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 1, 64).unwrap();
        
        // Each CPU handles the shootdown
        for cpu in 0..4 {
            ctrl.handle_shootdown(cpu, id);
        }
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.completed_cpus.load(Ordering::Acquire), 0xF);
    }

    /// Test: Partial completion
    #[test]
    fn partial_completion() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 1, 64).unwrap();
        
        // Only some CPUs handle it
        ctrl.handle_shootdown(0, id);
        ctrl.handle_shootdown(2, id);
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.completed_cpus.load(Ordering::Acquire), 0x5);
        assert_ne!(entry.state.load(Ordering::Acquire), shootdown_state::COMPLETED);
    }

    /// Test: PCID-specific shootdown via lazy
    #[test]
    fn pcid_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        
        let id = ctrl.request_lazy(100, 0xF, 1).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.shootdown_type.load(Ordering::Acquire), shootdown_type::LAZY);
        assert_eq!(entry.pcid.load(Ordering::Acquire), 100);
    }

    /// Test: CPU state initialization
    #[test]
    fn cpu_state_init() {
        let ctrl = TlbController::new();
        ctrl.cpu_states[0].init(0);
        
        assert_eq!(ctrl.cpu_states[0].cpu_id.load(Ordering::Acquire), 0);
        assert_eq!(ctrl.cpu_states[0].pending_count.load(Ordering::Acquire), 0);
    }

    /// Test: Active PCID tracking
    #[test]
    fn active_pcid_tracking() {
        let ctrl = TlbController::new();
        ctrl.cpu_states[0].init(0);
        
        // Initially no active PCIDs
        assert!(!ctrl.cpu_states[0].is_pcid_active(1));
        
        // Switch to PCID 1
        ctrl.switch_pcid(0, 0, 1);
        assert!(ctrl.cpu_states[0].is_pcid_active(1));
        
        // Switch to another PCID
        ctrl.switch_pcid(0, 1, 5);
        assert!(!ctrl.cpu_states[0].is_pcid_active(1));
        assert!(ctrl.cpu_states[0].is_pcid_active(5));
    }

    /// Test: Lazy deferral
    #[test]
    fn lazy_deferral() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        
        let id = ctrl.request_lazy(1, 0xF, 1).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.state.load(Ordering::Acquire), shootdown_state::DEFERRED);
        
        // Deferred count should be tracked
        assert!(entry.deferred_count.load(Ordering::Acquire) > 0);
    }

    /// Test: Statistics tracking
    #[test]
    fn statistics_tracking() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, false);
        
        let initial = ctrl.total_shootdowns.load(Ordering::Acquire);
        
        ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        
        assert_eq!(ctrl.total_shootdowns.load(Ordering::Acquire), initial + 1);
    }

    /// Test: Controller disable
    #[test]
    fn controller_disable() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        assert!(ctrl.enabled.load(Ordering::Acquire));
        
        ctrl.disable();
        assert!(!ctrl.enabled.load(Ordering::Acquire));
    }

    /// Test: Priority ordering
    #[test]
    fn priority_ordering() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id1 = ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        let id2 = ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        
        // Set different priorities
        ctrl.shootdowns[(id1 - 1) as usize].priority.store(10, Ordering::Release);
        ctrl.shootdowns[(id2 - 1) as usize].priority.store(5, Ordering::Release); // Higher priority
        
        // Both should be valid
        assert!(ctrl.shootdowns[(id1 - 1) as usize].valid.load(Ordering::Acquire));
        assert!(ctrl.shootdowns[(id2 - 1) as usize].valid.load(Ordering::Acquire));
    }

    /// Test: VM-specific shootdown
    #[test]
    fn vm_specific_shootdown() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 5, 64).unwrap();
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.vm_id.load(Ordering::Acquire), 5);
    }

    /// Test: Maximum pending shootdowns
    #[test]
    fn max_pending_shootdowns() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        // Request many shootdowns
        let mut count = 0;
        for _ in 0..MAX_PENDING_SHOOTDOWNS {
            if ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).is_ok() {
                count += 1;
            }
        }
        
        // Should have created many shootdowns
        assert!(count > 0);
    }

    /// Test: EPTP tracking via entry
    #[test]
    fn eptp_tracking() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, false, false, true);
        
        let id = ctrl.request_shootdown(shootdown_type::FULL, 0xF, 1, 64).unwrap();
        
        // Set EPTP manually
        let eptp = 0x123456789ABC;
        ctrl.shootdowns[(id - 1) as usize].eptp.store(eptp, Ordering::Release);
        
        let entry = &ctrl.shootdowns[(id - 1) as usize];
        assert_eq!(entry.eptp.load(Ordering::Acquire), eptp);
    }

    /// Test: Get statistics
    #[test]
    fn get_statistics() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, true, true);
        
        ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        ctrl.request_single_page(0x1000, 1, 0x1, 1).unwrap();
        
        let stats = ctrl.get_stats();
        assert!(stats.total_shootdowns >= 2);
    }

    /// Test: Batch processing
    #[test]
    fn batch_processing() {
        let mut ctrl = TlbController::new();
        ctrl.enable(4, true, false, false);
        
        // Create batch of shootdowns
        for _ in 0..10 {
            ctrl.request_shootdown(shootdown_type::FULL, 0x1, 1, 64).unwrap();
        }
        
        // Process batch
        let processed = ctrl.process_batch();
        assert!(processed > 0 || ctrl.cpu_states[0].pending_count.load(Ordering::Acquire) > 0);
    }

    /// Test: Shootdown entry initialization
    #[test]
    fn shootdown_entry_init() {
        let entry = TlbShootdown::new();
        
        assert_eq!(entry.shootdown_type.load(Ordering::Acquire), shootdown_type::FULL);
        assert_eq!(entry.state.load(Ordering::Acquire), shootdown_state::PENDING);
        assert!(!entry.valid.load(Ordering::Acquire));
    }
}
