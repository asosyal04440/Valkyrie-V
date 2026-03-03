//! EPT Cache Optimization
//!
//! Optimize EPT structure for better TLB hit rate with large pages, pre-fetch, and batching.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// EPT Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Page sizes
pub const PAGE_4K: u64 = 4096;
pub const PAGE_2M: u64 = 2 * 1024 * 1024;
pub const PAGE_1G: u64 = 1024 * 1024 * 1024;

/// EPT levels
pub mod ept_level {
    pub const PML4: u8 = 4;
    pub const PDPT: u8 = 3;
    pub const PD: u8 = 2;
    pub const PT: u8 = 1;
}

/// EPT entry flags
pub mod ept_flag {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const EXEC: u64 = 1 << 2;
    pub const MEMORY_TYPE: u64 = 0x7 << 3;
    pub const IGNORE_PAT: u64 = 1 << 6;
    pub const ACCESSED: u64 = 1 << 8;
    pub const DIRTY: u64 = 1 << 9;
    pub const EXEC_SUPER: u64 = 1 << 10;
    pub const VE: u64 = 1 << 11;
    pub const LARGE: u64 = 1 << 7;
    pub const PRESENT: u64 = 1 << 63;
}

/// Maximum EPT entries cached
pub const MAX_EPT_CACHE: usize = 65536;

/// Maximum EPT violations batched
pub const MAX_VIOLATION_BATCH: usize = 256;

/// Maximum VMs
pub const MAX_EPT_VMS: usize = 256;

// ─────────────────────────────────────────────────────────────────────────────
// EPT Cache Entry
// ─────────────────────────────────────────────────────────────────────────────

/// EPT cache entry
pub struct EptCacheEntry {
    /// Guest physical address (page aligned)
    pub gpa: AtomicU64,
    /// Host physical address (page aligned)
    pub hpa: AtomicU64,
    /// EPT entry value
    pub ept_entry: AtomicU64,
    /// Page size type (0=4K, 1=2M, 2=1G)
    pub page_size: AtomicU8,
    /// EPT level
    pub level: AtomicU8,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Access count
    pub access_count: AtomicU32,
    /// Last access timestamp
    pub last_access: AtomicU64,
    /// Is large page candidate
    pub large_candidate: AtomicBool,
    /// Is dirty
    pub dirty: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl EptCacheEntry {
    pub const fn new() -> Self {
        Self {
            gpa: AtomicU64::new(0),
            hpa: AtomicU64::new(0),
            ept_entry: AtomicU64::new(0),
            page_size: AtomicU8::new(0),
            level: AtomicU8::new(ept_level::PT),
            vm_id: AtomicU32::new(0),
            access_count: AtomicU32::new(0),
            last_access: AtomicU64::new(0),
            large_candidate: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize entry
    pub fn init(&self, gpa: u64, hpa: u64, ept_entry: u64, vm_id: u32, level: u8) {
        self.gpa.store(gpa, Ordering::Release);
        self.hpa.store(hpa, Ordering::Release);
        self.ept_entry.store(ept_entry, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.level.store(level, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self, is_write: bool) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
        
        if is_write {
            self.dirty.store(true, Ordering::Release);
        }
    }

    /// Check if can promote to large page
    pub fn check_large_candidate(&self) -> bool {
        self.access_count.load(Ordering::Acquire) > 100
    }

    /// Update EPT entry
    pub fn update_entry(&self, entry: u64) {
        self.ept_entry.store(entry, Ordering::Release);
    }

    /// Get flags
    pub fn get_flags(&self) -> u64 {
        self.ept_entry.load(Ordering::Acquire) & 0xFFF
    }

    /// Check flag
    pub fn has_flag(&self, flag: u64) -> bool {
        (self.ept_entry.load(Ordering::Acquire) & flag) != 0
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for EptCacheEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EPT Violation Entry
// ─────────────────────────────────────────────────────────────────────────────

/// EPT violation entry
pub struct EptViolation {
    /// Violation ID
    pub id: AtomicU32,
    /// GPA that caused violation
    pub gpa: AtomicU64,
    /// Qualification bits
    pub qualification: AtomicU64,
    /// VM ID
    pub vm_id: AtomicU32,
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// Violation type (read=0, write=1, exec=2)
    pub viol_type: AtomicU8,
    /// Is large page miss
    pub large_miss: AtomicBool,
    /// Resolution status
    pub status: AtomicU8,
    /// Timestamp
    pub timestamp: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl EptViolation {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            gpa: AtomicU64::new(0),
            qualification: AtomicU64::new(0),
            vm_id: AtomicU32::new(0),
            cpu_id: AtomicU8::new(0),
            viol_type: AtomicU8::new(0),
            large_miss: AtomicBool::new(false),
            status: AtomicU8::new(0),
            timestamp: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize violation
    pub fn init(&self, id: u32, gpa: u64, qualification: u64, vm_id: u32, cpu: u8) {
        self.id.store(id, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.qualification.store(qualification, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.cpu_id.store(cpu, Ordering::Release);
        self.timestamp.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
        
        // Parse qualification
        let qual = qualification;
        self.viol_type.store(
            if qual & 2 != 0 { 1 } else if qual & 4 != 0 { 2 } else { 0 },
            Ordering::Release
        );
    }

    /// Set status
    pub fn set_status(&self, status: u8) {
        self.status.store(status, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for EptViolation {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-VM EPT State
// ─────────────────────────────────────────────────────────────────────────────

/// Per-VM EPT state
pub struct VmEptState {
    /// VM ID
    pub vm_id: AtomicU32,
    /// EPTP value
    pub eptp: AtomicU64,
    /// EPTP base address
    pub eptp_base: AtomicU64,
    /// Memory type (0=UC, 1=WC, 4=WT, 5=WP, 6=WB)
    pub memory_type: AtomicU8,
    /// Enable dirty page tracking
    pub dirty_tracking: AtomicBool,
    /// Enable PML
    pub pml_enabled: AtomicBool,
    /// PML address
    pub pml_addr: AtomicU64,
    /// PML index
    pub pml_index: AtomicU16,
    /// 4K page count
    pub pages_4k: AtomicU64,
    /// 2M page count
    pub pages_2m: AtomicU64,
    /// 1G page count
    pub pages_1g: AtomicU64,
    /// EPT violations
    pub violations: AtomicU64,
    /// EPT violations resolved
    pub violations_resolved: AtomicU64,
    /// Large page promotions
    pub large_promotions: AtomicU64,
    /// Large page demotions
    pub large_demotions: AtomicU64,
    /// Cache hits
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// Prefetch count
    pub prefetch_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmEptState {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            eptp: AtomicU64::new(0),
            eptp_base: AtomicU64::new(0),
            memory_type: AtomicU8::new(6), // WB
            dirty_tracking: AtomicBool::new(false),
            pml_enabled: AtomicBool::new(false),
            pml_addr: AtomicU64::new(0),
            pml_index: AtomicU16::new0),
            pages_4k: AtomicU64::new(0),
            pages_2m: AtomicU64::new(0),
            pages_1g: AtomicU64::new(0),
            violations: AtomicU64::new(0),
            violations_resolved: AtomicU64::new(0),
            large_promotions: AtomicU64::new(0),
            large_demotions: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            prefetch_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize VM EPT
    pub fn init(&self, vm_id: u32, eptp_base: u64, memory_type: u8) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.eptp_base.store(eptp_base, Ordering::Release);
        self.memory_type.store(memory_type, Ordering::Release);
        
        // Build EPTP
        let eptp = eptp_base | ((memory_type as u64) << 3) | (1 << 6); // Enable WB, walk length 4
        self.eptp.store(eptp, Ordering::Release);
        
        self.valid.store(true, Ordering::Release);
    }

    /// Enable dirty tracking
    pub fn enable_dirty_tracking(&self, pml_addr: u64) {
        self.dirty_tracking.store(true, Ordering::Release);
        self.pml_enabled.store(true, Ordering::Release);
        self.pml_addr.store(pml_addr, Ordering::Release);
        
        // Update EPTP with dirty tracking
        let eptp = self.eptp.load(Ordering::Acquire) | (1 << 5);
        self.eptp.store(eptp, Ordering::Release);
    }

    /// Record violation
    pub fn record_violation(&self) {
        self.violations.fetch_add(1, Ordering::Release);
    }

    /// Record resolution
    pub fn record_resolution(&self) {
        self.violations_resolved.fetch_add(1, Ordering::Release);
    }

    /// Record cache hit
    pub fn record_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Release);
    }

    /// Record cache miss
    pub fn record_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Release);
    }

    /// Get hit rate
    pub fn get_hit_rate(&self) -> u32 {
        let hits = self.cache_hits.load(Ordering::Acquire);
        let misses = self.cache_misses.load(Ordering::Acquire);
        let total = hits + misses;
        
        if total == 0 {
            return 0;
        }
        
        ((hits * 100) / total) as u32
    }

    /// Get large page percentage
    pub fn get_large_page_pct(&self) -> u32 {
        let pages_4k = self.pages_4k.load(Ordering::Acquire);
        let pages_2m = self.pages_2m.load(Ordering::Acquire);
        let pages_1g = self.pages_1g.load(Ordering::Acquire);
        
        // 2M page = 512 4K pages
        // 1G page = 512 2M pages = 262144 4K pages
        let total_4k = pages_4k + pages_2m * 512 + pages_1g * 262144;
        
        if total_4k == 0 {
            return 0;
        }
        
        let large_4k = pages_2m * 512 + pages_1g * 262144;
        ((large_4k * 100) / total_4k) as u32
    }
}

impl Default for VmEptState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EPT Controller
// ─────────────────────────────────────────────────────────────────────────────

/// EPT controller
pub struct EptController {
    /// Cache entries
    pub cache: [EptCacheEntry; MAX_EPT_CACHE],
    /// Cache count
    pub cache_count: AtomicU32,
    /// VM states
    pub vm_states: [VmEptState; MAX_EPT_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Violation batch
    pub violations: [EptViolation; MAX_VIOLATION_BATCH],
    /// Violation count
    pub violation_count: AtomicU16,
    /// Next violation ID
    pub next_violation_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Large page promotion enabled
    pub large_page_enabled: AtomicBool,
    /// Prefetch enabled
    pub prefetch_enabled: AtomicBool,
    /// Violation batching enabled
    pub batch_enabled: AtomicBool,
    /// PML enabled
    pub pml_enabled: AtomicBool,
    /// Large page threshold (accesses before promotion)
    pub large_threshold: AtomicU32,
    /// Prefetch distance (pages)
    pub prefetch_distance: AtomicU16,
    /// Batch timeout (ns)
    pub batch_timeout: AtomicU64,
    /// Last batch time
    pub last_batch: AtomicU64,
    /// Total violations
    pub total_violations: AtomicU64,
    /// Total promotions
    pub total_promotions: AtomicU64,
    /// Total demotions
    pub total_demotions: AtomicU64,
    /// Total prefetches
    pub total_prefetches: AtomicU64,
}

impl EptController {
    pub const fn new() -> Self {
        Self {
            cache: [const { EptCacheEntry::new() }; MAX_EPT_CACHE],
            cache_count: AtomicU32::new(0),
            vm_states: [const { VmEptState::new() }; MAX_EPT_VMS],
            vm_count: AtomicU8::new(0),
            violations: [const { EptViolation::new() }; MAX_VIOLATION_BATCH],
            violation_count: AtomicU16::new(0),
            next_violation_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            large_page_enabled: AtomicBool::new(true),
            prefetch_enabled: AtomicBool::new(true),
            batch_enabled: AtomicBool::new(true),
            pml_enabled: AtomicBool::new(false),
            large_threshold: AtomicU32::new(100),
            prefetch_distance: AtomicU16::new(16),
            batch_timeout: AtomicU64::new(100_000), // 100us
            last_batch: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            total_promotions: AtomicU64::new(0),
            total_demotions: AtomicU64::new(0),
            total_prefetches: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, large_pages: bool, prefetch: bool, batch: bool) {
        self.large_page_enabled.store(large_pages, Ordering::Release);
        self.prefetch_enabled.store(prefetch, Ordering::Release);
        self.batch_enabled.store(batch, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM
    pub fn register_vm(&mut self, vm_id: u32, eptp_base: u64, memory_type: u8) -> Result<u8, HvError> {
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_EPT_VMS {
            return Err(HvError::LogicalFault);
        }
        
        // Check if VM already registered
        for i in 0..count as usize {
            if self.vm_states[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Ok(i as u8);
            }
        }
        
        let vm_state = &self.vm_states[count as usize];
        vm_state.init(vm_id, eptp_base, memory_type);
        
        self.vm_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Handle EPT violation
    pub fn handle_violation(&mut self, gpa: u64, qualification: u64, 
                            vm_id: u32, cpu: u8) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Record violation
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.record_violation();
        self.total_violations.fetch_add(1, Ordering::Release);
        
        // Check cache first
        if let Some(entry) = self.find_cache_entry(gpa, vm_id) {
            entry.record_access(qualification & 2 != 0);
            vm_state.record_hit();
            return Ok(0); // Already cached
        }
        
        vm_state.record_miss();
        
        // Add to violation batch
        if self.batch_enabled.load(Ordering::Acquire) {
            let count = self.violation_count.load(Ordering::Acquire);
            if count as usize >= MAX_VIOLATION_BATCH {
                self.process_batch()?;
            }
            
            let id = self.next_violation_id.fetch_add(1, Ordering::Release);
            let viol = &self.violations[count as usize];
            viol.init(id, gpa, qualification, vm_id, cpu);
            
            self.violation_count.fetch_add(1, Ordering::Release);
            
            Ok(id)
        } else {
            // Process immediately
            self.resolve_violation(gpa, vm_id, qualification)?;
            Ok(0)
        }
    }

    /// Process violation batch
    pub fn process_batch(&mut self) -> Result<u32, HvError> {
        let count = self.violation_count.load(Ordering::Acquire);
        if count == 0 {
            return Ok(0);
        }
        
        let now = Self::get_timestamp();
        let timeout = self.batch_timeout.load(Ordering::Acquire);
        
        if now - self.last_batch.load(Ordering::Acquire) < timeout {
            return Ok(0);
        }
        
        self.last_batch.store(now, Ordering::Release);
        
        let mut processed = 0u32;
        
        for i in 0..count as usize {
            let viol = &self.violations[i];
            if viol.valid.load(Ordering::Acquire) {
                let gpa = viol.gpa.load(Ordering::Acquire);
                let vm_id = viol.vm_id.load(Ordering::Acquire);
                let qual = viol.qualification.load(Ordering::Acquire);
                
                self.resolve_violation(gpa, vm_id, qual)?;
                viol.set_status(1); // Resolved
                processed += 1;
            }
        }
        
        // Clear batch
        self.violation_count.store(0, Ordering::Release);
        
        Ok(processed)
    }

    /// Resolve EPT violation
    fn resolve_violation(&mut self, gpa: u64, vm_id: u32, qualification: u64) -> Result<(), HvError> {
        // Find or create cache entry
        let slot = self.find_or_create_slot(vm_id)?;
        let entry = &self.cache[slot as usize];
        
        // Initialize entry (would normally translate GPA to HPA)
        let hpa = self.translate_gpa(gpa, vm_id)?;
        let ept_entry = self.build_ept_entry(hpa, qualification);
        
        entry.init(gpa, hpa, ept_entry, vm_id, ept_level::PT);
        entry.record_access(qualification & 2 != 0);
        
        // Update VM state
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.record_resolution();
        vm_state.pages_4k.fetch_add(1, Ordering::Release);
        
        // Prefetch if enabled
        if self.prefetch_enabled.load(Ordering::Acquire) {
            self.prefetch_pages(gpa, vm_id)?;
        }
        
        Ok(())
    }

    /// Translate GPA to HPA
    fn translate_gpa(&self, gpa: u64, _vm_id: u32) -> Result<u64, HvError> {
        // Would normally walk guest page tables or use memory map
        Ok(gpa) // Identity map for now
    }

    /// Build EPT entry
    fn build_ept_entry(&self, hpa: u64, qualification: u64) -> u64 {
        let mut entry = ept_flag::PRESENT | ept_flag::ACCESSED;
        
        // Set permissions based on qualification
        entry |= ept_flag::READ;
        entry |= ept_flag::WRITE;
        entry |= ept_flag::EXEC;
        entry |= ept_flag::EXEC_SUPER;
        
        // Set memory type
        entry |= (6 << 3); // WB
        
        // Set HPA
        entry |= hpa & !0xFFF;
        
        // Set dirty if write
        if qualification & 2 != 0 {
            entry |= ept_flag::DIRTY;
        }
        
        entry
    }

    /// Prefetch pages
    fn prefetch_pages(&mut self, gpa: u64, vm_id: u32) -> Result<(), HvError> {
        let distance = self.prefetch_distance.load(Ordering::Acquire) as u64;
        let page_size = PAGE_4K;
        
        for i in 1..=distance {
            let prefetch_gpa = gpa + i * page_size;
            
            // Skip if already cached
            if self.find_cache_entry(prefetch_gpa, vm_id).is_some() {
                continue;
            }
            
            // Add to cache
            if let Ok(slot) = self.find_or_create_slot(vm_id) {
                let entry = &self.cache[slot as usize];
                let hpa = self.translate_gpa(prefetch_gpa, vm_id)?;
                let ept_entry = self.build_ept_entry(hpa, 0);
                
                entry.init(prefetch_gpa, hpa, ept_entry, vm_id, ept_level::PT);
            }
        }
        
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.prefetch_count.fetch_add(distance as u64, Ordering::Release);
        self.total_prefetches.fetch_add(distance as u64, Ordering::Release);
        
        Ok(())
    }

    /// Promote to large page
    pub fn promote_to_large(&mut self, gpa_base: u64, vm_id: u32) -> Result<(), HvError> {
        if !self.large_page_enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Check if all 512 4K pages are candidates
        let mut all_candidates = true;
        let threshold = self.large_threshold.load(Ordering::Acquire);
        
        for i in 0..512 {
            let gpa = gpa_base + i as u64 * PAGE_4K;
            if let Some(entry) = self.find_cache_entry(gpa, vm_id) {
                if entry.access_count.load(Ordering::Acquire) < threshold {
                    all_candidates = false;
                    break;
                }
            } else {
                all_candidates = false;
                break;
            }
        }
        
        if !all_candidates {
            return Err(HvError::LogicalFault);
        }
        
        // Create 2M entry
        let slot = self.find_or_create_slot(vm_id)?;
        let entry = &self.cache[slot as usize];
        
        let hpa = self.translate_gpa(gpa_base, vm_id)?;
        let mut ept_entry = self.build_ept_entry(hpa, 0) | ept_flag::LARGE;
        
        entry.init(gpa_base, hpa, ept_entry, vm_id, ept_level::PD);
        entry.page_size.store(1, Ordering::Release); // 2M
        
        // Update VM state
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.pages_4k.fetch_sub(512, Ordering::Release);
        vm_state.pages_2m.fetch_add(1, Ordering::Release);
        vm_state.large_promotions.fetch_add(1, Ordering::Release);
        
        self.total_promotions.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Demote large page to 4K pages
    pub fn demote_large(&mut self, gpa_base: u64, vm_id: u32) -> Result<(), HvError> {
        let entry = self.find_cache_entry(gpa_base, vm_id).ok_or(HvError::LogicalFault)?;
        
        if entry.page_size.load(Ordering::Acquire) == 0 {
            return Err(HvError::LogicalFault); // Already 4K
        }
        
        // Mark as 4K
        entry.page_size.store(0, Ordering::Release);
        entry.ept_entry.fetch_and(!ept_flag::LARGE, Ordering::Release);
        entry.level.store(ept_level::PT, Ordering::Release);
        
        // Update VM state
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.pages_2m.fetch_sub(1, Ordering::Release);
        vm_state.pages_4k.fetch_add(512, Ordering::Release);
        vm_state.large_demotions.fetch_add(1, Ordering::Release);
        
        self.total_demotions.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Find cache entry
    fn find_cache_entry(&self, gpa: u64, vm_id: u32) -> Option<&EptCacheEntry> {
        for i in 0..self.cache_count.load(Ordering::Acquire) as usize {
            let entry = &self.cache[i];
            if entry.valid.load(Ordering::Acquire) &&
               entry.gpa.load(Ordering::Acquire) == gpa &&
               entry.vm_id.load(Ordering::Acquire) == vm_id {
                return Some(entry);
            }
        }
        None
    }

    /// Find or create cache slot
    fn find_or_create_slot(&mut self, vm_id: u32) -> Result<u32, HvError> {
        // Find invalid slot
        for i in 0..MAX_EPT_CACHE {
            if !self.cache[i].valid.load(Ordering::Acquire) {
                self.cache_count.fetch_max((i + 1) as u32, Ordering::Release);
                return Ok(i as u32);
            }
        }
        
        // Cache full, evict LRU
        self.evict_lru(vm_id)
    }

    /// Evict LRU entry
    fn evict_lru(&self, vm_id: u32) -> Result<u32, HvError> {
        let mut oldest_time = u64::MAX;
        let mut oldest_idx = 0;
        
        for i in 0..self.cache_count.load(Ordering::Acquire) as usize {
            let entry = &self.cache[i];
            if entry.vm_id.load(Ordering::Acquire) == vm_id {
                let last = entry.last_access.load(Ordering::Acquire);
                if last < oldest_time {
                    oldest_time = last;
                    oldest_idx = i;
                }
            }
        }
        
        if oldest_time == u64::MAX {
            return Err(HvError::LogicalFault);
        }
        
        self.cache[oldest_idx].valid.store(false, Ordering::Release);
        Ok(oldest_idx as u32)
    }

    /// Get VM state
    fn get_vm_state(&self, vm_id: u32) -> Option<&VmEptState> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_states[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_states[i]);
            }
        }
        None
    }

    /// Get statistics
    pub fn get_stats(&self) -> EptStats {
        let mut total_4k = 0u64;
        let mut total_2m = 0u64;
        let mut total_1g = 0u64;
        
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            total_4k += self.vm_states[i].pages_4k.load(Ordering::Acquire);
            total_2m += self.vm_states[i].pages_2m.load(Ordering::Acquire);
            total_1g += self.vm_states[i].pages_1g.load(Ordering::Acquire);
        }
        
        EptStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            cache_count: self.cache_count.load(Ordering::Acquire),
            pages_4k: total_4k,
            pages_2m: total_2m,
            pages_1g: total_1g,
            total_violations: self.total_violations.load(Ordering::Acquire),
            total_promotions: self.total_promotions.load(Ordering::Acquire),
            total_demotions: self.total_demotions.load(Ordering::Acquire),
            total_prefetches: self.total_prefetches.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for EptController {
    fn default() -> Self {
        Self::new()
    }
}

/// EPT statistics
#[repr(C)]
pub struct EptStats {
    pub enabled: bool,
    pub vm_count: u8,
    pub cache_count: u32,
    pub pages_4k: u64,
    pub pages_2m: u64,
    pub pages_1g: u64,
    pub total_violations: u64,
    pub total_promotions: u64,
    pub total_demotions: u64,
    pub total_prefetches: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vm() {
        let mut ctrl = EptController::new();
        ctrl.enable(true, true, true);
        
        let idx = ctrl.register_vm(1, 0x1000000, 6).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn handle_violation() {
        let mut ctrl = EptController::new();
        ctrl.enable(true, true, false);
        ctrl.register_vm(1, 0x1000000, 6).unwrap();
        
        let id = ctrl.handle_violation(0x1000, 0, 1, 0).unwrap();
        assert!(ctrl.cache_count.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn cache_hit() {
        let mut ctrl = EptController::new();
        ctrl.enable(true, true, false);
        ctrl.register_vm(1, 0x1000000, 6).unwrap();
        
        ctrl.handle_violation(0x1000, 0, 1, 0).unwrap();
        ctrl.handle_violation(0x1000, 0, 1, 0).unwrap(); // Should hit
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert!(vm.cache_hits.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn promote_to_large() {
        let mut ctrl = EptController::new();
        ctrl.enable(true, true, false);
        ctrl.register_vm(1, 0x1000000, 6).unwrap();
        ctrl.large_threshold.store(1, Ordering::Release);
        
        // Create 512 4K pages
        for i in 0..512 {
            ctrl.handle_violation(0x200000 + i as u64 * PAGE_4K, 0, 1, 0).unwrap();
        }
        
        // Promote
        ctrl.promote_to_large(0x200000, 1).unwrap();
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert!(vm.pages_2m.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn prefetch() {
        let mut ctrl = EptController::new();
        ctrl.enable(true, true, false);
        ctrl.register_vm(1, 0x1000000, 6).unwrap();
        ctrl.prefetch_distance.store(4, Ordering::Release);
        
        ctrl.handle_violation(0x1000, 0, 1, 0).unwrap();
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert!(vm.prefetch_count.load(Ordering::Acquire) > 0);
    }
}
