//! Large Page Breaking On Demand
//!
//! Break 2MB/1GB pages to 4KB when memory pressure is high for better overcommitment.
//! Based on VMware "Proactively Breaking Large Pages" (ASPLOS 2014).

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Large Page Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Page sizes
pub mod page_size {
    pub const PAGE_4K: u8 = 0;
    pub const PAGE_2M: u8 = 1;
    pub const PAGE_1G: u8 = 2;
}

/// Page size in bytes
pub const PAGE_4K_SIZE: usize = 4096;
pub const PAGE_2M_SIZE: usize = 2 * 1024 * 1024;
pub const PAGE_1G_SIZE: usize = 1024 * 1024 * 1024;

/// Pages in a large page
pub const PAGES_PER_2M: usize = 512;
pub const PAGES_PER_1G: usize = 262144;

/// Maximum large pages tracked
pub const MAX_LARGE_PAGES: usize = 16384;

/// Maximum small page entries
pub const MAX_SMALL_PAGES: usize = MAX_LARGE_PAGES * PAGES_PER_2M;

// ─────────────────────────────────────────────────────────────────────────────
// Large Page Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Large page states
pub mod large_page_state {
    pub const INTACT: u8 = 0;      // Large page intact
    pub const PARTIAL: u8 = 1;     // Partially broken
    pub const BROKEN: u8 = 2;      // Fully broken to 4K pages
    pub const BREAKING: u8 = 3;    // In progress of breaking
    pub const RECLAIMING: u8 = 4;  // Being reclaimed
}

/// Large page entry
pub struct LargePage {
    /// Large page frame number (LPFN)
    pub lpfn: AtomicU64,
    /// Guest physical address base
    pub gpa_base: AtomicU64,
    /// Page size type
    pub page_size: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// VM ID
    pub vm_id: AtomicU32,
    /// EPT entry address
    pub ept_entry: AtomicU64,
    /// Access count
    pub access_count: AtomicU64,
    /// Write count
    pub write_count: AtomicU64,
    /// Last access timestamp
    pub last_access: AtomicU64,
    /// Last write timestamp
    pub last_write: AtomicU64,
    /// Reference count (how many small pages still reference)
    pub ref_count: AtomicU16,
    /// Zero pages count (pages that are all zeros)
    pub zero_pages: AtomicU16,
    /// Shareable pages count
    pub shareable_pages: AtomicU16,
    /// Cold pages count (not recently accessed)
    pub cold_pages: AtomicU16,
    /// Break score (higher = better candidate for breaking)
    pub break_score: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
    /// Locked (don't break)
    pub locked: AtomicBool,
}

impl LargePage {
    pub const fn new() -> Self {
        Self {
            lpfn: AtomicU64::new(0),
            gpa_base: AtomicU64::new(0),
            page_size: AtomicU8::new(page_size::PAGE_2M),
            state: AtomicU8::new(large_page_state::INTACT),
            vm_id: AtomicU32::new(0),
            ept_entry: AtomicU64::new(0),
            access_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            last_access: AtomicU64::new(0),
            last_write: AtomicU64::new(0),
            ref_count: AtomicU16::new(PAGES_PER_2M as u16),
            zero_pages: AtomicU16::new(0),
            shareable_pages: AtomicU16::new(0),
            cold_pages: AtomicU16::new(0),
            break_score: AtomicU32::new(0),
            valid: AtomicBool::new(false),
            locked: AtomicBool::new(false),
        }
    }

    /// Initialize large page
    pub fn init(&self, lpfn: u64, gpa_base: u64, vm_id: u32, page_size: u8) {
        self.lpfn.store(lpfn, Ordering::Release);
        self.gpa_base.store(gpa_base, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.page_size.store(page_size, Ordering::Release);
        self.state.store(large_page_state::INTACT, Ordering::Release);
        self.ref_count.store(if page_size == page_size::PAGE_2M { 
            PAGES_PER_2M as u16 
        } else { 
            512 // For 1G, we track at 2M granularity
        }, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self, is_write: bool) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
        
        if is_write {
            self.write_count.fetch_add(1, Ordering::Release);
            self.last_write.store(Self::get_timestamp(), Ordering::Release);
        }
    }

    /// Calculate break score
    /// Higher score = better candidate for breaking
    pub fn calculate_score(&self, memory_pressure: u8) -> u32 {
        if self.locked.load(Ordering::Acquire) {
            return 0;
        }
        
        let state = self.state.load(Ordering::Acquire);
        if state == large_page_state::BROKEN || state == large_page_state::BREAKING {
            return 0;
        }
        
        let mut score = 0u32;
        
        // Factor 1: Cold pages (more cold = better candidate)
        let cold = self.cold_pages.load(Ordering::Acquire) as u32;
        score += cold * 100;
        
        // Factor 2: Zero pages (can be reclaimed easily)
        let zeros = self.zero_pages.load(Ordering::Acquire) as u32;
        score += zeros * 200;
        
        // Factor 3: Shareable pages (can be deduplicated)
        let shareable = self.shareable_pages.load(Ordering::Acquire) as u32;
        score += shareable * 150;
        
        // Factor 4: Write frequency (less writes = better candidate)
        let writes = self.write_count.load(Ordering::Acquire);
        if writes < 10 {
            score += 500;
        } else if writes < 100 {
            score += 200;
        }
        
        // Factor 5: Memory pressure multiplier
        score = (score as u64 * memory_pressure as u64 / 100) as u32;
        
        // Factor 6: Already partially broken
        if state == large_page_state::PARTIAL {
            score = (score * 150) / 100; // 1.5x multiplier
        }
        
        self.break_score.store(score, Ordering::Release);
        score
    }

    /// Update small page stats
    pub fn update_stats(&self, zeros: u16, shareable: u16, cold: u16) {
        self.zero_pages.store(zeros, Ordering::Release);
        self.shareable_pages.store(shareable, Ordering::Release);
        self.cold_pages.store(cold, Ordering::Release);
    }

    /// Decrement reference count
    pub fn dec_ref(&self) -> u16 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }

    /// Check if fully broken
    pub fn is_fully_broken(&self) -> bool {
        self.ref_count.load(Ordering::Acquire) == 0
    }

    /// Lock page
    pub fn lock(&self) {
        self.locked.store(true, Ordering::Release);
    }

    /// Unlock page
    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for LargePage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Small Page Entry (after breaking)
// ─────────────────────────────────────────────────────────────────────────────

/// Small page entry (4K)
pub struct SmallPage {
    /// Small page frame number
    pub pfn: AtomicU64,
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Parent large page index
    pub parent_idx: AtomicU32,
    /// Offset in large page (0-511 for 2M)
    pub offset: AtomicU16,
    /// Page state
    pub state: AtomicU8,
    /// Is zero page
    pub is_zero: AtomicBool,
    /// Is shared
    pub is_shared: AtomicBool,
    /// Is cold
    pub is_cold: AtomicBool,
    /// Access count
    pub access_count: AtomicU32,
    /// Last access
    pub last_access: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl SmallPage {
    pub const fn new() -> Self {
        Self {
            pfn: AtomicU64::new(0),
            gpa: AtomicU64::new(0),
            parent_idx: AtomicU32::new(0),
            offset: AtomicU16::new(0),
            state: AtomicU8::new(0),
            is_zero: AtomicBool::new(false),
            is_shared: AtomicBool::new(false),
            is_cold: AtomicBool::new(true),
            access_count: AtomicU32::new(0),
            last_access: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize small page
    pub fn init(&self, pfn: u64, gpa: u64, parent_idx: u32, offset: u16) {
        self.pfn.store(pfn, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.parent_idx.store(parent_idx, Ordering::Release);
        self.offset.store(offset, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
        self.is_cold.store(false, Ordering::Release);
    }

    /// Mark as zero
    pub fn mark_zero(&self) {
        self.is_zero.store(true, Ordering::Release);
    }

    /// Mark as shared
    pub fn mark_shared(&self) {
        self.is_shared.store(true, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for SmallPage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Large Page Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Large page controller
pub struct LargePageController {
    /// Large pages
    pub large_pages: [LargePage; MAX_LARGE_PAGES],
    /// Large page count
    pub large_page_count: AtomicU32,
    /// Small pages (broken from large)
    pub small_pages: [SmallPage; MAX_SMALL_PAGES],
    /// Small page count
    pub small_page_count: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
    /// Memory pressure threshold to start breaking
    pub break_threshold: AtomicU8,
    /// Memory pressure threshold to stop breaking
    pub stop_threshold: AtomicU8,
    /// Maximum pages to break per cycle
    pub max_break_per_cycle: AtomicU16,
    /// Minimum score to consider breaking
    pub min_break_score: AtomicU32,
    /// Current memory pressure
    pub memory_pressure: AtomicU8,
    /// Total large pages broken
    pub total_broken: AtomicU64,
    /// Total small pages created
    pub total_small_created: AtomicU64,
    /// Total pages reclaimed
    pub total_reclaimed: AtomicU64,
    /// Total zero pages reclaimed
    pub total_zero_reclaimed: AtomicU64,
    /// TLB flushes avoided
    pub tlb_flushes_avoided: AtomicU64,
    /// Last scan timestamp
    pub last_scan: AtomicU64,
    /// Scan interval (ms)
    pub scan_interval: AtomicU32,
}

impl LargePageController {
    pub const fn new() -> Self {
        Self {
            large_pages: [const { LargePage::new() }; MAX_LARGE_PAGES],
            large_page_count: AtomicU32::new(0),
            small_pages: [const { SmallPage::new() }; MAX_SMALL_PAGES],
            small_page_count: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            break_threshold: AtomicU8::new(85), // Start breaking at 85% pressure
            stop_threshold: AtomicU8::new(70),  // Stop at 70%
            max_break_per_cycle: AtomicU16::new(16), // Max 16 large pages per cycle
            min_break_score: AtomicU32::new(1000),
            memory_pressure: AtomicU8::new(0),
            total_broken: AtomicU64::new(0),
            total_small_created: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
            total_zero_reclaimed: AtomicU64::new(0),
            tlb_flushes_avoided: AtomicU64::new(0),
            last_scan: AtomicU64::new(0),
            scan_interval: AtomicU32::new(1000), // 1 second
        }
    }

    /// Enable controller
    pub fn enable(&mut self, break_threshold: u8, stop_threshold: u8) {
        self.break_threshold.store(break_threshold, Ordering::Release);
        self.stop_threshold.store(stop_threshold, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register large page
    pub fn register_large_page(&mut self, lpfn: u64, gpa_base: u64, 
                                vm_id: u32, page_size: u8) -> Result<u32, HvError> {
        let count = self.large_page_count.load(Ordering::Acquire);
        if count as usize >= MAX_LARGE_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count;
        let page = &self.large_pages[idx as usize];
        page.init(lpfn, gpa_base, vm_id, page_size);
        
        self.large_page_count.fetch_add(1, Ordering::Release);
        Ok(idx)
    }

    /// Unregister large page
    pub fn unregister_large_page(&mut self, idx: u32) -> Result<(), HvError> {
        if idx as usize >= MAX_LARGE_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let page = &self.large_pages[idx as usize];
        page.valid.store(false, Ordering::Release);
        
        Ok(())
    }

    /// Update memory pressure
    pub fn update_pressure(&self, pressure: u8) {
        self.memory_pressure.store(pressure, Ordering::Release);
    }

    /// Scan large pages for breaking candidates
    pub fn scan_for_candidates(&self) -> u32 {
        let now = Self::get_timestamp();
        let interval = self.scan_interval.load(Ordering::Acquire) as u64;
        
        if now - self.last_scan.load(Ordering::Acquire) < interval {
            return 0;
        }
        
        self.last_scan.store(now, Ordering::Release);
        
        let pressure = self.memory_pressure.load(Ordering::Acquire);
        let threshold = self.break_threshold.load(Ordering::Acquire);
        
        if pressure < threshold {
            return 0;
        }
        
        let mut candidates = 0u32;
        
        for i in 0..self.large_page_count.load(Ordering::Acquire) as usize {
            let page = &self.large_pages[i];
            if page.valid.load(Ordering::Acquire) {
                let score = page.calculate_score(pressure);
                if score >= self.min_break_score.load(Ordering::Acquire) {
                    candidates += 1;
                }
            }
        }
        
        candidates
    }

    /// Break large page into small pages
    pub fn break_large_page(&mut self, idx: u32) -> Result<u32, HvError> {
        if idx as usize >= MAX_LARGE_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let large = &self.large_pages[idx as usize];
        if !large.valid.load(Ordering::Acquire) || 
           large.locked.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let state = large.state.load(Ordering::Acquire);
        if state == large_page_state::BROKEN {
            return Err(HvError::LogicalFault);
        }
        
        // Lock the page
        large.lock();
        large.state.store(large_page_state::BREAKING, Ordering::Release);
        
        let gpa_base = large.gpa_base.load(Ordering::Acquire);
        let lpfn = large.lpfn.load(Ordering::Acquire);
        let page_size = large.page_size.load(Ordering::Acquire);
        
        let pages_to_create = if page_size == page_size::PAGE_2M {
            PAGES_PER_2M
        } else {
            512 // For 1G, break to 2M first
        };
        
        let mut created = 0u32;
        let small_count = self.small_page_count.load(Ordering::Acquire);
        
        for i in 0..pages_to_create {
            if (small_count as usize + created as usize) >= MAX_SMALL_PAGES {
                break;
            }
            
            let small_idx = small_count as usize + created as usize;
            let small = &self.small_pages[small_idx];
            
            let small_gpa = gpa_base + (i * PAGE_4K_SIZE) as u64;
            let small_pfn = lpfn * PAGES_PER_2M as u64 + i as u64;
            
            small.init(small_pfn, small_gpa, idx, i as u16);
            created += 1;
        }
        
        // Update large page state
        large.state.store(large_page_state::BROKEN, Ordering::Release);
        large.unlock();
        
        // Update statistics
        self.small_page_count.fetch_add(created as u64, Ordering::Release);
        self.total_broken.fetch_add(1, Ordering::Release);
        self.total_small_created.fetch_add(created as u64, Ordering::Release);
        
        Ok(created)
    }

    /// Break best candidates
    pub fn break_best_candidates(&mut self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let pressure = self.memory_pressure.load(Ordering::Acquire);
        let threshold = self.break_threshold.load(Ordering::Acquire);
        
        if pressure < threshold {
            return 0;
        }
        
        let max_break = self.max_break_per_cycle.load(Ordering::Acquire) as usize;
        let min_score = self.min_break_score.load(Ordering::Acquire);
        
        // Collect candidates with scores
        let mut candidates: [(u32, u32); 256] = [(0, 0); 256];
        let mut candidate_count = 0;
        
        for i in 0..self.large_page_count.load(Ordering::Acquire) as usize {
            if candidate_count >= 256 {
                break;
            }
            
            let page = &self.large_pages[i];
            if page.valid.load(Ordering::Acquire) && !page.locked.load(Ordering::Acquire) {
                let score = page.calculate_score(pressure);
                if score >= min_score {
                    candidates[candidate_count] = (i as u32, score);
                    candidate_count += 1;
                }
            }
        }
        
        // Sort by score (descending) - bubble sort
        for i in 0..candidate_count {
            for j in i + 1..candidate_count {
                if candidates[j].1 > candidates[i].1 {
                    let temp = candidates[i];
                    candidates[i] = candidates[j];
                    candidates[j] = temp;
                }
            }
        }
        
        // Break top candidates
        let mut broken = 0u32;
        for i in 0..candidate_count.min(max_break) {
            if self.break_large_page(candidates[i].0).is_ok() {
                broken += 1;
            }
        }
        
        broken
    }

    /// Reclaim zero pages
    pub fn reclaim_zero_pages(&mut self) -> u32 {
        let mut reclaimed = 0u32;
        let count = self.small_page_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            let small = &self.small_pages[i];
            if small.valid.load(Ordering::Acquire) && small.is_zero.load(Ordering::Acquire) {
                // Reclaim zero page
                small.valid.store(false, Ordering::Release);
                reclaimed += 1;
                
                // Update parent reference
                let parent_idx = small.parent_idx.load(Ordering::Acquire);
                if parent_idx < self.large_page_count.load(Ordering::Acquire) {
                    self.large_pages[parent_idx as usize].dec_ref();
                }
            }
        }
        
        self.total_reclaimed.fetch_add(reclaimed as u64, Ordering::Release);
        self.total_zero_reclaimed.fetch_add(reclaimed as u64, Ordering::Release);
        
        reclaimed
    }

    /// Mark small page as zero
    pub fn mark_page_zero(&self, small_idx: u64) -> Result<(), HvError> {
        if small_idx as usize >= MAX_SMALL_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let small = &self.small_pages[small_idx as usize];
        small.mark_zero();
        
        // Update parent stats
        let parent_idx = small.parent_idx.load(Ordering::Acquire);
        if parent_idx < self.large_page_count.load(Ordering::Acquire) {
            let parent = &self.large_pages[parent_idx as usize];
            parent.zero_pages.fetch_add(1, Ordering::Release);
        }
        
        Ok(())
    }

    /// Record access to small page
    pub fn record_small_page_access(&self, small_idx: u64) -> Result<(), HvError> {
        if small_idx as usize >= MAX_SMALL_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let small = &self.small_pages[small_idx as usize];
        small.record_access();
        
        // Update parent stats
        let parent_idx = small.parent_idx.load(Ordering::Acquire);
        if parent_idx < self.large_page_count.load(Ordering::Acquire) {
            self.large_pages[parent_idx as usize].record_access(false);
        }
        
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> LargePageStats {
        let mut intact = 0u32;
        let mut partial = 0u32;
        let mut broken = 0u32;
        
        for i in 0..self.large_page_count.load(Ordering::Acquire) as usize {
            match self.large_pages[i].state.load(Ordering::Acquire) {
                large_page_state::INTACT => intact += 1,
                large_page_state::PARTIAL => partial += 1,
                large_page_state::BROKEN => broken += 1,
                _ => {}
            }
        }
        
        LargePageStats {
            enabled: self.enabled.load(Ordering::Acquire),
            memory_pressure: self.memory_pressure.load(Ordering::Acquire),
            large_page_count: self.large_page_count.load(Ordering::Acquire),
            small_page_count: self.small_page_count.load(Ordering::Acquire),
            intact_pages: intact,
            partial_pages: partial,
            broken_pages: broken,
            total_broken: self.total_broken.load(Ordering::Acquire),
            total_reclaimed: self.total_reclaimed.load(Ordering::Acquire),
            total_zero_reclaimed: self.total_zero_reclaimed.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for LargePageController {
    fn default() -> Self {
        Self::new()
    }
}

/// Large page statistics
#[repr(C)]
pub struct LargePageStats {
    pub enabled: bool,
    pub memory_pressure: u8,
    pub large_page_count: u32,
    pub small_page_count: u64,
    pub intact_pages: u32,
    pub partial_pages: u32,
    pub broken_pages: u32,
    pub total_broken: u64,
    pub total_reclaimed: u64,
    pub total_zero_reclaimed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_large_page() {
        let mut ctrl = LargePageController::new();
        ctrl.enable(85, 70);
        
        let idx = ctrl.register_large_page(0x1000, 0x1000000, 1, page_size::PAGE_2M).unwrap();
        assert_eq!(ctrl.large_page_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn break_large_page() {
        let mut ctrl = LargePageController::new();
        ctrl.enable(85, 70);
        
        let idx = ctrl.register_large_page(0x1000, 0x1000000, 1, page_size::PAGE_2M).unwrap();
        let small_count = ctrl.break_large_page(idx).unwrap();
        
        assert_eq!(small_count, PAGES_PER_2M as u32);
        assert_eq!(ctrl.large_pages[idx as usize].state.load(Ordering::Acquire), large_page_state::BROKEN);
    }

    #[test]
    fn calculate_break_score() {
        let ctrl = LargePageController::new();
        let page = LargePage::new();
        page.init(0x1000, 0x1000000, 1, page_size::PAGE_2M);
        
        // Low score when no special conditions
        let score = page.calculate_score(50);
        assert!(score < 1000);
        
        // Higher score with zero pages
        page.update_stats(100, 50, 200);
        let score = page.calculate_score(90);
        assert!(score > 1000);
    }

    #[test]
    fn reclaim_zero_pages() {
        let mut ctrl = LargePageController::new();
        ctrl.enable(85, 70);
        
        let idx = ctrl.register_large_page(0x1000, 0x1000000, 1, page_size::PAGE_2M).unwrap();
        ctrl.break_large_page(idx).unwrap();
        
        // Mark some pages as zero
        ctrl.mark_page_zero(0).unwrap();
        ctrl.mark_page_zero(1).unwrap();
        ctrl.mark_page_zero(2).unwrap();
        
        let reclaimed = ctrl.reclaim_zero_pages();
        assert_eq!(reclaimed, 3);
    }

    #[test]
    fn break_best_candidates() {
        let mut ctrl = LargePageController::new();
        ctrl.enable(50, 30); // Low threshold for test
        ctrl.update_pressure(90); // High pressure
        
        // Create multiple large pages
        ctrl.register_large_page(0x1000, 0x1000000, 1, page_size::PAGE_2M).unwrap();
        ctrl.register_large_page(0x2000, 0x2000000, 1, page_size::PAGE_2M).unwrap();
        
        // Set high break score on first
        ctrl.large_pages[0].update_stats(200, 100, 300);
        
        let broken = ctrl.break_best_candidates();
        assert!(broken > 0);
    }
}
