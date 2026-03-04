//! Memory Ballooning Enhancement
//!
//! Dynamic memory reclamation with priority-based reclaim and free page hinting.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Balloon Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Page size
pub const PAGE_SIZE: usize = 4096;

/// Maximum balloon pages per VM
#[cfg(not(test))]
pub const MAX_BALLOON_PAGES: usize = 65536;
/// Maximum balloon pages per VM (reduced for tests)
#[cfg(test)]
pub const MAX_BALLOON_PAGES: usize = 16;

/// Maximum VMs with balloon
#[cfg(not(test))]
pub const MAX_BALLOON_VMS: usize = 256;
/// Maximum VMs with balloon (reduced for tests)
#[cfg(test)]
pub const MAX_BALLOON_VMS: usize = 4;

/// Balloon states
pub mod balloon_state {
    pub const IDLE: u8 = 0;
    pub const INFLATING: u8 = 1;
    pub const DEFLATING: u8 = 2;
    pub const PAUSED: u8 = 3;
    pub const ERROR: u8 = 4;
}

/// Reclaim priorities
pub mod reclaim_priority {
    pub const CRITICAL: u8 = 0;    // Host OOM imminent
    pub const HIGH: u8 = 1;        // Host memory pressure high
    pub const NORMAL: u8 = 2;      // Normal reclaim
    pub const LOW: u8 = 3;         // Opportunistic reclaim
    pub const BACKGROUND: u8 = 4; // Background scanning
}

// ─────────────────────────────────────────────────────────────────────────────
// Balloon Page Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Balloon page entry
pub struct BalloonPage {
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Page frame number in host
    pub pfn: AtomicU64,
    /// Page state (0=free, 1=inflated, 2=deflated)
    pub page_state: AtomicU8,
    /// Allocation timestamp
    pub alloc_time: AtomicU64,
    /// Last access timestamp
    pub last_access: AtomicU64,
    /// Access count
    pub access_count: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl BalloonPage {
    pub const fn new() -> Self {
        Self {
            gpa: AtomicU64::new(0),
            pfn: AtomicU64::new(0),
            page_state: AtomicU8::new(0),
            alloc_time: AtomicU64::new(0),
            last_access: AtomicU64::new(0),
            access_count: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize page
    pub fn init(&self, gpa: u64, pfn: u64) {
        self.gpa.store(gpa, Ordering::Release);
        self.pfn.store(pfn, Ordering::Release);
        self.page_state.store(1, Ordering::Release);
        self.alloc_time.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for BalloonPage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free Page Hint
// ─────────────────────────────────────────────────────────────────────────────

/// Free page hint from guest
pub struct FreePageHint {
    /// Hint ID
    pub id: AtomicU32,
    /// GPA of free page
    pub gpa: AtomicU64,
    /// PFN in host
    pub pfn: AtomicU64,
    /// Hint type (0=unused, 1=free, 2=zeroed)
    pub hint_type: AtomicU8,
    /// Processed
    pub processed: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl FreePageHint {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            gpa: AtomicU64::new(0),
            pfn: AtomicU64::new(0),
            hint_type: AtomicU8::new(0),
            processed: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Set hint
    pub fn set(&self, id: u32, gpa: u64, pfn: u64, hint_type: u8) {
        self.id.store(id, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.pfn.store(pfn, Ordering::Release);
        self.hint_type.store(hint_type, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }
}

impl Default for FreePageHint {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum free page hints
pub const MAX_FREE_PAGE_HINTS: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// VM Balloon State
// ─────────────────────────────────────────────────────────────────────────────

/// Per-VM balloon state
pub struct VmBalloon {
    /// VM ID
    pub vm_id: AtomicU32,
    /// Current balloon size (pages)
    pub current_size: AtomicU32,
    /// Target balloon size (pages)
    pub target_size: AtomicU32,
    /// Minimum size (pages)
    pub min_size: AtomicU32,
    /// Maximum size (pages)
    pub max_size: AtomicU32,
    /// Balloon state
    pub state: AtomicU8,
    /// Reclaim priority
    pub priority: AtomicU8,
    /// Balloon pages
    pub pages: [BalloonPage; MAX_BALLOON_PAGES],
    /// Page count
    pub page_count: AtomicU32,
    /// Free page hints
    pub free_hints: [FreePageHint; MAX_FREE_PAGE_HINTS],
    /// Free hint count
    pub free_hint_count: AtomicU16,
    /// Free hint processed count
    pub free_hint_processed: AtomicU16,
    /// Inflation rate (pages/sec)
    pub inflate_rate: AtomicU32,
    /// Deflation rate (pages/sec)
    pub deflate_rate: AtomicU32,
    /// Last adjustment time
    pub last_adjust: AtomicU64,
    /// Total inflated
    pub total_inflated: AtomicU64,
    /// Total deflated
    pub total_deflated: AtomicU64,
    /// Guest memory size (bytes)
    pub guest_memory: AtomicU64,
    /// Reserved memory (bytes)
    pub reserved_memory: AtomicU64,
    /// Driver installed
    pub driver_installed: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl VmBalloon {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            current_size: AtomicU32::new(0),
            target_size: AtomicU32::new(0),
            min_size: AtomicU32::new(0),
            max_size: AtomicU32::new(0),
            state: AtomicU8::new(balloon_state::IDLE),
            priority: AtomicU8::new(reclaim_priority::NORMAL),
            pages: [const { BalloonPage::new() }; MAX_BALLOON_PAGES],
            page_count: AtomicU32::new(0),
            free_hints: [const { FreePageHint::new() }; MAX_FREE_PAGE_HINTS],
            free_hint_count: AtomicU16::new(0),
            free_hint_processed: AtomicU16::new(0),
            inflate_rate: AtomicU32::new(512),  // 2MB/sec
            deflate_rate: AtomicU32::new(1024), // 4MB/sec
            last_adjust: AtomicU64::new(0),
            total_inflated: AtomicU64::new(0),
            total_deflated: AtomicU64::new(0),
            guest_memory: AtomicU64::new(0),
            reserved_memory: AtomicU64::new(0),
            driver_installed: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize balloon for VM
    pub fn init(&self, vm_id: u32, guest_memory: u64, min_size: u32, max_size: u32) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.guest_memory.store(guest_memory, Ordering::Release);
        self.min_size.store(min_size, Ordering::Release);
        self.max_size.store(max_size, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set target size
    pub fn set_target(&self, target: u32) {
        let min = self.min_size.load(Ordering::Acquire);
        let max = self.max_size.load(Ordering::Acquire);
        let target = target.clamp(min, max);
        self.target_size.store(target, Ordering::Release);
        
        let current = self.current_size.load(Ordering::Acquire);
        if target > current {
            self.state.store(balloon_state::INFLATING, Ordering::Release);
        } else if target < current {
            self.state.store(balloon_state::DEFLATING, Ordering::Release);
        } else {
            self.state.store(balloon_state::IDLE, Ordering::Release);
        }
    }

    /// Inflate balloon
    pub fn inflate(&self, pages: &[u64]) -> u32 {
        let current = self.current_size.load(Ordering::Acquire);
        let target = self.target_size.load(Ordering::Acquire);
        let max_inflate = target.saturating_sub(current);
        
        let to_inflate = (pages.len() as u32).min(max_inflate);
        let page_count = self.page_count.load(Ordering::Acquire);
        
        let mut inflated = 0u32;
        for i in 0..to_inflate as usize {
            if (page_count + inflated) as usize >= MAX_BALLOON_PAGES {
                break;
            }
            
            let idx = (page_count + inflated) as usize;
            self.pages[idx].init(pages[i], 0); // GPA, PFN would be resolved
            inflated += 1;
        }
        
        if inflated > 0 {
            self.page_count.fetch_add(inflated, Ordering::Release);
            self.current_size.fetch_add(inflated, Ordering::Release);
            self.total_inflated.fetch_add(inflated as u64, Ordering::Release);
            self.last_adjust.store(Self::get_timestamp(), Ordering::Release);
        }
        
        // Check if target reached
        if self.current_size.load(Ordering::Acquire) >= target {
            self.state.store(balloon_state::IDLE, Ordering::Release);
        }
        
        inflated
    }

    /// Deflate balloon
    pub fn deflate(&self, count: u32) -> u32 {
        let current = self.current_size.load(Ordering::Acquire);
        let target = self.target_size.load(Ordering::Acquire);
        let to_deflate = current.saturating_sub(target).min(count);
        
        if to_deflate == 0 {
            self.state.store(balloon_state::IDLE, Ordering::Release);
            return 0;
        }
        
        let page_count = self.page_count.load(Ordering::Acquire);
        
        // Invalidate pages (would return to guest)
        for i in 0..to_deflate as usize {
            let idx = (page_count - 1 - i as u32) as usize;
            self.pages[idx].valid.store(false, Ordering::Release);
            self.pages[idx].page_state.store(2, Ordering::Release); // Deflated
        }
        
        self.page_count.fetch_sub(to_deflate, Ordering::Release);
        self.current_size.fetch_sub(to_deflate, Ordering::Release);
        self.total_deflated.fetch_add(to_deflate as u64, Ordering::Release);
        self.last_adjust.store(Self::get_timestamp(), Ordering::Release);
        
        // Check if target reached
        if self.current_size.load(Ordering::Acquire) <= target {
            self.state.store(balloon_state::IDLE, Ordering::Release);
        }
        
        to_deflate
    }

    /// Add free page hint
    pub fn add_free_hint(&self, gpa: u64, pfn: u64, hint_type: u8) -> Result<(), HvError> {
        let count = self.free_hint_count.load(Ordering::Acquire);
        if count as usize >= MAX_FREE_PAGE_HINTS {
            return Err(HvError::LogicalFault);
        }
        
        let hint = &self.free_hints[count as usize];
        hint.set(count as u32, gpa, pfn, hint_type);
        
        self.free_hint_count.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Process free page hints
    pub fn process_free_hints(&self) -> u32 {
        let mut processed = 0u32;
        let count = self.free_hint_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            let hint = &self.free_hints[i];
            if !hint.processed.load(Ordering::Acquire) && hint.valid.load(Ordering::Acquire) {
                // Mark page as reclaimable
                hint.processed.store(true, Ordering::Release);
                processed += 1;
            }
        }
        
        self.free_hint_processed.fetch_add(processed as u16, Ordering::Release);
        processed
    }

    /// Get memory pressure percentage
    pub fn get_pressure(&self) -> u32 {
        let guest_mem = self.guest_memory.load(Ordering::Acquire);
        if guest_mem == 0 {
            return 0;
        }
        
        let balloon_size = self.current_size.load(Ordering::Acquire) as u64 * PAGE_SIZE as u64;
        ((balloon_size * 100) / guest_mem) as u32
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VmBalloon {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Balloon Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Balloon controller
pub struct BalloonController {
    /// VM balloons
    pub vm_balloons: [VmBalloon; MAX_BALLOON_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Global memory pressure threshold (%)
    pub pressure_threshold: AtomicU8,
    /// Critical pressure threshold (%)
    pub critical_threshold: AtomicU8,
    /// Host total memory
    pub host_memory: AtomicU64,
    /// Host free memory
    pub host_free: AtomicU64,
    /// Total balloon memory
    pub total_balloon: AtomicU64,
    /// Inflation count
    pub inflate_count: AtomicU64,
    /// Deflation count
    pub deflate_count: AtomicU64,
    /// Reclaim count
    pub reclaim_count: AtomicU64,
    /// Last pressure check
    pub last_pressure_check: AtomicU64,
    /// Pressure check interval (ms)
    pub pressure_interval: AtomicU32,
}

impl BalloonController {
    pub const fn new() -> Self {
        Self {
            vm_balloons: [const { VmBalloon::new() }; MAX_BALLOON_VMS],
            vm_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            pressure_threshold: AtomicU8::new(80),
            critical_threshold: AtomicU8::new(95),
            host_memory: AtomicU64::new(0),
            host_free: AtomicU64::new(0),
            total_balloon: AtomicU64::new(0),
            inflate_count: AtomicU64::new(0),
            deflate_count: AtomicU64::new(0),
            reclaim_count: AtomicU64::new(0),
            last_pressure_check: AtomicU64::new(0),
            pressure_interval: AtomicU32::new(100),
        }
    }

    /// Enable balloon controller
    pub fn enable(&mut self, host_memory: u64, pressure_threshold: u8, critical_threshold: u8) {
        self.host_memory.store(host_memory, Ordering::Release);
        self.pressure_threshold.store(pressure_threshold, Ordering::Release);
        self.critical_threshold.store(critical_threshold, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable balloon controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM
    pub fn register_vm(&mut self, vm_id: u32, guest_memory: u64, 
                       min_size: u32, max_size: u32) -> Result<u8, HvError> {
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_BALLOON_VMS {
            return Err(HvError::LogicalFault);
        }
        
        // Check if VM already registered
        for i in 0..count as usize {
            if self.vm_balloons[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Ok(i as u8);
            }
        }
        
        let balloon = &self.vm_balloons[count as usize];
        balloon.init(vm_id, guest_memory, min_size, max_size);
        
        self.vm_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Unregister VM
    pub fn unregister_vm(&mut self, vm_id: u32) -> Result<(), HvError> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_balloons[i].vm_id.load(Ordering::Acquire) == vm_id {
                self.vm_balloons[i].valid.store(false, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Get VM balloon
    pub fn get_vm_balloon(&self, vm_id: u32) -> Option<&VmBalloon> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_balloons[i].vm_id.load(Ordering::Acquire) == vm_id &&
               self.vm_balloons[i].valid.load(Ordering::Acquire) {
                return Some(&self.vm_balloons[i]);
            }
        }
        None
    }

    /// Get VM balloon mutable
    pub fn get_vm_balloon_mut(&mut self, vm_id: u32) -> Option<&mut VmBalloon> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_balloons[i].vm_id.load(Ordering::Acquire) == vm_id &&
               self.vm_balloons[i].valid.load(Ordering::Acquire) {
                return Some(&mut self.vm_balloons[i]);
            }
        }
        None
    }

    /// Check memory pressure
    pub fn check_pressure(&self) -> u8 {
        let now = Self::get_timestamp();
        let interval = self.pressure_interval.load(Ordering::Acquire) as u64;
        
        if now - self.last_pressure_check.load(Ordering::Acquire) < interval {
            return 0;
        }
        
        self.last_pressure_check.store(now, Ordering::Release);
        
        // Calculate pressure
        let host_mem = self.host_memory.load(Ordering::Acquire);
        let host_free = self.host_free.load(Ordering::Acquire);
        
        if host_mem == 0 {
            return 0;
        }
        
        let used = host_mem.saturating_sub(host_free);
        let pressure = ((used * 100) / host_mem) as u8;
        
        pressure
    }

    /// Adjust balloons based on pressure
    pub fn adjust_for_pressure(&mut self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let pressure = self.check_pressure();
        let threshold = self.pressure_threshold.load(Ordering::Acquire);
        let critical = self.critical_threshold.load(Ordering::Acquire);
        
        let mut adjustments = 0u32;
        
        if pressure >= critical {
            // Critical: inflate all balloons aggressively
            for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
                let balloon = &self.vm_balloons[i];
                if balloon.valid.load(Ordering::Acquire) && 
                   balloon.driver_installed.load(Ordering::Acquire) {
                    let current = balloon.current_size.load(Ordering::Acquire);
                    let max = balloon.max_size.load(Ordering::Acquire);
                    let target = (current + 1024).min(max); // Add 4MB
                    balloon.set_target(target);
                    balloon.priority.store(reclaim_priority::CRITICAL, Ordering::Release);
                    adjustments += 1;
                }
            }
        } else if pressure >= threshold {
            // High: inflate based on priority
            for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
                let balloon = &self.vm_balloons[i];
                if balloon.valid.load(Ordering::Acquire) &&
                   balloon.driver_installed.load(Ordering::Acquire) {
                    let current = balloon.current_size.load(Ordering::Acquire);
                    let max = balloon.max_size.load(Ordering::Acquire);
                    let target = (current + 256).min(max); // Add 1MB
                    balloon.set_target(target);
                    balloon.priority.store(reclaim_priority::HIGH, Ordering::Release);
                    adjustments += 1;
                }
            }
        } else if pressure < threshold - 20 {
            // Low: deflate balloons
            for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
                let balloon = &self.vm_balloons[i];
                if balloon.valid.load(Ordering::Acquire) &&
                   balloon.current_size.load(Ordering::Acquire) > 0 {
                    let current = balloon.current_size.load(Ordering::Acquire);
                    let min = balloon.min_size.load(Ordering::Acquire);
                    let target = current.saturating_sub(256).max(min); // Remove 1MB
                    balloon.set_target(target);
                    balloon.priority.store(reclaim_priority::LOW, Ordering::Release);
                    adjustments += 1;
                }
            }
        }
        
        adjustments
    }

    /// Process all balloon adjustments
    pub fn process_balloons(&mut self) -> (u32, u32) {
        let mut total_inflated = 0u32;
        let mut total_deflated = 0u32;
        
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            let balloon = &self.vm_balloons[i];
            if !balloon.valid.load(Ordering::Acquire) {
                continue;
            }
            
            let state = balloon.state.load(Ordering::Acquire);
            match state {
                balloon_state::INFLATING => {
                    // Would request pages from guest driver
                    let rate = balloon.inflate_rate.load(Ordering::Acquire);
                    // Simulate inflation
                    let pages = [0u64; 256]; // Placeholder
                    let inflated = balloon.inflate(&pages[..rate as usize / 4]);
                    total_inflated += inflated;
                }
                balloon_state::DEFLATING => {
                    let rate = balloon.deflate_rate.load(Ordering::Acquire);
                    let deflated = balloon.deflate(rate / 4);
                    total_deflated += deflated;
                }
                _ => {}
            }
        }
        
        if total_inflated > 0 {
            self.inflate_count.fetch_add(total_inflated as u64, Ordering::Release);
        }
        if total_deflated > 0 {
            self.deflate_count.fetch_add(total_deflated as u64, Ordering::Release);
        }
        
        (total_inflated, total_deflated)
    }

    /// Process free page hints from all VMs
    pub fn process_free_hints(&mut self) -> u32 {
        let mut total = 0u32;
        
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            let balloon = &self.vm_balloons[i];
            if balloon.valid.load(Ordering::Acquire) {
                total += balloon.process_free_hints();
            }
        }
        
        self.reclaim_count.fetch_add(total as u64, Ordering::Release);
        total
    }

    /// Set driver installed for VM
    pub fn set_driver_installed(&self, vm_id: u32, installed: bool) -> Result<(), HvError> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_balloons[i].vm_id.load(Ordering::Acquire) == vm_id {
                self.vm_balloons[i].driver_installed.store(installed, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Update host memory stats
    pub fn update_host_memory(&self, total: u64, free: u64) {
        self.host_memory.store(total, Ordering::Release);
        self.host_free.store(free, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> BalloonStats {
        let mut total_balloon = 0u64;
        let mut active_vms = 0u8;
        
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_balloons[i].valid.load(Ordering::Acquire) {
                active_vms += 1;
                total_balloon += self.vm_balloons[i].current_size.load(Ordering::Acquire) as u64 * PAGE_SIZE as u64;
            }
        }
        
        BalloonStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vm_count: active_vms,
            total_balloon,
            inflate_count: self.inflate_count.load(Ordering::Acquire),
            deflate_count: self.deflate_count.load(Ordering::Acquire),
            reclaim_count: self.reclaim_count.load(Ordering::Acquire),
            pressure: self.check_pressure(),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for BalloonController {
    fn default() -> Self {
        Self::new()
    }
}

/// Balloon statistics
#[repr(C)]
pub struct BalloonStats {
    pub enabled: bool,
    pub vm_count: u8,
    pub total_balloon: u64,
    pub inflate_count: u64,
    pub deflate_count: u64,
    pub reclaim_count: u64,
    pub pressure: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vm() {
        let mut ctrl = BalloonController::new();
        ctrl.enable(16 * 1024 * 1024 * 1024, 80, 95);
        
        let idx = ctrl.register_vm(1, 4 * 1024 * 1024 * 1024, 0, 1024 * 1024).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn inflate_balloon() {
        let mut ctrl = BalloonController::new();
        ctrl.enable(16 * 1024 * 1024 * 1024, 80, 95);
        ctrl.register_vm(1, 4 * 1024 * 1024 * 1024, 0, 1024 * 1024).unwrap();
        
        let balloon = ctrl.get_vm_balloon(1).unwrap();
        balloon.set_target(1024);
        balloon.driver_installed.store(true, Ordering::Release);
        
        let pages = [0x1000u64; 256];
        let inflated = balloon.inflate(&pages);
        assert!(inflated > 0);
    }

    #[test]
    fn deflate_balloon() {
        let mut ctrl = BalloonController::new();
        ctrl.enable(16 * 1024 * 1024 * 1024, 80, 95);
        ctrl.register_vm(1, 4 * 1024 * 1024 * 1024, 0, 1024 * 1024).unwrap();
        
        let balloon = ctrl.get_vm_balloon(1).unwrap();
        balloon.set_target(1024);
        
        let pages = [0x1000u64; 256];
        balloon.inflate(&pages);
        
        balloon.set_target(0);
        let deflated = balloon.deflate(256);
        assert!(deflated > 0);
    }

    #[test]
    fn free_page_hint() {
        let mut ctrl = BalloonController::new();
        ctrl.enable(16 * 1024 * 1024 * 1024, 80, 95);
        ctrl.register_vm(1, 4 * 1024 * 1024 * 1024, 0, 1024 * 1024).unwrap();
        
        let balloon = ctrl.get_vm_balloon(1).unwrap();
        balloon.add_free_hint(0x1000, 0x2000, 1).unwrap();
        
        let processed = balloon.process_free_hints();
        assert_eq!(processed, 1);
    }

    #[test]
    fn adjust_for_pressure() {
        let mut ctrl = BalloonController::new();
        ctrl.enable(16 * 1024 * 1024 * 1024, 80, 95);
        ctrl.register_vm(1, 4 * 1024 * 1024 * 1024, 0, 1024 * 1024).unwrap();
        
        // Set driver installed before updating memory
        ctrl.set_driver_installed(1, true).unwrap();
        
        // Simulate critical memory pressure (very low free memory)
        ctrl.update_host_memory(16 * 1024 * 1024 * 1024, 100 * 1024 * 1024); // 100MB free out of 16GB
        
        // Force pressure check to run by setting last check to 0 and interval to 0
        ctrl.pressure_interval.store(0, Ordering::Release);
        
        let adjustments = ctrl.adjust_for_pressure();
        assert!(adjustments > 0);
    }
}
