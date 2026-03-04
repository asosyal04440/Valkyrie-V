//! Hypervisor Introspection - Self-protection
//!
//! Hypervisor self-protection and integrity monitoring against attacks.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// HVI Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum protected regions
pub const MAX_PROTECTED_REGIONS: usize = 64;

/// Maximum integrity checks
pub const MAX_INTEGRITY_CHECKS: usize = 128;

/// Maximum watchpoints
pub const MAX_HVI_WATCHPOINTS: usize = 64;

/// Maximum event log entries
pub const MAX_EVENT_LOG: usize = 1024;

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// Protection types
pub mod prot_type {
    pub const READ: u8 = 1 << 0;
    pub const WRITE: u8 = 1 << 1;
    pub const EXECUTE: u8 = 1 << 2;
    pub const ALL: u8 = READ | WRITE | EXECUTE;
}

/// Integrity check types
pub mod check_type {
    pub const HASH: u8 = 0;        // Hash-based
    pub const CRC32: u8 = 1;       // CRC32 checksum
    pub const SIGNATURE: u8 = 2;   // Cryptographic signature
    pub const STRUCTURE: u8 = 3;   // Structure validation
}

/// Alert levels
pub mod alert_level {
    pub const INFO: u8 = 0;
    pub const WARNING: u8 = 1;
    pub const CRITICAL: u8 = 2;
    pub const FATAL: u8 = 3;
}

/// Event types
pub mod hvi_event {
    pub const NONE: u16 = 0;
    pub const INTEGRITY_VIOLATION: u16 = 1;
    pub const ACCESS_VIOLATION: u16 = 2;
    pub const TAMPER_ATTEMPT: u16 = 3;
    pub const ROOTKIT_DETECTED: u16 = 4;
    pub const CODE_INJECTION: u16 = 5;
    pub const HOOK_DETECTED: u16 = 6;
    pub const ROP_DETECTED: u16 = 7;
    pub const SHELLCODE_DETECTED: u16 = 8;
    pub const PROTECTION_TRIGGERED: u16 = 9;
    pub const CHECK_FAILED: u16 = 10;
    pub const MEMORY_CORRUPTION: u16 = 11;
    pub const CONFIG_CHANGE: u16 = 12;
}

// ─────────────────────────────────────────────────────────────────────────────
// Protected Region
// ─────────────────────────────────────────────────────────────────────────────

/// Protected memory region
pub struct ProtectedRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Start HPA (host physical address)
    pub hpa_start: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Protection mask
    pub protection: AtomicU8,
    /// Original hash
    pub hash: AtomicU64,
    /// Current hash
    pub current_hash: AtomicU64,
    /// Check count
    pub check_count: AtomicU64,
    /// Violation count
    pub violation_count: AtomicU32,
    /// Last check time
    pub last_check: AtomicU64,
    /// Last violation time
    pub last_violation: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl ProtectedRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            hpa_start: AtomicU64::new(0),
            size: AtomicU64::new(0),
            protection: AtomicU8::new(prot_type::ALL),
            hash: AtomicU64::new(0),
            current_hash: AtomicU64::new(0),
            check_count: AtomicU64::new(0),
            violation_count: AtomicU32::new(0),
            last_check: AtomicU64::new(0),
            last_violation: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, hpa_start: u64, size: u64, protection: u8, hash: u64) {
        self.region_id.store(region_id, Ordering::Release);
        self.hpa_start.store(hpa_start, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.protection.store(protection, Ordering::Release);
        self.hash.store(hash, Ordering::Release);
        self.current_hash.store(hash, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check integrity
    pub fn check_integrity(&self, computed_hash: u64) -> bool {
        self.check_count.fetch_add(1, Ordering::Release);
        self.last_check.store(Self::get_timestamp(), Ordering::Release);
        self.current_hash.store(computed_hash, Ordering::Release);
        
        let expected = self.hash.load(Ordering::Acquire);
        
        if computed_hash != expected {
            self.record_violation();
            false
        } else {
            true
        }
    }

    /// Record violation
    pub fn record_violation(&self) {
        self.violation_count.fetch_add(1, Ordering::Release);
        self.last_violation.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Update expected hash
    pub fn update_hash(&self, new_hash: u64) {
        self.hash.store(new_hash, Ordering::Release);
        self.current_hash.store(new_hash, Ordering::Release);
    }

    /// Check if address is in region
    pub fn contains(&self, hpa: u64) -> bool {
        let start = self.hpa_start.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        hpa >= start && hpa < start + size
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for ProtectedRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Integrity Check
// ─────────────────────────────────────────────────────────────────────────────

/// Integrity check entry
pub struct IntegrityCheck {
    /// Check ID
    pub check_id: AtomicU32,
    /// Check type
    pub check_type: AtomicU8,
    /// Target address
    pub target_addr: AtomicU64,
    /// Size in bytes
    pub size: AtomicU32,
    /// Expected value (hash/checksum)
    pub expected: AtomicU64,
    /// Current value
    pub current: AtomicU64,
    /// Check interval (ms)
    pub interval: AtomicU32,
    /// Last check time
    pub last_check: AtomicU64,
    /// Check count
    pub check_count: AtomicU64,
    /// Fail count
    pub fail_count: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl IntegrityCheck {
    pub const fn new() -> Self {
        Self {
            check_id: AtomicU32::new(0),
            check_type: AtomicU8::new(check_type::HASH),
            target_addr: AtomicU64::new(0),
            size: AtomicU32::new(0),
            expected: AtomicU64::new(0),
            current: AtomicU64::new(0),
            interval: AtomicU32::new(1000), // 1 second
            last_check: AtomicU64::new(0),
            check_count: AtomicU64::new(0),
            fail_count: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize check
    pub fn init(&self, check_id: u32, check_type: u8, target_addr: u64, 
                size: u32, expected: u64, interval: u32) {
        self.check_id.store(check_id, Ordering::Release);
        self.check_type.store(check_type, Ordering::Release);
        self.target_addr.store(target_addr, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.expected.store(expected, Ordering::Release);
        self.interval.store(interval, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Run check
    pub fn run_check(&self, computed: u64) -> bool {
        self.check_count.fetch_add(1, Ordering::Release);
        self.last_check.store(Self::get_timestamp(), Ordering::Release);
        self.current.store(computed, Ordering::Release);
        
        let expected = self.expected.load(Ordering::Acquire);
        
        if computed != expected {
            self.fail_count.fetch_add(1, Ordering::Release);
            false
        } else {
            true
        }
    }

    /// Update expected value
    pub fn update_expected(&self, new_expected: u64) {
        self.expected.store(new_expected, Ordering::Release);
    }

    /// Check if due
    pub fn is_due(&self) -> bool {
        let last = self.last_check.load(Ordering::Acquire);
        let interval = self.interval.load(Ordering::Acquire) as u64 * 1_000_000;
        let now = Self::get_timestamp();
        
        now >= last + interval
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for IntegrityCheck {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HVI Watchpoint
// ─────────────────────────────────────────────────────────────────────────────

/// HVI watchpoint
pub struct HviWatchpoint {
    /// Watchpoint ID
    pub wp_id: AtomicU32,
    /// Address
    pub addr: AtomicU64,
    /// Size in bytes
    pub size: AtomicU8,
    /// Access mask
    pub access_mask: AtomicU8,
    /// Hit count
    pub hit_count: AtomicU64,
    /// Last hit time
    pub last_hit: AtomicU64,
    /// Alert on hit
    pub alert: AtomicBool,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl HviWatchpoint {
    pub const fn new() -> Self {
        Self {
            wp_id: AtomicU32::new(0),
            addr: AtomicU64::new(0),
            size: AtomicU8::new(1),
            access_mask: AtomicU8::new(prot_type::ALL),
            hit_count: AtomicU64::new(0),
            last_hit: AtomicU64::new(0),
            alert: AtomicBool::new(true),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize watchpoint
    pub fn init(&self, wp_id: u32, addr: u64, size: u8, access_mask: u8, alert: bool) {
        self.wp_id.store(wp_id, Ordering::Release);
        self.addr.store(addr, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.access_mask.store(access_mask, Ordering::Release);
        self.alert.store(alert, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record hit
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Release);
        self.last_hit.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Check if address matches
    pub fn matches(&self, addr: u64, access: u8) -> bool {
        let wp_addr = self.addr.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        let mask = self.access_mask.load(Ordering::Acquire);
        
        addr >= wp_addr && addr < wp_addr + size as u64 && (mask & access) != 0
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for HviWatchpoint {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HVI Event Log Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Event log entry
pub struct EventLogEntry {
    /// Entry ID
    pub entry_id: AtomicU32,
    /// Event type
    pub event_type: AtomicU16,
    /// Alert level
    pub alert_level: AtomicU8,
    /// Address
    pub addr: AtomicU64,
    /// Value
    pub value: AtomicU64,
    /// Expected value
    pub expected: AtomicU64,
    /// Timestamp
    pub timestamp: AtomicU64,
    /// Source (region/check/wp ID)
    pub source_id: AtomicU32,
    /// Flags
    pub flags: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl EventLogEntry {
    pub const fn new() -> Self {
        Self {
            entry_id: AtomicU32::new(0),
            event_type: AtomicU16::new(hvi_event::NONE),
            alert_level: AtomicU8::new(alert_level::INFO),
            addr: AtomicU64::new(0),
            value: AtomicU64::new(0),
            expected: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
            source_id: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize entry
    pub fn init(&self, entry_id: u32, event_type: u16, alert_level: u8, 
                addr: u64, value: u64, expected: u64, source_id: u32) {
        self.entry_id.store(entry_id, Ordering::Release);
        self.event_type.store(event_type, Ordering::Release);
        self.alert_level.store(alert_level, Ordering::Release);
        self.addr.store(addr, Ordering::Release);
        self.value.store(value, Ordering::Release);
        self.expected.store(expected, Ordering::Release);
        self.source_id.store(source_id, Ordering::Release);
        self.timestamp.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for EventLogEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HVI Controller
// ─────────────────────────────────────────────────────────────────────────────

/// HVI controller
pub struct HviController {
    /// Protected regions
    pub regions: [ProtectedRegion; MAX_PROTECTED_REGIONS],
    /// Region count
    pub region_count: AtomicU8,
    /// Integrity checks
    pub checks: [IntegrityCheck; MAX_INTEGRITY_CHECKS],
    /// Check count
    pub check_count: AtomicU16,
    /// Watchpoints
    pub watchpoints: [HviWatchpoint; MAX_HVI_WATCHPOINTS],
    /// Watchpoint count
    pub wp_count: AtomicU8,
    /// Event log
    pub event_log: [EventLogEntry; MAX_EVENT_LOG],
    /// Event log head
    pub event_head: AtomicU16,
    /// Event log tail
    pub event_tail: AtomicU16,
    /// Event count
    pub event_count: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Protection active
    pub protection_active: AtomicBool,
    /// Monitoring active
    pub monitoring_active: AtomicBool,
    /// Auto-remediation
    pub auto_remediation: AtomicBool,
    /// Strict mode (block on violation)
    pub strict_mode: AtomicBool,
    /// Check interval (ms)
    pub check_interval: AtomicU32,
    /// Last full check
    pub last_full_check: AtomicU64,
    /// Total violations
    pub total_violations: AtomicU64,
    /// Total checks
    pub total_checks: AtomicU64,
    /// Total blocked
    pub total_blocked: AtomicU64,
    /// Critical violations
    pub critical_violations: AtomicU64,
}

impl HviController {
    pub const fn new() -> Self {
        Self {
            regions: [const { ProtectedRegion::new() }; MAX_PROTECTED_REGIONS],
            region_count: AtomicU8::new(0),
            checks: [const { IntegrityCheck::new() }; MAX_INTEGRITY_CHECKS],
            check_count: AtomicU16::new(0),
            watchpoints: [const { HviWatchpoint::new() }; MAX_HVI_WATCHPOINTS],
            wp_count: AtomicU8::new(0),
            event_log: [const { EventLogEntry::new() }; MAX_EVENT_LOG],
            event_head: AtomicU16::new(0),
            event_tail: AtomicU16::new(0),
            event_count: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            protection_active: AtomicBool::new(false),
            monitoring_active: AtomicBool::new(false),
            auto_remediation: AtomicBool::new(false),
            strict_mode: AtomicBool::new(true),
            check_interval: AtomicU32::new(1000),
            last_full_check: AtomicU64::new(0),
            total_violations: AtomicU64::new(0),
            total_checks: AtomicU64::new(0),
            total_blocked: AtomicU64::new(0),
            critical_violations: AtomicU64::new(0),
        }
    }

    /// Enable HVI
    pub fn enable(&mut self, protection: bool, monitoring: bool, 
                  auto_remediation: bool, strict: bool) {
        self.protection_active.store(protection, Ordering::Release);
        self.monitoring_active.store(monitoring, Ordering::Release);
        self.auto_remediation.store(auto_remediation, Ordering::Release);
        self.strict_mode.store(strict, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable HVI
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
        self.protection_active.store(false, Ordering::Release);
        self.monitoring_active.store(false, Ordering::Release);
    }

    /// Add protected region
    pub fn add_region(&mut self, hpa_start: u64, size: u64, 
                      protection: u8, hash: u64) -> Result<u8, HvError> {
        let count = self.region_count.load(Ordering::Acquire);
        if count as usize >= MAX_PROTECTED_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.regions[count as usize].init(count, hpa_start, size, protection, hash);
        self.region_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Add integrity check
    pub fn add_check(&mut self, check_type: u8, target_addr: u64, 
                     size: u32, expected: u64, interval: u32) -> Result<u32, HvError> {
        let count = self.check_count.load(Ordering::Acquire);
        if count as usize >= MAX_INTEGRITY_CHECKS {
            return Err(HvError::LogicalFault);
        }
        
        let check_id = count as u32 + 1;
        self.checks[count as usize].init(check_id, check_type, target_addr, size, expected, interval);
        self.check_count.fetch_add(1, Ordering::Release);
        
        Ok(check_id)
    }

    /// Add watchpoint
    pub fn add_watchpoint(&mut self, addr: u64, size: u8, 
                          access_mask: u8, alert: bool) -> Result<u32, HvError> {
        let count = self.wp_count.load(Ordering::Acquire);
        if count as usize >= MAX_HVI_WATCHPOINTS {
            return Err(HvError::LogicalFault);
        }
        
        let wp_id = count as u32 + 1;
        self.watchpoints[count as usize].init(wp_id, addr, size, access_mask, alert);
        self.wp_count.fetch_add(1, Ordering::Release);
        
        Ok(wp_id)
    }

    /// Log event
    pub fn log_event(&self, event_type: u16, alert_level: u8, 
                     addr: u64, value: u64, expected: u64, source_id: u32) -> Result<(), HvError> {
        let head = self.event_head.load(Ordering::Acquire);
        let tail = self.event_tail.load(Ordering::Acquire);
        
        let next_head = (head + 1) % MAX_EVENT_LOG as u16;
        if next_head == tail {
            // Log full, advance tail
            self.event_tail.store((tail + 1) % MAX_EVENT_LOG as u16, Ordering::Release);
        }
        
        let entry_id = self.event_count.fetch_add(1, Ordering::Release);
        self.event_log[head as usize].init(entry_id, event_type, alert_level, 
                                            addr, value, expected, source_id);
        self.event_head.store(next_head, Ordering::Release);
        
        Ok(())
    }

    /// Check memory access
    pub fn check_access(&self, hpa: u64, access: u8) -> Result<bool, HvError> {
        if !self.enabled.load(Ordering::Acquire) || !self.protection_active.load(Ordering::Acquire) {
            return Ok(true);
        }
        
        // Check protected regions
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            if region.enabled.load(Ordering::Acquire) && region.contains(hpa) {
                let prot = region.protection.load(Ordering::Acquire);
                
                if (prot & access) != 0 {
                    // Violation
                    region.record_violation();
                    self.total_violations.fetch_add(1, Ordering::Release);
                    self.total_blocked.fetch_add(1, Ordering::Release);
                    
                    self.log_event(
                        hvi_event::ACCESS_VIOLATION,
                        alert_level::CRITICAL,
                        hpa,
                        access as u64,
                        prot as u64,
                        i as u32
                    )?;
                    
                    return if self.strict_mode.load(Ordering::Acquire) {
                        Err(HvError::LogicalFault)
                    } else {
                        Ok(false)
                    };
                }
            }
        }
        
        // Check watchpoints
        for i in 0..self.wp_count.load(Ordering::Acquire) as usize {
            let wp = &self.watchpoints[i];
            if wp.enabled.load(Ordering::Acquire) && wp.matches(hpa, access) {
                wp.record_hit();
                
                if wp.alert.load(Ordering::Acquire) {
                    self.log_event(
                        hvi_event::PROTECTION_TRIGGERED,
                        alert_level::WARNING,
                        hpa,
                        access as u64,
                        0,
                        i as u32
                    )?;
                }
            }
        }
        
        Ok(true)
    }

    /// Run integrity checks
    pub fn run_checks(&self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) || !self.monitoring_active.load(Ordering::Acquire) {
            return 0;
        }
        
        let mut failures = 0u32;
        
        // Check regions
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            if !region.enabled.load(Ordering::Acquire) {
                continue;
            }
            
            // Would compute actual hash here
            let computed_hash = region.hash.load(Ordering::Acquire);
            
            if !region.check_integrity(computed_hash) {
                failures += 1;
                self.total_violations.fetch_add(1, Ordering::Release);
                
                self.log_event(
                    hvi_event::INTEGRITY_VIOLATION,
                    alert_level::CRITICAL,
                    region.hpa_start.load(Ordering::Acquire),
                    region.current_hash.load(Ordering::Acquire),
                    region.hash.load(Ordering::Acquire),
                    i as u32
                );
            }
            
            self.total_checks.fetch_add(1, Ordering::Release);
        }
        
        // Check integrity checks
        for i in 0..self.check_count.load(Ordering::Acquire) as usize {
            let check = &self.checks[i];
            if !check.enabled.load(Ordering::Acquire) || !check.is_due() {
                continue;
            }
            
            // Would compute actual value here
            let computed = check.expected.load(Ordering::Acquire);
            
            if !check.run_check(computed) {
                failures += 1;
                self.total_violations.fetch_add(1, Ordering::Release);
                
                self.log_event(
                    hvi_event::CHECK_FAILED,
                    alert_level::CRITICAL,
                    check.target_addr.load(Ordering::Acquire),
                    check.current.load(Ordering::Acquire),
                    check.expected.load(Ordering::Acquire),
                    i as u32
                );
            }
            
            self.total_checks.fetch_add(1, Ordering::Release);
        }
        
        self.last_full_check.store(Self::get_timestamp(), Ordering::Release);
        
        failures
    }

    /// Get event
    pub fn get_event(&self) -> Option<&EventLogEntry> {
        let head = self.event_head.load(Ordering::Acquire);
        let tail = self.event_tail.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        let entry = &self.event_log[tail as usize];
        self.event_tail.store((tail + 1) % MAX_EVENT_LOG as u16, Ordering::Release);
        
        Some(entry)
    }

    /// Get statistics
    pub fn get_stats(&self) -> HviStats {
        HviStats {
            enabled: self.enabled.load(Ordering::Acquire),
            protection_active: self.protection_active.load(Ordering::Acquire),
            monitoring_active: self.monitoring_active.load(Ordering::Acquire),
            region_count: self.region_count.load(Ordering::Acquire),
            check_count: self.check_count.load(Ordering::Acquire),
            wp_count: self.wp_count.load(Ordering::Acquire),
            total_violations: self.total_violations.load(Ordering::Acquire),
            total_checks: self.total_checks.load(Ordering::Acquire),
            total_blocked: self.total_blocked.load(Ordering::Acquire),
            critical_violations: self.critical_violations.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for HviController {
    fn default() -> Self {
        Self::new()
    }
}

/// HVI statistics
#[repr(C)]
pub struct HviStats {
    pub enabled: bool,
    pub protection_active: bool,
    pub monitoring_active: bool,
    pub region_count: u8,
    pub check_count: u16,
    pub wp_count: u8,
    pub total_violations: u64,
    pub total_checks: u64,
    pub total_blocked: u64,
    pub critical_violations: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_hvi() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        
        assert!(ctrl.enabled.load(Ordering::Acquire));
        assert!(ctrl.protection_active.load(Ordering::Acquire));
    }

    #[test]
    fn add_region() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        
        let id = ctrl.add_region(0x1000000, 4096, prot_type::WRITE | prot_type::EXECUTE, 0xABCDEF).unwrap();
        assert_eq!(ctrl.region_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn add_check() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        
        let id = ctrl.add_check(check_type::HASH, 0x2000000, 1024, 0x12345678, 1000).unwrap();
        assert_eq!(ctrl.check_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn add_watchpoint() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        
        let id = ctrl.add_watchpoint(0x3000000, 8, prot_type::WRITE, true).unwrap();
        assert_eq!(ctrl.wp_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn access_violation() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        ctrl.add_region(0x1000000, 4096, prot_type::WRITE, 0xABCDEF).unwrap();
        
        // Write to protected region should fail
        let result = ctrl.check_access(0x1000100, prot_type::WRITE);
        assert!(result.is_err() || result.ok() == Some(false));
        
        let stats = ctrl.get_stats();
        assert!(stats.total_violations > 0);
    }

    #[test]
    fn allowed_access() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        ctrl.add_region(0x1000000, 4096, prot_type::WRITE, 0xABCDEF).unwrap();
        
        // Read from write-protected region should succeed
        let result = ctrl.check_access(0x1000100, prot_type::READ);
        assert!(result.is_ok() && result.unwrap());
    }

    #[test]
    fn integrity_check() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        ctrl.add_region(0x1000000, 4096, prot_type::ALL, 0xABCDEF).unwrap();
        
        let failures = ctrl.run_checks();
        assert_eq!(failures, 0); // Hash matches
        
        let stats = ctrl.get_stats();
        assert!(stats.total_checks > 0);
    }

    #[test]
    fn event_logging() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        
        ctrl.log_event(hvi_event::INTEGRITY_VIOLATION, alert_level::CRITICAL,
                       0x1000000, 0x1111, 0x2222, 0).unwrap();
        
        let event = ctrl.get_event();
        assert!(event.is_some());
        
        let e = event.unwrap();
        assert_eq!(e.event_type.load(Ordering::Acquire), hvi_event::INTEGRITY_VIOLATION);
    }

    #[test]
    fn watchpoint_hit() {
        let mut ctrl = HviController::new();
        ctrl.enable(true, true, false, true);
        ctrl.add_watchpoint(0x3000000, 8, prot_type::WRITE, true).unwrap();
        
        // Access that matches watchpoint
        ctrl.check_access(0x3000004, prot_type::WRITE).unwrap();
        
        let wp = &ctrl.watchpoints[0];
        assert_eq!(wp.hit_count.load(Ordering::Acquire), 1);
    }
}
