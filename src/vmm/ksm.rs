//! Kernel Samepage Merging (KSM)
//!
//! Memory deduplication for VMs - finds identical pages across
//! VMs and merges them into a single copy-on-write page.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// KSM page hash table size (must be power of 2)
pub const KSM_HASH_BUCKETS: usize = 4096;

/// Maximum pages to scan per iteration
pub const KSM_MAX_SCAN_PAGES: u32 = 256;

/// KSM page state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KsmPageState {
    /// Not registered with KSM
    Unregistered = 0,
    /// Registered, waiting to be scanned
    Pending = 1,
    /// Stable (merged) page
    Stable = 2,
    /// Volatile (may change) page
    Volatile = 3,
    /// Shared (COW) page
    Shared = 4,
}

/// KSM page hash entry
#[repr(C)]
pub struct KsmHashEntry {
    /// Page content hash (xxHash64)
    pub hash: AtomicU64,
    /// Physical address of the page
    pub hpa: AtomicU64,
    /// Number of pages sharing this hash
    pub ref_count: AtomicU32,
    /// Page state
    pub state: AtomicU8,
}

impl KsmHashEntry {
    pub const fn new() -> Self {
        Self {
            hash: AtomicU64::new(0),
            hpa: AtomicU64::new(0),
            ref_count: AtomicU32::new(0),
            state: AtomicU8::new(KsmPageState::Unregistered as u8),
        }
    }
}

/// KSM statistics
#[repr(C)]
pub struct KsmStats {
    /// Pages currently shared
    pub pages_shared: AtomicU64,
    /// Pages currently sharing
    pub pages_sharing: AtomicU64,
    /// Pages unshared (COW broken)
    pub pages_unshared: AtomicU64,
    /// Pages volatile
    pub pages_volatile: AtomicU64,
    /// Full scans completed
    pub full_scans: AtomicU64,
    /// Pages merged
    pub pages_merged: AtomicU64,
    /// CPU time spent (TSC cycles)
    pub cpu_time: AtomicU64,
}

impl KsmStats {
    pub const fn new() -> Self {
        Self {
            pages_shared: AtomicU64::new(0),
            pages_sharing: AtomicU64::new(0),
            pages_unshared: AtomicU64::new(0),
            pages_volatile: AtomicU64::new(0),
            full_scans: AtomicU64::new(0),
            pages_merged: AtomicU64::new(0),
            cpu_time: AtomicU64::new(0),
        }
    }
}

/// KSM configuration
#[repr(C)]
pub struct KsmConfig {
    /// Enable KSM
    pub enabled: AtomicU8,
    /// Sleep time between scans (milliseconds)
    pub sleep_millisecs: AtomicU32,
    /// Pages to scan per iteration
    pub pages_to_scan: AtomicU32,
    /// Merge across NUMA nodes
    pub merge_across_nodes: AtomicU8,
    /// Max page age before re-scan
    pub max_page_age_ms: AtomicU32,
}

impl KsmConfig {
    pub const fn new() -> Self {
        Self {
            enabled: AtomicU8::new(0),
            sleep_millisecs: AtomicU32::new(200),
            pages_to_scan: AtomicU32::new(100),
            merge_across_nodes: AtomicU8::new(1),
            max_page_age_ms: AtomicU32::new(5000),
        }
    }
}

/// KSM driver state
pub struct KsmDriver {
    config: KsmConfig,
    stats: KsmStats,
    /// Hash table for page deduplication
    hash_table: [KsmHashEntry; KSM_HASH_BUCKETS],
    /// Current scan position
    scan_pos: AtomicU64,
    /// Number of registered VMs
    vm_count: AtomicU32,
}

impl KsmDriver {
    pub const fn new() -> Self {
        Self {
            config: KsmConfig::new(),
            stats: KsmStats::new(),
            hash_table: [const { KsmHashEntry::new() }; KSM_HASH_BUCKETS],
            scan_pos: AtomicU64::new(0),
            vm_count: AtomicU32::new(0),
        }
    }

    /// Enable or disable KSM
    pub fn set_enabled(&self, enabled: bool) {
        self.config.enabled.store(enabled as u8, Ordering::Release);
    }

    /// Set scan rate (pages per iteration)
    pub fn set_scan_rate(&self, pages: u32) {
        self.config.pages_to_scan.store(pages, Ordering::Release);
    }

    /// Set sleep interval between scans
    pub fn set_sleep_interval(&self, millis: u32) {
        self.config.sleep_millisecs.store(millis, Ordering::Release);
    }

    /// Register a VM for KSM scanning
    pub fn register_vm(&self) {
        self.vm_count.fetch_add(1, Ordering::Release);
    }

    /// Unregister a VM from KSM scanning
    pub fn unregister_vm(&self) {
        self.vm_count.fetch_sub(1, Ordering::Release);
    }

    /// Compute xxHash64 of a page (simplified - uses checksum)
    pub fn hash_page(data: &[u8; 4096]) -> u64 {
        // Simplified hash - in production use xxHash64 or similar
        let mut hash = 0u64;
        for chunk in data.chunks(8) {
            let mut bytes = [0u8; 8];
            bytes[..chunk.len()].copy_from_slice(chunk);
            hash = hash.wrapping_add(u64::from_le_bytes(bytes));
            hash = hash.rotate_left(13);
            hash = hash.wrapping_mul(0x517cc1b727220a95);
        }
        hash
    }

    /// Find a matching hash in the table
    fn find_matching(&self, hash: u64) -> Option<u32> {
        let bucket = (hash as usize) % KSM_HASH_BUCKETS;
        
        // Linear probe for matching hash
        for i in 0..8 {
            let idx = (bucket + i) % KSM_HASH_BUCKETS;
            let entry = &self.hash_table[idx];
            
            if entry.hash.load(Ordering::Acquire) == hash {
                return Some(idx as u32);
            }
            
            // Empty slot
            if entry.ref_count.load(Ordering::Acquire) == 0 {
                return None;
            }
        }
        None
    }

    /// Try to merge a page with existing identical pages
    pub fn try_merge_page(&self, hpa: u64, hash: u64) -> Result<bool, HvError> {
        if self.config.enabled.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }

        if let Some(idx) = self.find_matching(hash) {
            let entry = &self.hash_table[idx as usize];
            
            // Found matching page - increment ref count
            let old_count = entry.ref_count.fetch_add(1, Ordering::AcqRel);
            if old_count == 0 {
                // First page with this hash - store HPA
                entry.hpa.store(hpa, Ordering::Release);
                entry.state.store(KsmPageState::Stable as u8, Ordering::Release);
                self.stats.pages_shared.fetch_add(1, Ordering::Release);
            } else {
                // Duplicate - would merge here (COW)
                self.stats.pages_sharing.fetch_add(1, Ordering::Release);
                self.stats.pages_merged.fetch_add(1, Ordering::Release);
            }
            
            entry.hash.store(hash, Ordering::Release);
            return Ok(true);
        }

        // No match found - insert into empty slot
        let bucket = (hash as usize) % KSM_HASH_BUCKETS;
        for i in 0..8 {
            let idx = (bucket + i) % KSM_HASH_BUCKETS;
            let entry = &self.hash_table[idx];
            
            if entry.ref_count.load(Ordering::Acquire) == 0 {
                entry.hash.store(hash, Ordering::Release);
                entry.hpa.store(hpa, Ordering::Release);
                entry.ref_count.store(1, Ordering::Release);
                entry.state.store(KsmPageState::Stable as u8, Ordering::Release);
                self.stats.pages_shared.fetch_add(1, Ordering::Release);
                return Ok(true);
            }
        }

        // Table full
        Err(HvError::LogicalFault)
    }

    /// Break COW on a page (page was written to)
    pub fn break_cow(&self, hpa: u64, hash: u64) {
        if let Some(idx) = self.find_matching(hash) {
            let entry = &self.hash_table[idx as usize];
            
            if entry.hpa.load(Ordering::Acquire) == hpa {
                let old_count = entry.ref_count.fetch_sub(1, Ordering::AcqRel);
                if old_count <= 1 {
                    // Last reference - remove from table
                    entry.hash.store(0, Ordering::Release);
                    entry.hpa.store(0, Ordering::Release);
                    entry.state.store(KsmPageState::Unregistered as u8, Ordering::Release);
                    self.stats.pages_shared.fetch_sub(1, Ordering::Release);
                } else {
                    self.stats.pages_unshared.fetch_add(1, Ordering::Release);
                }
            }
        }
    }

    /// Run one scan iteration
    pub fn scan_iteration(&self, pages: &[(u64, u64)]) -> u32 {
        if self.config.enabled.load(Ordering::Acquire) == 0 {
            return 0;
        }

        let to_scan = self.config.pages_to_scan.load(Ordering::Acquire).min(pages.len() as u32);
        let mut merged = 0u32;

        for i in 0..to_scan as usize {
            if i >= pages.len() { break; }
            let (hpa, hash) = pages[i];
            
            if self.try_merge_page(hpa, hash).unwrap_or(false) {
                merged += 1;
            }
        }

        self.scan_pos.fetch_add(to_scan as u64, Ordering::Release);
        merged
    }

    /// Get current statistics
    pub fn get_stats(&self) -> KsmStats {
        KsmStats {
            pages_shared: AtomicU64::new(self.stats.pages_shared.load(Ordering::Acquire)),
            pages_sharing: AtomicU64::new(self.stats.pages_sharing.load(Ordering::Acquire)),
            pages_unshared: AtomicU64::new(self.stats.pages_unshared.load(Ordering::Acquire)),
            pages_volatile: AtomicU64::new(self.stats.pages_volatile.load(Ordering::Acquire)),
            full_scans: AtomicU64::new(self.stats.full_scans.load(Ordering::Acquire)),
            pages_merged: AtomicU64::new(self.stats.pages_merged.load(Ordering::Acquire)),
            cpu_time: AtomicU64::new(self.stats.cpu_time.load(Ordering::Acquire)),
        }
    }

    /// Calculate memory savings from KSM
    pub fn calculate_savings(&self) -> u64 {
        let sharing = self.stats.pages_sharing.load(Ordering::Acquire);
        let shared = self.stats.pages_shared.load(Ordering::Acquire);
        
        // Each shared page saves (sharing - 1) copies
        if shared > 0 {
            sharing * 4096
        } else {
            0
        }
    }
}

impl Default for KsmDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ksm_enable_disable() {
        let ksm = KsmDriver::new();
        
        ksm.set_enabled(true);
        assert_eq!(ksm.config.enabled.load(Ordering::Acquire), 1);
        
        ksm.set_enabled(false);
        assert_eq!(ksm.config.enabled.load(Ordering::Acquire), 0);
    }

    #[test]
    fn ksm_merge_identical_pages() {
        let ksm = KsmDriver::new();
        ksm.set_enabled(true);
        
        let hash = 0x12345678;
        
        // First page
        assert!(ksm.try_merge_page(0x1000, hash).unwrap());
        
        // Second identical page
        assert!(ksm.try_merge_page(0x2000, hash).unwrap());
        
        assert!(ksm.stats.pages_sharing.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn ksm_savings() {
        let ksm = KsmDriver::new();
        ksm.set_enabled(true);
        
        let hash = 0xABCD;
        ksm.try_merge_page(0x1000, hash).unwrap();
        ksm.try_merge_page(0x2000, hash).unwrap();
        ksm.try_merge_page(0x3000, hash).unwrap();
        
        let savings = ksm.calculate_savings();
        assert!(savings > 0);
    }
}
