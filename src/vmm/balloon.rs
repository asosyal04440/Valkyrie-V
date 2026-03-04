//! Memory Ballooning Driver
//!
//! Implements virtio-balloon protocol for dynamic memory management.
//! Allows the hypervisor to reclaim unused guest memory by inflating
//! the balloon (allocating pages in guest) or release memory by deflating.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Balloon page size (4KiB)
pub const BALLOON_PAGE_SIZE: u64 = 4096;

/// Maximum pages in balloon (1 GiB worth)
pub const MAX_BALLOON_PAGES: usize = 262_144;

/// Balloon configuration
#[repr(C)]
pub struct BalloonConfig {
    /// Number of pages guest should hold
    pub num_pages: AtomicU32,
    /// Actual pages held by guest
    pub actual: AtomicU32,
    /// Feature bits
    pub features: AtomicU32,
}

impl BalloonConfig {
    pub const fn new() -> Self {
        Self {
            num_pages: AtomicU32::new(0),
            actual: AtomicU32::new(0),
            features: AtomicU32::new(0),
        }
    }
}

/// Balloon statistics (VIRTIO_BALLOON_F_STATS_VQ)
#[repr(C)]
pub struct BalloonStats {
    pub swap_in: AtomicU64,
    pub swap_out: AtomicU64,
    pub major_faults: AtomicU64,
    pub minor_faults: AtomicU64,
    pub free_memory: AtomicU64,
    pub total_memory: AtomicU64,
    pub available_memory: AtomicU64,
}

impl BalloonStats {
    pub const fn new() -> Self {
        Self {
            swap_in: AtomicU64::new(0),
            swap_out: AtomicU64::new(0),
            major_faults: AtomicU64::new(0),
            minor_faults: AtomicU64::new(0),
            free_memory: AtomicU64::new(0),
            total_memory: AtomicU64::new(0),
            available_memory: AtomicU64::new(0),
        }
    }
}

/// Memory balloon driver state
pub struct BalloonDriver {
    config: BalloonConfig,
    stats: BalloonStats,
    /// Pages currently in balloon (GFNs)
    balloon_pages: [AtomicU64; 1024], // First 1024 pages as sample
    balloon_count: AtomicU32,
    /// Target size in pages
    target_pages: AtomicU32,
    /// Minimum pages to leave for guest
    min_pages: AtomicU32,
    /// Maximum pages to balloon
    max_pages: AtomicU32,
}

impl BalloonDriver {
    pub const fn new() -> Self {
        Self {
            config: BalloonConfig::new(),
            stats: BalloonStats::new(),
            balloon_pages: [const { AtomicU64::new(0) }; 1024],
            balloon_count: AtomicU32::new(0),
            target_pages: AtomicU32::new(0),
            min_pages: AtomicU32::new(256),    // 1 MiB minimum
            max_pages: AtomicU32::new(65536),  // 256 MiB maximum
        }
    }

    /// Inflate balloon - request guest to allocate pages
    pub fn inflate(&self, num_pages: u32) -> Result<(), HvError> {
        let current = self.balloon_count.load(Ordering::Acquire);
        let new_count = current.saturating_add(num_pages);
        
        if new_count > self.max_pages.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.target_pages.store(new_count, Ordering::Release);
        self.config.num_pages.store(new_count, Ordering::Release);
        Ok(())
    }

    /// Deflate balloon - release pages back to guest
    pub fn deflate(&self, num_pages: u32) -> Result<(), HvError> {
        let current = self.balloon_count.load(Ordering::Acquire);
        let new_count = current.saturating_sub(num_pages);
        
        if new_count < self.min_pages.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.target_pages.store(new_count, Ordering::Release);
        self.config.num_pages.store(new_count, Ordering::Release);
        Ok(())
    }

    /// Update actual balloon size (called when guest responds)
    pub fn update_actual(&self, actual: u32) {
        self.config.actual.store(actual, Ordering::Release);
        self.balloon_count.store(actual, Ordering::Release);
    }

    /// Get current balloon size in pages
    pub fn get_balloon_size(&self) -> u32 {
        self.balloon_count.load(Ordering::Acquire)
    }

    /// Get balloon size in bytes
    pub fn get_balloon_bytes(&self) -> u64 {
        self.balloon_count.load(Ordering::Acquire) as u64 * BALLOON_PAGE_SIZE
    }

    /// Set memory pressure target (0-100%)
    pub fn set_pressure(&self, pressure_percent: u8) {
        let max = self.max_pages.load(Ordering::Acquire) as u64;
        let target = (max * pressure_percent as u64 / 100) as u32;
        let clamped = target.max(self.min_pages.load(Ordering::Acquire));
        self.target_pages.store(clamped, Ordering::Release);
        self.config.num_pages.store(clamped, Ordering::Release);
    }

    /// Update statistics from guest
    pub fn update_stats(&self, stats: &BalloonStats) {
        self.stats.swap_in.store(
            stats.swap_in.load(Ordering::Acquire),
            Ordering::Release
        );
        self.stats.swap_out.store(
            stats.swap_out.load(Ordering::Acquire),
            Ordering::Release
        );
        self.stats.free_memory.store(
            stats.free_memory.load(Ordering::Acquire),
            Ordering::Release
        );
        self.stats.available_memory.store(
            stats.available_memory.load(Ordering::Acquire),
            Ordering::Release
        );
    }

    /// Check if ballooning is needed based on host memory pressure
    pub fn check_pressure(&self, host_free_percent: u8) -> bool {
        // If host has < 20% free memory, inflate balloon
        if host_free_percent < 20 {
            let inflate_pages = (self.max_pages.load(Ordering::Acquire) / 10) as u32;
            let _ = self.inflate(inflate_pages);
            return true;
        }
        // If host has > 50% free memory, deflate balloon
        if host_free_percent > 50 {
            let deflate_pages = (self.balloon_count.load(Ordering::Acquire) / 10) as u32;
            if deflate_pages > 0 {
                let _ = self.deflate(deflate_pages);
                return true;
            }
        }
        false
    }
}

impl Default for BalloonDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balloon_inflate_deflate() {
        let balloon = BalloonDriver::new();
        
        // Inflate by 512 pages (above min of 256)
        balloon.inflate(512).unwrap();
        assert_eq!(balloon.target_pages.load(Ordering::Acquire), 512);
        
        // Simulate guest responding to inflate
        balloon.update_actual(512);
        
        // Deflate by 256 pages (staying above min of 256)
        balloon.deflate(256).unwrap();
        assert_eq!(balloon.target_pages.load(Ordering::Acquire), 256);
    }

    #[test]
    fn balloon_respects_limits() {
        let balloon = BalloonDriver::new();
        
        // Should fail to inflate beyond max (65536)
        assert!(balloon.inflate(100_000).is_err());
        
        // Should fail to deflate below min (256) - starting from 0, deflate would go negative
        assert!(balloon.deflate(1).is_err());
    }

    #[test]
    fn balloon_pressure() {
        let balloon = BalloonDriver::new();
        
        // Low host memory -> inflate
        balloon.check_pressure(10);
        assert!(balloon.target_pages.load(Ordering::Acquire) > 0);
        
        // Simulate guest responding to inflate
        balloon.update_actual(balloon.target_pages.load(Ordering::Acquire));
        
        // High host memory -> deflate
        let before = balloon.target_pages.load(Ordering::Acquire);
        balloon.check_pressure(80);
        assert!(balloon.target_pages.load(Ordering::Acquire) < before);
    }
}
