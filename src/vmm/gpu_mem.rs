//! GPU Memory Virtualization
//!
//! Virtualized GPU memory management with address translation, migration, and oversubscription.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// GPU Memory Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum GPU memory regions
#[cfg(not(test))]
pub const MAX_GPU_MEM_REGIONS: usize = 64;
/// Maximum GPU memory regions (reduced for tests)
#[cfg(test)]
pub const MAX_GPU_MEM_REGIONS: usize = 4;

/// Maximum VMs with GPU memory
#[cfg(not(test))]
pub const MAX_GPU_MEM_VMS: usize = 128;
/// Maximum VMs with GPU memory (reduced for tests)
#[cfg(test)]
pub const MAX_GPU_MEM_VMS: usize = 4;

/// GPU page size (64KB)
pub const GPU_PAGE_SIZE: u64 = 64 * 1024;

/// Large GPU page size (2MB)
pub const GPU_LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum pages per region
#[cfg(not(test))]
pub const MAX_PAGES_PER_REGION: usize = 4096;
/// Maximum pages per region (reduced for tests)
#[cfg(test)]
pub const MAX_PAGES_PER_REGION: usize = 16;

/// Memory region types
pub mod region_type {
    pub const VRAM: u8 = 0;        // Video RAM
    pub const GDDR: u8 = 1;        // GDDR memory
    pub const HBM: u8 = 2;         // High Bandwidth Memory
    pub const SYSTEM: u8 = 3;      // System memory (pinned)
    pub const BAR: u8 = 4;         // PCI BAR memory
}

/// Memory region flags
pub mod region_flag {
    pub const READABLE: u32 = 1 << 0;
    pub const WRITABLE: u32 = 1 << 1;
    pub const EXECUTABLE: u32 = 1 << 2;
    pub const PINNED: u32 = 1 << 3;
    pub const MIGRATABLE: u32 = 1 << 4;
    pub const MAPPED: u32 = 1 << 5;
    pub const DIRTY: u32 = 1 << 6;
    pub const LARGE_PAGE: u32 = 1 << 7;
}

/// Page states
pub mod page_state {
    pub const FREE: u8 = 0;
    pub const ALLOCATED: u8 = 1;
    pub const MAPPED: u8 = 2;
    pub const DIRTY: u8 = 3;
    pub const MIGRATING: u8 = 4;
    pub const EVICTED: u8 = 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU Memory Page
// ─────────────────────────────────────────────────────────────────────────────

/// GPU memory page entry
pub struct GpuMemPage {
    /// Page index in region
    pub page_idx: AtomicU32,
    /// Guest GPU address
    pub gga: AtomicU64,
    /// Host GPU address (device address)
    pub hga: AtomicU64,
    /// System memory backing (if any)
    pub sys_addr: AtomicU64,
    /// State
    pub state: AtomicU8,
    /// Flags
    pub flags: AtomicU32,
    /// Reference count
    pub ref_count: AtomicU16,
    /// Last access timestamp
    pub last_access: AtomicU64,
    /// Access count
    pub access_count: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl GpuMemPage {
    pub const fn new() -> Self {
        Self {
            page_idx: AtomicU32::new(0),
            gga: AtomicU64::new(0),
            hga: AtomicU64::new(0),
            sys_addr: AtomicU64::new(0),
            state: AtomicU8::new(page_state::FREE),
            flags: AtomicU32::new(0),
            ref_count: AtomicU16::new(0),
            last_access: AtomicU64::new(0),
            access_count: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize page
    pub fn init(&self, page_idx: u32, gga: u64, hga: u64) {
        self.page_idx.store(page_idx, Ordering::Release);
        self.gga.store(gga, Ordering::Release);
        self.hga.store(hga, Ordering::Release);
        self.state.store(page_state::ALLOCATED, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Map to system memory
    pub fn map_sys(&self, sys_addr: u64) {
        self.sys_addr.store(sys_addr, Ordering::Release);
        self.state.store(page_state::MAPPED, Ordering::Release);
        self.flags.fetch_or(region_flag::MAPPED, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self, is_write: bool) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
        
        if is_write {
            self.state.store(page_state::DIRTY, Ordering::Release);
            self.flags.fetch_or(region_flag::DIRTY, Ordering::Release);
        }
    }

    /// Mark for migration
    pub fn start_migration(&self) {
        self.state.store(page_state::MIGRATING, Ordering::Release);
    }

    /// Complete migration
    pub fn complete_migration(&self, new_hga: u64) {
        self.hga.store(new_hga, Ordering::Release);
        self.state.store(page_state::MAPPED, Ordering::Release);
        self.flags.fetch_and(!region_flag::DIRTY, Ordering::Release);
    }

    /// Evict page
    pub fn evict(&self) {
        self.state.store(page_state::EVICTED, Ordering::Release);
    }

    /// Restore page
    pub fn restore(&self, new_hga: u64) {
        self.hga.store(new_hga, Ordering::Release);
        self.state.store(page_state::MAPPED, Ordering::Release);
    }

    /// Add reference
    pub fn add_ref(&self) -> u16 {
        self.ref_count.fetch_add(1, Ordering::Release)
    }

    /// Remove reference
    pub fn remove_ref(&self) -> u16 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for GpuMemPage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU Memory Region
// ─────────────────────────────────────────────────────────────────────────────

/// GPU memory region
pub struct GpuMemRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Region type
    pub region_type: AtomicU8,
    /// GPU ID
    pub gpu_id: AtomicU8,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Base guest GPU address
    pub gga_base: AtomicU64,
    /// Base host GPU address
    pub hga_base: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Flags
    pub flags: AtomicU32,
    /// Page count
    pub page_count: AtomicU32,
    /// Pages allocated
    pub pages_allocated: AtomicU32,
    /// Pages mapped
    pub pages_mapped: AtomicU32,
    /// Pages dirty
    pub pages_dirty: AtomicU32,
    /// Pages evicted
    pub pages_evicted: AtomicU32,
    /// Page table (simplified)
    pub pages: [GpuMemPage; MAX_PAGES_PER_REGION],
    /// Valid
    pub valid: AtomicBool,
}

impl GpuMemRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            region_type: AtomicU8::new(region_type::VRAM),
            gpu_id: AtomicU8::new(0),
            vm_id: AtomicU32::new(0),
            gga_base: AtomicU64::new(0),
            hga_base: AtomicU64::new(0),
            size: AtomicU64::new(0),
            flags: AtomicU32::new(region_flag::READABLE | region_flag::WRITABLE),
            page_count: AtomicU32::new(0),
            pages_allocated: AtomicU32::new(0),
            pages_mapped: AtomicU32::new(0),
            pages_dirty: AtomicU32::new(0),
            pages_evicted: AtomicU32::new(0),
            pages: [const { GpuMemPage::new() }; MAX_PAGES_PER_REGION],
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, region_type: u8, gpu_id: u8, 
                vm_id: u32, gga_base: u64, hga_base: u64, size: u64) {
        self.region_id.store(region_id, Ordering::Release);
        self.region_type.store(region_type, Ordering::Release);
        self.gpu_id.store(gpu_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.gga_base.store(gga_base, Ordering::Release);
        self.hga_base.store(hga_base, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.page_count.store((size / GPU_PAGE_SIZE) as u32, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Get page index for address
    pub fn get_page_idx(&self, gga: u64) -> Option<u32> {
        let base = self.gga_base.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        if gga < base || gga >= base + size {
            return None;
        }
        
        Some(((gga - base) / GPU_PAGE_SIZE) as u32)
    }

    /// Allocate page
    pub fn alloc_page(&self, page_idx: u32, hga: u64) -> Result<(), HvError> {
        if page_idx as usize >= MAX_PAGES_PER_REGION {
            return Err(HvError::LogicalFault);
        }
        
        let gga = self.gga_base.load(Ordering::Acquire) + (page_idx as u64 * GPU_PAGE_SIZE);
        
        self.pages[page_idx as usize].init(page_idx, gga, hga);
        self.pages_allocated.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Map page to system memory
    pub fn map_page(&self, page_idx: u32, sys_addr: u64) -> Result<(), HvError> {
        if page_idx as usize >= MAX_PAGES_PER_REGION {
            return Err(HvError::LogicalFault);
        }
        
        self.pages[page_idx as usize].map_sys(sys_addr);
        self.pages_mapped.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Get page by address
    pub fn get_page(&self, gga: u64) -> Option<&GpuMemPage> {
        let idx = self.get_page_idx(gga)?;
        let page = &self.pages[idx as usize];
        
        if page.valid.load(Ordering::Acquire) {
            Some(page)
        } else {
            None
        }
    }

    /// Translate GGA to HGA
    pub fn translate(&self, gga: u64) -> Option<u64> {
        let page = self.get_page(gga)?;
        
        let page_offset = gga % GPU_PAGE_SIZE;
        Some(page.hga.load(Ordering::Acquire) + page_offset)
    }

    /// Update statistics
    pub fn update_stats(&self) {
        let mut allocated = 0u32;
        let mut mapped = 0u32;
        let mut dirty = 0u32;
        let mut evicted = 0u32;
        
        for i in 0..self.page_count.load(Ordering::Acquire) as usize {
            let page = &self.pages[i];
            if !page.valid.load(Ordering::Acquire) {
                continue;
            }
            
            allocated += 1;
            
            match page.state.load(Ordering::Acquire) {
                page_state::MAPPED => mapped += 1,
                page_state::DIRTY => { mapped += 1; dirty += 1; }
                page_state::EVICTED => evicted += 1,
                _ => {}
            }
        }
        
        self.pages_allocated.store(allocated, Ordering::Release);
        self.pages_mapped.store(mapped, Ordering::Release);
        self.pages_dirty.store(dirty, Ordering::Release);
        self.pages_evicted.store(evicted, Ordering::Release);
    }
}

impl Default for GpuMemRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM GPU Memory State
// ─────────────────────────────────────────────────────────────────────────────

/// VM GPU memory state
pub struct VmGpuMemState {
    /// VM ID
    pub vm_id: AtomicU32,
    /// GPU ID
    pub gpu_id: AtomicU8,
    /// Memory regions
    pub regions: [GpuMemRegion; MAX_GPU_MEM_REGIONS],
    /// Region count
    pub region_count: AtomicU8,
    /// Total allocated memory
    pub total_allocated: AtomicU64,
    /// Total mapped memory
    pub total_mapped: AtomicU64,
    /// Total dirty memory
    pub total_dirty: AtomicU64,
    /// Quota
    pub quota: AtomicU64,
    /// Oversubscription ratio (x1000)
    pub oversub_ratio: AtomicU32,
    /// Migration in progress
    pub migrating: AtomicBool,
    /// Migration progress (0-100)
    pub migration_progress: AtomicU8,
    /// Valid
    pub valid: AtomicBool,
}

impl VmGpuMemState {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            gpu_id: AtomicU8::new(0),
            regions: [const { GpuMemRegion::new() }; MAX_GPU_MEM_REGIONS],
            region_count: AtomicU8::new(0),
            total_allocated: AtomicU64::new(0),
            total_mapped: AtomicU64::new(0),
            total_dirty: AtomicU64::new(0),
            quota: AtomicU64::new(0),
            oversub_ratio: AtomicU32::new(1000), // 1.0x
            migrating: AtomicBool::new(false),
            migration_progress: AtomicU8::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize VM state
    pub fn init(&self, vm_id: u32, gpu_id: u8, quota: u64) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.gpu_id.store(gpu_id, Ordering::Release);
        self.quota.store(quota, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add region
    pub fn add_region(&self, region_type: u8, gga_base: u64, 
                      hga_base: u64, size: u64) -> Result<u8, HvError> {
        let count = self.region_count.load(Ordering::Acquire);
        if count as usize >= MAX_GPU_MEM_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.regions[count as usize].init(
            count, region_type, self.gpu_id.load(Ordering::Acquire),
            self.vm_id.load(Ordering::Acquire), gga_base, hga_base, size
        );
        
        self.region_count.fetch_add(1, Ordering::Release);
        self.total_allocated.fetch_add(size, Ordering::Release);
        
        Ok(count)
    }

    /// Get region
    pub fn get_region(&self, region_id: u8) -> Option<&GpuMemRegion> {
        if region_id as usize >= MAX_GPU_MEM_REGIONS {
            return None;
        }
        
        let region = &self.regions[region_id as usize];
        if region.valid.load(Ordering::Acquire) {
            Some(region)
        } else {
            None
        }
    }

    /// Find region for address
    pub fn find_region(&self, gga: u64) -> Option<&GpuMemRegion> {
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            if region.valid.load(Ordering::Acquire) {
                let base = region.gga_base.load(Ordering::Acquire);
                let size = region.size.load(Ordering::Acquire);
                
                if gga >= base && gga < base + size {
                    return Some(region);
                }
            }
        }
        None
    }

    /// Translate address
    pub fn translate(&self, gga: u64) -> Option<u64> {
        let region = self.find_region(gga)?;
        region.translate(gga)
    }

    /// Update statistics
    pub fn update_stats(&self) {
        let mut allocated = 0u64;
        let mut mapped = 0u64;
        let mut dirty = 0u64;
        
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            if region.valid.load(Ordering::Acquire) {
                region.update_stats();
                
                allocated += region.size.load(Ordering::Acquire);
                mapped += region.pages_mapped.load(Ordering::Acquire) as u64 * GPU_PAGE_SIZE;
                dirty += region.pages_dirty.load(Ordering::Acquire) as u64 * GPU_PAGE_SIZE;
            }
        }
        
        self.total_allocated.store(allocated, Ordering::Release);
        self.total_mapped.store(mapped, Ordering::Release);
        self.total_dirty.store(dirty, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> VmGpuMemStats {
        VmGpuMemStats {
            vm_id: self.vm_id.load(Ordering::Acquire),
            gpu_id: self.gpu_id.load(Ordering::Acquire),
            region_count: self.region_count.load(Ordering::Acquire),
            total_allocated: self.total_allocated.load(Ordering::Acquire),
            total_mapped: self.total_mapped.load(Ordering::Acquire),
            total_dirty: self.total_dirty.load(Ordering::Acquire),
            quota: self.quota.load(Ordering::Acquire),
            oversub_ratio: self.oversub_ratio.load(Ordering::Acquire),
        }
    }
}

impl Default for VmGpuMemState {
    fn default() -> Self {
        Self::new()
    }
}

/// VM GPU memory statistics
#[repr(C)]
pub struct VmGpuMemStats {
    pub vm_id: u32,
    pub gpu_id: u8,
    pub region_count: u8,
    pub total_allocated: u64,
    pub total_mapped: u64,
    pub total_dirty: u64,
    pub quota: u64,
    pub oversub_ratio: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU Memory Controller
// ─────────────────────────────────────────────────────────────────────────────

/// GPU memory controller
pub struct GpuMemController {
    /// VM states
    pub vm_states: [VmGpuMemState; MAX_GPU_MEM_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Oversubscription enabled
    pub oversub_enabled: AtomicBool,
    /// Max oversubscription ratio (x1000)
    pub max_oversub_ratio: AtomicU32,
    /// Migration enabled
    pub migration_enabled: AtomicBool,
    /// Migration bandwidth (MB/s)
    pub migration_bw: AtomicU32,
    /// Eviction enabled
    pub eviction_enabled: AtomicBool,
    /// Eviction threshold (0-100)
    pub eviction_threshold: AtomicU8,
    /// Total GPU memory
    pub total_gpu_memory: AtomicU64,
    /// Used GPU memory
    pub used_gpu_memory: AtomicU64,
    /// Total migrations
    pub total_migrations: AtomicU64,
    /// Total eviction count
    pub total_evictions: AtomicU64,
    /// Total pages migrated
    pub total_pages_migrated: AtomicU64,
    /// Total bytes migrated
    pub total_bytes_migrated: AtomicU64,
}

impl GpuMemController {
    pub const fn new() -> Self {
        Self {
            vm_states: [const { VmGpuMemState::new() }; MAX_GPU_MEM_VMS],
            vm_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            oversub_enabled: AtomicBool::new(true),
            max_oversub_ratio: AtomicU32::new(2000), // 2.0x
            migration_enabled: AtomicBool::new(true),
            migration_bw: AtomicU32::new(10000), // 10 GB/s
            eviction_enabled: AtomicBool::new(true),
            eviction_threshold: AtomicU8::new(80),
            total_gpu_memory: AtomicU64::new(0),
            used_gpu_memory: AtomicU64::new(0),
            total_migrations: AtomicU64::new(0),
            total_evictions: AtomicU64::new(0),
            total_pages_migrated: AtomicU64::new(0),
            total_bytes_migrated: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, total_memory: u64, oversub: bool, 
                  migration: bool, eviction: bool) {
        self.total_gpu_memory.store(total_memory, Ordering::Release);
        self.oversub_enabled.store(oversub, Ordering::Release);
        self.migration_enabled.store(migration, Ordering::Release);
        self.eviction_enabled.store(eviction, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM
    pub fn register_vm(&mut self, vm_id: u32, gpu_id: u8, 
                       quota: u64, oversub_ratio: u32) -> Result<u8, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_GPU_MEM_VMS {
            return Err(HvError::LogicalFault);
        }
        
        // Check oversubscription
        if oversub_ratio > self.max_oversub_ratio.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let vm_state = &self.vm_states[count as usize];
        vm_state.init(vm_id, gpu_id, quota);
        vm_state.oversub_ratio.store(oversub_ratio, Ordering::Release);
        
        self.vm_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Get VM state
    pub fn get_vm_state(&self, vm_id: u32) -> Option<&VmGpuMemState> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_states[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_states[i]);
            }
        }
        None
    }

    /// Add memory region
    pub fn add_region(&self, vm_id: u32, region_type: u8, 
                      gga_base: u64, hga_base: u64, size: u64) -> Result<u8, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        
        // Check quota
        let current = vm_state.total_allocated.load(Ordering::Acquire);
        let quota = vm_state.quota.load(Ordering::Acquire);
        let oversub = vm_state.oversub_ratio.load(Ordering::Acquire);
        let effective_quota = quota * oversub as u64 / 1000;
        
        if current + size > effective_quota {
            return Err(HvError::LogicalFault);
        }
        
        let region_id = vm_state.add_region(region_type, gga_base, hga_base, size)?;
        
        self.used_gpu_memory.fetch_add(size, Ordering::Release);
        
        Ok(region_id)
    }

    /// Translate address
    pub fn translate(&self, vm_id: u32, gga: u64) -> Option<u64> {
        let vm_state = self.get_vm_state(vm_id)?;
        vm_state.translate(gga)
    }

    /// Handle memory access
    pub fn handle_access(&self, vm_id: u32, gga: u64, is_write: bool) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        let region = vm_state.find_region(gga).ok_or(HvError::LogicalFault)?;
        let page = region.get_page(gga).ok_or(HvError::LogicalFault)?;
        
        page.record_access(is_write);
        
        Ok(())
    }

    /// Migrate page
    pub fn migrate_page(&self, vm_id: u32, gga: u64, 
                        new_hga: u64) -> Result<(), HvError> {
        if !self.migration_enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        let region = vm_state.find_region(gga).ok_or(HvError::LogicalFault)?;
        let page = region.get_page(gga).ok_or(HvError::LogicalFault)?;
        
        page.start_migration();
        
        // Would perform actual DMA migration here
        page.complete_migration(new_hga);
        
        self.total_pages_migrated.fetch_add(1, Ordering::Release);
        self.total_bytes_migrated.fetch_add(GPU_PAGE_SIZE, Ordering::Release);
        
        Ok(())
    }

    /// Evict pages (LRU)
    pub fn evict_pages(&self, vm_id: u32, count: u32) -> Result<u32, HvError> {
        if !self.eviction_enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        
        // Find LRU pages
        let mut evicted = 0u32;
        
        for i in 0..vm_state.region_count.load(Ordering::Acquire) as usize {
            if evicted >= count {
                break;
            }
            
            let region = &vm_state.regions[i];
            if !region.valid.load(Ordering::Acquire) {
                continue;
            }
            
            // Find oldest pages
            for j in 0..region.page_count.load(Ordering::Acquire) as usize {
                if evicted >= count {
                    break;
                }
                
                let page = &region.pages[j];
                if page.valid.load(Ordering::Acquire) &&
                   page.state.load(Ordering::Acquire) != page_state::EVICTED &&
                   page.state.load(Ordering::Acquire) != page_state::DIRTY {
                    page.evict();
                    evicted += 1;
                }
            }
        }
        
        self.total_evictions.fetch_add(evicted as u64, Ordering::Release);
        self.used_gpu_memory.fetch_sub(evicted as u64 * GPU_PAGE_SIZE, Ordering::Release);
        
        Ok(evicted)
    }

    /// Check memory pressure
    pub fn check_pressure(&self) -> u8 {
        let total = self.total_gpu_memory.load(Ordering::Acquire);
        let used = self.used_gpu_memory.load(Ordering::Acquire);
        
        if total == 0 {
            return 0;
        }
        
        ((used * 100) / total) as u8
    }

    /// Run memory management
    pub fn run_memory_mgmt(&mut self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let pressure = self.check_pressure();
        let threshold = self.eviction_threshold.load(Ordering::Acquire);
        
        if pressure < threshold {
            return 0;
        }
        
        // Need to evict memory
        let target_pressure = threshold - 10;
        let total = self.total_gpu_memory.load(Ordering::Acquire);
        let target_used = total * target_pressure as u64 / 100;
        let current_used = self.used_gpu_memory.load(Ordering::Acquire);
        
        let bytes_to_evict = current_used.saturating_sub(target_used);
        let pages_to_evict = (bytes_to_evict / GPU_PAGE_SIZE) as u32;
        
        // Evict from VMs (round-robin)
        let mut evicted = 0u32;
        let vm_count = self.vm_count.load(Ordering::Acquire);
        
        if vm_count == 0 {
            return 0;
        }
        
        let per_vm = pages_to_evict / vm_count as u32;
        
        for i in 0..vm_count as usize {
            let vm_id = self.vm_states[i].vm_id.load(Ordering::Acquire);
            if let Ok(count) = self.evict_pages(vm_id, per_vm) {
                evicted += count;
            }
        }
        
        evicted
    }

    /// Get statistics
    pub fn get_stats(&self) -> GpuMemControllerStats {
        GpuMemControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            total_gpu_memory: self.total_gpu_memory.load(Ordering::Acquire),
            used_gpu_memory: self.used_gpu_memory.load(Ordering::Acquire),
            pressure: self.check_pressure(),
            oversub_enabled: self.oversub_enabled.load(Ordering::Acquire),
            migration_enabled: self.migration_enabled.load(Ordering::Acquire),
            eviction_enabled: self.eviction_enabled.load(Ordering::Acquire),
            total_migrations: self.total_migrations.load(Ordering::Acquire),
            total_evictions: self.total_evictions.load(Ordering::Acquire),
            total_pages_migrated: self.total_pages_migrated.load(Ordering::Acquire),
            total_bytes_migrated: self.total_bytes_migrated.load(Ordering::Acquire),
        }
    }
}

impl Default for GpuMemController {
    fn default() -> Self {
        Self::new()
    }
}

/// GPU memory controller statistics
#[repr(C)]
pub struct GpuMemControllerStats {
    pub enabled: bool,
    pub vm_count: u8,
    pub total_gpu_memory: u64,
    pub used_gpu_memory: u64,
    pub pressure: u8,
    pub oversub_enabled: bool,
    pub migration_enabled: bool,
    pub eviction_enabled: bool,
    pub total_migrations: u64,
    pub total_evictions: u64,
    pub total_pages_migrated: u64,
    pub total_bytes_migrated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vm() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        
        let idx = ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn add_region() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        
        let region_id = ctrl.add_region(1, region_type::VRAM, 
                                         0x100000000, 0x200000000, 
                                         4 * 1024 * 1024 * 1024).unwrap();
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.region_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn translate_address() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        ctrl.add_region(1, region_type::VRAM, 0x100000000, 0x200000000, 
                        4 * 1024 * 1024 * 1024).unwrap();
        
        // Allocate a page
        let vm = ctrl.get_vm_state(1).unwrap();
        let region = vm.get_region(0).unwrap();
        region.alloc_page(0, 0x200000000).unwrap();
        
        let hga = ctrl.translate(1, 0x100000000).unwrap();
        assert_eq!(hga, 0x200000000);
    }

    #[test]
    fn memory_pressure() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        
        let pressure = ctrl.check_pressure();
        assert_eq!(pressure, 0);
        
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        // Use smaller region size to ensure it fits (effective quota = 10GB * 1.5 = 15GB)
        ctrl.add_region(1, region_type::VRAM, 0x100000000, 0x200000000, 
                        4 * 1024 * 1024 * 1024).unwrap();
        
        let pressure = ctrl.check_pressure();
        assert!(pressure > 0);
    }

    #[test]
    fn oversubscription() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 2000).unwrap(); // 2x oversub
        
        // Should allow up to 20GB with 10GB quota and 2x oversub
        let result = ctrl.add_region(1, region_type::VRAM, 0x100000000, 0x200000000, 
                                      20 * 1024 * 1024 * 1024);
        assert!(result.is_ok());
    }

    #[test]
    fn page_eviction() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        ctrl.add_region(1, region_type::VRAM, 0x100000000, 0x200000000, 
                        256 * 1024 * 1024).unwrap(); // 256MB
        
        // Allocate pages (limited to MAX_PAGES_PER_REGION which is 16 in tests)
        let vm = ctrl.get_vm_state(1).unwrap();
        let region = vm.get_region(0).unwrap();
        for i in 0..10 {
            region.alloc_page(i, 0x200000000 + i as u64 * GPU_PAGE_SIZE).unwrap();
        }
        
        // Evict some pages
        let evicted = ctrl.evict_pages(1, 5).unwrap();
        assert!(evicted > 0);
    }

    #[test]
    fn page_migration() {
        let mut ctrl = GpuMemController::new();
        ctrl.enable(40 * 1024 * 1024 * 1024, true, true, true);
        ctrl.register_vm(1, 0, 10 * 1024 * 1024 * 1024, 1500).unwrap();
        ctrl.add_region(1, region_type::VRAM, 0x100000000, 0x200000000, 
                        256 * 1024 * 1024).unwrap();
        
        let vm = ctrl.get_vm_state(1).unwrap();
        let region = vm.get_region(0).unwrap();
        region.alloc_page(0, 0x200000000).unwrap();
        
        // Migrate page
        ctrl.migrate_page(1, 0x100000000, 0x300000000).unwrap();
        
        let hga = ctrl.translate(1, 0x100000000).unwrap();
        assert_eq!(hga, 0x300000000);
    }
}
