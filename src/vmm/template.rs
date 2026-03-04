//! VM Template/Cloning - COW Memory Fork
//!
//! Fast VM cloning with copy-on-write memory sharing for efficient template-based provisioning.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Template Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum templates
#[cfg(not(test))]
pub const MAX_TEMPLATES: usize = 64;
/// Maximum templates (reduced for tests)
#[cfg(test)]
pub const MAX_TEMPLATES: usize = 1;

/// Maximum clones per template
#[cfg(not(test))]
pub const MAX_CLONES_PER_TEMPLATE: usize = 256;
/// Maximum clones per template (reduced for tests)
#[cfg(test)]
pub const MAX_CLONES_PER_TEMPLATE: usize = 2;

/// Maximum total clones
#[cfg(not(test))]
pub const MAX_TOTAL_CLONES: usize = 4096;
/// Maximum total clones (reduced for tests)
#[cfg(test)]
pub const MAX_TOTAL_CLONES: usize = 4;

/// Maximum memory regions per template
#[cfg(not(test))]
pub const MAX_TEMPLATE_REGIONS: usize = 32;
/// Maximum memory regions per template (reduced for tests)
#[cfg(test)]
pub const MAX_TEMPLATE_REGIONS: usize = 2;

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// Template states
pub mod template_state {
    pub const CREATING: u8 = 0;
    pub const READY: u8 = 1;
    pub const ACTIVE: u8 = 2;
    pub const FROZEN: u8 = 3;
    pub const DELETING: u8 = 4;
}

/// Clone states
pub mod clone_state {
    pub const CREATING: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const PAUSED: u8 = 3;
    pub const STOPPED: u8 = 4;
    pub const DELETING: u8 = 5;
}

/// Region flags
pub mod region_flag {
    pub const COW: u32 = 1 << 0;
    pub const SHARED: u32 = 1 << 1;
    pub const PRIVATE: u32 = 1 << 2;
    pub const READ_ONLY: u32 = 1 << 3;
    pub const DIRTY: u32 = 1 << 4;
}

// ─────────────────────────────────────────────────────────────────────────────
// COW Page Entry
// ─────────────────────────────────────────────────────────────────────────────

/// COW page entry for tracking shared pages
pub struct CowPage {
    /// Page GPA in template
    pub gpa: AtomicU64,
    /// Page HPA (shared)
    pub hpa: AtomicU64,
    /// Reference count
    pub ref_count: AtomicU16,
    /// Flags
    pub flags: AtomicU32,
    /// Clone that owns private copy (if any)
    pub private_owner: AtomicU32,
    /// Private HPA (if COW broken)
    pub private_hpa: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CowPage {
    pub const fn new() -> Self {
        Self {
            gpa: AtomicU64::new(0),
            hpa: AtomicU64::new(0),
            ref_count: AtomicU16::new(0),
            flags: AtomicU32::new(region_flag::COW),
            private_owner: AtomicU32::new(0),
            private_hpa: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize COW page
    pub fn init(&self, gpa: u64, hpa: u64) {
        self.gpa.store(gpa, Ordering::Release);
        self.hpa.store(hpa, Ordering::Release);
        self.ref_count.store(1, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add reference
    pub fn add_ref(&self) -> u16 {
        self.ref_count.fetch_add(1, Ordering::Release)
    }

    /// Remove reference
    pub fn remove_ref(&self) -> u16 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }

    /// Get reference count
    pub fn get_ref_count(&self) -> u16 {
        self.ref_count.load(Ordering::Acquire)
    }

    /// Is COW (shared)
    pub fn is_cow(&self) -> bool {
        self.flags.load(Ordering::Acquire) & region_flag::COW != 0 &&
        self.private_hpa.load(Ordering::Acquire) == 0
    }

    /// Break COW (create private copy)
    pub fn break_cow(&self, owner: u32, private_hpa: u64) {
        self.private_owner.store(owner, Ordering::Release);
        self.private_hpa.store(private_hpa, Ordering::Release);
        self.flags.fetch_and(!region_flag::COW, Ordering::Release);
    }

    /// Get effective HPA for clone
    pub fn get_hpa_for_clone(&self, clone_id: u32) -> u64 {
        // If this clone owns private copy, use it
        if self.private_owner.load(Ordering::Acquire) == clone_id {
            self.private_hpa.load(Ordering::Acquire)
        } else {
            // Use shared HPA
            self.hpa.load(Ordering::Acquire)
        }
    }
}

impl Default for CowPage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Region
// ─────────────────────────────────────────────────────────────────────────────

/// Memory region for template/clone
pub struct MemRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Start GPA
    pub gpa_start: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Flags
    pub flags: AtomicU32,
    /// Page count
    pub page_count: AtomicU32,
    /// COW pages (indexed by page offset)
    pub cow_pages: [CowPage; 4096], // Max 16MB per region (4096 * 4KB)
    /// Valid
    pub valid: AtomicBool,
}

impl MemRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            gpa_start: AtomicU64::new(0),
            size: AtomicU64::new(0),
            flags: AtomicU32::new(region_flag::COW),
            page_count: AtomicU32::new(0),
            cow_pages: [const { CowPage::new() }; 4096],
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, gpa_start: u64, size: u64, flags: u32) {
        self.region_id.store(region_id, Ordering::Release);
        self.gpa_start.store(gpa_start, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.flags.store(flags, Ordering::Release);
        self.page_count.store((size / PAGE_SIZE) as u32, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Get page index for GPA
    pub fn get_page_idx(&self, gpa: u64) -> Option<u32> {
        let start = self.gpa_start.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        if gpa < start || gpa >= start + size {
            return None;
        }
        
        Some(((gpa - start) / PAGE_SIZE) as u32)
    }

    /// Get COW page
    pub fn get_cow_page(&self, page_idx: u32) -> Option<&CowPage> {
        if page_idx as usize >= 4096 {
            return None;
        }
        
        let page = &self.cow_pages[page_idx as usize];
        if page.valid.load(Ordering::Acquire) {
            Some(page)
        } else {
            None
        }
    }

    /// Initialize COW page
    pub fn init_cow_page(&self, page_idx: u32, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if page_idx as usize >= 4096 {
            return Err(HvError::LogicalFault);
        }
        
        self.cow_pages[page_idx as usize].init(gpa, hpa);
        Ok(())
    }
}

impl Default for MemRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM Template
// ─────────────────────────────────────────────────────────────────────────────

/// VM template for cloning
pub struct VmTemplate {
    /// Template ID
    pub template_id: AtomicU32,
    /// Template name hash
    pub name_hash: AtomicU64,
    /// State
    pub state: AtomicU8,
    /// Source VM ID
    pub source_vm_id: AtomicU32,
    /// Memory regions
    pub regions: [MemRegion; MAX_TEMPLATE_REGIONS],
    /// Region count
    pub region_count: AtomicU8,
    /// Total memory size
    pub total_memory: AtomicU64,
    /// vCPU count
    pub vcpu_count: AtomicU8,
    /// Clone count
    pub clone_count: AtomicU16,
    /// Max clones
    pub max_clones: AtomicU16,
    /// Shared pages
    pub shared_pages: AtomicU64,
    /// Private pages (COW broken)
    pub private_pages: AtomicU64,
    /// Memory saved (bytes)
    pub memory_saved: AtomicU64,
    /// Creation time
    pub creation_time: AtomicU64,
    /// Last clone time
    pub last_clone_time: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmTemplate {
    pub const fn new() -> Self {
        Self {
            template_id: AtomicU32::new(0),
            name_hash: AtomicU64::new(0),
            state: AtomicU8::new(template_state::CREATING),
            source_vm_id: AtomicU32::new(0),
            regions: [const { MemRegion::new() }; MAX_TEMPLATE_REGIONS],
            region_count: AtomicU8::new(0),
            total_memory: AtomicU64::new(0),
            vcpu_count: AtomicU8::new(0),
            clone_count: AtomicU16::new(0),
            max_clones: AtomicU16::new(MAX_CLONES_PER_TEMPLATE as u16),
            shared_pages: AtomicU64::new(0),
            private_pages: AtomicU64::new(0),
            memory_saved: AtomicU64::new(0),
            creation_time: AtomicU64::new(0),
            last_clone_time: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize template
    pub fn init(&self, template_id: u32, name_hash: u64, source_vm_id: u32, vcpu_count: u8) {
        self.template_id.store(template_id, Ordering::Release);
        self.name_hash.store(name_hash, Ordering::Release);
        self.source_vm_id.store(source_vm_id, Ordering::Release);
        self.vcpu_count.store(vcpu_count, Ordering::Release);
        self.creation_time.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add memory region
    pub fn add_region(&self, gpa_start: u64, size: u64, flags: u32) -> Result<u8, HvError> {
        let count = self.region_count.load(Ordering::Acquire);
        if count as usize >= MAX_TEMPLATE_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.regions[count as usize].init(count, gpa_start, size, flags);
        self.region_count.fetch_add(1, Ordering::Release);
        self.total_memory.fetch_add(size, Ordering::Release);
        
        Ok(count)
    }

    /// Initialize COW pages for region
    pub fn init_region_pages(&self, region_idx: u8, hpas: &[u64]) -> Result<(), HvError> {
        if region_idx as usize >= MAX_TEMPLATE_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        let region = &self.regions[region_idx as usize];
        let gpa_start = region.gpa_start.load(Ordering::Acquire);
        
        for (i, &hpa) in hpas.iter().enumerate() {
            if i >= 4096 {
                break;
            }
            let gpa = gpa_start + (i as u64 * PAGE_SIZE);
            region.init_cow_page(i as u32, gpa, hpa)?;
            self.shared_pages.fetch_add(1, Ordering::Release);
        }
        
        Ok(())
    }

    /// Mark as ready
    pub fn set_ready(&self) {
        self.state.store(template_state::READY, Ordering::Release);
    }

    /// Mark as active
    pub fn set_active(&self) {
        self.state.store(template_state::ACTIVE, Ordering::Release);
    }

    /// Freeze template (no new clones)
    pub fn freeze(&self) {
        self.state.store(template_state::FROZEN, Ordering::Release);
    }

    /// Increment clone count
    pub fn inc_clone_count(&self) -> Result<(), HvError> {
        let count = self.clone_count.load(Ordering::Acquire);
        if count >= self.max_clones.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.clone_count.fetch_add(1, Ordering::Release);
        self.last_clone_time.store(Self::get_timestamp(), Ordering::Release);
        Ok(())
    }

    /// Decrement clone count
    pub fn dec_clone_count(&self) {
        self.clone_count.fetch_sub(1, Ordering::Release);
    }

    /// Record COW break
    pub fn record_cow_break(&self) {
        self.shared_pages.fetch_sub(1, Ordering::Release);
        self.private_pages.fetch_add(1, Ordering::Release);
    }

    /// Record COW restore
    pub fn record_cow_restore(&self) {
        self.private_pages.fetch_sub(1, Ordering::Release);
        self.shared_pages.fetch_add(1, Ordering::Release);
        self.memory_saved.fetch_add(PAGE_SIZE, Ordering::Release);
    }

    /// Get memory savings percentage
    pub fn get_savings_pct(&self) -> u32 {
        let shared = self.shared_pages.load(Ordering::Acquire);
        let private = self.private_pages.load(Ordering::Acquire);
        let total = shared + private;
        
        if total == 0 {
            return 0;
        }
        
        ((shared * 100) / total) as u32
    }

    /// Get statistics
    pub fn get_stats(&self) -> TemplateStats {
        TemplateStats {
            template_id: self.template_id.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            region_count: self.region_count.load(Ordering::Acquire),
            total_memory: self.total_memory.load(Ordering::Acquire),
            vcpu_count: self.vcpu_count.load(Ordering::Acquire),
            clone_count: self.clone_count.load(Ordering::Acquire),
            shared_pages: self.shared_pages.load(Ordering::Acquire),
            private_pages: self.private_pages.load(Ordering::Acquire),
            savings_pct: self.get_savings_pct(),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VmTemplate {
    fn default() -> Self {
        Self::new()
    }
}

/// Template statistics
#[repr(C)]
pub struct TemplateStats {
    pub template_id: u32,
    pub state: u8,
    pub region_count: u8,
    pub total_memory: u64,
    pub vcpu_count: u8,
    pub clone_count: u16,
    pub shared_pages: u64,
    pub private_pages: u64,
    pub savings_pct: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// VM Clone
// ─────────────────────────────────────────────────────────────────────────────

/// VM clone instance
pub struct VmClone {
    /// Clone ID
    pub clone_id: AtomicU32,
    /// Template ID
    pub template_id: AtomicU32,
    /// VM ID (actual running VM)
    pub vm_id: AtomicU32,
    /// State
    pub state: AtomicU8,
    /// Private pages count
    pub private_pages: AtomicU64,
    /// Private memory allocated
    pub private_memory: AtomicU64,
    /// Creation time
    pub creation_time: AtomicU64,
    /// Start time
    pub start_time: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmClone {
    pub const fn new() -> Self {
        Self {
            clone_id: AtomicU32::new(0),
            template_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            state: AtomicU8::new(clone_state::CREATING),
            private_pages: AtomicU64::new(0),
            private_memory: AtomicU64::new(0),
            creation_time: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize clone
    pub fn init(&self, clone_id: u32, template_id: u32, vm_id: u32) {
        self.clone_id.store(clone_id, Ordering::Release);
        self.template_id.store(template_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.creation_time.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set state
    pub fn set_state(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    /// Record private page
    pub fn add_private_page(&self) {
        self.private_pages.fetch_add(1, Ordering::Release);
        self.private_memory.fetch_add(PAGE_SIZE, Ordering::Release);
    }

    /// Remove private page
    pub fn remove_private_page(&self) {
        self.private_pages.fetch_sub(1, Ordering::Release);
        self.private_memory.fetch_sub(PAGE_SIZE, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> CloneStats {
        CloneStats {
            clone_id: self.clone_id.load(Ordering::Acquire),
            template_id: self.template_id.load(Ordering::Acquire),
            vm_id: self.vm_id.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            private_pages: self.private_pages.load(Ordering::Acquire),
            private_memory: self.private_memory.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VmClone {
    fn default() -> Self {
        Self::new()
    }
}

/// Clone statistics
#[repr(C)]
pub struct CloneStats {
    pub clone_id: u32,
    pub template_id: u32,
    pub vm_id: u32,
    pub state: u8,
    pub private_pages: u64,
    pub private_memory: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Template/Clone Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Template/Clone controller
pub struct TemplateController {
    /// Templates
    pub templates: [VmTemplate; MAX_TEMPLATES],
    /// Template count
    pub template_count: AtomicU8,
    /// Clones
    pub clones: [VmClone; MAX_TOTAL_CLONES],
    /// Clone count
    pub clone_count: AtomicU16,
    /// Next template ID
    pub next_template_id: AtomicU32,
    /// Next clone ID
    pub next_clone_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Auto-freeze threshold (clones)
    pub auto_freeze_threshold: AtomicU16,
    /// Max total memory for templates
    pub max_template_memory: AtomicU64,
    /// Current template memory
    pub current_template_memory: AtomicU64,
    /// Total templates created
    pub total_templates: AtomicU64,
    /// Total clones created
    pub total_clones: AtomicU64,
    /// Total memory saved
    pub total_memory_saved: AtomicU64,
    /// Total COW breaks
    pub total_cow_breaks: AtomicU64,
}

impl TemplateController {
    pub const fn new() -> Self {
        Self {
            templates: [const { VmTemplate::new() }; MAX_TEMPLATES],
            template_count: AtomicU8::new(0),
            clones: [const { VmClone::new() }; MAX_TOTAL_CLONES],
            clone_count: AtomicU16::new(0),
            next_template_id: AtomicU32::new(1),
            next_clone_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            auto_freeze_threshold: AtomicU16::new(200),
            max_template_memory: AtomicU64::new(16 * 1024 * 1024 * 1024), // 16GB
            current_template_memory: AtomicU64::new(0),
            total_templates: AtomicU64::new(0),
            total_clones: AtomicU64::new(0),
            total_memory_saved: AtomicU64::new(0),
            total_cow_breaks: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, auto_freeze: u16, max_memory: u64) {
        self.auto_freeze_threshold.store(auto_freeze, Ordering::Release);
        self.max_template_memory.store(max_memory, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Create template from VM
    pub fn create_template(&mut self, name_hash: u64, source_vm_id: u32, 
                            vcpu_count: u8, regions: &[(u64, u64, u32)]) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.template_count.load(Ordering::Acquire);
        if count as usize >= MAX_TEMPLATES {
            return Err(HvError::LogicalFault);
        }
        
        let template_id = self.next_template_id.fetch_add(1, Ordering::Release);
        let template = &self.templates[count as usize];
        template.init(template_id, name_hash, source_vm_id, vcpu_count);
        
        // Add regions
        for &(gpa_start, size, flags) in regions {
            template.add_region(gpa_start, size, flags)?;
        }
        
        self.template_count.fetch_add(1, Ordering::Release);
        self.total_templates.fetch_add(1, Ordering::Release);
        
        Ok(template_id)
    }

    /// Initialize template pages
    pub fn init_template_pages(&self, template_id: u32, region_idx: u8, 
                                hpas: &[u64]) -> Result<(), HvError> {
        let template = self.get_template(template_id).ok_or(HvError::LogicalFault)?;
        template.init_region_pages(region_idx, hpas)
    }

    /// Finalize template
    pub fn finalize_template(&self, template_id: u32) -> Result<(), HvError> {
        let template = self.get_template(template_id).ok_or(HvError::LogicalFault)?;
        template.set_ready();
        Ok(())
    }

    /// Get template
    pub fn get_template(&self, template_id: u32) -> Option<&VmTemplate> {
        for i in 0..self.template_count.load(Ordering::Acquire) as usize {
            if self.templates[i].template_id.load(Ordering::Acquire) == template_id {
                return Some(&self.templates[i]);
            }
        }
        None
    }

    /// Create clone from template
    pub fn create_clone(&mut self, template_id: u32, vm_id: u32) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let template = self.get_template(template_id).ok_or(HvError::LogicalFault)?;
        
        // Check template state
        let state = template.state.load(Ordering::Acquire);
        if state != template_state::READY && state != template_state::ACTIVE {
            return Err(HvError::LogicalFault);
        }
        
        // Check clone limit
        let clone_count = self.clone_count.load(Ordering::Acquire);
        if clone_count as usize >= MAX_TOTAL_CLONES {
            return Err(HvError::LogicalFault);
        }
        
        // Increment template clone count
        template.inc_clone_count()?;
        
        // Auto-freeze if threshold reached
        if template.clone_count.load(Ordering::Acquire) >= self.auto_freeze_threshold.load(Ordering::Acquire) {
            template.freeze();
        }
        
        // Create clone
        let clone_id = self.next_clone_id.fetch_add(1, Ordering::Release);
        let clone = &self.clones[clone_count as usize];
        clone.init(clone_id, template_id, vm_id);
        clone.set_state(clone_state::READY);
        
        // Mark template as active
        template.set_active();
        
        self.clone_count.fetch_add(1, Ordering::Release);
        self.total_clones.fetch_add(1, Ordering::Release);
        
        Ok(clone_id)
    }

    /// Get clone
    pub fn get_clone(&self, clone_id: u32) -> Option<&VmClone> {
        for i in 0..self.clone_count.load(Ordering::Acquire) as usize {
            if self.clones[i].clone_id.load(Ordering::Acquire) == clone_id {
                return Some(&self.clones[i]);
            }
        }
        None
    }

    /// Handle COW fault
    pub fn handle_cow_fault(&self, clone_id: u32, gpa: u64, 
                            new_hpa: u64) -> Result<(), HvError> {
        let clone = self.get_clone(clone_id).ok_or(HvError::LogicalFault)?;
        let template = self.get_template(clone.template_id.load(Ordering::Acquire))
            .ok_or(HvError::LogicalFault)?;
        
        // Find region and page
        for i in 0..template.region_count.load(Ordering::Acquire) as usize {
            let region = &template.regions[i];
            
            if let Some(page_idx) = region.get_page_idx(gpa) {
                if let Some(cow_page) = region.get_cow_page(page_idx) {
                    // Break COW
                    cow_page.break_cow(clone_id, new_hpa);
                    
                    // Update stats
                    clone.add_private_page();
                    template.record_cow_break();
                    self.total_cow_breaks.fetch_add(1, Ordering::Release);
                    
                    return Ok(());
                }
            }
        }
        
        Err(HvError::LogicalFault)
    }

    /// Get HPA for clone
    pub fn get_hpa_for_clone(&self, clone_id: u32, gpa: u64) -> Option<u64> {
        let clone = self.get_clone(clone_id)?;
        let template = self.get_template(clone.template_id.load(Ordering::Acquire))?;
        
        for i in 0..template.region_count.load(Ordering::Acquire) as usize {
            let region = &template.regions[i];
            
            if let Some(page_idx) = region.get_page_idx(gpa) {
                if let Some(cow_page) = region.get_cow_page(page_idx) {
                    return Some(cow_page.get_hpa_for_clone(clone_id));
                }
            }
        }
        
        None
    }

    /// Start clone
    pub fn start_clone(&self, clone_id: u32) -> Result<(), HvError> {
        let clone = self.get_clone(clone_id).ok_or(HvError::LogicalFault)?;
        clone.set_state(clone_state::RUNNING);
        clone.start_time.store(Self::get_timestamp(), Ordering::Release);
        Ok(())
    }

    /// Stop clone
    pub fn stop_clone(&self, clone_id: u32) -> Result<(), HvError> {
        let clone = self.get_clone(clone_id).ok_or(HvError::LogicalFault)?;
        clone.set_state(clone_state::STOPPED);
        Ok(())
    }

    /// Delete clone
    pub fn delete_clone(&mut self, clone_id: u32) -> Result<(), HvError> {
        let clone = self.get_clone(clone_id).ok_or(HvError::LogicalFault)?;
        let template_id = clone.template_id.load(Ordering::Acquire);
        
        // Release private pages
        let private_pages = clone.private_pages.load(Ordering::Acquire);
        
        // Update template
        if let Some(template) = self.get_template(template_id) {
            template.dec_clone_count();
            
            // Restore shared pages
            for _ in 0..private_pages {
                template.record_cow_restore();
                self.total_memory_saved.fetch_add(PAGE_SIZE, Ordering::Release);
            }
        }
        
        clone.valid.store(false, Ordering::Release);
        clone.set_state(clone_state::DELETING);
        
        Ok(())
    }

    /// Delete template
    pub fn delete_template(&mut self, template_id: u32) -> Result<(), HvError> {
        let template = self.get_template(template_id).ok_or(HvError::LogicalFault)?;
        
        // Check for active clones
        if template.clone_count.load(Ordering::Acquire) > 0 {
            return Err(HvError::LogicalFault);
        }
        
        template.state.store(template_state::DELETING, Ordering::Release);
        template.valid.store(false, Ordering::Release);
        
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> ControllerStats {
        let mut active_templates = 0u8;
        let mut active_clones = 0u16;
        let mut total_shared = 0u64;
        let mut total_private = 0u64;
        
        for i in 0..self.template_count.load(Ordering::Acquire) as usize {
            let t = &self.templates[i];
            if t.valid.load(Ordering::Acquire) {
                active_templates += 1;
                total_shared += t.shared_pages.load(Ordering::Acquire);
                total_private += t.private_pages.load(Ordering::Acquire);
            }
        }
        
        for i in 0..self.clone_count.load(Ordering::Acquire) as usize {
            if self.clones[i].valid.load(Ordering::Acquire) {
                active_clones += 1;
            }
        }
        
        ControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            template_count: active_templates,
            clone_count: active_clones,
            total_templates: self.total_templates.load(Ordering::Acquire),
            total_clones: self.total_clones.load(Ordering::Acquire),
            total_shared_pages: total_shared,
            total_private_pages: total_private,
            total_memory_saved: self.total_memory_saved.load(Ordering::Acquire),
            total_cow_breaks: self.total_cow_breaks.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for TemplateController {
    fn default() -> Self {
        Self::new()
    }
}

/// Controller statistics
#[repr(C)]
pub struct ControllerStats {
    pub enabled: bool,
    pub template_count: u8,
    pub clone_count: u16,
    pub total_templates: u64,
    pub total_clones: u64,
    pub total_shared_pages: u64,
    pub total_private_pages: u64,
    pub total_memory_saved: u64,
    pub total_cow_breaks: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_template() {
        let mut ctrl = TemplateController::new();
        ctrl.enable(200, 16 * 1024 * 1024 * 1024);
        
        let template_id = ctrl.create_template(
            0x12345678,
            1,
            2,
            &[(0x80000000, 128 * 1024 * 1024, region_flag::COW)]
        ).unwrap();
        
        assert_eq!(ctrl.template_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn create_clone() {
        let mut ctrl = TemplateController::new();
        ctrl.enable(200, 16 * 1024 * 1024 * 1024);
        
        let template_id = ctrl.create_template(
            0x12345678,
            1,
            2,
            &[(0x80000000, 128 * 1024 * 1024, region_flag::COW)]
        ).unwrap();
        
        ctrl.finalize_template(template_id).unwrap();
        
        let clone_id = ctrl.create_clone(template_id, 100).unwrap();
        assert_eq!(ctrl.clone_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn cow_page() {
        let page = CowPage::new();
        page.init(0x80000000, 0x1000000);
        
        assert_eq!(page.get_ref_count(), 1);
        assert!(page.is_cow());
        
        // Break COW
        page.break_cow(1, 0x2000000);
        assert!(!page.is_cow());
        assert_eq!(page.get_hpa_for_clone(1), 0x2000000);
        assert_eq!(page.get_hpa_for_clone(2), 0x1000000);
    }

    #[test]
    fn cow_fault() {
        // Use Box to avoid stack overflow - TemplateController is large
        let mut ctrl = Box::new(TemplateController::new());
        ctrl.enable(200, 16 * 1024 * 1024 * 1024);
        
        let template_id = ctrl.create_template(
            0x12345678,
            1,
            2,
            &[(0x80000000, 16 * 1024 * 1024, region_flag::COW)]
        ).unwrap();
        
        // Initialize pages
        let hpas: Vec<u64> = (0..4096).map(|i| 0x1000000 + i * PAGE_SIZE).collect();
        ctrl.init_template_pages(template_id, 0, &hpas).unwrap();
        ctrl.finalize_template(template_id).unwrap();
        
        let clone_id = ctrl.create_clone(template_id, 100).unwrap();
        
        // Handle COW fault
        ctrl.handle_cow_fault(clone_id, 0x80001000, 0x20000000).unwrap();
        
        let hpa = ctrl.get_hpa_for_clone(clone_id, 0x80001000).unwrap();
        assert_eq!(hpa, 0x20000000);
    }

    #[test]
    fn memory_savings() {
        let mut ctrl = TemplateController::new();
        ctrl.enable(200, 16 * 1024 * 1024 * 1024);
        
        let template_id = ctrl.create_template(
            0x12345678,
            1,
            2,
            &[(0x80000000, 16 * 1024 * 1024, region_flag::COW)]
        ).unwrap();
        
        let hpas: Vec<u64> = (0..4096).map(|i| 0x1000000 + i * PAGE_SIZE).collect();
        ctrl.init_template_pages(template_id, 0, &hpas).unwrap();
        ctrl.finalize_template(template_id).unwrap();
        
        // Create clones (limited to MAX_CLONES_PER_TEMPLATE = 2 in tests)
        ctrl.create_clone(template_id, 100).unwrap();
        ctrl.create_clone(template_id, 101).unwrap();
        
        let template = ctrl.get_template(template_id).unwrap();
        let stats = template.get_stats();
        
        assert_eq!(stats.clone_count, 2);
        assert!(stats.savings_pct > 90); // Most pages still shared
    }

    #[test]
    fn delete_clone() {
        let mut ctrl = TemplateController::new();
        ctrl.enable(200, 16 * 1024 * 1024 * 1024);
        
        let template_id = ctrl.create_template(
            0x12345678,
            1,
            2,
            &[(0x80000000, 16 * 1024 * 1024, region_flag::COW)]
        ).unwrap();
        
        ctrl.finalize_template(template_id).unwrap();
        
        let clone_id = ctrl.create_clone(template_id, 100).unwrap();
        ctrl.delete_clone(clone_id).unwrap();
        
        let template = ctrl.get_template(template_id).unwrap();
        assert_eq!(template.clone_count.load(Ordering::Acquire), 0);
    }
}
