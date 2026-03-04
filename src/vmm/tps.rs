//! Transparent Page Sharing (TPS) Enhancement
//!
//! Advanced page sharing with sub-page sharing, COW, and security salting.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// TPS Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Page size
pub const PAGE_SIZE: usize = 4096;

/// Sub-page block size for sub-page sharing
pub const SUB_PAGE_SIZE: usize = 256; // 16 blocks per 4K page

/// Maximum shared pages
#[cfg(not(test))]
pub const MAX_SHARED_PAGES: usize = 131072;
/// Maximum shared pages (reduced for tests)
#[cfg(test)]
pub const MAX_SHARED_PAGES: usize = 64;

/// Maximum hash buckets
#[cfg(not(test))]
pub const MAX_HASH_BUCKETS: usize = 65536;
/// Maximum hash buckets (reduced for tests)
#[cfg(test)]
pub const MAX_HASH_BUCKETS: usize = 64;

/// Maximum VMs for salting
#[cfg(not(test))]
pub const MAX_VMS_SALTED: usize = 256;
/// Maximum VMs for salting (reduced for tests)
#[cfg(test)]
pub const MAX_VMS_SALTED: usize = 4;

// ─────────────────────────────────────────────────────────────────────────────
// Page Hash Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Page hash for deduplication
pub struct PageHash {
    /// Full page hash (SHA-256 truncated to 64-bit)
    pub hash: AtomicU64,
    /// Sub-page hashes (16 x 64-bit)
    pub sub_hashes: [AtomicU64; 16],
    /// Page frame number
    pub pfn: AtomicU64,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Reference count
    pub ref_count: AtomicU32,
    /// Is COW (Copy-on-Write)
    pub is_cow: AtomicBool,
    /// Last verified timestamp
    pub last_verified: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl PageHash {
    pub const fn new() -> Self {
        Self {
            hash: AtomicU64::new(0),
            sub_hashes: [const { AtomicU64::new(0) }; 16],
            pfn: AtomicU64::new(0),
            vm_id: AtomicU32::new(0),
            ref_count: AtomicU32::new(0),
            is_cow: AtomicBool::new(false),
            last_verified: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize with hash
    pub fn init(&self, hash: u64, pfn: u64, vm_id: u32) {
        self.hash.store(hash, Ordering::Release);
        self.pfn.store(pfn, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.ref_count.store(1, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set sub-page hash
    pub fn set_sub_hash(&self, idx: usize, hash: u64) {
        if idx < 16 {
            self.sub_hashes[idx].store(hash, Ordering::Release);
        }
    }

    /// Get sub-page hash
    pub fn get_sub_hash(&self, idx: usize) -> u64 {
        if idx < 16 {
            self.sub_hashes[idx].load(Ordering::Acquire)
        } else {
            0
        }
    }

    /// Increment reference
    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::Release)
    }

    /// Decrement reference
    pub fn release(&self) -> u32 {
        self.ref_count.fetch_sub(1, Ordering::Release)
    }

    /// Mark as COW
    pub fn set_cow(&self) {
        self.is_cow.store(true, Ordering::Release);
    }
}

impl Default for PageHash {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash Bucket
// ─────────────────────────────────────────────────────────────────────────────

/// Hash bucket for collision handling
pub struct HashBucket {
    /// Entries in bucket (indices into page_hashes)
    pub entries: [AtomicU32; 8],
    /// Entry count
    pub count: AtomicU8,
    /// Bucket lock (simple spinlock indicator)
    pub locked: AtomicBool,
}

impl HashBucket {
    pub const fn new() -> Self {
        Self {
            entries: [const { AtomicU32::new(0) }; 8],
            count: AtomicU8::new(0),
            locked: AtomicBool::new(false),
        }
    }

    /// Add entry
    pub fn add(&self, entry_idx: u32) -> bool {
        let count = self.count.load(Ordering::Acquire);
        if count >= 8 {
            return false;
        }
        self.entries[count as usize].store(entry_idx, Ordering::Release);
        self.count.fetch_add(1, Ordering::Release);
        true
    }

    /// Find entry by hash
    pub fn find(&self, hashes: &[PageHash], target_hash: u64) -> Option<u32> {
        for i in 0..self.count.load(Ordering::Acquire) as usize {
            let idx = self.entries[i].load(Ordering::Acquire) as usize;
            if hashes[idx].hash.load(Ordering::Acquire) == target_hash {
                return Some(idx as u32);
            }
        }
        None
    }
}

impl Default for HashBucket {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM Salt for Security
// ─────────────────────────────────────────────────────────────────────────────

/// VM salt entry for security (prevents cross-VM page sharing attacks)
pub struct VmSalt {
    /// VM ID
    pub vm_id: AtomicU32,
    /// Salt value (random, per-VM)
    pub salt: AtomicU64,
    /// Salt enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl VmSalt {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            salt: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize salt
    pub fn init(&self, vm_id: u32, salt: u64) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.salt.store(salt, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Apply salt to hash
    pub fn salt_hash(&self, hash: u64) -> u64 {
        if self.enabled.load(Ordering::Acquire) {
            hash ^ self.salt.load(Ordering::Acquire)
        } else {
            hash
        }
    }
}

impl Default for VmSalt {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COW (Copy-on-Write) Entry
// ─────────────────────────────────────────────────────────────────────────────

/// COW entry tracking
pub struct CowEntry {
    /// Original shared PFN
    pub shared_pfn: AtomicU64,
    /// New private PFN (after COW break)
    pub private_pfn: AtomicU64,
    /// VM ID that triggered COW
    pub vm_id: AtomicU32,
    /// GPA in guest
    pub gpa: AtomicU64,
    /// Active
    pub active: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl CowEntry {
    pub const fn new() -> Self {
        Self {
            shared_pfn: AtomicU64::new(0),
            private_pfn: AtomicU64::new(0),
            vm_id: AtomicU32::new(0),
            gpa: AtomicU64::new(0),
            active: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize COW entry
    pub fn init(&self, shared_pfn: u64, private_pfn: u64, vm_id: u32, gpa: u64) {
        self.shared_pfn.store(shared_pfn, Ordering::Release);
        self.private_pfn.store(private_pfn, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.active.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }
}

impl Default for CowEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum COW entries
pub const MAX_COW_ENTRIES: usize = 16384;

// ─────────────────────────────────────────────────────────────────────────────
// TPS Controller
// ─────────────────────────────────────────────────────────────────────────────

/// TPS sharing modes
pub mod tps_mode {
    pub const DISABLED: u8 = 0;
    pub const FULL_PAGE_ONLY: u8 = 1;
    pub const SUB_PAGE_ENABLED: u8 = 2;
    pub const FULL_WITH_SALT: u8 = 3;
}

/// TPS Controller
pub struct TpsController {
    /// Page hashes
    pub page_hashes: [PageHash; MAX_SHARED_PAGES],
    /// Hash count
    pub hash_count: AtomicU32,
    /// Hash buckets
    pub buckets: [HashBucket; MAX_HASH_BUCKETS],
    /// VM salts
    pub vm_salts: [VmSalt; MAX_VMS_SALTED],
    /// Salt count
    pub salt_count: AtomicU8,
    /// COW entries
    pub cow_entries: [CowEntry; MAX_COW_ENTRIES],
    /// COW count
    pub cow_count: AtomicU32,
    /// Sharing mode
    pub mode: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Sub-page sharing enabled
    pub sub_page_enabled: AtomicBool,
    /// Salting enabled (security)
    pub salting_enabled: AtomicBool,
    /// Cross-VM sharing enabled
    pub cross_vm_sharing: AtomicBool,
    /// Pages shared
    pub pages_shared: AtomicU64,
    /// Sub-pages shared
    pub sub_pages_shared: AtomicU64,
    /// Memory saved (bytes)
    pub memory_saved: AtomicU64,
    /// COW breaks
    pub cow_breaks: AtomicU64,
    /// Hash collisions
    pub hash_collisions: AtomicU64,
    /// Scan count
    pub scan_count: AtomicU64,
    /// Last scan timestamp
    pub last_scan: AtomicU64,
}

impl TpsController {
    pub const fn new() -> Self {
        Self {
            page_hashes: [const { PageHash::new() }; MAX_SHARED_PAGES],
            hash_count: AtomicU32::new(0),
            buckets: [const { HashBucket::new() }; MAX_HASH_BUCKETS],
            vm_salts: [const { VmSalt::new() }; MAX_VMS_SALTED],
            salt_count: AtomicU8::new(0),
            cow_entries: [const { CowEntry::new() }; MAX_COW_ENTRIES],
            cow_count: AtomicU32::new(0),
            mode: AtomicU8::new(tps_mode::FULL_WITH_SALT),
            enabled: AtomicBool::new(false),
            sub_page_enabled: AtomicBool::new(true),
            salting_enabled: AtomicBool::new(true),
            cross_vm_sharing: AtomicBool::new(false), // Security: disabled by default
            pages_shared: AtomicU64::new(0),
            sub_pages_shared: AtomicU64::new(0),
            memory_saved: AtomicU64::new(0),
            cow_breaks: AtomicU64::new(0),
            hash_collisions: AtomicU64::new(0),
            scan_count: AtomicU64::new(0),
            last_scan: AtomicU64::new(0),
        }
    }

    /// Enable TPS
    pub fn enable(&mut self, mode: u8, sub_page: bool, salting: bool, cross_vm: bool) {
        self.mode.store(mode, Ordering::Release);
        self.sub_page_enabled.store(sub_page, Ordering::Release);
        self.salting_enabled.store(salting, Ordering::Release);
        self.cross_vm_sharing.store(cross_vm, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable TPS
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM salt
    pub fn register_vm_salt(&mut self, vm_id: u32, salt: u64) -> Result<(), HvError> {
        let count = self.salt_count.load(Ordering::Acquire);
        if count as usize >= MAX_VMS_SALTED {
            return Err(HvError::LogicalFault);
        }
        
        // Check if VM already registered
        for i in 0..count as usize {
            if self.vm_salts[i].vm_id.load(Ordering::Acquire) == vm_id {
                // Update salt
                self.vm_salts[i].salt.store(salt, Ordering::Release);
                return Ok(());
            }
        }
        
        // Add new
        self.vm_salts[count as usize].init(vm_id, salt);
        self.salt_count.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Get VM salt
    pub fn get_vm_salt(&self, vm_id: u32) -> Option<&VmSalt> {
        for i in 0..self.salt_count.load(Ordering::Acquire) as usize {
            if self.vm_salts[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_salts[i]);
            }
        }
        None
    }

    /// Compute page hash
    pub fn compute_hash(&self, page_data: &[u8; PAGE_SIZE], vm_id: u32) -> u64 {
        // Simple hash (in production would use SHA-256)
        let mut hash: u64 = 0;
        
        // FNV-1a style hash
        for chunk in page_data.chunks(8) {
            let mut arr = [0u8; 8];
            for (i, byte) in chunk.iter().enumerate() {
                if i < 8 {
                    arr[i] = *byte;
                }
            }
            let val = u64::from_le_bytes(arr);
            hash = hash.wrapping_mul(1099511628211).wrapping_add(val);
        }
        
        // Apply salt if enabled
        if self.salting_enabled.load(Ordering::Acquire) {
            if let Some(salt) = self.get_vm_salt(vm_id) {
                hash = salt.salt_hash(hash);
            }
        }
        
        hash
    }

    /// Compute sub-page hashes
    pub fn compute_sub_hashes(&self, page_data: &[u8; PAGE_SIZE]) -> [u64; 16] {
        let mut hashes = [0u64; 16];
        
        for i in 0..16 {
            let start = i * SUB_PAGE_SIZE;
            let end = start + SUB_PAGE_SIZE;
            let block = &page_data[start..end];
            
            let mut hash: u64 = 0;
            for chunk in block.chunks(8) {
                let mut arr = [0u8; 8];
                for (j, byte) in chunk.iter().enumerate() {
                    if j < 8 {
                        arr[j] = *byte;
                    }
                }
                let val = u64::from_le_bytes(arr);
                hash = hash.wrapping_mul(1099511628211).wrapping_add(val);
            }
            hashes[i] = hash;
        }
        
        hashes
    }

    /// Register page for sharing
    pub fn register_page(&mut self, vm_id: u32, pfn: u64, page_data: &[u8; PAGE_SIZE]) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let hash = self.compute_hash(page_data, vm_id);
        let bucket_idx = (hash % MAX_HASH_BUCKETS as u64) as usize;
        
        // Check if already exists
        if let Some(existing_idx) = self.buckets[bucket_idx].find(&self.page_hashes, hash) {
            let existing = &self.page_hashes[existing_idx as usize];
            
            // Check cross-VM sharing permission
            if !self.cross_vm_sharing.load(Ordering::Acquire) && 
               existing.vm_id.load(Ordering::Acquire) != vm_id {
                // Can't share across VMs
                return Err(HvError::LogicalFault);
            }
            
            // Increment reference
            existing.add_ref();
            existing.set_cow();
            
            self.pages_shared.fetch_add(1, Ordering::Release);
            self.memory_saved.fetch_add(PAGE_SIZE as u64, Ordering::Release);
            
            return Ok(existing_idx);
        }
        
        // Create new entry
        let count = self.hash_count.load(Ordering::Acquire);
        if count as usize >= MAX_SHARED_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let entry_idx = count;
        let entry = &self.page_hashes[entry_idx as usize];
        entry.init(hash, pfn, vm_id);
        
        // Compute sub-page hashes if enabled
        if self.sub_page_enabled.load(Ordering::Acquire) {
            let sub_hashes = self.compute_sub_hashes(page_data);
            for i in 0..16 {
                entry.set_sub_hash(i, sub_hashes[i]);
            }
        }
        
        // Add to bucket
        if !self.buckets[bucket_idx].add(entry_idx) {
            self.hash_collisions.fetch_add(1, Ordering::Release);
        }
        
        self.hash_count.fetch_add(1, Ordering::Release);
        
        Ok(entry_idx)
    }

    /// Find shared page
    pub fn find_shared_page(&self, vm_id: u32, page_data: &[u8; PAGE_SIZE]) -> Option<u32> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        
        let hash = self.compute_hash(page_data, vm_id);
        let bucket_idx = (hash % MAX_HASH_BUCKETS as u64) as usize;
        
        self.buckets[bucket_idx].find(&self.page_hashes, hash)
    }

    /// Break COW (create private copy)
    pub fn break_cow(&mut self, shared_idx: u32, vm_id: u32, gpa: u64, new_pfn: u64) -> Result<u32, HvError> {
        if shared_idx as usize >= MAX_SHARED_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let shared = &self.page_hashes[shared_idx as usize];
        if !shared.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Create COW entry
        let cow_idx = self.cow_count.load(Ordering::Acquire);
        if cow_idx as usize >= MAX_COW_ENTRIES {
            return Err(HvError::LogicalFault);
        }
        
        let cow = &self.cow_entries[cow_idx as usize];
        cow.init(
            shared.pfn.load(Ordering::Acquire),
            new_pfn,
            vm_id,
            gpa,
        );
        
        // Decrement shared reference
        shared.release();
        
        self.cow_count.fetch_add(1, Ordering::Release);
        self.cow_breaks.fetch_add(1, Ordering::Release);
        
        Ok(cow_idx)
    }

    /// Find sub-page matches
    pub fn find_sub_page_matches(&self, page_data: &[u8; PAGE_SIZE]) -> [Option<(u32, u8)>; 16] {
        let mut matches: [Option<(u32, u8)>; 16] = [None; 16];
        
        if !self.sub_page_enabled.load(Ordering::Acquire) {
            return matches;
        }
        
        let sub_hashes = self.compute_sub_hashes(page_data);
        
        for i in 0..16 {
            for j in 0..self.hash_count.load(Ordering::Acquire) as usize {
                let entry = &self.page_hashes[j];
                if entry.get_sub_hash(i) == sub_hashes[i] {
                    matches[i] = Some((j as u32, i as u8));
                    self.sub_pages_shared.fetch_add(1, Ordering::Release);
                    break;
                }
            }
        }
        
        matches
    }

    /// Unregister page
    pub fn unregister_page(&mut self, idx: u32) -> Result<(), HvError> {
        if idx as usize >= MAX_SHARED_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.page_hashes[idx as usize];
        if !entry.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let refs = entry.release();
        if refs == 0 {
            // No more references, invalidate
            entry.valid.store(false, Ordering::Release);
            self.memory_saved.fetch_sub(PAGE_SIZE as u64, Ordering::Release);
        }
        
        Ok(())
    }

    /// Scan for shareable pages
    pub fn scan(&mut self) -> u64 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        self.scan_count.fetch_add(1, Ordering::Release);
        self.last_scan.store(Self::get_timestamp(), Ordering::Release);
        
        // Would scan memory and find shareable pages
        // Returns number of new shares found
        0
    }

    /// Get statistics
    pub fn get_stats(&self) -> TpsStats {
        TpsStats {
            enabled: self.enabled.load(Ordering::Acquire),
            mode: self.mode.load(Ordering::Acquire),
            hash_count: self.hash_count.load(Ordering::Acquire),
            pages_shared: self.pages_shared.load(Ordering::Acquire),
            sub_pages_shared: self.sub_pages_shared.load(Ordering::Acquire),
            memory_saved: self.memory_saved.load(Ordering::Acquire),
            cow_breaks: self.cow_breaks.load(Ordering::Acquire),
            hash_collisions: self.hash_collisions.load(Ordering::Acquire),
            scan_count: self.scan_count.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for TpsController {
    fn default() -> Self {
        Self::new()
    }
}

/// TPS statistics
#[repr(C)]
pub struct TpsStats {
    pub enabled: bool,
    pub mode: u8,
    pub hash_count: u32,
    pub pages_shared: u64,
    pub sub_pages_shared: u64,
    pub memory_saved: u64,
    pub cow_breaks: u64,
    pub hash_collisions: u64,
    pub scan_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_hash() {
        let tps = TpsController::new();
        let page = [0x41u8; PAGE_SIZE];
        
        let hash = tps.compute_hash(&page, 1);
        assert_ne!(hash, 0);
    }

    #[test]
    fn register_page() {
        let mut tps = TpsController::new();
        tps.enable(tps_mode::FULL_PAGE_ONLY, false, false, true);
        tps.register_vm_salt(1, 0x12345678).unwrap();
        
        let page = [0x42u8; PAGE_SIZE];
        let idx = tps.register_page(1, 0x1000, &page).unwrap();
        
        assert!(tps.page_hashes[idx as usize].valid.load(Ordering::Acquire));
    }

    #[test]
    fn find_shared_page() {
        let mut tps = TpsController::new();
        tps.enable(tps_mode::FULL_PAGE_ONLY, false, false, true);
        
        let page = [0x43u8; PAGE_SIZE];
        tps.register_page(1, 0x1000, &page).unwrap();
        
        let found = tps.find_shared_page(1, &page);
        assert!(found.is_some());
    }

    #[test]
    fn cow_break() {
        let mut tps = TpsController::new();
        tps.enable(tps_mode::FULL_PAGE_ONLY, false, false, true);
        
        let page = [0x44u8; PAGE_SIZE];
        let shared_idx = tps.register_page(1, 0x1000, &page).unwrap();
        
        let cow_idx = tps.break_cow(shared_idx, 1, 0x2000, 0x3000).unwrap();
        assert!(tps.cow_entries[cow_idx as usize].valid.load(Ordering::Acquire));
    }

    #[test]
    fn vm_salt_security() {
        let mut tps = TpsController::new();
        tps.enable(tps_mode::FULL_WITH_SALT, false, true, false);
        
        tps.register_vm_salt(1, 0x11111111).unwrap();
        tps.register_vm_salt(2, 0x22222222).unwrap();
        
        let page = [0x45u8; PAGE_SIZE];
        
        let hash1 = tps.compute_hash(&page, 1);
        let hash2 = tps.compute_hash(&page, 2);
        
        // Same page, different salts = different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn sub_page_hashes() {
        let tps = TpsController::new();
        let mut page = [0u8; PAGE_SIZE];
        
        // Different content in each sub-page
        for i in 0..16 {
            let start = i * SUB_PAGE_SIZE;
            for j in 0..SUB_PAGE_SIZE {
                page[start + j] = i as u8;
            }
        }
        
        let hashes = tps.compute_sub_hashes(&page);
        
        // Each sub-page should have different hash
        for i in 0..15 {
            assert_ne!(hashes[i], hashes[i + 1]);
        }
    }
}
