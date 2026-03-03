//! Memory Compression - VMware-style compressed memory pool
//!
//! Compress rarely-used memory pages instead of swapping to disk.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Compression Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Page size
pub const PAGE_SIZE: usize = 4096;

/// Maximum compressed pages in pool
pub const MAX_COMPRESSED_PAGES: usize = 65536;

/// Compression levels
pub mod compress_level {
    pub const NONE: u8 = 0;
    pub const FAST: u8 = 1;      // LZ4 fast
    pub const DEFAULT: u8 = 2;   // LZ4 default
    pub const BEST: u8 = 3;      // LZ4 high compression
}

/// Compression states
pub mod compress_state {
    pub const UNCOMPRESSED: u8 = 0;
    pub const COMPRESSING: u8 = 1;
    pub const COMPRESSED: u8 = 2;
    pub const DECOMPRESSING: u8 = 3;
    pub const EVICTING: u8 = 4;
}

/// Minimum compression ratio to keep
pub const MIN_COMPRESSION_RATIO: u32 = 50; // At least 50% savings

// ─────────────────────────────────────────────────────────────────────────────
// LZ4 Compression Implementation (Simplified)
// ─────────────────────────────────────────────────────────────────────────────

/// LZ4 hash table for compression
pub struct Lz4HashTable {
    /// Hash table entries
    pub table: [AtomicU32; 4096],
}

impl Lz4HashTable {
    pub const fn new() -> Self {
        Self {
            table: [const { AtomicU32::new(0) }; 4096],
        }
    }

    /// Hash function for 4-byte sequence
    #[inline]
    pub fn hash4(&self, data: &[u8]) -> u32 {
        if data.len() < 4 {
            return 0;
        }
        let val = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // Simple multiplicative hash
        val.wrapping_mul(2654435761) >> 20
    }

    /// Get position from hash
    pub fn get(&self, hash: u32) -> u32 {
        self.table[(hash & 0xFFF) as usize].load(Ordering::Acquire)
    }

    /// Set position for hash
    pub fn set(&self, hash: u32, pos: u32) {
        self.table[(hash & 0xFFF) as usize].store(pos, Ordering::Release);
    }
}

impl Default for Lz4HashTable {
    fn default() -> Self {
        Self::new()
    }
}

/// LZ4 compressor
pub struct Lz4Compressor {
    /// Hash table
    pub hash_table: Lz4HashTable,
    /// Compression level
    pub level: AtomicU8,
    /// Total bytes compressed
    pub total_compressed: AtomicU64,
    /// Total bytes output
    pub total_output: AtomicU64,
    /// Compression calls
    pub compress_calls: AtomicU64,
}

impl Lz4Compressor {
    pub const fn new() -> Self {
        Self {
            hash_table: Lz4HashTable::new(),
            level: AtomicU8::new(compress_level::FAST),
            total_compressed: AtomicU64::new(0),
            total_output: AtomicU64::new(0),
            compress_calls: AtomicU64::new(0),
        }
    }

    /// Compress a page of data
    /// Returns (compressed_size, success)
    pub fn compress_page(&mut self, src: &[u8; PAGE_SIZE], dst: &mut [u8; PAGE_SIZE]) -> u32 {
        self.compress_calls.fetch_add(1, Ordering::Release);
        
        // Reset hash table for each block
        for entry in &self.hash_table.table {
            entry.store(0, Ordering::Release);
        }
        
        let mut src_pos = 0usize;
        let mut dst_pos = 0usize;
        
        // Write literal length and literals
        let mut literal_start = 0usize;
        
        while src_pos + 4 < PAGE_SIZE {
            let hash = self.hash_table.hash4(&src[src_pos..]);
            let ref_pos = self.hash_table.get(hash) as usize;
            
            self.hash_table.set(hash, src_pos as u32);
            
            // Check for match
            if ref_pos > 0 && ref_pos < src_pos {
                let match_len = self.find_match(src, ref_pos, src_pos);
                
                if match_len >= 4 {
                    // Write literals before match
                    let literal_len = src_pos - literal_start;
                    dst_pos = self.write_literals(src, literal_start, literal_len, dst, dst_pos);
                    
                    // Write match
                    let offset = (src_pos - ref_pos) as u16;
                    let match_len_minus_4 = (match_len - 4) as u32;
                    
                    // Token: match length in high nibble
                    dst[dst_pos] = ((match_len_minus_4.min(15) as u8) << 4) | 
                                   (literal_len.min(15) as u8);
                    dst_pos += 1;
                    
                    // Write offset
                    dst[dst_pos] = (offset & 0xFF) as u8;
                    dst[dst_pos + 1] = (offset >> 8) as u8;
                    dst_pos += 2;
                    
                    // Extended match length if > 19
                    if match_len > 19 {
                        let mut extra = match_len - 19;
                        while extra >= 255 {
                            dst[dst_pos] = 255;
                            dst_pos += 1;
                            extra -= 255;
                        }
                        dst[dst_pos] = extra as u8;
                        dst_pos += 1;
                    }
                    
                    src_pos += match_len;
                    literal_start = src_pos;
                    continue;
                }
            }
            
            src_pos += 1;
        }
        
        // Write remaining literals
        let literal_len = PAGE_SIZE - literal_start;
        dst_pos = self.write_literals(src, literal_start, literal_len, dst, dst_pos);
        
        self.total_compressed.fetch_add(PAGE_SIZE as u64, Ordering::Release);
        self.total_output.fetch_add(dst_pos as u64, Ordering::Release);
        
        dst_pos as u32
    }

    /// Find match length at two positions
    fn find_match(&self, src: &[u8], pos1: usize, pos2: usize) -> usize {
        let mut len = 0usize;
        let max_len = PAGE_SIZE - pos2;
        
        while len < max_len && src[pos1 + len] == src[pos2 + len] {
            len += 1;
        }
        
        len
    }

    /// Write literals to output
    fn write_literals(&self, src: &[u8], start: usize, len: usize, 
                      dst: &mut [u8], dst_pos: usize) -> usize {
        if len == 0 {
            return dst_pos;
        }
        
        let mut pos = dst_pos;
        
        // Token: literal length in low nibble
        if len < 15 {
            dst[pos] = len as u8;
            pos += 1;
        } else {
            dst[pos] = 15;
            pos += 1;
            let mut remaining = len - 15;
            while remaining >= 255 {
                dst[pos] = 255;
                pos += 1;
                remaining -= 255;
            }
            dst[pos] = remaining as u8;
            pos += 1;
        }
        
        // Copy literals
        for i in 0..len {
            dst[pos + i] = src[start + i];
        }
        pos + len
    }

    /// Decompress a page of data
    /// Returns decompressed size
    pub fn decompress_page(&self, src: &[u8], src_len: usize, dst: &mut [u8; PAGE_SIZE]) -> u32 {
        let mut src_pos = 0usize;
        let mut dst_pos = 0usize;
        
        while src_pos < src_len && dst_pos < PAGE_SIZE {
            let token = src[src_pos];
            src_pos += 1;
            
            // Literal length
            let mut literal_len = (token & 0x0F) as usize;
            if literal_len == 15 {
                while src_pos < src_len {
                    let extra = src[src_pos] as usize;
                    src_pos += 1;
                    literal_len += extra;
                    if extra < 255 {
                        break;
                    }
                }
            }
            
            // Copy literals
            for i in 0..literal_len {
                if src_pos + i < src_len && dst_pos + i < PAGE_SIZE {
                    dst[dst_pos + i] = src[src_pos + i];
                }
            }
            src_pos += literal_len;
            dst_pos += literal_len;
            
            if src_pos >= src_len {
                break;
            }
            
            // Match offset
            if src_pos + 2 > src_len {
                break;
            }
            let offset = u16::from_le_bytes([src[src_pos], src[src_pos + 1]]) as usize;
            src_pos += 2;
            
            if offset == 0 || offset > dst_pos {
                break;
            }
            
            // Match length
            let mut match_len = ((token >> 4) & 0x0F) as usize + 4;
            if (token >> 4) == 15 {
                while src_pos < src_len {
                    let extra = src[src_pos] as usize;
                    src_pos += 1;
                    match_len += extra;
                    if extra < 255 {
                        break;
                    }
                }
            }
            
            // Copy match
            for i in 0..match_len {
                if dst_pos + i < PAGE_SIZE && dst_pos + i >= offset {
                    dst[dst_pos + i] = dst[dst_pos + i - offset];
                }
            }
            dst_pos += match_len;
        }
        
        dst_pos as u32
    }

    /// Get compression ratio (0-100)
    pub fn get_ratio(&self) -> u32 {
        let compressed = self.total_compressed.load(Ordering::Acquire);
        let output = self.total_output.load(Ordering::Acquire);
        
        if compressed == 0 {
            return 0;
        }
        
        ((compressed - output) * 100 / compressed) as u32
    }
}

impl Default for Lz4Compressor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compressed Page Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Compressed page entry in pool
pub struct CompressedPage {
    /// Original GPA (guest physical address)
    pub gpa: AtomicU64,
    /// Original page frame number
    pub pfn: AtomicU64,
    /// Compressed data offset in pool
    pub data_offset: AtomicU32,
    /// Compressed size (bytes)
    pub compressed_size: AtomicU16,
    /// Original size (always PAGE_SIZE)
    pub original_size: AtomicU16,
    /// Compression state
    pub state: AtomicU8,
    /// Compression level used
    pub level: AtomicU8,
    /// VM ID that owns this page
    pub vm_id: AtomicU32,
    /// Access count (for LRU)
    pub access_count: AtomicU32,
    /// Last access timestamp
    pub last_access: AtomicU64,
    /// Valid entry
    pub valid: AtomicBool,
    /// Dirty flag
    pub dirty: AtomicBool,
}

impl CompressedPage {
    pub const fn new() -> Self {
        Self {
            gpa: AtomicU64::new(0),
            pfn: AtomicU64::new(0),
            data_offset: AtomicU32::new(0),
            compressed_size: AtomicU16::new(0),
            original_size: AtomicU16::new(PAGE_SIZE as u16),
            state: AtomicU8::new(compress_state::UNCOMPRESSED),
            level: AtomicU8::new(compress_level::FAST),
            vm_id: AtomicU32::new(0),
            access_count: AtomicU32::new(0),
            last_access: AtomicU64::new(0),
            valid: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
        }
    }

    /// Initialize entry
    pub fn init(&self, gpa: u64, pfn: u64, vm_id: u32) {
        self.gpa.store(gpa, Ordering::Release);
        self.pfn.store(pfn, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.state.store(compress_state::UNCOMPRESSED, Ordering::Release);
        self.valid.store(true, Ordering::Release);
        self.access_count.store(0, Ordering::Release);
    }

    /// Mark as compressed
    pub fn set_compressed(&self, offset: u32, size: u16, level: u8) {
        self.data_offset.store(offset, Ordering::Release);
        self.compressed_size.store(size, Ordering::Release);
        self.level.store(level, Ordering::Release);
        self.state.store(compress_state::COMPRESSED, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.last_access.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> u32 {
        let original = self.original_size.load(Ordering::Acquire) as u32;
        let compressed = self.compressed_size.load(Ordering::Acquire) as u32;
        
        if original == 0 {
            return 0;
        }
        
        ((original - compressed) * 100) / original
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for CompressedPage {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Compressed Memory Pool
// ─────────────────────────────────────────────────────────────────────────────

/// Compressed memory pool controller
pub struct CompressedMemoryPool {
    /// Compressed pages metadata
    pub pages: [CompressedPage; MAX_COMPRESSED_PAGES],
    /// Page count
    pub page_count: AtomicU32,
    /// Data buffer (compressed data storage)
    pub data_buffer: [AtomicU8; MAX_COMPRESSED_PAGES * PAGE_SIZE / 2],
    /// Data buffer write offset
    pub data_offset: AtomicU32,
    /// LZ4 compressor
    pub compressor: Lz4Compressor,
    /// Compression enabled
    pub enabled: AtomicBool,
    /// Compression threshold (memory pressure %)
    pub threshold: AtomicU8,
    /// Maximum pool size (bytes)
    pub max_size: AtomicU64,
    /// Current pool size (bytes)
    pub current_size: AtomicU64,
    /// Memory saved (bytes)
    pub memory_saved: AtomicU64,
    /// Pages compressed
    pub pages_compressed: AtomicU64,
    /// Pages decompressed
    pub pages_decompressed: AtomicU64,
    /// Compression failures
    pub compress_failures: AtomicU64,
    /// Cache hits (decompress avoided)
    pub cache_hits: AtomicU64,
    /// Cache misses
    pub cache_misses: AtomicU64,
    /// Default compression level
    pub default_level: AtomicU8,
    /// Minimum compression ratio to keep
    pub min_ratio: AtomicU8,
}

impl CompressedMemoryPool {
    pub const fn new() -> Self {
        Self {
            pages: [const { CompressedPage::new() }; MAX_COMPRESSED_PAGES],
            page_count: AtomicU32::new(0),
            data_buffer: [const { AtomicU8::new(0) }; MAX_COMPRESSED_PAGES * PAGE_SIZE / 2],
            data_offset: AtomicU32::new(0),
            compressor: Lz4Compressor::new(),
            enabled: AtomicBool::new(false),
            threshold: AtomicU8::new(80), // Start at 80% memory pressure
            max_size: AtomicU64::new(1024 * 1024 * 1024), // 1GB max
            current_size: AtomicU64::new(0),
            memory_saved: AtomicU64::new(0),
            pages_compressed: AtomicU64::new(0),
            pages_decompressed: AtomicU64::new(0),
            compress_failures: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            default_level: AtomicU8::new(compress_level::FAST),
            min_ratio: AtomicU8::new(30), // Minimum 30% savings
        }
    }

    /// Enable compression
    pub fn enable(&mut self, threshold: u8, max_size: u64) {
        self.threshold.store(threshold, Ordering::Release);
        self.max_size.store(max_size, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable compression
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Compress a page
    /// Returns compressed page index or error
    pub fn compress_page(&mut self, gpa: u64, pfn: u64, vm_id: u32, 
                         page_data: &[u8; PAGE_SIZE]) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Find free slot
        let slot = self.find_free_slot()?;
        
        // Initialize entry
        self.pages[slot as usize].init(gpa, pfn, vm_id);
        self.pages[slot as usize].state.store(compress_state::COMPRESSING, Ordering::Release);
        
        // Compress data
        let mut compressed = [0u8; PAGE_SIZE];
        let compressed_size = self.compressor.compress_page(page_data, &mut compressed);
        
        // Check compression ratio
        let ratio = ((PAGE_SIZE - compressed_size as usize) * 100 / PAGE_SIZE) as u32;
        if ratio < self.min_ratio.load(Ordering::Acquire) as u32 {
            // Not worth compressing
            self.pages[slot as usize].valid.store(false, Ordering::Release);
            self.compress_failures.fetch_add(1, Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        // Allocate space in data buffer
        let data_offset = self.data_offset.fetch_add(compressed_size, Ordering::Release);
        
        // Copy compressed data to buffer
        for i in 0..compressed_size as usize {
            self.data_buffer[data_offset as usize + i].store(compressed[i], Ordering::Release);
        }
        
        // Update entry
        self.pages[slot as usize].set_compressed(
            data_offset,
            compressed_size as u16,
            self.default_level.load(Ordering::Acquire),
        );
        
        // Update statistics
        self.page_count.fetch_add(1, Ordering::Release);
        self.current_size.fetch_add(compressed_size as u64, Ordering::Release);
        self.memory_saved.fetch_add((PAGE_SIZE - compressed_size as usize) as u64, Ordering::Release);
        self.pages_compressed.fetch_add(1, Ordering::Release);
        
        Ok(slot)
    }

    /// Decompress a page
    pub fn decompress_page(&self, slot: u32, page_data: &mut [u8; PAGE_SIZE]) -> Result<(), HvError> {
        if slot as usize >= MAX_COMPRESSED_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.pages[slot as usize];
        if !entry.valid.load(Ordering::Acquire) ||
           entry.state.load(Ordering::Acquire) != compress_state::COMPRESSED {
            return Err(HvError::LogicalFault);
        }
        
        entry.state.store(compress_state::DECOMPRESSING, Ordering::Release);
        
        // Get compressed data
        let offset = entry.data_offset.load(Ordering::Acquire) as usize;
        let size = entry.compressed_size.load(Ordering::Acquire) as usize;
        
        // Decompress
        let mut compressed = [0u8; PAGE_SIZE];
        for i in 0..size {
            compressed[i] = self.data_buffer[offset + i].load(Ordering::Acquire);
        }
        
        self.compressor.decompress_page(&compressed, size, page_data);
        
        entry.state.store(compress_state::COMPRESSED, Ordering::Release);
        entry.record_access();
        
        self.pages_decompressed.fetch_add(1, Ordering::Release);
        self.cache_misses.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Find page by GPA
    pub fn find_page(&self, gpa: u64) -> Option<u32> {
        for i in 0..self.page_count.load(Ordering::Acquire) as usize {
            if self.pages[i].gpa.load(Ordering::Acquire) == gpa &&
               self.pages[i].valid.load(Ordering::Acquire) {
                return Some(i as u32);
            }
        }
        None
    }

    /// Evict page (remove from pool)
    pub fn evict_page(&mut self, slot: u32) -> Result<(), HvError> {
        if slot as usize >= MAX_COMPRESSED_PAGES {
            return Err(HvError::LogicalFault);
        }
        
        let entry = &self.pages[slot as usize];
        if !entry.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Mark as evicting
        entry.state.store(compress_state::EVICTING, Ordering::Release);
        
        // Update statistics
        let size = entry.compressed_size.load(Ordering::Acquire) as u64;
        self.current_size.fetch_sub(size, Ordering::Release);
        self.page_count.fetch_sub(1, Ordering::Release);
        
        // Invalidate
        entry.valid.store(false, Ordering::Release);
        
        Ok(())
    }

    /// Evict least recently used pages
    pub fn evict_lru(&mut self, count: u32) -> u32 {
        let mut evicted = 0u32;
        let mut candidates: [(u64, u32); 256] = [(0, 0); 256];
        let mut candidate_count = 0;
        
        // Find LRU candidates
        for i in 0..self.page_count.load(Ordering::Acquire) as usize {
            if candidate_count >= 256 {
                break;
            }
            let entry = &self.pages[i];
            if entry.valid.load(Ordering::Acquire) {
                candidates[candidate_count] = (entry.last_access.load(Ordering::Acquire), i as u32);
                candidate_count += 1;
            }
        }
        
        // Sort by last access (ascending) - simple bubble sort
        for i in 0..candidate_count {
            for j in i + 1..candidate_count {
                if candidates[j].0 < candidates[i].0 {
                    let temp = candidates[i];
                    candidates[i] = candidates[j];
                    candidates[j] = temp;
                }
            }
        }
        
        // Evict oldest
        for i in 0..(count as usize).min(candidate_count) {
            if self.evict_page(candidates[i].1).is_ok() {
                evicted += 1;
            }
        }
        
        evicted
    }

    /// Find free slot
    fn find_free_slot(&self) -> Result<u32, HvError> {
        // First, try to reuse invalid slots
        for i in 0..MAX_COMPRESSED_PAGES {
            if !self.pages[i].valid.load(Ordering::Acquire) {
                return Ok(i as u32);
            }
        }
        
        // No free slots
        Err(HvError::LogicalFault)
    }

    /// Get statistics
    pub fn get_stats(&self) -> CompressionStats {
        CompressionStats {
            enabled: self.enabled.load(Ordering::Acquire),
            page_count: self.page_count.load(Ordering::Acquire),
            current_size: self.current_size.load(Ordering::Acquire),
            memory_saved: self.memory_saved.load(Ordering::Acquire),
            pages_compressed: self.pages_compressed.load(Ordering::Acquire),
            pages_decompressed: self.pages_decompressed.load(Ordering::Acquire),
            compress_failures: self.compress_failures.load(Ordering::Acquire),
            cache_hits: self.cache_hits.load(Ordering::Acquire),
            cache_misses: self.cache_misses.load(Ordering::Acquire),
            compression_ratio: self.compressor.get_ratio(),
        }
    }
}

impl Default for CompressedMemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Compression statistics
#[repr(C)]
pub struct CompressionStats {
    pub enabled: bool,
    pub page_count: u32,
    pub current_size: u64,
    pub memory_saved: u64,
    pub pages_compressed: u64,
    pub pages_decompressed: u64,
    pub compress_failures: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub compression_ratio: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lz4_compress_decompress() {
        let mut compressor = Lz4Compressor::new();
        let src = [0x41u8; PAGE_SIZE]; // All 'A'
        let mut compressed = [0u8; PAGE_SIZE];
        let mut decompressed = [0u8; PAGE_SIZE];
        
        let size = compressor.compress_page(&src, &mut compressed);
        assert!(size < PAGE_SIZE as u32);
        
        let decompressed_size = compressor.decompress_page(&compressed, size as usize, &mut decompressed);
        assert_eq!(decompressed_size as usize, PAGE_SIZE);
    }

    #[test]
    fn compress_page_to_pool() {
        let mut pool = CompressedMemoryPool::new();
        pool.enable(80, 1024 * 1024 * 1024);
        
        let page_data = [0x42u8; PAGE_SIZE];
        let slot = pool.compress_page(0x1000, 1, 1, &page_data).unwrap();
        
        assert!(pool.pages[slot as usize].valid.load(Ordering::Acquire));
        assert!(pool.pages[slot as usize].compressed_size.load(Ordering::Acquire) < PAGE_SIZE as u16);
    }

    #[test]
    fn decompress_from_pool() {
        let mut pool = CompressedMemoryPool::new();
        pool.enable(80, 1024 * 1024 * 1024);
        
        let page_data = [0x43u8; PAGE_SIZE];
        let slot = pool.compress_page(0x1000, 1, 1, &page_data).unwrap();
        
        let mut recovered = [0u8; PAGE_SIZE];
        pool.decompress_page(slot, &mut recovered).unwrap();
        
        // Check first few bytes
        for i in 0..100 {
            assert_eq!(recovered[i], 0x43);
        }
    }

    #[test]
    fn evict_lru() {
        let mut pool = CompressedMemoryPool::new();
        pool.enable(80, 1024 * 1024 * 1024);
        
        let page_data = [0x44u8; PAGE_SIZE];
        pool.compress_page(0x1000, 1, 1, &page_data).unwrap();
        pool.compress_page(0x2000, 2, 1, &page_data).unwrap();
        pool.compress_page(0x3000, 3, 1, &page_data).unwrap();
        
        let evicted = pool.evict_lru(1);
        assert_eq!(evicted, 1);
        assert_eq!(pool.page_count.load(Ordering::Acquire), 2);
    }
}
