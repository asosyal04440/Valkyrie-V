use crate::vmm::virtio_mmio::{VirtIODevice, VirtIoDeviceType, VIRTIO_DEVICE_BLOCK};
use crate::vmm::virtio_queue::{DescChainElem, DescChainIter, SplitVirtqueue};
use crate::vmm::{HvError, HvResult};
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

pub const VIRTIO_BLK_F_RO: u32 = 5;
pub const VIRTIO_BLK_F_FLUSH: u32 = 9;
pub const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_GET_ID: u32 = 8;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const VIRTIO_BLK_MAX_SEGS: u32 = 256;
pub const VIRTIO_BLK_QUEUE_SIZE: u32 = 256;
pub const VIRTIO_BLK_SECTOR_SIZE: u64 = 512;

/// Maximum in-memory disk image size (64 MB by default)
pub const VIRTIO_BLK_MAX_IMAGE_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct VirtBlkRequest {
    pub request_type: u32,
    pub priority: u32,
    pub sector: u64,
}

impl VirtBlkRequest {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        Some(Self {
            request_type: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            priority: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            sector: u64::from_le_bytes([
                data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
            ]),
        })
    }
}

pub struct VirtIoBlockConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub blk_size: u32,
}

impl VirtIoBlockConfig {
    pub fn new(capacity: u64) -> Self {
        Self {
            capacity,
            size_max: 0x10000,
            seg_max: VIRTIO_BLK_MAX_SEGS,
            blk_size: 512,
        }
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        if buf.len() < 16 {
            return;
        }
        buf[0..8].copy_from_slice(&self.capacity.to_le_bytes());
        buf[8..12].copy_from_slice(&self.size_max.to_le_bytes());
        buf[12..16].copy_from_slice(&self.seg_max.to_le_bytes());
    }
}

pub struct VirtIoBlock {
    config: VirtIoBlockConfig,
    status: AtomicU8,
    features: AtomicU64,
    _queue_size: AtomicU32,
    queue_ready: AtomicU8,
    _last_avail: AtomicU16,
    used_idx: AtomicU16,
    reads: AtomicU64,
    writes: AtomicU64,
    errors: AtomicU64,
}

impl VirtIoBlock {
    pub fn new(capacity: u64) -> Self {
        Self {
            config: VirtIoBlockConfig::new(capacity),
            status: AtomicU8::new(0),
            features: AtomicU64::new(0),
            _queue_size: AtomicU32::new(0),
            queue_ready: AtomicU8::new(0),
            _last_avail: AtomicU16::new(0),
            used_idx: AtomicU16::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.reads.load(Ordering::Acquire),
            self.writes.load(Ordering::Acquire),
            self.errors.load(Ordering::Acquire),
        )
    }

    pub fn set_ready(&self, ready: bool) {
        self.queue_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }
}

impl VirtIODevice for VirtIoBlock {
    fn device_type(&self) -> VirtIoDeviceType {
        VirtIoDeviceType::Block
    }

    fn device_id(&self) -> u32 {
        VIRTIO_DEVICE_BLOCK
    }

    fn vendor_id(&self) -> u32 {
        0x1AF4
    }

    fn get_features(&self) -> u64 {
        // VIRTIO_BLK_F_SIZE_MAX(1) | VIRTIO_BLK_F_SEG_MAX(2) | VIRTIO_BLK_F_RO(5) |
        // VIRTIO_BLK_F_FLUSH(9)
        (1 << 1) | (1 << 2) | (1 << VIRTIO_BLK_F_RO) | (1 << VIRTIO_BLK_F_FLUSH)
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.features.store(features, Ordering::Release);
        Ok(())
    }

    fn get_status(&self) -> u32 {
        self.status.load(Ordering::Acquire) as u32
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.status.store(status as u8, Ordering::Release);
        Ok(())
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        let config_bytes = &mut [0u8; 16];
        self.config.to_bytes(config_bytes);

        let start = offset as usize;
        let end = (start + data.len()).min(16);

        if start >= 16 {
            return Err(HvError::LogicalFault);
        }

        data[..(end - start)].copy_from_slice(&config_bytes[start..end]);
        Ok(())
    }

    fn write_config(&mut self, _offset: u32, _data: &[u8]) -> Result<(), HvError> {
        Ok(())
    }

    fn queue_notify(&mut self, _queue: u32) -> Result<bool, HvError> {
        if self.queue_ready.load(Ordering::Acquire) == 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Ok(false);
        }
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.used_idx.fetch_add(1, Ordering::Relaxed);
        Ok(true)
    }
}

/// In-memory disk image storage for VirtIO Block.
/// This simulates a disk backed by host memory.
/// In a full implementation, this would be replaced with file-backed storage.
pub struct BlockStorage {
    /// Disk image data (allocated from host memory via Atlas or static pool)
    data: *mut u8,
    /// Size of allocated data
    data_size: usize,
    /// Capacity in sectors
    capacity_sectors: u64,
    /// Whether writes are allowed
    read_only: bool,
    /// Whether using static fallback (true) or Atlas allocation (false)
    is_static: bool,
    /// Optional file backend for persistent storage
    file_backend: Option<crate::vmm::file_backend::FileBackend>,
}

// Safety: BlockStorage manages raw pointer but is used only from single thread
unsafe impl Send for BlockStorage {}

impl BlockStorage {
    /// Create a new block storage with the given capacity in bytes.
    /// Memory is allocated from the host's memory pool via Atlas.
    /// Falls back to static buffer if Atlas is unavailable.
    pub fn new(capacity_bytes: u64) -> Option<Self> {
        let capacity_sectors = capacity_bytes / VIRTIO_BLK_SECTOR_SIZE;
        let alloc_size = capacity_bytes.min(VIRTIO_BLK_MAX_IMAGE_SIZE as u64) as usize;
        
        // Try Atlas allocation first
        let (data_ptr, is_static) = Self::try_atlas_allocate(alloc_size);
        
        Some(Self {
            data: data_ptr,
            data_size: alloc_size,
            capacity_sectors,
            read_only: false,
            is_static,
            file_backend: None,
        })
    }
    
    /// Create block storage backed by a file
    pub fn from_file(path: &str, read_only: bool) -> Option<Self> {
        use crate::vmm::file_backend::FileBackend;
        
        let mut backend = FileBackend::new()
            .with_path(path)
            .with_read_only(read_only);
        
        if !backend.open() {
            return None;
        }
        
        let size = backend.size();
        
        Some(Self {
            data: core::ptr::null_mut(),
            data_size: size as usize,
            capacity_sectors: size / 512,
            read_only,
            is_static: false,
            file_backend: Some(backend),
        })
    }
    
    /// Try to allocate from Atlas, fall back to static buffer
    fn try_atlas_allocate(size: usize) -> (*mut u8, bool) {
        // Try Atlas allocation
        // In a full implementation with Atlas available:
        // use crate::vmm::atlas::Atlas;
        // if let Some(ptr) = Atlas::allocate_host_region(size, 4096) {
        //     return (ptr, false);
        // }
        
        // Fallback: use static buffer with spinlock
        static mut STORAGE: [u8; VIRTIO_BLK_MAX_IMAGE_SIZE] = [0u8; VIRTIO_BLK_MAX_IMAGE_SIZE];
        static STORAGE_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
        
        // Try to acquire the storage lock
        if STORAGE_LOCK.compare_exchange(
            false,
            true,
            core::sync::atomic::Ordering::Acquire,
            core::sync::atomic::Ordering::Relaxed,
        ).is_ok() {
            unsafe { (STORAGE.as_mut_ptr(), true) }
        } else {
            // Storage in use - try to allocate from heap if available
            // For no_std, we could try to find another static region
            // or return null to indicate failure
            (core::ptr::null_mut(), true)
        }
    }
    
    /// Allocate from Atlas memory pool
    #[cfg(feature = "atlas")]
    fn allocate_from_atlas(size: usize) -> Option<*mut u8> {
        use crate::vmm::atlas::Atlas;
        Atlas::allocate_host_region(size, 4096)
    }
    
    #[cfg(not(feature = "atlas"))]
    fn allocate_from_atlas(_size: usize) -> Option<*mut u8> {
        None
    }
    
    /// Create block storage from a pre-allocated Atlas region
    pub fn from_atlas_region(ptr: *mut u8, size: usize, read_only: bool) -> Self {
        Self {
            data: ptr,
            data_size: size,
            capacity_sectors: (size as u64) / VIRTIO_BLK_SECTOR_SIZE,
            read_only,
            is_static: false,
            file_backend: None,
        }
    }

    /// Read sectors from the disk image.
    /// Returns the number of bytes actually read.
    pub fn read(&self, sector: u64, buf: &mut [u8]) -> usize {
        // If file backend is available, use it
        if let Some(ref backend) = self.file_backend {
            // FileBackend needs &mut self, so we need interior mutability
            // For now, fall through to memory read
        }
        
        let offset = sector * VIRTIO_BLK_SECTOR_SIZE;
        if offset >= self.data_size as u64 {
            return 0;
        }
        let start = offset as usize;
        let end = (start + buf.len()).min(self.data_size);
        let read_len = end - start;
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data.add(start),
                buf.as_mut_ptr(),
                read_len,
            );
        }
        read_len
    }

    /// Write sectors to the disk image.
    /// Returns the number of bytes actually written.
    pub fn write(&mut self, sector: u64, data: &[u8]) -> usize {
        if self.read_only {
            return 0;
        }
        
        // If file backend is available, use it
        if let Some(ref mut backend) = self.file_backend {
            let written = backend.write(sector, data);
            if written > 0 {
                return written;
            }
        }
        
        let offset = sector * VIRTIO_BLK_SECTOR_SIZE;
        if offset >= self.data_size as u64 {
            return 0;
        }
        let start = offset as usize;
        let end = (start + data.len()).min(self.data_size);
        let write_len = end - start;
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.data.add(start),
                write_len,
            );
        }
        write_len
    }

    /// Flush any cached writes.
    pub fn flush(&mut self) -> bool {
        if let Some(ref mut backend) = self.file_backend {
            return backend.flush();
        }
        true
    }

    /// Get capacity in sectors.
    pub fn capacity(&self) -> u64 {
        self.capacity_sectors
    }

    /// Load a disk image from a byte slice.
    pub fn load_image(&mut self, image: &[u8]) -> usize {
        let copy_len = image.len().min(self.data_size);
        unsafe {
            core::ptr::copy_nonoverlapping(
                image.as_ptr(),
                self.data,
                copy_len,
            );
        }
        copy_len
    }
}

impl Drop for BlockStorage {
    fn drop(&mut self) {
        // Release static storage lock if we were using it
        if self.is_static {
            static STORAGE_LOCK: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
            STORAGE_LOCK.store(false, core::sync::atomic::Ordering::Release);
        }
        // Atlas-allocated regions would be freed via Atlas::free_region()
    }
}

pub struct VirtIoBlockBackend {
    block: VirtIoBlock,
    /// Storage backend (in-memory disk image)
    storage: Option<BlockStorage>,
    /// Virtqueue for request processing
    vq: SplitVirtqueue,
    /// Request buffer for parsing
    req_buf: [u8; 16],
}

impl VirtIoBlockBackend {
    /// Create a new block backend with in-memory storage.
    pub fn new(capacity: u64) -> Self {
        let storage = BlockStorage::new(capacity);
        Self {
            block: VirtIoBlock::new(capacity),
            storage,
            vq: SplitVirtqueue::new(),
            req_buf: [0u8; 16],
        }
    }

    /// Create a backend with pre-loaded disk image.
    pub fn with_image(capacity: u64, image: &[u8]) -> Self {
        let mut backend = Self::new(capacity);
        if let Some(ref mut storage) = backend.storage {
            storage.load_image(image);
        }
        backend
    }

    pub fn get_stats(&self) -> (u64, u64, u64) {
        self.block.get_stats()
    }

    /// Setup the virtqueue for I/O processing.
    pub fn setup_queue(&mut self, size: u16, desc: u64, avail: u64, used: u64, guest_base: u64) {
        self.vq.setup(size, desc, avail, used, guest_base);
        self.block.set_ready(true);
    }

    /// Process pending block I/O requests.
    /// Returns the number of requests processed.
    pub fn process_requests(&mut self) -> u32 {
        let storage = match &mut self.storage {
            Some(s) => s,
            None => return 0,
        };

        let mut processed = 0u32;
        
        while let Some(head) = self.vq.pop_avail() {
            let mut chain = self.vq.walk_chain(head);
            
            // First descriptor contains the request header
            let req_desc = match chain.next() {
                Some(d) => d,
                None => {
                    self.vq.push_used(head, 0);
                    continue;
                }
            };

            // Read request header from guest memory
            let req_addr = req_desc.addr;
            let req_ptr = (self.vq.guest_base + req_addr) as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(req_ptr, self.req_buf.as_mut_ptr(), 16);
            }
            
            let request = match VirtBlkRequest::parse(&self.req_buf) {
                Some(r) => r,
                None => {
                    self.vq.push_used(head, 0);
                    continue;
                }
            };

            // Process the request based on type
            let mut status = VIRTIO_BLK_S_OK;
            let mut bytes_done = 0u32;

            match request.request_type {
                VIRTIO_BLK_T_IN => {
                    // Read: data descriptors follow the request header
                    // Process all write descriptors in the chain
                    let mut sector_offset = 0u64;
                    for data_desc in chain.by_ref() {
                        if !data_desc.write {
                            continue; // Skip non-write descriptors for read
                        }
                        // Read from storage into guest memory
                        let sectors_to_read = (data_desc.len / 512) as u64;
                        if sectors_to_read == 0 {
                            continue;
                        }
                        
                        let mut buf = [0u8; 4096];
                        let current_sector = request.sector + sector_offset;
                        let read_bytes = storage.read(current_sector, &mut buf[..data_desc.len as usize]);
                        
                        if read_bytes > 0 {
                            // Write data to guest memory
                            let data_ptr = (self.vq.guest_base + data_desc.addr) as *mut u8;
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    buf.as_ptr(),
                                    data_ptr,
                                    read_bytes,
                                );
                            }
                            bytes_done += read_bytes as u32;
                            sector_offset += sectors_to_read;
                        } else {
                            status = VIRTIO_BLK_S_IOERR;
                        }
                        // Continue processing more descriptors in chain
                    }
                    self.block.reads.fetch_add(1, Ordering::Relaxed);
                }
                VIRTIO_BLK_T_OUT => {
                    // Write: data descriptors contain data to write
                    // Process all read descriptors in the chain
                    let mut sector_offset = 0u64;
                    for data_desc in chain.by_ref() {
                        if data_desc.write {
                            continue; // Skip write descriptors for write operation
                        }
                        // Calculate sectors to write
                        let sectors_to_write = (data_desc.len / 512) as u64;
                        if sectors_to_write == 0 {
                            continue;
                        }
                        
                        // Read data from guest memory
                        let mut buf = [0u8; 4096];
                        let data_ptr = (self.vq.guest_base + data_desc.addr) as *const u8;
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                data_ptr,
                                buf.as_mut_ptr(),
                                data_desc.len as usize,
                            );
                        }
                        
                        let current_sector = request.sector + sector_offset;
                        let written = storage.write(current_sector, &buf[..data_desc.len as usize]);
                        
                        if written > 0 {
                            bytes_done += written as u32;
                            sector_offset += sectors_to_write;
                        } else {
                            status = VIRTIO_BLK_S_IOERR;
                        }
                        // Continue processing more descriptors in chain
                    }
                    self.block.writes.fetch_add(1, Ordering::Relaxed);
                }
                VIRTIO_BLK_T_FLUSH => {
                    if storage.flush() {
                        status = VIRTIO_BLK_S_OK;
                    } else {
                        status = VIRTIO_BLK_S_IOERR;
                    }
                }
                _ => {
                    status = VIRTIO_BLK_S_UNSUPP;
                }
            }

            // Write status byte to the last descriptor (should be a write descriptor)
            // The last descriptor in the chain is reserved for status byte
            let status_written = if let Some(status_desc) = chain.next() {
                if status_desc.write && status_desc.len >= 1 {
                    let status_ptr = (self.vq.guest_base + status_desc.addr) as *mut u8;
                    unsafe {
                        core::ptr::write(status_ptr, status);
                    }
                    true
                } else {
                    false
                }
            } else {
                // No status descriptor - this is an error but we complete anyway
                false
            };
            
            // If status couldn't be written, log error (in production)
            if !status_written {
                // Status descriptor missing or invalid
                // The request still completes but guest won't see status
            }
            
            self.vq.push_used(head, bytes_done);
            processed += 1;
        }

        processed
    }
}

impl VirtIODevice for VirtIoBlockBackend {
    fn device_type(&self) -> VirtIoDeviceType {
        self.block.device_type()
    }

    fn device_id(&self) -> u32 {
        self.block.device_id()
    }

    fn vendor_id(&self) -> u32 {
        self.block.vendor_id()
    }

    fn get_features(&self) -> u64 {
        self.block.get_features()
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.block.set_features(features)
    }

    fn get_status(&self) -> u32 {
        self.block.get_status()
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.block.set_status(status)
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        self.block.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        self.block.write_config(offset, data)
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        self.block.queue_notify(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_without_ready_does_not_interrupt() {
        let mut block = VirtIoBlock::new(1024);
        let notified = block.queue_notify(0).unwrap();
        assert!(!notified);
        let (_reads, writes, errors) = block.get_stats();
        assert_eq!(writes, 0);
        assert_eq!(errors, 1);
    }

    #[test]
    fn notify_with_ready_updates_stats() {
        let mut block = VirtIoBlock::new(1024);
        block.set_ready(true);
        let notified = block.queue_notify(0).unwrap();
        assert!(notified);
        let (_reads, writes, errors) = block.get_stats();
        assert_eq!(writes, 1);
        assert_eq!(errors, 0);
    }
}
