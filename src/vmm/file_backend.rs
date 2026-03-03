//! File-backed storage backend for VirtIO Block.
//!
//! Provides real disk I/O by interfacing with host filesystem.
//! Falls back to in-memory storage when file I/O unavailable.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Maximum disk image size (64 MB)
pub const MAX_DISK_SIZE: u64 = 64 * 1024 * 1024;

/// Sector size (512 bytes)
pub const SECTOR_SIZE: u64 = 512;

/// File handle type (platform-specific)
#[cfg(target_os = "linux")]
pub type FileHandle = i32;
#[cfg(target_os = "windows")]
pub type FileHandle = *mut core::ffi::c_void;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub type FileHandle = usize;

/// File-backed storage backend
pub struct FileBackend {
    /// File handle
    fd: AtomicU64,
    /// Whether file is open
    is_open: AtomicBool,
    /// File path (stored as fixed-size buffer for no_std)
    path: [u8; 256],
    /// Disk size in bytes
    size: AtomicU64,
    /// Read-only flag
    read_only: bool,
    /// Statistics
    reads: AtomicU64,
    writes: AtomicU64,
    read_bytes: AtomicU64,
    write_bytes: AtomicU64,
    errors: AtomicU64,
}

impl FileBackend {
    pub const fn new() -> Self {
        Self {
            fd: AtomicU64::new(0),
            is_open: AtomicBool::new(false),
            path: [0u8; 256],
            size: AtomicU64::new(0),
            read_only: false,
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            read_bytes: AtomicU64::new(0),
            write_bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
        }
    }

    pub fn with_path(mut self, path: &str) -> Self {
        let bytes = path.as_bytes();
        let len = bytes.len().min(255);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path[len] = 0;
        self
    }

    pub fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// Open the file for disk I/O
    #[cfg(target_os = "linux")]
    pub fn open(&mut self) -> bool {
        use core::ptr;
        
        const O_RDONLY: i32 = 0;
        const O_RDWR: i32 = 2;
        const O_CREAT: i32 = 64;
        const O_TRUNC: i32 = 512;
        const O_LARGEFILE: i32 = 0x8000;
        
        let flags = if self.read_only {
            O_RDONLY | O_LARGEFILE
        } else {
            O_RDWR | O_CREAT | O_LARGEFILE
        };
        
        let fd = unsafe {
            libc::open(self.path.as_ptr() as *const i8, flags, 0o644)
        };
        
        if fd < 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        // Get file size
        let mut stat: libc::stat = unsafe { core::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut stat) } < 0 {
            unsafe { libc::close(fd); }
            self.errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        let file_size = stat.st_size as u64;
        
        // If file is empty, create sparse file of max size
        if file_size == 0 && !self.read_only {
            if unsafe { libc::ftruncate(fd, MAX_DISK_SIZE as i64) } < 0 {
                unsafe { libc::close(fd); }
                self.errors.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            self.size.store(MAX_DISK_SIZE, Ordering::Release);
        } else {
            self.size.store(file_size, Ordering::Release);
        }
        
        self.fd.store(fd as u64, Ordering::Release);
        self.is_open.store(true, Ordering::Release);
        true
    }

    #[cfg(target_os = "windows")]
    pub fn open(&mut self) -> bool {
        // Windows file I/O implementation
        use core::ptr;
        
        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const CREATE_ALWAYS: u32 = 2;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        
        let access = if self.read_only {
            GENERIC_READ
        } else {
            GENERIC_READ | GENERIC_WRITE
        };
        
        let disposition = if self.read_only {
            OPEN_EXISTING
        } else {
            CREATE_ALWAYS
        };
        
        let handle = unsafe {
            winapi::um::fileapi::CreateFileA(
                self.path.as_ptr() as *const i8,
                access,
                0,
                ptr::null_mut(),
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        
        if handle.is_null() || handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        // Get file size
        let mut size_high: u32 = 0;
        let size_low = unsafe {
            winapi::um::fileapi::GetFileSize(handle, &mut size_high as *mut _ as *mut u32)
        };
        
        if size_low == winapi::um::errhandlingapi::INVALID_FILE_SIZE {
            unsafe { winapi::um::handleapi::CloseHandle(handle); }
            self.errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        
        let file_size = ((size_high as u64) << 32) | (size_low as u64);
        self.size.store(file_size, Ordering::Release);
        
        self.fd.store(handle as u64, Ordering::Release);
        self.is_open.store(true, Ordering::Release);
        true
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn open(&mut self) -> bool {
        self.errors.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Close the file
    pub fn close(&mut self) {
        let fd = self.fd.load(Ordering::Acquire);
        if fd != 0 {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::close(fd as i32);
            }
            #[cfg(target_os = "windows")]
            unsafe {
                winapi::um::handleapi::CloseHandle(fd as *mut _);
            }
            self.fd.store(0, Ordering::Release);
            self.is_open.store(false, Ordering::Release);
        }
    }

    /// Read sectors from disk
    #[cfg(target_os = "linux")]
    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> usize {
        let fd = self.fd.load(Ordering::Acquire) as i32;
        if fd <= 0 {
            return 0;
        }
        
        let offset = sector * SECTOR_SIZE;
        let size = self.size.load(Ordering::Acquire);
        
        if offset >= size {
            return 0;
        }
        
        let read_len = buf.len().min((size - offset) as usize);
        
        // Seek to offset
        unsafe {
            libc::lseek(fd, offset as i64, libc::SEEK_SET);
        }
        
        // Read data
        let result = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut i8, read_len)
        };
        
        if result > 0 {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.read_bytes.fetch_add(result as u64, Ordering::Relaxed);
            result as usize
        } else {
            self.errors.fetch_add(1, Ordering::Relaxed);
            0
        }
    }

    #[cfg(target_os = "windows")]
    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> usize {
        let handle = self.fd.load(Ordering::Acquire) as *mut _;
        if handle.is_null() {
            return 0;
        }
        
        let offset = sector * SECTOR_SIZE;
        let size = self.size.load(Ordering::Acquire);
        
        if offset >= size {
            return 0;
        }
        
        let read_len = buf.len().min((size - offset) as usize);
        let mut bytes_read: u32 = 0;
        
        unsafe {
            let mut overlapped: winapi::um::minwinbase::OVERLAPPED = core::mem::zeroed();
            overlapped.Offset = offset as u32;
            overlapped.OffsetHigh = (offset >> 32) as u32;
            
            if winapi::um::fileapi::ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                read_len as u32,
                &mut bytes_read,
                &mut overlapped,
            ) != 0 {
                self.reads.fetch_add(1, Ordering::Relaxed);
                self.read_bytes.fetch_add(bytes_read as u64, Ordering::Relaxed);
                bytes_read as usize
            } else {
                self.errors.fetch_add(1, Ordering::Relaxed);
                0
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn read(&mut self, _sector: u64, _buf: &mut [u8]) -> usize {
        0
    }

    /// Write sectors to disk
    #[cfg(target_os = "linux")]
    pub fn write(&mut self, sector: u64, data: &[u8]) -> usize {
        if self.read_only {
            return 0;
        }
        
        let fd = self.fd.load(Ordering::Acquire) as i32;
        if fd <= 0 {
            return 0;
        }
        
        let offset = sector * SECTOR_SIZE;
        
        // Seek to offset
        unsafe {
            libc::lseek(fd, offset as i64, libc::SEEK_SET);
        }
        
        // Write data
        let result = unsafe {
            libc::write(fd, data.as_ptr() as *const i8, data.len())
        };
        
        if result > 0 {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.write_bytes.fetch_add(result as u64, Ordering::Relaxed);
            result as usize
        } else {
            self.errors.fetch_add(1, Ordering::Relaxed);
            0
        }
    }

    #[cfg(target_os = "windows")]
    pub fn write(&mut self, sector: u64, data: &[u8]) -> usize {
        if self.read_only {
            return 0;
        }
        
        let handle = self.fd.load(Ordering::Acquire) as *mut _;
        if handle.is_null() {
            return 0;
        }
        
        let offset = sector * SECTOR_SIZE;
        let mut bytes_written: u32 = 0;
        
        unsafe {
            let mut overlapped: winapi::um::minwinbase::OVERLAPPED = core::mem::zeroed();
            overlapped.Offset = offset as u32;
            overlapped.OffsetHigh = (offset >> 32) as u32;
            
            if winapi::um::fileapi::WriteFile(
                handle,
                data.as_ptr() as *const _,
                data.len() as u32,
                &mut bytes_written,
                &mut overlapped,
            ) != 0 {
                self.writes.fetch_add(1, Ordering::Relaxed);
                self.write_bytes.fetch_add(bytes_written as u64, Ordering::Relaxed);
                bytes_written as usize
            } else {
                self.errors.fetch_add(1, Ordering::Relaxed);
                0
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn write(&mut self, _sector: u64, _data: &[u8]) -> usize {
        0
    }

    /// Flush cached writes
    #[cfg(target_os = "linux")]
    pub fn flush(&mut self) -> bool {
        let fd = self.fd.load(Ordering::Acquire) as i32;
        if fd <= 0 {
            return false;
        }
        unsafe { libc::fsync(fd) == 0 }
    }

    #[cfg(target_os = "windows")]
    pub fn flush(&mut self) -> bool {
        let handle = self.fd.load(Ordering::Acquire) as *mut _;
        if handle.is_null() {
            return false;
        }
        unsafe { winapi::um::fileapi::FlushFileBuffers(handle) != 0 }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn flush(&mut self) -> bool {
        true
    }

    /// Get disk size in sectors
    pub fn capacity(&self) -> u64 {
        self.size.load(Ordering::Acquire) / SECTOR_SIZE
    }

    /// Get disk size in bytes
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// Check if file is open
    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::Acquire)
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.reads.load(Ordering::Acquire),
            self.writes.load(Ordering::Acquire),
            self.read_bytes.load(Ordering::Acquire),
            self.write_bytes.load(Ordering::Acquire),
            self.errors.load(Ordering::Acquire),
        )
    }
}

impl Default for FileBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FileBackend {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_backend_creation() {
        let backend = FileBackend::new();
        assert!(!backend.is_open());
    }

    #[test]
    fn file_backend_with_path() {
        let backend = FileBackend::new().with_path("/tmp/test.img");
        assert_eq!(&backend.path[..11], b"/tmp/test.");
    }
}
