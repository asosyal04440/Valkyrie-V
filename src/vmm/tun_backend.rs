//! TAP/TUN network backend for VirtIO Net.
//!
//! Provides real network I/O by interfacing with the host's TAP/TUN device.
//! Falls back to in-memory simulation when TAP/TUN is unavailable.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Maximum packet size (64KB)
pub const MAX_PACKET_SIZE: usize = 65536;

/// Maximum packets in buffer
pub const MAX_BUFFERED_PACKETS: usize = 256;

/// TAP/TUN device types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunType {
    /// TUN device (layer 3, IP packets)
    Tun,
    /// TAP device (layer 2, Ethernet frames)
    Tap,
}

/// TAP/TUN configuration
#[derive(Debug, Clone, Copy)]
pub struct TunConfig {
    /// Device type (TUN or TAP)
    pub tun_type: TunType,
    /// Device name (e.g., "tap0", "tun0")
    pub name: [u8; 16],
    /// MTU
    pub mtu: u16,
    /// Whether to enable non-blocking mode
    pub non_blocking: bool,
}

impl TunConfig {
    pub const fn new_tap() -> Self {
        Self {
            tun_type: TunType::Tap,
            name: [0u8; 16],
            mtu: 1500,
            non_blocking: true,
        }
    }

    pub const fn new_tun() -> Self {
        Self {
            tun_type: TunType::Tun,
            name: [0u8; 16],
            mtu: 1500,
            non_blocking: true,
        }
    }

    pub fn with_name(mut self, name: &str) -> Self {
        let bytes = name.as_bytes();
        let len = bytes.len().min(15);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0; // Null terminator
        self
    }
}

/// TAP/TUN file descriptor (platform-specific)
#[cfg(target_os = "linux")]
pub type TunFd = i32;
#[cfg(target_os = "windows")]
pub type TunFd = *mut core::ffi::c_void;
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub type TunFd = usize;

/// TAP/TUN backend state
pub struct TunBackend {
    /// File descriptor for the TAP/TUN device
    fd: AtomicU64,
    /// Whether the device is open
    is_open: AtomicBool,
    /// Device configuration
    config: TunConfig,
    /// RX packet buffer (host -> guest)
    rx_buffer: [u8; MAX_PACKET_SIZE * 16],
    rx_lengths: [u16; 16],
    rx_head: AtomicU32,
    rx_tail: AtomicU32,
    /// TX packet buffer (guest -> host)
    tx_buffer: [u8; MAX_PACKET_SIZE * 16],
    tx_lengths: [u16; 16],
    tx_head: AtomicU32,
    tx_tail: AtomicU32,
    /// Statistics
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    rx_errors: AtomicU64,
    tx_errors: AtomicU64,
}

impl TunBackend {
    pub const fn new() -> Self {
        Self {
            fd: AtomicU64::new(0),
            is_open: AtomicBool::new(false),
            config: TunConfig::new_tap(),
            rx_buffer: [0u8; MAX_PACKET_SIZE * 16],
            rx_lengths: [0u16; 16],
            rx_head: AtomicU32::new(0),
            rx_tail: AtomicU32::new(0),
            tx_buffer: [0u8; MAX_PACKET_SIZE * 16],
            tx_lengths: [0u16; 16],
            tx_head: AtomicU32::new(0),
            tx_tail: AtomicU32::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_errors: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
        }
    }

    pub fn with_config(mut self, config: TunConfig) -> Self {
        self.config = config;
        self
    }

    /// Open the TAP/TUN device.
    /// Returns true on success.
    #[cfg(target_os = "linux")]
    pub fn open(&mut self) -> bool {
        use core::ptr;
        
        // Open /dev/net/tun
        const O_RDWR: i32 = 2;
        let fd = unsafe {
            libc::open(b"/dev/net/tun\0".as_ptr() as *const i8, O_RDWR)
        };
        
        if fd < 0 {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Configure TUN/TAP device
        #[repr(C)]
        struct IfReq {
            name: [u8; 16],
            flags: i16,
            pad: [u8; 22],
        }

        const IFF_TUN: i16 = 0x0001;
        const IFF_TAP: i16 = 0x0002;
        const IFF_NO_PI: i16 = 0x1000;

        let mut ifr = IfReq {
            name: self.config.name,
            flags: match self.config.tun_type {
                TunType::Tun => IFF_TUN | IFF_NO_PI,
                TunType::Tap => IFF_TAP | IFF_NO_PI,
            },
            pad: [0u8; 22],
        };

        const TUNSETIFF: u64 = 0x400454CA;

        let result = unsafe {
            libc::ioctl(fd, TUNSETIFF as u64, &mut ifr as *mut _ as u64)
        };

        if result < 0 {
            unsafe { libc::close(fd); }
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Set non-blocking if requested
        if self.config.non_blocking {
            const O_NONBLOCK: i32 = 0x800;
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL, 0);
                libc::fcntl(fd, libc::F_SETFL, flags | O_NONBLOCK);
            }
        }

        self.fd.store(fd as u64, Ordering::Release);
        self.is_open.store(true, Ordering::Release);
        true
    }

    #[cfg(target_os = "windows")]
    pub fn open(&mut self) -> bool {
        // Windows TAP driver implementation using WinTUN
        use core::ptr;
        
        // WinTUN driver constants
        const WIN_TUN_TYPE: u32 = 1; // WintunAdapter
        const WIN_TUN_LUID: u64 = 0; // Let system assign
        
        // Try to load WinTUN driver
        // This requires wintun.dll to be present in the system
        // For a no_std environment, we use direct syscalls or pre-loaded function pointers
        
        // Alternative: Use Windows native NDIS TAP driver
        // The TAP-Windows driver from OpenVPN creates a device like:
        // \\.\Global\{GUID}.tap
        
        // For now, we implement a simplified version that:
        // 1. Opens the TAP device if already installed
        // 2. Falls back to in-memory simulation if not available
        
        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        const OPEN_EXISTING: u32 = 3;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        const FILE_FLAG_OVERLAPPED: u32 = 0x40000000;
        
        // Try common TAP device paths
        let tap_paths: [[u8; 64]; 4] = [
            *b"\\\\.\\Global\\{E4AE8230-2B02-4B33-8E46-9B7CD9F63C4E}.tap\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"\\\\.\\tap0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"\\\\.\\Wintun0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            *b"\\\\.\\TAP0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        ];
        
        for path in &tap_paths {
            // Find null terminator
            let len = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            let path_ptr = path.as_ptr();
            
            let handle = unsafe {
                winapi::um::fileapi::CreateFileA(
                    path_ptr as *const i8,
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    ptr::null_mut(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                    ptr::null_mut(),
                )
            };
            
            if !handle.is_null() && handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
                self.fd.store(handle as u64, Ordering::Release);
                self.is_open.store(true, Ordering::Release);
                return true;
            }
        }
        
        // If no TAP device found, try using in-memory simulation mode
        // This allows the VM to run without a physical TAP driver
        // Packets will be buffered internally and can be read by host
        
        // Set a special marker to indicate in-memory mode
        self.fd.store(0xFFFF_FFFF_FFFF_FFFF, Ordering::Release);
        self.is_open.store(true, Ordering::Release);
        true
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn open(&mut self) -> bool {
        self.rx_errors.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Close the TAP/TUN device
    pub fn close(&mut self) {
        let fd = self.fd.load(Ordering::Acquire);
        if fd != 0 {
            #[cfg(target_os = "linux")]
            unsafe {
                libc::close(fd as i32);
            }
            self.fd.store(0, Ordering::Release);
            self.is_open.store(false, Ordering::Release);
        }
    }

    /// Read a packet from the TAP/TUN device (host -> guest).
    /// Returns the number of bytes read, or 0 on error/no data.
    #[cfg(target_os = "linux")]
    pub fn read_packet(&mut self, buf: &mut [u8]) -> usize {
        let fd = self.fd.load(Ordering::Acquire) as i32;
        if fd <= 0 {
            return 0;
        }

        let result = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut i8, buf.len())
        };

        if result > 0 {
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.rx_bytes.fetch_add(result as u64, Ordering::Relaxed);
            result as usize
        } else {
            self.rx_errors.fetch_add(1, Ordering::Relaxed);
            0
        }
    }

    #[cfg(target_os = "windows")]
    pub fn read_packet(&mut self, buf: &mut [u8]) -> usize {
        let fd = self.fd.load(Ordering::Acquire);
        
        // Check for in-memory simulation mode
        if fd == 0xFFFF_FFFF_FFFF_FFFF {
            // Read from internal RX buffer
            return self.dequeue_rx_bytes(buf);
        }
        
        let handle = fd as *mut _;
        if handle.is_null() {
            return 0;
        }
        
        // Use overlapped I/O for async read
        let mut overlapped: winapi::um::minwinbase::OVERLAPPED = unsafe { core::mem::zeroed() };
        let mut bytes_read: u32 = 0;
        
        let result = unsafe {
            winapi::um::fileapi::ReadFile(
                handle,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut bytes_read,
                &mut overlapped,
            )
        };
        
        if result != 0 && bytes_read > 0 {
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.rx_bytes.fetch_add(bytes_read as u64, Ordering::Relaxed);
            bytes_read as usize
        } else {
            // Check for pending I/O
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == winapi::um::errhandlingapi::ERROR_IO_PENDING {
                // I/O is pending - would need completion port
                // For now, return 0 (no data available)
                0
            } else {
                self.rx_errors.fetch_add(1, Ordering::Relaxed);
                0
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn read_packet(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    
    /// Helper to dequeue bytes from RX buffer (for in-memory mode)
    fn dequeue_rx_bytes(&mut self, buf: &mut [u8]) -> usize {
        let head = self.rx_head.load(Ordering::Acquire) as usize;
        let tail = self.rx_tail.load(Ordering::Acquire) as usize;
        
        if head == tail {
            return 0; // Buffer empty
        }
        
        let offset = head * MAX_PACKET_SIZE;
        let len = self.rx_lengths[head] as usize;
        let copy_len = len.min(buf.len());
        buf[..copy_len].copy_from_slice(&self.rx_buffer[offset..offset + copy_len]);
        
        let next = (head + 1) % 16;
        self.rx_head.store(next as u32, Ordering::Release);
        
        copy_len
    }

    /// Write a packet to the TAP/TUN device (guest -> host).
    /// Returns true on success.
    #[cfg(target_os = "linux")]
    pub fn write_packet(&mut self, data: &[u8]) -> bool {
        let fd = self.fd.load(Ordering::Acquire) as i32;
        if fd <= 0 {
            return false;
        }

        let result = unsafe {
            libc::write(fd, data.as_ptr() as *const i8, data.len())
        };

        if result > 0 {
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(result as u64, Ordering::Relaxed);
            true
        } else {
            self.tx_errors.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    #[cfg(target_os = "windows")]
    pub fn write_packet(&mut self, data: &[u8]) -> bool {
        let fd = self.fd.load(Ordering::Acquire);
        
        // Check for in-memory simulation mode
        if fd == 0xFFFF_FFFF_FFFF_FFFF {
            // Store in internal TX buffer
            return self.enqueue_tx_bytes(data);
        }
        
        let handle = fd as *mut _;
        if handle.is_null() {
            return false;
        }
        
        // Use overlapped I/O for async write
        let mut overlapped: winapi::um::minwinbase::OVERLAPPED = unsafe { core::mem::zeroed() };
        let mut bytes_written: u32 = 0;
        
        let result = unsafe {
            winapi::um::fileapi::WriteFile(
                handle,
                data.as_ptr() as *const _,
                data.len() as u32,
                &mut bytes_written,
                &mut overlapped,
            )
        };
        
        if result != 0 && bytes_written > 0 {
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(bytes_written as u64, Ordering::Relaxed);
            true
        } else {
            let error = unsafe { winapi::um::errhandlingapi::GetLastError() };
            if error == winapi::um::errhandlingapi::ERROR_IO_PENDING {
                // I/O is pending - count as success
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                true
            } else {
                self.tx_errors.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    pub fn write_packet(&mut self, _data: &[u8]) -> bool {
        false
    }
    
    /// Helper to enqueue bytes to TX buffer (for in-memory mode)
    fn enqueue_tx_bytes(&mut self, data: &[u8]) -> bool {
        let tail = self.tx_tail.load(Ordering::Acquire) as usize;
        let next = (tail + 1) % 16;
        let head = self.tx_head.load(Ordering::Acquire) as usize;
        
        if next == head {
            return false; // Buffer full
        }
        
        let offset = tail * MAX_PACKET_SIZE;
        let len = data.len().min(MAX_PACKET_SIZE);
        self.tx_buffer[offset..offset + len].copy_from_slice(&data[..len]);
        self.tx_lengths[tail] = len as u16;
        self.tx_tail.store(next as u32, Ordering::Release);
        
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        true
    }

    /// Enqueue a packet for RX (simulated when TAP/TUN unavailable)
    pub fn enqueue_rx(&mut self, data: &[u8]) -> bool {
        let tail = self.rx_tail.load(Ordering::Acquire) as usize;
        let next = (tail + 1) % 16;
        let head = self.rx_head.load(Ordering::Acquire) as usize;
        
        if next == head {
            return false; // Buffer full
        }

        let offset = tail * MAX_PACKET_SIZE;
        let len = data.len().min(MAX_PACKET_SIZE);
        self.rx_buffer[offset..offset + len].copy_from_slice(&data[..len]);
        self.rx_lengths[tail] = len as u16;
        self.rx_tail.store(next as u32, Ordering::Release);
        
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
        true
    }

    /// Dequeue a packet from RX buffer
    pub fn dequeue_rx(&mut self) -> Option<&[u8]> {
        let head = self.rx_head.load(Ordering::Acquire) as usize;
        let tail = self.rx_tail.load(Ordering::Acquire) as usize;
        
        if head == tail {
            return None;
        }

        let offset = head * MAX_PACKET_SIZE;
        let len = self.rx_lengths[head] as usize;
        let next = (head + 1) % 16;
        self.rx_head.store(next as u32, Ordering::Release);
        
        Some(&self.rx_buffer[offset..offset + len])
    }

    /// Enqueue a packet for TX
    pub fn enqueue_tx(&mut self, data: &[u8]) -> bool {
        let tail = self.tx_tail.load(Ordering::Acquire) as usize;
        let next = (tail + 1) % 16;
        let head = self.tx_head.load(Ordering::Acquire) as usize;
        
        if next == head {
            return false;
        }

        let offset = tail * MAX_PACKET_SIZE;
        let len = data.len().min(MAX_PACKET_SIZE);
        self.tx_buffer[offset..offset + len].copy_from_slice(&data[..len]);
        self.tx_lengths[tail] = len as u16;
        self.tx_tail.store(next as u32, Ordering::Release);
        true
    }

    /// Dequeue a packet from TX buffer
    pub fn dequeue_tx(&mut self) -> Option<&[u8]> {
        let head = self.tx_head.load(Ordering::Acquire) as usize;
        let tail = self.tx_tail.load(Ordering::Acquire) as usize;
        
        if head == tail {
            return None;
        }

        let offset = head * MAX_PACKET_SIZE;
        let len = self.tx_lengths[head] as usize;
        let next = (head + 1) % 16;
        self.tx_head.store(next as u32, Ordering::Release);
        
        Some(&self.tx_buffer[offset..offset + len])
    }

    /// Process TX queue - send packets to TAP/TUN
    pub fn process_tx(&mut self) -> u32 {
        let mut sent = 0u32;
        while let Some(data) = self.dequeue_tx() {
            if self.write_packet(data) {
                sent += 1;
            } else {
                break;
            }
        }
        sent
    }

    /// Process RX - read packets from TAP/TUN into buffer
    pub fn process_rx(&mut self) -> u32 {
        let mut received = 0u32;
        let mut buf = [0u8; MAX_PACKET_SIZE];
        
        loop {
            let len = self.read_packet(&mut buf);
            if len == 0 {
                break;
            }
            if !self.enqueue_rx(&buf[..len]) {
                break;
            }
            received += 1;
        }
        received
    }

    /// Check if device is open
    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::Acquire)
    }

    /// Check if there are pending RX packets
    pub fn has_rx(&self) -> bool {
        self.rx_head.load(Ordering::Acquire) != self.rx_tail.load(Ordering::Acquire)
    }

    /// Check if there are pending TX packets
    pub fn has_tx(&self) -> bool {
        self.tx_head.load(Ordering::Acquire) != self.tx_tail.load(Ordering::Acquire)
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Acquire),
            self.tx_packets.load(Ordering::Acquire),
            self.rx_bytes.load(Ordering::Acquire),
            self.tx_bytes.load(Ordering::Acquire),
            self.rx_errors.load(Ordering::Acquire),
            self.tx_errors.load(Ordering::Acquire),
        )
    }
}

impl Default for TunBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TunBackend {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_backend_creation() {
        let tun = TunBackend::new();
        assert!(!tun.is_open());
    }

    #[test]
    fn enqueue_dequeue_rx() {
        let mut tun = TunBackend::new();
        let packet = [0xFF; 64];
        
        assert!(tun.enqueue_rx(&packet));
        let received = tun.dequeue_rx().unwrap();
        assert_eq!(received.len(), 64);
    }

    #[test]
    fn enqueue_dequeue_tx() {
        let mut tun = TunBackend::new();
        let packet = [0xAA; 128];
        
        assert!(tun.enqueue_tx(&packet));
        let sent = tun.dequeue_tx().unwrap();
        assert_eq!(sent.len(), 128);
    }
}
