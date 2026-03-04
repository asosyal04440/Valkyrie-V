//! vhost-user Backend
//!
//! Zero-copy I/O with shared memory rings and userspace backend integration.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// vhost-user Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum vhost devices
pub const MAX_VHOST_DEVICES: usize = 32;

/// Maximum queues per device
pub const MAX_VHOST_QUEUES: usize = 16;

/// Maximum memory regions
pub const MAX_MEM_REGIONS: usize = 8;

/// Maximum log regions
pub const MAX_LOG_REGIONS: usize = 8;

/// vhost-user protocol features
pub mod vhost_feature {
    pub const PROTOCOL_FEATURES: u64 = 1 << 63;
    pub const MQ: u64 = 1 << 0;
    pub const LOG_SHMFD: u64 = 1 << 1;
    pub const RARP: u64 = 1 << 2;
    pub const MTU: u64 = 1 << 3;
    pub const SLAVE_SEND_FD: u64 = 1 << 4;
    pub const SLAVE_REQ: u64 = 1 << 5;
    pub const CRYPTO_SESSION: u64 = 1 << 6;
    pub const PAGEFAULT: u64 = 1 << 7;
    pub const CONFIGURE_MEM_SLOTS: u64 = 1 << 8;
    pub const PROTOCOL_UNSET: u64 = 1 << 9;
    pub const INFLIGHT_SHMFD: u64 = 1 << 10;
    pub const RESET_DEVICE: u64 = 1 << 11;
    pub const STOP: u64 = 1 << 12;
    pub const STATUS: u64 = 1 << 15;
}

/// vhost-user request types
pub mod vhost_req {
    pub const GET_FEATURES: u32 = 1;
    pub const SET_FEATURES: u32 = 2;
    pub const SET_OWNER: u32 = 3;
    pub const RESET_OWNER: u32 = 4;
    pub const SET_MEM_TABLE: u32 = 5;
    pub const SET_LOG_BASE: u32 = 6;
    pub const SET_LOG_FD: u32 = 7;
    pub const SET_VRING_NUM: u32 = 8;
    pub const SET_VRING_ADDR: u32 = 9;
    pub const SET_VRING_BASE: u32 = 10;
    pub const GET_VRING_BASE: u32 = 11;
    pub const SET_VRING_KICK: u32 = 12;
    pub const SET_VRING_CALL: u32 = 13;
    pub const SET_VRING_ERR: u32 = 14;
    pub const GET_PROTOCOL_FEATURES: u32 = 15;
    pub const SET_PROTOCOL_FEATURES: u32 = 16;
    pub const GET_QUEUE_NUM: u32 = 17;
    pub const SET_VRING_ENABLE: u32 = 18;
    pub const SEND_RARP: u32 = 19;
    pub const NET_SET_MTU: u32 = 20;
    pub const SET_SLAVE_REQ_FD: u32 = 21;
    pub const IOTLB_MSG: u32 = 22;
    pub const GET_CONFIG: u32 = 23;
    pub const SET_CONFIG: u32 = 24;
    pub const VRING_SET_LAYOUT: u32 = 25;
    pub const SET_INFLIGHT_FD: u32 = 26;
    pub const RESET_DEVICE: u32 = 27;
    pub const STOP: u32 = 28;
    pub const GET_STATUS: u32 = 29;
    pub const SET_STATUS: u32 = 30;
}

/// vhost-user message flags
pub mod vhost_msg_flag {
    pub const NEED_REPLY: u32 = 1 << 0;
    pub const REPLY: u32 = 1 << 1;
    pub const REPLY_ACK: u32 = 1 << 2;
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Region
// ─────────────────────────────────────────────────────────────────────────────

/// Memory region for vhost-user
pub struct VhostMemRegion {
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Host virtual address (in shared memory)
    pub hva: AtomicU64,
    /// Memory flags
    pub flags: AtomicU64,
    /// File offset
    pub offset: AtomicU64,
    /// File descriptor index
    pub fd_idx: AtomicU8,
    /// Valid
    pub valid: AtomicBool,
}

impl VhostMemRegion {
    pub const fn new() -> Self {
        Self {
            gpa: AtomicU64::new(0),
            size: AtomicU64::new(0),
            hva: AtomicU64::new(0),
            flags: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            fd_idx: AtomicU8::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, gpa: u64, size: u64, hva: u64, flags: u64) {
        self.gpa.store(gpa, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.hva.store(hva, Ordering::Release);
        self.flags.store(flags, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check if address is in region
    pub fn contains(&self, gpa: u64) -> bool {
        let start = self.gpa.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        gpa >= start && gpa < start + size
    }

    /// Translate GPA to HVA
    pub fn translate(&self, gpa: u64) -> Option<u64> {
        if !self.contains(gpa) {
            return None;
        }
        
        let gpa_start = self.gpa.load(Ordering::Acquire);
        let hva_start = self.hva.load(Ordering::Acquire);
        
        Some(hva_start + (gpa - gpa_start))
    }
}

impl Default for VhostMemRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// vring State
// ─────────────────────────────────────────────────────────────────────────────

/// vring state for vhost-user
pub struct VhostVringState {
    /// Queue index
    pub index: AtomicU16,
    /// Number of descriptors
    pub num: AtomicU16,
    /// Descriptor table address (GPA)
    pub desc_addr: AtomicU64,
    /// Available ring address (GPA)
    pub avail_addr: AtomicU64,
    /// Used ring address (GPA)
    pub used_addr: AtomicU64,
    /// Available ring base index
    pub avail_base: AtomicU16,
    /// Used ring base index
    pub used_base: AtomicU16,
    /// Kick eventfd index
    pub kick_fd: AtomicU8,
    /// Call eventfd index
    pub call_fd: AtomicU8,
    /// Error eventfd index
    pub err_fd: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Running
    pub running: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl VhostVringState {
    pub const fn new() -> Self {
        Self {
            index: AtomicU16::new(0),
            num: AtomicU16::new(0),
            desc_addr: AtomicU64::new(0),
            avail_addr: AtomicU64::new(0),
            used_addr: AtomicU64::new(0),
            avail_base: AtomicU16::new(0),
            used_base: AtomicU16::new(0),
            kick_fd: AtomicU8::new(0xFF),
            call_fd: AtomicU8::new(0xFF),
            err_fd: AtomicU8::new(0xFF),
            enabled: AtomicBool::new(false),
            running: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize vring
    pub fn init(&self, index: u16, num: u16) {
        self.index.store(index, Ordering::Release);
        self.num.store(num, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set addresses
    pub fn set_addresses(&self, desc: u64, avail: u64, used: u64) {
        self.desc_addr.store(desc, Ordering::Release);
        self.avail_addr.store(avail, Ordering::Release);
        self.used_addr.store(used, Ordering::Release);
    }

    /// Set base
    pub fn set_base(&self, avail: u16, used: u16) {
        self.avail_base.store(avail, Ordering::Release);
        self.used_base.store(used, Ordering::Release);
    }

    /// Set eventfds
    pub fn set_fds(&self, kick: u8, call: u8, err: u8) {
        self.kick_fd.store(kick, Ordering::Release);
        self.call_fd.store(call, Ordering::Release);
        self.err_fd.store(err, Ordering::Release);
    }

    /// Enable vring
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable vring
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        self.running.store(false, Ordering::Release);
    }

    /// Start vring
    pub fn start(&self) {
        self.running.store(true, Ordering::Release);
    }

    /// Stop vring
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
    }
}

impl Default for VhostVringState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// vhost-user Message
// ─────────────────────────────────────────────────────────────────────────────

/// vhost-user message header
pub struct VhostMsgHeader {
    /// Request type
    pub request: AtomicU32,
    /// Flags
    pub flags: AtomicU32,
    /// Size of payload
    pub size: AtomicU32,
}

impl VhostMsgHeader {
    pub const fn new() -> Self {
        Self {
            request: AtomicU32::new(0),
            flags: AtomicU32::new(0),
            size: AtomicU32::new(0),
        }
    }

    /// Initialize header
    pub fn init(&self, request: u32, flags: u32, size: u32) {
        self.request.store(request, Ordering::Release);
        self.flags.store(flags, Ordering::Release);
        self.size.store(size, Ordering::Release);
    }

    /// Needs reply
    pub fn needs_reply(&self) -> bool {
        self.flags.load(Ordering::Acquire) & vhost_msg_flag::NEED_REPLY != 0
    }

    /// Is reply
    pub fn is_reply(&self) -> bool {
        self.flags.load(Ordering::Acquire) & vhost_msg_flag::REPLY != 0
    }
}

impl Default for VhostMsgHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// vhost-user message payload (union-like)
pub struct VhostMsgPayload {
    /// u64 value (features, base, etc)
    pub u64: AtomicU64,
    /// vring state
    pub vring_state: [AtomicU64; 2], // index, num
    /// Memory region data
    pub mem_region: [AtomicU64; 4],  // gpa, size, hva, flags
    /// Config data
    pub config: [AtomicU8; 256],
}

impl VhostMsgPayload {
    pub const fn new() -> Self {
        Self {
            u64: AtomicU64::new(0),
            vring_state: [const { AtomicU64::new(0) }; 2],
            mem_region: [const { AtomicU64::new(0) }; 4],
            config: [const { AtomicU8::new(0) }; 256],
        }
    }
}

impl Default for VhostMsgPayload {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// vhost-user Device
// ─────────────────────────────────────────────────────────────────────────────

/// vhost-user device state
pub struct VhostDevice {
    /// Device ID
    pub device_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Device type
    pub device_type: AtomicU8,
    /// Feature bits
    pub features: AtomicU64,
    /// Protocol features
    pub protocol_features: AtomicU64,
    /// Memory regions
    pub mem_regions: [VhostMemRegion; MAX_MEM_REGIONS],
    /// Memory region count
    pub mem_region_count: AtomicU8,
    /// vrings
    pub vrings: [VhostVringState; MAX_VHOST_QUEUES],
    /// vring count
    pub vring_count: AtomicU8,
    /// Socket path hash
    pub socket_hash: AtomicU64,
    /// Connected
    pub connected: AtomicBool,
    /// Running
    pub running: AtomicBool,
    /// Zero-copy enabled
    pub zero_copy: AtomicBool,
    /// Log enabled
    pub log_enabled: AtomicBool,
    /// Log base address
    pub log_base: AtomicU64,
    /// Inflight enabled
    pub inflight_enabled: AtomicBool,
    /// Inflight address
    pub inflight_addr: AtomicU64,
    /// Messages processed
    pub msg_processed: AtomicU64,
    /// Bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Zero-copy hits
    pub zero_copy_hits: AtomicU64,
    /// Zero-copy misses
    pub zero_copy_misses: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VhostDevice {
    pub const fn new() -> Self {
        Self {
            device_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            device_type: AtomicU8::new(0),
            features: AtomicU64::new(0),
            protocol_features: AtomicU64::new(0),
            mem_regions: [const { VhostMemRegion::new() }; MAX_MEM_REGIONS],
            mem_region_count: AtomicU8::new(0),
            vrings: [const { VhostVringState::new() }; MAX_VHOST_QUEUES],
            vring_count: AtomicU8::new(0),
            socket_hash: AtomicU64::new(0),
            connected: AtomicBool::new(false),
            running: AtomicBool::new(false),
            zero_copy: AtomicBool::new(true),
            log_enabled: AtomicBool::new(false),
            log_base: AtomicU64::new(0),
            inflight_enabled: AtomicBool::new(false),
            inflight_addr: AtomicU64::new(0),
            msg_processed: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            zero_copy_hits: AtomicU64::new(0),
            zero_copy_misses: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize device
    pub fn init(&self, device_id: u32, vm_id: u32, device_type: u8) {
        self.device_id.store(device_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.device_type.store(device_type, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set features
    pub fn set_features(&self, features: u64) {
        self.features.store(features, Ordering::Release);
    }

    /// Set protocol features
    pub fn set_protocol_features(&self, features: u64) {
        self.protocol_features.store(features, Ordering::Release);
    }

    /// Add memory region
    pub fn add_mem_region(&self, gpa: u64, size: u64, hva: u64, flags: u64) -> Result<u8, HvError> {
        let count = self.mem_region_count.load(Ordering::Acquire);
        if count as usize >= MAX_MEM_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.mem_regions[count as usize].init(gpa, size, hva, flags);
        self.mem_region_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Translate GPA to HVA
    pub fn translate_gpa(&self, gpa: u64) -> Option<u64> {
        for i in 0..self.mem_region_count.load(Ordering::Acquire) as usize {
            if let Some(hva) = self.mem_regions[i].translate(gpa) {
                return Some(hva);
            }
        }
        None
    }

    /// Add vring
    pub fn add_vring(&self, index: u16, num: u16) -> Result<u8, HvError> {
        let count = self.vring_count.load(Ordering::Acquire);
        if count as usize >= MAX_VHOST_QUEUES {
            return Err(HvError::LogicalFault);
        }
        
        self.vrings[count as usize].init(index, num);
        self.vring_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get vring
    pub fn get_vring(&self, index: u16) -> Option<&VhostVringState> {
        for i in 0..self.vring_count.load(Ordering::Acquire) as usize {
            if self.vrings[i].index.load(Ordering::Acquire) == index {
                return Some(&self.vrings[i]);
            }
        }
        None
    }

    /// Start device
    pub fn start(&self) {
        self.running.store(true, Ordering::Release);
        
        for i in 0..self.vring_count.load(Ordering::Acquire) as usize {
            self.vrings[i].start();
        }
    }

    /// Stop device
    pub fn stop(&self) {
        self.running.store(false, Ordering::Release);
        
        for i in 0..self.vring_count.load(Ordering::Acquire) as usize {
            self.vrings[i].stop();
        }
    }

    /// Enable zero-copy
    pub fn enable_zero_copy(&self, enable: bool) {
        self.zero_copy.store(enable, Ordering::Release);
    }

    /// Process zero-copy I/O
    pub fn process_zero_copy(&self, gpa: u64, len: u64, is_write: bool) -> bool {
        if !self.zero_copy.load(Ordering::Acquire) {
            self.zero_copy_misses.fetch_add(1, Ordering::Release);
            return false;
        }
        
        // Translate GPA to HVA
        if let Some(_hva) = self.translate_gpa(gpa) {
            // Would perform direct memory access
            self.zero_copy_hits.fetch_add(1, Ordering::Release);
            self.bytes_transferred.fetch_add(len, Ordering::Release);
            true
        } else {
            self.zero_copy_misses.fetch_add(1, Ordering::Release);
            false
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> VhostStats {
        VhostStats {
            connected: self.connected.load(Ordering::Acquire),
            running: self.running.load(Ordering::Acquire),
            vring_count: self.vring_count.load(Ordering::Acquire),
            mem_region_count: self.mem_region_count.load(Ordering::Acquire),
            msg_processed: self.msg_processed.load(Ordering::Acquire),
            bytes_transferred: self.bytes_transferred.load(Ordering::Acquire),
            zero_copy_hits: self.zero_copy_hits.load(Ordering::Acquire),
            zero_copy_misses: self.zero_copy_misses.load(Ordering::Acquire),
        }
    }
}

impl Default for VhostDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// vhost statistics
#[repr(C)]
pub struct VhostStats {
    pub connected: bool,
    pub running: bool,
    pub vring_count: u8,
    pub mem_region_count: u8,
    pub msg_processed: u64,
    pub bytes_transferred: u64,
    pub zero_copy_hits: u64,
    pub zero_copy_misses: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// vhost-user Controller
// ─────────────────────────────────────────────────────────────────────────────

/// vhost-user controller
pub struct VhostController {
    /// Devices
    pub devices: [VhostDevice; MAX_VHOST_DEVICES],
    /// Device count
    pub device_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Zero-copy enabled globally
    pub zero_copy_enabled: AtomicBool,
    /// DPDK integration
    pub dpdk_enabled: AtomicBool,
    /// Total messages
    pub total_messages: AtomicU64,
    /// Total bytes
    pub total_bytes: AtomicU64,
    /// Total zero-copy hits
    pub total_zero_copy_hits: AtomicU64,
    /// Total zero-copy misses
    pub total_zero_copy_misses: AtomicU64,
}

impl VhostController {
    pub const fn new() -> Self {
        Self {
            devices: [const { VhostDevice::new() }; MAX_VHOST_DEVICES],
            device_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            zero_copy_enabled: AtomicBool::new(true),
            dpdk_enabled: AtomicBool::new(false),
            total_messages: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_zero_copy_hits: AtomicU64::new(0),
            total_zero_copy_misses: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, zero_copy: bool, dpdk: bool) {
        self.zero_copy_enabled.store(zero_copy, Ordering::Release);
        self.dpdk_enabled.store(dpdk, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Create device
    pub fn create_device(&mut self, vm_id: u32, device_type: u8) -> Result<u32, HvError> {
        let count = self.device_count.load(Ordering::Acquire);
        if count as usize >= MAX_VHOST_DEVICES {
            return Err(HvError::LogicalFault);
        }
        
        let device_id = count as u32 + 1;
        let device = &self.devices[count as usize];
        device.init(device_id, vm_id, device_type);
        device.enable_zero_copy(self.zero_copy_enabled.load(Ordering::Acquire));
        
        self.device_count.fetch_add(1, Ordering::Release);
        Ok(device_id)
    }

    /// Get device
    pub fn get_device(&self, device_id: u32) -> Option<&VhostDevice> {
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            if self.devices[i].device_id.load(Ordering::Acquire) == device_id {
                return Some(&self.devices[i]);
            }
        }
        None
    }

    /// Handle vhost-user message
    pub fn handle_message(&self, device_id: u32, request: u32, 
                          payload: &VhostMsgPayload) -> Result<u64, HvError> {
        let device = self.get_device(device_id).ok_or(HvError::LogicalFault)?;
        
        device.msg_processed.fetch_add(1, Ordering::Release);
        self.total_messages.fetch_add(1, Ordering::Release);
        
        match request {
            vhost_req::GET_FEATURES => {
                Ok(device.features.load(Ordering::Acquire))
            }
            vhost_req::SET_FEATURES => {
                device.set_features(payload.u64.load(Ordering::Acquire));
                Ok(0)
            }
            vhost_req::GET_PROTOCOL_FEATURES => {
                Ok(device.protocol_features.load(Ordering::Acquire))
            }
            vhost_req::SET_PROTOCOL_FEATURES => {
                device.set_protocol_features(payload.u64.load(Ordering::Acquire));
                Ok(0)
            }
            vhost_req::SET_MEM_TABLE => {
                // Would process memory table
                Ok(0)
            }
            vhost_req::SET_VRING_NUM => {
                let index = payload.vring_state[0].load(Ordering::Acquire) as u16;
                let num = payload.vring_state[1].load(Ordering::Acquire) as u16;
                
                if let Some(vring) = device.get_vring(index) {
                    vring.num.store(num, Ordering::Release);
                }
                Ok(0)
            }
            vhost_req::SET_VRING_ADDR => {
                let index = payload.vring_state[0].load(Ordering::Acquire) as u16;
                // Would process address structure
                Ok(0)
            }
            vhost_req::SET_VRING_BASE => {
                let index = payload.vring_state[0].load(Ordering::Acquire) as u16;
                let base = payload.vring_state[1].load(Ordering::Acquire) as u16;
                
                if let Some(vring) = device.get_vring(index) {
                    vring.avail_base.store(base, Ordering::Release);
                }
                Ok(0)
            }
            vhost_req::GET_VRING_BASE => {
                let index = payload.vring_state[0].load(Ordering::Acquire) as u16;
                
                if let Some(vring) = device.get_vring(index) {
                    Ok(vring.used_base.load(Ordering::Acquire) as u64)
                } else {
                    Ok(0)
                }
            }
            vhost_req::SET_VRING_ENABLE => {
                let index = payload.vring_state[0].load(Ordering::Acquire) as u16;
                let enable = payload.vring_state[1].load(Ordering::Acquire) != 0;
                
                if let Some(vring) = device.get_vring(index) {
                    if enable {
                        vring.enable();
                    } else {
                        vring.disable();
                    }
                }
                Ok(0)
            }
            vhost_req::SET_OWNER => {
                device.connected.store(true, Ordering::Release);
                Ok(0)
            }
            vhost_req::RESET_OWNER => {
                device.connected.store(false, Ordering::Release);
                device.stop();
                Ok(0)
            }
            _ => Ok(0)
        }
    }

    /// Process all devices
    pub fn process_devices(&self) -> u64 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let mut total = 0u64;
        
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            let device = &self.devices[i];
            if device.running.load(Ordering::Acquire) {
                // Process vrings
                for j in 0..device.vring_count.load(Ordering::Acquire) as usize {
                    let vring = &device.vrings[j];
                    if vring.running.load(Ordering::Acquire) {
                        // Would process vring descriptors
                        total += 1;
                    }
                }
            }
        }
        
        total
    }

    /// Update statistics
    pub fn update_stats(&self) {
        let mut bytes = 0u64;
        let mut hits = 0u64;
        let mut misses = 0u64;
        
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            bytes += self.devices[i].bytes_transferred.load(Ordering::Acquire);
            hits += self.devices[i].zero_copy_hits.load(Ordering::Acquire);
            misses += self.devices[i].zero_copy_misses.load(Ordering::Acquire);
        }
        
        self.total_bytes.store(bytes, Ordering::Release);
        self.total_zero_copy_hits.store(hits, Ordering::Release);
        self.total_zero_copy_misses.store(misses, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> VhostControllerStats {
        VhostControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            device_count: self.device_count.load(Ordering::Acquire),
            zero_copy_enabled: self.zero_copy_enabled.load(Ordering::Acquire),
            dpdk_enabled: self.dpdk_enabled.load(Ordering::Acquire),
            total_messages: self.total_messages.load(Ordering::Acquire),
            total_bytes: self.total_bytes.load(Ordering::Acquire),
            zero_copy_ratio: self.get_zero_copy_ratio(),
        }
    }

    /// Get zero-copy ratio
    fn get_zero_copy_ratio(&self) -> u32 {
        let hits = self.total_zero_copy_hits.load(Ordering::Acquire);
        let misses = self.total_zero_copy_misses.load(Ordering::Acquire);
        let total = hits + misses;
        
        if total == 0 {
            return 100;
        }
        
        ((hits * 100) / total) as u32
    }
}

impl Default for VhostController {
    fn default() -> Self {
        Self::new()
    }
}

/// vhost controller statistics
#[repr(C)]
pub struct VhostControllerStats {
    pub enabled: bool,
    pub device_count: u8,
    pub zero_copy_enabled: bool,
    pub dpdk_enabled: bool,
    pub total_messages: u64,
    pub total_bytes: u64,
    pub zero_copy_ratio: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::virtio_mq::device_type;

    #[test]
    fn create_device() {
        let mut ctrl = VhostController::new();
        ctrl.enable(true, false);
        
        let id = ctrl.create_device(1, device_type::NET).unwrap();
        assert_eq!(ctrl.device_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn handle_get_features() {
        let mut ctrl = VhostController::new();
        ctrl.enable(true, false);
        
        let device_id = ctrl.create_device(1, device_type::NET).unwrap();
        let device = ctrl.get_device(device_id).unwrap();
        device.set_features(0xFFFF);
        
        let payload = VhostMsgPayload::new();
        let features = ctrl.handle_message(device_id, vhost_req::GET_FEATURES, &payload).unwrap();
        
        assert_eq!(features, 0xFFFF);
    }

    #[test]
    fn memory_region() {
        let region = VhostMemRegion::new();
        // gpa=0x1000000, size=0x1000000 (16MB), hva=0x2000000
        // Range is [0x1000000, 0x2000000)
        region.init(0x1000000, 0x1000000, 0x2000000, 0);
        
        assert!(region.contains(0x1000000)); // Start
        assert!(region.contains(0x1FFFFFF)); // Last byte in range
        assert!(!region.contains(0x2000000)); // First byte outside range
        
        let hva = region.translate(0x1001000).unwrap();
        assert_eq!(hva, 0x2001000);
    }

    #[test]
    fn vring_state() {
        let vring = VhostVringState::new();
        vring.init(0, 256);
        vring.set_addresses(0x1000, 0x2000, 0x3000);
        vring.set_fds(0, 1, 2);
        vring.enable();
        
        assert!(vring.enabled.load(Ordering::Acquire));
        assert_eq!(vring.num.load(Ordering::Acquire), 256);
    }

    #[test]
    fn zero_copy() {
        let device = VhostDevice::new();
        device.init(1, 1, device_type::NET);
        device.enable_zero_copy(true);
        device.add_mem_region(0x1000000, 0x10000000, 0x2000000, 0).unwrap();
        
        let result = device.process_zero_copy(0x1001000, 64, false);
        assert!(result);
        
        let stats = device.get_stats();
        assert!(stats.zero_copy_hits > 0);
    }

    #[test]
    fn vring_enable_disable() {
        let device = VhostDevice::new();
        device.init(1, 1, device_type::NET);
        device.add_vring(0, 256).unwrap();
        device.add_vring(1, 256).unwrap();
        
        device.start();
        assert!(device.running.load(Ordering::Acquire));
        
        device.stop();
        assert!(!device.running.load(Ordering::Acquire));
    }
}
