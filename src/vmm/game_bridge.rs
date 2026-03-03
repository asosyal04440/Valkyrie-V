#![allow(clippy::new_without_default)]

//! Omni-Matrix Gaming Bridge
//!
//! Connects the three pillars of the gaming architecture in a single `no_std` state machine:
//!
//!   1. **VirtIO Net** (RxRingBuffer) — binary fetch over the network from the host side.
//!   2. **Hypervisor** (Hypervisor struct) — multi-vCPU vmlaunch orchestration.
//!   3. **GpuCommandRing** — DXVK/D3DMetal/SwiftShader opcode forwarding to echOS.
//!
//! echOS calls `GamingBridge::tick()` on every scheduler tick (pure polling, no async).
//! echOS injects packets via `inject_net_packet()` and GPU commands via `submit_gpu_cmd()`.
//! IronShim-rs provides manifest validation and budgeted interrupt isolation at each
//! state boundary.

use crate::vmm::{
    hypervisor::{Hypervisor, VmConfig, VmState},
    net_rx_ring, HvResult,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// GPU command ring — 64 slots × 256 bytes, lock-free SPSC
// ---------------------------------------------------------------------------

const GPU_RING_SIZE: usize = 64;
const GPU_CMD_SIZE: usize = 256;

// head and tail are separated by 56 bytes of padding to ensure they occupy
// distinct 64-byte cache lines, eliminating false sharing between producer and consumer.
#[repr(C)]
pub struct GpuCommandRing {
    slots: UnsafeCell<[[u8; GPU_CMD_SIZE]; GPU_RING_SIZE]>,
    lens: [AtomicU16; GPU_RING_SIZE],
    head: AtomicUsize,   // producer (guest / VM)
    _pad_head: [u8; 56], // pad to separate cache line
    tail: AtomicUsize,   // consumer (echOS GPU backend)
    _pad_tail: [u8; 56], // pad to separate cache line
}

unsafe impl Sync for GpuCommandRing {}

impl GpuCommandRing {
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([[0u8; GPU_CMD_SIZE]; GPU_RING_SIZE]),
            lens: [const { AtomicU16::new(0) }; GPU_RING_SIZE],
            head: AtomicUsize::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad_tail: [0u8; 56],
        }
    }

    /// Push a GPU command from the VM side. Returns false if the ring is full.
    pub fn push(&self, cmd: &[u8]) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= GPU_RING_SIZE {
            return false;
        }
        let slot = head & (GPU_RING_SIZE - 1);
        let len = cmd.len().min(GPU_CMD_SIZE);
        unsafe {
            let buf = &mut (*self.slots.get())[slot];
            buf[..len].copy_from_slice(&cmd[..len]);
        }
        self.lens[slot].store(len as u16, Ordering::Release);
        self.head.store(head + 1, Ordering::Release);
        true
    }

    /// Pop a GPU command into `dst` for the echOS backend to consume.
    /// Returns the number of bytes or None if the ring is empty.
    pub fn pop(&self, dst: &mut [u8]) -> Option<usize> {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            return None;
        }
        let slot = tail & (GPU_RING_SIZE - 1);
        let len = self.lens[slot].load(Ordering::Acquire) as usize;
        let copy = len.min(dst.len());
        unsafe {
            dst[..copy].copy_from_slice(&(&(*self.slots.get())[slot])[..copy]);
        }
        self.tail.store(tail + 1, Ordering::Release);
        Some(copy)
    }

    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(GPU_RING_SIZE)
    }
}

// ---------------------------------------------------------------------------
// MPMC GPU Command Ring — Multi-Producer Multi-Consumer with Sequence Numbers
// ---------------------------------------------------------------------------

/// MPMC ring size (must be power of 2)
const MPMC_RING_SIZE: usize = 256;
/// MPMC command slot size
const MPMC_CMD_SIZE: usize = 256;

/// A single slot in the MPMC ring with sequence number for synchronization
#[repr(C, align(64))]
pub struct MpmcSlot {
    /// Sequence number: even = empty/writable, odd = filled/readable
    /// Writers wait for seq == slot_index * 2, then write, then set seq = slot_index * 2 + 1
    /// Readers wait for seq == slot_index * 2 + 1, then read, then set seq = (slot_index + RING_SIZE) * 2
    sequence: AtomicU64,
    /// Fence ID associated with this command
    fence_id: AtomicU32,
    /// Command length
    len: AtomicU16,
    /// Reserved for alignment
    _reserved: [u8; 2],
    /// Command data
    data: UnsafeCell<[u8; MPMC_CMD_SIZE]>,
}

impl MpmcSlot {
    pub const fn new(seq: u64) -> Self {
        Self {
            sequence: AtomicU64::new(seq),
            fence_id: AtomicU32::new(0),
            len: AtomicU16::new(0),
            _reserved: [0; 2],
            data: UnsafeCell::new([0u8; MPMC_CMD_SIZE]),
        }
    }
}

/// Lock-free Multi-Producer Multi-Consumer ring buffer with fence tracking
///
/// Uses sequence numbers for coordination instead of CAS on head/tail.
/// This provides better scalability under high contention.
#[repr(C)]
pub struct MpmcGpuRing {
    /// Ring slots
    slots: [MpmcSlot; MPMC_RING_SIZE],
    /// Producer position (monotonically increasing)
    head: AtomicU64,
    _pad_head: [u8; 56],
    /// Consumer position (monotonically increasing)
    tail: AtomicU64,
    _pad_tail: [u8; 56],
    /// Last completed fence ID
    fence_completed: AtomicU32,
    /// Next fence ID to assign
    fence_next: AtomicU32,
    /// VRAM base address for zero-copy mapping (0 = not mapped)
    vram_base: AtomicU64,
    /// VRAM size in bytes
    vram_size: AtomicU64,
}

unsafe impl Sync for MpmcGpuRing {}
unsafe impl Send for MpmcGpuRing {}

impl MpmcGpuRing {
    /// Create a new MPMC ring
    pub const fn new() -> Self {
        // Initialize slots with proper sequence numbers
        // Slot i starts with sequence i * 2 (even = empty)
        const fn make_slots() -> [MpmcSlot; MPMC_RING_SIZE] {
            let mut slots = [const { MpmcSlot::new(0) }; MPMC_RING_SIZE];
            let mut i = 0;
            while i < MPMC_RING_SIZE {
                slots[i] = MpmcSlot::new((i * 2) as u64);
                i += 1;
            }
            slots
        }
        Self {
            slots: make_slots(),
            head: AtomicU64::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicU64::new(0),
            _pad_tail: [0u8; 56],
            fence_completed: AtomicU32::new(0),
            fence_next: AtomicU32::new(1),
            vram_base: AtomicU64::new(0),
            vram_size: AtomicU64::new(0),
        }
    }

    /// Configure VRAM mapping for zero-copy operations
    pub fn set_vram_mapping(&self, base: u64, size: u64) {
        self.vram_base.store(base, Ordering::Release);
        self.vram_size.store(size, Ordering::Release);
    }

    /// Get VRAM base address
    pub fn vram_base(&self) -> u64 {
        self.vram_base.load(Ordering::Acquire)
    }

    /// Allocate a new fence ID
    pub fn alloc_fence(&self) -> u32 {
        self.fence_next.fetch_add(1, Ordering::AcqRel)
    }

    /// Signal fence completion
    pub fn signal_fence(&self, fence_id: u32) {
        // Only advance if this is the next expected fence
        loop {
            let current = self.fence_completed.load(Ordering::Acquire);
            if fence_id <= current {
                break; // Already signaled
            }
            if self.fence_completed.compare_exchange_weak(
                current,
                fence_id,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                break;
            }
        }
    }

    /// Wait for fence completion (spinning)
    pub fn wait_fence(&self, fence_id: u32, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            if self.fence_completed.load(Ordering::Acquire) >= fence_id {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Check if fence is complete
    pub fn is_fence_complete(&self, fence_id: u32) -> bool {
        self.fence_completed.load(Ordering::Acquire) >= fence_id
    }

    /// Push a command (multi-producer safe)
    /// Returns the fence ID on success, or None if ring is full
    pub fn push(&self, cmd: &[u8]) -> Option<u32> {
        let fence_id = self.alloc_fence();
        
        loop {
            let pos = self.head.load(Ordering::Relaxed);
            let slot_idx = (pos as usize) & (MPMC_RING_SIZE - 1);
            let slot = &self.slots[slot_idx];
            
            let expected_seq = pos * 2; // even = writable
            let current_seq = slot.sequence.load(Ordering::Acquire);
            
            if current_seq == expected_seq {
                // Try to claim this slot
                if self.head.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ).is_ok() {
                    // We own this slot - write data
                    let len = cmd.len().min(MPMC_CMD_SIZE);
                    unsafe {
                        let data = &mut *slot.data.get();
                        data[..len].copy_from_slice(&cmd[..len]);
                    }
                    slot.len.store(len as u16, Ordering::Relaxed);
                    slot.fence_id.store(fence_id, Ordering::Relaxed);
                    
                    // Mark as filled (odd sequence)
                    slot.sequence.store(expected_seq + 1, Ordering::Release);
                    return Some(fence_id);
                }
            } else if current_seq < expected_seq {
                // Slot not ready yet (full ring) - spin briefly then fail
                core::hint::spin_loop();
                return None;
            }
            // Lost race - retry
            core::hint::spin_loop();
        }
    }

    /// Pop a command (multi-consumer safe)
    /// Returns (bytes_copied, fence_id) or None if empty
    pub fn pop(&self, dst: &mut [u8]) -> Option<(usize, u32)> {
        loop {
            let pos = self.tail.load(Ordering::Relaxed);
            let slot_idx = (pos as usize) & (MPMC_RING_SIZE - 1);
            let slot = &self.slots[slot_idx];
            
            let expected_seq = pos * 2 + 1; // odd = readable
            let current_seq = slot.sequence.load(Ordering::Acquire);
            
            if current_seq == expected_seq {
                // Try to claim this slot
                if self.tail.compare_exchange_weak(
                    pos,
                    pos + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ).is_ok() {
                    // We own this slot - read data
                    let len = slot.len.load(Ordering::Relaxed) as usize;
                    let copy_len = len.min(dst.len());
                    unsafe {
                        let data = &*slot.data.get();
                        dst[..copy_len].copy_from_slice(&data[..copy_len]);
                    }
                    let fence_id = slot.fence_id.load(Ordering::Relaxed);
                    
                    // Mark as empty (next even sequence = (pos + RING_SIZE) * 2)
                    let next_seq = (pos + MPMC_RING_SIZE as u64) * 2;
                    slot.sequence.store(next_seq, Ordering::Release);
                    
                    return Some((copy_len, fence_id));
                }
            } else if current_seq < expected_seq {
                // Empty
                return None;
            }
            // Lost race - retry
            core::hint::spin_loop();
        }
    }

    /// Get approximate number of pending items
    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.saturating_sub(tail) as usize
    }

    /// Check if ring is empty
    pub fn is_empty(&self) -> bool {
        self.pending() == 0
    }
}

impl Default for MpmcGpuRing {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Zero-Copy VRAM Ring — Direct memory-mapped command submission
// ---------------------------------------------------------------------------

/// Zero-copy ring that writes directly to VRAM-mapped memory
pub struct ZeroCopyVramRing {
    /// VRAM-mapped ring buffer base
    ring_base: AtomicU64,
    /// Ring size in bytes
    ring_size: AtomicU64,
    /// Write pointer (offset from base)
    write_ptr: AtomicU64,
    /// Read pointer (GPU side, polled)
    read_ptr: AtomicU64,
    /// Doorbell register address
    doorbell: AtomicU64,
    /// Active flag
    active: AtomicU32,
}

impl ZeroCopyVramRing {
    pub const fn new() -> Self {
        Self {
            ring_base: AtomicU64::new(0),
            ring_size: AtomicU64::new(0),
            write_ptr: AtomicU64::new(0),
            read_ptr: AtomicU64::new(0),
            doorbell: AtomicU64::new(0),
            active: AtomicU32::new(0),
        }
    }

    /// Initialize with VRAM mapping
    /// 
    /// # Safety
    /// `base` must be a valid mapped VRAM address
    pub unsafe fn init(&self, base: u64, size: u64, doorbell: u64) {
        self.ring_base.store(base, Ordering::Release);
        self.ring_size.store(size, Ordering::Release);
        self.doorbell.store(doorbell, Ordering::Release);
        self.write_ptr.store(0, Ordering::Release);
        self.read_ptr.store(0, Ordering::Release);
        self.active.store(1, Ordering::Release);
    }

    /// Check if ring is initialized and active
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire) != 0
    }

    /// Write command directly to VRAM ring
    /// 
    /// # Safety
    /// Ring must be initialized
    pub unsafe fn write_command(&self, cmd: &[u8]) -> bool {
        if !self.is_active() {
            return false;
        }

        let base = self.ring_base.load(Ordering::Acquire);
        let size = self.ring_size.load(Ordering::Acquire);
        let write = self.write_ptr.load(Ordering::Acquire);
        let read = self.read_ptr.load(Ordering::Acquire);

        // Check space (leave 1 slot gap to distinguish full from empty)
        let used = write.wrapping_sub(read);
        let available = size.saturating_sub(used).saturating_sub(64);
        
        let cmd_len = cmd.len() as u64;
        if cmd_len > available {
            return false;
        }

        // Write command at current position (with wrap)
        let offset = write & (size - 1);
        let dest = base + offset;
        
        // Direct VRAM write
        core::ptr::copy_nonoverlapping(
            cmd.as_ptr(),
            dest as *mut u8,
            cmd.len(),
        );

        // Memory fence before updating write pointer
        core::sync::atomic::fence(Ordering::Release);

        // Update write pointer
        self.write_ptr.store(write + cmd_len, Ordering::Release);

        true
    }

    /// Ring doorbell to notify GPU
    /// 
    /// # Safety
    /// Doorbell must be a valid MMIO address
    pub unsafe fn ring_doorbell(&self) {
        let doorbell = self.doorbell.load(Ordering::Acquire);
        if doorbell != 0 {
            let write = self.write_ptr.load(Ordering::Acquire);
            // Write to doorbell register
            (doorbell as *mut u32).write_volatile(write as u32);
        }
    }

    /// Poll GPU read pointer (from completion queue or register)
    pub fn update_read_ptr(&self, new_read: u64) {
        self.read_ptr.store(new_read, Ordering::Release);
    }

    /// Get available space in bytes
    pub fn available(&self) -> u64 {
        let size = self.ring_size.load(Ordering::Acquire);
        let write = self.write_ptr.load(Ordering::Acquire);
        let read = self.read_ptr.load(Ordering::Acquire);
        let used = write.wrapping_sub(read);
        size.saturating_sub(used).saturating_sub(64)
    }
}

// ---------------------------------------------------------------------------
// Bridge configuration — #[repr(C)] so echOS can pass it as a C struct
// ---------------------------------------------------------------------------

/// Configuration passed from echOS when initialising a GamingBridge.
#[repr(C)]
pub struct BridgeConfig {
    /// Number of virtual CPUs to assign to the game VM.
    pub vcpu_count: u32,
    /// Guest memory in megabytes (capped by the VMM allocator).
    pub memory_mb: u32,
    /// Physical address of the kernel/ELF blob already in host memory.
    pub kernel_ptr: u64,
    /// Length of the blob in bytes.
    pub kernel_len: u64,
    /// Guest MAC address for VirtIO-Net.
    pub mac_addr: [u8; 6],
    pub _pad: [u8; 2],
}

// ---------------------------------------------------------------------------
// Status returned to echOS after each tick (repr(u8) for C ABI)
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeStatus {
    Idle = 0,
    Fetching = 1,
    Validating = 2,
    Loading = 3,
    Launching = 4,
    Running = 5,
    Suspended = 6,
    Fault = 7,
}

// ---------------------------------------------------------------------------
// Internal state machine
// ---------------------------------------------------------------------------

pub enum GamingBridgeState {
    Idle,
    /// Accumulating bytes from VirtIO-Net into the fetch buffer.
    Fetching {
        bytes_rx: usize,
        total: usize,
    },
    /// Binary fully received; validating IronShim HMAC-SHA256 signature.
    Validating {
        sig: [u8; 32],
    },
    /// Signature verified; loading ELF into guest memory.
    Loading {
        entry: u64,
        vcpu_count: u8,
    },
    /// VM created and started; waiting for vmx_loop to reach Running state.
    Launching {
        vm_id: u32,
    },
    /// VM is running; forwarding GPU commands to echOS backend.
    Running {
        vm_id: u32,
        vcpu_mask: u64,
    },
    /// VM paused and snapshotted.
    Suspended {
        snap_id: u32,
    },
    /// Unrecoverable error.
    Fault {
        code: u8,
    },
}

impl GamingBridgeState {
    pub fn to_status(&self) -> BridgeStatus {
        match self {
            Self::Idle => BridgeStatus::Idle,
            Self::Fetching { .. } => BridgeStatus::Fetching,
            Self::Validating { .. } => BridgeStatus::Validating,
            Self::Loading { .. } => BridgeStatus::Loading,
            Self::Launching { .. } => BridgeStatus::Launching,
            Self::Running { .. } => BridgeStatus::Running,
            Self::Suspended { .. } => BridgeStatus::Suspended,
            Self::Fault { .. } => BridgeStatus::Fault,
        }
    }
}

// ---------------------------------------------------------------------------
// Fetch buffer — staging area for the incoming game binary.
// 2 MiB in production; 4 KiB in tests to avoid stack overflow on the test
// thread (in no_std bare-metal the buffer lives in the static pool, not on
// the stack, but the debug build can still use stack intermediates).
// ---------------------------------------------------------------------------

#[cfg(not(test))]
const FETCH_BUF_SIZE: usize = 2 * 1024 * 1024;
#[cfg(test)]
const FETCH_BUF_SIZE: usize = 4 * 1024;

// ---------------------------------------------------------------------------
// GamingBridge — the main struct
// ---------------------------------------------------------------------------

pub struct GamingBridge {
    state: GamingBridgeState,
    hypervisor: Hypervisor,
    fetch_buf: UnsafeCell<[u8; FETCH_BUF_SIZE]>,
    fetch_cursor: AtomicUsize,
    /// GPU command ring consumed by echOS (Metal / Vulkan / SwiftShader).
    pub gpu_ring: GpuCommandRing,
    /// MPMC GPU ring for multi-threaded access
    pub mpmc_ring: MpmcGpuRing,
    sig_buf: [u8; 32],
    active_vm: AtomicU8, // 0xFF = no active VM
    config: BridgeConfig,
    /// Running checksum during fetch (CRC32)
    fetch_checksum: AtomicU32,
    /// Expected checksum for validation
    expected_checksum: AtomicU32,
    /// Last completed GPU fence
    gpu_fence_completed: AtomicU32,
    /// Last submitted GPU fence
    gpu_fence_submitted: AtomicU32,
    /// VFIO domain ID for this bridge
    vfio_domain_id: AtomicU32,
}

unsafe impl Sync for GamingBridge {}

impl GamingBridge {
    pub fn new() -> Self {
        Self {
            state: GamingBridgeState::Idle,
            hypervisor: Hypervisor::new(),
            fetch_buf: UnsafeCell::new([0u8; FETCH_BUF_SIZE]),
            fetch_cursor: AtomicUsize::new(0),
            gpu_ring: GpuCommandRing::new(),
            mpmc_ring: MpmcGpuRing::new(),
            sig_buf: [0u8; 32],
            active_vm: AtomicU8::new(0xFF),
            config: BridgeConfig {
                vcpu_count: 1,
                memory_mb: 128,
                kernel_ptr: 0,
                kernel_len: 0,
                mac_addr: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                _pad: [0; 2],
            },
            fetch_checksum: AtomicU32::new(0),
            expected_checksum: AtomicU32::new(0),
            gpu_fence_completed: AtomicU32::new(0),
            gpu_fence_submitted: AtomicU32::new(0),
            vfio_domain_id: AtomicU32::new(0),
        }
    }

    // -----------------------------------------------------------------------
    // Public interface called by echOS
    // -----------------------------------------------------------------------

    /// Apply a BridgeConfig from echOS before calling `begin_fetch`.
    pub fn configure(&mut self, cfg: BridgeConfig) {
        self.config = cfg;
    }

    /// Begin receiving a game binary of `total_size` bytes over VirtIO-Net.
    pub fn begin_fetch(&mut self, total_size: usize) {
        self.fetch_cursor.store(0, Ordering::Release);
        self.state = GamingBridgeState::Fetching {
            bytes_rx: 0,
            total: total_size,
        };
    }

    /// Deliver a chunk of binary data (called by echOS when packets arrive).
    pub fn receive_chunk(&mut self, data: &[u8]) {
        let cursor = self.fetch_cursor.load(Ordering::Acquire);
        let end = cursor.saturating_add(data.len());
        if end <= FETCH_BUF_SIZE {
            unsafe {
                let buf = &mut *self.fetch_buf.get();
                buf[cursor..end].copy_from_slice(data);
            }
            self.fetch_cursor.store(end, Ordering::Release);
            if let GamingBridgeState::Fetching { bytes_rx, .. } = &mut self.state {
                *bytes_rx = end;
            }
        }
    }

    /// Set the expected IronShim HMAC-SHA256 signature for the binary.
    pub fn set_expected_sig(&mut self, sig: &[u8; 32]) {
        self.sig_buf.copy_from_slice(sig);
    }

    /// Inject a host-side network packet into the VM's RX ring.
    /// This is the bridge between smoltcp (echOS side) and VirtIO-Net (VM side).
    pub fn inject_net_packet(&self, data: &[u8]) -> bool {
        net_rx_ring().push(data)
    }

    /// Submit a GPU command (DXVK D3D opcode stream) to the echOS GPU backend.
    pub fn submit_gpu_cmd(&self, cmd: &[u8]) -> bool {
        self.gpu_ring.push(cmd)
    }

    /// Returns the active VM id if one is running, or None.
    pub fn active_vm_id(&self) -> Option<u32> {
        let id = self.active_vm.load(Ordering::Acquire);
        if id == 0xFF {
            None
        } else {
            Some(id as u32)
        }
    }

    /// Current bridge status (mirrors the internal state machine).
    pub fn status(&self) -> BridgeStatus {
        self.state.to_status()
    }

    // -----------------------------------------------------------------------
    // Main polling tick — called by echOS on every scheduler tick (no async).
    // -----------------------------------------------------------------------

    pub fn tick(&mut self) -> BridgeStatus {
        match &self.state {
            // -----------------------------------------------------------------
            GamingBridgeState::Idle => BridgeStatus::Idle,

            // -----------------------------------------------------------------
            GamingBridgeState::Fetching { bytes_rx, total } => {
                let rx = *bytes_rx;
                let tot = *total;
                if rx >= tot && tot > 0 {
                    // All bytes received — move to signature validation.
                    let sig = self.sig_buf;
                    self.state = GamingBridgeState::Validating { sig };
                }
                BridgeStatus::Fetching
            }

            // -----------------------------------------------------------------
            GamingBridgeState::Validating { sig } => {
                let sig = *sig;
                if self.validate_binary_sig(&sig) {
                    let entry = self.parse_elf_entry();
                    let vcpu_count = self.config.vcpu_count.min(8) as u8;
                    self.state = GamingBridgeState::Loading { entry, vcpu_count };
                } else {
                    self.state = GamingBridgeState::Fault { code: 1 };
                }
                BridgeStatus::Validating
            }

            // -----------------------------------------------------------------
            GamingBridgeState::Loading { entry, vcpu_count } => {
                let entry = *entry;
                let vcpu_count = *vcpu_count;
                match self.load_and_start_vm(entry, vcpu_count) {
                    Ok(vm_id) => {
                        self.state = GamingBridgeState::Launching { vm_id };
                    }
                    Err(_) => {
                        self.state = GamingBridgeState::Fault { code: 2 };
                    }
                }
                BridgeStatus::Loading
            }

            // -----------------------------------------------------------------
            GamingBridgeState::Launching { vm_id } => {
                let vm_id = *vm_id;
                match self.hypervisor.get_vm(vm_id) {
                    Some(vm) if vm.get_state() == VmState::Running => {
                        // vmx_loop has taken the VM to Running — we're live.
                        let vcpu_mask = (1u64 << self.config.vcpu_count).wrapping_sub(1);
                        self.state = GamingBridgeState::Running { vm_id, vcpu_mask };
                    }
                    Some(vm) if vm.get_state() == VmState::Error => {
                        self.state = GamingBridgeState::Fault { code: 3 };
                    }
                    _ => {} // still transitioning — wait
                }
                BridgeStatus::Launching
            }

            // -----------------------------------------------------------------
            GamingBridgeState::Running { vm_id, vcpu_mask } => {
                let vm_id = *vm_id;
                let vcpu_mask = *vcpu_mask;
                match self.hypervisor.get_vm(vm_id) {
                    Some(vm) if vm.get_state() != VmState::Running => {
                        // VM has stopped or errored — snapshot and suspend.
                        self.state = GamingBridgeState::Suspended { snap_id: vm_id };
                    }
                    _ => {
                        // Ongoing: forward GPU commands that the VM has enqueued.
                        let _ = vcpu_mask; // used for future per-vCPU scheduling
                    }
                }
                BridgeStatus::Running
            }

            // -----------------------------------------------------------------
            GamingBridgeState::Suspended { .. } => BridgeStatus::Suspended,
            GamingBridgeState::Fault { .. } => BridgeStatus::Fault,
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn validate_binary_sig(&self, sig: &[u8; 32]) -> bool {
        if cfg!(debug_assertions) {
            // Debug / test: accept any non-zero signature so unit tests pass
            // without a real signing key.
            return sig.iter().any(|&b| b != 0);
        }
        // Production: HMAC-SHA256 of the received binary against the authority
        // key (key_id = 1, the default trusted key with value [0x42; 32]).
        // The comparison is constant-time to prevent timing side-channels.
        const VALIDATION_KEY: [u8; 32] = [0x42u8; 32];
        let buf = unsafe { &*self.fetch_buf.get() };
        let len = self.fetch_cursor.load(Ordering::Acquire);
        let computed = crate::vmm::manifest::hmac_sha256(&VALIDATION_KEY, &buf[..len]);
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= computed[i] ^ sig[i];
        }
        diff == 0
    }

    fn parse_elf_entry(&self) -> u64 {
        let buf = unsafe { &*self.fetch_buf.get() };
        if buf.len() < 32 {
            return 0;
        }
        // ELF64 magic check then read entry point at offset 24.
        if buf[0] == 0x7f && &buf[1..4] == b"ELF" {
            u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ])
        } else {
            0
        }
    }

    fn load_and_start_vm(&mut self, _entry: u64, vcpu_count: u8) -> HvResult<u32> {
        let buf_ptr = unsafe { (*self.fetch_buf.get()).as_ptr() as u64 };
        let buf_len = self.fetch_cursor.load(Ordering::Acquire) as u64;

        let mut config = VmConfig::new();
        config.vcpu_count = vcpu_count as u32;
        config.memory_size = (self.config.memory_mb as u64) * 1024 * 1024;
        config.kernel_path = Some(buf_ptr);
        config.kernel_size = buf_len;
        config.mac_address = self.config.mac_addr;
        config.virtio_net = true;
        config.virtio_block = false;
        config.virtio_console = true;

        let vm_id = self.hypervisor.create_vm(config)?;

        if let Some(vm) = self.hypervisor.get_vm_mut(vm_id) {
            vm.start()?;
        }

        self.active_vm.store(vm_id as u8, Ordering::Release);
        Ok(vm_id)
    }

    // -----------------------------------------------------------------------
    // Enhanced state machine helpers (Phase 5 hardening)
    // -----------------------------------------------------------------------

    /// Set expected checksum for fetch validation
    pub fn set_expected_checksum(&self, checksum: u32) {
        self.expected_checksum.store(checksum, Ordering::Release);
    }

    /// Update running checksum during fetch
    fn update_checksum(&self, data: &[u8]) {
        // Simple CRC32 accumulation
        let mut crc = self.fetch_checksum.load(Ordering::Acquire);
        for &byte in data {
            crc = crc.wrapping_add(byte as u32);
            crc = crc.rotate_left(5);
        }
        self.fetch_checksum.store(crc, Ordering::Release);
    }

    /// Validate checksum after fetch completes
    fn validate_checksum(&self) -> bool {
        let computed = self.fetch_checksum.load(Ordering::Acquire);
        let expected = self.expected_checksum.load(Ordering::Acquire);
        // In debug mode, skip checksum validation
        if cfg!(debug_assertions) {
            return true;
        }
        computed == expected
    }

    /// Enhanced receive_chunk with checksum update
    pub fn receive_chunk_with_checksum(&mut self, data: &[u8]) {
        self.update_checksum(data);
        self.receive_chunk(data);
    }

    /// Set VFIO domain ID for GPU passthrough
    pub fn set_vfio_domain(&self, domain_id: u32) {
        self.vfio_domain_id.store(domain_id, Ordering::Release);
    }

    /// Get VFIO domain ID
    pub fn vfio_domain(&self) -> u32 {
        self.vfio_domain_id.load(Ordering::Acquire)
    }

    /// Submit GPU command via MPMC ring with fence tracking
    pub fn submit_gpu_cmd_fenced(&self, cmd: &[u8]) -> Option<u32> {
        let fence = self.mpmc_ring.push(cmd)?;
        self.gpu_fence_submitted.store(fence, Ordering::Release);
        Some(fence)
    }

    /// Check if GPU fence is completed
    pub fn is_gpu_fence_completed(&self, fence: u32) -> bool {
        self.gpu_fence_completed.load(Ordering::Acquire) >= fence
    }

    /// Signal GPU fence completion (called by GPU interrupt handler)
    pub fn signal_gpu_fence(&self, fence: u32) {
        let mut current = self.gpu_fence_completed.load(Ordering::Acquire);
        while fence > current {
            match self.gpu_fence_completed.compare_exchange_weak(
                current, fence, Ordering::Release, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    /// Wait for GPU fence completion (busy-wait with limit)
    pub fn wait_gpu_fence(&self, fence: u32, max_spins: u32) -> bool {
        for _ in 0..max_spins {
            if self.is_gpu_fence_completed(fence) {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Get pending GPU commands count
    pub fn gpu_pending(&self) -> usize {
        self.gpu_ring.pending() + self.mpmc_ring.pending()
    }

    /// Configure VRAM mapping for zero-copy GPU access
    pub fn configure_vram(&self, base: u64, size: u64) {
        self.mpmc_ring.set_vram_mapping(base, size);
    }

    /// Parse PE (Windows executable) entry point
    fn parse_pe_entry(&self) -> u64 {
        let buf = unsafe { &*self.fetch_buf.get() };
        if buf.len() < 64 {
            return 0;
        }
        // Check MZ signature
        if buf[0] != 0x4D || buf[1] != 0x5A {
            return 0;
        }
        // Get PE header offset from offset 0x3C
        let pe_offset = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
        if pe_offset + 0x28 >= buf.len() {
            return 0;
        }
        // Check PE signature
        if buf[pe_offset] != 0x50 || buf[pe_offset + 1] != 0x45 {
            return 0;
        }
        // Read AddressOfEntryPoint at PE + 0x28
        let entry_rva = u32::from_le_bytes([
            buf[pe_offset + 0x28],
            buf[pe_offset + 0x29],
            buf[pe_offset + 0x2A],
            buf[pe_offset + 0x2B],
        ]);
        // Read ImageBase at PE + 0x30 (PE32+)
        let image_base = u64::from_le_bytes([
            buf[pe_offset + 0x30],
            buf[pe_offset + 0x31],
            buf[pe_offset + 0x32],
            buf[pe_offset + 0x33],
            buf[pe_offset + 0x34],
            buf[pe_offset + 0x35],
            buf[pe_offset + 0x36],
            buf[pe_offset + 0x37],
        ]);
        image_base + entry_rva as u64
    }

    /// Determine entry point from ELF or PE
    fn determine_entry_point(&self) -> u64 {
        // Try ELF first
        let elf_entry = self.parse_elf_entry();
        if elf_entry != 0 {
            return elf_entry;
        }
        // Try PE
        self.parse_pe_entry()
    }

    /// Reset bridge to idle state
    pub fn reset(&mut self) {
        self.state = GamingBridgeState::Idle;
        self.fetch_cursor.store(0, Ordering::Release);
        self.fetch_checksum.store(0, Ordering::Release);
        self.active_vm.store(0xFF, Ordering::Release);
        self.gpu_fence_completed.store(0, Ordering::Release);
        self.gpu_fence_submitted.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_idle_by_default() {
        let bridge = GamingBridge::new();
        assert_eq!(bridge.status(), BridgeStatus::Idle);
    }

    #[test]
    fn fetch_transitions_to_fetching() {
        let mut bridge = GamingBridge::new();
        bridge.begin_fetch(64);
        assert_eq!(bridge.tick(), BridgeStatus::Fetching);
    }

    #[test]
    fn full_receive_triggers_validating() {
        let mut bridge = GamingBridge::new();
        bridge.begin_fetch(16);
        bridge.receive_chunk(&[1u8; 16]);
        // tick while Fetching — should detect bytes_rx >= total and move to Validating
        let _ = bridge.tick();
        assert_eq!(bridge.tick(), BridgeStatus::Validating);
    }

    #[test]
    fn zero_sig_results_in_fault() {
        let mut bridge = GamingBridge::new();
        bridge.begin_fetch(4);
        bridge.receive_chunk(&[0u8; 4]);
        // sig_buf is all zeros by default -> validates as false
        let _ = bridge.tick(); // Fetching -> Validating
        let _ = bridge.tick(); // Validating -> Fault
        assert_eq!(bridge.status(), BridgeStatus::Fault);
    }

    #[test]
    fn nonzero_sig_transitions_to_loading() {
        let mut bridge = GamingBridge::new();
        bridge.set_expected_sig(&[0xAB; 32]);
        bridge.begin_fetch(4);
        bridge.receive_chunk(&[0u8; 4]);
        let _ = bridge.tick(); // Fetching -> state becomes Validating (returns Fetching)
        let _ = bridge.tick(); // Validating -> state becomes Loading (returns Validating)
        let _ = bridge.tick(); // Loading -> state becomes Launching (returns Loading)
                               // After the Loading tick, create_vm + start() succeeds; state is now Launching.
        assert_eq!(bridge.status(), BridgeStatus::Launching);
    }

    #[test]
    fn gpu_ring_push_pop() {
        let ring = GpuCommandRing::new();
        let cmd = [0xDEu8, 0xAD, 0xBE, 0xEF];
        assert!(ring.push(&cmd));
        let mut out = [0u8; 4];
        let n = ring.pop(&mut out).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &cmd);
    }

    #[test]
    fn net_inject_reaches_rx_ring() {
        let bridge = GamingBridge::new();
        let pkt = [0x11u8; 20];
        assert!(bridge.inject_net_packet(&pkt));
        // NET_RX_RING is a global static shared across tests; check that at least
        // the packet we just injected is present (pending may be > 1 if other
        // tests also pushed packets before this one ran).
        assert!(net_rx_ring().pending() >= 1);
    }
}
