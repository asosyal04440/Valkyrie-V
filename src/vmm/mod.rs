#![allow(clippy::new_without_default)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::len_without_is_empty)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::identity_op)]
#![allow(clippy::let_unit_value)]

pub mod advanced_io;
pub mod advanced_memory;
pub mod advanced_security;
pub mod apic;
pub mod apicv;
pub mod atlas;
pub mod balloon;
pub mod chase_lev;
pub mod chronos;
pub mod d3d_intercept;
pub mod disk_image;
pub mod file_backend;
pub mod dxbc_spirv;
pub mod ept;
pub mod fault_tolerance;
pub mod cloud;
pub mod debug;
pub mod enterprise;
pub mod game_bridge;
pub mod guest_memory;
pub mod hypercall;
pub mod hypervisor;
pub mod ioapic;
pub mod ipi;
pub mod irq;
pub mod kernel_loader;
pub mod ksm;
pub mod manifest;
pub mod migration;
pub mod monitoring;
pub mod multiboot2;
pub mod multitenant;
pub mod msi;
pub mod nested;
pub mod nvme;
pub mod pci;
pub mod nested_virt;
pub mod performance;
pub mod scheduler;
pub mod secure_boot;
pub mod shader_translator;
pub mod soft_raster;
pub mod sriov;
pub mod svm;
pub mod svm_handler;
pub mod ugir;
pub mod tun_backend;
pub mod vcpu;
pub mod vfio;
pub mod virtio_block;
pub mod virtio_console;
pub mod virtio_gpu;
pub mod virtio_mmio;
pub mod virtio_net;
pub mod virtio_net_enhanced;
pub mod virtio_queue;
pub mod vmx;
pub mod vmx_handler;
pub mod vram_map;
pub mod vtd;

// Year 5 Optimization Modules
pub mod memory_compress;
pub mod tps;
pub mod balloon_enhanced;
pub mod large_page;
pub mod sched_adv;
pub mod power_mgmt;
pub mod tlb;
pub mod ept_cache;
pub mod virtio_mq;
pub mod vhost_user;
pub mod ioat_dma;
pub mod microvm;
pub mod template;
pub mod vgpu;
pub mod gpu_mem;
pub mod cbt;
pub mod live_snap;
pub mod vmi;
pub mod hvi;
pub mod tracing;
pub mod pmu;
pub mod numamem;
pub mod numaio;

pub type HvResult<T> = Result<T, HvError>;

use apic::{Apic, TscSync};
use atlas::{Allocation, Atlas};
use chronos::Chronos;
use core::arch::x86_64::{__cpuid, __cpuid_count};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use ept::Ept;
use vmx::Vmx;
use vmx_handler::{AeroFrame, MinimalRegs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverTag {
    pub guest_id: u64,
}

#[derive(Debug)]
pub enum HvError {
    HardwareFault,
    LogicalFault,
}

#[derive(Clone, Copy)]
pub struct Capabilities {
    pub vmx: bool,
    pub ept: bool,
    pub tsc_deadline: bool,
    pub invariant_tsc: bool,
    pub x2apic: bool,
}

const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;

#[cfg(not(test))]
fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    }
    ((high as u64) << 32) | low as u64
}

#[cfg(test)]
fn read_msr(_msr: u32) -> u64 {
    0
}

fn probe_capabilities() -> Capabilities {
    let leaf1 = unsafe { __cpuid(1) };
    let leaf7 = unsafe { __cpuid_count(7, 0) };
    let vmx = (leaf1.ecx & (1 << 5)) != 0;
    let x2apic = (leaf1.ecx & (1 << 21)) != 0;
    let tsc_deadline = (leaf1.ecx & (1 << 24)) != 0;
    let invariant_tsc = (unsafe { __cpuid(0x8000_0007) }.edx & (1 << 8)) != 0;
    let vmx_ctls2 = read_msr(IA32_VMX_PROCBASED_CTLS2);
    let ept_allowed1 = (vmx_ctls2 >> 32) as u32;
    let ept = vmx && ((ept_allowed1 & (1 << 1)) != 0);
    let _ = leaf7;
    Capabilities {
        vmx,
        ept,
        tsc_deadline,
        invariant_tsc,
        x2apic,
    }
}

#[derive(Clone, Copy)]
pub struct CapabilityDecision {
    pub fatal: bool,
    pub degraded: bool,
}

pub fn evaluate_capabilities(caps: Capabilities) -> CapabilityDecision {
    let fatal = !caps.vmx;
    let degraded = caps.vmx && !caps.ept;
    CapabilityDecision { fatal, degraded }
}

pub trait HypervisorOps {
    fn run_vm(&self, state: &mut HypervisorState, launched: &mut bool) -> Result<(), HvError>;
    fn inject_interrupt(&self, irq: u32) -> Result<(), HvError>;
    fn capabilities(&self) -> Capabilities;
}

#[derive(Clone, Copy)]
pub struct VmxOps {
    caps: Capabilities,
}

impl VmxOps {
    pub const fn new(caps: Capabilities) -> Self {
        Self { caps }
    }
}

impl HypervisorOps for VmxOps {
    fn run_vm(&self, state: &mut HypervisorState, launched: &mut bool) -> Result<(), HvError> {
        if *launched {
            state.vmx.resume()
        } else {
            *launched = true;
            state.vmx.launch()
        }
    }

    fn inject_interrupt(&self, irq: u32) -> Result<(), HvError> {
        crate::vmm::irq::irq_registry()
            .trigger(irq)
            .map_err(|_| HvError::LogicalFault)
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }
}

#[derive(Clone, Copy)]
pub struct SvmOps {
    caps: Capabilities,
}

impl SvmOps {
    pub const fn new(caps: Capabilities) -> Self {
        Self { caps }
    }
}

impl HypervisorOps for SvmOps {
    fn run_vm(&self, _state: &mut HypervisorState, _launched: &mut bool) -> Result<(), HvError> {
        Err(HvError::LogicalFault)
    }

    fn inject_interrupt(&self, _irq: u32) -> Result<(), HvError> {
        Err(HvError::LogicalFault)
    }

    fn capabilities(&self) -> Capabilities {
        self.caps
    }
}

#[derive(Clone, Copy)]
pub struct TelemetryRecord {
    pub timestamp: u64,
    pub kind: u32,
    pub value: u32,
}

impl TelemetryRecord {
    pub const fn new() -> Self {
        Self {
            timestamp: 0,
            kind: 0,
            value: 0,
        }
    }
}

const TELEMETRY_RING_SIZE: usize = 256;
pub const TELEMETRY_BUDGET_EXCEEDED: u32 = 1;
pub const TELEMETRY_QUARANTINE: u32 = 2;
pub const TELEMETRY_STRESS_EPT: u32 = 3;
pub const TELEMETRY_STRESS_IRQ: u32 = 4;
pub const TELEMETRY_CAP_DEGRADED: u32 = 5;
pub const TELEMETRY_VIRTIO_MMIO: u32 = 6;
pub const TELEMETRY_EPT_VIOLATION: u32 = 7;
pub const TELEMETRY_VMX_EXIT: u32 = 8;
const MAX_FAULT_RECOVERIES: u64 = 64;

fn recovery_budget_exhausted(recoveries: u64) -> bool {
    recoveries >= MAX_FAULT_RECOVERIES
}

const VIRTIO_MMIO_BASE_NET: u64 = 0x1000_0000;
const VIRTIO_MMIO_BASE_BLK: u64 = 0x1001_0000;
const VIRTIO_MMIO_BASE_CONSOLE: u64 = 0x1002_0000;
const VIRTIO_MMIO_SIZE: u64 = 0x1000;
const DEFAULT_GUEST_BASE: u64 = 0x4000_0000;
const DEFAULT_GUEST_HUGEPAGES: usize = 1;
const DMA_BUFFER_SIZE: usize = 64 * 1024;
const DMA_MAPS: usize = 64;
const VIRTIO_DESC_SIZE: u64 = 16;

// ---------------------------------------------------------------------------
// Phase 2: VirtIO Feature Bits
// ---------------------------------------------------------------------------

// VirtIO 1.0 feature bits
const VIRTIO_F_VERSION_1: u64 = 1 << 32;          // VirtIO 1.0 protocol
const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28; // Indirect descriptors
const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;     // Event idx optimization

// Network device features
const VIRTIO_NET_F_CSUM: u64 = 1 << 0;            // Checksum offload
const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;     // Guest checksum
const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;     // Guest TSO IPv4
const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;     // Guest TSO IPv6
const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;     // Host TSO IPv4
const VIRTIO_NET_F_HOST_TSO6: u64 = 1 << 12;     // Host TSO IPv6

// Block device features
const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;        // Max request size
const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;         // Max segments
const VIRTIO_BLK_F_RO: u64 = 1 << 5;              // Read-only
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;           // FLUSH support

// VirtIO device status bits
const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;  // Guest acknowledged device
const VIRTIO_STATUS_DRIVER: u8 = 2;       // Guest driver loaded
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;    // Driver ready
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;  // Feature negotiation OK
const VIRTIO_STATUS_FAILED: u8 = 128;     // Device failed

#[derive(Clone, Copy)]
pub struct DmaMap {
    gpa: u64,
    size: u64,
    offset: u64,
}

/// Scatter-gather entry: guest physical address + length pair for DMA operations
#[derive(Clone, Copy, Debug)]
pub struct SgEntry {
    pub gpa: u64,
    pub len: u32,
}

pub struct DmaEngine {
    buffer: UnsafeCell<[u8; DMA_BUFFER_SIZE]>,
    maps: [UnsafeCell<DmaMap>; DMA_MAPS],
    map_len: AtomicUsize,
    /// Host-virtual-address base of guest RAM (0 = not configured).
    /// When set, GPAs that don't resolve to the DMA side-buffer are
    /// served directly from guest RAM at `guest_host_base + gpa`.
    guest_host_base: AtomicU64,
    /// Size of guest RAM in bytes.
    guest_limit: AtomicU64,
    /// Statistics: total map operations.
    stat_total_maps: AtomicU64,
    /// Statistics: total read operations.
    stat_total_reads: AtomicU64,
    /// Statistics: total write operations.
    stat_total_writes: AtomicU64,
    /// Statistics: cumulative bytes transferred (reads + writes).
    stat_bytes_transferred: AtomicU64,
}

unsafe impl Sync for DmaEngine {}

impl DmaEngine {
    pub const fn new() -> Self {
        const EMPTY_MAP: UnsafeCell<DmaMap> = UnsafeCell::new(DmaMap {
            gpa: 0,
            size: 0,
            offset: 0,
        });
        Self {
            buffer: UnsafeCell::new([0u8; DMA_BUFFER_SIZE]),
            maps: [EMPTY_MAP; DMA_MAPS],
            map_len: AtomicUsize::new(0),
            guest_host_base: AtomicU64::new(0),
            guest_limit: AtomicU64::new(0),
            stat_total_maps: AtomicU64::new(0),
            stat_total_reads: AtomicU64::new(0),
            stat_total_writes: AtomicU64::new(0),
            stat_bytes_transferred: AtomicU64::new(0),
        }
    }

    /// Configure direct guest-RAM backing.  Once set, GPAs not in the
    /// side-buffer map are resolved directly to `host_base + gpa`.
    pub fn set_guest_backing(&self, host_base: u64, limit: u64) {
        self.guest_host_base.store(host_base, Ordering::Release);
        self.guest_limit.store(limit, Ordering::Release);
    }

    pub fn map_region(&self, gpa: u64, size: u64) -> Option<u64> {
        if size == 0 || size as usize > DMA_BUFFER_SIZE {
            return None;
        }
        // Validate GPA is within guest memory limit.
        let limit = self.guest_limit.load(Ordering::Acquire);
        if limit > 0 && gpa.saturating_add(size) > limit {
            return None;  // GPA out of range
        }
        
        // Validate against MMIO holes and reserved regions.
        // MMIO hole: 0xFE000000 - 0xFEE00000 (LAPIC at 0xFEE00000)
        // LAPIC: 0xFEE00000 - 0xFEF00000
        // IOAPIC: 0xFEC00000 - 0xFED00000
        const MMIO_HOLE_START: u64 = 0xFE00_0000;
        const MMIO_HOLE_END: u64 = 0xFF00_0000;
        const LAPIC_BASE: u64 = 0xFEE0_0000;
        const LAPIC_SIZE: u64 = 0x0010_0000;
        const IOAPIC_BASE: u64 = 0xFEC0_0000;
        const IOAPIC_SIZE: u64 = 0x0010_0000;
        
        // Check if GPA range overlaps with MMIO regions
        let gpa_end = gpa.saturating_add(size);
        
        // MMIO hole check
        if gpa < MMIO_HOLE_END && gpa_end > MMIO_HOLE_START {
            return None;  // Overlaps with MMIO hole
        }
        
        // LAPIC check
        if gpa < LAPIC_BASE + LAPIC_SIZE && gpa_end > LAPIC_BASE {
            return None;  // Overlaps with LAPIC
        }
        
        // IOAPIC check
        if gpa < IOAPIC_BASE + IOAPIC_SIZE && gpa_end > IOAPIC_BASE {
            return None;  // Overlaps with IOAPIC
        }
        
        // BIOS/ACPI region check (0xE0000 - 0x100000)
        const BIOS_REGION_START: u64 = 0x000E_0000;
        const BIOS_REGION_END: u64 = 0x0010_0000;
        if gpa < BIOS_REGION_END && gpa_end > BIOS_REGION_START {
            return None;  // Overlaps with BIOS/ACPI region
        }
        
        let count = self.map_len.load(Ordering::Acquire);
        if count >= DMA_MAPS {
            return None;
        }
        // Compute the next free byte in the flat DMA buffer (scan existing mappings).
        let mut next_offset = 0u64;
        for index in 0..count {
            let entry = unsafe { *self.maps[index].get() };
            let end = entry.offset.saturating_add(entry.size);
            if end > next_offset {
                next_offset = end;
            }
        }
        if (next_offset as usize) + (size as usize) > DMA_BUFFER_SIZE {
            return None;
        }

        // Find sorted insertion point (ascending by gpa) so that resolve()
        // can use binary search instead of linear scan.
        let mut insert_at = count;
        for i in 0..count {
            let entry = unsafe { *self.maps[i].get() };
            if gpa < entry.gpa {
                insert_at = i;
                break;
            }
        }
        // Shift entries right to open the insertion slot.
        let mut i = count;
        while i > insert_at {
            unsafe {
                *self.maps[i].get() = *self.maps[i - 1].get();
            }
            i -= 1;
        }
        unsafe {
            *self.maps[insert_at].get() = DmaMap {
                gpa,
                size,
                offset: next_offset,
            };
        }
        self.map_len.store(count + 1, Ordering::Release);
        self.stat_total_maps.fetch_add(1, Ordering::Relaxed);
        Some(next_offset)
    }

    /// Resolve a guest physical address to a host pointer.
    ///
    /// Resolution order:
    ///   1. DMA side-buffer — binary search the sorted `maps` array.
    ///   2. Direct guest RAM — if `guest_host_base` is set and the GPA fits.
    ///
    /// Returns `None` only when neither path can satisfy the request.
    fn resolve_ptr(&self, gpa: u64, size: usize) -> Option<*mut u8> {
        // ── 1. Try DMA side-buffer ──────────────────────────────────────────
        let count = self.map_len.load(Ordering::Acquire);
        if count > 0 {
            let mut lo = 0usize;
            let mut hi = count;
            while lo + 1 < hi {
                let mid = lo + (hi - lo) / 2;
                let entry_gpa = unsafe { (*self.maps[mid].get()).gpa };
                if entry_gpa <= gpa {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            let entry = unsafe { *self.maps[lo].get() };
            if gpa >= entry.gpa && gpa + size as u64 <= entry.gpa + entry.size {
                let offset = (entry.offset + (gpa - entry.gpa)) as usize;
                let buf = unsafe { &mut *self.buffer.get() };
                return Some(buf[offset..].as_mut_ptr());
            }
        }

        // ── 2. Fall back to direct guest RAM ────────────────────────────────
        let host_base = self.guest_host_base.load(Ordering::Acquire);
        let limit = self.guest_limit.load(Ordering::Acquire);
        if host_base != 0 && gpa + size as u64 <= limit {
            return Some((host_base + gpa) as *mut u8);
        }

        None
    }

    pub fn read_u16(&self, gpa: u64) -> Option<u16> {
        let ptr = self.resolve_ptr(gpa, 2)?;
        let mut buf = [0u8; 2];
        unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), 2) };
        self.stat_total_reads.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(2, Ordering::Relaxed);
        Some(u16::from_le_bytes(buf))
    }

    pub fn read_u32(&self, gpa: u64) -> Option<u32> {
        let ptr = self.resolve_ptr(gpa, 4)?;
        let mut buf = [0u8; 4];
        unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), 4) };
        self.stat_total_reads.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(4, Ordering::Relaxed);
        Some(u32::from_le_bytes(buf))
    }

    pub fn read_u64(&self, gpa: u64) -> Option<u64> {
        let ptr = self.resolve_ptr(gpa, 8)?;
        let mut buf = [0u8; 8];
        unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), 8) };
        self.stat_total_reads.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(8, Ordering::Relaxed);
        Some(u64::from_le_bytes(buf))
    }

    pub fn write_u16(&self, gpa: u64, value: u16) -> bool {
        let ptr = match self.resolve_ptr(gpa, 2) {
            Some(p) => p,
            None => return false,
        };
        let bytes = value.to_le_bytes();
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 2) };
        self.stat_total_writes.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(2, Ordering::Relaxed);
        true
    }

    pub fn write_u32(&self, gpa: u64, value: u32) -> bool {
        let ptr = match self.resolve_ptr(gpa, 4) {
            Some(p) => p,
            None => return false,
        };
        let bytes = value.to_le_bytes();
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 4) };
        self.stat_total_writes.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(4, Ordering::Relaxed);
        true
    }

    pub fn write_u64(&self, gpa: u64, value: u64) -> bool {
        let ptr = match self.resolve_ptr(gpa, 8) {
            Some(p) => p,
            None => return false,
        };
        let bytes = value.to_le_bytes();
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, 8) };
        self.stat_total_writes.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(8, Ordering::Relaxed);
        true
    }

    pub fn write_u8(&self, gpa: u64, value: u8) -> bool {
        let ptr = match self.resolve_ptr(gpa, 1) {
            Some(p) => p,
            None => return false,
        };
        unsafe { *ptr = value };
        self.stat_total_writes.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub fn read_u8(&self, gpa: u64) -> Option<u8> {
        let ptr = match self.resolve_ptr(gpa, 1) {
            Some(p) => p,
            None => return None,
        };
        let value = unsafe { *ptr };
        self.stat_total_reads.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(1, Ordering::Relaxed);
        Some(value)
    }

    pub fn read_bytes(&self, gpa: u64, out: &mut [u8]) -> bool {
        let ptr = match self.resolve_ptr(gpa, out.len()) {
            Some(p) => p,
            None => return false,
        };
        unsafe { core::ptr::copy_nonoverlapping(ptr as *const u8, out.as_mut_ptr(), out.len()) };
        self.stat_total_reads.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(out.len() as u64, Ordering::Relaxed);
        true
    }

    pub fn write_bytes(&self, gpa: u64, input: &[u8]) -> bool {
        let ptr = match self.resolve_ptr(gpa, input.len()) {
            Some(p) => p,
            None => return false,
        };
        unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), ptr, input.len()) };
        self.stat_total_writes.fetch_add(1, Ordering::Relaxed);
        self.stat_bytes_transferred.fetch_add(input.len() as u64, Ordering::Relaxed);
        true
    }

    /// Read from multiple non-contiguous guest memory regions into a single buffer.
    /// 
    /// This is useful for VirtIO descriptor chains where data spans multiple
    /// descriptors (e.g., block I/O with header + data + status in separate buffers).
    /// 
    /// Returns the total number of bytes read, or 0 if any segment fails.
    pub fn read_sg(&self, sg_list: &[SgEntry], out: &mut [u8]) -> usize {
        let mut offset = 0usize;
        
        for entry in sg_list {
            let segment_len = entry.len as usize;
            if offset + segment_len > out.len() {
                return 0; // Output buffer too small
            }
            
            if !self.read_bytes(entry.gpa, &mut out[offset..offset + segment_len]) {
                return 0; // Read failed for this segment
            }
            
            offset += segment_len;
        }
        
        offset
    }

    /// Write from a single buffer to multiple non-contiguous guest memory regions.
    /// 
    /// This is useful for filling scattered guest buffers (e.g., network packet
    /// fragmented across multiple RX descriptors).
    /// 
    /// Returns the total number of bytes written, or 0 if any segment fails.
    pub fn write_sg(&self, sg_list: &[SgEntry], input: &[u8]) -> usize {
        let mut offset = 0usize;
        
        for entry in sg_list {
            let segment_len = entry.len as usize;
            if offset + segment_len > input.len() {
                return 0; // Input buffer too small
            }
            
            if !self.write_bytes(entry.gpa, &input[offset..offset + segment_len]) {
                return 0; // Write failed for this segment
            }
            
            offset += segment_len;
        }
        
        offset
    }

    pub fn snapshot(&self, out: &mut [u8; DMA_BUFFER_SIZE]) {
        let buffer = unsafe { &*self.buffer.get() };
        let used = self.map_len.load(Ordering::Acquire);
        if used == 0 {
            out.fill(0);
            return;
        }
        // Only copy up to the highest mapped offset to avoid copying dead space.
        let mut max_end: usize = 0;
        for i in 0..used {
            let entry = unsafe { *self.maps[i].get() };
            let end = (entry.offset + entry.size) as usize;
            if end > max_end {
                max_end = end;
            }
        }
        let copy_len = max_end.min(DMA_BUFFER_SIZE);
        out[..copy_len].copy_from_slice(&buffer[..copy_len]);
        if copy_len < DMA_BUFFER_SIZE {
            out[copy_len..].fill(0);
        }
    }

    pub fn restore(&self, input: &[u8; DMA_BUFFER_SIZE]) {
        let buffer = unsafe { &mut *self.buffer.get() };
        buffer.copy_from_slice(input);
    }

    pub fn reset(&self) {
        self.map_len.store(0, Ordering::Release);
        self.guest_host_base.store(0, Ordering::Release);
        self.guest_limit.store(0, Ordering::Release);
        self.stat_total_maps.store(0, Ordering::Release);
        self.stat_total_reads.store(0, Ordering::Release);
        self.stat_total_writes.store(0, Ordering::Release);
        self.stat_bytes_transferred.store(0, Ordering::Release);
        let buffer = unsafe { &mut *self.buffer.get() };
        buffer.fill(0);
    }

    /// Get DMA statistics: (total_maps, total_reads, total_writes, bytes_transferred).
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stat_total_maps.load(Ordering::Relaxed),
            self.stat_total_reads.load(Ordering::Relaxed),
            self.stat_total_writes.load(Ordering::Relaxed),
            self.stat_bytes_transferred.load(Ordering::Relaxed),
        )
    }
}

pub struct VirtioDirect {
    net_enabled: AtomicU8,
    blk_enabled: AtomicU8,
    console_enabled: AtomicU8,
    net_base: AtomicU64,
    blk_base: AtomicU64,
    console_base: AtomicU64,
    net_device: VirtioDevice,
    blk_device: VirtioDevice,
    console_device: VirtioDevice,
    dma: DmaEngine,
    net_model: VirtioNetModel,
    blk_model: VirtioBlockModel,
    console_model: VirtioConsoleModel,
}

impl VirtioDirect {
    pub const fn new() -> Self {
        Self {
            net_enabled: AtomicU8::new(0),
            blk_enabled: AtomicU8::new(0),
            console_enabled: AtomicU8::new(0),
            net_base: AtomicU64::new(VIRTIO_MMIO_BASE_NET),
            blk_base: AtomicU64::new(VIRTIO_MMIO_BASE_BLK),
            console_base: AtomicU64::new(VIRTIO_MMIO_BASE_CONSOLE),
            net_device: VirtioDevice::new(1),
            blk_device: VirtioDevice::new(2),
            console_device: VirtioDevice::new(3),
            dma: DmaEngine::new(),
            net_model: VirtioNetModel::new(),
            blk_model: VirtioBlockModel::new(),
            console_model: VirtioConsoleModel::new(),
        }
    }

    pub fn enable_default(&self) {
        self.net_enabled.store(1, Ordering::Release);
        self.blk_enabled.store(1, Ordering::Release);
        self.console_enabled.store(1, Ordering::Release);
        self.net_base.store(VIRTIO_MMIO_BASE_NET, Ordering::Release);
        self.blk_base.store(VIRTIO_MMIO_BASE_BLK, Ordering::Release);
        self.console_base.store(VIRTIO_MMIO_BASE_CONSOLE, Ordering::Release);
    }

    /// Wire the DMA engine to real guest RAM so that VirtIO descriptor
    /// addresses (GPAs) resolve directly to guest memory pages instead of
    /// the 64 KiB side buffer.
    pub fn set_guest_backing(&self, host_base: u64, limit: u64) {
        self.dma.set_guest_backing(host_base, limit);
    }

    pub fn status(&self) -> (u8, u8, u64, u64) {
        (
            self.net_enabled.load(Ordering::Acquire),
            self.blk_enabled.load(Ordering::Acquire),
            self.net_base.load(Ordering::Acquire),
            self.blk_base.load(Ordering::Acquire),
        )
    }

    pub fn mmio_read(&self, addr: u64) -> Option<u32> {
        let (device, offset) = self.device_for_addr(addr)?;
        Some(device.read_reg(offset))
    }

    pub fn mmio_write(&self, addr: u64, value: u32) -> bool {
        let (device, offset) = match self.device_for_addr(addr) {
            Some(pair) => pair,
            None => return false,
        };
        device.write_reg(offset, value);
        record_telemetry(TELEMETRY_VIRTIO_MMIO, offset);
        true
    }

    pub fn dma_map(&self, gpa: u64, size: u64) -> Option<u64> {
        self.dma.map_region(gpa, size)
    }

    pub fn dma_read_u32(&self, gpa: u64) -> Option<u32> {
        self.dma.read_u32(gpa)
    }

    pub fn dma_read_u64(&self, gpa: u64) -> Option<u64> {
        self.dma.read_u64(gpa)
    }

    pub fn dma_write_u32(&self, gpa: u64, value: u32) -> bool {
        self.dma.write_u32(gpa, value)
    }

    pub fn dma_write_u64(&self, gpa: u64, value: u64) -> bool {
        self.dma.write_u64(gpa, value)
    }

    pub fn process_queues(&self) -> u32 {
        let mut total = 0;
        total += self.net_device.process_queue(&self.dma, &self.net_model);
        total += self.blk_device.process_queue(&self.dma, &self.blk_model);
        total += self.console_device.process_queue(&self.dma, &self.console_model);
        total
    }

    pub fn snapshot(&self, out: &mut SnapshotVirtioState) {
        out.net = self.net_device.snapshot();
        out.blk = self.blk_device.snapshot();
        out.console = self.console_device.snapshot();
        self.dma.snapshot(&mut out.dma);
        out.net_stats = self.net_model.stats();
        out.blk_stats = self.blk_model.stats();
        out.console_stats = self.console_model.stats();
    }

    pub fn restore(&self, input: &SnapshotVirtioState) {
        self.net_device.restore(&input.net);
        self.blk_device.restore(&input.blk);
        self.console_device.restore(&input.console);
        self.dma.restore(&input.dma);
        self.net_model.restore_stats(input.net_stats);
        self.blk_model.restore_stats(input.blk_stats);
        self.console_model.restore_stats(input.console_stats);
    }

    pub fn reset_backend(&self) {
        self.net_device.restore(&VirtioDeviceState::empty());
        self.blk_device.restore(&VirtioDeviceState::empty());
        self.console_device.restore(&VirtioDeviceState::empty());
        self.dma.reset();
        self.net_model.restore_stats((0, 0, 0));
        self.blk_model.restore_stats((0, 0, 0));
        self.console_model.restore_stats((0, 0, 0));
        console_output_ring().clear();
        net_tx_ring().clear();
        net_rx_ring().clear();
        block_io_ring().clear();
        async_completion_ring().clear();
        multi_port_console().clear_all();
    }

    fn device_for_addr(&self, addr: u64) -> Option<(&VirtioDevice, u32)> {
        let net_base = self.net_base.load(Ordering::Acquire);
        let blk_base = self.blk_base.load(Ordering::Acquire);
        let console_base = self.console_base.load(Ordering::Acquire);
        
        if self.net_enabled.load(Ordering::Acquire) != 0
            && addr >= net_base
            && addr < net_base + VIRTIO_MMIO_SIZE
        {
            return Some((&self.net_device, (addr - net_base) as u32));
        }
        if self.blk_enabled.load(Ordering::Acquire) != 0
            && addr >= blk_base
            && addr < blk_base + VIRTIO_MMIO_SIZE
        {
            return Some((&self.blk_device, (addr - blk_base) as u32));
        }
        if self.console_enabled.load(Ordering::Acquire) != 0
            && addr >= console_base
            && addr < console_base + VIRTIO_MMIO_SIZE
        {
            return Some((&self.console_device, (addr - console_base) as u32));
        }
        None
    }
}

static VIRTIO_DIRECT: VirtioDirect = VirtioDirect::new();

pub fn virtio_direct() -> &'static VirtioDirect {
    &VIRTIO_DIRECT
}

pub struct VirtioDevice {
    device_id: u32,
    queue_num_max: u32,
    queue_num: AtomicU32,
    queue_ready: AtomicU8,
    queue_desc: AtomicU64,
    queue_avail: AtomicU64,
    queue_used: AtomicU64,
    queue_notify: AtomicU32,
    queue_select: AtomicU32,
    last_avail: AtomicU16,
    used_idx: AtomicU16,
    
    // Phase 2: Feature negotiation
    device_features: AtomicU64,    // Features offered by device
    driver_features: AtomicU64,    // Features accepted by driver
    device_status: AtomicU8,       // Device status (ACKNOWLEDGE, DRIVER, etc.)
    
    // Phase 2: Event idx optimization
    avail_event_idx: AtomicU16,    // Suppress notifications until idx
    used_event_idx: AtomicU16,     // Guest wants notification at idx
    
    // Phase 2: Interrupt coalescing
    irq_pending: AtomicU32,        // Pending interrupt count
    irq_coalesce_thresh: AtomicU32, // Coalesce threshold (0 = disabled)
}

impl VirtioDevice {
    pub const fn new(device_id: u32) -> Self {
        Self {
            device_id,
            queue_num_max: 256,
            queue_num: AtomicU32::new(0),
            queue_ready: AtomicU8::new(0),
            queue_desc: AtomicU64::new(0),
            queue_avail: AtomicU64::new(0),
            queue_used: AtomicU64::new(0),
            queue_notify: AtomicU32::new(0),
            queue_select: AtomicU32::new(0),
            last_avail: AtomicU16::new(0),
            used_idx: AtomicU16::new(0),
            device_features: AtomicU64::new(0),
            driver_features: AtomicU64::new(0),
            device_status: AtomicU8::new(0),
            avail_event_idx: AtomicU16::new(0),
            used_event_idx: AtomicU16::new(0),
            irq_pending: AtomicU32::new(0),
            irq_coalesce_thresh: AtomicU32::new(0),
        }
    }
    
    // Phase 2: Set device features (called at init)
    pub fn set_device_features(&self, features: u64) {
        self.device_features.store(features, Ordering::Release);
    }
    
    // Phase 2: Check if feature is negotiated
    pub fn has_feature(&self, bit: u64) -> bool {
        let driver = self.driver_features.load(Ordering::Acquire);
        (driver & bit) != 0
    }
    
    // Phase 2: Device status state machine
    pub fn set_status(&self, status: u8) {
        let old = self.device_status.load(Ordering::Acquire);
        
        // Validate state transitions
        if status == VIRTIO_STATUS_FAILED {
            // FAILED can be set at any time
            self.device_status.store(status, Ordering::Release);
            return;
        }
        
        // Check valid progression: ACKNOWLEDGE -> DRIVER -> FEATURES_OK -> DRIVER_OK
        if status & VIRTIO_STATUS_ACKNOWLEDGE != 0 && old == 0 {
            // First transition: 0 -> ACKNOWLEDGE
            self.device_status.store(status, Ordering::Release);
        } else if status & VIRTIO_STATUS_DRIVER != 0 && old & VIRTIO_STATUS_ACKNOWLEDGE != 0 {
            // ACKNOWLEDGE -> DRIVER
            self.device_status.store(status, Ordering::Release);
        } else if status & VIRTIO_STATUS_FEATURES_OK != 0 && old & VIRTIO_STATUS_DRIVER != 0 {
            // DRIVER -> FEATURES_OK
            self.device_status.store(status, Ordering::Release);
        } else if status & VIRTIO_STATUS_DRIVER_OK != 0 && old & VIRTIO_STATUS_FEATURES_OK != 0 {
            // FEATURES_OK -> DRIVER_OK (device fully initialized)
            self.device_status.store(status, Ordering::Release);
        } else if status == 0 {
            // Reset
            self.device_status.store(0, Ordering::Release);
            self.driver_features.store(0, Ordering::Release);
        }
    }
    
    pub fn get_status(&self) -> u8 {
        self.device_status.load(Ordering::Acquire)
    }
    
    pub fn is_driver_ok(&self) -> bool {
        self.get_status() & VIRTIO_STATUS_DRIVER_OK != 0
    }

    pub fn snapshot(&self) -> VirtioDeviceState {
        VirtioDeviceState {
            queue_num: self.queue_num.load(Ordering::Acquire),
            queue_ready: self.queue_ready.load(Ordering::Acquire),
            queue_desc: self.queue_desc.load(Ordering::Acquire),
            queue_avail: self.queue_avail.load(Ordering::Acquire),
            queue_used: self.queue_used.load(Ordering::Acquire),
            queue_notify: self.queue_notify.load(Ordering::Acquire),
            queue_select: self.queue_select.load(Ordering::Acquire),
            last_avail: self.last_avail.load(Ordering::Acquire),
            used_idx: self.used_idx.load(Ordering::Acquire),
        }
    }

    pub fn restore(&self, state: &VirtioDeviceState) {
        self.queue_num.store(state.queue_num, Ordering::Release);
        self.queue_ready.store(state.queue_ready, Ordering::Release);
        self.queue_desc.store(state.queue_desc, Ordering::Release);
        self.queue_avail.store(state.queue_avail, Ordering::Release);
        self.queue_used.store(state.queue_used, Ordering::Release);
        self.queue_notify
            .store(state.queue_notify, Ordering::Release);
        self.queue_select
            .store(state.queue_select, Ordering::Release);
        self.last_avail.store(state.last_avail, Ordering::Release);
        self.used_idx.store(state.used_idx, Ordering::Release);
    }

    pub fn read_reg(&self, offset: u32) -> u32 {
        match offset {
            0x000 => 0x74726976,
            0x004 => 2,
            0x008 => self.device_id,
            0x00c => 0x1af4,
            0x034 => self.queue_num_max,
            0x038 => self.queue_num.load(Ordering::Acquire),
            0x044 => self.queue_ready.load(Ordering::Acquire) as u32,
            0x050 => self.queue_notify.load(Ordering::Acquire),
            0x080 => self.queue_desc.load(Ordering::Acquire) as u32,
            0x084 => (self.queue_desc.load(Ordering::Acquire) >> 32) as u32,
            0x090 => self.queue_avail.load(Ordering::Acquire) as u32,
            0x094 => (self.queue_avail.load(Ordering::Acquire) >> 32) as u32,
            0x0A0 => self.queue_used.load(Ordering::Acquire) as u32,
            0x0A4 => (self.queue_used.load(Ordering::Acquire) >> 32) as u32,
            0x030 => self.queue_select.load(Ordering::Acquire),
            // Phase 2: Feature negotiation registers
            0x010 => self.device_features.load(Ordering::Acquire) as u32,        // DeviceFeatures low
            0x014 => (self.device_features.load(Ordering::Acquire) >> 32) as u32, // DeviceFeatures high
            0x020 => self.driver_features.load(Ordering::Acquire) as u32,        // DriverFeatures low
            0x024 => (self.driver_features.load(Ordering::Acquire) >> 32) as u32, // DriverFeatures high
            // Phase 2: Device status
            0x070 => self.device_status.load(Ordering::Acquire) as u32,
            _ => 0,
        }
    }

    pub fn write_reg(&self, offset: u32, value: u32) {
        match offset {
            0x030 => {
                self.queue_select.store(value, Ordering::Release);
            }
            0x038 => {
                let capped = value.min(self.queue_num_max);
                self.queue_num.store(capped, Ordering::Release);
            }
            0x044 => {
                self.queue_ready.store((value & 1) as u8, Ordering::Release);
            }
            0x050 => {
                self.queue_notify.fetch_add(1, Ordering::Relaxed);
            }
            0x080 => {
                let high = self.queue_desc.load(Ordering::Acquire) & 0xFFFF_FFFF_0000_0000;
                self.queue_desc
                    .store(high | value as u64, Ordering::Release);
            }
            0x084 => {
                let low = self.queue_desc.load(Ordering::Acquire) & 0x0000_0000_FFFF_FFFF;
                self.queue_desc
                    .store(low | ((value as u64) << 32), Ordering::Release);
            }
            0x090 => {
                let high = self.queue_avail.load(Ordering::Acquire) & 0xFFFF_FFFF_0000_0000;
                self.queue_avail
                    .store(high | value as u64, Ordering::Release);
            }
            0x094 => {
                let low = self.queue_avail.load(Ordering::Acquire) & 0x0000_0000_FFFF_FFFF;
                self.queue_avail
                    .store(low | ((value as u64) << 32), Ordering::Release);
            }
            0x0A0 => {
                let high = self.queue_used.load(Ordering::Acquire) & 0xFFFF_FFFF_0000_0000;
                self.queue_used
                    .store(high | value as u64, Ordering::Release);
            }
            0x0A4 => {
                let low = self.queue_used.load(Ordering::Acquire) & 0x0000_0000_FFFF_FFFF;
                self.queue_used
                    .store(low | ((value as u64) << 32), Ordering::Release);
            }
            // Phase 2: Driver features write
            0x020 => {
                let high = self.driver_features.load(Ordering::Acquire) & 0xFFFF_FFFF_0000_0000;
                self.driver_features.store(high | value as u64, Ordering::Release);
            }
            0x024 => {
                let low = self.driver_features.load(Ordering::Acquire) & 0x0000_0000_FFFF_FFFF;
                self.driver_features.store(low | ((value as u64) << 32), Ordering::Release);
            }
            // Phase 2: Device status write
            0x070 => {
                self.set_status(value as u8);
            }
            _ => {}
        }
    }

    pub fn process_queue<M: VirtioModel>(&self, dma: &DmaEngine, model: &M) -> u32 {
        if self.queue_ready.load(Ordering::Acquire) == 0 {
            return 0;
        }
        let notify = self.queue_notify.load(Ordering::Acquire);
        if notify == 0 {
            return 0;
        }
        let desc_base = self.queue_desc.load(Ordering::Acquire);
        let avail_base = self.queue_avail.load(Ordering::Acquire);
        let used_base = self.queue_used.load(Ordering::Acquire);
        let avail_idx = match dma.read_u16(avail_base + 2) {
            Some(value) => value,
            None => return 0,
        };
        let mut last_avail = self.last_avail.load(Ordering::Acquire);
        let mut used = self.used_idx.load(Ordering::Acquire);
        let mut processed = 0u32;
        while last_avail != avail_idx {
            // Read head descriptor index from avail ring
            let avail_slot = (last_avail as u64 % 256) * 2;
            let head_idx = match dma.read_u16(avail_base + 4 + avail_slot) {
                Some(idx) => idx,
                None => break,
            };
            
            // Walk descriptor chain starting at head_idx
            let chain = DescChainIter::new(dma, desc_base, head_idx);
            let mut chain_processed = false;
            
            for desc in chain {
                // Process each descriptor in the chain
                // For now, we process the first descriptor only (legacy behavior)
                // Full multi-descriptor support will be added per-device basis
                if model.process_desc(dma, desc.gpa, desc.len, desc.flags) {
                    chain_processed = true;
                }
                break; // Legacy: process only first descriptor
            }
            
            if chain_processed {
                used = used.wrapping_add(1);
                processed = processed.wrapping_add(1);
            }
            
            last_avail = last_avail.wrapping_add(1);
        }
        let _ = dma.write_u16(used_base + 2, used);
        self.used_idx.store(used, Ordering::Release);
        self.last_avail.store(last_avail, Ordering::Release);
        self.queue_notify.store(0, Ordering::Release);
        processed
    }
}

#[derive(Clone, Copy)]
pub struct VirtioDeviceState {
    queue_num: u32,
    queue_ready: u8,
    queue_desc: u64,
    queue_avail: u64,
    queue_used: u64,
    queue_notify: u32,
    queue_select: u32,
    last_avail: u16,
    used_idx: u16,
}

impl VirtioDeviceState {
    pub const fn empty() -> Self {
        Self {
            queue_num: 0,
            queue_ready: 0,
            queue_desc: 0,
            queue_avail: 0,
            queue_used: 0,
            queue_notify: 0,
            queue_select: 0,
            last_avail: 0,
            used_idx: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// VirtIO Descriptor Chain Walker
// ---------------------------------------------------------------------------

const VIRTIO_DESC_F_NEXT: u32 = 1;       // Descriptor continues via next field
const VIRTIO_DESC_F_WRITE: u32 = 2;      // Device writes (read-only for guest)
const VIRTIO_DESC_F_INDIRECT: u32 = 4;   // Buffer contains indirect descriptors

/// Single descriptor in a chain
#[derive(Clone, Copy, Debug)]
pub struct VirtioDescriptor {
    pub gpa: u64,      // Guest physical address
    pub len: u32,      // Byte length
    pub flags: u32,    // VIRTIO_DESC_F_* flags
    pub next: u16,     // Next descriptor index (if NEXT flag set)
}

impl VirtioDescriptor {
    /// Check if descriptor has NEXT flag (part of chain)
    pub fn has_next(&self) -> bool {
        (self.flags & VIRTIO_DESC_F_NEXT) != 0
    }

    /// Check if descriptor is device-writable (guest read-only)
    pub fn is_write(&self) -> bool {
        (self.flags & VIRTIO_DESC_F_WRITE) != 0
    }

    /// Check if descriptor points to indirect descriptor table
    pub fn is_indirect(&self) -> bool {
        (self.flags & VIRTIO_DESC_F_INDIRECT) != 0
    }
}

/// Descriptor chain iterator - walks multi-descriptor chains
pub struct DescChainIter<'a> {
    dma: &'a DmaEngine,
    desc_base: u64,
    current_idx: u16,
    chain_len: u8,
    max_chain_len: u8,
}

impl<'a> DescChainIter<'a> {
    /// Create a new chain iterator starting at `head_idx` in descriptor table
    pub fn new(dma: &'a DmaEngine, desc_base: u64, head_idx: u16) -> Self {
        Self {
            dma,
            desc_base,
            current_idx: head_idx,
            chain_len: 0,
            max_chain_len: 32, // VirtIO typical limit to prevent infinite loops
        }
    }

    /// Read descriptor at given index from descriptor table
    fn read_desc(&self, idx: u16) -> Option<VirtioDescriptor> {
        let desc_addr = self.desc_base + (idx as u64 * VIRTIO_DESC_SIZE);
        
        let gpa = self.dma.read_u64(desc_addr)?;
        let len = self.dma.read_u32(desc_addr + 8)?;
        let flags_u16 = self.dma.read_u16(desc_addr + 12)?;
        let next = self.dma.read_u16(desc_addr + 14)?;
        
        Some(VirtioDescriptor {
            gpa,
            len,
            flags: flags_u16 as u32,
            next,
        })
    }
}

impl Iterator for DescChainIter<'_> {
    type Item = VirtioDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.chain_len >= self.max_chain_len {
            return None; // Prevent infinite loops from malformed chains
        }

        let desc = self.read_desc(self.current_idx)?;
        self.chain_len += 1;

        if desc.has_next() {
            self.current_idx = desc.next;
        } else {
            // Mark end of chain by setting impossible index
            self.current_idx = 0xFFFF;
        }

        Some(desc)
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Indirect Descriptor Table Support
// ---------------------------------------------------------------------------

/// Iterator for processing indirect descriptor tables
/// Indirect descriptors allow a single descriptor to point to a table of descriptors
pub struct IndirectDescIter<'a> {
    dma: &'a DmaEngine,
    table_gpa: u64,
    table_len: u32,
    current_offset: u32,
}

impl<'a> IndirectDescIter<'a> {
    /// Create new indirect descriptor iterator
    /// `table_gpa`: Guest physical address of indirect descriptor table
    /// `table_len`: Total byte length of table
    pub fn new(dma: &'a DmaEngine, table_gpa: u64, table_len: u32) -> Self {
        Self {
            dma,
            table_gpa,
            table_len,
            current_offset: 0,
        }
    }
}

impl Iterator for IndirectDescIter<'_> {
    type Item = VirtioDescriptor;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset + 16 > self.table_len {
            return None;
        }

        let desc_addr = self.table_gpa + self.current_offset as u64;
        let gpa = self.dma.read_u64(desc_addr)?;
        let len = self.dma.read_u32(desc_addr + 8)?;
        let flags_u16 = self.dma.read_u16(desc_addr + 12)?;
        let next = self.dma.read_u16(desc_addr + 14)?;

        self.current_offset += 16;

        Some(VirtioDescriptor {
            gpa,
            len,
            flags: flags_u16 as u32,
            next,
        })
    }
}

// ---------------------------------------------------------------------------
// Phase 2: Used Ring Updates
// ---------------------------------------------------------------------------

/// Used ring element (id + len)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UsedElem {
    pub id: u32,  // Descriptor chain head index
    pub len: u32, // Total bytes written by device
}

/// Write a used ring element at the given index
/// Returns true on success, false if DMA write failed
pub fn write_used_elem(dma: &DmaEngine, used_base: u64, idx: u16, elem: UsedElem) -> bool {
    let elem_offset = 4 + (idx as u64 % 256) * 8; // Skip flags(2) + idx(2)
    let elem_addr = used_base + elem_offset;
    
    if !dma.write_u32(elem_addr, elem.id) {
        return false;
    }
    if !dma.write_u32(elem_addr + 4, elem.len) {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Phase 2: Interrupt Coalescing
// ---------------------------------------------------------------------------

/// Interrupt coalescing to reduce VM exits
/// Batches interrupts until threshold is reached or timeout expires
pub struct InterruptCoalescer {
    pending: AtomicU32,
    threshold: AtomicU32,
    last_delivery: AtomicU64,
}

impl InterruptCoalescer {
    pub const fn new() -> Self {
        Self {
            pending: AtomicU32::new(0),
            threshold: AtomicU32::new(0), // 0 = disabled, deliver immediately
            last_delivery: AtomicU64::new(0),
        }
    }
    
    /// Set coalescing threshold (0 = disabled)
    pub fn set_threshold(&self, threshold: u32) {
        self.threshold.store(threshold, Ordering::Release);
    }
    
    /// Check if interrupt should be delivered now
    pub fn should_deliver(&self) -> bool {
        let threshold = self.threshold.load(Ordering::Acquire);
        if threshold == 0 {
            return true; // Coalescing disabled
        }
        
        let pending = self.pending.load(Ordering::Acquire);
        pending >= threshold
    }
    
    /// Add a pending interrupt
    pub fn add_pending(&self) {
        self.pending.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Clear pending interrupts and return previous count
    pub fn clear_pending(&self) -> u32 {
        self.pending.swap(0, Ordering::Relaxed)
    }
}

static IRQ_COALESCER: InterruptCoalescer = InterruptCoalescer::new();

pub fn irq_coalescer() -> &'static InterruptCoalescer {
    &IRQ_COALESCER
}

pub trait VirtioModel {
    fn process_desc(&self, dma: &DmaEngine, gpa: u64, len: u32, flags: u32) -> bool;
    fn stats(&self) -> (u64, u64, u32);
    fn restore_stats(&self, stats: (u64, u64, u32));
}

// ---------------------------------------------------------------------------
// Console Output Ring — Guest VirtIO console TX (guest→host output)
// ---------------------------------------------------------------------------

const CONSOLE_OUTPUT_SIZE: usize = 8192;

pub struct ConsoleOutputRing {
    buffer: UnsafeCell<[u8; CONSOLE_OUTPUT_SIZE]>,
    head: AtomicUsize,
}

unsafe impl Sync for ConsoleOutputRing {}

impl ConsoleOutputRing {
    pub const fn new() -> Self {
        Self {
            buffer: UnsafeCell::new([0u8; CONSOLE_OUTPUT_SIZE]),
            head: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        
        let current = self.head.load(Ordering::Acquire);
        if current + data.len() > CONSOLE_OUTPUT_SIZE {
            return false; // Ring full
        }
        
        let buf = unsafe { &mut *self.buffer.get() };
        let start = current % CONSOLE_OUTPUT_SIZE;
        
        if start + data.len() <= CONSOLE_OUTPUT_SIZE {
            buf[start..start + data.len()].copy_from_slice(data);
        } else {
            let first = CONSOLE_OUTPUT_SIZE - start;
            buf[start..].copy_from_slice(&data[..first]);
            buf[..data.len() - first].copy_from_slice(&data[first..]);
        }
        
        self.head.store(current + data.len(), Ordering::Release);
        true
    }

    pub fn drain(&self, dst: &mut [u8]) -> usize {
        let h = self.head.load(Ordering::Acquire);
        let avail = h.min(CONSOLE_OUTPUT_SIZE);
        let start = if h > CONSOLE_OUTPUT_SIZE { 
            h - CONSOLE_OUTPUT_SIZE 
        } else { 
            0 
        };
        let count = avail.min(dst.len());
        
        let buf = unsafe { &*self.buffer.get() };
        for i in 0..count {
            let slot = (start + i) % CONSOLE_OUTPUT_SIZE;
            dst[i] = buf[slot];
        }
        count
    }
    
    pub fn clear(&self) {
        self.head.store(0, Ordering::Release);
    }
}

static CONSOLE_OUTPUT: ConsoleOutputRing = ConsoleOutputRing::new();

pub fn console_output_ring() -> &'static ConsoleOutputRing {
    &CONSOLE_OUTPUT
}

// ---------------------------------------------------------------------------
// Console Input Ring — Host-to-guest COM1-style input (host→guest RX)
// ---------------------------------------------------------------------------

const CONSOLE_INPUT_SIZE: usize = 256;

pub struct ConsoleInputRing {
    buffer: UnsafeCell<[u8; CONSOLE_INPUT_SIZE]>,
    write_head: AtomicUsize,
    read_head: AtomicUsize,
}

unsafe impl Sync for ConsoleInputRing {}

impl ConsoleInputRing {
    pub const fn new() -> Self {
        Self {
            buffer: UnsafeCell::new([0u8; CONSOLE_INPUT_SIZE]),
            write_head: AtomicUsize::new(0),
            read_head: AtomicUsize::new(0),
        }
    }

    pub fn push(&self, byte: u8) -> bool {
        let w = self.write_head.load(Ordering::Acquire);
        let r = self.read_head.load(Ordering::Acquire);
        
        if w - r >= CONSOLE_INPUT_SIZE {
            return false; // Full
        }
        
        let buf = unsafe { &mut *self.buffer.get() };
        buf[w % CONSOLE_INPUT_SIZE] = byte;
        self.write_head.store(w + 1, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<u8> {
        let r = self.read_head.load(Ordering::Acquire);
        let w = self.write_head.load(Ordering::Acquire);
        
        if r >= w {
            return None; // Empty
        }
        
        let buf = unsafe { &*self.buffer.get() };
        let byte = buf[r % CONSOLE_INPUT_SIZE];
        self.read_head.store(r + 1, Ordering::Release);
        Some(byte)
    }
    
    pub fn available(&self) -> usize {
        let w = self.write_head.load(Ordering::Acquire);
        let r = self.read_head.load(Ordering::Acquire);
        w.wrapping_sub(r).min(CONSOLE_INPUT_SIZE)
    }
}

static CONSOLE_INPUT: ConsoleInputRing = ConsoleInputRing::new();

pub fn console_input_ring() -> &'static ConsoleInputRing {
    &CONSOLE_INPUT
}

// ---------------------------------------------------------------------------
// VirtIO Console Model — processes console TX/RX descriptors
// ---------------------------------------------------------------------------

pub struct VirtioConsoleModel {
    rx: AtomicU64,
    tx: AtomicU64,
    last_len: AtomicU32,
}

impl VirtioConsoleModel {
    pub const fn new() -> Self {
        Self {
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            last_len: AtomicU32::new(0),
        }
    }
}

impl VirtioModel for VirtioConsoleModel {
    fn process_desc(&self, dma: &DmaEngine, gpa: u64, len: u32, flags: u32) -> bool {
        if flags & 1 == 0 {
            // RX direction: inject bytes from host input ring to guest
            let mut bytes_written = 0u32;
            
            while bytes_written < len {
                if let Some(byte) = console_input_ring().pop() {
                    if dma.write_u8(gpa + bytes_written as u64, byte) {
                        bytes_written += 1;
                    } else {
                        break;
                    }
                } else {
                    break; // No more input available
                }
            }
            
            if bytes_written > 0 {
                self.rx.fetch_add(1, Ordering::Relaxed);
                self.last_len.store(bytes_written, Ordering::Relaxed);
                true
            } else {
                false
            }
        } else {
            // TX direction: read from guest descriptor and push to output ring
            let read_len = len.min(256) as usize;
            let mut tmp = [0u8; 256];
            
            let ok = dma.read_bytes(gpa, &mut tmp[..read_len]);
            if ok {
                if console_output_ring().push(&tmp[..read_len]) {
                    self.tx.fetch_add(1, Ordering::Relaxed);
                    self.last_len.store(len, Ordering::Relaxed);
                    true
                } else {
                    false // Output ring full
                }
            } else {
                false
            }
        }
    }

    fn stats(&self) -> (u64, u64, u32) {
        (
            self.rx.load(Ordering::Acquire),
            self.tx.load(Ordering::Acquire),
            self.last_len.load(Ordering::Acquire),
        )
    }

    fn restore_stats(&self, stats: (u64, u64, u32)) {
        self.rx.store(stats.0, Ordering::Release);
        self.tx.store(stats.1, Ordering::Release);
        self.last_len.store(stats.2, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// VirtIO Net Model
// ---------------------------------------------------------------------------

pub struct VirtioNetModel {
    rx: AtomicU64,
    tx: AtomicU64,
    last_len: AtomicU32,
}

impl VirtioNetModel {
    pub const fn new() -> Self {
        Self {
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
            last_len: AtomicU32::new(0),
        }
    }
}

impl VirtioModel for VirtioNetModel {
    fn process_desc(&self, dma: &DmaEngine, gpa: u64, len: u32, flags: u32) -> bool {
        if flags & 1 == 0 {
            // RX direction: pop a packet from host-injected ring, prepend VirtNetHdr
            if len < 12 {
                return false; // Not enough space for VirtNetHdr
            }
            
            let mut tmp = [0u8; RX_SLOT_SIZE];
            let pkt_len = if let Some(len) = net_rx_ring().pop(&mut tmp) {
                len
            } else {
                // No packet pending - write zeros to keep descriptor valid
                let write_len = (len as usize).min(RX_SLOT_SIZE);
                let zeros = [0u8; RX_SLOT_SIZE];
                let ok = dma.write_bytes(gpa, &zeros[..write_len]);
                if ok {
                    self.rx.fetch_add(1, Ordering::Relaxed);
                    self.last_len.store(0, Ordering::Relaxed);
                }
                return ok;
            };
            
            // Build VirtNetHdr (12 bytes zero for simple RX, no offload)
            let hdr = VirtNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
                num_buffers: 1,
            };
            
            // Write VirtNetHdr (12 bytes)
            let hdr_bytes = [
                hdr.flags,
                hdr.gso_type,
                (hdr.hdr_len & 0xFF) as u8,
                (hdr.hdr_len >> 8) as u8,
                (hdr.gso_size & 0xFF) as u8,
                (hdr.gso_size >> 8) as u8,
                (hdr.csum_start & 0xFF) as u8,
                (hdr.csum_start >> 8) as u8,
                (hdr.csum_offset & 0xFF) as u8,
                (hdr.csum_offset >> 8) as u8,
                (hdr.num_buffers & 0xFF) as u8,
                (hdr.num_buffers >> 8) as u8,
            ];
            
            if !dma.write_bytes(gpa, &hdr_bytes) {
                return false;
            }
            
            // Write packet data after header
            let frame_space = (len as usize).saturating_sub(12);
            let write_len = pkt_len.min(frame_space);
            let ok = dma.write_bytes(gpa + 12, &tmp[..write_len]);
            if ok {
                self.rx.fetch_add(1, Ordering::Relaxed);
                self.last_len.store(write_len as u32, Ordering::Relaxed);
            }
            ok
        } else {
            // TX direction: parse VirtNetHdr (12 bytes) + frame data, push to TX command queue
            if len < 12 {
                return false; // Invalid: must have at least VirtNetHdr
            }
            
            // Read VirtNetHdr (12 bytes)
            let mut hdr_bytes = [0u8; 12];
            if !dma.read_bytes(gpa, &mut hdr_bytes) {
                return false;
            }
            
            let hdr = VirtNetHdr {
                flags: hdr_bytes[0],
                gso_type: hdr_bytes[1],
                hdr_len: u16::from_le_bytes([hdr_bytes[2], hdr_bytes[3]]),
                gso_size: u16::from_le_bytes([hdr_bytes[4], hdr_bytes[5]]),
                csum_start: u16::from_le_bytes([hdr_bytes[6], hdr_bytes[7]]),
                csum_offset: u16::from_le_bytes([hdr_bytes[8], hdr_bytes[9]]),
                num_buffers: u16::from_le_bytes([hdr_bytes[10], hdr_bytes[11]]),
            };
            
            // Read frame data (len - 12 bytes, max 1514)
            let frame_len = (len as usize - 12).min(1514);
            let mut frame_data = [0u8; 1514];
            if frame_len > 0 {
                if !dma.read_bytes(gpa + 12, &mut frame_data[..frame_len]) {
                    return false;
                }
            }
            
            // Push to TX command queue for echOS kernel-bypass NIC
            let frame = EthernetFrame {
                hdr,
                data: frame_data,
                len: frame_len as u16,
            };
            
            let ok = net_tx_ring().push(frame);
            if ok {
                self.tx.fetch_add(1, Ordering::Relaxed);
                self.last_len.store(frame_len as u32, Ordering::Relaxed);
            }
            ok
        }
    }

    fn stats(&self) -> (u64, u64, u32) {
        (
            self.rx.load(Ordering::Acquire),
            self.tx.load(Ordering::Acquire),
            self.last_len.load(Ordering::Acquire),
        )
    }

    fn restore_stats(&self, stats: (u64, u64, u32)) {
        self.rx.store(stats.0, Ordering::Release);
        self.tx.store(stats.1, Ordering::Release);
        self.last_len.store(stats.2, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// VirtIO Block I/O Command Queue
// ---------------------------------------------------------------------------

// VirtIO block request types
const VIRTIO_BLK_T_IN: u32 = 0;     // Read from device
const VIRTIO_BLK_T_OUT: u32 = 1;    // Write to device
const VIRTIO_BLK_T_FLUSH: u32 = 4;  // Flush cache
const VIRTIO_BLK_T_DISCARD: u32 = 11; // Discard/TRIM

// VirtIO block status codes
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Phase 2: Validate block sector addressing (512-byte alignment)
/// Returns true if sector range is valid and won't overflow
pub fn validate_block_sector(sector: u64, num_sectors: u32) -> bool {
    // Check for overflow in sector addressing
    if sector > (u64::MAX >> 9) {
        return false;
    }
    // Check that total sectors don't overflow
    let total_sectors = sector.checked_add(num_sectors as u64);
    if total_sectors.is_none() {
        return false;
    }
    // Sector addressing is naturally 512-byte aligned
    true
}

// VirtIO block request header (16 bytes) - first descriptor in chain
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtBlkRequest {
    pub req_type: u32,   // VIRTIO_BLK_T_IN/OUT/FLUSH/DISCARD
    pub reserved: u32,   // Must be 0
    pub sector: u64,     // 512-byte sector offset (Phase 2: validated for overflow)
}

impl VirtBlkRequest {
    pub const ZERO: Self = Self {
        req_type: 0,
        reserved: 0,
        sector: 0,
    };
}

// Parsed block I/O command for echOS io_uring/NVMe driver
#[derive(Clone, Copy)]
pub struct BlockIoCmd {
    pub req_type: u32,       // IN/OUT/FLUSH/DISCARD
    pub sector: u64,         // Starting 512-byte sector
    pub data_gpa: u64,       // Guest physical address of data buffer
    pub data_len: u32,       // Data length in bytes
    pub status_gpa: u64,     // GPA to write status byte (last descriptor)
}

impl BlockIoCmd {
    pub const ZERO: Self = Self {
        req_type: 0,
        sector: 0,
        data_gpa: 0,
        data_len: 0,
        status_gpa: 0,
    };
}

const BLOCK_CMD_RING_SIZE: usize = 128;

// BlockIoCmdRing — lock-free 128-slot command queue.
// VirtioBlockModel pushes parsed block requests here.
// echOS io_uring/NVMe driver calls `block_io_ring().pop()` to drain and execute.
#[repr(C)]
pub struct BlockIoCmdRing {
    slots: UnsafeCell<[BlockIoCmd; BLOCK_CMD_RING_SIZE]>,
    head: AtomicUsize,   // VirtIO producer advances this
    _pad_head: [u8; 56],
    tail: AtomicUsize,   // echOS consumer advances this
    _pad_tail: [u8; 56],
}

unsafe impl Sync for BlockIoCmdRing {}

impl BlockIoCmdRing {
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([BlockIoCmd::ZERO; BLOCK_CMD_RING_SIZE]),
            head: AtomicUsize::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad_tail: [0u8; 56],
        }
    }

    /// Push a parsed block I/O command. Returns false if ring full.
    pub fn push(&self, cmd: BlockIoCmd) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= BLOCK_CMD_RING_SIZE {
            return false; // ring full
        }
        let slot = head & (BLOCK_CMD_RING_SIZE - 1);
        unsafe {
            (*self.slots.get())[slot] = cmd;
        }
        self.head.fetch_add(1, Ordering::Release);
        true
    }

    /// Pop a command for echOS io_uring/NVMe to execute. Returns None if empty.
    pub fn pop(&self) -> Option<BlockIoCmd> {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            return None; // ring empty
        }
        let slot = tail & (BLOCK_CMD_RING_SIZE - 1);
        let cmd = unsafe { (*self.slots.get())[slot] };
        self.tail.fetch_add(1, Ordering::Release);
        Some(cmd)
    }

    /// Number of commands pending execution.
    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(BLOCK_CMD_RING_SIZE)
    }

    /// Clear all pending commands (for reset/snapshot restore).
    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        self.head.store(tail, Ordering::Release);
    }
}

static BLOCK_IO_RING: BlockIoCmdRing = BlockIoCmdRing::new();

pub fn block_io_ring() -> &'static BlockIoCmdRing {
    &BLOCK_IO_RING
}

// ---------------------------------------------------------------------------
// VirtIO Block Model (with legacy storage buffer for testing)
// ---------------------------------------------------------------------------

const BLOCK_STORAGE_SIZE: usize = 128 * 1024;

pub struct VirtioBlockModel {
    storage: UnsafeCell<[u8; BLOCK_STORAGE_SIZE]>,
    cursor: AtomicUsize,
    reads: AtomicU64,
    writes: AtomicU64,
    last_len: AtomicU32,
}

unsafe impl Sync for VirtioBlockModel {}

impl VirtioBlockModel {
    pub const fn new() -> Self {
        Self {
            storage: UnsafeCell::new([0u8; BLOCK_STORAGE_SIZE]),
            cursor: AtomicUsize::new(0),
            reads: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            last_len: AtomicU32::new(0),
        }
    }

    fn next_offset(&self, len: usize) -> usize {
        loop {
            let cursor = self.cursor.load(Ordering::Relaxed);
            let mut next = cursor + len;
            if next >= BLOCK_STORAGE_SIZE {
                next = len; // wrap: new offset starts at 0
            }
            match self.cursor.compare_exchange_weak(
                cursor,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return if cursor + len >= BLOCK_STORAGE_SIZE { 0 } else { cursor };
                }
                Err(_) => {} // retry
            }
        }
    }
}

impl VirtioModel for VirtioBlockModel {
    fn process_desc(&self, dma: &DmaEngine, gpa: u64, len: u32, flags: u32) -> bool {
        let length = len as usize;
        if length < 16 {
            return false; // Must have at least VirtBlkRequest header
        }
        
        // Parse VirtBlkRequest header (16 bytes)
        let mut hdr_bytes = [0u8; 16];
        if !dma.read_bytes(gpa, &mut hdr_bytes) {
            return false;
        }
        
        let req = VirtBlkRequest {
            req_type: u32::from_le_bytes([hdr_bytes[0], hdr_bytes[1], hdr_bytes[2], hdr_bytes[3]]),
            reserved: u32::from_le_bytes([hdr_bytes[4], hdr_bytes[5], hdr_bytes[6], hdr_bytes[7]]),
            sector: u64::from_le_bytes([
                hdr_bytes[8], hdr_bytes[9], hdr_bytes[10], hdr_bytes[11],
                hdr_bytes[12], hdr_bytes[13], hdr_bytes[14], hdr_bytes[15]
            ]),
        };
        
        // Data region: after header, before status byte (last byte)
        let data_offset = 16;
        let data_len = if length > 17 {
            length - 17  // 16-byte header + 1-byte status
        } else {
            0
        };
        let status_gpa = gpa + (length - 1) as u64;
        
        // Build command for echOS io_uring/NVMe
        let cmd = BlockIoCmd {
            req_type: req.req_type,
            sector: req.sector,
            data_gpa: gpa + data_offset as u64,
            data_len: data_len as u32,
            status_gpa,
        };
        
        // Push to command ring for echOS to execute
        if !block_io_ring().push(cmd) {
            // Ring full - write error status
            let _ = dma.write_u8(status_gpa, VIRTIO_BLK_S_IOERR);
            return false;
        }
        
        // Update stats based on request type
        match req.req_type {
            VIRTIO_BLK_T_IN => {
                self.reads.fetch_add(1, Ordering::Relaxed);
                self.last_len.store(data_len as u32, Ordering::Relaxed);
            }
            VIRTIO_BLK_T_OUT => {
                self.writes.fetch_add(1, Ordering::Relaxed);
                self.last_len.store(data_len as u32, Ordering::Relaxed);
            }
            VIRTIO_BLK_T_FLUSH | VIRTIO_BLK_T_DISCARD => {
                // Special commands - no data transfer
                self.last_len.store(0, Ordering::Relaxed);
            }
            _ => {
                // Unsupported operation - write error status
                let _ = dma.write_u8(status_gpa, VIRTIO_BLK_S_UNSUPP);
                return false;
            }
        }
        
        // Note: Status byte (VIRTIO_BLK_S_OK) will be written by echOS driver
        // after I/O completion. VirtIO just queues the command here.
        true
    }

    fn stats(&self) -> (u64, u64, u32) {
        (
            self.reads.load(Ordering::Acquire),
            self.writes.load(Ordering::Acquire),
            self.last_len.load(Ordering::Acquire),
        )
    }

    fn restore_stats(&self, stats: (u64, u64, u32)) {
        self.reads.store(stats.0, Ordering::Release);
        self.writes.store(stats.1, Ordering::Release);
        self.last_len.store(stats.2, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// VirtIO Network TX Command Queue
// ---------------------------------------------------------------------------

// Phase 2: VirtNet header flags
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1; // Partial checksum required
const VIRTIO_NET_HDR_F_DATA_VALID: u8 = 2;  // Checksum already valid

// Phase 2: GSO (Generic Segmentation Offload) types
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;   // No GSO
const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;  // TCP Segmentation Offload IPv4
const VIRTIO_NET_HDR_GSO_UDP: u8 = 3;    // UDP fragmentation offload
const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;  // TSO IPv6

/// VirtIO network header (12 bytes) - precedes frame data in TX descriptors
/// Phase 2: Extended documentation for GSO/TSO and checksum offload
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VirtNetHdr {
    /// Phase 2: Checksum offload flags
    /// Bit 0 (NEEDS_CSUM): Host must compute partial checksum
    /// Bit 1 (DATA_VALID): Checksum is already valid, no computation needed
    pub flags: u8,
    
    /// Phase 2: GSO type (for large packet segmentation)
    /// 0=NONE, 1=TCPv4, 3=UDP, 4=TCPv6
    pub gso_type: u8,
    
    /// Phase 2: Header length (bytes from start to TCP/UDP payload)
    /// Used for TSO to know where to split segments
    pub hdr_len: u16,
    
    /// Phase 2: GSO segment size (MSS for TSO)
    /// Maximum segment size for large send offload
    pub gso_size: u16,
    
    /// Phase 2: Checksum start offset (where to begin checksum calculation)
    pub csum_start: u16,
    
    /// Phase 2: Checksum insert offset (where to write computed checksum)
    pub csum_offset: u16,
    
    /// Number of buffers (used for RX only, must be 0 for TX)
    pub num_buffers: u16,
}

impl VirtNetHdr {
    pub const ZERO: Self = Self {
        flags: 0,
        gso_type: 0,
        hdr_len: 0,
        gso_size: 0,
        csum_start: 0,
        csum_offset: 0,
        num_buffers: 0,
    };
}

// Parsed Ethernet frame with VirtIO header + data
#[derive(Clone, Copy)]
pub struct EthernetFrame {
    pub hdr: VirtNetHdr,
    pub data: [u8; 1514],  // Max standard Ethernet frame (no jumbo)
    pub len: u16,          // Actual frame data length (excludes 12-byte VirtNetHdr)
}

impl EthernetFrame {
    pub const ZERO: Self = Self {
        hdr: VirtNetHdr::ZERO,
        data: [0u8; 1514],
        len: 0,
    };
}

const TX_RING_SIZE: usize = 64;

// NetTxCmdRing — lock-free 64-slot transmit command queue.
// VirtioNetModel pushes parsed frames here (guest TX descriptors).
// echOS kernel-bypass NIC calls `net_tx_ring().pop()` to drain and transmit.
#[repr(C)]
pub struct NetTxCmdRing {
    slots: UnsafeCell<[EthernetFrame; TX_RING_SIZE]>,
    head: AtomicUsize,   // VirtIO producer advances this
    _pad_head: [u8; 56], // cache line isolation
    tail: AtomicUsize,   // echOS consumer advances this
    _pad_tail: [u8; 56],
}

unsafe impl Sync for NetTxCmdRing {}

impl NetTxCmdRing {
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([EthernetFrame::ZERO; TX_RING_SIZE]),
            head: AtomicUsize::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad_tail: [0u8; 56],
        }
    }

    /// Push a parsed frame from guest TX descriptor. Returns false if ring full.
    pub fn push(&self, frame: EthernetFrame) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= TX_RING_SIZE {
            return false; // ring full
        }
        let slot = head & (TX_RING_SIZE - 1);
        unsafe {
            (*self.slots.get())[slot] = frame;
        }
        self.head.fetch_add(1, Ordering::Release);
        true
    }

    /// Pop a frame for echOS NIC to transmit. Returns None if ring empty.
    pub fn pop(&self) -> Option<EthernetFrame> {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            return None; // ring empty
        }
        let slot = tail & (TX_RING_SIZE - 1);
        let frame = unsafe { (*self.slots.get())[slot] };
        self.tail.fetch_add(1, Ordering::Release);
        Some(frame)
    }

    /// Number of frames pending transmission.
    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(TX_RING_SIZE)
    }

    /// Clear all pending frames (for reset/snapshot restore).
    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        self.head.store(tail, Ordering::Release);
    }
}

static NET_TX_RING: NetTxCmdRing = NetTxCmdRing::new();

pub fn net_tx_ring() -> &'static NetTxCmdRing {
    &NET_TX_RING
}

// ---------------------------------------------------------------------------
// VirtIO Network RX Ring
// ---------------------------------------------------------------------------

// RxRingBuffer — lock-free 64-slot receive ring for host-injected packets.
// echOS calls `net_rx_ring().push(data)` via `valkyrie_net_inject()`.
// VirtioNetModel reads from it in process_desc (RX direction).

const RX_RING_SIZE: usize = 64;
const RX_SLOT_SIZE: usize = 1514;

// Each AtomicUsize (8 bytes) is padded to a full 64-byte cache line to prevent
// false sharing between the producer writing `head` and the consumer writing `tail`.
#[repr(C)]
pub struct RxRingBuffer {
    slots: UnsafeCell<[[u8; RX_SLOT_SIZE]; RX_RING_SIZE]>,
    lens: [AtomicU16; RX_RING_SIZE],
    head: AtomicUsize,   // producer (host/inject) advances this
    _pad_head: [u8; 56], // pad head to its own 64-byte cache line
    tail: AtomicUsize,   // consumer (VirtIO RX) advances this
    _pad_tail: [u8; 56], // pad tail to its own 64-byte cache line
}

unsafe impl Sync for RxRingBuffer {}

impl RxRingBuffer {
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([[0u8; RX_SLOT_SIZE]; RX_RING_SIZE]),
            lens: [const { AtomicU16::new(0) }; RX_RING_SIZE],
            head: AtomicUsize::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad_tail: [0u8; 56],
        }
    }

    /// Push a packet from the host side. Returns false if the ring is full.
    pub fn push(&self, data: &[u8]) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= RX_RING_SIZE {
            return false; // ring full
        }
        let slot = head & (RX_RING_SIZE - 1);
        let len = data.len().min(RX_SLOT_SIZE);
        unsafe {
            let buf = &mut (*self.slots.get())[slot];
            buf[..len].copy_from_slice(&data[..len]);
        }
        self.lens[slot].store(len as u16, Ordering::Release);
        self.head.fetch_add(1, Ordering::Release);
        true
    }

    /// Pop a packet into `dst`. Returns the number of bytes written, or None if empty.
    pub fn pop(&self, dst: &mut [u8]) -> Option<usize> {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            return None; // ring empty
        }
        let slot = tail & (RX_RING_SIZE - 1);
        let len = self.lens[slot].load(Ordering::Acquire) as usize;
        let copy = len.min(dst.len());
        unsafe {
            dst[..copy].copy_from_slice(&(&(*self.slots.get())[slot])[..copy]);
        }
        self.tail.fetch_add(1, Ordering::Release);
        Some(copy)
    }

    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(RX_RING_SIZE)
    }

    /// Clear all pending packets (for reset/snapshot restore).
    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        self.head.store(tail, Ordering::Release);
    }
}

static NET_RX_RING: RxRingBuffer = RxRingBuffer::new();

pub fn net_rx_ring() -> &'static RxRingBuffer {
    &NET_RX_RING
}

// ---------------------------------------------------------------------------
// Async Completion Tracking Ring
// ---------------------------------------------------------------------------

const ASYNC_COMPLETION_RING_SIZE: usize = 256;

/// Async I/O completion entry
#[derive(Clone, Copy, Debug)]
pub struct AsyncCompletion {
    pub id: u64,           // Request ID
    pub status: u8,        // Completion status (0=OK, 1=ERROR)
    pub result_len: u32,   // Bytes transferred
    pub timestamp: u64,    // Completion timestamp (for ordering)
}

impl AsyncCompletion {
    pub const ZERO: Self = Self {
        id: 0,
        status: 0,
        result_len: 0,
        timestamp: 0,
    };
}

/// Lock-free async completion ring - tracks completed I/O operations
pub struct AsyncCompletionRing {
    slots: UnsafeCell<[AsyncCompletion; ASYNC_COMPLETION_RING_SIZE]>,
    head: AtomicUsize,
    _pad_head: [u8; 56],
    tail: AtomicUsize,
    _pad_tail: [u8; 56],
    next_id: AtomicU64, // Auto-incrementing request ID
}

unsafe impl Sync for AsyncCompletionRing {}

impl AsyncCompletionRing {
    pub const fn new() -> Self {
        Self {
            slots: UnsafeCell::new([AsyncCompletion::ZERO; ASYNC_COMPLETION_RING_SIZE]),
            head: AtomicUsize::new(0),
            _pad_head: [0u8; 56],
            tail: AtomicUsize::new(0),
            _pad_tail: [0u8; 56],
            next_id: AtomicU64::new(1),
        }
    }

    /// Allocate a new request ID
    pub fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Push a completion (from device/backend)
    pub fn push(&self, completion: AsyncCompletion) -> bool {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) >= ASYNC_COMPLETION_RING_SIZE {
            return false; // ring full
        }
        let slot = head & (ASYNC_COMPLETION_RING_SIZE - 1);
        unsafe {
            (*self.slots.get())[slot] = completion;
        }
        self.head.fetch_add(1, Ordering::Release);
        true
    }

    /// Pop a completion (for guest consumption)
    pub fn pop(&self) -> Option<AsyncCompletion> {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail >= head {
            return None;
        }
        let slot = tail & (ASYNC_COMPLETION_RING_SIZE - 1);
        let completion = unsafe { (*self.slots.get())[slot] };
        self.tail.fetch_add(1, Ordering::Release);
        Some(completion)
    }

    pub fn pending(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        head.wrapping_sub(tail).min(ASYNC_COMPLETION_RING_SIZE)
    }

    pub fn clear(&self) {
        let tail = self.tail.load(Ordering::Acquire);
        self.head.store(tail, Ordering::Release);
        self.next_id.store(1, Ordering::Release);
    }
}

static ASYNC_COMPLETION_RING: AsyncCompletionRing = AsyncCompletionRing::new();

pub fn async_completion_ring() -> &'static AsyncCompletionRing {
    &ASYNC_COMPLETION_RING
}

// ---------------------------------------------------------------------------
// Network Link Status and Configuration
// ---------------------------------------------------------------------------

pub struct NetworkLinkStatus {
    link_up: AtomicU8,
    mac_addr: UnsafeCell<[u8; 6]>,
    speed_mbps: AtomicU32,
    config_generation: AtomicU32, // Incremented on config changes
}

unsafe impl Sync for NetworkLinkStatus {}

impl NetworkLinkStatus {
    pub const fn new() -> Self {
        Self {
            link_up: AtomicU8::new(1), // Default: link up
            mac_addr: UnsafeCell::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]), // Default MAC
            speed_mbps: AtomicU32::new(1000), // 1 Gbps
            config_generation: AtomicU32::new(0),
        }
    }

    pub fn set_link_up(&self, up: bool) {
        self.link_up.store(if up { 1 } else { 0 }, Ordering::Release);
        self.config_generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_link_up(&self) -> bool {
        self.link_up.load(Ordering::Acquire) != 0
    }

    pub fn set_mac(&self, mac: &[u8; 6]) {
        unsafe {
            (*self.mac_addr.get()).copy_from_slice(mac);
        }
        self.config_generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_mac(&self) -> [u8; 6] {
        unsafe { *self.mac_addr.get() }
    }

    pub fn config_generation(&self) -> u32 {
        self.config_generation.load(Ordering::Acquire)
    }
}

static NETWORK_LINK_STATUS: NetworkLinkStatus = NetworkLinkStatus::new();

pub fn network_link_status() -> &'static NetworkLinkStatus {
    &NETWORK_LINK_STATUS
}

// ---------------------------------------------------------------------------
// Multi-Port Console Support
// ---------------------------------------------------------------------------

const CONSOLE_MAX_PORTS: usize = 16;
const CONSOLE_PORT_OUTPUT_SIZE: usize = 4096;
const CONSOLE_PORT_INPUT_SIZE: usize = 256;

/// Single console port (one of up to 16 ports)
pub struct ConsolePort {
    output: UnsafeCell<[u8; CONSOLE_PORT_OUTPUT_SIZE]>,
    output_head: AtomicUsize,
    input: UnsafeCell<[u8; CONSOLE_PORT_INPUT_SIZE]>,
    input_write_head: AtomicUsize,
    input_read_head: AtomicUsize,
    enabled: AtomicU8,
}

unsafe impl Sync for ConsolePort {}

impl ConsolePort {
    pub const fn new() -> Self {
        Self {
            output: UnsafeCell::new([0u8; CONSOLE_PORT_OUTPUT_SIZE]),
            output_head: AtomicUsize::new(0),
            input: UnsafeCell::new([0u8; CONSOLE_PORT_INPUT_SIZE]),
            input_write_head: AtomicUsize::new(0),
            input_read_head: AtomicUsize::new(0),
            enabled: AtomicU8::new(0),
        }
    }

    pub fn push_output(&self, data: &[u8]) -> bool {
        let head = self.output_head.load(Ordering::Acquire);
        let space = CONSOLE_PORT_OUTPUT_SIZE - head;
        if data.len() > space {
            return false;
        }
        unsafe {
            let buf = &mut *self.output.get();
            buf[head..head + data.len()].copy_from_slice(data);
        }
        self.output_head.fetch_add(data.len(), Ordering::Release);
        true
    }

    pub fn drain_output(&self, out: &mut [u8]) -> usize {
        let head = self.output_head.load(Ordering::Acquire);
        let copy_len = head.min(out.len());
        if copy_len == 0 {
            return 0;
        }
        unsafe {
            let buf = &*self.output.get();
            out[..copy_len].copy_from_slice(&buf[..copy_len]);
            let buf_mut = &mut *self.output.get();
            buf_mut.copy_within(copy_len..head, 0);
        }
        self.output_head.fetch_sub(copy_len, Ordering::Release);
        copy_len
    }

    pub fn push_input(&self, byte: u8) -> bool {
        let write_head = self.input_write_head.load(Ordering::Acquire);
        let read_head = self.input_read_head.load(Ordering::Acquire);
        let next = (write_head + 1) & (CONSOLE_PORT_INPUT_SIZE - 1);
        if next == read_head {
            return false; // full
        }
        unsafe {
            (*self.input.get())[write_head] = byte;
        }
        self.input_write_head.store(next, Ordering::Release);
        true
    }

    pub fn pop_input(&self) -> Option<u8> {
        let read_head = self.input_read_head.load(Ordering::Acquire);
        let write_head = self.input_write_head.load(Ordering::Acquire);
        if read_head == write_head {
            return None;
        }
        let byte = unsafe { (*self.input.get())[read_head] };
        let next = (read_head + 1) & (CONSOLE_PORT_INPUT_SIZE - 1);
        self.input_read_head.store(next, Ordering::Release);
        Some(byte)
    }

    pub fn clear(&self) {
        self.output_head.store(0, Ordering::Release);
        self.input_write_head.store(0, Ordering::Release);
        self.input_read_head.store(0, Ordering::Release);
    }
}

/// Multi-port console manager
pub struct MultiPortConsole {
    ports: [ConsolePort; CONSOLE_MAX_PORTS],
}

unsafe impl Sync for MultiPortConsole {}

impl MultiPortConsole {
    pub const fn new() -> Self {
        const PORT: ConsolePort = ConsolePort::new();
        Self {
            ports: [PORT; CONSOLE_MAX_PORTS],
        }
    }

    pub fn port(&self, index: usize) -> Option<&ConsolePort> {
        if index < CONSOLE_MAX_PORTS {
            Some(&self.ports[index])
        } else {
            None
        }
    }

    pub fn clear_all(&self) {
        for port in &self.ports {
            port.clear();
        }
    }
}

static MULTI_PORT_CONSOLE: MultiPortConsole = MultiPortConsole::new();

pub fn multi_port_console() -> &'static MultiPortConsole {
    &MULTI_PORT_CONSOLE
}

// ---------------------------------------------------------------------------
// Control Queue Messages
// ---------------------------------------------------------------------------

/// VirtIO control queue message types
const VIRTIO_NET_CTRL_RX: u8 = 0;
const VIRTIO_NET_CTRL_MAC: u8 = 1;
const VIRTIO_NET_CTRL_VLAN: u8 = 2;
const VIRTIO_CONSOLE_CTRL_PORT: u8 = 10;

#[derive(Clone, Copy, Debug)]
pub struct ControlQueueMsg {
    pub class: u8,
    pub command: u8,
    pub data_len: u16,
    pub status: u8, // 0=OK, 1=ERROR
}

impl ControlQueueMsg {
    pub const fn new(class: u8, command: u8) -> Self {
        Self {
            class,
            command,
            data_len: 0,
            status: 0,
        }
    }
}

/// Process network control queue command
pub fn process_net_control_msg(msg: &ControlQueueMsg, _data: &[u8]) -> u8 {
    match msg.class {
        VIRTIO_NET_CTRL_RX => {
            // RX mode control (promiscuous, allmulti, etc.)
            0 // OK
        }
        VIRTIO_NET_CTRL_MAC => {
            // MAC address filtering
            0 // OK
        }
        VIRTIO_NET_CTRL_VLAN => {
            // VLAN filtering
            0 // OK
        }
        _ => 1, // Unsupported
    }
}

// ---------------------------------------------------------------------------

const SNAPSHOT_LOG_SIZE: usize = 1024;

pub struct SnapshotLog {
    head: AtomicUsize,
    tail: AtomicUsize,
    active: AtomicU8,
    entries: [UnsafeCell<u64>; SNAPSHOT_LOG_SIZE],
}

unsafe impl Sync for SnapshotLog {}

impl SnapshotLog {
    pub const fn new() -> Self {
        const EMPTY: UnsafeCell<u64> = UnsafeCell::new(0);
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            active: AtomicU8::new(0),
            entries: [EMPTY; SNAPSHOT_LOG_SIZE],
        }
    }

    pub fn begin(&self) {
        self.active.store(1, Ordering::Release);
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
    }

    pub fn end(&self) {
        self.active.store(0, Ordering::Release);
    }

    pub fn record(&self, gpa: u64) {
        if self.active.load(Ordering::Acquire) == 0 {
            return;
        }
        let head = self.head.load(Ordering::Relaxed);
        let next = (head + 1) % SNAPSHOT_LOG_SIZE;
        if next == self.tail.load(Ordering::Acquire) {
            return;
        }
        unsafe {
            *self.entries[head].get() = gpa;
        }
        self.head.store(next, Ordering::Release);
    }

    pub fn pop(&self) -> Option<u64> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let value = unsafe { *self.entries[tail].get() };
        let next = (tail + 1) % SNAPSHOT_LOG_SIZE;
        self.tail.store(next, Ordering::Release);
        Some(value)
    }

    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            head - tail
        } else {
            SNAPSHOT_LOG_SIZE - (tail - head)
        }
    }
}

static SNAPSHOT_LOG: SnapshotLog = SnapshotLog::new();

pub fn snapshot_log() -> &'static SnapshotLog {
    &SNAPSHOT_LOG
}

const SNAPSHOT_IMAGE_SIZE: usize = 2048;

pub struct SnapshotManager {
    base: AtomicU64,
    size: AtomicU64,
    len: AtomicUsize,
    finalized: AtomicU8,
    restore_pending: AtomicU8,
    pages: [UnsafeCell<u64>; SNAPSHOT_IMAGE_SIZE],
}

unsafe impl Sync for SnapshotManager {}

impl SnapshotManager {
    pub const fn new() -> Self {
        const EMPTY: UnsafeCell<u64> = UnsafeCell::new(0);
        Self {
            base: AtomicU64::new(0),
            size: AtomicU64::new(0),
            len: AtomicUsize::new(0),
            finalized: AtomicU8::new(0),
            restore_pending: AtomicU8::new(0),
            pages: [EMPTY; SNAPSHOT_IMAGE_SIZE],
        }
    }

    pub fn configure(&self, base: u64, size: u64) {
        self.base.store(base, Ordering::Release);
        self.size.store(size, Ordering::Release);
    }

    pub fn finalize_from_log(&self) {
        self.len.store(0, Ordering::Release);
        let mut idx = 0usize;
        while let Some(gpa) = snapshot_log().pop() {
            if idx >= SNAPSHOT_IMAGE_SIZE {
                break;
            }
            unsafe {
                *self.pages[idx].get() = gpa;
            }
            idx += 1;
        }
        self.len.store(idx, Ordering::Release);
        self.finalized.store(1, Ordering::Release);
    }

    pub fn request_restore(&self) -> bool {
        if self.finalized.load(Ordering::Acquire) == 0 {
            return false;
        }
        self.restore_pending.store(1, Ordering::Release);
        true
    }

    pub fn apply_restore(&self, ept: &mut Ept) -> Result<bool, HvError> {
        if self.restore_pending.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }
        let len = self.len.load(Ordering::Acquire);
        for index in 0..len {
            let gpa = unsafe { *self.pages[index].get() };
            ept.map_4k(gpa, gpa)?;
        }
        self.restore_pending.store(0, Ordering::Release);
        Ok(true)
    }

    pub fn stats(&self) -> (u64, u64, usize, u8) {
        (
            self.base.load(Ordering::Acquire),
            self.size.load(Ordering::Acquire),
            self.len.load(Ordering::Acquire),
            self.finalized.load(Ordering::Acquire),
        )
    }
}

static SNAPSHOT_MANAGER: SnapshotManager = SnapshotManager::new();

pub fn snapshot_manager() -> &'static SnapshotManager {
    &SNAPSHOT_MANAGER
}

pub struct SnapshotVirtioState {
    net: VirtioDeviceState,
    blk: VirtioDeviceState,
    console: VirtioDeviceState,
    dma: [u8; DMA_BUFFER_SIZE],
    net_stats: (u64, u64, u32),
    blk_stats: (u64, u64, u32),
    console_stats: (u64, u64, u32),
}

impl SnapshotVirtioState {
    pub const fn new() -> Self {
        Self {
            net: VirtioDeviceState::empty(),
            blk: VirtioDeviceState::empty(),
            console: VirtioDeviceState::empty(),
            dma: [0u8; DMA_BUFFER_SIZE],
            net_stats: (0, 0, 0),
            blk_stats: (0, 0, 0),
            console_stats: (0, 0, 0),
        }
    }
}

pub struct CpuState {
    regs: UnsafeCell<MinimalRegs>,
}

unsafe impl Sync for CpuState {}

impl CpuState {
    pub const fn new() -> Self {
        Self {
            regs: UnsafeCell::new(MinimalRegs {
                rax: 0, rcx: 0, rdx: 0, rbx: 0,
                rsp: 0, rbp: 0, rsi: 0, rdi: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0, rflags: 0,
                cs: 0, ds: 0, es: 0, ss: 0,
            }),
        }
    }

    pub fn set_regs(&self, regs: MinimalRegs) {
        unsafe {
            *self.regs.get() = regs;
        }
    }

    pub fn regs(&self) -> MinimalRegs {
        unsafe { *self.regs.get() }
    }
}

static CPU_STATE: CpuState = CpuState::new();

pub fn cpu_state() -> &'static CpuState {
    &CPU_STATE
}

pub struct SnapshotState {
    valid: AtomicU8,
    regs: UnsafeCell<MinimalRegs>,
    virtio: UnsafeCell<SnapshotVirtioState>,
}

unsafe impl Sync for SnapshotState {}

impl SnapshotState {
    pub const fn new() -> Self {
        Self {
            valid: AtomicU8::new(0),
            regs: UnsafeCell::new(MinimalRegs {
                rax: 0, rcx: 0, rdx: 0, rbx: 0,
                rsp: 0, rbp: 0, rsi: 0, rdi: 0,
                r8: 0, r9: 0, r10: 0, r11: 0,
                r12: 0, r13: 0, r14: 0, r15: 0,
                rip: 0, rflags: 0,
                cs: 0, ds: 0, es: 0, ss: 0,
            }),
            virtio: UnsafeCell::new(SnapshotVirtioState::new()),
        }
    }

    pub fn save(&self) {
        let regs = cpu_state().regs();
        unsafe {
            *self.regs.get() = regs;
        }
        unsafe {
            let virtio_state = &mut *self.virtio.get();
            virtio_direct().snapshot(virtio_state);
        }
        self.valid.store(1, Ordering::Release);
    }

    pub fn restore(&self) -> bool {
        if self.valid.load(Ordering::Acquire) == 0 {
            return false;
        }
        let regs = unsafe { *self.regs.get() };
        cpu_state().set_regs(regs);
        unsafe {
            let virtio_state = &*self.virtio.get();
            virtio_direct().restore(virtio_state);
        }
        true
    }
}

static SNAPSHOT_STATE: SnapshotState = SnapshotState::new();

pub fn snapshot_state() -> &'static SnapshotState {
    &SNAPSHOT_STATE
}

static STRESS: StressInjector = StressInjector::new();

pub fn stress_injector() -> &'static StressInjector {
    &STRESS
}

pub struct StressInjector {
    seed: AtomicU64,
    enabled: AtomicU8,
    cadence: AtomicU32,
}

impl StressInjector {
    pub const fn new() -> Self {
        Self {
            seed: AtomicU64::new(0x9E37_79B9_7F4A_7C15),
            enabled: AtomicU8::new(0),
            cadence: AtomicU32::new(128),
        }
    }

    pub fn enable(&self) {
        self.enabled.store(1, Ordering::Release);
    }

    pub fn disable(&self) {
        self.enabled.store(0, Ordering::Release);
    }

    pub fn set_cadence(&self, value: u32) {
        self.cadence.store(value.max(1), Ordering::Release);
    }

    pub fn tick(&self, now: u64) -> StressEvent {
        if self.enabled.load(Ordering::Acquire) == 0 {
            return StressEvent::None;
        }
        let mut seed = self.seed.load(Ordering::Relaxed);
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(now | 1);
        self.seed.store(seed, Ordering::Release);
        let cadence = self.cadence.load(Ordering::Acquire).max(1) as u64;
        if seed % cadence != 0 {
            return StressEvent::None;
        }
        if seed & 1 == 0 {
            StressEvent::EptFault
        } else {
            StressEvent::IrqStorm
        }
    }

    pub fn run_soak(&self, iterations: u64, cadence: u32) -> u64 {
        let mut count = 0u64;
        self.set_cadence(cadence);
        self.enable();
        for step in 0..iterations {
            match self.tick(step) {
                StressEvent::None => {}
                StressEvent::EptFault => {
                    record_telemetry(TELEMETRY_STRESS_EPT, 0);
                    count += 1;
                }
                StressEvent::IrqStorm => {
                    record_telemetry(TELEMETRY_STRESS_IRQ, 0);
                    count += 1;
                }
            }
        }
        self.disable();
        count
    }
}

pub enum StressEvent {
    None,
    EptFault,
    IrqStorm,
}

pub struct TelemetryRing {
    head: AtomicUsize,
    tail: AtomicUsize,
    buffer: [UnsafeCell<TelemetryRecord>; TELEMETRY_RING_SIZE],
}

unsafe impl Sync for TelemetryRing {}

impl TelemetryRing {
    pub const fn new() -> Self {
        const EMPTY: UnsafeCell<TelemetryRecord> = UnsafeCell::new(TelemetryRecord::new());
        Self {
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            buffer: [EMPTY; TELEMETRY_RING_SIZE],
        }
    }

    pub fn push(&self, record: TelemetryRecord) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let next = (head + 1) % TELEMETRY_RING_SIZE;
        if next == self.tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            *self.buffer[head].get() = record;
        }
        self.head.store(next, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<TelemetryRecord> {
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == self.head.load(Ordering::Acquire) {
            return None;
        }
        let record = unsafe { *self.buffer[tail].get() };
        let next = (tail + 1) % TELEMETRY_RING_SIZE;
        self.tail.store(next, Ordering::Release);
        Some(record)
    }

    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        if head >= tail {
            head - tail
        } else {
            TELEMETRY_RING_SIZE - (tail - head)
        }
    }

    pub fn clear(&self) {
        let head = self.head.load(Ordering::Acquire);
        self.tail.store(head, Ordering::Release);
    }
}

static TELEMETRY_RING: TelemetryRing = TelemetryRing::new();

pub fn record_telemetry(kind: u32, value: u32) {
    let record = TelemetryRecord {
        timestamp: unsafe { core::arch::x86_64::_rdtsc() },
        kind,
        value,
    };
    let _ = TELEMETRY_RING.push(record);
}

pub fn telemetry_pop() -> Option<TelemetryRecord> {
    TELEMETRY_RING.pop()
}

pub fn telemetry_len() -> usize {
    TELEMETRY_RING.len()
}

pub fn telemetry_clear() {
    TELEMETRY_RING.clear()
}

// ─── GpuCommandQueue (Pillar 3) ───────────────────────────────────────────────
//
// Three-priority lock-free command ring connecting the D3D interceptor to the
// GPU dispatcher / soft-rasterizer.
//
//   HIGH   — 128 slots × 512 B  (fences, presents, state-invalids)
//   NORMAL — 1024 slots × 4096 B (draw calls, compute dispatches)
//   BULK   — 256 slots × 16384 B (resource uploads, DXBC blobs)

use core::cell::UnsafeCell as _UnsafeCell;
use core::sync::atomic::AtomicUsize as _AtomicUsize;
use ugir::UGCommand;

/// Queue priority levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GpuQueuePriority {
    High = 0,
    Normal = 1,
    Bulk = 2,
}

/// A single entry in a priority ring.
#[derive(Clone, Copy)]
pub struct GpuCmdEntry<const CAP: usize> {
    pub cmds: [UGCommand; CAP],
    pub count: u16,
    pub seq: u32,
    pub _pad: [u8; 2],
}

impl<const CAP: usize> GpuCmdEntry<CAP> {
    pub const fn empty() -> Self {
        const NOP: UGCommand = UGCommand {
            kind: ugir::UGCommandKind::Nop,
            _pad: [0; 3],
            p: ugir::UGPayload::zeroed(),
            x: 0,
            y: 0,
            z: 0,
            src_addr: 0,
            dst_addr: 0,
            size: 0,
            clear_value: 0.0,
            width: 0,
            height: 0,
            handle: ugir::UGHandle::NULL,
            pipeline_id: 0,
            descriptor_id: 0,
            descriptor_set: 0,
            binding: 0,
            buffer_addr: 0,
            stride: 0,
            index_type: 0,
            buffer_id: 0,
            offset: 0,
        };
        Self {
            cmds: [NOP; CAP],
            count: 0,
            seq: 0,
            _pad: [0; 2],
        }
    }
}

/// Typed priority ring.
pub struct GpuPriorityRing<const SLOTS: usize, const CAP: usize> {
    head: _AtomicUsize,
    tail: _AtomicUsize,
    buf: [_UnsafeCell<GpuCmdEntry<CAP>>; SLOTS],
}

unsafe impl<const SLOTS: usize, const CAP: usize> Sync for GpuPriorityRing<SLOTS, CAP> {}

impl<const SLOTS: usize, const CAP: usize> GpuPriorityRing<SLOTS, CAP> {
    pub const fn new() -> Self {
        Self {
            head: _AtomicUsize::new(0),
            tail: _AtomicUsize::new(0),
            buf: [const { _UnsafeCell::new(GpuCmdEntry::empty()) }; SLOTS],
        }
    }

    pub fn push(&self, entry: GpuCmdEntry<CAP>) -> bool {
        let h = self.head.load(Ordering::Relaxed);
        let next = (h + 1) % SLOTS;
        if next == self.tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            *self.buf[h % SLOTS].get() = entry;
        }
        self.head.store(next, Ordering::Release);
        true
    }

    pub fn pop(&self) -> Option<GpuCmdEntry<CAP>> {
        let t = self.tail.load(Ordering::Relaxed);
        if t == self.head.load(Ordering::Acquire) {
            return None;
        }
        let entry = unsafe { *self.buf[t % SLOTS].get() };
        self.tail.store((t + 1) % SLOTS, Ordering::Release);
        Some(entry)
    }

    pub fn len(&self) -> usize {
        let h = self.head.load(Ordering::Acquire);
        let t = self.tail.load(Ordering::Acquire);
        if h >= t {
            h - t
        } else {
            SLOTS - (t - h)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Per-priority capacities (commands per slot).
const GPU_HIGH_SLOTS: usize = 128;
const GPU_NORMAL_SLOTS: usize = 1024;
const GPU_BULK_SLOTS: usize = 256;

const GPU_HIGH_CAP: usize = 8; // ~512 B each (UGCommand = 64B)
const GPU_NORMAL_CAP: usize = 64; // ~4096 B each
const GPU_BULK_CAP: usize = 256; // ~16384 B each

/// Three-priority GPU command queue.
pub struct GpuCommandQueue {
    pub high: GpuPriorityRing<GPU_HIGH_SLOTS, GPU_HIGH_CAP>,
    pub normal: GpuPriorityRing<GPU_NORMAL_SLOTS, GPU_NORMAL_CAP>,
    pub bulk: GpuPriorityRing<GPU_BULK_SLOTS, GPU_BULK_CAP>,
    submitted: AtomicU32,
    drained: AtomicU32,
}

unsafe impl Sync for GpuCommandQueue {}

impl GpuCommandQueue {
    pub const fn new() -> Self {
        Self {
            high: GpuPriorityRing::new(),
            normal: GpuPriorityRing::new(),
            bulk: GpuPriorityRing::new(),
            submitted: AtomicU32::new(0),
            drained: AtomicU32::new(0),
        }
    }

    /// Submit a batch of commands to the appropriate priority ring.
    /// Returns `false` if the ring is full.
    pub fn submit(&self, priority: GpuQueuePriority, cmds: &[UGCommand]) -> bool {
        match priority {
            GpuQueuePriority::High => {
                let n = cmds.len().min(GPU_HIGH_CAP);
                let mut entry = GpuCmdEntry::<GPU_HIGH_CAP>::empty();
                entry.cmds[..n].copy_from_slice(&cmds[..n]);
                entry.count = n as u16;
                entry.seq = self.submitted.fetch_add(1, Ordering::Relaxed);
                self.high.push(entry)
            }
            GpuQueuePriority::Normal => {
                let n = cmds.len().min(GPU_NORMAL_CAP);
                let mut entry = GpuCmdEntry::<GPU_NORMAL_CAP>::empty();
                entry.cmds[..n].copy_from_slice(&cmds[..n]);
                entry.count = n as u16;
                entry.seq = self.submitted.fetch_add(1, Ordering::Relaxed);
                self.normal.push(entry)
            }
            GpuQueuePriority::Bulk => {
                let n = cmds.len().min(GPU_BULK_CAP);
                let mut entry = GpuCmdEntry::<GPU_BULK_CAP>::empty();
                entry.cmds[..n].copy_from_slice(&cmds[..n]);
                entry.count = n as u16;
                entry.seq = self.submitted.fetch_add(1, Ordering::Relaxed);
                self.bulk.push(entry)
            }
        }
    }

    /// Total commands ever submitted.
    pub fn submitted(&self) -> u32 {
        self.submitted.load(Ordering::Acquire)
    }

    /// Total entries ever drained.
    pub fn drained(&self) -> u32 {
        self.drained.load(Ordering::Acquire)
    }

    /// Total pending entries across all priorities.
    pub fn pending(&self) -> usize {
        self.high.len() + self.normal.len() + self.bulk.len()
    }
}

/// Global GPU command queue.
pub static GPU_QUEUE: GpuCommandQueue = GpuCommandQueue::new();

pub struct ControlPlane;

impl ControlPlane {
    pub const fn new() -> Self {
        Self
    }

    pub fn handle_request(&self, input: &str, output: &mut [u8]) -> Result<usize, HvError> {
        let method = extract_string_field(input, "\"method\"").ok_or(HvError::LogicalFault)?;
        let id = extract_number_field(input, "\"id\"").ok_or(HvError::LogicalFault)?;
        match method {
            "ping" => write_result_string(id, "pong", output),
            "vm.start" => {
                // Create a VM with a default config and launch it through the
                // global Hypervisor singleton (wired to VmxOps / vmx_loop).
                let hv = global_hypervisor();
                let config = crate::vmm::hypervisor::VmConfig::new();
                let ok = if let Ok(vm_id) = hv.create_vm(config) {
                    hv.get_vm_mut(vm_id).map_or(false, |vm| vm.start().is_ok())
                } else {
                    false
                };
                write_result_bool(id, ok, output)
            }
            "vm.stop" => write_result_bool(id, true, output),
            "caps.get" => write_result_caps(id, output),
            "virtio.direct.enable" => {
                virtio_direct().enable_default();
                write_result_bool(id, true, output)
            }
            "virtio.direct.status" => write_result_virtio_status(id, output),
            "virtio.mmio.read" => {
                let addr = extract_number_field(input, "\"addr\"").ok_or(HvError::LogicalFault)?;
                let value = virtio_direct().mmio_read(addr).unwrap_or(0);
                write_result_u64(id, value as u64, output)
            }
            "virtio.mmio.write" => {
                let addr = extract_number_field(input, "\"addr\"").ok_or(HvError::LogicalFault)?;
                let value =
                    extract_number_field(input, "\"value\"").ok_or(HvError::LogicalFault)?;
                let ok = virtio_direct().mmio_write(addr, value as u32);
                write_result_bool(id, ok, output)
            }
            "virtio.dma.map" => {
                let gpa = extract_number_field(input, "\"gpa\"").ok_or(HvError::LogicalFault)?;
                let size = extract_number_field(input, "\"size\"").ok_or(HvError::LogicalFault)?;
                let offset = virtio_direct().dma_map(gpa, size).unwrap_or(0);
                write_result_u64(id, offset, output)
            }
            "virtio.dma.read32" => {
                let gpa = extract_number_field(input, "\"gpa\"").ok_or(HvError::LogicalFault)?;
                let value = virtio_direct().dma_read_u32(gpa).unwrap_or(0);
                write_result_u64(id, value as u64, output)
            }
            "virtio.dma.read64" => {
                let gpa = extract_number_field(input, "\"gpa\"").ok_or(HvError::LogicalFault)?;
                let value = virtio_direct().dma_read_u64(gpa).unwrap_or(0);
                write_result_u64(id, value, output)
            }
            "virtio.dma.write32" => {
                let gpa = extract_number_field(input, "\"gpa\"").ok_or(HvError::LogicalFault)?;
                let value =
                    extract_number_field(input, "\"value\"").ok_or(HvError::LogicalFault)?;
                let ok = virtio_direct().dma_write_u32(gpa, value as u32);
                write_result_bool(id, ok, output)
            }
            "virtio.dma.write64" => {
                let gpa = extract_number_field(input, "\"gpa\"").ok_or(HvError::LogicalFault)?;
                let value =
                    extract_number_field(input, "\"value\"").ok_or(HvError::LogicalFault)?;
                let ok = virtio_direct().dma_write_u64(gpa, value);
                write_result_bool(id, ok, output)
            }
            "virtio.process" => {
                let count = virtio_direct().process_queues();
                write_result_u64(id, count as u64, output)
            }
            "virtio.stats" => write_result_virtio_stats(id, output),
            "snapshot.begin" => {
                snapshot_log().begin();
                write_result_bool(id, true, output)
            }
            "snapshot.end" => {
                snapshot_log().end();
                write_result_bool(id, true, output)
            }
            "snapshot.finalize" => {
                snapshot_manager().finalize_from_log();
                write_result_bool(id, true, output)
            }
            "snapshot.save" => {
                snapshot_state().save();
                write_result_bool(id, true, output)
            }
            "snapshot.load" => {
                let ok = snapshot_state().restore();
                write_result_bool(id, ok, output)
            }
            "snapshot.restore" => {
                let ok = snapshot_manager().request_restore();
                write_result_bool(id, ok, output)
            }
            "snapshot.stats" => write_result_snapshot_stats(id, output),
            "snapshot.pop" => write_result_snapshot(id, output),
            "telemetry.stats" => write_result_stats(id, output),
            "telemetry.pop" => write_result_telemetry(id, output),
            "telemetry.export" => {
                let max = extract_number_field(input, "\"max\"").unwrap_or(16);
                write_result_telemetry_batch(id, max as usize, output)
            }
            "cpu.regs.set" => {
                let rax = extract_number_field(input, "\"rax\"").ok_or(HvError::LogicalFault)?;
                let rcx = extract_number_field(input, "\"rcx\"").ok_or(HvError::LogicalFault)?;
                let rdx = extract_number_field(input, "\"rdx\"").ok_or(HvError::LogicalFault)?;
                let rsp = extract_number_field(input, "\"rsp\"").ok_or(HvError::LogicalFault)?;
                let rip = extract_number_field(input, "\"rip\"").ok_or(HvError::LogicalFault)?;
                cpu_state().set_regs(MinimalRegs {
                    rax, rcx, rdx,
                    rbx: 0, rsp, rbp: 0, rsi: 0, rdi: 0,
                    r8: 0, r9: 0, r10: 0, r11: 0,
                    r12: 0, r13: 0, r14: 0, r15: 0,
                    rip, rflags: 0,
                    cs: 0, ds: 0, es: 0, ss: 0,
                });
                write_result_bool(id, true, output)
            }
            "cpu.regs.get" => write_result_cpu_regs(id, cpu_state().regs(), output),
            "stress.enable" => {
                STRESS.enable();
                write_result_bool(id, true, output)
            }
            "stress.disable" => {
                STRESS.disable();
                write_result_bool(id, true, output)
            }
            "stress.soak" => {
                let iterations = extract_number_field(input, "\"iterations\"").unwrap_or(0);
                let cadence = extract_number_field(input, "\"cadence\"").unwrap_or(128);
                let count = STRESS.run_soak(iterations, cadence as u32);
                write_result_u64(id, count, output)
            }
            "hardware.info" => write_result_hardware_info(id, output),
            "hardware.signature" => write_result_u64(id, hardware_signature(), output),
            "regression.check" => {
                let expected =
                    extract_number_field(input, "\"expected\"").ok_or(HvError::LogicalFault)?;
                let ok = hardware_signature() == expected;
                write_result_bool(id, ok, output)
            }
            _ => Err(HvError::LogicalFault),
        }
    }
}

fn extract_string_field<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    let start = input.find(key)?;
    let mut index = start + key.len();
    let bytes = input.as_bytes();
    while index < bytes.len() && bytes[index] != b':' {
        index += 1;
    }
    if index >= bytes.len() {
        return None;
    }
    index += 1;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\n' | b'\t' | b'\r') {
        index += 1;
    }
    if index >= bytes.len() || bytes[index] != b'"' {
        return None;
    }
    index += 1;
    let begin = index;
    while index < bytes.len() && bytes[index] != b'"' {
        index += 1;
    }
    if index >= bytes.len() {
        return None;
    }
    Some(&input[begin..index])
}

fn extract_number_field(input: &str, key: &str) -> Option<u64> {
    let start = input.find(key)?;
    let mut index = start + key.len();
    let bytes = input.as_bytes();
    while index < bytes.len() && bytes[index] != b':' {
        index += 1;
    }
    if index >= bytes.len() {
        return None;
    }
    index += 1;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\n' | b'\t' | b'\r') {
        index += 1;
    }
    if index >= bytes.len() || !bytes[index].is_ascii_digit() {
        return None;
    }
    let mut value: u64 = 0;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add((bytes[index] - b'0') as u64);
        index += 1;
    }
    Some(value)
}

fn write_result_string(id: u64, value: &str, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":\"")?;
    writer.push_str(value)?;
    writer.push_str("\"}")?;
    Ok(writer.pos)
}

fn write_result_bool(id: u64, value: bool, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":")?;
    writer.push_str(if value { "true" } else { "false" })?;
    writer.push_str("}")?;
    Ok(writer.pos)
}

fn write_result_u64(id: u64, value: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":")?;
    writer.push_u64(value)?;
    writer.push_str("}")?;
    Ok(writer.pos)
}

fn write_result_stats(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"queued\":")?;
    writer.push_u64(telemetry_len() as u64)?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_result_telemetry(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":")?;
    match telemetry_pop() {
        Some(record) => {
            writer.push_str("{\"timestamp\":")?;
            writer.push_u64(record.timestamp)?;
            writer.push_str(",\"kind\":")?;
            writer.push_u64(record.kind as u64)?;
            writer.push_str(",\"value\":")?;
            writer.push_u64(record.value as u64)?;
            writer.push_str("}")?;
        }
        None => {
            writer.push_str("null")?;
        }
    }
    writer.push_str("}")?;
    Ok(writer.pos)
}

fn write_result_telemetry_batch(id: u64, max: usize, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    let limit = max.min(32);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":[")?;
    let mut count = 0usize;
    while count < limit {
        let record = match telemetry_pop() {
            Some(record) => record,
            None => break,
        };
        if count > 0 {
            writer.push_str(",")?;
        }
        writer.push_str("{\"timestamp\":")?;
        writer.push_u64(record.timestamp)?;
        writer.push_str(",\"kind\":")?;
        writer.push_u64(record.kind as u64)?;
        writer.push_str(",\"value\":")?;
        writer.push_u64(record.value as u64)?;
        writer.push_str("}")?;
        count += 1;
    }
    writer.push_str("]}")?;
    Ok(writer.pos)
}

fn write_result_cpu_regs(id: u64, regs: MinimalRegs, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"rax\":")?;
    writer.push_u64(regs.rax)?;
    writer.push_str(",\"rcx\":")?;
    writer.push_u64(regs.rcx)?;
    writer.push_str(",\"rdx\":")?;
    writer.push_u64(regs.rdx)?;
    writer.push_str(",\"rsp\":")?;
    writer.push_u64(regs.rsp)?;
    writer.push_str(",\"rip\":")?;
    writer.push_u64(regs.rip)?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_result_virtio_stats(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    let (net_rx, net_tx, net_len) = virtio_direct().net_model.stats();
    let (blk_read, blk_write, blk_len) = virtio_direct().blk_model.stats();
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"net\":{\"rx\":")?;
    writer.push_u64(net_rx)?;
    writer.push_str(",\"tx\":")?;
    writer.push_u64(net_tx)?;
    writer.push_str(",\"last_len\":")?;
    writer.push_u64(net_len as u64)?;
    writer.push_str("},\"blk\":{\"reads\":")?;
    writer.push_u64(blk_read)?;
    writer.push_str(",\"writes\":")?;
    writer.push_u64(blk_write)?;
    writer.push_str(",\"last_len\":")?;
    writer.push_u64(blk_len as u64)?;
    writer.push_str("}}}")?;
    Ok(writer.pos)
}

fn cpu_vendor() -> [u8; 12] {
    let info = unsafe { __cpuid(0) };
    let mut vendor = [0u8; 12];
    vendor[0..4].copy_from_slice(&info.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&info.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&info.ecx.to_le_bytes());
    vendor
}

fn hardware_signature() -> u64 {
    let caps = probe_capabilities();
    let mut value = 0u64;
    value ^= (caps.vmx as u64) << 0;
    value ^= (caps.ept as u64) << 1;
    value ^= (caps.tsc_deadline as u64) << 2;
    value ^= (caps.invariant_tsc as u64) << 3;
    value ^= (caps.x2apic as u64) << 4;
    let vendor = cpu_vendor();
    for (index, byte) in vendor.iter().enumerate() {
        value ^= (*byte as u64) << (index % 8);
        value = value.rotate_left(3);
    }
    value
}

fn write_result_hardware_info(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    let vendor = cpu_vendor();
    let vendor_str = core::str::from_utf8(&vendor).unwrap_or("unknown");
    let caps = probe_capabilities();
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"vendor\":\"")?;
    writer.push_str(vendor_str)?;
    writer.push_str("\",\"signature\":")?;
    writer.push_u64(hardware_signature())?;
    writer.push_str(",\"vmx\":")?;
    writer.push_str(if caps.vmx { "true" } else { "false" })?;
    writer.push_str(",\"ept\":")?;
    writer.push_str(if caps.ept { "true" } else { "false" })?;
    writer.push_str(",\"tsc_deadline\":")?;
    writer.push_str(if caps.tsc_deadline { "true" } else { "false" })?;
    writer.push_str(",\"invariant_tsc\":")?;
    writer.push_str(if caps.invariant_tsc { "true" } else { "false" })?;
    writer.push_str(",\"x2apic\":")?;
    writer.push_str(if caps.x2apic { "true" } else { "false" })?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_telemetry_event(
    seq: u64,
    record: TelemetryRecord,
    output: &mut [u8],
) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(seq)?;
    writer.push_str(",\"method\":\"telemetry.event\",\"params\":{")?;
    writer.push_str("\"timestamp\":")?;
    writer.push_u64(record.timestamp)?;
    writer.push_str(",\"kind\":")?;
    writer.push_u64(record.kind as u64)?;
    writer.push_str(",\"value\":")?;
    writer.push_u64(record.value as u64)?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_result_caps(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let caps = probe_capabilities();
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"vmx\":")?;
    writer.push_str(if caps.vmx { "true" } else { "false" })?;
    writer.push_str(",\"ept\":")?;
    writer.push_str(if caps.ept { "true" } else { "false" })?;
    writer.push_str(",\"tsc_deadline\":")?;
    writer.push_str(if caps.tsc_deadline { "true" } else { "false" })?;
    writer.push_str(",\"invariant_tsc\":")?;
    writer.push_str(if caps.invariant_tsc { "true" } else { "false" })?;
    writer.push_str(",\"x2apic\":")?;
    writer.push_str(if caps.x2apic { "true" } else { "false" })?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_result_virtio_status(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let (net_enabled, blk_enabled, net_base, blk_base) = virtio_direct().status();
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"net_enabled\":")?;
    writer.push_str(if net_enabled != 0 { "true" } else { "false" })?;
    writer.push_str(",\"blk_enabled\":")?;
    writer.push_str(if blk_enabled != 0 { "true" } else { "false" })?;
    writer.push_str(",\"net_base\":")?;
    writer.push_u64(net_base)?;
    writer.push_str(",\"blk_base\":")?;
    writer.push_u64(blk_base)?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_result_snapshot(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":")?;
    match snapshot_log().pop() {
        Some(gpa) => {
            writer.push_str("{\"gpa\":")?;
            writer.push_u64(gpa)?;
            writer.push_str("}")?;
        }
        None => {
            writer.push_str("null")?;
        }
    }
    writer.push_str("}")?;
    Ok(writer.pos)
}

fn write_result_snapshot_stats(id: u64, output: &mut [u8]) -> Result<usize, HvError> {
    let (base, size, len, finalized) = snapshot_manager().stats();
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"result\":{\"base\":")?;
    writer.push_u64(base)?;
    writer.push_str(",\"size\":")?;
    writer.push_u64(size)?;
    writer.push_str(",\"pages\":")?;
    writer.push_u64(len as u64)?;
    writer.push_str(",\"finalized\":")?;
    writer.push_u64(finalized as u64)?;
    writer.push_str("}}")?;
    Ok(writer.pos)
}

fn write_error(id: u64, message: &str, output: &mut [u8]) -> Result<usize, HvError> {
    let mut writer = WriteCursor::new(output);
    writer.push_str("{\"jsonrpc\":\"2.0\",\"id\":")?;
    writer.push_u64(id)?;
    writer.push_str(",\"error\":\"")?;
    writer.push_str(message)?;
    writer.push_str("\"}")?;
    Ok(writer.pos)
}

struct WriteCursor<'a> {
    buffer: &'a mut [u8],
    pos: usize,
}

impl<'a> WriteCursor<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, pos: 0 }
    }

    fn push_str(&mut self, value: &str) -> Result<(), HvError> {
        let bytes = value.as_bytes();
        if self.pos + bytes.len() > self.buffer.len() {
            return Err(HvError::LogicalFault);
        }
        self.buffer[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    fn push_u64(&mut self, mut value: u64) -> Result<(), HvError> {
        let mut buf = [0u8; 20];
        let mut len = 0usize;
        if value == 0 {
            buf[0] = b'0';
            len = 1;
        } else {
            while value > 0 {
                let digit = (value % 10) as u8;
                buf[len] = b'0' + digit;
                len += 1;
                value /= 10;
            }
            buf[..len].reverse();
        }
        if self.pos + len > self.buffer.len() {
            return Err(HvError::LogicalFault);
        }
        self.buffer[self.pos..self.pos + len].copy_from_slice(&buf[..len]);
        self.pos += len;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct ControlFrame {
    len: u16,
    data: [u8; CONTROL_FRAME_SIZE],
}

impl ControlFrame {
    pub const fn new() -> Self {
        Self {
            len: 0,
            data: [0u8; CONTROL_FRAME_SIZE],
        }
    }
}

const CONTROL_FRAME_SIZE: usize = 512;
const CONTROL_QUEUE_SIZE: usize = 64;

pub struct ControlChannel {
    req_head: AtomicUsize,
    req_tail: AtomicUsize,
    resp_head: AtomicUsize,
    resp_tail: AtomicUsize,
    req_buf: [UnsafeCell<ControlFrame>; CONTROL_QUEUE_SIZE],
    resp_buf: [UnsafeCell<ControlFrame>; CONTROL_QUEUE_SIZE],
}

unsafe impl Sync for ControlChannel {}

impl ControlChannel {
    pub const fn new() -> Self {
        const EMPTY: UnsafeCell<ControlFrame> = UnsafeCell::new(ControlFrame::new());
        Self {
            req_head: AtomicUsize::new(0),
            req_tail: AtomicUsize::new(0),
            resp_head: AtomicUsize::new(0),
            resp_tail: AtomicUsize::new(0),
            req_buf: [EMPTY; CONTROL_QUEUE_SIZE],
            resp_buf: [EMPTY; CONTROL_QUEUE_SIZE],
        }
    }

    pub fn enqueue_request(&self, input: &[u8]) -> bool {
        if input.len() > CONTROL_FRAME_SIZE {
            return false;
        }
        let head = self.req_head.load(Ordering::Relaxed);
        let next = (head + 1) % CONTROL_QUEUE_SIZE;
        if next == self.req_tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            let frame = &mut *self.req_buf[head].get();
            frame.len = input.len() as u16;
            frame.data[..input.len()].copy_from_slice(input);
        }
        self.req_head.store(next, Ordering::Release);
        true
    }

    pub fn dequeue_response(&self, output: &mut [u8]) -> Option<usize> {
        let tail = self.resp_tail.load(Ordering::Relaxed);
        if tail == self.resp_head.load(Ordering::Acquire) {
            return None;
        }
        let frame = unsafe { &*self.resp_buf[tail].get() };
        let len = frame.len as usize;
        if len > output.len() {
            return None;
        }
        output[..len].copy_from_slice(&frame.data[..len]);
        let next = (tail + 1) % CONTROL_QUEUE_SIZE;
        self.resp_tail.store(next, Ordering::Release);
        Some(len)
    }

    pub fn enqueue_response(&self, input: &[u8]) -> bool {
        if input.len() > CONTROL_FRAME_SIZE {
            return false;
        }
        let head = self.resp_head.load(Ordering::Relaxed);
        let next = (head + 1) % CONTROL_QUEUE_SIZE;
        if next == self.resp_tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            let frame = &mut *self.resp_buf[head].get();
            frame.len = input.len() as u16;
            frame.data[..input.len()].copy_from_slice(input);
        }
        self.resp_head.store(next, Ordering::Release);
        true
    }

    pub fn process_next(&self, control: &ControlPlane) -> bool {
        let tail = self.req_tail.load(Ordering::Relaxed);
        if tail == self.req_head.load(Ordering::Acquire) {
            return false;
        }
        let frame = unsafe { *self.req_buf[tail].get() };
        let next = (tail + 1) % CONTROL_QUEUE_SIZE;
        self.req_tail.store(next, Ordering::Release);
        let mut response_buf = [0u8; CONTROL_FRAME_SIZE];
        let len = match core::str::from_utf8(&frame.data[..frame.len as usize]) {
            Ok(input) => match control.handle_request(input, &mut response_buf) {
                Ok(len) => len,
                Err(_) => {
                    let id = extract_number_field(input, "\"id\"").unwrap_or(0);
                    write_error(id, "invalid", &mut response_buf).unwrap_or(0)
                }
            },
            Err(_) => write_error(0, "invalid", &mut response_buf).unwrap_or(0),
        };
        if len == 0 {
            return false;
        }
        let head = self.resp_head.load(Ordering::Relaxed);
        let next = (head + 1) % CONTROL_QUEUE_SIZE;
        if next == self.resp_tail.load(Ordering::Acquire) {
            return false;
        }
        unsafe {
            let out = &mut *self.resp_buf[head].get();
            out.len = len as u16;
            out.data[..len].copy_from_slice(&response_buf[..len]);
        }
        self.resp_head.store(next, Ordering::Release);
        true
    }
}

pub struct TelemetryIpc {
    seq: AtomicU32,
}

impl TelemetryIpc {
    pub const fn new() -> Self {
        Self {
            seq: AtomicU32::new(1),
        }
    }

    pub fn pump(&self, channel: &ControlChannel, max: usize) -> usize {
        let mut count = 0usize;
        while count < max {
            let record = match telemetry_pop() {
                Some(record) => record,
                None => break,
            };
            let mut buffer = [0u8; CONTROL_FRAME_SIZE];
            let seq = self.seq.fetch_add(1, Ordering::Relaxed) as u64;
            let len = match write_telemetry_event(seq, record, &mut buffer) {
                Ok(len) => len,
                Err(_) => break,
            };
            if !channel.enqueue_response(&buffer[..len]) {
                break;
            }
            count += 1;
        }
        count
    }
}

static TELEMETRY_IPC: TelemetryIpc = TelemetryIpc::new();

pub fn telemetry_ipc() -> &'static TelemetryIpc {
    &TELEMETRY_IPC
}

// ---------------------------------------------------------------------------
// Global Hypervisor singleton
// Cannot be a plain static because Hypervisor::new() calls CPUID (not const).
// Uses Option<Hypervisor> in an UnsafeCell, lazily initialised on first use.
// ---------------------------------------------------------------------------

struct GlobalHv(UnsafeCell<Option<hypervisor::Hypervisor>>);
unsafe impl Sync for GlobalHv {}
static GLOBAL_HV: GlobalHv = GlobalHv(UnsafeCell::new(None));

pub fn global_hypervisor() -> &'static mut hypervisor::Hypervisor {
    unsafe {
        let opt = &mut *GLOBAL_HV.0.get();
        opt.get_or_insert_with(hypervisor::Hypervisor::new)
    }
}

// ---------------------------------------------------------------------------

pub struct HypervisorState {
    pub apic: Apic,
    pub atlas: Atlas,
    pub chronos: Chronos,
    pub ept: Ept,
    pub aeroframe: AeroFrame,
    pub vmx: Vmx,
    pub hv_ops: VmxOps,
    pub tsc_sync: TscSync,
    pub guest_allocation: Allocation,
    pub tsc_baseline: u64,
    pub safe_mode: bool,
    pub recoveries: u64,
    pub caps: Capabilities,
    /// Batched INVEPT: set to true when EPT mappings change, cleared after flush.
    pub ept_dirty: bool,
}

pub fn init() -> Result<HypervisorState, HvError> {
    let apic = Apic::new()?;
    let mut atlas = Atlas::new()?;
    atlas.reserve_hugepages(DEFAULT_GUEST_BASE, DEFAULT_GUEST_HUGEPAGES)?;
    let guest_allocation = atlas.allocate_guest_region(0)?;
    let chronos = Chronos::new()?;
    let ept = Ept::new();
    let aeroframe = AeroFrame::new()?;
    let tsc_sync = TscSync::new();
    let vmx = Vmx::new(ept.eptp())?;
    let caps = probe_capabilities();
    let decision = evaluate_capabilities(caps);
    if decision.fatal {
        return Err(HvError::HardwareFault);
    }
    let hv_ops = VmxOps::new(caps);
    snapshot_manager().configure(guest_allocation.base.0, guest_allocation.size);
    // Force the global Hypervisor singleton to initialise during hypervisor setup.
    let _ = global_hypervisor();
    if decision.degraded {
        record_telemetry(TELEMETRY_CAP_DEGRADED, 0);
    }
    Ok(HypervisorState {
        apic,
        atlas,
        chronos,
        ept,
        aeroframe,
        vmx,
        hv_ops,
        tsc_sync,
        guest_allocation,
        tsc_baseline: 0,
        safe_mode: decision.degraded,
        recoveries: 0,
        caps,
        ept_dirty: false,
    })
}

impl HypervisorState {
    pub fn update_tsc_baseline(&mut self, overhead: u64) {
        if overhead > self.tsc_baseline {
            self.tsc_baseline = overhead;
        }
    }

    pub fn recover_from_fault(&mut self) -> bool {
        self.safe_mode = true;
        self.recoveries = self.recoveries.wrapping_add(1);
        self.tsc_baseline = 0;
        recovery_budget_exhausted(self.recoveries)
    }

    pub fn stress_tick(&mut self, now: u64) {
        match stress_injector().tick(now) {
            StressEvent::None => {}
            StressEvent::EptFault => {
                snapshot_log().record(self.guest_allocation.base.0);
                record_telemetry(TELEMETRY_STRESS_EPT, 0);
            }
            StressEvent::IrqStorm => {
                let _ = crate::vmm::irq::force_quarantine(32);
                record_telemetry(TELEMETRY_STRESS_IRQ, 32);
            }
        }
    }

    pub fn apply_restore(&mut self) -> Result<bool, HvError> {
        let state_restored = snapshot_state().restore();
        let memory_restored = snapshot_manager().apply_restore(&mut self.ept)?;
        Ok(state_restored || memory_restored)
    }
}

#[inline(always)]
pub fn park_forever() -> ! {
    loop {
        // HLT halts the logical processor until the next interrupt, burning zero power
        // on idle. spin_loop() burns 100% of the core with PAUSE instructions.
        unsafe { core::arch::asm!("hlt") };
    }
}

pub fn run() -> ! {
    let mut state = match init() {
        Ok(state) => state,
        Err(_) => park_forever(),
    };
    let _ = state
        .tsc_sync
        .record_local(0, unsafe { core::arch::x86_64::_rdtsc() });
    let apic_ids = [0u32, 1u32];
    let indices = [0usize, 1usize];
    let _ = state
        .chronos
        .rendezvous_sync(&state.apic, &state.tsc_sync, &apic_ids, &indices, 0x10);
    let _ = vmx_handler::vmx_loop(&mut state);
    park_forever()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_plane_ping() {
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"pong\""));
    }

    #[test]
    fn control_plane_telemetry_pop() {
        telemetry_clear();
        record_telemetry(TELEMETRY_BUDGET_EXCEEDED, 7);
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"telemetry.pop\"}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"kind\":1"));
        assert!(response.contains("\"value\":7"));
    }

    #[test]
    fn control_channel_ping() {
        let channel = ControlChannel::new();
        let control = ControlPlane::new();
        assert!(channel.enqueue_request(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}"));
        assert!(channel.process_next(&control));
        let mut output = [0u8; 512];
        let len = channel.dequeue_response(&mut output).unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"pong\""));
    }

    #[test]
    fn snapshot_log_streaming() {
        snapshot_log().begin();
        snapshot_log().record(0x1000);
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"snapshot.pop\"}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"gpa\":4096"));
        snapshot_log().end();
    }

    #[test]
    fn virtio_direct_enable_status() {
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let _ = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"virtio.direct.enable\"}",
                &mut output,
            )
            .unwrap();
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"virtio.direct.status\"}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"net_enabled\":true"));
        assert!(response.contains("\"blk_enabled\":true"));
    }

    #[test]
    fn virtio_mmio_queue_config() {
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let _ = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"virtio.direct.enable\"}",
                &mut output,
            )
            .unwrap();
        let _ = control
            .handle_request("{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"virtio.mmio.write\",\"addr\":268435576,\"value\":128}", &mut output)
            .unwrap();
        let _ = control
            .handle_request("{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"virtio.mmio.write\",\"addr\":268435588,\"value\":1}", &mut output)
            .unwrap();
        let len = control
            .handle_request("{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"virtio.mmio.read\",\"addr\":268435588}", &mut output)
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"result\":1"));
    }

    #[test]
    fn snapshot_finalize_restore() {
        snapshot_log().begin();
        snapshot_log().record(0x2000);
        snapshot_log().end();
        snapshot_manager().finalize_from_log();
        assert!(snapshot_manager().request_restore());
        let mut ept = Ept::new();
        let applied = snapshot_manager().apply_restore(&mut ept).unwrap();
        assert!(applied);
    }

    #[test]
    fn telemetry_ipc_pump() {
        telemetry_clear();
        record_telemetry(TELEMETRY_VIRTIO_MMIO, 42);
        let channel = ControlChannel::new();
        let count = telemetry_ipc().pump(&channel, 4);
        assert_eq!(count, 1);
        let mut output = [0u8; 512];
        let len = channel.dequeue_response(&mut output).unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"telemetry.event\""));
        assert!(response.contains("\"kind\":6"));
    }

    #[test]
    fn stress_automation_runs() {
        telemetry_clear();
        stress_injector().enable();
        stress_injector().set_cadence(1);
        for step in 0..256u64 {
            match stress_injector().tick(step) {
                StressEvent::EptFault => record_telemetry(TELEMETRY_STRESS_EPT, 0),
                StressEvent::IrqStorm => record_telemetry(TELEMETRY_STRESS_IRQ, 0),
                StressEvent::None => {}
            }
        }
        assert!(telemetry_len() > 0);
        stress_injector().set_cadence(128);
        stress_injector().disable();
    }

    #[test]
    fn virtio_backend_processes_queue() {
        virtio_direct().reset_backend();
        net_tx_ring().clear();
        let _ = virtio_direct().enable_default();
        let base = VIRTIO_MMIO_BASE_NET;
        let desc_gpa = 0x2000u64;
        let avail_gpa = 0x2100u64;
        let used_gpa = 0x2200u64;
        let data_gpa = 0x3000u64;
        assert!(virtio_direct().dma_map(desc_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(avail_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(used_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(data_gpa, 0x1000).is_some());
        
        // Build packet: VirtNetHdr (12 bytes) + minimal frame (46 bytes for valid Ethernet)
        let mut packet = [0u8; 58]; // 12 + 46
        // VirtNetHdr (zeros are valid - no offload/GSO)
        packet[2..4].copy_from_slice(&14u16.to_le_bytes()); // hdr_len
        packet[10..12].copy_from_slice(&1u16.to_le_bytes()); // num_buffers
        // Frame data (46 bytes) - simple pattern
        for i in 12..58 {
            packet[i] = (i - 12) as u8;
        }
        assert!(virtio_direct().dma.write_bytes(data_gpa, &packet));
        
        assert!(virtio_direct().dma_write_u64(desc_gpa, data_gpa));
        assert!(virtio_direct().dma_write_u32(desc_gpa + 8, 58)); // total length
        assert!(virtio_direct().dma_write_u32(desc_gpa + 12, 1)); // flags=1 (TX)
        assert!(virtio_direct().dma_write_u32(avail_gpa, 1u32 << 16));
        assert!(virtio_direct().mmio_write(base + 0x080, desc_gpa as u32));
        assert!(virtio_direct().mmio_write(base + 0x084, (desc_gpa >> 32) as u32));
        assert!(virtio_direct().mmio_write(base + 0x090, avail_gpa as u32));
        assert!(virtio_direct().mmio_write(base + 0x094, (avail_gpa >> 32) as u32));
        assert!(virtio_direct().mmio_write(base + 0x0A0, used_gpa as u32));
        assert!(virtio_direct().mmio_write(base + 0x0A4, (used_gpa >> 32) as u32));
        assert!(virtio_direct().mmio_write(base + 0x038, 1));
        assert!(virtio_direct().mmio_write(base + 0x044, 1));
        assert!(virtio_direct().mmio_write(base + 0x050, 0));
        let processed = virtio_direct().process_queues();
        assert_eq!(processed, 1);
        let (rx, tx, last_len) = virtio_direct().net_model.stats();
        assert_eq!(rx, 0);
        assert_eq!(tx, 1);
        assert_eq!(last_len, 46); // Frame length (58 - 12 VirtNetHdr)
        
        // Verify frame in TX ring
        assert_eq!(net_tx_ring().pending(), 1);
    }

    #[test]
    fn console_output_ring_push_drain() {
        console_output_ring().clear();
        let test_data = b"Hello from guest console!\n";
        assert!(console_output_ring().push(test_data));
        
        let mut output = [0u8; 128];
        let drained = console_output_ring().drain(&mut output);
        assert_eq!(drained, test_data.len());
        assert_eq!(&output[..drained], test_data);
    }

    #[test]
    fn console_input_ring_push_pop() {
        let input_ring = console_input_ring();
        
        // Push some bytes from host
        assert!(input_ring.push(b'A'));
        assert!(input_ring.push(b'B'));
        assert!(input_ring.push(b'C'));
        
        // Pop and verify
        assert_eq!(input_ring.pop(), Some(b'A'));
        assert_eq!(input_ring.pop(), Some(b'B'));
        assert_eq!(input_ring.pop(), Some(b'C'));
        assert_eq!(input_ring.pop(), None);
        
        assert_eq!(input_ring.available(), 0);
    }

    #[test]
    fn console_tx_descriptor_processing() {
        virtio_direct().reset_backend();
        console_output_ring().clear();
        virtio_direct().enable_default();
        
        let desc_gpa = 0x5000u64;
        let data_gpa = 0x6000u64;
        let test_msg = b"Guest TX message\n";
        
        // Setup DMA
        assert!(virtio_direct().dma_map(desc_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(data_gpa, 0x1000).is_some());
        
        // Write test message to guest memory
        assert!(virtio_direct().dma.write_bytes(data_gpa, test_msg));
        
        // Setup TX descriptor (flags=1 for write, i.e., guest TX)
        assert!(virtio_direct().dma_write_u64(desc_gpa, data_gpa));
        assert!(virtio_direct().dma_write_u32(desc_gpa + 8, test_msg.len() as u32));
        assert!(virtio_direct().dma_write_u32(desc_gpa + 12, 1)); // flags=1 (write)
        
        // Process via console model directly
        let ok = virtio_direct().console_model.process_desc(
            &virtio_direct().dma,
            data_gpa,
            test_msg.len() as u32,
            1
        );
        assert!(ok);
        
        // Verify message appeared in output ring
        let mut output = [0u8; 128];
        let drained = console_output_ring().drain(&mut output);
        assert_eq!(drained, test_msg.len());
        assert_eq!(&output[..drained], test_msg);
        
        let (rx, tx, _) = virtio_direct().console_model.stats();
        assert_eq!(tx, 1);
        assert_eq!(rx, 0);
    }

    #[test]
    fn net_tx_ring_push_pop() {
        net_tx_ring().clear();
        
        // Create test frame
        let frame = EthernetFrame {
            hdr: VirtNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 14,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
                num_buffers: 1,
            },
            data: [0x42; 1514],
            len: 60,
        };
        
        // Push and pop
        assert!(net_tx_ring().push(frame));
        assert_eq!(net_tx_ring().pending(), 1);
        
        let popped = net_tx_ring().pop().unwrap();
        assert_eq!(popped.len, 60);
        assert_eq!(popped.hdr.hdr_len, 14);
        assert_eq!(popped.data[0], 0x42);
        
        assert_eq!(net_tx_ring().pending(), 0);
        assert!(net_tx_ring().pop().is_none());
    }

    #[test]
    fn net_tx_frame_parsing() {
        // Verify VirtNetHdr parsing from bytes
        let hdr_bytes: [u8; 12] = [
            0x01,       // flags
            0x00,       // gso_type
            0x0E, 0x00, // hdr_len = 14
            0x00, 0x00, // gso_size = 0
            0x12, 0x00, // csum_start = 18
            0x10, 0x00, // csum_offset = 16
            0x01, 0x00, // num_buffers = 1
        ];
        
        let hdr = VirtNetHdr {
            flags: hdr_bytes[0],
            gso_type: hdr_bytes[1],
            hdr_len: u16::from_le_bytes([hdr_bytes[2], hdr_bytes[3]]),
            gso_size: u16::from_le_bytes([hdr_bytes[4], hdr_bytes[5]]),
            csum_start: u16::from_le_bytes([hdr_bytes[6], hdr_bytes[7]]),
            csum_offset: u16::from_le_bytes([hdr_bytes[8], hdr_bytes[9]]),
            num_buffers: u16::from_le_bytes([hdr_bytes[10], hdr_bytes[11]]),
        };
        
        assert_eq!(hdr.flags, 1);
        assert_eq!(hdr.hdr_len, 14);
        assert_eq!(hdr.csum_start, 18);
        assert_eq!(hdr.csum_offset, 16);
    }

    #[test]
    fn net_tx_descriptor_processing() {
        virtio_direct().reset_backend();
        net_tx_ring().clear();
        virtio_direct().enable_default();
        
        let desc_gpa = 0x7000u64;
        let packet_gpa = 0x8000u64;
        
        // Setup DMA
        assert!(virtio_direct().dma_map(desc_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(packet_gpa, 0x1000).is_some());
        
        // Build packet: VirtNetHdr (12 bytes) + Ethernet frame (60 bytes)
        let mut packet_data = [0u8; 72];
        
        // VirtNetHdr
        packet_data[0] = 0; // flags
        packet_data[1] = 0; // gso_type
        packet_data[2..4].copy_from_slice(&14u16.to_le_bytes()); // hdr_len
        packet_data[4..6].copy_from_slice(&0u16.to_le_bytes()); // gso_size
        packet_data[6..8].copy_from_slice(&0u16.to_le_bytes()); // csum_start
        packet_data[8..10].copy_from_slice(&0u16.to_le_bytes()); // csum_offset
        packet_data[10..12].copy_from_slice(&1u16.to_le_bytes()); // num_buffers
        
        // Ethernet frame (simple pattern)
        for i in 12..72 {
            packet_data[i] = ((i - 12) % 256) as u8;
        }
        
        // Write packet to guest memory
        assert!(virtio_direct().dma.write_bytes(packet_gpa, &packet_data));
        
        // Process TX descriptor (flags=1 for guest→host)
        let ok = virtio_direct().net_model.process_desc(
            &virtio_direct().dma,
            packet_gpa,
            72,
            1
        );
        assert!(ok);
        
        // Verify frame in TX ring
        assert_eq!(net_tx_ring().pending(), 1);
        let frame = net_tx_ring().pop().unwrap();
        assert_eq!(frame.len, 60); // 72 - 12 VirtNetHdr
        assert_eq!(frame.hdr.hdr_len, 14);
        assert_eq!(frame.data[0], 0); // First byte of Ethernet frame
        assert_eq!(frame.data[1], 1);
        assert_eq!(frame.data[59], 59);
        
        let (_, tx, last_len) = virtio_direct().net_model.stats();
        assert_eq!(tx, 1);
        assert_eq!(last_len, 60);
    }

    #[test]
    fn net_rx_ring_push_pop() {
        // Clear and test basic RX ring operations
        let rx_ring = net_rx_ring();
        
        // Push a test packet from host
        let test_packet = [0xAA; 64];
        assert!(rx_ring.push(&test_packet));
        assert_eq!(rx_ring.pending(), 1);
        
        // Pop and verify
        let mut output = [0u8; 128];
        let popped_len = rx_ring.pop(&mut output).unwrap();
        assert_eq!(popped_len, 64);
        assert_eq!(&output[..64], &test_packet);
        
        assert_eq!(rx_ring.pending(), 0);
        assert!(rx_ring.pop(&mut output).is_none());
    }

    #[test]
    fn net_rx_descriptor_processing() {
        virtio_direct().reset_backend();
        virtio_direct().enable_default();
        
        let rx_gpa = 0x9000u64;
        
        // Setup DMA
        assert!(virtio_direct().dma_map(rx_gpa, 0x1000).is_some());
        
        // Push a packet to RX ring (echOS injecting packet to guest)
        let test_frame = [0x42; 60];
        assert!(net_rx_ring().push(&test_frame));
        
        // Process RX descriptor (flags=0 for guest RX)
        let ok = virtio_direct().net_model.process_desc(
            &virtio_direct().dma,
            rx_gpa,
            128, // Descriptor can hold 128 bytes
            0    // flags=0 for RX
        );
        assert!(ok);
        
        // Verify VirtNetHdr (12 bytes) + frame data written to guest memory
        let mut received = [0u8; 72];
        assert!(virtio_direct().dma.read_bytes(rx_gpa, &mut received));
        
        // Check VirtNetHdr (should be zeros except num_buffers=1)
        assert_eq!(received[0], 0); // flags
        assert_eq!(received[1], 0); // gso_type
        assert_eq!(received[10], 1); // num_buffers (little-endian)
        assert_eq!(received[11], 0);
        
        // Check frame data (starts at byte 12)
        for i in 0..60 {
            assert_eq!(received[12 + i], 0x42, "Mismatch at frame byte {}", i);
        }
        
        let (rx, _, last_len) = virtio_direct().net_model.stats();
        assert_eq!(rx, 1);
        assert_eq!(last_len, 60); // Frame length (excludes VirtNetHdr)
    }

    #[test]
    fn net_rx_empty_descriptor() {
        virtio_direct().reset_backend();
        virtio_direct().enable_default();
        
        let rx_gpa = 0xA000u64;
        assert!(virtio_direct().dma_map(rx_gpa, 0x1000).is_some());
        
        // Process RX descriptor when ring is empty
        let ok = virtio_direct().net_model.process_desc(
            &virtio_direct().dma,
            rx_gpa,
            64,
            0 // RX
        );
        assert!(ok); // Should succeed but write zeros
        
        // Verify zeros written
        let mut received = [0u8; 64];
        assert!(virtio_direct().dma.read_bytes(rx_gpa, &mut received));
        assert_eq!(&received, &[0u8; 64]);
    }

    #[test]
    fn block_io_ring_push_pop() {
        block_io_ring().clear();
        
        // Create test READ command
        let cmd = BlockIoCmd {
            req_type: 0, // VIRTIO_BLK_T_IN (READ)
            sector: 100,
            data_gpa: 0xB000,
            data_len: 4096,
            status_gpa: 0xB000 + 4096,
        };
        
        // Push and pop
        assert!(block_io_ring().push(cmd));
        assert_eq!(block_io_ring().pending(), 1);
        
        let popped = block_io_ring().pop().unwrap();
        assert_eq!(popped.req_type, 0);
        assert_eq!(popped.sector, 100);
        assert_eq!(popped.data_len, 4096);
        
        assert_eq!(block_io_ring().pending(), 0);
        assert!(block_io_ring().pop().is_none());
    }

    #[test]
    fn block_io_read_request() {
        virtio_direct().reset_backend();
        block_io_ring().clear();
        virtio_direct().enable_default();
        
        let req_gpa = 0xC000u64;
        assert!(virtio_direct().dma_map(req_gpa, 0x2000).is_some());
        
        // Build VirtBlkRequest: READ 8 sectors (4096 bytes) from sector 50
        // Total descriptor: 16-byte header + 4096 data + 1 status = 4113 bytes
        let mut request = [0u8; 4113];
        
        // VirtBlkRequest header (16 bytes)
        request[0..4].copy_from_slice(&0u32.to_le_bytes()); // VIRTIO_BLK_T_IN (READ)
        request[4..8].copy_from_slice(&0u32.to_le_bytes()); // reserved
        request[8..16].copy_from_slice(&50u64.to_le_bytes()); // sector
        // Data region (bytes 16-4111) - will be filled by echOS on READ
        // Status byte (byte 4112) - will be written by echOS after completion
        
        // Write request to guest memory
        assert!(virtio_direct().dma.write_bytes(req_gpa, &request));
        
        // Process descriptor (VirtIO queues the command)
        let ok = virtio_direct().blk_model.process_desc(
            &virtio_direct().dma,
            req_gpa,
            4113,
            0 // flags (unused for block - type is in header)
        );
        assert!(ok);
        
        // Verify command in ring
        assert_eq!(block_io_ring().pending(), 1);
        let cmd = block_io_ring().pop().unwrap();
        assert_eq!(cmd.req_type, 0); // READ
        assert_eq!(cmd.sector, 50);
        assert_eq!(cmd.data_gpa, req_gpa + 16); // After header
        assert_eq!(cmd.data_len, 4096); // 4113 - 16 - 1
        assert_eq!(cmd.status_gpa, req_gpa + 4112); // Last byte
        
        let (reads, writes, last_len) = virtio_direct().blk_model.stats();
        assert_eq!(reads, 1);
        assert_eq!(writes, 0);
        assert_eq!(last_len, 4096);
    }

    #[test]
    fn block_io_write_request() {
        virtio_direct().reset_backend();
        block_io_ring().clear();
        virtio_direct().enable_default();
        
        let req_gpa = 0xD000u64;
        assert!(virtio_direct().dma_map(req_gpa, 0x2000).is_some());
        
        // Build VirtBlkRequest: WRITE 4 sectors (2048 bytes) to sector 200
        let mut request = [0u8; 2065]; // 16 + 2048 + 1
        
        // VirtBlkRequest header
        request[0..4].copy_from_slice(&1u32.to_le_bytes()); // VIRTIO_BLK_T_OUT (WRITE)
        request[4..8].copy_from_slice(&0u32.to_le_bytes());
        request[8..16].copy_from_slice(&200u64.to_le_bytes());
        
        // Data region (test pattern)
        for i in 16..2064 {
            request[i] = ((i - 16) % 256) as u8;
        }
        
        // Write request
        assert!(virtio_direct().dma.write_bytes(req_gpa, &request));
        
        // Process descriptor
        let ok = virtio_direct().blk_model.process_desc(
            &virtio_direct().dma,
            req_gpa,
            2065,
            0
        );
        assert!(ok);
        
        // Verify command
        assert_eq!(block_io_ring().pending(), 1);
        let cmd = block_io_ring().pop().unwrap();
        assert_eq!(cmd.req_type, 1); // WRITE
        assert_eq!(cmd.sector, 200);
        assert_eq!(cmd.data_len, 2048);
        
        let (reads, writes, last_len) = virtio_direct().blk_model.stats();
        assert_eq!(reads, 0);
        assert_eq!(writes, 1);
        assert_eq!(last_len, 2048);
    }

    #[test]
    fn block_io_flush_request() {
        virtio_direct().reset_backend();
        block_io_ring().clear();
        virtio_direct().enable_default();
        
        let req_gpa = 0xE000u64;
        assert!(virtio_direct().dma_map(req_gpa, 0x1000).is_some());
        
        // FLUSH command: header + status only (no data)
        let mut request = [0u8; 17]; // 16 + 1
        request[0..4].copy_from_slice(&4u32.to_le_bytes()); // VIRTIO_BLK_T_FLUSH
        request[4..8].copy_from_slice(&0u32.to_le_bytes());
        request[8..16].copy_from_slice(&0u64.to_le_bytes()); // sector ignored
        
        assert!(virtio_direct().dma.write_bytes(req_gpa, &request));
        
        let ok = virtio_direct().blk_model.process_desc(
            &virtio_direct().dma,
            req_gpa,
            17,
            0
        );
        assert!(ok);
        
        // Verify FLUSH command
        assert_eq!(block_io_ring().pending(), 1);
        let cmd = block_io_ring().pop().unwrap();
        assert_eq!(cmd.req_type, 4); // FLUSH
        assert_eq!(cmd.data_len, 0); // No data for FLUSH
        
        let (_, _, last_len) = virtio_direct().blk_model.stats();
        assert_eq!(last_len, 0); // FLUSH has no data transfer
    }

    #[test]
    fn desc_chain_single_descriptor() {
        virtio_direct().reset_backend();
        let desc_base = 0xF000u64;
        assert!(virtio_direct().dma_map(desc_base, 0x1000).is_some());
        
        // Setup single descriptor (no NEXT flag)
        // Descriptor format: gpa(8) + len(4) + flags(2) + next(2) = 16 bytes
        let desc_addr = desc_base;
        assert!(virtio_direct().dma_write_u64(desc_addr, 0x10000)); // gpa
        assert!(virtio_direct().dma_write_u32(desc_addr + 8, 1024)); // len
        assert!(virtio_direct().dma.write_bytes(desc_addr + 12, &[0u8, 0u8])); // flags (no NEXT)
        assert!(virtio_direct().dma.write_bytes(desc_addr + 14, &[0u8, 0u8])); // next (unused)
        
        // Walk chain (should yield exactly 1 descriptor)
        let chain = DescChainIter::new(&virtio_direct().dma, desc_base, 0);
        let descs: Vec<VirtioDescriptor> = chain.collect();
        
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0].gpa, 0x10000);
        assert_eq!(descs[0].len, 1024);
        assert!(!descs[0].has_next());
    }

    #[test]
    fn desc_chain_three_descriptors() {
        virtio_direct().reset_backend();
        let desc_base = 0xF000u64;
        assert!(virtio_direct().dma_map(desc_base, 0x1000).is_some());
        
        // Setup 3-descriptor chain: 0 -> 1 -> 2
        // Descriptor 0: header (NEXT flag set, next=1)
        let desc0_addr = desc_base;
        assert!(virtio_direct().dma_write_u64(desc0_addr, 0x20000)); // gpa
        assert!(virtio_direct().dma_write_u32(desc0_addr + 8, 16)); // len
        assert!(virtio_direct().dma.write_bytes(desc0_addr + 12, &[1u8, 0u8])); // flags (NEXT=1)
        assert!(virtio_direct().dma.write_bytes(desc0_addr + 14, &[1u8, 0u8])); // next=1
        
        // Descriptor 1: data (NEXT flag set, next=2)
        let desc1_addr = desc_base + 16;
        assert!(virtio_direct().dma_write_u64(desc1_addr, 0x30000));
        assert!(virtio_direct().dma_write_u32(desc1_addr + 8, 4096));
        assert!(virtio_direct().dma.write_bytes(desc1_addr + 12, &[1u8, 0u8])); // NEXT
        assert!(virtio_direct().dma.write_bytes(desc1_addr + 14, &[2u8, 0u8])); // next=2
        
        // Descriptor 2: status (no NEXT flag)
        let desc2_addr = desc_base + 32;
        assert!(virtio_direct().dma_write_u64(desc2_addr, 0x40000));
        assert!(virtio_direct().dma_write_u32(desc2_addr + 8, 1));
        assert!(virtio_direct().dma.write_bytes(desc2_addr + 12, &[2u8, 0u8])); // flags (WRITE=2, no NEXT)
        assert!(virtio_direct().dma.write_bytes(desc2_addr + 14, &[0u8, 0u8])); // next (unused)
        
        // Walk chain
        let chain = DescChainIter::new(&virtio_direct().dma, desc_base, 0);
        let descs: Vec<VirtioDescriptor> = chain.collect();
        
        assert_eq!(descs.len(), 3);
        
        // Verify descriptor 0 (header)
        assert_eq!(descs[0].gpa, 0x20000);
        assert_eq!(descs[0].len, 16);
        assert!(descs[0].has_next());
        assert!(!descs[0].is_write());
        
        // Verify descriptor 1 (data)
        assert_eq!(descs[1].gpa, 0x30000);
        assert_eq!(descs[1].len, 4096);
        assert!(descs[1].has_next());
        
        // Verify descriptor 2 (status)
        assert_eq!(descs[2].gpa, 0x40000);
        assert_eq!(descs[2].len, 1);
        assert!(!descs[2].has_next());
        assert!(descs[2].is_write());
    }

    #[test]
    fn desc_chain_max_length_limit() {
        virtio_direct().reset_backend();
        let desc_base = 0xF000u64;
        assert!(virtio_direct().dma_map(desc_base, 0x1000).is_some());
        
        // Setup circular chain: 0 -> 1 -> 0 (infinite loop)
        let desc0_addr = desc_base;
        assert!(virtio_direct().dma_write_u64(desc0_addr, 0x50000));
        assert!(virtio_direct().dma_write_u32(desc0_addr + 8, 64));
        assert!(virtio_direct().dma.write_bytes(desc0_addr + 12, &[1u8, 0u8])); // NEXT
        assert!(virtio_direct().dma.write_bytes(desc0_addr + 14, &[1u8, 0u8])); // next=1
        
        let desc1_addr = desc_base + 16;
        assert!(virtio_direct().dma_write_u64(desc1_addr, 0x60000));
        assert!(virtio_direct().dma_write_u32(desc1_addr + 8, 64));
        assert!(virtio_direct().dma.write_bytes(desc1_addr + 12, &[1u8, 0u8])); // NEXT
        assert!(virtio_direct().dma.write_bytes(desc1_addr + 14, &[0u8, 0u8])); // next=0 (back to desc0)
        
        // Walk chain (should stop at max_chain_len=32)
        let chain = DescChainIter::new(&virtio_direct().dma, desc_base, 0);
        let descs: Vec<VirtioDescriptor> = chain.collect();
        
        assert_eq!(descs.len(), 32); // Should hit safety limit
    }

    #[test]
    fn dma_sg_read_contiguous() {
        virtio_direct().reset_backend();
        
        let gpa1 = 0x10000u64;
        let gpa2 = 0x11000u64;
        let gpa3 = 0x12000u64;
        
        assert!(virtio_direct().dma_map(gpa1, 0x1000).is_some());
        assert!(virtio_direct().dma_map(gpa2, 0x1000).is_some());
        assert!(virtio_direct().dma_map(gpa3, 0x1000).is_some());
        
        // Write test data to three regions
        let data1 = b"Hello, ";
        let data2 = b"scatter-gather ";
        let data3 = b"world!";
        
        assert!(virtio_direct().dma.write_bytes(gpa1, data1));
        assert!(virtio_direct().dma.write_bytes(gpa2, data2));
        assert!(virtio_direct().dma.write_bytes(gpa3, data3));
        
        // Build scatter-gather list
        use crate::vmm::SgEntry;
        let sg_list = [
            SgEntry { gpa: gpa1, len: data1.len() as u32 },
            SgEntry { gpa: gpa2, len: data2.len() as u32 },
            SgEntry { gpa: gpa3, len: data3.len() as u32 },
        ];
        
        // Read using scatter-gather
        let total_len = data1.len() + data2.len() + data3.len();
        let mut output = vec![0u8; total_len];
        let read_len = virtio_direct().dma.read_sg(&sg_list, &mut output);
        
        assert_eq!(read_len, total_len);
        assert_eq!(&output[..data1.len()], data1);
        assert_eq!(&output[data1.len()..data1.len() + data2.len()], data2);
        assert_eq!(&output[data1.len() + data2.len()..], data3);
    }

    #[test]
    fn dma_sg_write_scattered() {
        virtio_direct().reset_backend();
        
        let gpa1 = 0x20000u64;
        let gpa2 = 0x21000u64;
        let gpa3 = 0x22000u64;
        
        assert!(virtio_direct().dma_map(gpa1, 0x1000).is_some());
        assert!(virtio_direct().dma_map(gpa2, 0x1000).is_some());
        assert!(virtio_direct().dma_map(gpa3, 0x1000).is_some());
        
        // Prepare input data
        let input = b"VirtIO scatter-gather DMA test!";
        
        // Build scatter-gather list: split into 3 segments
        use crate::vmm::SgEntry;
        let sg_list = [
            SgEntry { gpa: gpa1, len: 10 },
            SgEntry { gpa: gpa2, len: 15 },
            SgEntry { gpa: gpa3, len: 6 },
        ];
        
        // Write using scatter-gather
        let written = virtio_direct().dma.write_sg(&sg_list, input);
        assert_eq!(written, 31);
        
        // Verify each segment
        let mut seg1 = [0u8; 10];
        let mut seg2 = [0u8; 15];
        let mut seg3 = [0u8; 6];
        
        assert!(virtio_direct().dma.read_bytes(gpa1, &mut seg1));
        assert!(virtio_direct().dma.read_bytes(gpa2, &mut seg2));
        assert!(virtio_direct().dma.read_bytes(gpa3, &mut seg3));
        
        assert_eq!(&seg1, &input[..10]);
        assert_eq!(&seg2, &input[10..25]);
        assert_eq!(&seg3, &input[25..31]);
    }

    #[test]
    fn dma_sg_block_io_chain() {
        virtio_direct().reset_backend();
        
        // Simulate VirtIO block READ: header(16) + data(4096) + status(1)
        let hdr_gpa = 0x30000u64;
        let data_gpa = 0x31000u64;
        let status_gpa = 0x32000u64;
        
        assert!(virtio_direct().dma_map(hdr_gpa, 0x1000).is_some());
        assert!(virtio_direct().dma_map(data_gpa, 0x5000).is_some());
        assert!(virtio_direct().dma_map(status_gpa, 0x1000).is_some());
        
        // Write header: VirtBlkRequest (READ from sector 100)
        let mut header = [0u8; 16];
        header[0..4].copy_from_slice(&0u32.to_le_bytes()); // VIRTIO_BLK_T_IN
        header[8..16].copy_from_slice(&100u64.to_le_bytes()); // sector
        assert!(virtio_direct().dma.write_bytes(hdr_gpa, &header));
        
        // Write data (simulate disk read result)
        let disk_data = [0x42u8; 4096];
        assert!(virtio_direct().dma.write_bytes(data_gpa, &disk_data));
        
        // Write status byte
        assert!(virtio_direct().dma.write_u8(status_gpa, 0)); // VIRTIO_BLK_S_OK
        
        // Read entire chain using scatter-gather
        use crate::vmm::SgEntry;
        let sg_list = [
            SgEntry { gpa: hdr_gpa, len: 16 },
            SgEntry { gpa: data_gpa, len: 4096 },
            SgEntry { gpa: status_gpa, len: 1 },
        ];
        
        let mut chain_buf = vec![0u8; 4113];
        let read_len = virtio_direct().dma.read_sg(&sg_list, &mut chain_buf);
        
        assert_eq!(read_len, 4113);
        
        // Verify header
        assert_eq!(&chain_buf[..16], &header);
        
        // Verify data
        assert_eq!(&chain_buf[16..4112], &disk_data[..]);
        
        // Verify status
        assert_eq!(chain_buf[4112], 0);
    }

    #[test]
    fn dma_sg_error_handling() {
        virtio_direct().reset_backend();
        
        let gpa = 0x40000u64;
        assert!(virtio_direct().dma_map(gpa, 0x100).is_some());
        
        use crate::vmm::SgEntry;
        
        // Test read_sg with invalid GPA (unmapped)
        let sg_list = [
            SgEntry { gpa, len: 64 },
            SgEntry { gpa: 0x99999999, len: 64 }, // Invalid
        ];
        let mut output = vec![0u8; 128];
        let result = virtio_direct().dma.read_sg(&sg_list, &mut output);
        assert_eq!(result, 0); // Should fail
        
        // Test write_sg with buffer too small
        let sg_list_large = [
            SgEntry { gpa, len: 200 },
        ];
        let small_input = [0xAAu8; 100];
        let result = virtio_direct().dma.write_sg(&sg_list_large, &small_input);
        assert_eq!(result, 0); // Should fail due to size mismatch
    }

    #[test]
    fn async_completion_ring_basic() {
        async_completion_ring().clear();
        
        // Allocate request IDs
        let id1 = async_completion_ring().alloc_id();
        let id2 = async_completion_ring().alloc_id();
        assert!(id2 > id1);
        
        // Push completions
        let comp1 = AsyncCompletion {
            id: id1,
            status: 0,
            result_len: 4096,
            timestamp: 1000,
        };
        let comp2 = AsyncCompletion {
            id: id2,
            status: 1,
            result_len: 0,
            timestamp: 1001,
        };
        
        assert!(async_completion_ring().push(comp1));
        assert!(async_completion_ring().push(comp2));
        assert_eq!(async_completion_ring().pending(), 2);
        
        // Pop completions
        let popped1 = async_completion_ring().pop().unwrap();
        assert_eq!(popped1.id, id1);
        assert_eq!(popped1.status, 0);
        assert_eq!(popped1.result_len, 4096);
        
        let popped2 = async_completion_ring().pop().unwrap();
        assert_eq!(popped2.id, id2);
        assert_eq!(popped2.status, 1);
        
        assert_eq!(async_completion_ring().pending(), 0);
        assert!(async_completion_ring().pop().is_none());
    }

    #[test]
    fn network_link_status_toggle() {
        let link = network_link_status();
        
        // Default: link up
        assert!(link.is_link_up());
        let gen0 = link.config_generation();
        
        // Set link down
        link.set_link_up(false);
        assert!(!link.is_link_up());
        assert_eq!(link.config_generation(), gen0 + 1);
        
        // Set link up
        link.set_link_up(true);
        assert!(link.is_link_up());
        assert_eq!(link.config_generation(), gen0 + 2);
    }

    #[test]
    fn network_mac_address_config() {
        let link = network_link_status();
        
        let new_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let gen0 = link.config_generation();
        
        link.set_mac(&new_mac);
        assert_eq!(link.get_mac(), new_mac);
        assert_eq!(link.config_generation(), gen0 + 1);
    }

    #[test]
    fn multi_port_console_output() {
        multi_port_console().clear_all();
        
        let port0 = multi_port_console().port(0).unwrap();
        let port1 = multi_port_console().port(1).unwrap();
        
        // Write to port 0
        let msg0 = b"Port 0 message";
        assert!(port0.push_output(msg0));
        
        // Write to port 1
        let msg1 = b"Port 1 message";
        assert!(port1.push_output(msg1));
        
        // Drain port 0
        let mut out0 = [0u8; 128];
        let len0 = port0.drain_output(&mut out0);
        assert_eq!(len0, msg0.len());
        assert_eq!(&out0[..len0], msg0);
        
        // Drain port 1
        let mut out1 = [0u8; 128];
        let len1 = port1.drain_output(&mut out1);
        assert_eq!(len1, msg1.len());
        assert_eq!(&out1[..len1], msg1);
        
        // Verify empty
        assert_eq!(port0.drain_output(&mut out0), 0);
        assert_eq!(port1.drain_output(&mut out1), 0);
    }

    #[test]
    fn multi_port_console_input() {
        multi_port_console().clear_all();
        
        let port = multi_port_console().port(5).unwrap();
        
        // Push host input
        assert!(port.push_input(b'A'));
        assert!(port.push_input(b'B'));
        assert!(port.push_input(b'C'));
        
        // Pop guest reads
        assert_eq!(port.pop_input(), Some(b'A'));
        assert_eq!(port.pop_input(), Some(b'B'));
        assert_eq!(port.pop_input(), Some(b'C'));
        assert_eq!(port.pop_input(), None);
    }

    #[test]
    fn control_queue_network_commands() {
        // Test RX mode control
        let msg_rx = ControlQueueMsg::new(0, 0); // VIRTIO_NET_CTRL_RX
        let status = process_net_control_msg(&msg_rx, &[]);
        assert_eq!(status, 0); // OK
        
        // Test MAC control
        let msg_mac = ControlQueueMsg::new(1, 0); // VIRTIO_NET_CTRL_MAC
        let status = process_net_control_msg(&msg_mac, &[]);
        assert_eq!(status, 0); // OK
        
        // Test VLAN control
        let msg_vlan = ControlQueueMsg::new(2, 0); // VIRTIO_NET_CTRL_VLAN
        let status = process_net_control_msg(&msg_vlan, &[]);
        assert_eq!(status, 0); // OK
        
        // Test unsupported command
        let msg_invalid = ControlQueueMsg::new(99, 0);
        let status = process_net_control_msg(&msg_invalid, &[]);
        assert_eq!(status, 1); // ERROR
    }

    #[test]
    fn async_completion_ring_full() {
        async_completion_ring().clear();
        
        // Fill the ring (256 slots)
        for i in 0..256 {
            let comp = AsyncCompletion {
                id: i as u64,
                status: 0,
                result_len: 0,
                timestamp: i as u64,
            };
            assert!(async_completion_ring().push(comp));
        }
        
        // Ring should be full now
        let overflow = AsyncCompletion {
            id: 999,
            status: 0,
            result_len: 0,
            timestamp: 999,
        };
        assert!(!async_completion_ring().push(overflow)); // Should fail
        
        // Pop one and retry
        assert!(async_completion_ring().pop().is_some());
        assert!(async_completion_ring().push(overflow)); // Should succeed now
    }

    #[test]
    fn multi_port_console_boundary() {
        // Test port 0 (valid)
        assert!(multi_port_console().port(0).is_some());
        
        // Test port 15 (valid, last port)
        assert!(multi_port_console().port(15).is_some());
        
        // Test port 16 (invalid, out of bounds)
        assert!(multi_port_console().port(16).is_none());
        
        // Test port 100 (invalid)
        assert!(multi_port_console().port(100).is_none());
    }

    #[test]
    fn snapshot_state_save_restore() {
        virtio_direct().reset_backend();
        cpu_state().set_regs(MinimalRegs {
            rax: 1, rcx: 2, rdx: 3, rbx: 0,
            rsp: 4, rbp: 0, rsi: 0, rdi: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 5, rflags: 0,
            cs: 0, ds: 0, es: 0, ss: 0,
        });
        virtio_direct().net_model.restore_stats((11, 12, 13));
        virtio_direct().blk_model.restore_stats((21, 22, 23));
        snapshot_state().save();
        cpu_state().set_regs(MinimalRegs {
            rax: 8, rcx: 9, rdx: 10, rbx: 0,
            rsp: 11, rbp: 0, rsi: 0, rdi: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 12, rflags: 0,
            cs: 0, ds: 0, es: 0, ss: 0,
        });
        virtio_direct().net_model.restore_stats((1, 1, 1));
        virtio_direct().blk_model.restore_stats((2, 2, 2));
        assert!(snapshot_state().restore());
        let regs = cpu_state().regs();
        assert_eq!(regs.rax, 1);
        assert_eq!(regs.rcx, 2);
        assert_eq!(regs.rdx, 3);
        assert_eq!(regs.rsp, 4);
        assert_eq!(regs.rip, 5);
        let (net_rx, net_tx, net_len) = virtio_direct().net_model.stats();
        let (blk_read, blk_write, blk_len) = virtio_direct().blk_model.stats();
        assert_eq!(net_rx, 11);
        assert_eq!(net_tx, 12);
        assert_eq!(net_len, 13);
        assert_eq!(blk_read, 21);
        assert_eq!(blk_write, 22);
        assert_eq!(blk_len, 23);
    }

    #[test]
    fn telemetry_export_batch() {
        telemetry_clear();
        record_telemetry(TELEMETRY_BUDGET_EXCEEDED, 1);
        record_telemetry(TELEMETRY_STRESS_EPT, 2);
        let control = ControlPlane::new();
        let mut output = [0u8; 512];
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"telemetry.export\",\"max\":2}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"result\":["));
        assert!(response.contains("\"kind\":1"));
        assert!(response.contains("\"kind\":3"));
    }

    #[test]
    fn stress_soak_control_plane() {
        telemetry_clear();
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let len = control
            .handle_request(
                "{\"jsonrpc\":\"2.0\",\"id\":30,\"method\":\"stress.soak\",\"iterations\":64,\"cadence\":1}",
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"result\":"));
        assert!(telemetry_len() > 0);
    }

    #[test]
    fn hardware_signature_regression_check() {
        let signature = hardware_signature();
        let control = ControlPlane::new();
        let mut output = [0u8; 256];
        let len = control
            .handle_request(
                &format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":40,\"method\":\"regression.check\",\"expected\":{}}}",
                    signature
                ),
                &mut output,
            )
            .unwrap();
        let response = core::str::from_utf8(&output[..len]).unwrap();
        assert!(response.contains("\"result\":true"));
    }

    #[test]
    fn recovery_budget_threshold_behaves() {
        assert!(!recovery_budget_exhausted(MAX_FAULT_RECOVERIES - 1));
        assert!(recovery_budget_exhausted(MAX_FAULT_RECOVERIES));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Phase 2 Tests: Protocol Completeness
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn virtio_feature_negotiation() {
        let dev = VirtioDevice::new(1);
        
        // Set device features
        dev.set_device_features(VIRTIO_F_VERSION_1 | VIRTIO_NET_F_CSUM | VIRTIO_NET_F_HOST_TSO4);
        
        // Read device features
        let dev_feat_lo = dev.read_reg(0x010);
        let dev_feat_hi = dev.read_reg(0x014);
        assert_eq!(dev_feat_lo, 0x00000801); // CSUM(bit 0) + HOST_TSO4(bit 11)
        assert_eq!(dev_feat_hi, 0x00000001); // VERSION_1(bit 32)
        
        // Driver acknowledges features
        dev.write_reg(0x020, 0x00000801); // Accept CSUM + TSO4
        dev.write_reg(0x024, 0x00000001); // Accept VERSION_1
        
        // Verify negotiation
        assert!(dev.has_feature(VIRTIO_F_VERSION_1));
        assert!(dev.has_feature(VIRTIO_NET_F_CSUM));
        assert!(dev.has_feature(VIRTIO_NET_F_HOST_TSO4));
        assert!(!dev.has_feature(VIRTIO_NET_F_HOST_TSO6)); // Not negotiated
    }

    #[test]
    fn virtio_device_status_state_machine() {
        let dev = VirtioDevice::new(1);
        
        // Initial state: 0
        assert_eq!(dev.get_status(), 0);
        assert!(!dev.is_driver_ok());
        
        // ACKNOWLEDGE
        dev.set_status(VIRTIO_STATUS_ACKNOWLEDGE);
        assert_eq!(dev.get_status(), VIRTIO_STATUS_ACKNOWLEDGE);
        
        // DRIVER
        dev.set_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        assert_eq!(dev.get_status(), VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
        
        // FEATURES_OK
        dev.set_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);
        assert_eq!(dev.get_status() & VIRTIO_STATUS_FEATURES_OK, VIRTIO_STATUS_FEATURES_OK);
        
        // DRIVER_OK (device ready)
        dev.set_status(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
        assert!(dev.is_driver_ok());
        
        // Reset
        dev.set_status(0);
        assert_eq!(dev.get_status(), 0);
    }

    #[test]
    fn virtio_net_hdr_gso_tso_fields() {
        // Test TSO packet header
        let hdr = VirtNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 54,     // Eth(14) + IP(20) + TCP(20)
            gso_size: 1460,  // MSS (typical Ethernet MTU - headers)
            csum_start: 34,  // IP header end (where TCP checksum starts)
            csum_offset: 16, // TCP checksum field offset
            num_buffers: 0,
        };
        
        assert_eq!(hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(hdr.hdr_len, 54);
        assert_eq!(hdr.gso_size, 1460);
        assert_eq!(hdr.csum_start, 34);
        assert_eq!(hdr.csum_offset, 16);
    }

    #[test]
    fn virtio_net_hdr_checksum_offload() {
        // Test checksum offload request
        let hdr = VirtNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 34,
            csum_offset: 16,
            num_buffers: 0,
        };
        
        assert_eq!(hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_F_NEEDS_CSUM);
        assert_eq!(hdr.gso_type, VIRTIO_NET_HDR_GSO_NONE);
        
        // Test valid checksum indicator
        let hdr2 = VirtNetHdr {
            flags: VIRTIO_NET_HDR_F_DATA_VALID,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 0,
        };
        assert_eq!(hdr2.flags & VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_F_DATA_VALID);
    }

    #[test]
    fn block_sector_addressing_validation() {
        // Valid sector range
        assert!(validate_block_sector(0, 8));
        assert!(validate_block_sector(100, 16));
        assert!(validate_block_sector(1000000, 128));
        
        // Edge case: max valid sector
        assert!(validate_block_sector(u64::MAX >> 10, 1));
        
        // Invalid: overflow
        assert!(!validate_block_sector(u64::MAX - 10, 1000));
        assert!(!validate_block_sector(u64::MAX, 1));
    }

    #[test]
    fn block_request_flush_discard_handling() {
        let dma = DmaEngine::new();
        let _ = dma.map_region(0x0FF00, 0x100);
        
        // FLUSH request (no sector/data)
        let flush_req = VirtBlkRequest {
            req_type: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        };
        assert_eq!(flush_req.req_type, 4);
        
        // DISCARD request
        let discard_req = VirtBlkRequest {
            req_type: VIRTIO_BLK_T_DISCARD,
            reserved: 0,
            sector: 1024,
        };
        assert_eq!(discard_req.req_type, 11);
        assert_eq!(discard_req.sector, 1024);
        
        // Write status OK
        let status_gpa = 0x0FF00u64;
        assert!(dma.write_u8(status_gpa, VIRTIO_BLK_S_OK));
        assert_eq!(dma.read_u8(status_gpa), Some(VIRTIO_BLK_S_OK));
        
        // Write status UNSUPP
        assert!(dma.write_u8(status_gpa, VIRTIO_BLK_S_UNSUPP));
        assert_eq!(dma.read_u8(status_gpa), Some(VIRTIO_BLK_S_UNSUPP));
    }

    #[test]
    fn indirect_descriptor_table_processing() {
        let dma = DmaEngine::new();
        let _ = dma.map_region(0x01000, 0x1000);
        
        // Create indirect descriptor table at GPA 0x50000
        let table_gpa = 0x01000u64;
        
        // Write 3 descriptors in indirect table
        // Desc 0: addr=0x60000, len=1024, flags=0, next=1
        assert!(dma.write_u64(table_gpa, 0x60000));
        assert!(dma.write_u32(table_gpa + 8, 1024));
        assert!(dma.write_u16(table_gpa + 12, 0));
        assert!(dma.write_u16(table_gpa + 14, 1));
        
        // Desc 1: addr=0x61000, len=2048, flags=0, next=2
        assert!(dma.write_u64(table_gpa + 16, 0x61000));
        assert!(dma.write_u32(table_gpa + 24, 2048));
        assert!(dma.write_u16(table_gpa + 28, 0));
        assert!(dma.write_u16(table_gpa + 30, 2));
        
        // Desc 2: addr=0x62000, len=512, flags=0, next=0
        assert!(dma.write_u64(table_gpa + 32, 0x62000));
        assert!(dma.write_u32(table_gpa + 40, 512));
        assert!(dma.write_u16(table_gpa + 44, 0));
        assert!(dma.write_u16(table_gpa + 46, 0));
        
        // Read back via IndirectDescIter
        let mut iter = IndirectDescIter::new(&dma, table_gpa, 48);
        
        let desc0 = iter.next().unwrap();
        assert_eq!(desc0.gpa, 0x60000);
        assert_eq!(desc0.len, 1024);
        
        let desc1 = iter.next().unwrap();
        assert_eq!(desc1.gpa, 0x61000);
        assert_eq!(desc1.len, 2048);
        
        let desc2 = iter.next().unwrap();
        assert_eq!(desc2.gpa, 0x62000);
        assert_eq!(desc2.len, 512);
        
        assert!(iter.next().is_none());
    }

    #[test]
    fn used_ring_element_write() {
        let dma = DmaEngine::new();
        let used_base = 0x02000u64;
        let _ = dma.map_region(used_base, 0x1000);
        
        // Write used ring header (flags + idx)
        assert!(dma.write_u16(used_base, 0)); // flags
        assert!(dma.write_u16(used_base + 2, 0)); // idx
        
        // Write used element at index 0
        let elem = UsedElem { id: 42, len: 1500 };
        assert!(write_used_elem(&dma, used_base, 0, elem));
        
        // Read back
        let elem_addr = used_base + 4;
        assert_eq!(dma.read_u32(elem_addr), Some(42));
        assert_eq!(dma.read_u32(elem_addr + 4), Some(1500));
        
        // Write at index 1
        let elem2 = UsedElem { id: 99, len: 4096 };
        assert!(write_used_elem(&dma, used_base, 1, elem2));
        
        let elem2_addr = used_base + 4 + 8;
        assert_eq!(dma.read_u32(elem2_addr), Some(99));
        assert_eq!(dma.read_u32(elem2_addr + 4), Some(4096));
    }

    #[test]
    fn event_idx_optimization() {
        let dev = VirtioDevice::new(1);
        
        // Set event idx feature
        dev.set_device_features(VIRTIO_F_RING_EVENT_IDX);
        dev.write_reg(0x024, 1); // Accept feature (bit 29 -> bit 29-32 = 0 in high dword)
        
        // Set avail event idx
        dev.avail_event_idx.store(10, Ordering::Release);
        assert_eq!(dev.avail_event_idx.load(Ordering::Acquire), 10);
        
        // Set used event idx
        dev.used_event_idx.store(20, Ordering::Release);
        assert_eq!(dev.used_event_idx.load(Ordering::Acquire), 20);
    }

    #[test]
    fn interrupt_coalescing_threshold() {
        irq_coalescer().set_threshold(0);
        irq_coalescer().clear_pending();
        
        // Threshold 0 (disabled) - always deliver
        irq_coalescer().add_pending();
        assert!(irq_coalescer().should_deliver());
        irq_coalescer().clear_pending();
        
        // Set threshold to 4
        irq_coalescer().set_threshold(4);
        assert!(!irq_coalescer().should_deliver()); // 0 pending
        
        irq_coalescer().add_pending();
        irq_coalescer().add_pending();
        irq_coalescer().add_pending();
        assert!(!irq_coalescer().should_deliver()); // 3 pending < 4
        
        irq_coalescer().add_pending();
        assert!(irq_coalescer().should_deliver()); // 4 pending >= 4
        
        let cleared = irq_coalescer().clear_pending();
        assert_eq!(cleared, 4);
        assert!(!irq_coalescer().should_deliver());
    }

    #[test]
    fn interrupt_coalescing_disabled() {
        irq_coalescer().set_threshold(0); // Disable
        irq_coalescer().clear_pending();
        
        // Even 1 pending should trigger when disabled
        irq_coalescer().add_pending();
        assert!(irq_coalescer().should_deliver());
    }

    #[test]
    fn virtio_version_1_feature_bit() {
        let dev = VirtioDevice::new(1);
        dev.set_device_features(VIRTIO_F_VERSION_1);
        
        let hi = dev.read_reg(0x014);
        assert_eq!(hi, 1); // Bit 32 -> bit 0 of high dword
        
        dev.write_reg(0x024, 1);
        assert!(dev.has_feature(VIRTIO_F_VERSION_1));
    }

    #[test]
    fn virtio_indirect_desc_feature() {
        let dev = VirtioDevice::new(1);
        dev.set_device_features(VIRTIO_F_RING_INDIRECT_DESC);
        
        let lo = dev.read_reg(0x010);
        assert_eq!(lo & (1 << 28), 1 << 28); // Bit 28
        
        dev.write_reg(0x020, 1 << 28);
        assert!(dev.has_feature(VIRTIO_F_RING_INDIRECT_DESC));
    }

    #[test]
    fn virtio_status_failed_transition() {
        let dev = VirtioDevice::new(1);
        dev.set_status(VIRTIO_STATUS_ACKNOWLEDGE);
        
        // FAILED can be set from any state
        dev.set_status(VIRTIO_STATUS_FAILED);
        assert_eq!(dev.get_status(), VIRTIO_STATUS_FAILED);
    }

    #[test]
    fn block_request_type_constants() {
        assert_eq!(VIRTIO_BLK_T_IN, 0);
        assert_eq!(VIRTIO_BLK_T_OUT, 1);
        assert_eq!(VIRTIO_BLK_T_FLUSH, 4);
        assert_eq!(VIRTIO_BLK_T_DISCARD, 11);
    }
}
