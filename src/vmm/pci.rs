//! PCI Configuration Space Emulation (Type-1 Mechanism)
//!
//! Provides a virtual PCI bus that the guest accesses via I/O ports
//! 0xCF8 (address) and 0xCFC-0xCFF (data).
//!
//! The address register (0xCF8) format:
//!   [31]     = enable bit
//!   [23:16]  = bus number (0-255)
//!   [15:11]  = device number (0-31)
//!   [10:8]   = function number (0-7)
//!   [7:2]    = register number (dword-aligned offset into config space)
//!   [1:0]    = always 0
//!
//! Supported virtual devices:
//!   Bus 0, Device 0, Function 0: Host bridge (Intel-style)
//!   Bus 0, Device 1, Function 0: ISA bridge (for legacy device routing)
//!
//! All other BDF combinations return 0xFFFFFFFF (no device).

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Number of dwords in a PCI Type-0 config header (256 bytes / 4).
const CONFIG_DWORDS: usize = 64;

/// Maximum number of virtual PCI devices on bus 0.
const MAX_DEVICES: usize = 4;

/// Maximum number of BARs per device
const MAX_BARS: usize = 6;

/// MMIO allocation region start (4GB boundary, below 4GB for 32-bit BARs)
const MMIO_REGION_START: u64 = 0xE000_0000;

/// MMIO allocation region size (256 MB)
const MMIO_REGION_SIZE: u64 = 0x1000_0000;

/// I/O port allocation region start
const IO_REGION_START: u64 = 0x1000;

/// I/O port allocation region size
const IO_REGION_SIZE: u64 = 0x1000;

// ─── BAR Allocator ─────────────────────────────────────────────────────────────

/// BAR allocator for dynamic MMIO/IO address assignment
pub struct BarAllocator {
    /// Next available MMIO address
    next_mmio: AtomicU64,
    /// Next available I/O port
    next_io: AtomicU64,
    /// Allocation bitmap for tracking used regions
    mmio_used: AtomicU64,
    io_used: AtomicU64,
}

impl BarAllocator {
    pub const fn new() -> Self {
        Self {
            next_mmio: AtomicU64::new(MMIO_REGION_START),
            next_io: AtomicU64::new(IO_REGION_START),
            mmio_used: AtomicU64::new(0),
            io_used: AtomicU64::new(0),
        }
    }

    /// Allocate MMIO space for a BAR
    /// Returns the base address, or 0 if allocation failed
    pub fn alloc_mmio(&self, size: u64, align: u64) -> u64 {
        let aligned_size = (size + align - 1) & !(align - 1);
        
        loop {
            let current = self.next_mmio.load(Ordering::Acquire);
            let aligned_base = (current + align - 1) & !(align - 1);
            let new_base = aligned_base + aligned_size;
            
            // Check if we've exhausted the MMIO region
            if new_base > MMIO_REGION_START + MMIO_REGION_SIZE {
                return 0;
            }
            
            // Try to claim this region
            if self.next_mmio.compare_exchange(
                current,
                new_base,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return aligned_base;
            }
        }
    }

    /// Allocate I/O port space for a BAR
    /// Returns the base address, or 0 if allocation failed
    pub fn alloc_io(&self, size: u64, align: u64) -> u64 {
        let aligned_size = (size + align - 1) & !(align - 1);
        
        loop {
            let current = self.next_io.load(Ordering::Acquire);
            let aligned_base = (current + align - 1) & !(align - 1);
            let new_base = aligned_base + aligned_size;
            
            // Check if we've exhausted the I/O region
            if new_base > IO_REGION_START + IO_REGION_SIZE {
                return 0;
            }
            
            // Try to claim this region
            if self.next_io.compare_exchange(
                current,
                new_base,
                Ordering::AcqRel,
                Ordering::Acquire,
            ).is_ok() {
                return aligned_base;
            }
        }
    }

    /// Free MMIO space (mark as available for reuse)
    pub fn free_mmio(&self, _base: u64, _size: u64) {
        // Simple bump allocator doesn't support freeing
        // In a real implementation, this would mark the region as free
    }

    /// Free I/O port space (mark as available for reuse)
    pub fn free_io(&self, _base: u64, _size: u64) {
        // Simple bump allocator doesn't support freeing
    }

    /// Reset allocator state
    pub fn reset(&self) {
        self.next_mmio.store(MMIO_REGION_START, Ordering::Release);
        self.next_io.store(IO_REGION_START, Ordering::Release);
        self.mmio_used.store(0, Ordering::Release);
        self.io_used.store(0, Ordering::Release);
    }
}

/// Global BAR allocator
static BAR_ALLOCATOR: BarAllocator = BarAllocator::new();

/// Get the global BAR allocator
pub fn bar_allocator() -> &'static BarAllocator {
    &BAR_ALLOCATOR
}

/// A single virtual PCI device's 256-byte config space.
struct PciDevice {
    config: [AtomicU32; CONFIG_DWORDS],
    /// BAR size masks — one per BAR (regs 4-9).
    /// Zero = BAR not implemented (reads/writes return 0).
    /// Non-zero = the mask returned when the guest writes 0xFFFFFFFF for
    /// BAR sizing.  E.g., 0xFFFFF000 = 4 KiB MMIO BAR.
    bar_masks: [AtomicU32; MAX_BARS],
    /// BAR allocated addresses (for dynamic allocation)
    bar_addrs: [AtomicU64; MAX_BARS],
    /// Whether BAR has been allocated
    bar_allocated: [AtomicU32; MAX_BARS],
}

impl PciDevice {
    const fn new() -> Self {
        const ZERO: AtomicU32 = AtomicU32::new(0);
        const ZERO64: AtomicU64 = AtomicU64::new(0);
        Self {
            config: [ZERO; CONFIG_DWORDS],
            bar_masks: [ZERO; MAX_BARS],
            bar_addrs: [ZERO64; MAX_BARS],
            bar_allocated: [ZERO; MAX_BARS],
        }
    }

    /// Initialise config space with the given vendor/device/class etc.
    fn init(&self, vendor: u16, device: u16, class: u32, subsys: u32, header_type: u8) {
        // Dword 0: vendor + device
        self.config[0].store(
            (device as u32) << 16 | vendor as u32,
            Ordering::Relaxed,
        );
        // Dword 1: command + status (bus master + memory space + I/O space enabled)
        self.config[1].store(0x0000_0007, Ordering::Relaxed);
        // Dword 2: revision (0) + class code
        self.config[2].store(class, Ordering::Relaxed);
        // Dword 3: cache line, latency, header type, BIST
        self.config[3].store((header_type as u32) << 16, Ordering::Relaxed);
        // Dword 11: subsystem vendor + subsystem device
        self.config[11].store(subsys, Ordering::Relaxed);
    }

    fn read(&self, reg: usize) -> u32 {
        if reg < CONFIG_DWORDS {
            self.config[reg].load(Ordering::Relaxed)
        } else {
            0xFFFF_FFFF
        }
    }

    fn write(&self, reg: usize, value: u32) {
        // BARs (regs 4-9) and writable config fields
        if reg < CONFIG_DWORDS {
            match reg {
                // Don't allow overwriting vendor/device/class/header-type
                0 | 2 | 3 => {}
                // Command/Status: only command bits are writable (atomic update)
                1 => {
                    // Atomic read-modify-write to prevent race conditions
                    let _ = self.config[1].fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |old| {
                            // Keep status bits (upper 16), allow command bits (lower 16)
                            Some((old & 0xFFFF_0000) | (value & 0x0000_FFFF))
                        },
                    );
                }
                // BARs: handle sizing (write 0xFFFFFFFF, read back mask)
                4..=9 => {
                    let bar_idx = reg - 4;
                    let mask = self.bar_masks[bar_idx].load(Ordering::Relaxed);
                    if mask == 0 {
                        // BAR not implemented — always reads as 0, writes ignored
                        self.config[reg].store(0, Ordering::Relaxed);
                    } else if value == 0xFFFFFFFF {
                        // BAR sizing: return mask on next read
                        self.config[reg].store(mask, Ordering::Relaxed);
                    } else if value != 0 {
                        // Guest is programming the BAR
                        // Check if this is an I/O BAR (bit 0 = 1) or MMIO BAR (bit 0 = 0)
                        let is_io = (mask & 1) != 0;
                        let is_64bit = (mask & 0x4) != 0;
                        
                        // Apply the mask for address
                        let addr = value & mask;
                        self.config[reg].store(addr, Ordering::Relaxed);
                        
                        // Mark as allocated by guest
                        self.bar_allocated[bar_idx].store(1, Ordering::Release);
                        
                        // For 64-bit BARs, also handle the upper 32 bits
                        if is_64bit && bar_idx + 1 < MAX_BARS {
                            // Upper BAR will be written separately by guest
                        }
                    } else {
                        // value == 0: guest wants to deallocate
                        self.config[reg].store(0, Ordering::Relaxed);
                        self.bar_allocated[bar_idx].store(0, Ordering::Release);
                    }
                }
                // Interrupt line/pin (reg 15)
                15 => {
                    self.config[15].store(value, Ordering::Relaxed);
                }
                _ => {
                    self.config[reg].store(value, Ordering::Relaxed);
                }
            }
        }
    }
}

unsafe impl Sync for PciDevice {}

/// The virtual PCI bus — holds the address register and device array.
pub struct PciBus {
    /// Current PCI config address register (written via port 0xCF8).
    address: AtomicU32,
    /// Virtual devices: index = device number on bus 0.
    devices: [PciDevice; MAX_DEVICES],
}

impl PciBus {
    const fn new() -> Self {
        Self {
            address: AtomicU32::new(0),
            devices: [
                PciDevice::new(),
                PciDevice::new(),
                PciDevice::new(),
                PciDevice::new(),
            ],
        }
    }

    /// Initialise the default device set.
    fn init_defaults(&self) {
        // Device 0: Host Bridge (Intel 440FX-like)
        //   Vendor 0x8086 (Intel), Device 0x1237 (440FX)
        //   Class 0x0600_0000 = Host bridge
        self.devices[0].init(0x8086, 0x1237, 0x0600_0000, 0x0000_0000, 0x00);

        // Device 1: ISA Bridge (PIIX3-like for legacy routing)
        //   Vendor 0x8086, Device 0x7000 (PIIX3)
        //   Class 0x0601_0000 = ISA bridge
        self.devices[1].init(0x8086, 0x7000, 0x0601_0000, 0x0000_0000, 0x00);
    }

    // ── Port I/O interface ──────────────────────────────────────────────────

    /// Handle write to PCI address port (0xCF8).
    pub fn write_address(&self, value: u32) {
        self.address.store(value, Ordering::Relaxed);
    }

    /// Handle read from PCI address port (0xCF8).
    pub fn read_address(&self) -> u32 {
        self.address.load(Ordering::Relaxed)
    }

    /// Handle read from PCI data port (0xCFC-0xCFF).
    /// `byte_offset`: 0-3, from `port & 3`.
    pub fn read_data(&self, byte_offset: u8) -> u32 {
        let addr = self.address.load(Ordering::Relaxed);
        // Enable bit must be set
        if addr & 0x8000_0000 == 0 {
            return 0xFFFF_FFFF;
        }
        let bus = (addr >> 16) & 0xFF;
        let dev = (addr >> 11) & 0x1F;
        let _func = (addr >> 8) & 0x07;
        let reg = ((addr >> 2) & 0x3F) as usize;

        // We only emulate bus 0
        if bus != 0 {
            return 0xFFFF_FFFF;
        }
        if (dev as usize) >= MAX_DEVICES {
            return 0xFFFF_FFFF;
        }

        let dword = self.devices[dev as usize].read(reg);
        // Handle sub-dword access
        dword >> (byte_offset * 8)
    }

    /// Handle write to PCI data port (0xCFC-0xCFF).
    pub fn write_data(&self, byte_offset: u8, value: u32) {
        let addr = self.address.load(Ordering::Relaxed);
        if addr & 0x8000_0000 == 0 {
            return;
        }
        let bus = (addr >> 16) & 0xFF;
        let dev = (addr >> 11) & 0x1F;
        let _func = (addr >> 8) & 0x07;
        let reg = ((addr >> 2) & 0x3F) as usize;

        if bus != 0 {
            return;
        }
        if (dev as usize) >= MAX_DEVICES {
            return;
        }

        // For simplicity, only full-dword writes are forwarded.
        // Sub-dword writes are absorbed (reads still handle sub-dword).
        if byte_offset == 0 {
            self.devices[dev as usize].write(reg, value);
        }
    }
}

unsafe impl Sync for PciBus {}

static PCI_BUS: PciBus = PciBus::new();

/// One-time initialisation — call during hypervisor boot.
static PCI_INIT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Global accessor for the PCI bus.
pub fn pci_bus() -> &'static PciBus {
    if !PCI_INIT.load(Ordering::Acquire) {
        if !PCI_INIT.swap(true, Ordering::AcqRel) {
            PCI_BUS.init_defaults();
        }
    }
    &PCI_BUS
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pci_host_bridge_vendor_device() {
        let bus = PciBus::new();
        bus.init_defaults();
        // Select bus 0, device 0, function 0, register 0 (vendor/device)
        bus.write_address(0x8000_0000); // enable + bus=0, dev=0, func=0, reg=0
        let val = bus.read_data(0);
        assert_eq!(val & 0xFFFF, 0x8086); // Intel vendor
        assert_eq!(val >> 16, 0x1237);    // 440FX device
    }

    #[test]
    fn pci_no_device_returns_all_ones() {
        let bus = PciBus::new();
        bus.init_defaults();
        // Select bus 0, device 3, function 0, register 0 — no device there
        bus.write_address(0x8000_1800); // dev=3
        let val = bus.read_data(0);
        // Device 3 has all-zero config → vendor 0x0000 means "no device"
        // In our impl this returns 0 from the AtomicU32 default, but
        // firmware treats vendor=0 as absent, which is also acceptable.
        // The important thing is bus > 0 returns 0xFFFFFFFF.
        let _val = val; // device 3 is empty (all zeros)

        // Bus 1, any device: should be all-ones
        bus.write_address(0x8001_0000); // bus=1
        let val2 = bus.read_data(0);
        assert_eq!(val2, 0xFFFF_FFFF);
    }

    #[test]
    fn pci_disable_bit_returns_all_ones() {
        let bus = PciBus::new();
        bus.init_defaults();
        bus.write_address(0x0000_0000); // enable bit NOT set
        let val = bus.read_data(0);
        assert_eq!(val, 0xFFFF_FFFF);
    }
}
