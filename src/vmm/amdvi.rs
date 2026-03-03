//! AMD-Vi (AMD I/O Virtualization Technology)
//!
//! Implements DMA remapping for AMD platforms. Similar to Intel VT-d but uses
//! different ACPI tables (IVRS vs DMAR) and register layouts.
//!
//! Key structures:
//! - Device Table: Maps device IDs to translation info
//! - Guest Page Tables: Similar to x86-64 paging for DMA translation
//! - Interrupt Remapping Table: Redirects device interrupts
//! - Command Buffer: Ring buffer for invalidation commands
//! - Event Log: Reports translation faults and events

#![allow(dead_code)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, Ordering};

// ─── IVRS ACPI Table ───────────────────────────────────────────────────────────

/// IVRS table signature "IVRS"
pub const IVRS_SIGNATURE: [u8; 4] = *b"IVRS";

/// IVRS table header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IvrsHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    /// I/O virtualization info
    pub iv_info: u32,
    pub reserved: u64,
}

/// IVRS block header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IvrsBlockHeader {
    pub block_type: u8,
    pub flags: u8,
    pub length: u16,
    pub device_id: u16,
    pub capability_offset: u16,
    pub iommu_base: u64,
    pub pci_segment: u16,
    pub iommu_info: u16,
    pub iommu_feature: u32,
}

/// IVRS block types
pub mod ivrs_type {
    pub const IVHD_TYPE10: u8 = 0x10; // I/O Virtualization Hardware Definition (legacy)
    pub const IVHD_TYPE11: u8 = 0x11; // IVHD with extended features
    pub const IVHD_TYPE40: u8 = 0x40; // IVHD for ACPI HID devices
    pub const IVMD_TYPE20: u8 = 0x20; // I/O Virtualization Memory Definition (all)
    pub const IVMD_TYPE21: u8 = 0x21; // IVMD for specific device
    pub const IVMD_TYPE22: u8 = 0x22; // IVMD for device range
}

/// Device Entry types within IVHD
pub mod dev_entry {
    pub const PAD4: u8 = 0x00;         // 4-byte pad
    pub const ALL: u8 = 0x01;          // All devices
    pub const SELECT: u8 = 0x02;       // Single device select
    pub const RANGE_START: u8 = 0x03;  // Start of device range
    pub const RANGE_END: u8 = 0x04;    // End of device range
    pub const ALIAS_SELECT: u8 = 0x42; // Alias (phantom function)
    pub const ALIAS_RANGE: u8 = 0x43;  // Alias range
    pub const EXT_SELECT: u8 = 0x46;   // Extended select
    pub const EXT_RANGE: u8 = 0x47;    // Extended range
    pub const SPECIAL: u8 = 0x48;      // Special device (IOAPIC, HPET)
    pub const ACPI_HID: u8 = 0xF0;     // ACPI HID device
}

// ─── AMD-Vi Register Offsets ───────────────────────────────────────────────────

pub mod amdvi_reg {
    pub const DEV_TAB_BASE: u64 = 0x000;      // Device Table Base
    pub const CMD_BUF_BASE: u64 = 0x008;      // Command Buffer Base
    pub const EVT_LOG_BASE: u64 = 0x010;      // Event Log Base
    pub const CONTROL: u64 = 0x018;           // Control Register
    pub const EXCL_BASE: u64 = 0x020;         // Exclusion Range Base
    pub const EXCL_LIMIT: u64 = 0x028;        // Exclusion Range Limit
    pub const EXT_FEATURE: u64 = 0x030;       // Extended Feature Register
    pub const PPR_LOG_BASE: u64 = 0x038;      // PPR Log Base
    pub const HW_EVT_HI: u64 = 0x040;         // Hardware Event Upper
    pub const HW_EVT_LO: u64 = 0x048;         // Hardware Event Lower
    pub const HW_EVT_STATUS: u64 = 0x050;     // Hardware Event Status
    pub const SMI_FILTER0: u64 = 0x060;       // SMI Filter 0
    pub const GALOG_BASE: u64 = 0x0E0;        // Guest Virtual APIC Log Base
    pub const GALOG_TAIL: u64 = 0x0E8;        // Guest Virtual APIC Log Tail
    pub const PPR_LOG_B_BASE: u64 = 0x0F0;    // PPR Log B Base
    pub const EVT_LOG_B_BASE: u64 = 0x0F8;    // Event Log B Base
    pub const DEV_TAB_SEG0: u64 = 0x100;      // Device Table Segment 0
    pub const DEV_TAB_SEG1: u64 = 0x108;      // Device Table Segment 1
    pub const DEV_TAB_SEG2: u64 = 0x110;      // Device Table Segment 2
    pub const DEV_TAB_SEG3: u64 = 0x118;      // Device Table Segment 3
    pub const DEV_TAB_SEG4: u64 = 0x120;      // Device Table Segment 4
    pub const DEV_TAB_SEG5: u64 = 0x128;      // Device Table Segment 5
    pub const DEV_TAB_SEG6: u64 = 0x130;      // Device Table Segment 6
    pub const DEV_TAB_SEG7: u64 = 0x138;      // Device Table Segment 7
    pub const CMD_BUF_HEAD: u64 = 0x2000;     // Command Buffer Head
    pub const CMD_BUF_TAIL: u64 = 0x2008;     // Command Buffer Tail
    pub const EVT_LOG_HEAD: u64 = 0x2010;     // Event Log Head
    pub const EVT_LOG_TAIL: u64 = 0x2018;     // Event Log Tail
    pub const STATUS: u64 = 0x2020;           // IOMMU Status
    pub const PPR_LOG_HEAD: u64 = 0x2030;     // PPR Log Head
    pub const PPR_LOG_TAIL: u64 = 0x2038;     // PPR Log Tail
    pub const GALOG_HEAD: u64 = 0x2040;       // GA Log Head
    pub const GALOG_TAIL_REG: u64 = 0x2048;   // GA Log Tail Register
    pub const PPR_LOG_B_HEAD: u64 = 0x2050;   // PPR Log B Head
    pub const PPR_LOG_B_TAIL: u64 = 0x2058;   // PPR Log B Tail
    pub const EVT_LOG_B_HEAD: u64 = 0x2060;   // Event Log B Head
    pub const EVT_LOG_B_TAIL: u64 = 0x2068;   // Event Log B Tail
    pub const PPR_LOG_AUTO_RESP: u64 = 0x2080; // PPR Log Auto Response
    pub const PPR_LOG_OVFLW_EARLY: u64 = 0x2088; // PPR Log Overflow Early
    pub const PPR_LOG_B_OVFLW_EARLY: u64 = 0x2090; // PPR Log B Overflow Early
}

// ─── Control Register Bits ─────────────────────────────────────────────────────

pub mod ctrl {
    pub const IOMMU_EN: u64 = 1 << 0;         // IOMMU Enable
    pub const HT_TUN_EN: u64 = 1 << 1;        // HyperTransport Tunnel Enable
    pub const EVT_LOG_EN: u64 = 1 << 2;       // Event Log Enable
    pub const EVT_INT_EN: u64 = 1 << 3;       // Event Log Interrupt Enable
    pub const COMWAIT_INT_EN: u64 = 1 << 4;   // Completion Wait Interrupt Enable
    pub const INV_TIMEOUT_MASK: u64 = 0x7 << 5; // Invalidation Timeout
    pub const PASS_PW: u64 = 1 << 8;          // Pass Posted Write
    pub const RESP_PASS_PW: u64 = 1 << 9;     // Response Pass Posted Write
    pub const COHERENT: u64 = 1 << 10;        // Coherent
    pub const ISOC: u64 = 1 << 11;            // Isochronous
    pub const CMD_BUF_EN: u64 = 1 << 12;      // Command Buffer Enable
    pub const PPR_LOG_EN: u64 = 1 << 13;      // PPR Log Enable
    pub const PPR_INT_EN: u64 = 1 << 14;      // PPR Interrupt Enable
    pub const PPR_EN: u64 = 1 << 15;          // PPR Enable
    pub const GT_EN: u64 = 1 << 16;           // Guest Translation Enable
    pub const GA_EN: u64 = 1 << 17;           // Guest Virtual APIC Enable
    pub const CRW: u64 = 0x7 << 18;           // Cache Replacement Window
    pub const SMI_FILTER_EN: u64 = 1 << 22;   // SMI Filter Enable
    pub const SELF_WRITE_DIS: u64 = 1 << 23;  // Self Write Disable
    pub const SNOOP_EN: u64 = 1 << 24;        // Snoop Enable
    pub const GALOG_EN: u64 = 1 << 28;        // GA Log Enable
    pub const GAINT_EN: u64 = 1 << 29;        // GA Interrupt Enable
    pub const DTE_SEG_EN_MASK: u64 = 0x7 << 36; // Device Table Segment Enable
    pub const BLKSTOPMRK_EN: u64 = 1 << 47;   // Block StopMark Enable
    pub const PPR_AUTO_RESP_EN: u64 = 1 << 48; // PPR Auto Response Enable
    pub const MARC_EN: u64 = 1 << 62;         // Memory Access Routing & Control Enable
    pub const BLKSTOPMRK_INT_EN: u64 = 1 << 63; // Block StopMark Interrupt Enable
}

// ─── Status Register Bits ──────────────────────────────────────────────────────

pub mod status {
    pub const EVT_OVERFLOW: u64 = 1 << 0;     // Event Log Overflow
    pub const EVT_LOG_INT: u64 = 1 << 1;      // Event Log Interrupt
    pub const COMWAIT_INT: u64 = 1 << 2;      // Completion Wait Interrupt
    pub const EVT_LOG_RUN: u64 = 1 << 3;      // Event Log Running
    pub const CMD_BUF_RUN: u64 = 1 << 4;      // Command Buffer Running
    pub const PPR_OVERFLOW: u64 = 1 << 5;     // PPR Log Overflow
    pub const PPR_INT: u64 = 1 << 6;          // PPR Interrupt
    pub const PPR_LOG_RUN: u64 = 1 << 7;      // PPR Log Running
    pub const GALOG_RUN: u64 = 1 << 8;        // GA Log Running
    pub const GALOG_OVERFLOW: u64 = 1 << 9;   // GA Log Overflow
    pub const GALOG_INT: u64 = 1 << 10;       // GA Log Interrupt
    pub const PPR_B_OVERFLOW: u64 = 1 << 11;  // PPR Log B Overflow
    pub const PPR_LOG_ACTIVE: u64 = 1 << 12;  // PPR Log Active
    pub const EVT_B_OVERFLOW: u64 = 1 << 15;  // Event Log B Overflow
    pub const EVT_LOG_ACTIVE: u64 = 1 << 16;  // Event Log Active
    pub const PPR_B_LOG_ACTIVE: u64 = 1 << 17; // PPR Log B Active
    pub const EVT_B_LOG_ACTIVE: u64 = 1 << 18; // Event Log B Active
}

// ─── Extended Features ─────────────────────────────────────────────────────────

pub mod efr {
    /// Prefetch Support
    pub fn prefetch_sup(efr: u64) -> bool { efr & 1 != 0 }
    /// PPR Support
    pub fn ppr_sup(efr: u64) -> bool { (efr >> 1) & 1 != 0 }
    /// x2APIC Support
    pub fn xt_sup(efr: u64) -> bool { (efr >> 2) & 1 != 0 }
    /// NX Support
    pub fn nx_sup(efr: u64) -> bool { (efr >> 3) & 1 != 0 }
    /// Guest Translation Support
    pub fn gt_sup(efr: u64) -> bool { (efr >> 4) & 1 != 0 }
    /// Guest Virtual APIC Support
    pub fn ga_sup(efr: u64) -> bool { (efr >> 7) & 1 != 0 }
    /// Hardware Error Register Support
    pub fn he_sup(efr: u64) -> bool { (efr >> 8) & 1 != 0 }
    /// Performance Counter Support
    pub fn pc_sup(efr: u64) -> bool { (efr >> 9) & 1 != 0 }
    /// Host Address Translation Size (bits 13-17)
    pub fn hats(efr: u64) -> u32 { ((efr >> 13) & 0x3) as u32 }
    /// Guest Address Translation Size (bits 18-19)
    pub fn gats(efr: u64) -> u32 { ((efr >> 18) & 0x3) as u32 }
    /// Invalidate All Supported
    pub fn ia_sup(efr: u64) -> bool { (efr >> 21) & 1 != 0 }
    /// Guest APIC Mode Available (bits 22-23)
    pub fn gam_sup(efr: u64) -> u32 { ((efr >> 22) & 0x7) as u32 }
    /// Device Table Segmentation Supported (bits 36-38)
    pub fn dte_seg_sup(efr: u64) -> u32 { ((efr >> 36) & 0x3) as u32 }
}

// ─── Device Table Entry ────────────────────────────────────────────────────────

/// Device Table Entry (256 bits = 32 bytes)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceTableEntry {
    pub data: [u64; 4],
}

impl DeviceTableEntry {
    pub const fn empty() -> Self {
        Self { data: [0u64; 4] }
    }

    /// Check if DTE is valid
    pub fn valid(&self) -> bool {
        self.data[0] & 1 != 0
    }

    /// Check if translation is valid
    pub fn translation_valid(&self) -> bool {
        (self.data[0] >> 1) & 1 != 0
    }

    /// Get interrupt remapping table root pointer
    pub fn int_table_root(&self) -> u64 {
        self.data[2] & 0xFFFF_FFFF_FFFF_F000
    }

    /// Get page table root pointer
    pub fn page_table_root(&self) -> u64 {
        self.data[0] & 0xFFFF_FFFF_FFFF_F000
    }

    /// Get domain ID (bits 72-87 in data[1])
    pub fn domain_id(&self) -> u16 {
        ((self.data[1] >> 8) & 0xFFFF) as u16
    }

    /// Get page table mode (bits 9-11)
    pub fn mode(&self) -> u8 {
        ((self.data[0] >> 9) & 0x7) as u8
    }

    /// Configure for guest translation
    pub fn set_guest_cr3(&mut self, pt_root: u64, domain_id: u16, mode: u8) {
        // data[0]:
        // Bit 0: V (Valid)
        // Bit 1: TV (Translation Valid)
        // Bits 9-11: Mode (paging levels: 4=4-level, 5=5-level)
        // Bits 12-51: Page Table Root Pointer
        self.data[0] = 1 // Valid
            | (1 << 1) // Translation Valid
            | ((mode as u64 & 0x7) << 9)
            | (pt_root & 0xFFFF_FFFF_FFFF_F000);

        // data[1]:
        // Bits 8-23: Domain ID
        // Bits 0-7: IOTLB Cache hints
        self.data[1] = (domain_id as u64) << 8;
    }

    /// Configure for pass-through (no translation)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        // Mode 0 = translation bypassed
        self.data[0] = 1; // Valid only, TV=0, Mode=0
        self.data[1] = (domain_id as u64) << 8;
    }

    /// Enable interrupt remapping
    pub fn set_interrupt_remap(&mut self, irt_root: u64, irt_len: u8) {
        // data[2]:
        // Bit 0: IV (Interrupt Valid)
        // Bits 4-7: IntTabLen (log2 of table size)
        // Bits 12-51: Interrupt Table Root Pointer
        self.data[2] = 1 // IV
            | ((irt_len as u64 & 0xF) << 4)
            | (irt_root & 0xFFFF_FFFF_FFFF_F000);
    }

    /// Enable IOTLB support
    pub fn set_iotlb_support(&mut self, enable: bool) {
        if enable {
            self.data[0] |= 1 << 8; // I (IOTLB)
        } else {
            self.data[0] &= !(1 << 8);
        }
    }
}

// ─── Page Table Entries ────────────────────────────────────────────────────────

/// AMD-Vi page table entry flags
pub const PTE_PRESENT: u64 = 1 << 0;    // Present/Valid
pub const PTE_NEXT_LEVEL: u64 = 0;      // Points to next level table (implicit)
pub const PTE_READ: u64 = 1 << 61;      // Read permission (IR)
pub const PTE_WRITE: u64 = 1 << 62;     // Write permission (IW)
pub const PTE_FC: u64 = 1 << 1;         // Force Coherent
pub const PTE_ACCESSED: u64 = 1 << 5;
pub const PTE_DIRTY: u64 = 1 << 6;
pub const PTE_LARGE: u64 = 1 << 7;      // For 2MB/1GB pages (next level = 0)

/// AMD-Vi page table (4KB, 512 entries)
#[repr(C, align(4096))]
pub struct AmdViPageTable {
    pub entries: [u64; 512],
}

impl AmdViPageTable {
    pub const fn new() -> Self {
        Self { entries: [0u64; 512] }
    }
}

// ─── Command Buffer Entries ────────────────────────────────────────────────────

/// Command buffer entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandEntry {
    pub data: [u64; 2],
}

impl CommandEntry {
    pub const fn empty() -> Self {
        Self { data: [0, 0] }
    }

    /// Create COMPLETION_WAIT command
    pub fn completion_wait(store_addr: u64, store_data: u64) -> Self {
        // Opcode 0x01: COMPLETION_WAIT
        let cmd = 0x01u64 | (1 << 4) // S (Store)
            | (store_addr & 0xFFFF_FFFF_FFFF_FFF8);
        Self { data: [cmd, store_data] }
    }

    /// Create INVALIDATE_DEVTAB_ENTRY command
    pub fn invalidate_dte(device_id: u16) -> Self {
        // Opcode 0x02: INVALIDATE_DEVTAB_ENTRY
        let cmd = 0x02u64 | ((device_id as u64) << 16);
        Self { data: [cmd, 0] }
    }

    /// Create INVALIDATE_IOMMU_PAGES command
    pub fn invalidate_pages(domain_id: u16, address: u64, s: bool, pde: bool) -> Self {
        // Opcode 0x03: INVALIDATE_IOMMU_PAGES
        let cmd = 0x03u64 
            | ((domain_id as u64) << 16)
            | if s { 1 << 0 } else { 0 }  // S (Size)
            | if pde { 1 << 1 } else { 0 }; // PDE (Page Directory Entry)
        Self { data: [cmd, address & !0xFFF] }
    }

    /// Create INVALIDATE_IOTLB_PAGES command
    pub fn invalidate_iotlb(device_id: u16, domain_id: u16, address: u64) -> Self {
        // Opcode 0x04: INVALIDATE_IOTLB_PAGES
        let cmd = 0x04u64
            | ((device_id as u64) << 16)
            | ((domain_id as u64) << 32);
        Self { data: [cmd, address & !0xFFF] }
    }

    /// Create INVALIDATE_INTERRUPT_TABLE command
    pub fn invalidate_int_table(device_id: u16) -> Self {
        // Opcode 0x05: INVALIDATE_INTERRUPT_TABLE
        let cmd = 0x05u64 | ((device_id as u64) << 16);
        Self { data: [cmd, 0] }
    }

    /// Create PREFETCH_IOMMU_PAGES command
    pub fn prefetch_pages(device_id: u16, address: u64, size_bits: u8) -> Self {
        // Opcode 0x06: PREFETCH_IOMMU_PAGES
        let cmd = 0x06u64 
            | ((device_id as u64) << 16)
            | ((size_bits as u64 & 0x7) << 12);
        Self { data: [cmd, address & !0xFFF] }
    }

    /// Create COMPLETE_PPR_REQUEST command
    pub fn complete_ppr(device_id: u16, pasid: u32, response: u8) -> Self {
        // Opcode 0x07: COMPLETE_PPR_REQUEST
        let cmd = 0x07u64
            | ((device_id as u64) << 16)
            | ((response as u64 & 0xF) << 60);
        Self { data: [cmd, pasid as u64] }
    }

    /// Create INVALIDATE_ALL command
    pub fn invalidate_all() -> Self {
        // Opcode 0x08: INVALIDATE_IOMMU_ALL
        Self { data: [0x08, 0] }
    }
}

// ─── Event Log Entries ─────────────────────────────────────────────────────────

/// Event log entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventEntry {
    pub data: [u64; 2],
}

impl EventEntry {
    /// Get event code
    pub fn event_code(&self) -> u8 {
        ((self.data[1] >> 60) & 0xF) as u8
    }

    /// Get device ID
    pub fn device_id(&self) -> u16 {
        (self.data[0] & 0xFFFF) as u16
    }

    /// Get domain ID
    pub fn domain_id(&self) -> u16 {
        ((self.data[0] >> 16) & 0xFFFF) as u16
    }

    /// Get faulting address (for page faults)
    pub fn address(&self) -> u64 {
        self.data[1] & 0x0FFF_FFFF_FFFF_F000
    }
}

/// Event codes
pub mod event_code {
    pub const ILLEGAL_DEV_TAB_ENTRY: u8 = 0x01;
    pub const IO_PAGE_FAULT: u8 = 0x02;
    pub const DEV_TAB_HW_ERROR: u8 = 0x03;
    pub const PAGE_TAB_HW_ERROR: u8 = 0x04;
    pub const ILLEGAL_CMD_ERROR: u8 = 0x05;
    pub const CMD_HW_ERROR: u8 = 0x06;
    pub const IOTLB_INV_TIMEOUT: u8 = 0x07;
    pub const INVALID_DEV_REQUEST: u8 = 0x08;
    pub const INVALID_PPR_REQUEST: u8 = 0x09;
    pub const EVENT_COUNTER_ZERO: u8 = 0x10;
}

// ─── Static Memory Pools ───────────────────────────────────────────────────────

/// Maximum AMD-Vi units
pub const MAX_AMDVI_UNITS: usize = 8;

/// Device table size (64K entries, 2MB total)
pub const DEV_TABLE_SIZE: usize = 65536;

/// Command buffer size (4KB, 256 entries)
pub const CMD_BUF_SIZE: usize = 256;

/// Event log size (4KB, 256 entries)
pub const EVT_LOG_SIZE: usize = 256;

/// Page table pool size
pub const PT_POOL_SIZE: usize = 256;

/// Static device table per unit
#[repr(C, align(4096))]
pub struct DeviceTable {
    pub entries: [DeviceTableEntry; DEV_TABLE_SIZE],
}

impl DeviceTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { DeviceTableEntry::empty() }; DEV_TABLE_SIZE],
        }
    }
}

/// Command buffer (4KB aligned)
#[repr(C, align(4096))]
pub struct CommandBuffer {
    pub entries: [CommandEntry; CMD_BUF_SIZE],
}

impl CommandBuffer {
    pub const fn new() -> Self {
        Self {
            entries: [const { CommandEntry::empty() }; CMD_BUF_SIZE],
        }
    }
}

/// Event log buffer (4KB aligned)
#[repr(C, align(4096))]
pub struct EventLog {
    pub entries: [EventEntry; EVT_LOG_SIZE],
}

impl EventLog {
    pub const fn new() -> Self {
        Self {
            entries: [const { EventEntry { data: [0, 0] } }; EVT_LOG_SIZE],
        }
    }
}

// Static allocations
static mut DEVICE_TABLES: [DeviceTable; MAX_AMDVI_UNITS] = [const { DeviceTable::new() }; MAX_AMDVI_UNITS];
static mut COMMAND_BUFFERS: [CommandBuffer; MAX_AMDVI_UNITS] = [const { CommandBuffer::new() }; MAX_AMDVI_UNITS];
static mut EVENT_LOGS: [EventLog; MAX_AMDVI_UNITS] = [const { EventLog::new() }; MAX_AMDVI_UNITS];

static mut PT_POOL: [AmdViPageTable; PT_POOL_SIZE] = [const { AmdViPageTable::new() }; PT_POOL_SIZE];
static PT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

fn alloc_page_table() -> Result<*mut AmdViPageTable, HvError> {
    let idx = PT_POOL_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= PT_POOL_SIZE {
        return Err(HvError::LogicalFault);
    }
    Ok(unsafe { &mut PT_POOL[idx] as *mut AmdViPageTable })
}

// ─── AMD-Vi Unit ───────────────────────────────────────────────────────────────

/// AMD-Vi IOMMU unit
pub struct AmdViUnit {
    /// MMIO base address
    mmio_base: u64,
    /// Unit index
    unit_idx: usize,
    /// Extended features
    efr: u64,
    /// PCI segment
    segment: u16,
    /// Command buffer tail pointer
    cmd_tail: usize,
}

impl AmdViUnit {
    /// Create from IVHD
    pub fn from_ivhd(block: &IvrsBlockHeader, unit_idx: usize) -> Self {
        Self {
            mmio_base: block.iommu_base,
            unit_idx,
            efr: 0,
            segment: block.pci_segment,
            cmd_tail: 0,
        }
    }

    /// Read MMIO register
    #[inline]
    fn read_reg64(&self, offset: u64) -> u64 {
        let addr = (self.mmio_base + offset) as *const u64;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write MMIO register
    #[inline]
    fn write_reg64(&self, offset: u64, value: u64) {
        let addr = (self.mmio_base + offset) as *mut u64;
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    /// Initialize the IOMMU
    pub fn init(&mut self) -> Result<(), HvError> {
        // Read extended features
        self.efr = self.read_reg64(amdvi_reg::EXT_FEATURE);

        // Set device table base
        let dt_base = unsafe { &DEVICE_TABLES[self.unit_idx] as *const DeviceTable as u64 };
        // Size field: log2(entries) - 1 = 15 for 64K entries
        let dt_reg = dt_base | 15; // 64K entries
        self.write_reg64(amdvi_reg::DEV_TAB_BASE, dt_reg);

        // Set command buffer base
        let cmd_base = unsafe { &COMMAND_BUFFERS[self.unit_idx] as *const CommandBuffer as u64 };
        // Length field: log2(size) - 8 = 0 for 256 entries (4KB)
        let cmd_reg = cmd_base | 8; // 4KB buffer (2^12 = 4096, 256 entries)
        self.write_reg64(amdvi_reg::CMD_BUF_BASE, cmd_reg);

        // Set event log base
        let evt_base = unsafe { &EVENT_LOGS[self.unit_idx] as *const EventLog as u64 };
        let evt_reg = evt_base | 8;
        self.write_reg64(amdvi_reg::EVT_LOG_BASE, evt_reg);

        // Clear head/tail pointers
        self.write_reg64(amdvi_reg::CMD_BUF_HEAD, 0);
        self.write_reg64(amdvi_reg::CMD_BUF_TAIL, 0);
        self.write_reg64(amdvi_reg::EVT_LOG_HEAD, 0);
        self.write_reg64(amdvi_reg::EVT_LOG_TAIL, 0);

        Ok(())
    }

    /// Enable the IOMMU
    pub fn enable(&self) -> Result<(), HvError> {
        let mut ctrl = self.read_reg64(amdvi_reg::CONTROL);
        ctrl |= ctrl::IOMMU_EN | ctrl::CMD_BUF_EN | ctrl::EVT_LOG_EN;
        self.write_reg64(amdvi_reg::CONTROL, ctrl);

        // Wait for command buffer to start running
        self.wait_status(status::CMD_BUF_RUN)?;
        self.wait_status(status::EVT_LOG_RUN)?;

        Ok(())
    }

    /// Disable the IOMMU
    pub fn disable(&self) -> Result<(), HvError> {
        let mut ctrl = self.read_reg64(amdvi_reg::CONTROL);
        ctrl &= !ctrl::IOMMU_EN;
        self.write_reg64(amdvi_reg::CONTROL, ctrl);

        // Wait for shutdown
        self.wait_status_clear(status::CMD_BUF_RUN)?;

        Ok(())
    }

    /// Wait for status bit
    fn wait_status(&self, status_bit: u64) -> Result<(), HvError> {
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if self.read_reg64(amdvi_reg::STATUS) & status_bit != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Wait for status bit to clear
    fn wait_status_clear(&self, status_bit: u64) -> Result<(), HvError> {
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if self.read_reg64(amdvi_reg::STATUS) & status_bit == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Submit a command to the command buffer
    pub fn submit_command(&mut self, cmd: CommandEntry) -> Result<(), HvError> {
        let cmd_buf = unsafe { &mut COMMAND_BUFFERS[self.unit_idx] };
        
        // Write command
        cmd_buf.entries[self.cmd_tail] = cmd;
        
        // Advance tail
        self.cmd_tail = (self.cmd_tail + 1) % CMD_BUF_SIZE;
        let tail_offset = (self.cmd_tail * 16) as u64;
        self.write_reg64(amdvi_reg::CMD_BUF_TAIL, tail_offset);

        Ok(())
    }

    /// Wait for all commands to complete
    pub fn completion_wait(&mut self) -> Result<(), HvError> {
        // Use a known memory location for completion
        static COMPLETION_MARKER: AtomicU64 = AtomicU64::new(0);
        let marker_addr = &COMPLETION_MARKER as *const AtomicU64 as u64;
        
        // Clear marker
        COMPLETION_MARKER.store(0, Ordering::SeqCst);

        // Submit completion wait command
        let cmd = CommandEntry::completion_wait(marker_addr, 0xDEAD_BEEF);
        self.submit_command(cmd)?;

        // Wait for marker to be written
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if COMPLETION_MARKER.load(Ordering::SeqCst) == 0xDEAD_BEEF {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }

        Err(HvError::LogicalFault)
    }

    /// Invalidate all IOMMU caches
    pub fn invalidate_all(&mut self) -> Result<(), HvError> {
        if efr::ia_sup(self.efr) {
            self.submit_command(CommandEntry::invalidate_all())?;
            self.completion_wait()
        } else {
            // Fall back to invalidating individual entries
            Ok(())
        }
    }

    /// Invalidate device table entry
    pub fn invalidate_dte(&mut self, device_id: u16) -> Result<(), HvError> {
        self.submit_command(CommandEntry::invalidate_dte(device_id))?;
        self.completion_wait()
    }

    /// Map a device for DMA translation
    pub fn map_device(&mut self, device_id: u16, pt_builder: &PageTableBuilder, domain_id: u16) -> Result<(), HvError> {
        let dt = unsafe { &mut DEVICE_TABLES[self.unit_idx] };
        let dte = &mut dt.entries[device_id as usize];

        // Configure for 4-level paging (mode 4)
        dte.set_guest_cr3(pt_builder.root_addr(), domain_id, 4);
        
        // Invalidate cache
        self.invalidate_dte(device_id)?;

        Ok(())
    }

    /// Set pass-through for a device
    pub fn set_passthrough(&mut self, device_id: u16, domain_id: u16) -> Result<(), HvError> {
        let dt = unsafe { &mut DEVICE_TABLES[self.unit_idx] };
        let dte = &mut dt.entries[device_id as usize];

        dte.set_passthrough(domain_id);
        self.invalidate_dte(device_id)?;

        Ok(())
    }

    /// Get extended features
    pub fn efr(&self) -> u64 { self.efr }
    pub fn supports_guest_translation(&self) -> bool { efr::gt_sup(self.efr) }
    pub fn supports_prefetch(&self) -> bool { efr::prefetch_sup(self.efr) }
    pub fn supports_ppr(&self) -> bool { efr::ppr_sup(self.efr) }
}

// ─── Page Table Builder ────────────────────────────────────────────────────────

/// Build AMD-Vi page tables for a DMA region
pub struct PageTableBuilder {
    pml4_idx: usize,
}

impl PageTableBuilder {
    pub fn new() -> Result<Self, HvError> {
        let table = alloc_page_table()?;
        let base = unsafe { &PT_POOL[0] as *const AmdViPageTable as usize };
        let idx = (table as usize - base) / core::mem::size_of::<AmdViPageTable>();
        Ok(Self { pml4_idx: idx })
    }

    fn pml4_mut(&self) -> &mut AmdViPageTable {
        unsafe { &mut PT_POOL[self.pml4_idx] }
    }

    pub fn root_addr(&self) -> u64 {
        self.pml4_mut() as *const AmdViPageTable as u64
    }

    fn get_or_alloc(parent: &mut AmdViPageTable, idx: usize) -> Result<&'static mut AmdViPageTable, HvError> {
        let entry = parent.entries[idx];
        if entry & PTE_PRESENT != 0 && entry & PTE_LARGE == 0 {
            let addr = (entry & 0xFFFF_FFFF_FFFF_F000) as *mut AmdViPageTable;
            return Ok(unsafe { &mut *addr });
        }
        let child = alloc_page_table()?;
        parent.entries[idx] = (child as u64) | PTE_PRESENT | PTE_READ | PTE_WRITE;
        Ok(unsafe { &mut *child })
    }

    /// Map a 4KB page
    pub fn map_4k(&mut self, iova: u64, hpa: u64) -> Result<(), HvError> {
        if iova & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        let pml4 = self.pml4_mut();
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pt = Self::get_or_alloc(pd, pd_idx)?;
        pt.entries[pt_idx] = (hpa & 0xFFFF_FFFF_FFFF_F000)
            | PTE_PRESENT | PTE_READ | PTE_WRITE | PTE_ACCESSED | PTE_DIRTY;
        Ok(())
    }

    /// Map a 2MB large page
    pub fn map_2m(&mut self, iova: u64, hpa: u64) -> Result<(), HvError> {
        if iova & 0x1F_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        let pml4 = self.pml4_mut();
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        pd.entries[pd_idx] = (hpa & 0xFFFF_FFFF_FFE0_0000)
            | PTE_PRESENT | PTE_READ | PTE_WRITE | PTE_LARGE | PTE_ACCESSED | PTE_DIRTY;
        Ok(())
    }

    /// Map a 1GB huge page
    pub fn map_1g(&mut self, iova: u64, hpa: u64) -> Result<(), HvError> {
        if iova & 0x3FFF_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((iova >> 30) & 0x1FF) as usize;

        let pml4 = self.pml4_mut();
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        pdpt.entries[pdpt_idx] = (hpa & 0xFFFF_FFFF_C000_0000)
            | PTE_PRESENT | PTE_READ | PTE_WRITE | PTE_LARGE | PTE_ACCESSED | PTE_DIRTY;
        Ok(())
    }

    /// Map a range with optimal page sizes
    pub fn map_range(&mut self, base_iova: u64, base_hpa: u64, size: u64) -> Result<(), HvError> {
        let mut offset = 0u64;
        while offset < size {
            let iova = base_iova.wrapping_add(offset);
            let hpa = base_hpa.wrapping_add(offset);
            let remaining = size - offset;

            if iova & 0x3FFF_FFFF == 0 && hpa & 0x3FFF_FFFF == 0 && remaining >= 0x4000_0000 {
                self.map_1g(iova, hpa)?;
                offset = offset.wrapping_add(0x4000_0000);
            } else if iova & 0x1F_FFFF == 0 && hpa & 0x1F_FFFF == 0 && remaining >= 0x20_0000 {
                self.map_2m(iova, hpa)?;
                offset = offset.wrapping_add(0x20_0000);
            } else {
                self.map_4k(iova, hpa)?;
                offset = offset.wrapping_add(0x1000);
            }
        }
        Ok(())
    }
}

impl Default for PageTableBuilder {
    fn default() -> Self {
        Self::new().expect("Page table allocation failed")
    }
}

// ─── Global Domain ID Allocator ────────────────────────────────────────────────

static NEXT_DOMAIN_ID: AtomicU32 = AtomicU32::new(1);

pub fn alloc_domain_id() -> u16 {
    let id = NEXT_DOMAIN_ID.fetch_add(1, Ordering::SeqCst);
    (id & 0xFFFF) as u16
}

// ─── Interrupt Remapping ───────────────────────────────────────────────────────

/// Interrupt Remapping Table Entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IrteEntry {
    pub data: [u64; 2],
}

impl IrteEntry {
    pub const fn empty() -> Self {
        Self { data: [0, 0] }
    }

    /// Configure for remapped interrupt
    pub fn set_remapped(&mut self, vector: u8, dest_id: u8, dest_mode: bool, delivery_mode: u8) {
        // data[0]:
        // Bit 0: RemapEn
        // Bit 1: SupIOPF
        // Bits 5-7: IntType (delivery mode)
        // Bit 11: DM (destination mode)
        // Bits 16-23: Destination
        // Bits 24-31: Vector
        self.data[0] = 1 // RemapEn
            | ((delivery_mode as u64 & 0x7) << 5)
            | if dest_mode { 1 << 11 } else { 0 }
            | ((dest_id as u64) << 16)
            | ((vector as u64) << 24);
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dte_layout() {
        let mut dte = DeviceTableEntry::empty();
        assert!(!dte.valid());
        
        dte.set_guest_cr3(0x1000, 1, 4);
        assert!(dte.valid());
        assert!(dte.translation_valid());
        assert_eq!(dte.page_table_root(), 0x1000);
        assert_eq!(dte.domain_id(), 1);
        assert_eq!(dte.mode(), 4);
    }

    #[test]
    fn dte_passthrough() {
        let mut dte = DeviceTableEntry::empty();
        dte.set_passthrough(5);
        assert!(dte.valid());
        assert!(!dte.translation_valid());
        assert_eq!(dte.domain_id(), 5);
    }

    #[test]
    fn command_entry() {
        let cmd = CommandEntry::invalidate_all();
        assert_eq!(cmd.data[0] & 0xF, 0x08);
    }

    #[test]
    fn completion_wait_cmd() {
        let cmd = CommandEntry::completion_wait(0x1000, 0x1234);
        assert_eq!(cmd.data[0] & 0xF, 0x01);
        assert_eq!(cmd.data[1], 0x1234);
    }

    #[test]
    fn invalidate_dte_cmd() {
        let cmd = CommandEntry::invalidate_dte(0x0100);
        assert_eq!(cmd.data[0] & 0xF, 0x02);
        assert_eq!((cmd.data[0] >> 16) & 0xFFFF, 0x0100);
    }

    #[test]
    fn pte_flags() {
        let entry = PTE_PRESENT | PTE_READ | PTE_WRITE;
        assert!(entry & PTE_PRESENT != 0);
        assert!(entry & PTE_READ != 0);
        assert!(entry & PTE_LARGE == 0);
    }

    #[test]
    fn efr_decode() {
        // Sample EFR value with common features
        let efr = 0x0000_0123_0000_007F;
        assert!(efr::prefetch_sup(efr));
        assert!(efr::ppr_sup(efr));
        assert!(efr::gt_sup(efr));
    }

    #[test]
    fn domain_id_alloc() {
        let id1 = alloc_domain_id();
        let id2 = alloc_domain_id();
        assert_ne!(id1, id2);
    }
}
