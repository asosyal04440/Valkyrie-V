//! Intel VT-d (Virtualization Technology for Directed I/O)
//!
//! Implements DMA remapping for PCIe device passthrough.
//! Parses ACPI DMAR table and programs root/context tables.
//!
//! Key structures:
//! - Root Table: 4KB, indexed by bus number
//! - Context Table: 4KB per bus, indexed by device:function
//! - Second-Level Page Tables: Similar to EPT for DMA address translation
//! - Interrupt Remapping Table: Redirects MSI/MSI-X to guest vectors

#![allow(dead_code)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicUsize, Ordering};

// ─── DMAR ACPI Table ───────────────────────────────────────────────────────────

/// DMAR table signature "DMAR"
pub const DMAR_SIGNATURE: [u8; 4] = *b"DMAR";

/// DMAR table header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DmarHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    /// Host address width (N-1, so 48-bit = 47)
    pub host_addr_width: u8,
    pub flags: u8,
    pub reserved: [u8; 10],
}

/// DMAR remapping structure types
pub mod dmar_type {
    pub const DRHD: u16 = 0; // DMA Remapping Hardware Unit Definition
    pub const RMRR: u16 = 1; // Reserved Memory Region Reporting
    pub const ATSR: u16 = 2; // Root Port ATS Capability Reporting
    pub const RHSA: u16 = 3; // Remapping Hardware Static Affinity
    pub const ANDD: u16 = 4; // ACPI Name-space Device Declaration
    pub const SATC: u16 = 5; // SoC Integrated Address Translation Cache
}

/// DMAR remapping structure header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DmarStructHeader {
    pub struct_type: u16,
    pub length: u16,
}

/// DMA Remapping Hardware Unit Definition (DRHD)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Drhd {
    pub header: DmarStructHeader,
    pub flags: u8,
    pub reserved: u8,
    pub segment: u16,
    pub register_base: u64,
    // Followed by Device Scope structures
}

/// Device Scope structure
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct DeviceScope {
    pub scope_type: u8,
    pub length: u8,
    pub reserved: u16,
    pub enum_id: u8,
    pub start_bus: u8,
    // Followed by path entries (bus:device.function)
}

/// Device scope types
pub mod scope_type {
    pub const PCI_ENDPOINT: u8 = 1;
    pub const PCI_SUB_HIERARCHY: u8 = 2;
    pub const IOAPIC: u8 = 3;
    pub const HPET: u8 = 4;
    pub const ACPI_NAMESPACE: u8 = 5;
}

// ─── VT-d Register Offsets ─────────────────────────────────────────────────────

pub mod vtd_reg {
    pub const VER: u64 = 0x000;           // Version
    pub const CAP: u64 = 0x008;           // Capability
    pub const ECAP: u64 = 0x010;          // Extended Capability
    pub const GCMD: u64 = 0x018;          // Global Command
    pub const GSTS: u64 = 0x01C;          // Global Status
    pub const RTADDR: u64 = 0x020;        // Root Table Address
    pub const CCMD: u64 = 0x028;          // Context Command
    pub const FSTS: u64 = 0x034;          // Fault Status
    pub const FECTL: u64 = 0x038;         // Fault Event Control
    pub const FEDATA: u64 = 0x03C;        // Fault Event Data
    pub const FEADDR: u64 = 0x040;        // Fault Event Address
    pub const FEUADDR: u64 = 0x044;       // Fault Event Upper Address
    pub const AFLOG: u64 = 0x058;         // Advanced Fault Log
    pub const PMEN: u64 = 0x064;          // Protected Memory Enable
    pub const PLMBASE: u64 = 0x068;       // Protected Low Memory Base
    pub const PLMLIMIT: u64 = 0x06C;      // Protected Low Memory Limit
    pub const PHMBASE: u64 = 0x070;       // Protected High Memory Base
    pub const PHMLIMIT: u64 = 0x078;      // Protected High Memory Limit
    pub const IQH: u64 = 0x080;           // Invalidation Queue Head
    pub const IQT: u64 = 0x088;           // Invalidation Queue Tail
    pub const IQA: u64 = 0x090;           // Invalidation Queue Address
    pub const ICS: u64 = 0x09C;           // Invalidation Completion Status
    pub const IRTA: u64 = 0x0B8;          // Interrupt Remapping Table Address
    pub const PQH: u64 = 0x0C0;           // Page Request Queue Head
    pub const PQT: u64 = 0x0C8;           // Page Request Queue Tail
    pub const PQA: u64 = 0x0D0;           // Page Request Queue Address
    pub const PRS: u64 = 0x0DC;           // Page Request Status
    pub const PECTL: u64 = 0x0E0;         // Page Request Event Control
    pub const PEDATA: u64 = 0x0E4;        // Page Request Event Data
    pub const PEADDR: u64 = 0x0E8;        // Page Request Event Address
    pub const PEUADDR: u64 = 0x0EC;       // Page Request Event Upper Address
    pub const MTRRCAP: u64 = 0x100;       // MTRR Capability
    pub const MTRRDEF: u64 = 0x108;       // MTRR Default Type
}

// ─── VT-d Global Command/Status Bits ───────────────────────────────────────────

pub mod gcmd {
    pub const CFI: u32 = 1 << 23;         // Compatibility Format Interrupt
    pub const SIRTP: u32 = 1 << 24;       // Set Interrupt Remap Table Pointer
    pub const IRE: u32 = 1 << 25;         // Interrupt Remapping Enable
    pub const QIE: u32 = 1 << 26;         // Queued Invalidation Enable
    pub const WBF: u32 = 1 << 27;         // Write Buffer Flush
    pub const EAFL: u32 = 1 << 28;        // Enable Advanced Fault Logging
    pub const SFL: u32 = 1 << 29;         // Set Fault Log
    pub const SRTP: u32 = 1 << 30;        // Set Root Table Pointer
    pub const TE: u32 = 1 << 31;          // Translation Enable
}

pub mod gsts {
    pub const CFIS: u32 = 1 << 23;
    pub const IRTPS: u32 = 1 << 24;
    pub const IRES: u32 = 1 << 25;
    pub const QIES: u32 = 1 << 26;
    pub const WBFS: u32 = 1 << 27;
    pub const AFLS: u32 = 1 << 28;
    pub const FLS: u32 = 1 << 29;
    pub const RTPS: u32 = 1 << 30;
    pub const TES: u32 = 1 << 31;
}

// ─── VT-d Capability Bits ──────────────────────────────────────────────────────

pub mod cap {
    /// Number of domains supported (bits 0-2)
    pub fn nd(cap: u64) -> u32 { (cap & 0x7) as u32 }
    /// Required Write-Buffer Flushing
    pub fn rwbf(cap: u64) -> bool { (cap >> 4) & 1 != 0 }
    /// Protected Low-Memory Region
    pub fn plmr(cap: u64) -> bool { (cap >> 5) & 1 != 0 }
    /// Protected High-Memory Region
    pub fn phmr(cap: u64) -> bool { (cap >> 6) & 1 != 0 }
    /// Caching Mode
    pub fn cm(cap: u64) -> bool { (cap >> 7) & 1 != 0 }
    /// Supported Adjusted Guest Address Widths (bits 8-12)
    pub fn sagaw(cap: u64) -> u32 { ((cap >> 8) & 0x1F) as u32 }
    /// Maximum Guest Address Width (bits 16-21)
    pub fn mgaw(cap: u64) -> u32 { ((cap >> 16) & 0x3F) as u32 }
    /// Zero Length Read
    pub fn zlr(cap: u64) -> bool { (cap >> 22) & 1 != 0 }
    /// Fault-recording Register offset (bits 24-33)
    pub fn fro(cap: u64) -> u32 { ((cap >> 24) & 0x3FF) as u32 }
    /// Second Stage Large Page Support (bits 34-37)
    pub fn sslps(cap: u64) -> u32 { ((cap >> 34) & 0xF) as u32 }
    /// Page Selective Invalidation
    pub fn psi(cap: u64) -> bool { (cap >> 39) & 1 != 0 }
    /// Number of Fault-recording Registers (bits 40-47)
    pub fn nfr(cap: u64) -> u32 { ((cap >> 40) & 0xFF) as u32 }
    /// Max Address Mask Value (bits 48-53)
    pub fn mamv(cap: u64) -> u32 { ((cap >> 48) & 0x3F) as u32 }
    /// DMA Write Draining
    pub fn dwd(cap: u64) -> bool { (cap >> 54) & 1 != 0 }
    /// DMA Read Draining
    pub fn drd(cap: u64) -> bool { (cap >> 55) & 1 != 0 }
    /// First Stage 1GB Page Support
    pub fn fl1gp(cap: u64) -> bool { (cap >> 56) & 1 != 0 }
    /// Posted Interrupts Support
    pub fn pi(cap: u64) -> bool { (cap >> 59) & 1 != 0 }
    /// First Stage 5-level Paging Support
    pub fn fl5lp(cap: u64) -> bool { (cap >> 60) & 1 != 0 }
}

pub mod ecap {
    /// Coherency
    pub fn c(ecap: u64) -> bool { ecap & 1 != 0 }
    /// Queued Invalidation
    pub fn qi(ecap: u64) -> bool { (ecap >> 1) & 1 != 0 }
    /// Device-TLB
    pub fn dt(ecap: u64) -> bool { (ecap >> 2) & 1 != 0 }
    /// Interrupt Remapping
    pub fn ir(ecap: u64) -> bool { (ecap >> 3) & 1 != 0 }
    /// Extended Interrupt Mode
    pub fn eim(ecap: u64) -> bool { (ecap >> 4) & 1 != 0 }
    /// Caching Hints
    pub fn ch(ecap: u64) -> bool { (ecap >> 6) & 1 != 0 }
    /// Pass Through
    pub fn pt(ecap: u64) -> bool { (ecap >> 6) & 1 != 0 }
    /// Snoop Control
    pub fn sc(ecap: u64) -> bool { (ecap >> 7) & 1 != 0 }
    /// IOTLB Register Offset (bits 8-17)
    pub fn iro(ecap: u64) -> u32 { ((ecap >> 8) & 0x3FF) as u32 }
    /// Maximum Handle Mask Value (bits 20-23)
    pub fn mhmv(ecap: u64) -> u32 { ((ecap >> 20) & 0xF) as u32 }
    /// Nested Translation
    pub fn nest(ecap: u64) -> bool { (ecap >> 26) & 1 != 0 }
    /// Page Request
    pub fn prs(ecap: u64) -> bool { (ecap >> 29) & 1 != 0 }
    /// Execute Request
    pub fn ers(ecap: u64) -> bool { (ecap >> 30) & 1 != 0 }
    /// Supervisor Request
    pub fn srs(ecap: u64) -> bool { (ecap >> 31) & 1 != 0 }
    /// No Write Flag
    pub fn nwfs(ecap: u64) -> bool { (ecap >> 33) & 1 != 0 }
    /// Extended Accessed Flag
    pub fn eafs(ecap: u64) -> bool { (ecap >> 34) & 1 != 0 }
    /// Page-request Drain
    pub fn pds(ecap: u64) -> bool { (ecap >> 42) & 1 != 0 }
}

// ─── Root/Context Table Entries ────────────────────────────────────────────────

/// Root table entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RootEntry {
    pub lo: u64,
    pub hi: u64,
}

impl RootEntry {
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Check if entry is present
    pub fn present(&self) -> bool {
        self.lo & 1 != 0
    }

    /// Get context table pointer
    pub fn context_table(&self) -> u64 {
        self.lo & !0xFFF
    }

    /// Set context table pointer
    pub fn set_context_table(&mut self, addr: u64) {
        self.lo = (addr & !0xFFF) | 1; // Set present bit
    }
}

/// Context table entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ContextEntry {
    pub lo: u64,
    pub hi: u64,
}

impl ContextEntry {
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Check if entry is present
    pub fn present(&self) -> bool {
        self.lo & 1 != 0
    }

    /// Check if entry uses fault processing disable
    pub fn fpd(&self) -> bool {
        (self.lo >> 1) & 1 != 0
    }

    /// Get translation type (bits 2-3)
    pub fn translation_type(&self) -> u8 {
        ((self.lo >> 2) & 0x3) as u8
    }

    /// Get address width (bits 64-66 in hi)
    pub fn address_width(&self) -> u8 {
        (self.hi & 0x7) as u8
    }

    /// Get domain ID (bits 72-87 in hi)
    pub fn domain_id(&self) -> u16 {
        ((self.hi >> 8) & 0xFFFF) as u16
    }

    /// Get second-level page table pointer
    pub fn slpt_ptr(&self) -> u64 {
        self.lo & 0xFFFF_FFFF_FFFF_F000
    }

    /// Configure for second-level translation
    pub fn set_slpt(&mut self, slpt_addr: u64, domain_id: u16, addr_width: u8) {
        self.lo = (slpt_addr & !0xFFF) | 1; // Present
        self.hi = (addr_width as u64 & 0x7) | ((domain_id as u64) << 8);
    }

    /// Configure for pass-through (identity mapping)
    pub fn set_passthrough(&mut self, domain_id: u16) {
        // Translation type 2 = pass-through
        self.lo = (2 << 2) | 1; // Present + pass-through
        self.hi = ((domain_id as u64) << 8);
    }
}

// ─── Second-Level Page Tables ──────────────────────────────────────────────────

/// SLPT entry flags (similar to EPT)
pub const SLPT_READ: u64 = 1 << 0;
pub const SLPT_WRITE: u64 = 1 << 1;
pub const SLPT_EXECUTE: u64 = 1 << 2;  // Only with execute request support
pub const SLPT_ACCESSED: u64 = 1 << 8;
pub const SLPT_DIRTY: u64 = 1 << 9;
pub const SLPT_LARGE: u64 = 1 << 7;   // For 2MB/1GB pages
pub const SLPT_SNP: u64 = 1 << 11;    // Snoop control

/// Second-level page table (4KB, 512 entries)
#[repr(C, align(4096))]
pub struct SlptTable {
    pub entries: [u64; 512],
}

impl SlptTable {
    pub const fn new() -> Self {
        Self { entries: [0u64; 512] }
    }
}

// ─── VT-d Static Memory Pools ──────────────────────────────────────────────────

/// Maximum number of IOMMU units
pub const MAX_IOMMU_UNITS: usize = 8;

/// Root table (4KB, 256 entries for 256 buses)
#[repr(C, align(4096))]
pub struct RootTable {
    pub entries: [RootEntry; 256],
}

impl RootTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { RootEntry::empty() }; 256],
        }
    }
}

/// Context table (4KB, 256 entries for 32 devices * 8 functions)
#[repr(C, align(4096))]
pub struct ContextTable {
    pub entries: [ContextEntry; 256],
}

impl ContextTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { ContextEntry::empty() }; 256],
        }
    }
}

/// Maximum buses with context tables
pub const MAX_CONTEXT_TABLES: usize = 256;

/// SLPT pool size (256 pages)
pub const SLPT_POOL_SIZE: usize = 256;

/// Static root tables (one per IOMMU unit)
static mut ROOT_TABLES: [RootTable; MAX_IOMMU_UNITS] = [const { RootTable::new() }; MAX_IOMMU_UNITS];

/// Static context tables pool
static mut CONTEXT_TABLES: [ContextTable; MAX_CONTEXT_TABLES] = [const { ContextTable::new() }; MAX_CONTEXT_TABLES];
static CONTEXT_TABLE_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Static SLPT pool
static mut SLPT_POOL: [SlptTable; SLPT_POOL_SIZE] = [const { SlptTable::new() }; SLPT_POOL_SIZE];
static SLPT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

fn alloc_context_table() -> Result<*mut ContextTable, HvError> {
    let idx = CONTEXT_TABLE_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_CONTEXT_TABLES {
        return Err(HvError::LogicalFault);
    }
    Ok(unsafe { &mut CONTEXT_TABLES[idx] as *mut ContextTable })
}

fn alloc_slpt() -> Result<*mut SlptTable, HvError> {
    let idx = SLPT_POOL_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= SLPT_POOL_SIZE {
        return Err(HvError::LogicalFault);
    }
    Ok(unsafe { &mut SLPT_POOL[idx] as *mut SlptTable })
}

// ─── VT-d Unit ─────────────────────────────────────────────────────────────────

/// VT-d remapping unit
pub struct VtdUnit {
    /// MMIO register base
    reg_base: u64,
    /// Unit index
    unit_idx: usize,
    /// Capability register value
    cap: u64,
    /// Extended capability register value
    ecap: u64,
    /// Segment number
    segment: u16,
    /// Whether unit handles all devices
    include_all: bool,
}

impl VtdUnit {
    /// Create from DRHD structure
    pub fn from_drhd(drhd: &Drhd, unit_idx: usize) -> Self {
        Self {
            reg_base: drhd.register_base,
            unit_idx,
            cap: 0,
            ecap: 0,
            segment: drhd.segment,
            include_all: (drhd.flags & 1) != 0,
        }
    }

    /// Read VT-d register
    #[inline]
    fn read_reg32(&self, offset: u64) -> u32 {
        let addr = (self.reg_base + offset) as *const u32;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write VT-d register
    #[inline]
    fn write_reg32(&self, offset: u64, value: u32) {
        let addr = (self.reg_base + offset) as *mut u32;
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    /// Read 64-bit VT-d register
    #[inline]
    fn read_reg64(&self, offset: u64) -> u64 {
        let addr = (self.reg_base + offset) as *const u64;
        unsafe { core::ptr::read_volatile(addr) }
    }

    /// Write 64-bit VT-d register
    #[inline]
    fn write_reg64(&self, offset: u64, value: u64) {
        let addr = (self.reg_base + offset) as *mut u64;
        unsafe { core::ptr::write_volatile(addr, value) }
    }

    /// Initialize the VT-d unit
    pub fn init(&mut self) -> Result<(), HvError> {
        // Read capabilities
        self.cap = self.read_reg64(vtd_reg::CAP);
        self.ecap = self.read_reg64(vtd_reg::ECAP);

        // Check minimum requirements
        if cap::sagaw(self.cap) == 0 {
            return Err(HvError::HardwareFault);
        }

        // Set root table address
        let root_addr = unsafe { &ROOT_TABLES[self.unit_idx] as *const RootTable as u64 };
        self.write_reg64(vtd_reg::RTADDR, root_addr);

        // Issue set root table pointer command
        let mut gcmd = self.read_reg32(vtd_reg::GSTS);
        gcmd |= gcmd::SRTP;
        self.write_reg32(vtd_reg::GCMD, gcmd);

        // Wait for completion
        self.wait_status(gsts::RTPS)?;

        // Clear fault status
        self.write_reg32(vtd_reg::FSTS, 0xFFFF_FFFF);

        Ok(())
    }

    /// Wait for status bit to be set
    fn wait_status(&self, status_bit: u32) -> Result<(), HvError> {
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if self.read_reg32(vtd_reg::GSTS) & status_bit != 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Wait for status bit to be cleared
    fn wait_status_clear(&self, status_bit: u32) -> Result<(), HvError> {
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if self.read_reg32(vtd_reg::GSTS) & status_bit == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Enable DMA remapping
    pub fn enable(&self) -> Result<(), HvError> {
        let mut gcmd = self.read_reg32(vtd_reg::GSTS);
        gcmd |= gcmd::TE;
        self.write_reg32(vtd_reg::GCMD, gcmd);
        self.wait_status(gsts::TES)
    }

    /// Disable DMA remapping
    pub fn disable(&self) -> Result<(), HvError> {
        let mut gcmd = self.read_reg32(vtd_reg::GSTS);
        gcmd &= !gcmd::TE;
        self.write_reg32(vtd_reg::GCMD, gcmd);
        self.wait_status_clear(gsts::TES)
    }

    /// Flush write buffer if required
    pub fn flush_write_buffer(&self) -> Result<(), HvError> {
        if !cap::rwbf(self.cap) {
            return Ok(());
        }
        let mut gcmd = self.read_reg32(vtd_reg::GSTS);
        gcmd |= gcmd::WBF;
        self.write_reg32(vtd_reg::GCMD, gcmd);
        self.wait_status_clear(gsts::WBFS)
    }

    /// Invalidate context cache globally
    pub fn invalidate_context_global(&self) -> Result<(), HvError> {
        // Context command: global invalidation
        let ccmd: u64 = (1u64 << 63) | (1u64 << 61); // ICC + Global granularity
        self.write_reg64(vtd_reg::CCMD, ccmd);

        // Wait for completion
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            if self.read_reg64(vtd_reg::CCMD) & (1u64 << 63) == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Invalidate IOTLB globally
    pub fn invalidate_iotlb_global(&self) -> Result<(), HvError> {
        let iro = ecap::iro(self.ecap) as u64;
        let iotlb_reg = self.reg_base + (iro << 4) + 8;

        // IOTLB command: global invalidation, drain reads/writes
        let cmd: u64 = (1u64 << 63) | (1u64 << 60); // IVT + Global granularity
        let addr = iotlb_reg as *mut u64;
        unsafe { core::ptr::write_volatile(addr, cmd) };

        // Wait for completion
        let mut timeout = 1_000_000u32;
        while timeout > 0 {
            let val = unsafe { core::ptr::read_volatile(addr) };
            if val & (1u64 << 63) == 0 {
                return Ok(());
            }
            timeout -= 1;
            core::hint::spin_loop();
        }
        Err(HvError::LogicalFault)
    }

    /// Map a device for DMA remapping
    pub fn map_device(&mut self, bus: u8, dev: u8, func: u8, slpt: &SlptTable, domain_id: u16) -> Result<(), HvError> {
        let root_table = unsafe { &mut ROOT_TABLES[self.unit_idx] };
        let root_entry = &mut root_table.entries[bus as usize];

        // Allocate context table if needed
        if !root_entry.present() {
            let ctx_table = alloc_context_table()?;
            root_entry.set_context_table(ctx_table as u64);
        }

        // Get context table
        let ctx_addr = root_entry.context_table() as *mut ContextTable;
        let ctx_table = unsafe { &mut *ctx_addr };

        // Context entry index = (device * 8) + function
        let ctx_idx = ((dev as usize) << 3) | (func as usize);
        let ctx_entry = &mut ctx_table.entries[ctx_idx];

        // Set up second-level page table
        let slpt_addr = slpt as *const SlptTable as u64;
        // Address width: 48-bit = 2 (AGAW 48-bit = value 2)
        ctx_entry.set_slpt(slpt_addr, domain_id, 2);

        // Invalidate caches
        self.invalidate_context_global()?;
        self.invalidate_iotlb_global()?;
        self.flush_write_buffer()?;

        Ok(())
    }

    /// Set up pass-through for a device (identity mapping)
    pub fn set_passthrough(&mut self, bus: u8, dev: u8, func: u8, domain_id: u16) -> Result<(), HvError> {
        let root_table = unsafe { &mut ROOT_TABLES[self.unit_idx] };
        let root_entry = &mut root_table.entries[bus as usize];

        if !root_entry.present() {
            let ctx_table = alloc_context_table()?;
            root_entry.set_context_table(ctx_table as u64);
        }

        let ctx_addr = root_entry.context_table() as *mut ContextTable;
        let ctx_table = unsafe { &mut *ctx_addr };

        let ctx_idx = ((dev as usize) << 3) | (func as usize);
        ctx_table.entries[ctx_idx].set_passthrough(domain_id);

        self.invalidate_context_global()?;
        self.invalidate_iotlb_global()?;
        self.flush_write_buffer()?;

        Ok(())
    }

    /// Get unit capabilities
    pub fn cap(&self) -> u64 { self.cap }
    pub fn ecap(&self) -> u64 { self.ecap }
    pub fn supports_queued_invalidation(&self) -> bool { ecap::qi(self.ecap) }
    pub fn supports_interrupt_remapping(&self) -> bool { ecap::ir(self.ecap) }
}

// ─── SLPT Builder ──────────────────────────────────────────────────────────────

/// Build SLPT for a DMA memory region
pub struct SlptBuilder {
    pml4_idx: usize,
}

impl SlptBuilder {
    pub fn new() -> Result<Self, HvError> {
        let table = alloc_slpt()?;
        let base = unsafe { &SLPT_POOL[0] as *const SlptTable as usize };
        let idx = (table as usize - base) / core::mem::size_of::<SlptTable>();
        Ok(Self { pml4_idx: idx })
    }

    fn pml4_mut(&self) -> &mut SlptTable {
        unsafe { &mut SLPT_POOL[self.pml4_idx] }
    }

    /// Get root table physical address
    pub fn root_addr(&self) -> u64 {
        self.pml4_mut() as *const SlptTable as u64
    }

    fn get_or_alloc(parent: &mut SlptTable, idx: usize) -> Result<&'static mut SlptTable, HvError> {
        let entry = parent.entries[idx];
        if entry & SLPT_READ != 0 && entry & SLPT_LARGE == 0 {
            let addr = (entry & 0xFFFF_FFFF_FFFF_F000) as *mut SlptTable;
            return Ok(unsafe { &mut *addr });
        }
        let child = alloc_slpt()?;
        parent.entries[idx] = (child as u64) | SLPT_READ | SLPT_WRITE;
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
            | SLPT_READ | SLPT_WRITE | SLPT_ACCESSED | SLPT_DIRTY;
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
            | SLPT_READ | SLPT_WRITE | SLPT_LARGE | SLPT_ACCESSED | SLPT_DIRTY;
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
            | SLPT_READ | SLPT_WRITE | SLPT_LARGE | SLPT_ACCESSED | SLPT_DIRTY;
        Ok(())
    }

    /// Map a range using optimal page sizes
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

impl Default for SlptBuilder {
    fn default() -> Self {
        Self::new().expect("SLPT allocation failed")
    }
}

// ─── Interrupt Remapping ───────────────────────────────────────────────────────

/// Interrupt Remapping Table Entry (128 bits)
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IrteEntry {
    pub lo: u64,
    pub hi: u64,
}

impl IrteEntry {
    pub const fn empty() -> Self {
        Self { lo: 0, hi: 0 }
    }

    /// Check if entry is present
    pub fn present(&self) -> bool {
        self.lo & 1 != 0
    }

    /// Configure for remapped interrupt
    pub fn set_remapped(&mut self, vector: u8, dest_id: u32, trigger_mode: bool, delivery_mode: u8) {
        // Bits 0: Present
        // Bits 1: FPD (Fault Processing Disable)
        // Bits 4-7: Destination Mode (0=physical, 1=logical)
        // Bits 8-10: Redirection Hint
        // Bits 11-14: Trigger Mode
        // Bits 16-23: Vector
        // Bits 32-63: Destination ID
        self.lo = 1 // Present
            | ((delivery_mode as u64 & 0x7) << 5)
            | if trigger_mode { 1 << 4 } else { 0 }
            | ((vector as u64) << 16);
        self.hi = dest_id as u64;
    }
}

/// Maximum entries in interrupt remapping table (64K entries)
pub const MAX_IRTE_ENTRIES: usize = 256;

/// Static interrupt remapping table
#[repr(C, align(4096))]
pub struct InterruptRemappingTable {
    pub entries: [IrteEntry; MAX_IRTE_ENTRIES],
}

impl InterruptRemappingTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { IrteEntry::empty() }; MAX_IRTE_ENTRIES],
        }
    }
}

static mut IRTE: InterruptRemappingTable = InterruptRemappingTable::new();
static IRTE_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Allocate an IRTE entry
pub fn alloc_irte_entry() -> Result<usize, HvError> {
    let idx = IRTE_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= MAX_IRTE_ENTRIES {
        return Err(HvError::LogicalFault);
    }
    Ok(idx)
}

/// Enable interrupt remapping on a VT-d unit
pub fn enable_interrupt_remapping(unit: &mut VtdUnit) -> Result<(), HvError> {
    if !unit.supports_interrupt_remapping() {
        return Err(HvError::HardwareFault);
    }

    // Set IRTA (Interrupt Remapping Table Address)
    let irte_addr = unsafe { &IRTE as *const InterruptRemappingTable as u64 };
    // Size = log2(entries) - 1 = log2(256) - 1 = 7
    let irta_val = irte_addr | 7; // 256 entries
    unit.write_reg64(vtd_reg::IRTA, irta_val);

    // Set interrupt remapping table pointer
    let mut gcmd = unit.read_reg32(vtd_reg::GSTS);
    gcmd |= gcmd::SIRTP;
    unit.write_reg32(vtd_reg::GCMD, gcmd);
    unit.wait_status(gsts::IRTPS)?;

    // Enable interrupt remapping
    gcmd |= gcmd::IRE;
    unit.write_reg32(vtd_reg::GCMD, gcmd);
    unit.wait_status(gsts::IRES)?;

    Ok(())
}

// ─── Global VT-d Manager ───────────────────────────────────────────────────────

/// Maximum detected IOMMU units
static IOMMU_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Domain ID allocator
static NEXT_DOMAIN_ID: AtomicU32 = AtomicU32::new(1);

/// Allocate a domain ID
pub fn alloc_domain_id() -> u16 {
    let id = NEXT_DOMAIN_ID.fetch_add(1, Ordering::SeqCst);
    (id & 0xFFFF) as u16
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_entry_layout() {
        let mut re = RootEntry::empty();
        assert!(!re.present());
        re.set_context_table(0x1000);
        assert!(re.present());
        assert_eq!(re.context_table(), 0x1000);
    }

    #[test]
    fn context_entry_layout() {
        let mut ce = ContextEntry::empty();
        assert!(!ce.present());
        ce.set_slpt(0x2000, 1, 2);
        assert!(ce.present());
        assert_eq!(ce.slpt_ptr(), 0x2000);
        assert_eq!(ce.domain_id(), 1);
        assert_eq!(ce.address_width(), 2);
    }

    #[test]
    fn context_entry_passthrough() {
        let mut ce = ContextEntry::empty();
        ce.set_passthrough(5);
        assert!(ce.present());
        assert_eq!(ce.translation_type(), 2);
        assert_eq!(ce.domain_id(), 5);
    }

    #[test]
    fn cap_decode() {
        // Sample capability value
        let cap = 0x00C0_0065_0046_2F6E;
        assert!(cap::sagaw(cap) > 0);
        assert!(cap::mgaw(cap) > 0);
    }

    #[test]
    fn ecap_decode() {
        // Sample extended capability
        let ecap: u64 = 0x0000_0050_0000_0000;
        // These are hardware-dependent
    }

    #[test]
    fn slpt_flags() {
        let entry = SLPT_READ | SLPT_WRITE | SLPT_ACCESSED;
        assert!(entry & SLPT_READ != 0);
        assert!(entry & SLPT_WRITE != 0);
        assert!(entry & SLPT_EXECUTE == 0);
    }

    #[test]
    fn irte_entry_layout() {
        let mut irte = IrteEntry::empty();
        assert!(!irte.present());
        irte.set_remapped(0x30, 0, false, 0);
        assert!(irte.present());
    }

    #[test]
    fn domain_id_allocation() {
        let id1 = alloc_domain_id();
        let id2 = alloc_domain_id();
        assert_ne!(id1, id2);
    }
}
