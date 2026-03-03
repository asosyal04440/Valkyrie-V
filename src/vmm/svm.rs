//! AMD Secure Virtual Machine (SVM) Implementation
//!
//! Provides AMD-V (SVM) virtualization support as an alternative to Intel VT-x.
//! AMD SVM uses VMCB (Virtual Machine Control Block) instead of Intel's VMCS.
//!
//! Key differences from Intel VMX:
//! - VMCB is a single 4KB page (vs VMCS which requires separate regions)
//! - VMRUN/VMEXIT instead of VMLAUNCH/VMRESUME/VM-Exit
//! - NPT (Nested Page Tables) instead of EPT
//! - Different MSR addresses and exit codes
//!
//! Reference: AMD64 Architecture Programmer's Manual Volume 2: System Programming

#![allow(dead_code)]
#![allow(clippy::fn_to_numeric_cast)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ─── MSR Indices ───────────────────────────────────────────────────────────────

/// VM_CR MSR - controls SVM enable
pub const MSR_VM_CR: u32 = 0xC001_0114;
/// VM_HSAVE_PA MSR - host save area physical address
pub const MSR_VM_HSAVE_PA: u32 = 0xC001_0117;
/// SVM features MSR
pub const MSR_SVM_FEATURES: u32 = 0xC000_000A;
/// EFER MSR (Extended Feature Enable Register)
pub const MSR_EFER: u32 = 0xC000_0080;

// EFER bits
pub const EFER_SVME: u64 = 1 << 12; // SVM Enable

// VM_CR bits
pub const VM_CR_DPD: u64 = 1 << 0;  // Debug port disable
pub const VM_CR_R_INIT: u64 = 1 << 1; // Intercept INIT
pub const VM_CR_DIS_A20M: u64 = 1 << 2; // Disable A20 masking
pub const VM_CR_LOCK: u64 = 1 << 3;  // SVM lock
pub const VM_CR_SVMDIS: u64 = 1 << 4; // SVM disable

// ─── VMCB Offsets ──────────────────────────────────────────────────────────────

/// VMCB Control Area (offset 0x000 - 0x3FF)
pub mod vmcb_ctrl {
    pub const CR_RD_INTERCEPTS: usize = 0x000;   // CR read intercepts (16 bits)
    pub const CR_WR_INTERCEPTS: usize = 0x002;   // CR write intercepts (16 bits)
    pub const DR_RD_INTERCEPTS: usize = 0x004;   // DR read intercepts (16 bits)
    pub const DR_WR_INTERCEPTS: usize = 0x006;   // DR write intercepts (16 bits)
    pub const EXCEPTION_INTERCEPTS: usize = 0x008; // Exception intercepts (32 bits)
    pub const GENERAL_1_INTERCEPTS: usize = 0x00C; // Misc intercepts (32 bits)
    pub const GENERAL_2_INTERCEPTS: usize = 0x010; // More intercepts (32 bits)
    pub const PAUSE_FILTER_THRESH: usize = 0x03C; // PAUSE filter threshold
    pub const PAUSE_FILTER_COUNT: usize = 0x03E;  // PAUSE filter count
    pub const IOPM_BASE_PA: usize = 0x040;        // I/O permission map base
    pub const MSRPM_BASE_PA: usize = 0x048;       // MSR permission map base
    pub const TSC_OFFSET: usize = 0x050;          // TSC offset
    pub const GUEST_ASID: usize = 0x058;          // Guest ASID
    pub const TLB_CONTROL: usize = 0x05C;         // TLB control
    pub const V_TPR: usize = 0x060;               // Virtual TPR
    pub const V_IRQ: usize = 0x061;               // Virtual IRQ
    pub const V_INTR_PRIO: usize = 0x062;         // Virtual interrupt priority
    pub const V_IGN_TPR: usize = 0x063;           // V_IGN_TPR
    pub const V_INTR_MASKING: usize = 0x064;      // Virtual interrupt masking
    pub const V_INTR_VECTOR: usize = 0x065;       // Virtual interrupt vector
    pub const INTERRUPT_SHADOW: usize = 0x068;    // Interrupt shadow
    pub const EXIT_CODE: usize = 0x070;           // Exit code
    pub const EXIT_INFO_1: usize = 0x078;         // Exit info 1
    pub const EXIT_INFO_2: usize = 0x080;         // Exit info 2
    pub const EXIT_INT_INFO: usize = 0x088;       // Exit interrupt info
    pub const NP_ENABLE: usize = 0x090;           // Nested paging enable
    pub const AVIC_APIC_BAR: usize = 0x098;       // AVIC APIC BAR
    pub const GHCB_PA: usize = 0x0A0;             // GHCB physical address
    pub const EVENT_INJ: usize = 0x0A8;           // Event injection
    pub const N_CR3: usize = 0x0B0;               // Nested CR3 (NPT root)
    pub const LBR_VIRT_ENABLE: usize = 0x0B8;     // LBR virtualization enable
    pub const VMCB_CLEAN: usize = 0x0C0;          // VMCB clean bits
    pub const NRIP: usize = 0x0C8;                // Next RIP (for instruction decode)
    pub const NUM_BYTES_FETCHED: usize = 0x0D0;   // Number of bytes fetched
    pub const GUEST_INSTR_BYTES: usize = 0x0D1;   // Guest instruction bytes (15 bytes)
    pub const AVIC_APIC_BACKING_PAGE: usize = 0x0E0;
    pub const AVIC_LOGICAL_TABLE: usize = 0x0F0;
    pub const AVIC_PHYSICAL_TABLE: usize = 0x0F8;
    pub const VMSA_PTR: usize = 0x108;            // SEV-ES VMSA pointer
    pub const VMGEXIT_RSVD: usize = 0x110;        // Reserved for VMGEXIT
}

/// VMCB State Save Area (offset 0x400 - 0xFFF)
pub mod vmcb_state {
    pub const ES_SEL: usize = 0x400;
    pub const ES_ATTRIB: usize = 0x402;
    pub const ES_LIMIT: usize = 0x404;
    pub const ES_BASE: usize = 0x408;
    pub const CS_SEL: usize = 0x410;
    pub const CS_ATTRIB: usize = 0x412;
    pub const CS_LIMIT: usize = 0x414;
    pub const CS_BASE: usize = 0x418;
    pub const SS_SEL: usize = 0x420;
    pub const SS_ATTRIB: usize = 0x422;
    pub const SS_LIMIT: usize = 0x424;
    pub const SS_BASE: usize = 0x428;
    pub const DS_SEL: usize = 0x430;
    pub const DS_ATTRIB: usize = 0x432;
    pub const DS_LIMIT: usize = 0x434;
    pub const DS_BASE: usize = 0x438;
    pub const FS_SEL: usize = 0x440;
    pub const FS_ATTRIB: usize = 0x442;
    pub const FS_LIMIT: usize = 0x444;
    pub const FS_BASE: usize = 0x448;
    pub const GS_SEL: usize = 0x450;
    pub const GS_ATTRIB: usize = 0x452;
    pub const GS_LIMIT: usize = 0x454;
    pub const GS_BASE: usize = 0x458;
    pub const GDTR_SEL: usize = 0x460;
    pub const GDTR_ATTRIB: usize = 0x462;
    pub const GDTR_LIMIT: usize = 0x464;
    pub const GDTR_BASE: usize = 0x468;
    pub const LDTR_SEL: usize = 0x470;
    pub const LDTR_ATTRIB: usize = 0x472;
    pub const LDTR_LIMIT: usize = 0x474;
    pub const LDTR_BASE: usize = 0x478;
    pub const IDTR_SEL: usize = 0x480;
    pub const IDTR_ATTRIB: usize = 0x482;
    pub const IDTR_LIMIT: usize = 0x484;
    pub const IDTR_BASE: usize = 0x488;
    pub const TR_SEL: usize = 0x490;
    pub const TR_ATTRIB: usize = 0x492;
    pub const TR_LIMIT: usize = 0x494;
    pub const TR_BASE: usize = 0x498;
    // 0x4A0 - 0x4CA: Reserved
    pub const CPL: usize = 0x4CB;
    // 0x4CC - 0x4CF: Reserved
    pub const EFER: usize = 0x4D0;
    // 0x4D8 - 0x547: Reserved
    pub const CR4: usize = 0x548;
    pub const CR3: usize = 0x550;
    pub const CR0: usize = 0x558;
    pub const DR7: usize = 0x560;
    pub const DR6: usize = 0x568;
    pub const RFLAGS: usize = 0x570;
    pub const RIP: usize = 0x578;
    // 0x580 - 0x5CF: Reserved
    pub const RSP: usize = 0x5D8;
    pub const S_CET: usize = 0x5E0;
    pub const SSP: usize = 0x5E8;
    pub const ISST_ADDR: usize = 0x5F0;
    pub const RAX: usize = 0x5F8;
    pub const STAR: usize = 0x600;
    pub const LSTAR: usize = 0x608;
    pub const CSTAR: usize = 0x610;
    pub const SFMASK: usize = 0x618;
    pub const KERNEL_GS_BASE: usize = 0x620;
    pub const SYSENTER_CS: usize = 0x628;
    pub const SYSENTER_ESP: usize = 0x630;
    pub const SYSENTER_EIP: usize = 0x638;
    pub const CR2: usize = 0x640;
    // 0x648 - 0x667: Reserved
    pub const G_PAT: usize = 0x668;
    pub const DBGCTL: usize = 0x670;
    pub const BR_FROM: usize = 0x678;
    pub const BR_TO: usize = 0x680;
    pub const LAST_EXCP_FROM: usize = 0x688;
    pub const LAST_EXCP_TO: usize = 0x690;
    // 0x698 - 0x7FF: Reserved
    // 0x800 - 0xFFF: Reserved for SEV-ES
}

// ─── VMEXIT Codes ──────────────────────────────────────────────────────────────

pub mod exit_code {
    pub const CR0_READ: u64 = 0x000;
    pub const CR0_WRITE: u64 = 0x010;
    pub const CR3_READ: u64 = 0x003;
    pub const CR3_WRITE: u64 = 0x013;
    pub const CR4_READ: u64 = 0x004;
    pub const CR4_WRITE: u64 = 0x014;
    pub const CR8_READ: u64 = 0x008;
    pub const CR8_WRITE: u64 = 0x018;
    pub const DR0_READ: u64 = 0x020;
    pub const DR0_WRITE: u64 = 0x030;
    pub const EXCP_BASE: u64 = 0x040;
    pub const EXCP_DE: u64 = 0x040; // Divide error
    pub const EXCP_DB: u64 = 0x041; // Debug
    pub const EXCP_BP: u64 = 0x043; // Breakpoint
    pub const EXCP_UD: u64 = 0x046; // Invalid opcode
    pub const EXCP_NM: u64 = 0x047; // Device not available
    pub const EXCP_DF: u64 = 0x048; // Double fault
    pub const EXCP_TS: u64 = 0x04A; // Invalid TSS
    pub const EXCP_NP: u64 = 0x04B; // Segment not present
    pub const EXCP_SS: u64 = 0x04C; // Stack segment fault
    pub const EXCP_GP: u64 = 0x04D; // General protection
    pub const EXCP_PF: u64 = 0x04E; // Page fault
    pub const EXCP_MF: u64 = 0x050; // x87 FP exception
    pub const EXCP_AC: u64 = 0x051; // Alignment check
    pub const EXCP_MC: u64 = 0x052; // Machine check
    pub const EXCP_XF: u64 = 0x053; // SIMD FP exception
    pub const INTR: u64 = 0x060;    // Physical interrupt
    pub const NMI: u64 = 0x061;     // NMI
    pub const SMI: u64 = 0x062;     // SMI
    pub const INIT: u64 = 0x063;    // INIT
    pub const VINTR: u64 = 0x064;   // Virtual interrupt
    pub const CR0_SEL_WRITE: u64 = 0x065; // Selective CR0 write
    pub const IDTR_READ: u64 = 0x066;
    pub const GDTR_READ: u64 = 0x067;
    pub const LDTR_READ: u64 = 0x068;
    pub const TR_READ: u64 = 0x069;
    pub const IDTR_WRITE: u64 = 0x06A;
    pub const GDTR_WRITE: u64 = 0x06B;
    pub const LDTR_WRITE: u64 = 0x06C;
    pub const TR_WRITE: u64 = 0x06D;
    pub const RDTSC: u64 = 0x06E;
    pub const RDPMC: u64 = 0x06F;
    pub const PUSHF: u64 = 0x070;
    pub const POPF: u64 = 0x071;
    pub const CPUID: u64 = 0x072;
    pub const RSM: u64 = 0x073;
    pub const IRET: u64 = 0x074;
    pub const SWINT: u64 = 0x075;   // Software interrupt (INTn)
    pub const INVD: u64 = 0x076;
    pub const PAUSE: u64 = 0x077;
    pub const HLT: u64 = 0x078;
    pub const INVLPG: u64 = 0x079;
    pub const INVLPGA: u64 = 0x07A;
    pub const IOIO: u64 = 0x07B;    // I/O instruction
    pub const MSR: u64 = 0x07C;     // MSR access
    pub const TASK_SWITCH: u64 = 0x07D;
    pub const FERR_FREEZE: u64 = 0x07E;
    pub const SHUTDOWN: u64 = 0x07F;
    pub const VMRUN: u64 = 0x080;
    pub const VMMCALL: u64 = 0x081;
    pub const VMLOAD: u64 = 0x082;
    pub const VMSAVE: u64 = 0x083;
    pub const STGI: u64 = 0x084;
    pub const CLGI: u64 = 0x085;
    pub const SKINIT: u64 = 0x086;
    pub const RDTSCP: u64 = 0x087;
    pub const ICEBP: u64 = 0x088;
    pub const WBINVD: u64 = 0x089;
    pub const MONITOR: u64 = 0x08A;
    pub const MWAIT: u64 = 0x08B;
    pub const MWAIT_COND: u64 = 0x08C; // Conditional MWAIT
    pub const XSETBV: u64 = 0x08D;
    pub const RDPRU: u64 = 0x08E;
    pub const EFER_WRITE_TRAP: u64 = 0x08F;
    pub const CR_WRITE_TRAP_BASE: u64 = 0x090;
    pub const INVLPGB: u64 = 0x0A0;
    pub const INVLPGB_ILLEGAL: u64 = 0x0A1;
    pub const INVPCID: u64 = 0x0A2;
    pub const MCOMMIT: u64 = 0x0A3;
    pub const TLBSYNC: u64 = 0x0A4;
    pub const NPF: u64 = 0x400;     // Nested page fault
    pub const AVIC_INCOMPLETE_IPI: u64 = 0x401;
    pub const AVIC_NOACCEL: u64 = 0x402;
    pub const VMGEXIT: u64 = 0x403; // SEV-ES VMGEXIT
    pub const INVALID: u64 = u64::MAX - 1;
    pub const BUSY: u64 = u64::MAX - 2;
}

// ─── Intercept Bits ────────────────────────────────────────────────────────────

pub mod intercept {
    // General 1 intercepts (offset 0x00C)
    pub const INTR: u32 = 1 << 0;
    pub const NMI: u32 = 1 << 1;
    pub const SMI: u32 = 1 << 2;
    pub const INIT: u32 = 1 << 3;
    pub const VINTR: u32 = 1 << 4;
    pub const CR0_SEL_WR: u32 = 1 << 5;
    pub const IDTR_RD: u32 = 1 << 6;
    pub const GDTR_RD: u32 = 1 << 7;
    pub const LDTR_RD: u32 = 1 << 8;
    pub const TR_RD: u32 = 1 << 9;
    pub const IDTR_WR: u32 = 1 << 10;
    pub const GDTR_WR: u32 = 1 << 11;
    pub const LDTR_WR: u32 = 1 << 12;
    pub const TR_WR: u32 = 1 << 13;
    pub const RDTSC: u32 = 1 << 14;
    pub const RDPMC: u32 = 1 << 15;
    pub const PUSHF: u32 = 1 << 16;
    pub const POPF: u32 = 1 << 17;
    pub const CPUID: u32 = 1 << 18;
    pub const RSM: u32 = 1 << 19;
    pub const IRET: u32 = 1 << 20;
    pub const SWINT: u32 = 1 << 21;
    pub const INVD: u32 = 1 << 22;
    pub const PAUSE: u32 = 1 << 23;
    pub const HLT: u32 = 1 << 24;
    pub const INVLPG: u32 = 1 << 25;
    pub const INVLPGA: u32 = 1 << 26;
    pub const IOIO_PROT: u32 = 1 << 27;
    pub const MSR_PROT: u32 = 1 << 28;
    pub const TASK_SWITCH: u32 = 1 << 29;
    pub const FERR_FREEZE: u32 = 1 << 30;
    pub const SHUTDOWN: u32 = 1 << 31;

    // General 2 intercepts (offset 0x010)
    pub const VMRUN: u32 = 1 << 0;
    pub const VMMCALL: u32 = 1 << 1;
    pub const VMLOAD: u32 = 1 << 2;
    pub const VMSAVE: u32 = 1 << 3;
    pub const STGI: u32 = 1 << 4;
    pub const CLGI: u32 = 1 << 5;
    pub const SKINIT: u32 = 1 << 6;
    pub const RDTSCP: u32 = 1 << 7;
    pub const ICEBP: u32 = 1 << 8;
    pub const WBINVD: u32 = 1 << 9;
    pub const MONITOR: u32 = 1 << 10;
    pub const MWAIT: u32 = 1 << 11;
    pub const MWAIT_COND: u32 = 1 << 12;
    pub const XSETBV: u32 = 1 << 13;
    pub const RDPRU: u32 = 1 << 14;
    pub const EFER_TRAP: u32 = 1 << 15;
}

// ─── VMCB Structure ────────────────────────────────────────────────────────────

/// 4KB VMCB page
#[repr(C, align(4096))]
pub struct VmcbPage {
    pub data: [u8; 4096],
}

impl VmcbPage {
    pub const fn new() -> Self {
        Self { data: [0u8; 4096] }
    }

    #[inline]
    pub fn read_u8(&self, offset: usize) -> u8 {
        self.data[offset]
    }

    #[inline]
    pub fn write_u8(&mut self, offset: usize, value: u8) {
        self.data[offset] = value;
    }

    #[inline]
    pub fn read_u16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.data[offset], self.data[offset + 1]])
    }

    #[inline]
    pub fn write_u16(&mut self, offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        self.data[offset] = bytes[0];
        self.data[offset + 1] = bytes[1];
    }

    #[inline]
    pub fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ])
    }

    #[inline]
    pub fn write_u32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }

    #[inline]
    pub fn read_u64(&self, offset: usize) -> u64 {
        u64::from_le_bytes([
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
            self.data[offset + 4],
            self.data[offset + 5],
            self.data[offset + 6],
            self.data[offset + 7],
        ])
    }

    #[inline]
    pub fn write_u64(&mut self, offset: usize, value: u64) {
        let bytes = value.to_le_bytes();
        self.data[offset..offset + 8].copy_from_slice(&bytes);
    }
}

// ─── Static VMCB/Host Save Areas ───────────────────────────────────────────────

/// Maximum number of SVM VMCB slots
pub const MAX_SVM_SLOTS: usize = 64;

/// Host state save area (4KB aligned)
#[repr(C, align(4096))]
struct HostSaveArea {
    /// General purpose registers saved on VMRUN
    gprs: HostGprs,
    /// Remaining space for other host state
    _reserved: [u8; 4096 - core::mem::size_of::<HostGprs>()],
}

/// Host GPR state saved during VMRUN
#[repr(C)]
struct HostGprs {
    rax: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

impl HostGprs {
    const fn new() -> Self {
        Self {
            rax: 0, rcx: 0, rdx: 0, rbx: 0,
            rbp: 0, rsi: 0, rdi: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
        }
    }
}

impl HostSaveArea {
    const fn new() -> Self {
        Self { 
            gprs: HostGprs::new(),
            _reserved: [0u8; 4096 - core::mem::size_of::<HostGprs>()],
        }
    }
}

/// Static VMCB pages
static mut VMCB_PAGES: [VmcbPage; MAX_SVM_SLOTS] = [const { VmcbPage::new() }; MAX_SVM_SLOTS];

/// Static host save areas
static mut HOST_SAVE_AREAS: [HostSaveArea; MAX_SVM_SLOTS] = [const { HostSaveArea::new() }; MAX_SVM_SLOTS];

/// VMCB slot allocator
static NEXT_SVM_SLOT: AtomicUsize = AtomicUsize::new(0);

// ─── NPT (Nested Page Tables) ──────────────────────────────────────────────────

/// NPT entry flags (same as regular page table with some additions)
pub const NPT_PRESENT: u64 = 1 << 0;
pub const NPT_WRITE: u64 = 1 << 1;
pub const NPT_USER: u64 = 1 << 2;
pub const NPT_PWT: u64 = 1 << 3;      // Page-level write-through
pub const NPT_PCD: u64 = 1 << 4;      // Page-level cache disable
pub const NPT_ACCESSED: u64 = 1 << 5;
pub const NPT_DIRTY: u64 = 1 << 6;
pub const NPT_LARGE: u64 = 1 << 7;    // 2MB/1GB page
pub const NPT_NX: u64 = 1 << 63;      // No execute

/// 4-level NPT structure (similar to EPT)
#[repr(C, align(4096))]
pub struct NptTable {
    entries: [u64; 512],
}

impl NptTable {
    pub const fn new() -> Self {
        Self { entries: [0u64; 512] }
    }
}

/// NPT pool size (256 pages = 1MB)
pub const NPT_POOL_SIZE: usize = 256;

/// Static NPT page pool
static mut NPT_POOL: [NptTable; NPT_POOL_SIZE] = [const { NptTable::new() }; NPT_POOL_SIZE];
static NPT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

fn npt_pool_alloc() -> Result<*mut NptTable, HvError> {
    let idx = NPT_POOL_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= NPT_POOL_SIZE {
        NPT_POOL_NEXT.store(NPT_POOL_SIZE, Ordering::SeqCst);
        return Err(HvError::LogicalFault);
    }
    Ok(unsafe { &mut NPT_POOL[idx] as *mut NptTable })
}

/// NPT manager for a single VM
pub struct Npt {
    pml4_idx: usize,
}

impl Npt {
    pub const fn new() -> Self {
        Self { pml4_idx: usize::MAX }
    }

    fn ensure_pml4(&mut self) -> Result<&mut NptTable, HvError> {
        if self.pml4_idx == usize::MAX {
            let ptr = npt_pool_alloc()?;
            let base = unsafe { &NPT_POOL[0] as *const NptTable as usize };
            self.pml4_idx = (ptr as usize - base) / core::mem::size_of::<NptTable>();
        }
        Ok(unsafe { &mut NPT_POOL[self.pml4_idx] })
    }

    fn pml4(&self) -> &NptTable {
        if self.pml4_idx == usize::MAX {
            unsafe { &NPT_POOL[0] }
        } else {
            unsafe { &NPT_POOL[self.pml4_idx] }
        }
    }

    /// Get CR3 value for NPT (physical address of PML4)
    pub fn cr3(&self) -> u64 {
        self.pml4() as *const NptTable as u64
    }

    fn get_or_alloc(parent: &mut NptTable, idx: usize) -> Result<&'static mut NptTable, HvError> {
        let entry = parent.entries[idx];
        if entry & NPT_PRESENT != 0 && entry & NPT_LARGE == 0 {
            let addr = (entry & 0xFFFF_FFFF_FFFF_F000) as *mut NptTable;
            return Ok(unsafe { &mut *addr });
        }
        let child = npt_pool_alloc()?;
        parent.entries[idx] = (child as u64) | NPT_PRESENT | NPT_WRITE | NPT_USER;
        Ok(unsafe { &mut *child })
    }

    /// Map a 4KB page
    pub fn map_4k(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pt = Self::get_or_alloc(pd, pd_idx)?;
        pt.entries[pt_idx] = (hpa & 0xFFFF_FFFF_FFFF_F000) 
            | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_ACCESSED | NPT_DIRTY;
        Ok(())
    }

    /// Map a 2MB large page
    pub fn map_2m(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0x1F_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        pd.entries[pd_idx] = (hpa & 0xFFFF_FFFF_FFE0_0000)
            | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE | NPT_ACCESSED | NPT_DIRTY;
        Ok(())
    }

    /// Map a 1GB huge page
    pub fn map_1g(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0x3FFF_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        pdpt.entries[pdpt_idx] = (hpa & 0xFFFF_FFFF_C000_0000)
            | NPT_PRESENT | NPT_WRITE | NPT_USER | NPT_LARGE | NPT_ACCESSED | NPT_DIRTY;
        Ok(())
    }

    /// Map a range using largest possible page sizes
    pub fn map_range(&mut self, base: u64, size: u64) -> Result<(), HvError> {
        let mut offset = 0u64;
        while offset < size {
            let gpa = base.wrapping_add(offset);
            let remaining = size - offset;
            if gpa & 0x3FFF_FFFF == 0 && remaining >= 0x4000_0000 {
                self.map_1g(gpa, gpa)?;
                offset = offset.wrapping_add(0x4000_0000);
            } else if gpa & 0x1F_FFFF == 0 && remaining >= 0x20_0000 {
                self.map_2m(gpa, gpa)?;
                offset = offset.wrapping_add(0x20_0000);
            } else {
                self.map_4k(gpa, gpa)?;
                offset = offset.wrapping_add(0x1000);
            }
        }
        Ok(())
    }
}

// ─── SVM Context ───────────────────────────────────────────────────────────────

/// SVM virtual machine context
pub struct Svm {
    /// VMCB slot index
    slot: usize,
    /// NPT for this VM
    npt: Npt,
    /// Whether the VM has been launched
    launched: bool,
}

impl Svm {
    /// Create a new SVM context
    pub fn new() -> Result<Self, HvError> {
        Self::enable_svm()?;
        
        let slot = NEXT_SVM_SLOT.fetch_add(1, Ordering::SeqCst);
        if slot >= MAX_SVM_SLOTS {
            return Err(HvError::LogicalFault);
        }

        // Set up host save area
        let hsave_pa = unsafe { &HOST_SAVE_AREAS[slot] as *const HostSaveArea as u64 };
        write_msr(MSR_VM_HSAVE_PA, hsave_pa);

        let mut svm = Self {
            slot,
            npt: Npt::new(),
            launched: false,
        };

        svm.setup_vmcb()?;
        Ok(svm)
    }

    /// Enable SVM in EFER
    fn enable_svm() -> Result<(), HvError> {
        // Check if SVM is available
        let cpuid = unsafe { core::arch::x86_64::__cpuid(0x8000_0001) };
        if cpuid.ecx & (1 << 2) == 0 {
            return Err(HvError::HardwareFault); // SVM not supported
        }

        // Check VM_CR for SVM lock
        let vm_cr = read_msr(MSR_VM_CR);
        if vm_cr & VM_CR_SVMDIS != 0 {
            return Err(HvError::HardwareFault); // SVM disabled in BIOS
        }

        // Enable SVM in EFER
        let efer = read_msr(MSR_EFER);
        if efer & EFER_SVME == 0 {
            write_msr(MSR_EFER, efer | EFER_SVME);
        }

        Ok(())
    }

    /// Set up the VMCB with initial values
    fn setup_vmcb(&mut self) -> Result<(), HvError> {
        // Get NPT CR3 first to avoid borrow conflict
        let npt_cr3 = self.npt.cr3();
        let vmcb = self.vmcb_mut();

        // ── Control area setup ──────────────────────────────────────────────
        
        // Intercept CPUID, MSR, HLT, I/O
        let intercepts1 = intercept::CPUID | intercept::MSR_PROT | intercept::HLT 
            | intercept::IOIO_PROT | intercept::SHUTDOWN;
        vmcb.write_u32(vmcb_ctrl::GENERAL_1_INTERCEPTS, intercepts1);

        // Intercept VMRUN, VMMCALL
        let intercepts2 = intercept::VMRUN | intercept::VMMCALL;
        vmcb.write_u32(vmcb_ctrl::GENERAL_2_INTERCEPTS, intercepts2);

        // ASID (must be non-zero for TLB tagging)
        vmcb.write_u32(vmcb_ctrl::GUEST_ASID, 1);

        // Enable nested paging
        vmcb.write_u64(vmcb_ctrl::NP_ENABLE, 1);

        // Set NPT CR3 (will be updated when NPT is built)
        vmcb.write_u64(vmcb_ctrl::N_CR3, npt_cr3);

        // ── Guest state setup (64-bit long mode) ────────────────────────────
        
        // EFER: LME + LMA + NXE
        let guest_efer: u64 = (1 << 8) | (1 << 10) | (1 << 11);
        vmcb.write_u64(vmcb_state::EFER, guest_efer);

        // CR0: PE + NE + ET + PG
        let guest_cr0: u64 = 0x8000_0031;
        vmcb.write_u64(vmcb_state::CR0, guest_cr0);

        // CR3: guest page tables at 0x1000
        vmcb.write_u64(vmcb_state::CR3, 0x1000);

        // CR4: PAE + OSFXSR + OSXMMEXCPT
        let guest_cr4: u64 = 0x0620;
        vmcb.write_u64(vmcb_state::CR4, guest_cr4);

        // DR7: default value
        vmcb.write_u64(vmcb_state::DR7, 0x400);

        // RFLAGS: bit 1 always set
        vmcb.write_u64(vmcb_state::RFLAGS, 0x2);

        // Code segment (64-bit code)
        vmcb.write_u16(vmcb_state::CS_SEL, 0x08);
        vmcb.write_u16(vmcb_state::CS_ATTRIB, 0x029B); // L=1, P=1, S=1, type=B
        vmcb.write_u32(vmcb_state::CS_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::CS_BASE, 0);

        // Data segment
        vmcb.write_u16(vmcb_state::SS_SEL, 0x10);
        vmcb.write_u16(vmcb_state::SS_ATTRIB, 0x0093);
        vmcb.write_u32(vmcb_state::SS_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::SS_BASE, 0);

        vmcb.write_u16(vmcb_state::DS_SEL, 0x10);
        vmcb.write_u16(vmcb_state::DS_ATTRIB, 0x0093);
        vmcb.write_u32(vmcb_state::DS_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::DS_BASE, 0);

        vmcb.write_u16(vmcb_state::ES_SEL, 0x10);
        vmcb.write_u16(vmcb_state::ES_ATTRIB, 0x0093);
        vmcb.write_u32(vmcb_state::ES_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::ES_BASE, 0);

        vmcb.write_u16(vmcb_state::FS_SEL, 0);
        vmcb.write_u16(vmcb_state::FS_ATTRIB, 0x0093);
        vmcb.write_u32(vmcb_state::FS_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::FS_BASE, 0);

        vmcb.write_u16(vmcb_state::GS_SEL, 0);
        vmcb.write_u16(vmcb_state::GS_ATTRIB, 0x0093);
        vmcb.write_u32(vmcb_state::GS_LIMIT, 0xFFFF_FFFF);
        vmcb.write_u64(vmcb_state::GS_BASE, 0);

        // GDTR
        vmcb.write_u32(vmcb_state::GDTR_LIMIT, 0x27);
        vmcb.write_u64(vmcb_state::GDTR_BASE, 0x500);

        // IDTR
        vmcb.write_u32(vmcb_state::IDTR_LIMIT, 0x0FFF);
        vmcb.write_u64(vmcb_state::IDTR_BASE, 0x7000);

        // TR (Task Register)
        vmcb.write_u16(vmcb_state::TR_SEL, 0x18);
        vmcb.write_u16(vmcb_state::TR_ATTRIB, 0x008B);
        vmcb.write_u32(vmcb_state::TR_LIMIT, 0x67);
        vmcb.write_u64(vmcb_state::TR_BASE, 0);

        // LDTR (unusable)
        vmcb.write_u16(vmcb_state::LDTR_SEL, 0);
        vmcb.write_u16(vmcb_state::LDTR_ATTRIB, 0x0082);
        vmcb.write_u32(vmcb_state::LDTR_LIMIT, 0xFFFF);
        vmcb.write_u64(vmcb_state::LDTR_BASE, 0);

        // CPL = 0 (kernel mode)
        vmcb.write_u8(vmcb_state::CPL, 0);

        Ok(())
    }

    /// Get mutable reference to this VM's VMCB
    fn vmcb_mut(&mut self) -> &mut VmcbPage {
        unsafe { &mut VMCB_PAGES[self.slot] }
    }

    /// Get reference to this VM's VMCB
    pub fn vmcb(&self) -> &VmcbPage {
        unsafe { &VMCB_PAGES[self.slot] }
    }

    /// Set guest RIP
    pub fn set_guest_rip(&mut self, rip: u64) {
        self.vmcb_mut().write_u64(vmcb_state::RIP, rip);
    }

    /// Set guest RSP
    pub fn set_guest_rsp(&mut self, rsp: u64) {
        self.vmcb_mut().write_u64(vmcb_state::RSP, rsp);
    }

    /// Set guest RAX
    pub fn set_guest_rax(&mut self, rax: u64) {
        self.vmcb_mut().write_u64(vmcb_state::RAX, rax);
    }

    /// Get guest RIP
    pub fn guest_rip(&self) -> u64 {
        self.vmcb().read_u64(vmcb_state::RIP)
    }

    /// Get guest RSP
    pub fn guest_rsp(&self) -> u64 {
        self.vmcb().read_u64(vmcb_state::RSP)
    }

    /// Get guest RAX
    pub fn guest_rax(&self) -> u64 {
        self.vmcb().read_u64(vmcb_state::RAX)
    }

    /// Get guest RCX from host save area (saved on VMRUN)
    pub fn guest_rcx(&self) -> u64 {
        // RCX is saved in host save area, not VMCB
        // We need to read from the host save area or track manually
        // For now, return 0 - full implementation would read from host save area
        // The host save area contains: RAX, RCX, RDX, RBX, RBP, RSI, RDI, R8-R15
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rcx }
    }

    /// Get guest RBX from host save area
    pub fn guest_rbx(&self) -> u64 {
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rbx }
    }

    /// Get guest RDX from host save area
    pub fn guest_rdx(&self) -> u64 {
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rdx }
    }

    /// Set guest RCX in host save area
    pub fn set_guest_rcx(&mut self, rcx: u64) {
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rcx = rcx }
    }

    /// Set guest RBX in host save area
    pub fn set_guest_rbx(&mut self, rbx: u64) {
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rbx = rbx }
    }

    /// Set guest RDX in host save area
    pub fn set_guest_rdx(&mut self, rdx: u64) {
        unsafe { HOST_SAVE_AREAS[self.slot].gprs.rdx = rdx }
    }

    /// Get exit code
    pub fn exit_code(&self) -> u64 {
        self.vmcb().read_u64(vmcb_ctrl::EXIT_CODE)
    }

    /// Get exit info 1
    pub fn exit_info_1(&self) -> u64 {
        self.vmcb().read_u64(vmcb_ctrl::EXIT_INFO_1)
    }

    /// Get exit info 2
    pub fn exit_info_2(&self) -> u64 {
        self.vmcb().read_u64(vmcb_ctrl::EXIT_INFO_2)
    }

    /// Get next RIP (for decode assist)
    pub fn next_rip(&self) -> u64 {
        self.vmcb().read_u64(vmcb_ctrl::NRIP)
    }

    /// Inject an event (interrupt/exception) into the guest via EVENT_INJ
    /// EVENT_INJ format (64-bit):
    /// - Bits [7:0]: Vector
    /// - Bits [10:8]: Type (0=intr, 2=NMI, 3=exception, 4=software intr)
    /// - Bit 11: Error code valid
    /// - Bits [31:12]: Error code (if valid)
    /// - Bit 32: Valid (must be set to inject)
    pub fn inject_event(&mut self, vector: u8, event_type: u8, error_code: Option<u32>) {
        let mut inj: u64 = vector as u64;
        inj |= (event_type as u64) << 8;
        
        if let Some(code) = error_code {
            inj |= 1 << 11; // Error code valid
            inj |= (code as u64) << 12;
        }
        
        inj |= 1 << 32; // Valid bit
        
        self.vmcb_mut().write_u64(vmcb_ctrl::EVENT_INJ, inj);
    }

    /// Inject a hardware interrupt
    pub fn inject_interrupt(&mut self, vector: u8) {
        // Type 0 = external interrupt
        self.inject_event(vector, 0, None);
    }

    /// Inject an exception
    pub fn inject_exception(&mut self, vector: u8, error_code: Option<u32>) {
        // Type 3 = exception
        self.inject_event(vector, 3, error_code);
    }

    /// Inject NMI
    pub fn inject_nmi(&mut self) {
        // Type 2 = NMI, vector 2 is ignored for NMI
        self.inject_event(2, 2, None);
    }

    /// Check if event injection is pending
    pub fn is_event_pending(&self) -> bool {
        let inj = self.vmcb().read_u64(vmcb_ctrl::EVENT_INJ);
        (inj >> 32) & 1 == 1
    }

    /// Clear pending event injection
    pub fn clear_event_injection(&mut self) {
        self.vmcb_mut().write_u64(vmcb_ctrl::EVENT_INJ, 0);
    }

    /// Get EXIT_INT_INFO (interrupt info that caused exit)
    pub fn exit_int_info(&self) -> u64 {
        self.vmcb().read_u64(vmcb_ctrl::EXIT_INT_INFO)
    }

    /// Configure NPT for guest memory
    pub fn configure_npt(&mut self, mem_size: u64) -> Result<(), HvError> {
        self.npt.map_range(0, mem_size)?;
        let npt_cr3 = self.npt.cr3();
        self.vmcb_mut().write_u64(vmcb_ctrl::N_CR3, npt_cr3);
        Ok(())
    }

    /// Run the guest (VMRUN instruction)
    #[cfg(not(test))]
    pub fn run(&mut self) -> Result<(), HvError> {
        let vmcb_pa = unsafe { &VMCB_PAGES[self.slot] as *const VmcbPage as u64 };
        
        // Clear VMCB clean bits to force reload of all state
        self.vmcb_mut().write_u32(vmcb_ctrl::VMCB_CLEAN, 0);

        unsafe {
            vmrun(vmcb_pa);
        }

        self.launched = true;
        Ok(())
    }

    #[cfg(test)]
    pub fn run(&mut self) -> Result<(), HvError> {
        self.launched = true;
        Ok(())
    }

    /// Inject an interrupt into the guest
    pub fn inject_interrupt(&mut self, vector: u8) {
        let vmcb = self.vmcb_mut();
        vmcb.write_u8(vmcb_ctrl::V_IRQ, 1);
        vmcb.write_u8(vmcb_ctrl::V_INTR_VECTOR, vector);
        vmcb.write_u8(vmcb_ctrl::V_INTR_PRIO, 0xF); // Highest priority
    }

    /// Advance RIP by instruction length (using NRIP if available)
    pub fn advance_rip(&mut self) {
        let nrip = self.next_rip();
        if nrip != 0 {
            self.set_guest_rip(nrip);
        } else {
            // Fallback: advance by a fixed amount (not ideal)
            let rip = self.guest_rip();
            self.set_guest_rip(rip.wrapping_add(2));
        }
    }

    /// Get mutable reference to NPT
    pub fn npt_mut(&mut self) -> &mut Npt {
        &mut self.npt
    }
}

impl Default for Svm {
    fn default() -> Self {
        Self::new().expect("SVM initialization failed")
    }
}

// ─── Low-level functions ───────────────────────────────────────────────────────

fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    }
    ((high as u64) << 32) | low as u64
}

fn write_msr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        core::arch::asm!("wrmsr", in("ecx") msr, in("eax") low, in("edx") high);
    }
}

/// Execute VMRUN instruction
/// 
/// # Safety
/// vmcb_pa must point to a valid, properly configured VMCB
#[cfg(not(test))]
unsafe fn vmrun(vmcb_pa: u64) {
    core::arch::asm!(
        // Save host state
        "push rbx",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push rbp",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        // Load VMCB address into RAX
        "mov rax, {vmcb}",
        // Execute VMRUN
        "vmrun",
        // VMEXIT returns here
        // Restore host state
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rbp",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rbx",
        vmcb = in(reg) vmcb_pa,
        options(nostack)
    );
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmcb_page_read_write() {
        let mut vmcb = VmcbPage::new();
        
        vmcb.write_u64(vmcb_state::RIP, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(vmcb.read_u64(vmcb_state::RIP), 0xDEAD_BEEF_CAFE_BABE);

        vmcb.write_u32(vmcb_ctrl::GENERAL_1_INTERCEPTS, 0x1234_5678);
        assert_eq!(vmcb.read_u32(vmcb_ctrl::GENERAL_1_INTERCEPTS), 0x1234_5678);

        vmcb.write_u16(vmcb_state::CS_SEL, 0x08);
        assert_eq!(vmcb.read_u16(vmcb_state::CS_SEL), 0x08);
    }

    #[test]
    fn vmcb_offsets_are_correct() {
        // Verify critical offsets match AMD spec
        assert_eq!(vmcb_ctrl::EXIT_CODE, 0x070);
        assert_eq!(vmcb_ctrl::EXIT_INFO_1, 0x078);
        assert_eq!(vmcb_ctrl::N_CR3, 0x0B0);
        assert_eq!(vmcb_state::RIP, 0x578);
        assert_eq!(vmcb_state::RSP, 0x5D8);
        assert_eq!(vmcb_state::RAX, 0x5F8);
        assert_eq!(vmcb_state::CR0, 0x558);
        assert_eq!(vmcb_state::CR3, 0x550);
        assert_eq!(vmcb_state::EFER, 0x4D0);
    }

    #[test]
    fn npt_map_4k() {
        let mut npt = Npt::new();
        npt.map_4k(0x1000, 0x1000).unwrap();
        npt.map_4k(0x2000, 0x2000).unwrap();
        // Verify CR3 is non-zero after mapping
        assert_ne!(npt.cr3(), 0);
    }

    #[test]
    fn npt_map_2m() {
        let mut npt = Npt::new();
        npt.map_2m(0x20_0000, 0x20_0000).unwrap();
        assert_ne!(npt.cr3(), 0);
    }

    #[test]
    fn exit_codes_match_spec() {
        assert_eq!(exit_code::CPUID, 0x072);
        assert_eq!(exit_code::HLT, 0x078);
        assert_eq!(exit_code::IOIO, 0x07B);
        assert_eq!(exit_code::MSR, 0x07C);
        assert_eq!(exit_code::NPF, 0x400);
        assert_eq!(exit_code::VMMCALL, 0x081);
    }

    #[test]
    fn intercept_bits() {
        let i1 = intercept::CPUID | intercept::HLT | intercept::MSR_PROT;
        assert_eq!(i1 & intercept::CPUID, intercept::CPUID);
        assert_eq!(i1 & intercept::HLT, intercept::HLT);
        assert_eq!(i1 & intercept::MSR_PROT, intercept::MSR_PROT);
    }
}
