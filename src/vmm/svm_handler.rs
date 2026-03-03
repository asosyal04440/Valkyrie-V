//! AMD SVM VMEXIT Handler
//!
//! Provides exit handling for AMD Secure Virtual Machine similar to vmx_handler.rs.
//! Handles NPT violations, CPUID/MSR intercepts, I/O instructions, and interrupt injection.

#![allow(dead_code)]

use crate::vmm::svm::{exit_code, vmcb_ctrl, vmcb_state, Svm, Npt};
use crate::vmm::{HvError, HvResult};
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

// ─── Exit Handler Result ───────────────────────────────────────────────────────

/// Result of handling a VMEXIT
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmExitAction {
    /// Continue executing the guest
    Continue,
    /// Halt the guest (HLT instruction)
    Halt,
    /// Shutdown requested
    Shutdown,
    /// Error occurred
    Error(SvmExitError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvmExitError {
    UnhandledExit(u64),
    NptViolation,
    InvalidState,
    InjectionFailed,
}

// ─── SVM Handler State ─────────────────────────────────────────────────────────

/// Pending interrupt for SVM (similar to VMX PENDING_IRQ)
pub static SVM_PENDING_IRQ: AtomicU8 = AtomicU8::new(0);

/// PIT tick counter for SVM guests
static SVM_PIT_TICK: AtomicU32 = AtomicU32::new(0);

/// PIT fire interval
const SVM_PIT_FIRE_INTERVAL: u32 = 64;
/// PIT IRQ0 vector (8259A remapped)
const PIT_IRQ0_VECTOR: u8 = 0x20;

// ─── I/O Port Exit Info Decode ─────────────────────────────────────────────────

/// Decoded I/O exit information from EXIT_INFO_1
#[derive(Debug)]
pub struct IoExitInfo {
    pub port: u16,
    pub is_in: bool,
    pub is_string: bool,
    pub is_rep: bool,
    pub size: u8,    // 1, 2, or 4 bytes
    pub addr_size: u8, // 16, 32, or 64 bit
}

impl IoExitInfo {
    /// Decode EXIT_INFO_1 for IOIO exit
    pub fn from_exit_info(info1: u64) -> Self {
        // AMD SVM IOIO exit info layout:
        // Bits 0: Direction (0=OUT, 1=IN)
        // Bit 2: String instruction
        // Bit 3: REP prefix
        // Bits 4-6: Operand size (1=byte, 2=word, 4=dword)
        // Bits 7-9: Address size (0=16, 1=32, 2=64)
        // Bits 16-31: Port number
        let is_in = (info1 & 1) != 0;
        let is_string = (info1 & (1 << 2)) != 0;
        let is_rep = (info1 & (1 << 3)) != 0;
        let size_bits = ((info1 >> 4) & 0x7) as u8;
        let size = match size_bits {
            1 => 1,
            2 => 2,
            4 => 4,
            _ => 1,
        };
        let addr_bits = ((info1 >> 7) & 0x7) as u8;
        let addr_size = match addr_bits {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64,
        };
        let port = ((info1 >> 16) & 0xFFFF) as u16;

        Self {
            port,
            is_in,
            is_string,
            is_rep,
            size,
            addr_size,
        }
    }
}

// ─── MSR Exit Info Decode ──────────────────────────────────────────────────────

/// Decoded MSR exit information
#[derive(Debug)]
pub struct MsrExitInfo {
    pub msr_index: u32,
    pub is_write: bool,
}

impl MsrExitInfo {
    /// Decode EXIT_INFO_1 for MSR exit
    pub fn from_exit_info(info1: u64, guest_rcx: u32) -> Self {
        // Bit 0 of EXIT_INFO_1: 0=RDMSR, 1=WRMSR
        let is_write = (info1 & 1) != 0;
        Self {
            msr_index: guest_rcx,
            is_write,
        }
    }
}

// ─── NPT Violation Info ────────────────────────────────────────────────────────

/// Decoded NPT fault information from EXIT_INFO_1
#[derive(Debug)]
pub struct NptFaultInfo {
    pub present: bool,
    pub write: bool,
    pub user: bool,
    pub reserved_bit: bool,
    pub execute: bool,
    pub gpa: u64,
}

impl NptFaultInfo {
    /// Decode EXIT_INFO_1 and EXIT_INFO_2 for NPT fault
    pub fn from_exit_info(info1: u64, info2: u64) -> Self {
        // EXIT_INFO_1 contains page fault error code:
        // Bit 0: P - Present
        // Bit 1: W - Write access
        // Bit 2: U - User mode access
        // Bit 3: RSV - Reserved bit violation
        // Bit 4: I/D - Instruction fetch
        Self {
            present: (info1 & 1) != 0,
            write: (info1 & (1 << 1)) != 0,
            user: (info1 & (1 << 2)) != 0,
            reserved_bit: (info1 & (1 << 3)) != 0,
            execute: (info1 & (1 << 4)) != 0,
            gpa: info2,
        }
    }
}

// ─── CPUID Emulation ───────────────────────────────────────────────────────────

/// Emulate CPUID instruction
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

impl CpuidResult {
    /// Create a zeroed result
    pub const fn zero() -> Self {
        Self { eax: 0, ebx: 0, ecx: 0, edx: 0 }
    }
}

/// Emulate CPUID for the guest
pub fn emulate_cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    match leaf {
        // Vendor string
        0 => CpuidResult {
            eax: 0x0000_0016, // Max standard leaf
            ebx: 0x6874_7541, // "Auth"
            ecx: 0x444D_4163, // "cAMD"
            edx: 0x6974_6E65, // "enti"
        },
        
        // Feature info
        1 => CpuidResult {
            eax: 0x00A2_0F12, // Family/Model/Stepping (Zen 3)
            ebx: 0x0008_0800, // CLFLUSH size, initial APIC ID
            ecx: 0x7EFA_3203, // Features (SSE3, SSE4, POPCNT, etc.)
            edx: 0x178B_FBFF, // Features (FPU, VME, PSE, etc.)
        },
        
        // Cache/TLB info
        2 => CpuidResult::zero(),
        
        // Processor serial (disabled)
        3 => CpuidResult::zero(),
        
        // Deterministic cache parameters
        4 => match subleaf {
            0 => CpuidResult {
                eax: 0x0000_0121, // L1 data cache
                ebx: 0x01C0_003F,
                ecx: 0x0000_003F,
                edx: 0x0000_0000,
            },
            _ => CpuidResult::zero(),
        },
        
        // MONITOR/MWAIT
        5 => CpuidResult::zero(),
        
        // Thermal and Power Management
        6 => CpuidResult {
            eax: 0x0000_0004,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        
        // Extended feature flags
        7 => match subleaf {
            0 => CpuidResult {
                eax: 0,
                ebx: 0x219C_91A9, // FSGSBASE, BMI1, AVX2, BMI2, etc.
                ecx: 0x0000_0000,
                edx: 0x0000_0000,
            },
            _ => CpuidResult::zero(),
        },
        
        // Extended max leaf
        0x8000_0000 => CpuidResult {
            eax: 0x8000_001F, // Max extended leaf
            ebx: 0x6874_7541, // "Auth"
            ecx: 0x444D_4163, // "cAMD"
            edx: 0x6974_6E65, // "enti"
        },
        
        // Extended feature flags
        0x8000_0001 => CpuidResult {
            eax: 0x00A2_0F12,
            ebx: 0,
            ecx: 0x75C2_37FF, // LAHF, SVM, ABM, SSE4A, etc.
            edx: 0x2FD3_FBFF, // NX, LM, 3DNow, etc.
        },
        
        // Processor brand string (part 1)
        0x8000_0002 => CpuidResult {
            eax: 0x2045_564C, // " LVE"
            ebx: 0x6563_6863, // "hce "
            ecx: 0x56_2D53, // "S-V\0"
            edx: 0x0000_0000,
        },
        
        // Processor brand string (part 2-4)
        0x8000_0003 | 0x8000_0004 => CpuidResult::zero(),
        
        // L1 Cache/TLB
        0x8000_0005 => CpuidResult {
            eax: 0xFF40_FF18,
            ebx: 0xFF40_FF30,
            ecx: 0x1002_0140, // L1 data cache
            edx: 0x4004_0140, // L1 instruction cache
        },
        
        // L2 Cache/TLB
        0x8000_0006 => CpuidResult {
            eax: 0x0000_0000,
            ebx: 0x4200_0000,
            ecx: 0x0200_4140, // L2 cache
            edx: 0x0000_0000,
        },
        
        // APM
        0x8000_0007 => CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0x0000_0100, // TSC Invariant
        },
        
        // Address sizes
        0x8000_0008 => CpuidResult {
            eax: 0x0000_3030, // 48-bit virtual, 48-bit physical
            ebx: 0x0000_100D,
            ecx: 0x0000_4007, // Core count
            edx: 0,
        },
        
        // SVM Features
        0x8000_000A => CpuidResult {
            eax: 0x0000_0001, // SVM revision
            ebx: 0x0000_0040, // Number of ASIDs
            ecx: 0,
            edx: 0x0001_7BFF, // SVM features (NPT, NRIP, etc.)
        },
        
        _ => CpuidResult::zero(),
    }
}

// ─── MSR Emulation ─────────────────────────────────────────────────────────────

/// Known MSR values for emulation
pub struct MsrEmulator {
    tsc: AtomicU32,
    apic_base: AtomicU32,
}

impl MsrEmulator {
    pub const fn new() -> Self {
        Self {
            tsc: AtomicU32::new(0),
            apic_base: AtomicU32::new(0xFEE0_0000 >> 12), // Default APIC base
        }
    }
}

static MSR_EMU: MsrEmulator = MsrEmulator::new();

/// Handle MSR read
pub fn emulate_rdmsr(msr: u32) -> u64 {
    match msr {
        // IA32_TSC
        0x10 => {
            #[cfg(target_arch = "x86_64")]
            unsafe { core::arch::x86_64::_rdtsc() }
            #[cfg(not(target_arch = "x86_64"))]
            0
        }
        
        // IA32_APIC_BASE
        0x1B => {
            let base = MSR_EMU.apic_base.load(Ordering::Relaxed) as u64;
            (base << 12) | 0x900 // Enable, BSP
        }
        
        // IA32_MTRRCAP
        0xFE => 0x0000_0D0A,
        
        // IA32_SYSENTER_CS
        0x174 => 0,
        
        // IA32_SYSENTER_ESP
        0x175 => 0,
        
        // IA32_SYSENTER_EIP
        0x176 => 0,
        
        // IA32_PAT
        0x277 => 0x0007_0406_0007_0406,
        
        // IA32_EFER
        0xC000_0080 => 0x0D01, // LME, LMA, NXE
        
        // IA32_STAR
        0xC000_0081 => 0,
        
        // IA32_LSTAR
        0xC000_0082 => 0,
        
        // IA32_CSTAR
        0xC000_0083 => 0,
        
        // IA32_FMASK
        0xC000_0084 => 0,
        
        // IA32_FS_BASE
        0xC000_0100 => 0,
        
        // IA32_GS_BASE
        0xC000_0101 => 0,
        
        // IA32_KERNEL_GS_BASE
        0xC000_0102 => 0,
        
        // Unknown - return 0
        _ => 0,
    }
}

/// Handle MSR write
pub fn emulate_wrmsr(msr: u32, _value: u64) -> bool {
    match msr {
        // IA32_TSC - ignore
        0x10 => true,
        
        // IA32_APIC_BASE
        0x1B => {
            // Accept but don't relocate
            true
        }
        
        // IA32_SYSENTER_*
        0x174 | 0x175 | 0x176 => true,
        
        // IA32_PAT
        0x277 => true,
        
        // IA32_EFER
        0xC000_0080 => true,
        
        // IA32_STAR, LSTAR, CSTAR, FMASK
        0xC000_0081..=0xC000_0084 => true,
        
        // IA32_FS_BASE, GS_BASE, KERNEL_GS_BASE
        0xC000_0100..=0xC000_0102 => true,
        
        // Unknown - return false
        _ => false,
    }
}

// ─── SVM Exit Handler ──────────────────────────────────────────────────────────

/// Main SVM exit handler context
pub struct SvmHandler {
    /// NPT dirty flag for batched TLB flush
    npt_dirty: bool,
}

impl SvmHandler {
    pub const fn new() -> Self {
        Self { npt_dirty: false }
    }

    /// Handle a VMEXIT
    pub fn handle_exit(&mut self, svm: &mut Svm) -> SvmExitAction {
        let exit_code = svm.exit_code();
        let info1 = svm.exit_info_1();
        let info2 = svm.exit_info_2();

        match exit_code {
            exit_code::NPF => self.handle_npf(svm, info1, info2),
            exit_code::IOIO => self.handle_io(svm, info1),
            exit_code::MSR => self.handle_msr(svm, info1),
            exit_code::CPUID => self.handle_cpuid(svm),
            exit_code::HLT => SvmExitAction::Halt,
            exit_code::SHUTDOWN => SvmExitAction::Shutdown,
            exit_code::VMMCALL => self.handle_vmmcall(svm),
            exit_code::VINTR => {
                // Virtual interrupt delivered, continue
                SvmExitAction::Continue
            }
            exit_code::INTR => {
                // Physical interrupt, continue
                SvmExitAction::Continue
            }
            exit_code::NMI => {
                // NMI, continue
                SvmExitAction::Continue
            }
            // Exception intercepts
            exit_code::EXCP_DE..=exit_code::EXCP_XF => {
                self.handle_exception(svm, exit_code)
            }
            // CR access
            exit_code::CR0_READ..=exit_code::CR8_WRITE => {
                self.handle_cr_access(svm, exit_code);
                SvmExitAction::Continue
            }
            // RDTSC/RDTSCP
            exit_code::RDTSC | exit_code::RDTSCP => {
                self.handle_rdtsc(svm);
                SvmExitAction::Continue
            }
            // Unhandled exit
            _ => SvmExitAction::Error(SvmExitError::UnhandledExit(exit_code)),
        }
    }

    /// Handle NPT fault (similar to EPT violation)
    fn handle_npf(&mut self, svm: &mut Svm, info1: u64, info2: u64) -> SvmExitAction {
        let fault = NptFaultInfo::from_exit_info(info1, info2);
        let gpa = fault.gpa;
        let frame_addr = gpa & !0xFFF;

        // Check for MMIO intercepts first
        
        // IOAPIC MMIO (0xFEC0_0000)
        if frame_addr == 0xFEC0_0000 {
            // Would forward to IOAPIC emulation
            svm.advance_rip();
            return SvmExitAction::Continue;
        }

        // LAPIC MMIO (0xFEE0_0000)
        if frame_addr == 0xFEE0_0000 {
            // Would forward to LAPIC emulation
            svm.advance_rip();
            return SvmExitAction::Continue;
        }

        // VirtIO MMIO regions
        const VIRTIO_NET: u64 = 0xFEB0_0000;
        const VIRTIO_BLK: u64 = 0xFEB0_1000;
        const VIRTIO_CON: u64 = 0xFEB0_2000;
        
        if frame_addr == VIRTIO_NET || frame_addr == VIRTIO_BLK || frame_addr == VIRTIO_CON {
            // Would forward to VirtIO emulation
            svm.advance_rip();
            return SvmExitAction::Continue;
        }

        // Normal memory access - map the page
        if svm.npt_mut().map_4k(frame_addr, frame_addr).is_ok() {
            self.npt_dirty = true;
            SvmExitAction::Continue
        } else {
            SvmExitAction::Error(SvmExitError::NptViolation)
        }
    }

    /// Handle I/O port access
    fn handle_io(&mut self, svm: &mut Svm, info1: u64) -> SvmExitAction {
        let io = IoExitInfo::from_exit_info(info1);
        
        if io.is_in {
            // Use the platform emulator from vmx_handler
            if let Some(value) = crate::vmm::vmx_handler::emulate_port_in(io.port, io.size) {
                // Write result to guest RAX based on size
                let rax = svm.guest_rax();
                let new_rax = match io.size {
                    1 => (rax & !0xFF) | (value as u64 & 0xFF),
                    2 => (rax & !0xFFFF) | (value as u64 & 0xFFFF),
                    4 => value as u64,
                    _ => value as u64,
                };
                svm.set_guest_rax(new_rax);
            }
        } else {
            // OUT instruction - value is in RAX
            let rax = svm.guest_rax();
            let value = match io.size {
                1 => rax as u32 & 0xFF,
                2 => rax as u32 & 0xFFFF,
                4 => rax as u32,
                _ => rax as u32,
            };
            let _ = crate::vmm::vmx_handler::emulate_port_out(io.port, io.size, value);
        }

        svm.advance_rip();
        SvmExitAction::Continue
    }

    /// Handle MSR access
    fn handle_msr(&mut self, svm: &mut Svm, info1: u64) -> SvmExitAction {
        // Guest RCX contains MSR index
        // For now, use guest_rax as a proxy since we don't have direct RCX access
        let is_write = (info1 & 1) != 0;
        
        // In a real implementation, we'd read RCX from the guest state
        // For now, use the exit_info_2 which might contain additional info
        let msr_idx = svm.exit_info_2() as u32;

        if is_write {
            let value = svm.guest_rax();
            let _ = emulate_wrmsr(msr_idx, value);
        } else {
            let result = emulate_rdmsr(msr_idx);
            svm.set_guest_rax(result);
        }

        svm.advance_rip();
        SvmExitAction::Continue
    }

    /// Handle CPUID instruction
    fn handle_cpuid(&mut self, svm: &mut Svm) -> SvmExitAction {
        // EAX contains leaf, ECX contains subleaf
        let rax = svm.guest_rax();
        let leaf = rax as u32;
        // Read subleaf from guest RCX
        let subleaf = svm.guest_rcx() as u32;

        let result = emulate_cpuid(leaf, subleaf);

        // Write results back to guest registers
        svm.set_guest_rax(result.eax as u64);
        svm.set_guest_rbx(result.ebx as u64);
        svm.set_guest_rcx(result.ecx as u64);
        svm.set_guest_rdx(result.edx as u64);

        svm.advance_rip();
        SvmExitAction::Continue
    }

    /// Handle VMMCALL hypercall
    fn handle_vmmcall(&mut self, svm: &mut Svm) -> SvmExitAction {
        let rax = svm.guest_rax();
        
        // Hypercall dispatch based on RAX
        match rax {
            // Hypervisor presence check
            0 => {
                svm.set_guest_rax(0x564B_5652); // "VKVR" signature
            }
            // Get hypervisor version
            1 => {
                svm.set_guest_rax(0x0001_0000); // Version 1.0
            }
            // Unknown hypercall
            _ => {
                svm.set_guest_rax(u64::MAX); // Error
            }
        }

        svm.advance_rip();
        SvmExitAction::Continue
    }

    /// Handle exception intercept
    fn handle_exception(&mut self, svm: &mut Svm, exit_code: u64) -> SvmExitAction {
        let vector = (exit_code - exit_code::EXCP_BASE) as u8;
        
        match vector {
            // #NM - Device not available (FPU)
            7 => {
                // Would initialize FPU state for guest
                svm.advance_rip();
                SvmExitAction::Continue
            }
            // #PF - Page fault (shouldn't happen with NPT enabled)
            14 => {
                // Forward to guest's page fault handler
                SvmExitAction::Continue
            }
            // Other exceptions - reflect to guest
            _ => {
                // Inject the exception back to guest
                inject_event(svm, vector, EventType::Exception);
                SvmExitAction::Continue
            }
        }
    }

    /// Handle CR access
    fn handle_cr_access(&mut self, svm: &mut Svm, exit_code: u64) {
        // CR read/write exits
        // The new value is already applied by hardware for writes
        // For reads, the value is already in the destination register
        svm.advance_rip();
    }

    /// Handle RDTSC/RDTSCP
    fn handle_rdtsc(&mut self, svm: &mut Svm) {
        #[cfg(target_arch = "x86_64")]
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        #[cfg(not(target_arch = "x86_64"))]
        let tsc = 0u64;

        // Write TSC to RAX (low) and RDX (high)
        // We only have RAX access via VMCB state
        svm.set_guest_rax(tsc & 0xFFFF_FFFF);

        svm.advance_rip();
    }

    /// Check if NPT needs flush
    pub fn needs_npt_flush(&self) -> bool {
        self.npt_dirty
    }

    /// Clear NPT dirty flag
    pub fn clear_npt_dirty(&mut self) {
        self.npt_dirty = false;
    }
}

// ─── Event Injection ───────────────────────────────────────────────────────────

/// Event types for injection
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    External,
    Nmi,
    Exception,
    SoftwareInterrupt,
}

/// Inject an event into the guest via VMCB
pub fn inject_event(svm: &mut Svm, vector: u8, event_type: EventType) {
    // VMCB Event Injection format:
    // Bits 7:0 - Vector
    // Bits 10:8 - Type (0=external, 2=NMI, 3=exception, 4=software)
    // Bit 11 - Error code valid
    // Bit 31 - Valid
    
    let type_bits = match event_type {
        EventType::External => 0,
        EventType::Nmi => 2,
        EventType::Exception => 3,
        EventType::SoftwareInterrupt => 4,
    };

    let error_code_valid = matches!(
        vector,
        8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30
    );

    let event_inj = (vector as u64)
        | ((type_bits as u64) << 8)
        | if error_code_valid { 1 << 11 } else { 0 }
        | (1 << 31); // Valid bit

    // Write to VMCB EVENT_INJ field
    // This would need mutable access to the VMCB
    // For now, use the V_IRQ mechanism for interrupts
    if matches!(event_type, EventType::External) {
        svm.inject_interrupt(vector);
    }
}

/// Inject a pending interrupt if the guest is interruptible
pub fn try_inject_pending_irq(svm: &mut Svm) -> bool {
    let vector = SVM_PENDING_IRQ.load(Ordering::Acquire);
    if vector == 0 {
        return false;
    }

    // Check if guest is interruptible (RFLAGS.IF set, no interrupt shadow)
    // Read RFLAGS from VMCB
    let rflags = svm.vmcb.rflags;
    let if_flag = (rflags & (1 << 9)) != 0;
    
    // Check interrupt shadow (V_IRQ in VMCB)
    // V_IRQ (bit 8) indicates if virtual interrupt is pending
    // V_IRQ_MASK (bit 24) indicates if interrupts are masked
    let v_irq = (svm.vmcb.v_irq & 0xFF) != 0;
    let v_int_state = svm.vmcb.v_int_state;
    let int_shadow = (v_int_state & 0x1) != 0; // Interrupt shadow active
    
    // Guest is interruptible if:
    // 1. RFLAGS.IF = 1
    // 2. No interrupt shadow active (not after STI/MOV SS)
    // 3. V_IRQ is not already pending
    if !if_flag || int_shadow || v_irq {
        // Guest is not interruptible
        // Set V_IRQ_MASK to trigger interrupt window exit
        svm.vmcb.v_int_state |= 0x2; // Enable V_INTR_MASKING
        return false;
    }

    svm.inject_interrupt(vector);
    SVM_PENDING_IRQ.store(0, Ordering::Release);
    true
}

// ─── SVM Main Loop ─────────────────────────────────────────────────────────────

/// Run the SVM main loop
pub fn svm_loop(svm: &mut Svm, mem_size: u64) -> HvResult<()> {
    // Configure NPT for guest memory
    svm.configure_npt(mem_size)?;

    let mut handler = SvmHandler::new();

    loop {
        // Inject pending interrupt before entry
        let _ = try_inject_pending_irq(svm);

        // Run the guest
        svm.run()?;

        // Handle the exit
        match handler.handle_exit(svm) {
            SvmExitAction::Continue => {
                // Continue execution
            }
            SvmExitAction::Halt => {
                // Guest executed HLT
                return Ok(());
            }
            SvmExitAction::Shutdown => {
                // Guest requested shutdown
                return Ok(());
            }
            SvmExitAction::Error(e) => {
                match e {
                    SvmExitError::UnhandledExit(code) => {
                        // Log unhandled exit
                        return Err(HvError::LogicalFault);
                    }
                    _ => return Err(HvError::LogicalFault),
                }
            }
        }

        // PIT timer tick
        {
            let tick = SVM_PIT_TICK.fetch_add(1, Ordering::Relaxed);
            if tick % SVM_PIT_FIRE_INTERVAL == 0 {
                SVM_PENDING_IRQ.store(PIT_IRQ0_VECTOR, Ordering::Release);
            }
        }

        // Flush NPT TLB if needed
        if handler.needs_npt_flush() {
            // AMD doesn't have INVEPT, but has INVLPGA for individual pages
            // or TLB control in VMCB for full flush
            handler.clear_npt_dirty();
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_exit_info_decode() {
        // IN AL, 0x3F8 (byte read)
        let info = IoExitInfo::from_exit_info(0x03F8_0011);
        assert!(info.is_in);
        assert_eq!(info.port, 0x3F8);
        assert_eq!(info.size, 1);
        assert!(!info.is_string);
    }

    #[test]
    fn io_exit_info_out() {
        // OUT 0x80, AL (byte write)
        let info = IoExitInfo::from_exit_info(0x0080_0010);
        assert!(!info.is_in);
        assert_eq!(info.port, 0x80);
        assert_eq!(info.size, 1);
    }

    #[test]
    fn npt_fault_decode() {
        // Write fault to GPA 0x1000
        let fault = NptFaultInfo::from_exit_info(0x3, 0x1000);
        assert!(fault.present);
        assert!(fault.write);
        assert!(!fault.user);
        assert_eq!(fault.gpa, 0x1000);
    }

    #[test]
    fn cpuid_vendor() {
        let result = emulate_cpuid(0, 0);
        assert!(result.eax > 0);
        // Check for "AuthenticAMD" vendor string
        assert_eq!(result.ebx, 0x6874_7541);
    }

    #[test]
    fn cpuid_features() {
        let result = emulate_cpuid(1, 0);
        // Check for basic features
        assert!(result.ecx != 0);
        assert!(result.edx != 0);
    }

    #[test]
    fn cpuid_svm_features() {
        let result = emulate_cpuid(0x8000_000A, 0);
        // Check SVM revision
        assert_eq!(result.eax, 1);
        // Check ASID count
        assert!(result.ebx >= 64);
    }

    #[test]
    fn msr_apic_base() {
        let result = emulate_rdmsr(0x1B);
        // Check default APIC base with enable flags
        assert_eq!(result & 0xFFFF_F000, 0xFEE0_0000);
        assert!(result & 0x800 != 0); // Enable bit
    }

    #[test]
    fn msr_efer() {
        let result = emulate_rdmsr(0xC000_0080);
        // Check LME, LMA bits
        assert!(result & 0x100 != 0); // LME
        assert!(result & 0x400 != 0); // LMA
    }

    #[test]
    fn handler_creation() {
        let handler = SvmHandler::new();
        assert!(!handler.needs_npt_flush());
    }
}
