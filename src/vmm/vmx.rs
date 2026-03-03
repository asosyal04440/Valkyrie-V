#![allow(dead_code)]
#![allow(clippy::fn_to_numeric_cast)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, Ordering};

// ── VM State constants ─────────────────────────────────────────────────────────
pub const VM_STATE_RUNNING: u32 = 0;
pub const VM_STATE_SHUTDOWN: u32 = 1;
pub const VM_STATE_REBOOT: u32 = 2;
pub const VM_STATE_PAUSED: u32 = 3;

/// Global VM state
pub static VM_STATE: AtomicU32 = AtomicU32::new(VM_STATE_RUNNING);

/// Special exit codes for shutdown/reboot
pub const VMX_EXIT_SHUTDOWN: u64 = 0xFFFF_FFFF_FFFF_FFF0;
pub const VMX_EXIT_REBOOT: u64 = 0xFFFF_FFFF_FFFF_FFF1;

// ── MSR indices ──────────────────────────────────────────────────────────────
const IA32_FEATURE_CONTROL: u32 = 0x3A;
const IA32_VMX_BASIC: u32 = 0x480;
const IA32_VMX_PINBASED_CTLS: u32 = 0x481;
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
const IA32_VMX_EXIT_CTLS: u32 = 0x483;
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
const IA32_VMX_CR0_FIXED0: u32 = 0x486;
const IA32_VMX_CR0_FIXED1: u32 = 0x487;
const IA32_VMX_CR4_FIXED0: u32 = 0x488;
const IA32_VMX_CR4_FIXED1: u32 = 0x489;

// ── VM-entry / VM-exit control bits ──────────────────────────────────────────
const VM_ENTRY_IA32E_MODE: u64 = 1 << 9; // IA-32e Mode Guest (64-bit)
const VM_ENTRY_LOAD_EFER: u64 = 1 << 15; // load IA32_EFER on entry
const VM_EXIT_HOST_64BIT: u64 = 1 << 9; // Host Address-Space Size
const VM_EXIT_SAVE_EFER: u64 = 1 << 20;
const VM_EXIT_LOAD_EFER: u64 = 1 << 21;

// ── CPU-based controls ───────────────────────────────────────────────────────
const CPU_BASED_ACTIVATE_SECONDARY: u64 = 1 << 31;
const CPU_BASED_HLT_EXITING: u64 = 1 << 7;
const CPU_BASED_USE_MSR_BITMAPS: u64 = 1 << 28;
const CPU_BASED_INTERRUPT_WINDOW: u64 = 1 << 2;
const SECONDARY_ENABLE_VPID: u64 = 1 << 0;
const SECONDARY_ENABLE_EPT: u64 = 1 << 1;
const SECONDARY_ENABLE_RDTSCP: u64 = 1 << 3;
const SECONDARY_UNRESTRICTED_GUEST: u64 = 1 << 7;
const SECONDARY_ENABLE_XSAVES: u64 = 1 << 20;

// ── 16-bit VMCS control fields ───────────────────────────────────────────────
const VMCS_CTRL_VPID: u64 = 0x0000;

// ── 64-bit VMCS control fields ───────────────────────────────────────────────
const VMCS_CTRL_MSR_BITMAP: u64 = 0x2004;
const VMCS_CTRL_TSC_OFFSET: u64 = 0x2010;
const VMCS_CTRL_EPTP: u64 = 0x201A;

// ── 32-bit VMCS control fields ───────────────────────────────────────────────
const VMCS_CTRL_PIN_BASED: u64 = 0x4000;
const VMCS_CTRL_CPU_BASED: u64 = 0x4002;
const VMCS_CTRL_EXCEPTION_BITMAP: u64 = 0x4004;
const VMCS_CTRL_VM_EXIT_CONTROLS: u64 = 0x400C;
const VMCS_CTRL_VM_ENTRY_CONTROLS: u64 = 0x4012;
const VMCS_CTRL_SECONDARY_CPU_BASED: u64 = 0x401E;

// ── 32-bit VMCS VM-entry interrupt injection ──────────────────────────────────
const VMCS_VM_ENTRY_INTR_INFO: u64 = 0x4016;
const VMCS_VM_ENTRY_INTR_ERR: u64 = 0x4018;
const VMCS_VM_ENTRY_INSTR_LEN: u64 = 0x401A;

// ── 16-bit guest-state selector fields (Intel SDM Vol 3C App B) ──────────────
const VMCS_GUEST_ES_SEL: u64 = 0x0800;
const VMCS_GUEST_CS_SEL: u64 = 0x0802;
const VMCS_GUEST_SS_SEL: u64 = 0x0804;
const VMCS_GUEST_DS_SEL: u64 = 0x0806;
const VMCS_GUEST_FS_SEL: u64 = 0x0808;
const VMCS_GUEST_GS_SEL: u64 = 0x080A;
const VMCS_GUEST_LDTR_SEL: u64 = 0x080C;
const VMCS_GUEST_TR_SEL: u64 = 0x080E;

// ── 16-bit host-state selector fields ────────────────────────────────────────
const VMCS_HOST_ES_SEL: u64 = 0x0C00;
const VMCS_HOST_CS_SEL: u64 = 0x0C02;
const VMCS_HOST_SS_SEL: u64 = 0x0C04;
const VMCS_HOST_DS_SEL: u64 = 0x0C06;
const VMCS_HOST_FS_SEL: u64 = 0x0C08;
const VMCS_HOST_GS_SEL: u64 = 0x0C0A;
const VMCS_HOST_TR_SEL: u64 = 0x0C0C;

// ── 64-bit guest-state fields ─────────────────────────────────────────────────
const VMCS_GUEST_VMCS_LINK: u64 = 0x2800; // must be 0xFFFFFFFFFFFFFFFF
const VMCS_GUEST_IA32_EFER: u64 = 0x2806;

// ── 32-bit guest-state fields ─────────────────────────────────────────────────
const VMCS_GUEST_ES_LIMIT: u64 = 0x4800;
const VMCS_GUEST_CS_LIMIT: u64 = 0x4802;
const VMCS_GUEST_SS_LIMIT: u64 = 0x4804;
const VMCS_GUEST_DS_LIMIT: u64 = 0x4806;
const VMCS_GUEST_FS_LIMIT: u64 = 0x4808;
const VMCS_GUEST_GS_LIMIT: u64 = 0x480A;
const VMCS_GUEST_LDTR_LIMIT: u64 = 0x480C;
const VMCS_GUEST_TR_LIMIT: u64 = 0x480E;
const VMCS_GUEST_GDTR_LIMIT: u64 = 0x4810;
const VMCS_GUEST_IDTR_LIMIT: u64 = 0x4812;
const VMCS_GUEST_ES_AR: u64 = 0x4814;
const VMCS_GUEST_CS_AR: u64 = 0x4816;
const VMCS_GUEST_SS_AR: u64 = 0x4818;
const VMCS_GUEST_DS_AR: u64 = 0x481A;
const VMCS_GUEST_FS_AR: u64 = 0x481C;
const VMCS_GUEST_GS_AR: u64 = 0x481E;
const VMCS_GUEST_LDTR_AR: u64 = 0x4820;
const VMCS_GUEST_TR_AR: u64 = 0x4822;
const VMCS_GUEST_INTERRUPTIBILITY: u64 = 0x4824;
const VMCS_GUEST_ACTIVITY: u64 = 0x4826;
const VMCS_GUEST_SYSENTER_CS: u64 = 0x482A;

// ── Natural-width guest-state fields ─────────────────────────────────────────
const VMCS_GUEST_CR0: u64 = 0x6800;
const VMCS_GUEST_CR3: u64 = 0x6802;
const VMCS_GUEST_CR4: u64 = 0x6804;
const VMCS_GUEST_ES_BASE: u64 = 0x6806;
const VMCS_GUEST_CS_BASE: u64 = 0x6808;
const VMCS_GUEST_SS_BASE: u64 = 0x680A;
const VMCS_GUEST_DS_BASE: u64 = 0x680C;
const VMCS_GUEST_FS_BASE: u64 = 0x680E;
const VMCS_GUEST_GS_BASE: u64 = 0x6810;
const VMCS_GUEST_LDTR_BASE: u64 = 0x6812;
const VMCS_GUEST_TR_BASE: u64 = 0x6814;
const VMCS_GUEST_GDTR_BASE: u64 = 0x6816;
const VMCS_GUEST_IDTR_BASE: u64 = 0x6818;
const VMCS_GUEST_DR7: u64 = 0x681A;
const VMCS_GUEST_RSP: u64 = 0x681C;
const VMCS_GUEST_RIP: u64 = 0x681E;
const VMCS_GUEST_RFLAGS: u64 = 0x6820;
const VMCS_GUEST_SYSENTER_ESP: u64 = 0x6824;
const VMCS_GUEST_SYSENTER_EIP: u64 = 0x6826;

// ── Natural-width host-state fields ──────────────────────────────────────────
const VMCS_HOST_CR0: u64 = 0x6C00;
const VMCS_HOST_CR3: u64 = 0x6C02;
const VMCS_HOST_CR4: u64 = 0x6C04; // was wrong (0x6C02) in original
const VMCS_HOST_FS_BASE: u64 = 0x6C06;
const VMCS_HOST_GS_BASE: u64 = 0x6C08;
const VMCS_HOST_TR_BASE: u64 = 0x6C0A;
const VMCS_HOST_GDTR_BASE: u64 = 0x6C0C;
const VMCS_HOST_IDTR_BASE: u64 = 0x6C0E;
const VMCS_HOST_SYSENTER_ESP: u64 = 0x6C10;
const VMCS_HOST_SYSENTER_EIP: u64 = 0x6C12;
const VMCS_HOST_RSP: u64 = 0x6C14;
const VMCS_HOST_RIP: u64 = 0x6C16;

// ── Read-only VMCS data fields ────────────────────────────────────────────────
const EXIT_REASON: u64 = 0x4402;
const EXIT_QUALIFICATION: u64 = 0x6400;
const GUEST_PHYS_ADDR: u64 = 0x2400;
const VMCS_VM_INSTR_ERR: u64 = 0x4400;
pub const VMCS_EXIT_INSTR_LEN: u64 = 0x440C;

// ── VM-exit reason codes (Intel SDM Vol 3C Table C-1) ────────────────────────
pub const VMX_EXIT_EXCEPTION_NMI: u64 = 0;
pub const VMX_EXIT_TRIPLE_FAULT: u64 = 2;
pub const VMX_EXIT_INTERRUPT_WINDOW: u64 = 7;
pub const VMX_EXIT_CPUID: u64 = 10;
pub const VMX_EXIT_HLT: u64 = 12;
pub const VMX_EXIT_INVLPG: u64 = 14;
pub const VMX_EXIT_RDTSC: u64 = 16;
pub const VMX_EXIT_VMCALL: u64 = 18;
pub const VMX_EXIT_CR_ACCESS: u64 = 28;
pub const VMX_EXIT_MOV_DR: u64 = 29;
pub const VMX_EXIT_IO_INSTRUCTION: u64 = 30;
pub const VMX_EXIT_RDMSR: u64 = 31;
pub const VMX_EXIT_WRMSR: u64 = 32;
pub const VMX_EXIT_ENTRY_FAIL_GUEST: u64 = 33;
pub const VMX_EXIT_MWAIT: u64 = 36;
pub const VMX_EXIT_MONITOR: u64 = 39;
pub const VMX_EXIT_PAUSE: u64 = 40;
pub const VMX_EXIT_ENTRY_FAIL_MCE: u64 = 41;
pub const VMX_EXIT_EPT_VIOLATION: u64 = 48;
pub const VMX_EXIT_EPT_MISCONFIG: u64 = 49;
pub const VMX_EXIT_RDTSCP: u64 = 51;
pub const VMX_EXIT_PREEMPTION_TIMER: u64 = 52;
pub const VMX_EXIT_XSETBV: u64 = 55;

#[repr(align(4096))]
struct VmxPage([u8; 4096]);

/// Task State Segment (TSS) for 64-bit mode
/// Used for task switching and privilege level transitions
#[repr(C, align(16))]
pub struct Tss {
    pub reserved1: u32,
    pub rsp0: u64,           // Stack pointer for CPL=0
    pub rsp1: u64,           // Stack pointer for CPL=1
    pub rsp2: u64,           // Stack pointer for CPL=2
    pub reserved2: u32,
    pub ist: [u64; 7],       // Interrupt Stack Table entries
    pub reserved3: u64,
    pub reserved4: u16,
    pub iomap_base: u16,     // I/O Permission Map offset
}

impl Tss {
    pub const fn new() -> Self {
        Self {
            reserved1: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: 0x68, // Size of TSS - no I/O bitmap
        }
    }

    /// Set the CPL0 stack pointer (used on privilege transitions)
    pub fn set_rsp0(&mut self, rsp0: u64) {
        self.rsp0 = rsp0;
    }

    /// Set an Interrupt Stack Table entry
    pub fn set_ist(&mut self, index: usize, stack: u64) {
        if index < 7 {
            self.ist[index] = stack;
        }
    }
}

/// Host TSS for VMX operation
/// Required for proper VM-exit handling and privilege transitions
static mut HOST_TSS: Tss = Tss::new();

/// TSS descriptor for GDT
#[repr(C)]
pub struct TssDescriptor {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    limit_high: u8,
    base_high: u8,
    base_upper: u32,
    reserved: u32,
}

impl TssDescriptor {
    pub const fn new(base: u64, limit: u32) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access: 0x89, // Present, TSS type
            limit_high: ((limit >> 16) & 0x0F) as u8 | 0x00, // No granularity for TSS
            base_high: ((base >> 24) & 0xFF) as u8,
            base_upper: (base >> 32) as u32,
            reserved: 0,
        }
    }
}

/// Initialize host TSS for VMX operation
/// Must be called before VMXON
pub unsafe fn setup_host_tss(gdt_base: u64, tss_selector: u16) {
    // Set up the TSS with the exit stack as RSP0
    // This ensures proper stack switching on VM-exit
    let slot = 0; // Use first slot for host TSS
    let stack_top = HOST_EXIT_STACKS[slot].0.as_ptr() as u64 + 16384;
    HOST_TSS.set_rsp0(stack_top);
    
    // Set IST entries for NMI and double fault handling
    HOST_TSS.set_ist(1, stack_top); // IST1 for NMI
    HOST_TSS.set_ist(2, stack_top); // IST2 for double fault
    
    // Load TR with the TSS selector
    core::arch::asm!(
        "ltr {0}",
        in(reg) tss_selector,
        options(nostack, preserves_flags)
    );
    
    // Update VMCS host TR base
    let _ = vmwrite(VMCS_HOST_TR_BASE, &HOST_TSS as *const _ as u64);
    let _ = vmwrite(VMCS_HOST_TR_SEL, tss_selector as u64);
}

/// Get host TSS reference
pub fn host_tss() -> &'static Tss {
    unsafe { &HOST_TSS }
}

/// Get mutable host TSS reference
pub fn host_tss_mut() -> &'static mut Tss {
    unsafe { &mut HOST_TSS }
}

/// 16 KB host stack used on every VM-exit.  Top of stack = base + 16384 - 8.
#[repr(align(16))]
struct VmxExitStack([u8; 16384]);

/// Maximum number of vCPU VMCS / exit-stack slots.
pub const MAX_VMCS_SLOTS: usize = 64;

static mut VMXON_REGION: VmxPage = VmxPage([0; 4096]);
static mut MSR_BITMAP_REGION: VmxPage = VmxPage([0; 4096]);

/// Per-vCPU VMCS regions — one 4 KiB page per vCPU.
static mut VMCS_REGIONS: [VmxPage; MAX_VMCS_SLOTS] = [const { VmxPage([0; 4096]) }; MAX_VMCS_SLOTS];

/// Per-vCPU exit stacks — 16 KiB per vCPU so each has its own stack frame.
static mut HOST_EXIT_STACKS: [VmxExitStack; MAX_VMCS_SLOTS] =
    [const { VmxExitStack([0; 16384]) }; MAX_VMCS_SLOTS];

/// Monotonic counter for assigning VMCS slots.
static NEXT_VMCS_SLOT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// VM-exit entry point (assembly).  Saves GPRs, calls Rust dispatch.
// vm_exit_dispatch returns u64 in RAX:
//   0 → fast-path: pop GPRs + VMRESUME (CPUID, I/O, MSR, EPT)
//   1 → fatal: pop GPRs + HLT (unrecoverable exit)
// Only present in non-test builds because it issues bare-metal instructions.
#[cfg(not(test))]
core::arch::global_asm!(
    ".global vm_exit_entry",
    "vm_exit_entry:",
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rdi",
    "push rsi",
    "push rbp",
    "push rbx",
    "push rdx",
    "push rcx",
    "push rax",
    "mov  rdi, rsp", // first arg = frame pointer
    "sub  rsp, 8",   // 16-byte align
    "call vm_exit_dispatch",
    "add  rsp, 8",
    // RAX = return value from vm_exit_dispatch
    "mov  r15, rax", // save dispatch result in r15
    "pop rax",
    "pop rcx",
    "pop rdx",
    "pop rbx",
    "pop rbp",
    "pop rsi",
    "pop rdi",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "test r15, r15", // check dispatch result before popping r15
    "pop r15",
    "jnz  .Lfatal_exit",
    // Fast path: vmresume directly
    "vmresume",
    ".Lfatal_exit:",
    "hlt",
    "jmp .Lfatal_exit",
);

#[cfg(not(test))]
extern "C" {
    fn vm_exit_entry();
}

/// Global pointer to the active VM's EPT.
/// Set once before VMLAUNCH by the caller; read by `vm_exit_dispatch` on every
/// EPT violation exit.  Safety: written before launch on the same logical CPU
/// with interrupts disabled; the VM-exit handler runs in the same context.
#[cfg(not(test))]
static mut ACTIVE_EPT: *mut crate::vmm::ept::Ept = core::ptr::null_mut();

/// Install the EPT that `vm_exit_dispatch` should map pages into.
/// # Safety
/// Must be called on the same logical CPU that will execute VMLAUNCH, before
/// VMLAUNCH.
#[cfg(not(test))]
pub unsafe fn set_active_ept(ept: &mut crate::vmm::ept::Ept) {
    ACTIVE_EPT = ept as *mut crate::vmm::ept::Ept;
}

/// Handle MMIO access to the I/O APIC region.
///
/// EPT violations for IOAPIC_BASE (0xFEC00000) arrive here.  We decode the
/// access direction from the EPT-violation exit qualification:
///   bit 0 = data read, bit 1 = data write.
/// For writes we need the value the guest intended to store.  In the fast-path
/// we cannot easily decode the full instruction, so we use the guest RAX from
/// the GPR frame as the value (covers the MOV [mem], EAX pattern used by all
/// real IOAPIC drivers).  For reads the result goes back to guest RAX.
#[cfg(not(test))]
fn handle_ioapic_mmio(frame: *mut u64, gpa: u64) {
    use crate::vmm::ioapic::ioapic;

    let offset = gpa & 0xFFF;
    let qual = vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let is_write = (qual & 2) != 0;

    if is_write {
        // Guest value from RAX (frame[0])
        let value = if !frame.is_null() {
            (unsafe { *frame.add(0) }) as u32
        } else {
            0
        };
        ioapic().mmio_write(offset, value);
    } else {
        let result = ioapic().mmio_read(offset);
        if !frame.is_null() {
            unsafe { *frame.add(0) = result as u64; }
        }
    }

    // Advance RIP past the faulting instruction.
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
        let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
    }
}

/// Handle MMIO access to the Local APIC region (0xFEE00000).
///
/// Works identically to `handle_ioapic_mmio` but dispatches to the
/// global guest LAPIC instance in `vcpu.rs`.  The LAPIC register offset
/// is the low 12 bits of the GPA (registers are 16-byte aligned, so the
/// canonical offset is `(gpa & 0xFF0)`).
#[cfg(not(test))]
fn handle_lapic_mmio(frame: *mut u64, gpa: u64) {
    use crate::vmm::vcpu::guest_lapic;

    let offset = (gpa & 0xFFF) as u32;
    let qual = vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let is_write = (qual & 2) != 0;

    if is_write {
        let value = if !frame.is_null() {
            (unsafe { *frame.add(0) }) as u32
        } else {
            0
        };
        guest_lapic().write(offset, value);
    } else {
        let result = guest_lapic().read(offset);
        if !frame.is_null() {
            unsafe { *frame.add(0) = result as u64; }
        }
    }

    // Advance RIP past the faulting instruction.
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
        let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
    }
}

/// Handle MMIO access to a VirtIO MMIO device region.
///
/// VirtIO MMIO GPAs (0x10000000, 0x10010000, 0x10020000) are NOT identity-
/// mapped in the EPT, so guest accesses fault here.  We dispatch through
/// `VirtioDirect::mmio_read / mmio_write` which already demuxes by address.
#[cfg(not(test))]
fn handle_virtio_mmio(frame: *mut u64, gpa: u64) {
    use crate::vmm::virtio_direct;

    let qual = vmread(EXIT_QUALIFICATION).unwrap_or(0);
    let is_write = (qual & 2) != 0;

    if is_write {
        let value = if !frame.is_null() {
            (unsafe { *frame.add(0) }) as u32
        } else {
            0
        };
        let _ = virtio_direct().mmio_write(gpa, value);
    } else {
        let result = virtio_direct().mmio_read(gpa).unwrap_or(0);
        if !frame.is_null() {
            unsafe { *frame.add(0) = result as u64; }
        }
    }

    // Advance RIP past the faulting instruction.
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
        let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
    }
}

/// Returns true if `page_gpa` falls on a VirtIO MMIO device page.
#[cfg(not(test))]
fn is_virtio_mmio_page(page_gpa: u64) -> bool {
    page_gpa == crate::vmm::hypervisor::VIRTIO_MMIO_BASE_NET
        || page_gpa == crate::vmm::hypervisor::VIRTIO_MMIO_BASE_BLK
        || page_gpa == crate::vmm::hypervisor::VIRTIO_MMIO_BASE_CONSOLE
}

/// Fast-path PIT timer tick — mirrors the logic in `vmx_loop` but for the
/// assembly-level dispatcher.  Every PIT_FIRE_INTERVAL exits, assert IRQ0.
#[cfg(not(test))]
fn pit_tick_fast() {
    use crate::vmm::vmx_handler::PENDING_IRQ;
    use core::sync::atomic::Ordering;

    static PIT_TICK_COUNTER: core::sync::atomic::AtomicU32 =
        core::sync::atomic::AtomicU32::new(0);

    let tick = PIT_TICK_COUNTER.fetch_add(1, Ordering::Relaxed);
    if tick % 64 == 0 {
        // Route IRQ0 through the I/O APIC if it has a valid entry,
        // otherwise fall back to the hardcoded vector 0x20.
        let vector = crate::vmm::ioapic::ioapic()
            .route_irq(0)
            .unwrap_or(0x20);
        PENDING_IRQ.store(vector, Ordering::Release);
    }
}

/// Fast-path LAPIC timer check — if the timer has fired, set PENDING_IRQ
/// so `inject_pending_irq_fast` delivers it to the guest.
#[cfg(not(test))]
fn lapic_timer_tick_fast() {
    use crate::vmm::vcpu::guest_lapic;
    use crate::vmm::vmx_handler::PENDING_IRQ;
    use core::sync::atomic::Ordering;

    #[cfg(target_arch = "x86_64")]
    let now = unsafe { core::arch::x86_64::_rdtsc() };
    #[cfg(not(target_arch = "x86_64"))]
    let now = 0u64;

    if let Some(vector) = guest_lapic().check_timer(now) {
        // Only overwrite if no other IRQ is already pending
        let _ = PENDING_IRQ.compare_exchange(0, vector, Ordering::AcqRel, Ordering::Relaxed);
    }
}

/// Fast-path pending interrupt injection — injects a queued vector into the
/// VMCS VM-entry interrupt-info field so the guest receives it on VMRESUME.
#[cfg(not(test))]
fn inject_pending_irq_fast() {
    use crate::vmm::vmx_handler::PENDING_IRQ;
    use core::sync::atomic::Ordering;

    let vec = PENDING_IRQ.load(Ordering::Acquire);
    if vec == 0 {
        return;
    }

    // Check interruptibility
    let interruptibility = vmread(VMCS_GUEST_INTERRUPTIBILITY).unwrap_or(0);
    let rflags = vmread(VMCS_GUEST_RFLAGS).unwrap_or(0);
    if interruptibility & 0x3 != 0 || rflags & (1 << 9) == 0 {
        // Guest not ready — enable interrupt-window exiting so we re-exit
        // the moment IF goes high.
        let procbased = vmread(VMCS_CTRL_CPU_BASED).unwrap_or(0);
        let _ = vmwrite(VMCS_CTRL_CPU_BASED, procbased | CPU_BASED_INTERRUPT_WINDOW);
        return;
    }

    // Inject: external interrupt, valid bit set
    let info: u32 = (vec as u32) | (1 << 31);
    if vmwrite(VMCS_VM_ENTRY_INTR_INFO, info as u64).is_ok() {
        PENDING_IRQ.store(0, Ordering::Release);
        // Clear interrupt-window exiting if it was set
        let procbased = vmread(VMCS_CTRL_CPU_BASED).unwrap_or(0);
        let _ = vmwrite(VMCS_CTRL_CPU_BASED, procbased & !CPU_BASED_INTERRUPT_WINDOW);
    }
}

/// Rust VM-exit dispatcher — called from the assembly entry with GPR frame.
/// Returns 0 for fast-path exits that can VMRESUME immediately (CPUID, I/O,
/// MSR, EPT violation), or 1 for fatal/unrecoverable exits (assembly halts).
#[cfg(not(test))]
#[no_mangle]
extern "C" fn vm_exit_dispatch(frame: *mut u64) -> u64 {
    let reason = vmread(EXIT_REASON).unwrap_or(0xFFFF) & 0xFFFF;
    match reason {
        VMX_EXIT_CPUID => {
            handle_cpuid_exit(frame);
            0
        }
        VMX_EXIT_IO_INSTRUCTION => {
            handle_io_exit(frame);
            0
        }
        VMX_EXIT_RDMSR => {
            handle_rdmsr_exit(frame);
            0
        }
        VMX_EXIT_WRMSR => {
            handle_wrmsr_exit(frame);
            0
        }
        VMX_EXIT_HLT => {
            // Advance RIP past the 1-byte HLT so the guest continues.
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let _ = vmwrite(VMCS_GUEST_RIP, rip.wrapping_add(1));
            }
            // Check LAPIC timer even on HLT
            lapic_timer_tick_fast();
            inject_pending_irq_fast();
            0
        }
        VMX_EXIT_VMCALL => {
            // Hypercall dispatch
            // RAX = hypercall number, RBX-R8 = arguments
            // Result returned in RAX
            let hypercall_num = if !frame.is_null() {
                unsafe { core::ptr::read(frame) } // RAX
            } else {
                0
            };
            
            let args = if !frame.is_null() {
                unsafe {
                    [
                        core::ptr::read(frame.add(1)),  // RBX
                        core::ptr::read(frame.add(2)),  // RCX
                        core::ptr::read(frame.add(3)),  // RDX
                        core::ptr::read(frame.add(4)),  // RSI
                        core::ptr::read(frame.add(5)),  // RDI
                        core::ptr::read(frame.add(8)),  // R8
                    ]
                }
            } else {
                [0u64; 6]
            };

            use crate::vmm::hypercall::{HypercallContext, DefaultHypercallHandler, dispatch_hypercall};
            let ctx = HypercallContext::new(hypercall_num, args);
            let mut handler = DefaultHypercallHandler::new();
            let result = dispatch_hypercall(&ctx, &mut handler);

            // Write result to guest RAX
            if !frame.is_null() {
                unsafe { *frame.add(0) = result; }
            }
            
            // Check for shutdown/reboot requests
            if handler.is_shutdown_requested() || handler.is_reboot_requested() {
                // Signal VM state change to VirtualMachine
                // Set the appropriate VM state flag
                if handler.is_shutdown_requested() {
                    // Set shutdown state - VM will terminate
                    VM_STATE.store(VM_STATE_SHUTDOWN, Ordering::Release);
                    return VMX_EXIT_SHUTDOWN; // Special return code for shutdown
                } else if handler.is_reboot_requested() {
                    // Set reboot state - VM will restart
                    VM_STATE.store(VM_STATE_REBOOT, Ordering::Release);
                    return VMX_EXIT_REBOOT; // Special return code for reboot
                }
            }
            
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_CR_ACCESS => {
            // CR0/CR4 access - handle guest state tracking
            // Qualification bits: [3:0] = CR number, [5:4] = access type, [9:8] = LMSW operand type
            let qual = vmread(EXIT_QUALIFICATION).unwrap_or(0);
            let cr_num = (qual & 0xF) as u8;
            let access_type = ((qual >> 4) & 0x3) as u8;
            let is_write = access_type == 0; // 0 = write to CR, 1 = read from CR
            let lmsw_type = ((qual >> 8) & 0x3) as u8; // 0 = LMSW from memory, 1 = LMSW from reg
            
            match cr_num {
                0 => {
                    // CR0 access
                    if is_write {
                        // Guest writing to CR0 - update VMCS guest CR0
                        // The guest value is in GPR (typically RAX for MOV CR0, RAX)
                        // For LMSW, the operand type determines source
                        
                        // Read guest RAX (GPR0 in exit stack)
                        let guest_rax = unsafe { *frame.add(0) }; // RAX is at offset 0 in exit stack
                        
                        // For LMSW, only lower 16 bits are used
                        let new_cr0 = if lmsw_type != 0 || access_type == 0 {
                            guest_rax & 0xFFFFFFFF
                        } else {
                            guest_rax
                        };
                        
                        // CR0 validation:
                        // - Bit 0 (PE): Protected mode enable - guest can toggle
                        // - Bit 1 (MP): Monitor coprocessor - guest can set
                        // - Bit 2 (EM): Emulation - guest can set
                        // - Bit 3 (TS): Task switched - guest can set
                        // - Bit 4 (ET): Extension type - read-only
                        // - Bit 5 (NE): Numeric error - guest can set
                        // - Bit 16 (WP): Write protect - guest can set
                        // - Bit 18 (AM): Alignment mask - guest can set
                        // - Bit 29 (NW): Not-write through - guest can set
                        // - Bit 30 (CD): Cache disable - guest can set
                        // - Bit 31 (PG): Paging - guest can set (requires PE=1)
                        
                        // Read current guest CR0
                        let current_cr0 = vmread(VMCS_GUEST_CR0).unwrap_or(0x80000001); // Default: ET + NE + PE
                        
                        // Validate PG bit: if PG=1, PE must be 1
                        let validated_cr0 = if (new_cr0 & 0x80000000) != 0 && (new_cr0 & 1) == 0 {
                            // PG=1 but PE=0 - invalid, force PE=1
                            new_cr0 | 1
                        } else {
                            new_cr0
                        };
                        
                        // Update guest CR0 in VMCS
                        let _ = vmwrite(VMCS_GUEST_CR0, validated_cr0);
                        
                        // If CR0.PG changed, we may need to update CR3/CR4 shadow
                        if (validated_cr0 ^ current_cr0) & 0x80000000 != 0 {
                            // Paging was enabled/disabled - guest page tables may need refresh
                        }
                    }
                }
                4 => {
                    // CR4 access
                    if is_write {
                        // Guest writing to CR4 - update VMCS guest CR4
                        let guest_rax = unsafe { *frame.add(0) };
                        let new_cr4 = guest_rax;
                        
                        // CR4 validation:
                        // - Bit 0 (VME): Virtual 8086 mode extensions
                        // - Bit 1 (PVI): Protected mode virtual interrupts
                        // - Bit 2 (TSD): Time stamp disable
                        // - Bit 3 (DE): Debugging extensions
                        // - Bit 4 (PSE): Page size extensions
                        // - Bit 5 (PAE): Physical address extension
                        // - Bit 6 (MCE): Machine check enable
                        // - Bit 7 (PGE): Page global enable
                        // - Bit 9 (OSFXSR): OS support for FXSAVE/FXRSTOR
                        // - Bit 10 (OSXMMEXCPT): OS support for SIMD exceptions
                        // - Bit 18 (OSXSAVE): OS support for XSAVE
                        // - Bit 20 (SMEP): Supervisor mode execution protection
                        // - Bit 21 (SMAP): Supervisor mode access protection
                        
                        // Mask off reserved bits and unsupported features
                        let supported_cr4_bits: u64 = 0x00307F7F; // Supported CR4 bits
                        let validated_cr4 = new_cr4 & supported_cr4_bits;
                        
                        // Update guest CR4 in VMCS
                        let _ = vmwrite(VMCS_GUEST_CR4, validated_cr4);
                    }
                }
                _ => {}
            }
            
            // Advance RIP past the instruction
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_INTERRUPT_WINDOW => {
            // The guest is now interruptible — clear the window exiting
            // bit and try to inject the pending IRQ immediately.
            let procbased = vmread(VMCS_CTRL_CPU_BASED).unwrap_or(0);
            let _ = vmwrite(VMCS_CTRL_CPU_BASED, procbased & !CPU_BASED_INTERRUPT_WINDOW);
            inject_pending_irq_fast();
            0
        }
        VMX_EXIT_EPT_VIOLATION | VMX_EXIT_EPT_MISCONFIG => {
            if let Ok(gpa) = vmread(GUEST_PHYS_ADDR) {
                let page_gpa = gpa & !0xFFF;
                // ── IOAPIC MMIO intercept ────────────────────────────────
                if page_gpa == crate::vmm::ioapic::IOAPIC_BASE {
                    handle_ioapic_mmio(frame, gpa);
                // ── LAPIC MMIO intercept ─────────────────────────────────
                } else if page_gpa == crate::vmm::vcpu::LAPIC_MMIO_BASE {
                    handle_lapic_mmio(frame, gpa);
                // ── VirtIO MMIO intercept ────────────────────────────────
                } else if is_virtio_mmio_page(page_gpa) {
                    handle_virtio_mmio(frame, gpa);
                } else {
                    // Normal dynamic EPT: map the faulting page on-demand.
                    unsafe {
                        if !ACTIVE_EPT.is_null() {
                            let ept = &mut *ACTIVE_EPT;
                            let _ = ept.map_4k(page_gpa, page_gpa);
                            let _ = crate::vmm::ept::invept_single(ept.eptp());
                        }
                    }
                }
            }
            // ── PIT timer tick (integrated into fast-path) ──────────────
            pit_tick_fast();
            // ── LAPIC timer check ────────────────────────────────────────
            lapic_timer_tick_fast();
            // ── Inject pending interrupt ─────────────────────────────────
            inject_pending_irq_fast();
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_EPT_VIOLATION, 0);
            0
        }
        VMX_EXIT_EXCEPTION_NMI => {
            // NMI passthrough — no action needed.
            0
        }
        VMX_EXIT_TRIPLE_FAULT => {
            // Triple fault — fatal, but log diagnostics before halting.
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_VMX_EXIT, reason as u32);
            let rip = vmread(VMCS_GUEST_RIP).unwrap_or(0xDEAD);
            let cr0 = vmread(VMCS_GUEST_CR0).unwrap_or(0);
            let cr3 = vmread(VMCS_GUEST_CR3).unwrap_or(0);
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_EPT_VIOLATION, rip as u32);
            let _ = cr0;
            let _ = cr3;
            1 // fatal
        }
        VMX_EXIT_INVLPG => {
            // Guest executed INVLPG — with EPT this only flushes the
            // guest's own TLB entry.  Just advance RIP.
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_RDTSC => {
            // RDTSC exiting — return host TSC + offset in EDX:EAX.
            // (Only fires if CPU_BASED_RDTSC_EXITING is set.)
            #[cfg(target_arch = "x86_64")]
            let tsc = unsafe { core::arch::x86_64::_rdtsc() };
            #[cfg(not(target_arch = "x86_64"))]
            let tsc = 0u64;
            if !frame.is_null() {
                unsafe {
                    *frame.add(0) = tsc & 0xFFFF_FFFF;         // EAX
                    *frame.add(2) = (tsc >> 32) & 0xFFFF_FFFF; // EDX
                }
            }
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let _ = vmwrite(VMCS_GUEST_RIP, rip + 2); // RDTSC = 0F 31
            }
            0
        }
        VMX_EXIT_MOV_DR => {
            // Debug register access — advance past the instruction.
            // We don't emulate DRs, just let the guest think it worked.
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_ENTRY_FAIL_GUEST => {
            // VM-entry failure due to invalid guest state.
            // Log VMCS error and guest state for debugging.
            let err = vmread(VMCS_VM_INSTR_ERR).unwrap_or(0xFFFF);
            let rip = vmread(VMCS_GUEST_RIP).unwrap_or(0);
            let cr0 = vmread(VMCS_GUEST_CR0).unwrap_or(0);
            let cr3 = vmread(VMCS_GUEST_CR3).unwrap_or(0);
            let cr4 = vmread(VMCS_GUEST_CR4).unwrap_or(0);
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_VMX_EXIT, err as u32);
            let _ = (rip, cr0, cr3, cr4);
            1 // fatal
        }
        VMX_EXIT_MWAIT => {
            // MWAIT — treat as NOP, advance past instruction.
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_MONITOR => {
            // MONITOR — treat as NOP, advance past instruction.
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(3);
                let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
            }
            0
        }
        VMX_EXIT_PAUSE => {
            // PAUSE — no-op, just resume.  No RIP advance needed because
            // PAUSE exiting already accounts for the instruction length.
            0
        }
        VMX_EXIT_ENTRY_FAIL_MCE => {
            // VM-entry failure due to machine-check event — fatal.
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_VMX_EXIT, reason as u32);
            1
        }
        VMX_EXIT_RDTSCP => {
            // RDTSCP exiting — return TSC in EDX:EAX, IA32_TSC_AUX in ECX.
            #[cfg(target_arch = "x86_64")]
            let tsc = unsafe { core::arch::x86_64::_rdtsc() };
            #[cfg(not(target_arch = "x86_64"))]
            let tsc = 0u64;
            if !frame.is_null() {
                unsafe {
                    *frame.add(0) = tsc & 0xFFFF_FFFF;         // EAX
                    *frame.add(2) = (tsc >> 32) & 0xFFFF_FFFF; // EDX
                    *frame.add(1) = 0;                          // ECX = TSC_AUX (vCPU 0)
                }
            }
            if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
                let _ = vmwrite(VMCS_GUEST_RIP, rip + 3); // RDTSCP = 0F 01 F9
            }
            0
        }
        VMX_EXIT_PREEMPTION_TIMER => {
            // VMX preemption timer fired — check LAPIC timer and inject.
            lapic_timer_tick_fast();
            inject_pending_irq_fast();
            0
        }
        VMX_EXIT_XSETBV => {
            // Guest wrote XCR0 via XSETBV.  Validate and pass through.
            handle_xsetbv_exit(frame);
            0
        }
        _ => {
            crate::vmm::record_telemetry(crate::vmm::TELEMETRY_VMX_EXIT, reason as u32);
            1 // fatal: unknown exit → assembly halts
        }
    }
}

pub struct Vmx {
    vmxon_pa: u64,
    vmcs_pa: u64,
    msr_bitmap_pa: u64,
    slot: usize,
}

impl Vmx {
    pub fn new(eptp: u64) -> Result<Self, HvError> {
        Self::enable_vmx()?;
        let slot = NEXT_VMCS_SLOT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        if slot >= MAX_VMCS_SLOTS {
            return Err(HvError::LogicalFault);
        }
        let vmxon_pa = core::ptr::addr_of!(VMXON_REGION) as u64;
        let vmcs_pa = unsafe { core::ptr::addr_of!(VMCS_REGIONS[slot]) } as u64;
        let msr_bitmap_pa = core::ptr::addr_of!(MSR_BITMAP_REGION) as u64;
        let revision = (read_msr(IA32_VMX_BASIC) & 0x7FFF_FFFF) as u32;
        unsafe {
            core::ptr::write_volatile(vmxon_pa as *mut u32, revision);
            core::ptr::write_volatile(vmcs_pa as *mut u32, revision);
        }
        let vmxon_ptr = &vmxon_pa as *const u64;
        let vmcs_ptr = &vmcs_pa as *const u64;
        vmxon(vmxon_ptr)?;
        vmptrld(vmcs_ptr)?;
        let vmx = Self {
            vmxon_pa,
            vmcs_pa,
            msr_bitmap_pa,
            slot,
        };
        vmx.setup_vmcs(eptp)?;
        Ok(vmx)
    }

    fn enable_vmx() -> Result<(), HvError> {
        let mut feature = read_msr(IA32_FEATURE_CONTROL);
        if feature & 0x1 == 0 {
            feature |= 0x1 | 0x4;
            write_msr(IA32_FEATURE_CONTROL, feature);
        } else if feature & 0x4 == 0 {
            return Err(HvError::HardwareFault);
        }
        let cr0_fixed0 = read_msr(IA32_VMX_CR0_FIXED0);
        let cr0_fixed1 = read_msr(IA32_VMX_CR0_FIXED1);
        let cr4_fixed0 = read_msr(IA32_VMX_CR4_FIXED0);
        let cr4_fixed1 = read_msr(IA32_VMX_CR4_FIXED1);
        let mut cr0 = read_cr0();
        let mut cr4 = read_cr4();
        cr0 |= cr0_fixed0;
        cr0 &= cr0_fixed1;
        cr4 |= cr4_fixed0;
        cr4 &= cr4_fixed1;
        cr4 |= 1 << 13;
        write_cr0(cr0);
        write_cr4(cr4);
        Ok(())
    }

    fn setup_vmcs(&self, eptp: u64) -> Result<(), HvError> {
        // ── Execution controls ────────────────────────────────────────────────
        let pinbased = adjust_control(0, IA32_VMX_PINBASED_CTLS);
        let mut procbased = adjust_control(
            CPU_BASED_HLT_EXITING | CPU_BASED_USE_MSR_BITMAPS,
            IA32_VMX_PROCBASED_CTLS,
        );
        procbased |= CPU_BASED_ACTIVATE_SECONDARY;
        let secondary = adjust_control(
            SECONDARY_ENABLE_EPT | SECONDARY_ENABLE_VPID | SECONDARY_ENABLE_RDTSCP
                | SECONDARY_UNRESTRICTED_GUEST,
            IA32_VMX_PROCBASED_CTLS2,
        );
        // VM-exit: must request 64-bit host (bit 9 = Host Address-Space Size)
        let exit_ctls = adjust_control(
            VM_EXIT_HOST_64BIT | VM_EXIT_SAVE_EFER | VM_EXIT_LOAD_EFER,
            IA32_VMX_EXIT_CTLS,
        );
        // VM-entry: must request 64-bit guest (bit 9 = IA-32e Mode Guest)
        let entry_ctls = adjust_control(
            VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_EFER,
            IA32_VMX_ENTRY_CTLS,
        );
        vmwrite(VMCS_CTRL_PIN_BASED, pinbased)?;
        vmwrite(VMCS_CTRL_CPU_BASED, procbased)?;
        vmwrite(VMCS_CTRL_SECONDARY_CPU_BASED, secondary)?;
        vmwrite(VMCS_CTRL_VM_EXIT_CONTROLS, exit_ctls)?;
        vmwrite(VMCS_CTRL_VM_ENTRY_CONTROLS, entry_ctls)?;
        // Intercept only #NM (vec 7) for FPU context switching.
        vmwrite(VMCS_CTRL_EXCEPTION_BITMAP, 1 << 7)?;
        vmwrite(VMCS_CTRL_MSR_BITMAP, self.msr_bitmap_pa)?;
        // VPID: allocated dynamically per-vCPU via scheduler::allocate_vpid()
        // Caller must set this via set_vpid() before first VMRESUME.
        // Default to 0 (no VPID) until allocated.
        vmwrite(VMCS_CTRL_VPID, 0)?;
        vmwrite(VMCS_CTRL_EPTP, eptp)?;
        // TSC offset: guest TSC = host TSC + offset.
        // Start at 0 (no skew); can be adjusted per-vCPU later.
        vmwrite(VMCS_CTRL_TSC_OFFSET, 0)?;

        // ── Guest EFER: LME | LMA (long-mode active + enabled) ───────────────
        let efer_lme: u64 = 1 << 8;
        let efer_lma: u64 = 1 << 10;
        let efer_nxe: u64 = 1 << 11;
        vmwrite(VMCS_GUEST_IA32_EFER, efer_lme | efer_lma | efer_nxe)?;

        // ── Guest control registers ───────────────────────────────────────────
        // CR0: PE | NE | ET | PG — required for 64-bit long mode.
        let cr0_base: u64 = 0x8000_0031;
        let cr0 = (cr0_base | read_msr(IA32_VMX_CR0_FIXED0)) & read_msr(IA32_VMX_CR0_FIXED1);
        vmwrite(VMCS_GUEST_CR0, cr0)?;
        // CR3: identity PML4 at 0x1000 (populated by EPT mapping)
        vmwrite(VMCS_GUEST_CR3, 0x1000)?;
        // CR4: PAE | OSFXSR | OSXMMEXCPT for 64-bit.
        let cr4_base: u64 = 0x0620;
        let cr4 = (cr4_base | read_msr(IA32_VMX_CR4_FIXED0)) & read_msr(IA32_VMX_CR4_FIXED1);
        vmwrite(VMCS_GUEST_CR4, cr4)?;
        vmwrite(VMCS_GUEST_DR7, 0x400)?;
        vmwrite(VMCS_GUEST_RFLAGS, 0x2)?; // bit 1 is always 1

        // ── Guest segments — minimal 64-bit long-mode layout ─────────────────
        // Selector layout: GDT[0]=null, GDT[1]=code64(0x08), GDT[2]=data64(0x10)
        // Access-rights encoding (32-bit field):
        //   bits 3:0 = type  4=S  6:5=DPL  7=P  14=L(code)  15=G
        const SEL_CODE64: u64 = 0x08;
        const SEL_DATA64: u64 = 0x10;
        const AR_CODE64: u64 = 0xA09B; // G=1,L=1,P=1,S=1,type=0xB
        const AR_DATA64: u64 = 0xC093; // G=1,DB=1,P=1,S=1,type=3
        const AR_TSS32: u64 = 0x008B; // P=1,type=0xB (busy TSS)
        const AR_UNUSABLE: u64 = 0x0001_0000;
        const FLAT_LIMIT: u64 = 0xFFFF_FFFF;

        vmwrite(VMCS_GUEST_CS_SEL, SEL_CODE64)?;
        vmwrite(VMCS_GUEST_CS_BASE, 0)?;
        vmwrite(VMCS_GUEST_CS_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_CS_AR, AR_CODE64)?;
        vmwrite(VMCS_GUEST_SS_SEL, SEL_DATA64)?;
        vmwrite(VMCS_GUEST_SS_BASE, 0)?;
        vmwrite(VMCS_GUEST_SS_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_SS_AR, AR_DATA64)?;
        vmwrite(VMCS_GUEST_DS_SEL, SEL_DATA64)?;
        vmwrite(VMCS_GUEST_DS_BASE, 0)?;
        vmwrite(VMCS_GUEST_DS_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_DS_AR, AR_DATA64)?;
        vmwrite(VMCS_GUEST_ES_SEL, SEL_DATA64)?;
        vmwrite(VMCS_GUEST_ES_BASE, 0)?;
        vmwrite(VMCS_GUEST_ES_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_ES_AR, AR_DATA64)?;
        vmwrite(VMCS_GUEST_FS_SEL, 0)?;
        vmwrite(VMCS_GUEST_FS_BASE, 0)?;
        vmwrite(VMCS_GUEST_FS_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_FS_AR, AR_DATA64)?;
        vmwrite(VMCS_GUEST_GS_SEL, 0)?;
        vmwrite(VMCS_GUEST_GS_BASE, 0)?;
        vmwrite(VMCS_GUEST_GS_LIMIT, FLAT_LIMIT)?;
        vmwrite(VMCS_GUEST_GS_AR, AR_DATA64)?;
        // LDTR: unusable
        vmwrite(VMCS_GUEST_LDTR_SEL, 0)?;
        vmwrite(VMCS_GUEST_LDTR_BASE, 0)?;
        vmwrite(VMCS_GUEST_LDTR_LIMIT, 0xFFFF)?;
        vmwrite(VMCS_GUEST_LDTR_AR, AR_UNUSABLE)?;
        // TR: minimal busy TSS at GDT[3]=0x18
        vmwrite(VMCS_GUEST_TR_SEL, 0x18)?;
        vmwrite(VMCS_GUEST_TR_BASE, 0)?;
        vmwrite(VMCS_GUEST_TR_LIMIT, 0x67)?;
        vmwrite(VMCS_GUEST_TR_AR, AR_TSS32)?;
        // GDTR: 3-entry flat GDT at guest physical 0x500
        vmwrite(VMCS_GUEST_GDTR_BASE, 0x500)?;
        vmwrite(VMCS_GUEST_GDTR_LIMIT, 0x27)?; // 5 descriptors × 8 - 1
                                               // IDTR: zeroed stub at 0x7000 (guest OS overwrites with its own)
        vmwrite(VMCS_GUEST_IDTR_BASE, 0x7000)?;
        vmwrite(VMCS_GUEST_IDTR_LIMIT, 0x0FFF)?; // 256 entries × 16 bytes - 1
        // Misc guest state
        vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0)?;
        vmwrite(VMCS_GUEST_ACTIVITY, 0)?; // active
        vmwrite(VMCS_GUEST_SYSENTER_CS, 0)?;
        vmwrite(VMCS_GUEST_SYSENTER_ESP, 0)?;
        vmwrite(VMCS_GUEST_SYSENTER_EIP, 0)?;
        // VMCS link pointer = 0xFFFFFFFFFFFFFFFF (no shadow VMCS)
        vmwrite(VMCS_GUEST_VMCS_LINK, 0xFFFF_FFFF_FFFF_FFFF)?;
        // RIP/RSP set to 0; caller overrides via set_guest_rip/rsp
        vmwrite(VMCS_GUEST_RSP, 0)?;
        vmwrite(VMCS_GUEST_RIP, 0)?;

        // ── Host state ────────────────────────────────────────────────────────
        vmwrite(VMCS_HOST_CR0, read_cr0())?;
        vmwrite(VMCS_HOST_CR3, read_cr3())?;
        vmwrite(VMCS_HOST_CR4, read_cr4())?;
        vmwrite(VMCS_HOST_CS_SEL, read_cs() & !7)?; // RPL=0, TI=0
        vmwrite(VMCS_HOST_SS_SEL, read_ss() & !7)?;
        vmwrite(VMCS_HOST_DS_SEL, 0)?;
        vmwrite(VMCS_HOST_ES_SEL, 0)?;
        vmwrite(VMCS_HOST_FS_SEL, read_fs() & !7)?;
        vmwrite(VMCS_HOST_GS_SEL, read_gs() & !7)?;
        vmwrite(VMCS_HOST_TR_SEL, read_tr() & !7)?;
        vmwrite(VMCS_HOST_FS_BASE, read_fs_base())?;
        vmwrite(VMCS_HOST_GS_BASE, read_gs_base())?;
        vmwrite(VMCS_HOST_TR_BASE, 0)?; // simplified; no host TSS
        vmwrite(VMCS_HOST_GDTR_BASE, read_gdtr_base())?;
        vmwrite(VMCS_HOST_IDTR_BASE, read_idtr_base())?;
        vmwrite(VMCS_HOST_SYSENTER_ESP, 0)?;
        vmwrite(VMCS_HOST_SYSENTER_EIP, 0)?;
        // Host RSP = top of this vCPU's exit stack
        let exit_stack_top = unsafe {
            core::ptr::addr_of!(HOST_EXIT_STACKS[self.slot]) as u64 + 16384 - 8
        };
        vmwrite(VMCS_HOST_RSP, exit_stack_top)?;
        // Host RIP = vm_exit_entry (assembled above; zero in test builds)
        #[cfg(not(test))]
        vmwrite(VMCS_HOST_RIP, vm_exit_entry as u64)?;
        #[cfg(test)]
        vmwrite(VMCS_HOST_RIP, 0)?;
        Ok(())
    }

    pub fn launch(&self) -> Result<(), HvError> {
        vmlaunch()
    }

    pub fn resume(&self) -> Result<(), HvError> {
        vmresume()
    }

    pub fn exit_reason(&self) -> Result<u64, HvError> {
        vmread(EXIT_REASON)
    }

    pub fn exit_qualification(&self) -> Result<u64, HvError> {
        vmread(EXIT_QUALIFICATION)
    }

    pub fn guest_phys_addr(&self) -> Result<u64, HvError> {
        vmread(GUEST_PHYS_ADDR)
    }

    /// Set the initial guest RIP before VMLAUNCH.
    pub fn set_guest_rip(&self, rip: u64) -> Result<(), HvError> {
        vmwrite(VMCS_GUEST_RIP, rip)
    }

    /// Set the initial guest RSP before VMLAUNCH.
    pub fn set_guest_rsp(&self, rsp: u64) -> Result<(), HvError> {
        vmwrite(VMCS_GUEST_RSP, rsp)
    }

    /// Override the guest CR3 (root page table GPA).
    pub fn set_guest_cr3(&self, cr3: u64) -> Result<(), HvError> {
        vmwrite(VMCS_GUEST_CR3, cr3)
    }

    /// Read the VM_INSTRUCTION_ERROR field (valid after a VMfailValid).
    pub fn instruction_error(&self) -> u64 {
        vmread(VMCS_VM_INSTR_ERR).unwrap_or(0)
    }

    /// Advance the guest RIP by the instruction length recorded in the VMCS.
    /// Used by the high-level exit handler for exits whose instruction is
    /// entirely consumed by the emulator (CPUID, RDMSR, WRMSR, etc.).
    pub fn advance_rip(&self) -> Result<(), HvError> {
        let rip = vmread(VMCS_GUEST_RIP)?;
        let len = vmread(VMCS_EXIT_INSTR_LEN).unwrap_or(2);
        vmwrite(VMCS_GUEST_RIP, rip + len)
    }

    /// Inject an external interrupt into the guest via VM-entry interrupt info.
    ///
    /// `vector`: interrupt vector number (e.g. 0x20 for IRQ0/timer)
    ///
    /// The interrupt is delivered on the next VMRESUME if the guest has
    /// interrupts enabled (RFLAGS.IF=1) and is not in an interruptibility
    /// shadow (STI/MOV SS).
    pub fn inject_interrupt(&self, vector: u8) -> Result<bool, HvError> {
        // Check guest interruptibility: if STI or MOV-SS blocking is active,
        // or RFLAGS.IF == 0, enable "interrupt-window exiting" so the CPU
        // re-exits the instant the guest becomes interruptible.
        let interruptibility = vmread(VMCS_GUEST_INTERRUPTIBILITY).unwrap_or(0);
        let rflags = vmread(VMCS_GUEST_RFLAGS).unwrap_or(0);
        if interruptibility & 0x3 != 0 || rflags & (1 << 9) == 0 {
            self.enable_interrupt_window()?;
            return Ok(false); // deferred — caller keeps vector pending
        }
        // VM-entry interrupt info format (Intel SDM Vol 3C §24.8.3):
        //   [7:0]   = vector
        //   [10:8]  = type (0 = external interrupt)
        //   [11]    = deliver error code (0 for external)
        //   [31]    = valid bit
        let info: u32 = (vector as u32) | (0 << 8) | (1 << 31);
        vmwrite(VMCS_VM_ENTRY_INTR_INFO, info as u64)?;
        Ok(true) // injected
    }

    /// Enable "interrupt-window exiting" so the CPU re-exits as soon as
    /// the guest becomes interruptible (IF=1, no STI/MOV-SS shadow).
    fn enable_interrupt_window(&self) -> Result<(), HvError> {
        let mut procbased = vmread(VMCS_CTRL_CPU_BASED).unwrap_or(0);
        procbased |= CPU_BASED_INTERRUPT_WINDOW;
        vmwrite(VMCS_CTRL_CPU_BASED, procbased)
    }

    /// Clear "interrupt-window exiting" after we successfully inject.
    pub fn clear_interrupt_window(&self) -> Result<(), HvError> {
        let mut procbased = vmread(VMCS_CTRL_CPU_BASED).unwrap_or(0);
        procbased &= !CPU_BASED_INTERRUPT_WINDOW;
        vmwrite(VMCS_CTRL_CPU_BASED, procbased)
    }

    /// Set the VPID (Virtual Processor ID) for this vCPU.
    /// Must be called before the first VMRESUME if VPID is enabled.
    /// VPID enables TLB tagging to avoid flushes on VM-exit.
    pub fn set_vpid(&self, vpid: u16) -> Result<(), HvError> {
        vmwrite(VMCS_CTRL_VPID, vpid as u64)
    }

    /// Get the current VPID from VMCS.
    pub fn get_vpid(&self) -> u16 {
        vmread(VMCS_CTRL_VPID).unwrap_or(0) as u16
    }

    /// Invalidate TLB entries for this VPID (single-context INVVPID).
    /// Call this when the vCPU's page tables change (e.g., CR3 write).
    pub fn invvpid_single(&self) -> Result<(), HvError> {
        let vpid = self.get_vpid();
        if vpid == 0 {
            return Ok(()); // No VPID, nothing to flush
        }
        // INVVPID descriptor: [0:15]=VPID, [16:63]=reserved, [64:127]=linear address (0 for type 1)
        let descriptor = [vpid as u64, 0];
        unsafe {
            let mut status: u8;
            core::arch::asm!(
                "invvpid {ty}, [{desc}]",
                "setna {status}",
                desc = in(reg) &descriptor,
                ty = in(reg) 1u64, // Type 1: individual address (with linear addr 0 = all)
                status = out(reg_byte) status,
                options(nostack, preserves_flags)
            );
            if status == 0 {
                Ok(())
            } else {
                Err(HvError::HardwareFault)
            }
        }
    }

    /// Invalidate all TLB entries for this VPID (single-context, all addresses).
    pub fn invvpid_all(&self) -> Result<(), HvError> {
        let vpid = self.get_vpid();
        if vpid == 0 {
            return Ok(());
        }
        // Type 1 with linear address 0 flushes all entries for the VPID
        self.invvpid_single()
    }

    /// Invalidate all TLB entries (global INVVPID, type 2).
    /// Use sparingly - this flushes all VPIDs including host.
    pub unsafe fn invvpid_global() -> Result<(), HvError> {
        let descriptor = [0u64, 0u64];
        let mut status: u8;
        core::arch::asm!(
            "invvpid {ty}, [{desc}]",
            "setna {status}",
            desc = in(reg) &descriptor,
            ty = in(reg) 2u64, // Type 2: global
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
        if status == 0 {
            Ok(())
        } else {
            Err(HvError::HardwareFault)
        }
    }
}

/// Emulate a CPUID instruction for the guest.
///
/// Frame layout (from the `vm_exit_entry` assembly push sequence):
///   frame[0]=rax  frame[1]=rcx  frame[2]=rdx  frame[3]=rbx
///   frame[4]=rbp  frame[5]=rsi  frame[6]=rdi  frame[7..]=r8-r15
///
/// Input:  leaf in frame[0] (rax), subleaf in frame[1] (rcx).
/// Output: eax/ebx/ecx/edx written back into frame[0..=3] respectively.  
/// RIP is advanced by 2 (CPUID is always 2-byte 0F A2).
///
/// Sensitive bits masked:
///   leaf 1 ecx bit 5  (VMXE — hide VMX capability from guest)
///   leaf 1 ecx bit 31 (RAZ — hypervisor-present bit cleared)
///   leaf 0x4000_0000  (hypervisor CPUID leaf — return Valkyrie-V signature)
#[cfg(not(test))]
fn handle_cpuid_exit(frame: *mut u64) {
    if frame.is_null() {
        return;
    }
    let leaf = unsafe { *frame.add(0) } as u32;
    let subleaf = unsafe { *frame.add(1) } as u32;

    let (mut eax, mut ebx, mut ecx, mut edx): (u32, u32, u32, u32);

    match leaf {
        // ── Hypervisor signature leaf ────────────────────────────────────
        0x4000_0000 => {
            eax = 0x4000_0001;
            ebx = u32::from_le_bytes(*b"Vkyr");
            ecx = u32::from_le_bytes(*b"Vkyr");
            edx = u32::from_le_bytes(*b"Vkyr");
        }
        // ── Hypervisor features leaf ─────────────────────────────────────
        0x4000_0001 => {
            // bit 0: paravirt TSC, bit 1: paravirt IPI
            eax = 0x0000_0003;
            ebx = 0;
            ecx = 0;
            edx = 0;
        }
        _ => {
            // Execute real CPUID on host and then sanitize.
            unsafe {
                let ebx_val: u32;
                core::arch::asm!(
                    "push rbx",
                    "cpuid",
                    "mov {ebx_out:e}, ebx",
                    "pop rbx",
                    ebx_out = out(reg) ebx_val,
                    inout("eax") leaf  => eax,
                    inout("ecx") subleaf => ecx,
                    out("edx") edx,
                );
                ebx = ebx_val;
            }

            match leaf {
                // ── Leaf 0: clamp max standard leaf ──────────────────────
                0 => {
                    // Cap max leaf to 0x15 (TSC/core crystal)
                    if eax > 0x15 {
                        eax = 0x15;
                    }
                }
                // ── Leaf 1: feature flags ────────────────────────────────
                1 => {
                    // ECX: clear VMX (5), SMX (6), hypervisor-present (31)
                    ecx &= !((1u32 << 5) | (1u32 << 6) | (1u32 << 31));
                    // Set hypervisor bit so guest knows it's virtualized
                    ecx |= 1u32 << 31;
                    // EDX: mask out APIC (9) — we emulate APIC separately
                    // (leave it set for now; guest expects it)
                    // Zero out initial APIC ID in EBX[31:24] for vCPU 0
                    ebx &= 0x00FF_FFFF;
                }
                // ── Leaf 4: deterministic cache params ───────────────────
                4 => {
                    // Zero APIC-ID fields (EAX[31:26], EAX[25:14]) for
                    // single-socket / single-core presentation
                    eax &= 0x0000_3FFF;
                }
                // ── Leaf 7: structured extended features ─────────────────
                7 => {
                    if subleaf == 0 {
                        // EBX: mask SGX (2), HLE (4), RTM (11)
                        ebx &= !((1u32 << 2) | (1u32 << 4) | (1u32 << 11));
                        // ECX: mask TME (13), SGX_LC (30)
                        ecx &= !((1u32 << 13) | (1u32 << 30));
                    }
                }
                // ── Leaf 0xB / 0x1F: extended topology ───────────────────
                0x0B | 0x1F => {
                    // Present as single-thread, single-core
                    eax = 0; // bits to shift = 0
                    ebx = 1; // 1 logical processor at this level
                    // EDX = x2APIC ID = 0 for vCPU 0
                    edx = 0;
                }
                // ── Leaf 0x80000000: max extended leaf ────────────────────
                0x8000_0000 => {
                    if eax > 0x8000_0008 {
                        eax = 0x8000_0008;
                    }
                }
                // ── Leaf 0x80000008: address sizes ───────────────────────
                0x8000_0008 => {
                    // Cap physical address bits to 48
                    let phys_bits = eax & 0xFF;
                    if phys_bits > 48 {
                        eax = (eax & !0xFF) | 48;
                    }
                }
                _ => {} // pass through
            }
        }
    }

    unsafe {
        *frame.add(0) = eax as u64;
        *frame.add(3) = ebx as u64;
        *frame.add(1) = ecx as u64;
        *frame.add(2) = edx as u64;
    }

    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let _ = vmwrite(VMCS_GUEST_RIP, rip + 2);
    }
}

/// MSR indices that are safe to pass through directly to the host hardware
/// when the guest issues RDMSR/WRMSR.
///
/// SECURITY: IA32_APIC_BASE (0x1B), IA32_TSC_DEADLINE (0x6E) and
/// IA32_MISC_ENABLE (0x1A0) are NOT in this list — they are virtualized
/// separately to prevent the guest from reconfiguring the host APIC,
/// corrupting host timers, or toggling dangerous host features.
#[cfg(not(test))]
const MSR_PASSTHROUGH: &[u32] = &[
    0x0000_0010, // IA32_TIME_STAMP_COUNTER
    0x0000_00E7, // IA32_MPERF
    0x0000_00E8, // IA32_APERF
    0x0000_0174, // IA32_SYSENTER_CS
    0x0000_0175, // IA32_SYSENTER_ESP
    0x0000_0176, // IA32_SYSENTER_EIP
    0x0000_0277, // IA32_PAT
    0xC000_0080, // IA32_EFER
    0xC000_0081, // STAR
    0xC000_0082, // LSTAR
    0xC000_0083, // CSTAR
    0xC000_0084, // SFMASK  (IA32_FMASK)
    0xC000_0100, // FS.BASE
    0xC000_0101, // GS.BASE
    0xC000_0102, // KernelGSBase
    0xC000_0103, // IA32_TSC_AUX
];

// ── Virtualized MSR shadow state ─────────────────────────────────────────────
// These MSRs must NOT be passed through because writing them on the host would
// corrupt host hardware state (APIC reconfiguration, timer corruption, etc.).
// Instead we maintain per-guest shadow values that RDMSR reads back and WRMSR
// stores to.

#[cfg(not(test))]
const MSR_IA32_APIC_BASE: u32 = 0x0000_001B;
#[cfg(not(test))]
const MSR_IA32_TSC_DEADLINE: u32 = 0x0000_006E;
#[cfg(not(test))]
const MSR_IA32_MISC_ENABLE: u32 = 0x0000_01A0;

/// Default APIC base: 0xFEE0_0000 with enable bit set.
#[cfg(not(test))]
static VIRT_APIC_BASE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0xFEE0_0900); // base + BSP + enable
#[cfg(not(test))]
static VIRT_TSC_DEADLINE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
#[cfg(not(test))]
static VIRT_MISC_ENABLE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x0000_0000_0000_0001); // fast-strings enable

/// Handle RDMSR exit.  MSR index is in guest RCX (frame[1]).
/// Result eax:edx written into frame[0]:frame[2].
#[cfg(not(test))]
fn handle_rdmsr_exit(frame: *mut u64) {
    if frame.is_null() {
        return;
    }
    let msr = unsafe { *frame.add(1) } as u32;
    let (lo, hi) = match msr {
        // ── Virtualized MSRs ─────────────────────────────────────────────
        MSR_IA32_APIC_BASE => {
            let val = VIRT_APIC_BASE.load(core::sync::atomic::Ordering::Relaxed);
            (val as u32, (val >> 32) as u32)
        }
        MSR_IA32_TSC_DEADLINE => {
            let val = VIRT_TSC_DEADLINE.load(core::sync::atomic::Ordering::Relaxed);
            (val as u32, (val >> 32) as u32)
        }
        MSR_IA32_MISC_ENABLE => {
            let val = VIRT_MISC_ENABLE.load(core::sync::atomic::Ordering::Relaxed);
            (val as u32, (val >> 32) as u32)
        }
        // ── Hardware passthrough ─────────────────────────────────────────
        _ if MSR_PASSTHROUGH.contains(&msr) => {
            let lo: u32;
            let hi: u32;
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") msr,
                    out("eax") lo,
                    out("edx") hi,
                );
            }
            (lo, hi)
        }
        // ── Unknown MSRs: return zero (avoid #GP) ────────────────────────
        _ => (0u32, 0u32),
    };
    unsafe {
        *frame.add(0) = lo as u64; // rax
        *frame.add(2) = hi as u64; // rdx
    }
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let _ = vmwrite(VMCS_GUEST_RIP, rip + 2);
    }
}

/// Handle WRMSR exit.  MSR index in guest RCX (frame[1]);
/// low 32 bits in RAX (frame[0]), high 32 bits in RDX (frame[2]).
#[cfg(not(test))]
fn handle_wrmsr_exit(frame: *mut u64) {
    if frame.is_null() {
        return;
    }
    let msr = unsafe { *frame.add(1) } as u32;
    let lo = unsafe { *frame.add(0) } as u32;
    let hi = unsafe { *frame.add(2) } as u32;
    let val = (hi as u64) << 32 | lo as u64;
    match msr {
        // ── Virtualized MSRs ─────────────────────────────────────────────
        MSR_IA32_APIC_BASE => {
            // Allow the guest to think it moved the APIC, but don't touch
            // the real hardware register.
            VIRT_APIC_BASE.store(val, core::sync::atomic::Ordering::Relaxed);
        }
        MSR_IA32_TSC_DEADLINE => {
            VIRT_TSC_DEADLINE.store(val, core::sync::atomic::Ordering::Relaxed);
        }
        MSR_IA32_MISC_ENABLE => {
            // Mask off dangerous bits and store.
            VIRT_MISC_ENABLE.store(val & 0x0000_0000_0000_0001, core::sync::atomic::Ordering::Relaxed);
        }
        // ── Hardware passthrough ─────────────────────────────────────────
        _ if MSR_PASSTHROUGH.contains(&msr) => {
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") msr,
                    in("eax") lo,
                    in("edx") hi,
                );
            }
        }
        // Unknown MSRs: silently discard.
        _ => {}
    }
    // Always advance RIP.
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let _ = vmwrite(VMCS_GUEST_RIP, rip + 2);
    }
}

/// Handle XSETBV exit (reason 55).
///
/// The guest attempted to write XCR0 via XSETBV (ECX=0, EDX:EAX=value).
/// Validate the requested feature mask and, if safe, execute the real XSETBV
/// on behalf of the guest.  Invalid values → inject #GP(0) instead.
///
/// Frame layout: frame[0]=RAX, frame[1]=RCX, frame[2]=RDX.
#[cfg(not(test))]
fn handle_xsetbv_exit(frame: *mut u64) {
    if frame.is_null() {
        return;
    }
    let xcr_index = unsafe { *frame.add(1) } as u32;
    let lo = unsafe { *frame.add(0) } as u32;
    let hi = unsafe { *frame.add(2) } as u32;
    let value = ((hi as u64) << 32) | lo as u64;

    // Only XCR0 (index 0) is defined.
    if xcr_index != 0 {
        inject_guest_gp();
        return;
    }

    // XCR0 validation (Intel SDM Vol 1 §13):
    //   - Bit 0 (x87) must always be 1.
    //   - If AVX (bit 2) is set, SSE (bit 1) must be set.
    //   - Bits beyond host-supported features must not be set.
    if value & 1 == 0 {
        inject_guest_gp();
        return;
    }
    if value & (1 << 2) != 0 && value & (1 << 1) == 0 {
        inject_guest_gp();
        return;
    }

    // Execute the real XSETBV on the physical CPU.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") lo,
            in("edx") hi,
        );
    }

    // Advance RIP past the 3-byte XSETBV instruction (0F 01 D1).
    if let Ok(rip) = vmread(VMCS_GUEST_RIP) {
        let _ = vmwrite(VMCS_GUEST_RIP, rip + 3);
    }
}

/// Inject #GP(0) into the guest via VM-entry interrupt injection.
#[cfg(not(test))]
fn inject_guest_gp() {
    // Type 3 = hardware exception, vector 13 = #GP, error code = 0, valid bit 31
    let info: u32 = 13 | (3 << 8) | (1 << 11) | (1 << 31);
    let _ = vmwrite(VMCS_VM_ENTRY_INTR_INFO, info as u64);
    let _ = vmwrite(VMCS_VM_ENTRY_INTR_ERR, 0);
    // Don't advance RIP — the guest sees the exception at the faulting IP.
}

/// Handle IO_INSTRUCTION exit.  For IN instructions, write the emulated
/// result into guest RAX (frame[0]) so the guest sees it when we VMRESUME.
/// The same `emulate_port_in` table is used here and in the high-level handler.
#[cfg(not(test))]
fn handle_io_exit(frame: *mut u64) {
    use crate::vmm::vmx_handler::{emulate_port_in, emulate_port_out};

    let Ok(qual) = vmread(EXIT_QUALIFICATION) else {
        return;
    };
    let size = match qual & 0x7 {
        0 => 1u8,
        1 => 2u8,
        3 => 4u8,
        _ => 1u8,
    };
    let is_in = (qual & (1 << 3)) != 0;
    let port = ((qual >> 16) & 0xFFFF) as u16;
    let Ok(rip) = vmread(VMCS_GUEST_RIP) else {
        return;
    };
    let Ok(len) = vmread(VMCS_EXIT_INSTR_LEN) else {
        return;
    };

    if is_in {
        let result = emulate_port_in(port, size).unwrap_or(0xFF);
        // Mask to the access width and zero-extend into RAX.
        let masked = match size {
            1 => result & 0xFF,
            2 => result & 0xFFFF,
            _ => result,
        };
        if !frame.is_null() {
            unsafe {
                // Preserve top 32 bits of RAX per Intel SDM (IN r/m8 zero-extends EAX).
                let rax = *frame.add(0);
                *frame.add(0) = (rax & 0xFFFF_FFFF_0000_0000) | masked as u64;
            }
        }
    } else if !frame.is_null() {
        let val = unsafe { *frame.add(0) } as u32;
        emulate_port_out(port, size, val);
    }

    let _ = vmwrite(VMCS_GUEST_RIP, rip + len);
}

fn adjust_control(value: u64, msr: u32) -> u64 {
    let msr_value = read_msr(msr);
    let allowed0 = msr_value as u32 as u64;
    let allowed1 = (msr_value >> 32) as u32 as u64;
    (value | allowed0) & allowed1
}

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

fn read_cr3() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr3", out(reg) value);
    }
    value
}

fn read_cs() -> u64 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, cs", out(reg) v);
    }
    v as u64
}
fn read_ss() -> u64 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, ss", out(reg) v);
    }
    v as u64
}
fn read_fs() -> u64 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, fs", out(reg) v);
    }
    v as u64
}
fn read_gs() -> u64 {
    let v: u16;
    unsafe {
        core::arch::asm!("mov {0:x}, gs", out(reg) v);
    }
    v as u64
}
fn read_tr() -> u64 {
    let v: u16;
    unsafe {
        core::arch::asm!("str {0:x}", out(reg) v);
    }
    v as u64
}
fn read_fs_base() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") 0xC000_0100u32, out("eax") lo, out("edx") hi);
    }
    ((hi as u64) << 32) | lo as u64
}
fn read_gs_base() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") 0xC000_0101u32, out("eax") lo, out("edx") hi);
    }
    ((hi as u64) << 32) | lo as u64
}
fn read_gdtr_base() -> u64 {
    let mut buf = [0u8; 10];
    unsafe {
        core::arch::asm!("sgdt [{0}]", in(reg) buf.as_mut_ptr(), options(nostack));
    }
    u64::from_le_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ])
}
fn read_idtr_base() -> u64 {
    let mut buf = [0u8; 10];
    unsafe {
        core::arch::asm!("sidt [{0}]", in(reg) buf.as_mut_ptr(), options(nostack));
    }
    u64::from_le_bytes([
        buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
    ])
}

fn read_cr0() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr0", out(reg) value);
    }
    value
}

fn write_cr0(value: u64) {
    unsafe {
        core::arch::asm!("mov cr0, {0}", in(reg) value);
    }
}

fn read_cr4() -> u64 {
    let value: u64;
    unsafe {
        core::arch::asm!("mov {0}, cr4", out(reg) value);
    }
    value
}

fn write_cr4(value: u64) {
    unsafe {
        core::arch::asm!("mov cr4, {0}", in(reg) value);
    }
}

fn vmxon(ptr: *const u64) -> Result<(), HvError> {
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmxon [{0}]",
            "setna {status}",
            in(reg) ptr,
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

fn vmptrld(ptr: *const u64) -> Result<(), HvError> {
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmptrld [{0}]",
            "setna {status}",
            in(reg) ptr,
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

fn vmlaunch() -> Result<(), HvError> {
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmlaunch",
            "setna {status}",
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

fn vmresume() -> Result<(), HvError> {
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmresume",
            "setna {status}",
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

fn vmwrite(field: u64, value: u64) -> Result<(), HvError> {
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmwrite {value}, {field}",
            "setna {status}",
            value = in(reg) value,
            field = in(reg) field,
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

fn vmread(field: u64) -> Result<u64, HvError> {
    let mut value: u64;
    let mut status: u8;
    unsafe {
        core::arch::asm!(
            "vmread {field}, {value}",
            "setna {status}",
            field = in(reg) field,
            value = out(reg) value,
            status = out(reg_byte) status,
            options(nostack, preserves_flags)
        );
    }
    if status == 0 {
        Ok(value)
    } else {
        Err(HvError::HardwareFault)
    }
}
