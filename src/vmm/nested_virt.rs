//! Nested Virtualization - L2 VM Support
//!
//! Virtual VMX/SVM for running hypervisors inside VMs.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Nested Virtualization Constants
// ─────────────────────────────────────────────────────────────────────────────

/// VMX instruction opcodes
pub mod vmx_instr {
    pub const VMCALL: u8 = 0x01;
    pub const VMLAUNCH: u8 = 0x02;
    pub const VMRESUME: u8 = 0x03;
    pub const VMCLEAR: u8 = 0x04;
    pub const VMPTRLD: u8 = 0x05;
    pub const VMPTRST: u8 = 0x06;
    pub const VMREAD: u8 = 0x07;
    pub const VMWRITE: u8 = 0x08;
    pub const VMXOFF: u8 = 0x09;
    pub const VMXON: u8 = 0x0A;
    pub const INVEPT: u8 = 0x0B;
    pub const INVVPID: u8 = 0x0C;
    pub const VMFUNC: u8 = 0x0D;
    pub const PMLCLEAR: u8 = 0x0E;
    pub const PMLLOG: u8 = 0x0F;
}

/// SVM instruction opcodes
pub mod svm_instr {
    pub const VMRUN: u8 = 0x01;
    pub const VMMCALL: u8 = 0x02;
    pub const VMLOAD: u8 = 0x03;
    pub const VMSAVE: u8 = 0x04;
    pub const CLGI: u8 = 0x05;
    pub const STGI: u8 = 0x06;
    pub const INVLPGA: u8 = 0x07;
    pub const SKINIT: u8 = 0x08;
    pub const NPF: u8 = 0x09;
}

/// VMCS field encodings (subset for nested)
pub mod vmcs_field {
    // 16-bit control
    pub const VPID: u32 = 0x0000;
    pub const POSTED_INTR_NV: u32 = 0x0002;
    pub const EPTP_INDEX: u32 = 0x0004;
    
    // 16-bit guest state
    pub const GUEST_ES_SEL: u32 = 0x0800;
    pub const GUEST_CS_SEL: u32 = 0x0802;
    pub const GUEST_SS_SEL: u32 = 0x0804;
    pub const GUEST_DS_SEL: u32 = 0x0806;
    pub const GUEST_FS_SEL: u32 = 0x0808;
    pub const GUEST_GS_SEL: u32 = 0x080A;
    pub const GUEST_LDTR_SEL: u32 = 0x080C;
    pub const GUEST_TR_SEL: u32 = 0x080E;
    pub const GUEST_INTR_STATUS: u32 = 0x0810;
    
    // 64-bit control
    pub const IO_BITMAP_A: u32 = 0x2000;
    pub const IO_BITMAP_B: u32 = 0x2002;
    pub const MSR_BITMAP: u32 = 0x2004;
    pub const EPTP: u32 = 0x201A;
    pub const EPTP_LIST: u32 = 0x2024;
    pub const PML_ADDRESS: u32 = 0x2028;
    
    // 64-bit guest state
    pub const VMCS_LINK_PTR: u32 = 0x2800;
    pub const GUEST_IA32_DEBUGCTL: u32 = 0x2802;
    pub const GUEST_IA32_PAT: u32 = 0x2804;
    pub const GUEST_IA32_EFER: u32 = 0x2806;
    pub const GUEST_IA32_PERF_CTL: u32 = 0x2808;
    pub const GUEST_PDPTR0: u32 = 0x280A;
    pub const GUEST_PDPTR1: u32 = 0x280C;
    pub const GUEST_PDPTR2: u32 = 0x280E;
    pub const GUEST_PDPTR3: u32 = 0x2810;
    
    // 32-bit control
    pub const PIN_BASED_CTLS: u32 = 0x4000;
    pub const PROC_BASED_CTLS: u32 = 0x4002;
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    pub const PF_ERROR_MASK: u32 = 0x4006;
    pub const PF_ERROR_MATCH: u32 = 0x4008;
    pub const CR3_TARGET_COUNT: u32 = 0x400A;
    pub const EXIT_CTLS: u32 = 0x400C;
    pub const EXIT_MSR_STORE_COUNT: u32 = 0x400E;
    pub const EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    pub const ENTRY_CTLS: u32 = 0x4012;
    pub const ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    pub const ENTRY_INTR_INFO: u32 = 0x4016;
    pub const ENTRY_EXCEPTION_ERROR: u32 = 0x4018;
    pub const ENTRY_INSTR_LEN: u32 = 0x401A;
    pub const TPR_THRESHOLD: u32 = 0x401C;
    pub const PROC_BASED_CTLS2: u32 = 0x401E;
    pub const PLE_GAP: u32 = 0x4020;
    pub const PLE_WINDOW: u32 = 0x4022;
    
    // 32-bit guest state
    pub const GUEST_ES_LIMIT: u32 = 0x4800;
    pub const GUEST_CS_LIMIT: u32 = 0x4802;
    pub const GUEST_SS_LIMIT: u32 = 0x4804;
    pub const GUEST_DS_LIMIT: u32 = 0x4806;
    pub const GUEST_FS_LIMIT: u32 = 0x4808;
    pub const GUEST_GS_LIMIT: u32 = 0x480A;
    pub const GUEST_LDTR_LIMIT: u32 = 0x480C;
    pub const GUEST_TR_LIMIT: u32 = 0x480E;
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;
    pub const GUEST_ES_AR: u32 = 0x4814;
    pub const GUEST_CS_AR: u32 = 0x4816;
    pub const GUEST_SS_AR: u32 = 0x4818;
    pub const GUEST_DS_AR: u32 = 0x481A;
    pub const GUEST_FS_AR: u32 = 0x481C;
    pub const GUEST_GS_AR: u32 = 0x481E;
    pub const GUEST_LDTR_AR: u32 = 0x4820;
    pub const GUEST_TR_AR: u32 = 0x4822;
    pub const GUEST_INTR_INFO: u32 = 0x4824;
    pub const GUEST_INTR_ERROR: u32 = 0x4826;
    pub const GUEST_ACT_STATE: u32 = 0x4828;
    pub const GUEST_SMBASE: u32 = 0x482A;
    pub const GUEST_IA32_SYSENTER_CS: u32 = 0x482C;
    
    // Natural-width guest state
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_ES_BASE: u32 = 0x6806;
    pub const GUEST_CS_BASE: u32 = 0x6808;
    pub const GUEST_SS_BASE: u32 = 0x680A;
    pub const GUEST_DS_BASE: u32 = 0x680C;
    pub const GUEST_FS_BASE: u32 = 0x680E;
    pub const GUEST_GS_BASE: u32 = 0x6810;
    pub const GUEST_LDTR_BASE: u32 = 0x6812;
    pub const GUEST_TR_BASE: u32 = 0x6814;
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    pub const GUEST_DR7: u32 = 0x681A;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;
    pub const GUEST_IA32_SYSENTER_ESP: u32 = 0x6822;
    pub const GUEST_IA32_SYSENTER_EIP: u32 = 0x6824;
}

/// Maximum nested VMCS per L1
pub const MAX_NESTED_VMCS: usize = 16;
/// Maximum L2 VMs per L1
pub const MAX_L2_VMS: usize = 16;

// ─────────────────────────────────────────────────────────────────────────────
// Virtual VMCS (VMCS12)
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual VMCS for L2 guest (VMCS12 format)
pub struct VirtualVmcs {
    /// VMCS revision ID
    pub revision_id: AtomicU32,
    /// VMX abort indicator
    pub vmx_abort: AtomicU32,
    /// VMCS data (field -> value mapping)
    pub fields: [AtomicU64; 512],
    /// VMCS is active
    pub active: AtomicBool,
    /// VMCS is launched
    pub launched: AtomicBool,
    /// VMCS is clear
    pub clear: AtomicBool,
    /// GPA of VMCS in L1 memory
    pub l1_gpa: AtomicU64,
    /// L2 VM ID
    pub l2_vm_id: AtomicU32,
}

impl VirtualVmcs {
    pub const fn new() -> Self {
        Self {
            revision_id: AtomicU32::new(0),
            vmx_abort: AtomicU32::new(0),
            fields: [const { AtomicU64::new(0) }; 512],
            active: AtomicBool::new(false),
            launched: AtomicBool::new(false),
            clear: AtomicBool::new(true),
            l1_gpa: AtomicU64::new(0),
            l2_vm_id: AtomicU32::new(0),
        }
    }

    /// Initialize VMCS
    pub fn init(&self, revision: u32, l1_gpa: u64) {
        self.revision_id.store(revision, Ordering::Release);
        self.l1_gpa.store(l1_gpa, Ordering::Release);
        self.active.store(true, Ordering::Release);
        self.clear.store(true, Ordering::Release);
        self.launched.store(false, Ordering::Release);
    }

    /// Read VMCS field
    pub fn read_field(&self, encoding: u32) -> u64 {
        let idx = Self::field_to_index(encoding);
        self.fields[idx].load(Ordering::Acquire)
    }

    /// Write VMCS field
    pub fn write_field(&self, encoding: u32, value: u64) {
        let idx = Self::field_to_index(encoding);
        self.fields[idx].store(value, Ordering::Release);
    }

    /// Convert field encoding to index
    fn field_to_index(encoding: u32) -> usize {
        // Simplified: use lower bits as index
        ((encoding >> 4) as usize) % 512
    }

    /// Clear VMCS
    pub fn clear(&self) {
        for field in &self.fields {
            field.store(0, Ordering::Release);
        }
        self.clear.store(true, Ordering::Release);
        self.launched.store(false, Ordering::Release);
    }

    /// Launch VMCS
    pub fn launch(&self) {
        self.clear.store(false, Ordering::Release);
        self.launched.store(true, Ordering::Release);
    }

    /// Resume VMCS
    pub fn resume(&self) {
        // Already launched
    }
}

impl Default for VirtualVmcs {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// L2 VM State
// ─────────────────────────────────────────────────────────────────────────────

/// L2 VM state
pub struct L2VmState {
    /// L2 VM ID
    pub vm_id: AtomicU32,
    /// Parent L1 VM ID
    pub l1_vm_id: AtomicU32,
    /// Associated VMCS
    pub vmcs_idx: AtomicU8,
    /// Active
    pub active: AtomicBool,
    /// Running
    pub running: AtomicBool,
    /// Exit pending
    pub exit_pending: AtomicBool,
    /// Exit reason
    pub exit_reason: AtomicU32,
    /// Exit qualification
    pub exit_qual: AtomicU64,
    /// Exit instruction length
    pub exit_instr_len: AtomicU32,
    /// Exit interruption info
    pub exit_intr_info: AtomicU32,
    /// Exit interruption error
    pub exit_intr_error: AtomicU32,
    /// IDT vectoring info
    pub idt_vectoring: AtomicU32,
    /// IDT vectoring error
    pub idt_vectoring_error: AtomicU32,
    /// Guest physical address (for exits)
    pub gpa: AtomicU64,
    /// VPID
    pub vpid: AtomicU16,
    /// EPTP
    pub eptp: AtomicU64,
    /// MSR bitmap GPA
    pub msr_bitmap: AtomicU64,
    /// IO bitmap A GPA
    pub io_bitmap_a: AtomicU64,
    /// IO bitmap B GPA
    pub io_bitmap_b: AtomicU64,
}

impl L2VmState {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            l1_vm_id: AtomicU32::new(0),
            vmcs_idx: AtomicU8::new(0),
            active: AtomicBool::new(false),
            running: AtomicBool::new(false),
            exit_pending: AtomicBool::new(false),
            exit_reason: AtomicU32::new(0),
            exit_qual: AtomicU64::new(0),
            exit_instr_len: AtomicU32::new(0),
            exit_intr_info: AtomicU32::new(0),
            exit_intr_error: AtomicU32::new(0),
            idt_vectoring: AtomicU32::new(0),
            idt_vectoring_error: AtomicU32::new(0),
            gpa: AtomicU64::new(0),
            vpid: AtomicU16::new(0),
            eptp: AtomicU64::new(0),
            msr_bitmap: AtomicU64::new(0),
            io_bitmap_a: AtomicU64::new(0),
            io_bitmap_b: AtomicU64::new(0),
        }
    }

    /// Initialize L2 VM
    pub fn init(&self, vm_id: u32, l1_vm_id: u32, vmcs_idx: u8) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.l1_vm_id.store(l1_vm_id, Ordering::Release);
        self.vmcs_idx.store(vmcs_idx, Ordering::Release);
        self.active.store(true, Ordering::Release);
    }

    /// Set exit information
    pub fn set_exit(&self, reason: u32, qual: u64, instr_len: u32) {
        self.exit_reason.store(reason, Ordering::Release);
        self.exit_qual.store(qual, Ordering::Release);
        self.exit_instr_len.store(instr_len, Ordering::Release);
        self.exit_pending.store(true, Ordering::Release);
    }

    /// Clear exit
    pub fn clear_exit(&self) {
        self.exit_pending.store(false, Ordering::Release);
    }
}

impl Default for L2VmState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Nested Virtualization Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Nested virtualization mode
pub mod nested_mode {
    pub const NONE: u8 = 0;
    pub const VMX: u8 = 1;
    pub const SVM: u8 = 2;
}

/// Nested virtualization controller
pub struct NestedController {
    /// Nested mode
    pub mode: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Virtual VMCS array
    pub vmcs: [VirtualVmcs; MAX_NESTED_VMCS],
    /// VMCS count
    pub vmcs_count: AtomicU8,
    /// Current VMCS pointer (L1 GPA)
    pub current_vmcs_ptr: AtomicU64,
    /// Current VMCS index
    pub current_vmcs_idx: AtomicU8,
    /// L2 VM states
    pub l2_vms: [L2VmState; MAX_L2_VMS],
    /// L2 VM count
    pub l2_vm_count: AtomicU8,
    /// Active L2 VM ID
    pub active_l2: AtomicU32,
    /// VMXON active
    pub vmxon_active: AtomicBool,
    /// VMX MSR shadow
    pub vmx_msr_shadow: [AtomicU64; 16],
    /// SVM MSR shadow
    pub svm_msr_shadow: [AtomicU64; 16],
    /// Nested exit count
    pub nested_exits: AtomicU64,
    /// Nested entry count
    pub nested_entries: AtomicU64,
    /// L2 instruction count
    pub l2_instr_count: AtomicU64,
}

impl NestedController {
    pub const fn new() -> Self {
        Self {
            mode: AtomicU8::new(nested_mode::NONE),
            enabled: AtomicBool::new(false),
            vmcs: [const { VirtualVmcs::new() }; MAX_NESTED_VMCS],
            vmcs_count: AtomicU8::new(0),
            current_vmcs_ptr: AtomicU64::new(0),
            current_vmcs_idx: AtomicU8::new(0xFF),
            l2_vms: [const { L2VmState::new() }; MAX_L2_VMS],
            l2_vm_count: AtomicU8::new(0),
            active_l2: AtomicU32::new(0),
            vmxon_active: AtomicBool::new(false),
            vmx_msr_shadow: [const { AtomicU64::new(0) }; 16],
            svm_msr_shadow: [const { AtomicU64::new(0) }; 16],
            nested_exits: AtomicU64::new(0),
            nested_entries: AtomicU64::new(0),
            l2_instr_count: AtomicU64::new(0),
        }
    }

    /// Enable nested virtualization
    pub fn enable(&mut self, mode: u8) {
        self.mode.store(mode, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable nested virtualization
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
        self.mode.store(nested_mode::NONE, Ordering::Release);
        self.vmxon_active.store(false, Ordering::Release);
    }

    /// VMXON instruction
    pub fn vmxon(&mut self, vmcs_gpa: u64) -> Result<(), HvError> {
        if self.vmxon_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.vmxon_active.store(true, Ordering::Release);
        Ok(())
    }

    /// VMXOFF instruction
    pub fn vmxoff(&mut self) -> Result<(), HvError> {
        if !self.vmxon_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.vmxon_active.store(false, Ordering::Release);
        self.current_vmcs_ptr.store(0, Ordering::Release);
        self.current_vmcs_idx.store(0xFF, Ordering::Release);
        Ok(())
    }

    /// VMCLEAR instruction
    pub fn vmclear(&mut self, vmcs_gpa: u64) -> Result<(), HvError> {
        let idx = self.find_or_create_vmcs(vmcs_gpa)?;
        self.vmcs[idx as usize].clear();
        
        if self.current_vmcs_ptr.load(Ordering::Acquire) == vmcs_gpa {
            self.current_vmcs_ptr.store(0, Ordering::Release);
            self.current_vmcs_idx.store(0xFF, Ordering::Release);
        }
        
        Ok(())
    }

    /// VMPTRLD instruction
    pub fn vmptrld(&mut self, vmcs_gpa: u64) -> Result<(), HvError> {
        if !self.vmxon_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let idx = self.find_or_create_vmcs(vmcs_gpa)?;
        self.current_vmcs_ptr.store(vmcs_gpa, Ordering::Release);
        self.current_vmcs_idx.store(idx, Ordering::Release);
        
        Ok(())
    }

    /// VMPTRST instruction
    pub fn vmptrst(&self) -> u64 {
        self.current_vmcs_ptr.load(Ordering::Acquire)
    }

    /// VMREAD instruction
    pub fn vmread(&self, encoding: u32) -> Result<u64, HvError> {
        let idx = self.current_vmcs_idx.load(Ordering::Acquire);
        if idx == 0xFF {
            return Err(HvError::LogicalFault);
        }
        
        Ok(self.vmcs[idx as usize].read_field(encoding))
    }

    /// VMWRITE instruction
    pub fn vmwrite(&self, encoding: u32, value: u64) -> Result<(), HvError> {
        let idx = self.current_vmcs_idx.load(Ordering::Acquire);
        if idx == 0xFF {
            return Err(HvError::LogicalFault);
        }
        
        self.vmcs[idx as usize].write_field(encoding, value);
        Ok(())
    }

    /// VMLAUNCH instruction
    pub fn vmlaunch(&mut self, l1_vm_id: u32) -> Result<u32, HvError> {
        if !self.vmxon_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let vmcs_idx = self.current_vmcs_idx.load(Ordering::Acquire);
        if vmcs_idx == 0xFF {
            return Err(HvError::LogicalFault);
        }
        
        let vmcs = &self.vmcs[vmcs_idx as usize];
        if vmcs.launched.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault); // Use VMRESUME
        }
        
        // Create L2 VM
        let l2_id = self.create_l2_vm(l1_vm_id, vmcs_idx)?;
        vmcs.launch();
        
        self.active_l2.store(l2_id, Ordering::Release);
        self.nested_entries.fetch_add(1, Ordering::Release);
        
        Ok(l2_id)
    }

    /// VMRESUME instruction
    pub fn vmresume(&mut self) -> Result<u32, HvError> {
        if !self.vmxon_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let vmcs_idx = self.current_vmcs_idx.load(Ordering::Acquire);
        if vmcs_idx == 0xFF {
            return Err(HvError::LogicalFault);
        }
        
        let vmcs = &self.vmcs[vmcs_idx as usize];
        if !vmcs.launched.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault); // Use VMLAUNCH
        }
        
        vmcs.resume();
        
        let l2_id = vmcs.l2_vm_id.load(Ordering::Acquire);
        self.active_l2.store(l2_id, Ordering::Release);
        self.nested_entries.fetch_add(1, Ordering::Release);
        
        Ok(l2_id)
    }

    /// VMCALL instruction (from L2)
    pub fn vmcall(&mut self) -> Result<(), HvError> {
        let l2_id = self.active_l2.load(Ordering::Acquire);
        if l2_id == 0 {
            return Err(HvError::LogicalFault);
        }
        
        // Inject VM exit to L1
        self.inject_vmexit(0x1B, 0, 0); // EXIT_REASON_VMCALL
        Ok(())
    }

    /// Inject VM exit to L1
    pub fn inject_vmexit(&mut self, reason: u32, qual: u64, instr_len: u32) {
        let l2_id = self.active_l2.load(Ordering::Acquire);
        if l2_id == 0 {
            return;
        }
        
        // Find L2 state
        for l2 in &self.l2_vms {
            if l2.vm_id.load(Ordering::Acquire) == l2_id {
                l2.set_exit(reason, qual, instr_len);
                break;
            }
        }
        
        self.active_l2.store(0, Ordering::Release);
        self.nested_exits.fetch_add(1, Ordering::Release);
    }

    /// Find or create VMCS
    fn find_or_create_vmcs(&mut self, gpa: u64) -> Result<u8, HvError> {
        // Check if VMCS already exists
        for i in 0..self.vmcs_count.load(Ordering::Acquire) as usize {
            if self.vmcs[i].l1_gpa.load(Ordering::Acquire) == gpa {
                return Ok(i as u8);
            }
        }
        
        // Create new VMCS
        let count = self.vmcs_count.load(Ordering::Acquire);
        if count as usize >= MAX_NESTED_VMCS {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count;
        self.vmcs[idx as usize].init(0x15, gpa); // Revision ID
        self.vmcs_count.fetch_add(1, Ordering::Release);
        
        Ok(idx)
    }

    /// Create L2 VM
    fn create_l2_vm(&mut self, l1_vm_id: u32, vmcs_idx: u8) -> Result<u32, HvError> {
        let count = self.l2_vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_L2_VMS {
            return Err(HvError::LogicalFault);
        }
        
        let l2_id = (count as u32 + 1) | (l1_vm_id << 16); // Encode parent
        let l2 = &self.l2_vms[count as usize];
        
        l2.init(l2_id, l1_vm_id, vmcs_idx);
        
        // Link VMCS to L2
        self.vmcs[vmcs_idx as usize].l2_vm_id.store(l2_id, Ordering::Release);
        
        self.l2_vm_count.fetch_add(1, Ordering::Release);
        Ok(l2_id)
    }

    /// Get nested statistics
    pub fn get_stats(&self) -> NestedStats {
        NestedStats {
            mode: self.mode.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
            vmcs_count: self.vmcs_count.load(Ordering::Acquire),
            l2_vm_count: self.l2_vm_count.load(Ordering::Acquire),
            nested_exits: self.nested_exits.load(Ordering::Acquire),
            nested_entries: self.nested_entries.load(Ordering::Acquire),
            l2_instr_count: self.l2_instr_count.load(Ordering::Acquire),
        }
    }
}

impl Default for NestedController {
    fn default() -> Self {
        Self::new()
    }
}

/// Nested virtualization statistics
#[repr(C)]
pub struct NestedStats {
    pub mode: u8,
    pub enabled: bool,
    pub vmcs_count: u8,
    pub l2_vm_count: u8,
    pub nested_exits: u64,
    pub nested_entries: u64,
    pub l2_instr_count: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// SVM Nested Virtualization (AMD)
// ─────────────────────────────────────────────────────────────────────────────

/// VMCB (Virtual Machine Control Block) for SVM
pub struct Vmcb {
    /// VMCB GPA in L1
    pub l1_gpa: AtomicU64,
    /// CR0
    pub cr0: AtomicU64,
    /// CR2
    pub cr2: AtomicU64,
    /// CR3
    pub cr3: AtomicU64,
    /// CR4
    pub cr4: AtomicU64,
    /// EFER
    pub efer: AtomicU64,
    /// RIP
    pub rip: AtomicU64,
    /// RSP
    pub rsp: AtomicU64,
    /// RFLAGS
    pub rflags: AtomicU64,
    /// DR6
    pub dr6: AtomicU64,
    /// DR7
    pub dr7: AtomicU64,
    /// CPL
    pub cpl: AtomicU8,
    /// Guest ASID
    pub asid: AtomicU32,
    /// Guest VPID
    pub vpid: AtomicU16,
    /// NP enable
    pub np_enabled: AtomicBool,
    /// NPT root
    pub npt_root: AtomicU64,
    /// Intercept vectors
    pub intercept_vec: [AtomicU32; 4],
    /// Valid
    pub valid: AtomicBool,
}

impl Vmcb {
    pub const fn new() -> Self {
        Self {
            l1_gpa: AtomicU64::new(0),
            cr0: AtomicU64::new(0),
            cr2: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            cr4: AtomicU64::new(0),
            efer: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            rsp: AtomicU64::new(0),
            rflags: AtomicU64::new(0),
            dr6: AtomicU64::new(0),
            dr7: AtomicU64::new(0),
            cpl: AtomicU8::new(0),
            asid: AtomicU32::new(0),
            vpid: AtomicU16::new(0),
            np_enabled: AtomicBool::new(false),
            npt_root: AtomicU64::new(0),
            intercept_vec: [const { AtomicU32::new(0) }; 4],
            valid: AtomicBool::new(false),
        }
    }

    /// Check intercept
    pub fn check_intercept(&self, vector: u8) -> bool {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        (self.intercept_vec[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }

    /// Set intercept
    pub fn set_intercept(&self, vector: u8, enable: bool) {
        let idx = (vector / 32) as usize;
        let bit = vector % 32;
        if enable {
            self.intercept_vec[idx].fetch_or(1 << bit, Ordering::Release);
        } else {
            self.intercept_vec[idx].fetch_and(!(1 << bit), Ordering::Release);
        }
    }
}

impl Default for Vmcb {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum VMCBs
pub const MAX_VMCB: usize = 16;

/// SVM nested controller
pub struct SvmNestedController {
    /// VMCBs
    pub vmcbs: [Vmcb; MAX_VMCB],
    /// VMCB count
    pub vmcb_count: AtomicU8,
    /// Current VMCB index
    pub current_vmcb: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Guest ASID counter
    pub asid_counter: AtomicU32,
    /// VMRUN count
    pub vmrun_count: AtomicU64,
    /// #VMEXIT count
    pub vmexit_count: AtomicU64,
}

impl SvmNestedController {
    pub const fn new() -> Self {
        Self {
            vmcbs: [const { Vmcb::new() }; MAX_VMCB],
            vmcb_count: AtomicU8::new(0),
            current_vmcb: AtomicU8::new(0xFF),
            enabled: AtomicBool::new(false),
            asid_counter: AtomicU32::new(1),
            vmrun_count: AtomicU64::new(0),
            vmexit_count: AtomicU64::new(0),
        }
    }

    /// Enable SVM nested
    pub fn enable(&mut self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// VMRUN instruction
    pub fn vmrun(&mut self, vmcb_gpa: u64) -> Result<u32, HvError> {
        let idx = self.find_or_create_vmcb(vmcb_gpa)?;
        self.current_vmcb.store(idx, Ordering::Release);
        self.vmrun_count.fetch_add(1, Ordering::Release);
        Ok(idx as u32)
    }

    /// VMLOAD instruction
    pub fn vmload(&mut self, vmcb_gpa: u64) -> Result<(), HvError> {
        let idx = self.find_or_create_vmcb(vmcb_gpa)?;
        // Load state from VMCB
        let _ = idx;
        Ok(())
    }

    /// VMSAVE instruction
    pub fn vmsave(&mut self, vmcb_gpa: u64) -> Result<(), HvError> {
        let idx = self.find_or_create_vmcb(vmcb_gpa)?;
        // Save state to VMCB
        let _ = idx;
        Ok(())
    }

    /// Inject #VMEXIT
    pub fn inject_vmexit(&mut self, exit_code: u64, exit_info1: u64, exit_info2: u64) {
        self.current_vmcb.store(0xFF, Ordering::Release);
        self.vmexit_count.fetch_add(1, Ordering::Release);
        let _ = (exit_code, exit_info1, exit_info2);
    }

    /// Find or create VMCB
    fn find_or_create_vmcb(&mut self, gpa: u64) -> Result<u8, HvError> {
        for i in 0..self.vmcb_count.load(Ordering::Acquire) as usize {
            if self.vmcbs[i].l1_gpa.load(Ordering::Acquire) == gpa {
                return Ok(i as u8);
            }
        }
        
        let count = self.vmcb_count.load(Ordering::Acquire);
        if count as usize >= MAX_VMCB {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count;
        let vmcb = &self.vmcbs[idx as usize];
        vmcb.l1_gpa.store(gpa, Ordering::Release);
        vmcb.asid.store(self.asid_counter.fetch_add(1, Ordering::Release), Ordering::Release);
        vmcb.valid.store(true, Ordering::Release);
        
        self.vmcb_count.fetch_add(1, Ordering::Release);
        Ok(idx)
    }

    /// Get statistics
    pub fn get_stats(&self) -> SvmNestedStats {
        SvmNestedStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vmcb_count: self.vmcb_count.load(Ordering::Acquire),
            vmrun_count: self.vmrun_count.load(Ordering::Acquire),
            vmexit_count: self.vmexit_count.load(Ordering::Acquire),
        }
    }
}

impl Default for SvmNestedController {
    fn default() -> Self {
        Self::new()
    }
}

/// SVM nested statistics
#[repr(C)]
pub struct SvmNestedStats {
    pub enabled: bool,
    pub vmcb_count: u8,
    pub vmrun_count: u64,
    pub vmexit_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_vmxon() {
        let mut nested = NestedController::new();
        nested.enable(nested_mode::VMX);
        
        nested.vmxon(0x1000).unwrap();
        assert!(nested.vmxon_active.load(Ordering::Acquire));
    }

    #[test]
    fn nested_vmclear() {
        let mut nested = NestedController::new();
        nested.enable(nested_mode::VMX);
        nested.vmxon(0x1000).unwrap();
        
        nested.vmclear(0x2000).unwrap();
        assert_eq!(nested.vmcs_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn nested_vmptrld() {
        let mut nested = NestedController::new();
        nested.enable(nested_mode::VMX);
        nested.vmxon(0x1000).unwrap();
        
        nested.vmptrld(0x2000).unwrap();
        assert_eq!(nested.current_vmcs_ptr.load(Ordering::Acquire), 0x2000);
    }

    #[test]
    fn nested_vmwrite() {
        let mut nested = NestedController::new();
        nested.enable(nested_mode::VMX);
        nested.vmxon(0x1000).unwrap();
        nested.vmptrld(0x2000).unwrap();
        
        nested.vmwrite(vmcs_field::GUEST_RIP, 0x10000).unwrap();
        let rip = nested.vmread(vmcs_field::GUEST_RIP).unwrap();
        assert_eq!(rip, 0x10000);
    }

    #[test]
    fn svm_vmrun() {
        let mut svm = SvmNestedController::new();
        svm.enable();
        
        svm.vmrun(0x1000).unwrap();
        assert_eq!(svm.vmrun_count.load(Ordering::Acquire), 1);
    }
}
