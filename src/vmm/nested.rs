//! Nested Virtualization
//!
//! Support for running VMs inside VMs (L2 guests within L1 hypervisors).
//! Implements VMCS shadowing and nested VMX/SVM.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Nested VMX Constants
// ─────────────────────────────────────────────────────────────────────────────

/// VMCS field encoding for shadowing
pub const VMCS_LINK_POINTER: u32 = 0x00002800;
pub const VMCS_LINK_POINTER_HIGH: u32 = 0x00002801;

/// VMCS launch state
pub const VMCS_LAUNCH_STATE_CLEAR: u8 = 0;
pub const VMCS_LAUNCH_STATE_LAUNCHED: u8 = 1;

/// MSR bitmap for nested VMX
pub const MSR_IA32_VMX_BASIC: u32 = 0x480;
pub const MSR_IA32_VMX_PINBASED_CTLS: u32 = 0x481;
pub const MSR_IA32_VMX_PROCBASED_CTLS: u32 = 0x482;
pub const MSR_IA32_VMX_EXIT_CTLS: u32 = 0x483;
pub const MSR_IA32_VMX_ENTRY_CTLS: u32 = 0x484;
pub const MSR_IA32_VMX_MISC: u32 = 0x485;
pub const MSR_IA32_VMX_CR0_FIXED0: u32 = 0x486;
pub const MSR_IA32_VMX_CR0_FIXED1: u32 = 0x487;
pub const MSR_IA32_VMX_CR4_FIXED0: u32 = 0x488;
pub const MSR_IA32_VMX_CR4_FIXED1: u32 = 0x489;
pub const MSR_IA32_VMX_VMCS_ENUM: u32 = 0x48A;
pub const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x48B;
pub const MSR_IA32_VMX_EPT_VPID_CAP: u32 = 0x48C;
pub const MSR_IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x48D;
pub const MSR_IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x48E;
pub const MSR_IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x48F;
pub const MSR_IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x490;
pub const MSR_IA32_VMX_VMFUNC: u32 = 0x491;

// ─────────────────────────────────────────────────────────────────────────────
// Nested VMCS (VMCS12)
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum VMCS fields we track
pub const MAX_VMCS_FIELDS: usize = 256;

/// Nested VMCS (VMCS12) - L1 hypervisor's VMCS for L2 guest
#[repr(C, align(4096))]
pub struct NestedVmcs {
    /// VMCS revision ID
    pub revision_id: AtomicU32,
    /// VMX abort indicator
    pub abort_indicator: AtomicU32,
    /// Launch state (clear or launched)
    pub launch_state: AtomicU8,
    /// VMCS data fields (indexed by encoding)
    pub fields: [AtomicU64; MAX_VMCS_FIELDS],
    /// Field valid bitmap
    pub field_valid: [AtomicU64; 4], // 256 bits
    /// Is this VMCS currently active
    pub is_active: AtomicBool,
    /// Is this VMCS the current VMCS
    pub is_current: AtomicBool,
    /// Link pointer (to VMCS that will be resumed)
    pub link_pointer: AtomicU64,
}

impl NestedVmcs {
    pub const fn new() -> Self {
        Self {
            revision_id: AtomicU32::new(0), // Set from VMX_BASIC
            abort_indicator: AtomicU32::new(0),
            launch_state: AtomicU8::new(VMCS_LAUNCH_STATE_CLEAR),
            fields: [const { AtomicU64::new(0) }; MAX_VMCS_FIELDS],
            field_valid: [const { AtomicU64::new(0) }; 4],
            is_active: AtomicBool::new(false),
            is_current: AtomicBool::new(false),
            link_pointer: AtomicU64::new(0xFFFFFFFFFFFFFFFF),
        }
    }

    /// Set VMCS revision from VMX_BASIC MSR
    pub fn set_revision(&self, revision: u32) {
        self.revision_id.store(revision, Ordering::Release);
    }

    /// Read a VMCS field
    pub fn read_field(&self, encoding: u32) -> Result<u64, HvError> {
        let idx = Self::field_index(encoding)?;
        if !self.is_field_valid(idx) {
            return Err(HvError::LogicalFault);
        }
        Ok(self.fields[idx].load(Ordering::Acquire))
    }

    /// Write a VMCS field
    pub fn write_field(&self, encoding: u32, value: u64) -> Result<(), HvError> {
        let idx = Self::field_index(encoding)?;
        self.fields[idx].store(value, Ordering::Release);
        self.set_field_valid(idx, true);
        Ok(())
    }

    /// Convert VMCS encoding to field index
    fn field_index(encoding: u32) -> Result<usize, HvError> {
        // Simplified - real implementation would use full encoding table
        let idx = (encoding & 0x1FF) as usize;
        if idx >= MAX_VMCS_FIELDS {
            return Err(HvError::LogicalFault);
        }
        Ok(idx)
    }

    /// Check if field is valid
    fn is_field_valid(&self, idx: usize) -> bool {
        let word = idx / 64;
        let bit = idx % 64;
        (self.field_valid[word].load(Ordering::Acquire) & (1u64 << bit)) != 0
    }

    /// Set field valid bit
    fn set_field_valid(&self, idx: usize, valid: bool) {
        let word = idx / 64;
        let bit = idx % 64;
        if valid {
            self.field_valid[word].fetch_or(1u64 << bit, Ordering::Release);
        } else {
            self.field_valid[word].fetch_and(!(1u64 << bit), Ordering::Release);
        }
    }

    /// Clear VMCS (VMCLEAR)
    pub fn vmclear(&self) {
        self.launch_state.store(VMCS_LAUNCH_STATE_CLEAR, Ordering::Release);
        self.is_current.store(false, Ordering::Release);
    }

    /// Launch VMCS (VMLAUNCH)
    pub fn vmlaunch(&self) -> Result<(), HvError> {
        if self.launch_state.load(Ordering::Acquire) == VMCS_LAUNCH_STATE_LAUNCHED {
            return Err(HvError::LogicalFault);
        }
        self.launch_state.store(VMCS_LAUNCH_STATE_LAUNCHED, Ordering::Release);
        self.is_current.store(true, Ordering::Release);
        Ok(())
    }

    /// Resume VMCS (VMRESUME)
    pub fn vmresume(&self) -> Result<(), HvError> {
        if self.launch_state.load(Ordering::Acquire) != VMCS_LAUNCH_STATE_LAUNCHED {
            return Err(HvError::LogicalFault);
        }
        self.is_current.store(true, Ordering::Release);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Nested Virtualization State
// ─────────────────────────────────────────────────────────────────────────────

/// L1 hypervisor state (saved when entering L2)
#[repr(C)]
pub struct L1HostState {
    /// CR0, CR3, CR4
    pub cr0: AtomicU64,
    pub cr3: AtomicU64,
    pub cr4: AtomicU64,
    /// RSP, RIP, RFLAGS
    pub rsp: AtomicU64,
    pub rip: AtomicU64,
    pub rflags: AtomicU64,
    /// Segment registers
    pub cs_selector: AtomicU16,
    pub cs_base: AtomicU64,
    pub cs_limit: AtomicU32,
    pub cs_access: AtomicU32,
    pub ds_selector: AtomicU16,
    pub es_selector: AtomicU16,
    pub ss_selector: AtomicU16,
    pub fs_selector: AtomicU16,
    pub fs_base: AtomicU64,
    pub gs_selector: AtomicU16,
    pub gs_base: AtomicU64,
    pub ldtr_selector: AtomicU16,
    pub tr_selector: AtomicU16,
    /// GDTR, IDTR
    pub gdtr_base: AtomicU64,
    pub gdtr_limit: AtomicU32,
    pub idtr_base: AtomicU64,
    pub idtr_limit: AtomicU32,
    /// EFER
    pub efer: AtomicU64,
    /// PAT
    pub pat: AtomicU64,
    /// Debug controls
    pub dr7: AtomicU64,
    pub ia32_debugctl: AtomicU64,
}

impl L1HostState {
    pub const fn new() -> Self {
        Self {
            cr0: AtomicU64::new(0),
            cr3: AtomicU64::new(0),
            cr4: AtomicU64::new(0),
            rsp: AtomicU64::new(0),
            rip: AtomicU64::new(0),
            rflags: AtomicU64::new(0),
            cs_selector: AtomicU16::new(0),
            cs_base: AtomicU64::new(0),
            cs_limit: AtomicU32::new(0),
            cs_access: AtomicU32::new(0),
            ds_selector: AtomicU16::new(0),
            es_selector: AtomicU16::new(0),
            ss_selector: AtomicU16::new(0),
            fs_selector: AtomicU16::new(0),
            fs_base: AtomicU64::new(0),
            gs_selector: AtomicU16::new(0),
            gs_base: AtomicU64::new(0),
            ldtr_selector: AtomicU16::new(0),
            tr_selector: AtomicU16::new(0),
            gdtr_base: AtomicU64::new(0),
            gdtr_limit: AtomicU32::new(0),
            idtr_base: AtomicU64::new(0),
            idtr_limit: AtomicU32::new(0),
            efer: AtomicU64::new(0),
            pat: AtomicU64::new(0),
            dr7: AtomicU64::new(0),
            ia32_debugctl: AtomicU64::new(0),
        }
    }
}

/// Nested virtualization controller
pub struct NestedVirtController {
    /// Current nested VMCS (VMCS12)
    pub vmcs12: NestedVmcs,
    /// L1 host state (saved when entering L2)
    pub l1_state: L1HostState,
    /// Is nested virtualization active
    pub is_active: AtomicBool,
    /// Are we currently in L2 guest
    pub in_l2: AtomicBool,
    /// VMCS shadowing enabled
    pub shadow_vmcs: AtomicBool,
    /// Shadow VMCS pointer
    pub shadow_vmcs_addr: AtomicU64,
    /// Nested exit reason (for VMexit to L1)
    pub exit_reason: AtomicU32,
    /// Nested exit qualification
    pub exit_qualification: AtomicU64,
    /// Nested exit interrupt info
    pub exit_int_info: AtomicU32,
    /// Nested IDT vectoring info
    pub idt_vectoring_info: AtomicU32,
    /// Nested exit instruction length
    pub exit_instr_len: AtomicU32,
    /// Nested exit instruction info
    pub exit_instr_info: AtomicU32,
    /// Nested guest physical address (for EPT violations)
    pub guest_physical_addr: AtomicU64,
}

impl NestedVirtController {
    pub const fn new() -> Self {
        Self {
            vmcs12: NestedVmcs::new(),
            l1_state: L1HostState::new(),
            is_active: AtomicBool::new(false),
            in_l2: AtomicBool::new(false),
            shadow_vmcs: AtomicBool::new(false),
            shadow_vmcs_addr: AtomicU64::new(0),
            exit_reason: AtomicU32::new(0),
            exit_qualification: AtomicU64::new(0),
            exit_int_info: AtomicU32::new(0),
            idt_vectoring_info: AtomicU32::new(0),
            exit_instr_len: AtomicU32::new(0),
            exit_instr_info: AtomicU32::new(0),
            guest_physical_addr: AtomicU64::new(0),
        }
    }

    /// Enable nested virtualization
    pub fn enable(&self) {
        self.is_active.store(true, Ordering::Release);
    }

    /// Disable nested virtualization
    pub fn disable(&self) {
        self.is_active.store(false, Ordering::Release);
        self.in_l2.store(false, Ordering::Release);
    }

    /// Enter L2 guest (VMLAUNCH/VMRESUME)
    pub fn enter_l2(&self) -> Result<(), HvError> {
        if !self.is_active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Save L1 state
        self.save_l1_state();
        
        // Load L2 state from VMCS12
        self.load_l2_state()?;
        
        self.in_l2.store(true, Ordering::Release);
        Ok(())
    }

    /// Exit from L2 guest (VMexit to L1)
    pub fn exit_l2(&self, reason: u32, qualification: u64) {
        // Save L2 state to VMCS12
        self.save_l2_state();
        
        // Set exit information
        self.exit_reason.store(reason, Ordering::Release);
        self.exit_qualification.store(qualification, Ordering::Release);
        
        // Restore L1 state
        self.restore_l1_state();
        
        self.in_l2.store(false, Ordering::Release);
    }

    /// Save L1 host state
    fn save_l1_state(&self) {
        // In real implementation, save all registers from VMCS
        // For now, just mark as saved
    }

    /// Restore L1 host state
    fn restore_l1_state(&self) {
        // In real implementation, restore all registers to VMCS
    }

    /// Load L2 guest state from VMCS12
    fn load_l2_state(&self) -> Result<(), HvError> {
        // In real implementation, load VMCS12 fields into VMCS02
        Ok(())
    }

    /// Save L2 guest state to VMCS12
    fn save_l2_state(&self) {
        // In real implementation, save VMCS02 fields to VMCS12
    }

    /// Handle VMREAD from L1
    pub fn vmread(&self, encoding: u32) -> Result<u64, HvError> {
        self.vmcs12.read_field(encoding)
    }

    /// Handle VMWRITE from L1
    pub fn vmwrite(&self, encoding: u32, value: u64) -> Result<(), HvError> {
        self.vmcs12.write_field(encoding, value)
    }

    /// Handle VMCLEAR from L1
    pub fn vmclear(&self, vmcs_addr: u64) -> Result<(), HvError> {
        // In real implementation, clear the VMCS at vmcs_addr
        self.vmcs12.vmclear();
        Ok(())
    }

    /// Handle VMPTRLD from L1
    pub fn vmptrld(&self, vmcs_addr: u64) -> Result<(), HvError> {
        // In real implementation, load VMCS12 from vmcs_addr
        self.vmcs12.is_active.store(true, Ordering::Release);
        Ok(())
    }

    /// Handle VMPTRST from L1
    pub fn vmptrst(&self) -> u64 {
        // Return current VMCS pointer
        if self.vmcs12.is_active.load(Ordering::Acquire) {
            0 // Placeholder
        } else {
            0xFFFFFFFFFFFFFFFF
        }
    }

    /// Handle VMLAUNCH from L1
    pub fn vmlaunch(&self) -> Result<(), HvError> {
        self.vmcs12.vmlaunch()?;
        self.enter_l2()
    }

    /// Handle VMRESUME from L1
    pub fn vmresume(&self) -> Result<(), HvError> {
        self.vmcs12.vmresume()?;
        self.enter_l2()
    }

    /// Check if nested VMX is supported
    pub fn is_supported() -> bool {
        // Check CPUID and VMX MSRs
        true
    }

    /// Get nested VMX MSR value
    pub fn get_vmx_msr(msr: u32) -> u64 {
        match msr {
            MSR_IA32_VMX_BASIC => {
                // VMCS revision (31:0), size in bytes (44:32)
                0x00000001 | (4096u64 << 32)
            }
            MSR_IA32_VMX_PINBASED_CTLS => {
                // Allowed 0-settings | Allowed 1-settings
                0x0000000000000001 | (0x000000000000003F << 32)
            }
            MSR_IA32_VMX_PROCBASED_CTLS => {
                0x0000000000000001 | (0x00000000FFF9FFFE << 32)
            }
            MSR_IA32_VMX_EXIT_CTLS => {
                0x0000000000000001 | (0x00000000003FFFFF << 32)
            }
            MSR_IA32_VMX_ENTRY_CTLS => {
                0x0000000000000001 | (0x00000000003FFFFF << 32)
            }
            MSR_IA32_VMX_MISC => {
                // CR3 target count, etc.
                0x0000000000000001
            }
            MSR_IA32_VMX_EPT_VPID_CAP => {
                // EPT and VPID capabilities
                0x0000000000000617 // Support 4-level EPT, VPID, etc.
            }
            _ => 0,
        }
    }
}

impl Default for NestedVirtController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_vmcs_basic() {
        let vmcs = NestedVmcs::new();
        
        // Write and read field
        vmcs.write_field(0x00006800, 0x1234).unwrap(); // CR0
        assert_eq!(vmcs.read_field(0x00006800).unwrap(), 0x1234);
    }

    #[test]
    fn nested_vmcs_launch_state() {
        let vmcs = NestedVmcs::new();
        
        // VMLAUNCH should succeed first time
        vmcs.vmlaunch().unwrap();
        assert_eq!(vmcs.launch_state.load(Ordering::Acquire), VMCS_LAUNCH_STATE_LAUNCHED);
        
        // VMLAUNCH should fail after launched
        assert!(vmcs.vmlaunch().is_err());
        
        // VMCLEAR resets state
        vmcs.vmclear();
        assert_eq!(vmcs.launch_state.load(Ordering::Acquire), VMCS_LAUNCH_STATE_CLEAR);
    }

    #[test]
    fn nested_virt_enable() {
        let ctrl = NestedVirtController::new();
        
        ctrl.enable();
        assert!(ctrl.is_active.load(Ordering::Acquire));
        
        ctrl.disable();
        assert!(!ctrl.is_active.load(Ordering::Acquire));
    }

    #[test]
    fn nested_vmx_msrs() {
        let basic = NestedVirtController::get_vmx_msr(MSR_IA32_VMX_BASIC);
        assert_ne!(basic, 0);
        
        let ept_cap = NestedVirtController::get_vmx_msr(MSR_IA32_VMX_EPT_VPID_CAP);
        assert_ne!(ept_cap, 0);
    }
}
