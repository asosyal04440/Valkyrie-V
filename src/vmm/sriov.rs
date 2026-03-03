//! SR-IOV (Single Root I/O Virtualization)
//!
//! Virtual Function (VF) management for direct device passthrough.
//! Enables multiple VMs to share a single physical PCIe device.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// SR-IOV PCIe Capability Constants
// ─────────────────────────────────────────────────────────────────────────────

/// SR-IOV capability ID
pub const PCI_EXT_CAP_ID_SRIOV: u16 = 0x0016;

/// SR-IOV capability offsets
pub const SRIOV_CAP: u32 = 0x04;           // SR-IOV Capabilities
pub const SRIOV_CTRL: u32 = 0x08;          // SR-IOV Control
pub const SRIOV_STATUS: u32 = 0x0A;        // SR-IOV Status
pub const SRIOV_INITIAL_VF: u32 = 0x0C;    // Initial VFs
pub const SRIOV_TOTAL_VF: u32 = 0x0E;      // Total VFs
pub const SRIOV_NUM_VF: u32 = 0x10;        // Number VFs
pub const SRIOV_VF_OFFSET: u32 = 0x14;     // First VF Offset
pub const SRIOV_VF_STRIDE: u32 = 0x16;     // VF Stride
pub const SRIOV_VF_DID: u32 = 0x1A;        // VF Device ID
pub const SRIOV_SUP_PGSIZE: u32 = 0x1C;    // Supported Page Sizes
pub const SRIOV_SYS_PGSIZE: u32 = 0x20;    // System Page Size
pub const SRIOV_BAR: u32 = 0x24;           // VF BAR0-5 (24 bytes)
pub const SRIOV_VF_MIGRATION: u32 = 0x3C;  // VF Migration State Array Offset

/// SR-IOV Control bits
pub const SRIOV_CTRL_VFE: u16 = 1 << 0;     // VF Enable
pub const SRIOV_CTRL_VFM: u16 = 1 << 1;     // VF Migration Enable
pub const SRIOV_CTRL_INTR: u16 = 1 << 2;    // VF Migration Interrupt Enable
pub const SRIOV_CTRL_MSE: u16 = 1 << 3;     // VF Memory Space Enable
pub const SRIOV_CTRL_ARI: u16 = 1 << 4;     // ARI Capable Hierarchy

/// SR-IOV Status bits
pub const SRIOV_STATUS_VFM: u16 = 1 << 0;   // VF Migration Status

/// Maximum VFs per PF
pub const MAX_VFS_PER_PF: usize = 256;

/// Maximum BARs per VF
pub const MAX_VF_BARS: usize = 6;

// ─────────────────────────────────────────────────────────────────────────────
// Virtual Function State
// ─────────────────────────────────────────────────────────────────────────────

/// VF state enumeration
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum VfState {
    /// VF not allocated
    Unallocated = 0,
    /// VF allocated but not enabled
    Allocated = 1,
    /// VF enabled and ready
    Enabled = 2,
    /// VF assigned to VM
    Assigned = 3,
    /// VF in migration
    Migrating = 4,
    /// VF in error state
    Error = 5,
}

/// Virtual Function descriptor
#[repr(C)]
pub struct VirtualFunction {
    /// VF index within PF
    pub vf_index: AtomicU16,
    /// VF PCI bus:device:function
    pub bdf: AtomicU16,
    /// VF state
    pub state: AtomicU8,
    /// Owner VM ID (0 = unassigned)
    pub owner_vm_id: AtomicU32,
    /// VF BAR values
    pub bars: [AtomicU64; MAX_VF_BARS],
    /// VF BAR sizes
    pub bar_sizes: [AtomicU64; MAX_VF_BARS],
    /// VF BAR enabled flags
    pub bar_enabled: [AtomicBool; MAX_VF_BARS],
    /// MSI-X table address
    pub msix_table_addr: AtomicU64,
    /// MSI-X table size
    pub msix_table_size: AtomicU16,
    /// MSI-X enabled
    pub msix_enabled: AtomicBool,
    /// Interrupt vector base
    pub intr_vector_base: AtomicU16,
    /// DMA address translation (IOMMU domain)
    pub iommu_domain: AtomicU32,
    /// VF driver notification pending
    pub notify_pending: AtomicBool,
}

impl VirtualFunction {
    pub const fn new() -> Self {
        Self {
            vf_index: AtomicU16::new(0),
            bdf: AtomicU16::new(0),
            state: AtomicU8::new(VfState::Unallocated as u8),
            owner_vm_id: AtomicU32::new(0),
            bars: [const { AtomicU64::new(0) }; MAX_VF_BARS],
            bar_sizes: [const { AtomicU64::new(0) }; MAX_VF_BARS],
            bar_enabled: [const { AtomicBool::new(false) }; MAX_VF_BARS],
            msix_table_addr: AtomicU64::new(0),
            msix_table_size: AtomicU16::new(0),
            msix_enabled: AtomicBool::new(false),
            intr_vector_base: AtomicU16::new(0),
            iommu_domain: AtomicU32::new(0),
            notify_pending: AtomicBool::new(false),
        }
    }

    /// Check if VF is available for assignment
    pub fn is_available(&self) -> bool {
        let state = self.state.load(Ordering::Acquire);
        (state == VfState::Enabled as u8 || state == VfState::Allocated as u8)
            && self.owner_vm_id.load(Ordering::Acquire) == 0
    }

    /// Assign VF to VM
    pub fn assign_to_vm(&self, vm_id: u32) -> Result<(), HvError> {
        if !self.is_available() {
            return Err(HvError::LogicalFault);
        }
        
        self.owner_vm_id.store(vm_id, Ordering::Release);
        self.state.store(VfState::Assigned as u8, Ordering::Release);
        Ok(())
    }

    /// Release VF from VM
    pub fn release_from_vm(&self) {
        self.owner_vm_id.store(0, Ordering::Release);
        self.state.store(VfState::Enabled as u8, Ordering::Release);
    }

    /// Configure BAR
    pub fn configure_bar(&self, bar_idx: usize, addr: u64, size: u64) {
        if bar_idx >= MAX_VF_BARS {
            return;
        }
        
        self.bars[bar_idx].store(addr, Ordering::Release);
        self.bar_sizes[bar_idx].store(size, Ordering::Release);
        self.bar_enabled[bar_idx].store(true, Ordering::Release);
    }

    /// Get BAR address
    pub fn get_bar_addr(&self, bar_idx: usize) -> u64 {
        if bar_idx >= MAX_VF_BARS {
            return 0;
        }
        self.bars[bar_idx].load(Ordering::Acquire)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical Function Controller
// ─────────────────────────────────────────────────────────────────────────────

/// SR-IOV Physical Function controller
pub struct SriovPfController {
    /// PF PCI bus:device:function
    pub pf_bdf: AtomicU16,
    /// PF vendor ID
    pub vendor_id: AtomicU16,
    /// PF device ID
    pub device_id: AtomicU16,
    /// VF device ID
    pub vf_device_id: AtomicU16,
    /// Total VFs supported
    pub total_vfs: AtomicU16,
    /// Initial VFs
    pub initial_vfs: AtomicU16,
    /// Number of VFs enabled
    pub num_vfs_enabled: AtomicU16,
    /// VF offset (first VF BDF = PF BDF + offset)
    pub vf_offset: AtomicU16,
    /// VF stride (distance between VF BDFs)
    pub vf_stride: AtomicU16,
    /// Supported page sizes
    pub sup_pgsize: AtomicU32,
    /// System page size
    pub sys_pgsize: AtomicU32,
    /// SR-IOV control register
    pub ctrl: AtomicU16,
    /// SR-IOV status register
    pub status: AtomicU16,
    /// Virtual Functions
    pub vfs: [VirtualFunction; MAX_VFS_PER_PF],
    /// VF BAR configuration templates
    pub vf_bar_templates: [AtomicU64; MAX_VF_BARS],
    /// Migration support enabled
    pub migration_enabled: AtomicBool,
    /// ARI (Alternative Routing ID) supported
    pub ari_supported: AtomicBool,
}

impl SriovPfController {
    pub const fn new() -> Self {
        Self {
            pf_bdf: AtomicU16::new(0),
            vendor_id: AtomicU16::new(0),
            device_id: AtomicU16::new(0),
            vf_device_id: AtomicU16::new(0),
            total_vfs: AtomicU16::new(0),
            initial_vfs: AtomicU16::new(0),
            num_vfs_enabled: AtomicU16::new(0),
            vf_offset: AtomicU16::new(1),
            vf_stride: AtomicU16::new(1),
            sup_pgsize: AtomicU32::new(0xFFF), // 4KB to 1GB pages
            sys_pgsize: AtomicU32::new(0x1000), // 4KB
            ctrl: AtomicU16::new(0),
            status: AtomicU16::new(0),
            vfs: [const { VirtualFunction::new() }; MAX_VFS_PER_PF],
            vf_bar_templates: [const { AtomicU64::new(0) }; MAX_VF_BARS],
            migration_enabled: AtomicBool::new(false),
            ari_supported: AtomicBool::new(false),
        }
    }

    /// Initialize PF with device information
    pub fn init(&mut self, bdf: u16, vendor_id: u16, device_id: u16, 
                vf_device_id: u16, total_vfs: u16, vf_offset: u16, vf_stride: u16) {
        self.pf_bdf.store(bdf, Ordering::Release);
        self.vendor_id.store(vendor_id, Ordering::Release);
        self.device_id.store(device_id, Ordering::Release);
        self.vf_device_id.store(vf_device_id, Ordering::Release);
        self.total_vfs.store(total_vfs, Ordering::Release);
        self.vf_offset.store(vf_offset, Ordering::Release);
        self.vf_stride.store(vf_stride, Ordering::Release);
        
        // Initialize VF states
        for (i, vf) in self.vfs.iter().enumerate() {
            if i < total_vfs as usize {
                vf.vf_index.store(i as u16, Ordering::Release);
                vf.state.store(VfState::Unallocated as u8, Ordering::Release);
                
                // Calculate VF BDF
                let vf_bdf = bdf.wrapping_add(vf_offset.wrapping_add((i as u16) * vf_stride));
                vf.bdf.store(vf_bdf, Ordering::Release);
            }
        }
    }

    /// Enable SR-IOV
    pub fn enable_sriov(&mut self, num_vfs: u16) -> Result<(), HvError> {
        if num_vfs > self.total_vfs.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Enable SR-IOV
        let ctrl = self.ctrl.load(Ordering::Acquire) | SRIOV_CTRL_VFE | SRIOV_CTRL_MSE;
        self.ctrl.store(ctrl, Ordering::Release);
        self.num_vfs_enabled.store(num_vfs, Ordering::Release);
        
        // Enable VFs
        for i in 0..num_vfs as usize {
            let vf = &self.vfs[i];
            vf.state.store(VfState::Enabled as u8, Ordering::Release);
        }
        
        Ok(())
    }

    /// Disable SR-IOV
    pub fn disable_sriov(&mut self) {
        // Release all VFs
        for vf in &self.vfs {
            if vf.owner_vm_id.load(Ordering::Acquire) != 0 {
                vf.release_from_vm();
            }
            vf.state.store(VfState::Unallocated as u8, Ordering::Release);
        }
        
        // Clear control
        self.ctrl.store(0, Ordering::Release);
        self.num_vfs_enabled.store(0, Ordering::Release);
    }

    /// Find available VF
    pub fn find_available_vf(&self) -> Option<&VirtualFunction> {
        let num_vfs = self.num_vfs_enabled.load(Ordering::Acquire) as usize;
        for i in 0..num_vfs {
            let vf = &self.vfs[i];
            if vf.is_available() {
                return Some(vf);
            }
        }
        None
    }

    /// Find available VF by index
    pub fn get_vf(&self, vf_index: u16) -> Option<&VirtualFunction> {
        if vf_index as usize >= MAX_VFS_PER_PF {
            return None;
        }
        Some(&self.vfs[vf_index as usize])
    }

    /// Assign VF to VM
    pub fn assign_vf(&self, vf_index: u16, vm_id: u32) -> Result<u16, HvError> {
        let vf = self.get_vf(vf_index).ok_or(HvError::LogicalFault)?;
        vf.assign_to_vm(vm_id)?;
        
        // Return VF BDF for guest PCI configuration
        Ok(vf.bdf.load(Ordering::Acquire))
    }

    /// Release VF from VM
    pub fn release_vf(&self, vf_index: u16) -> Result<(), HvError> {
        let vf = self.get_vf(vf_index).ok_or(HvError::LogicalFault)?;
        vf.release_from_vm();
        Ok(())
    }

    /// Configure VF BARs
    pub fn configure_vf_bars(&self, vf_index: u16, bars: [u64; MAX_VF_BARS], sizes: [u64; MAX_VF_BARS]) {
        let Some(vf) = self.get_vf(vf_index) else { return };
        
        for i in 0..MAX_VF_BARS {
            if sizes[i] != 0 {
                vf.configure_bar(i, bars[i], sizes[i]);
            }
        }
    }

    /// Read SR-IOV capability register
    pub fn read_cap(&self, offset: u32) -> u32 {
        match offset {
            SRIOV_CAP => 0, // No migration support
            SRIOV_CTRL => self.ctrl.load(Ordering::Acquire) as u32,
            SRIOV_STATUS => self.status.load(Ordering::Acquire) as u32,
            SRIOV_INITIAL_VF => self.initial_vfs.load(Ordering::Acquire) as u32,
            SRIOV_TOTAL_VF => self.total_vfs.load(Ordering::Acquire) as u32,
            SRIOV_NUM_VF => self.num_vfs_enabled.load(Ordering::Acquire) as u32,
            SRIOV_VF_OFFSET => self.vf_offset.load(Ordering::Acquire) as u32,
            SRIOV_VF_STRIDE => self.vf_stride.load(Ordering::Acquire) as u32,
            SRIOV_VF_DID => self.vf_device_id.load(Ordering::Acquire) as u32,
            SRIOV_SUP_PGSIZE => self.sup_pgsize.load(Ordering::Acquire),
            SRIOV_SYS_PGSIZE => self.sys_pgsize.load(Ordering::Acquire),
            _ => {
                if offset >= SRIOV_BAR && offset < SRIOV_BAR + 24 {
                    let bar_idx = ((offset - SRIOV_BAR) / 4) as usize;
                    if bar_idx < MAX_VF_BARS {
                        self.vf_bar_templates[bar_idx].load(Ordering::Acquire) as u32
                    } else {
                        0
                    }
                } else {
                    0
                }
            }
        }
    }

    /// Write SR-IOV capability register
    pub fn write_cap(&mut self, offset: u32, value: u32) {
        match offset {
            SRIOV_CTRL => {
                let ctrl = value as u16;
                let old_ctrl = self.ctrl.load(Ordering::Acquire);
                
                // Handle VF enable/disable
                if (ctrl & SRIOV_CTRL_VFE) != 0 && (old_ctrl & SRIOV_CTRL_VFE) == 0 {
                    // Enabling - use NUM_VF to determine count
                    let num_vfs = self.num_vfs_enabled.load(Ordering::Acquire);
                    if num_vfs > 0 {
                        let _ = self.enable_sriov(num_vfs);
                    }
                } else if (ctrl & SRIOV_CTRL_VFE) == 0 && (old_ctrl & SRIOV_CTRL_VFE) != 0 {
                    // Disabling
                    self.disable_sriov();
                }
                
                self.ctrl.store(ctrl, Ordering::Release);
            }
            SRIOV_NUM_VF => {
                self.num_vfs_enabled.store(value as u16, Ordering::Release);
            }
            SRIOV_SYS_PGSIZE => {
                self.sys_pgsize.store(value, Ordering::Release);
            }
            _ => {
                if offset >= SRIOV_BAR && offset < SRIOV_BAR + 24 {
                    let bar_idx = ((offset - SRIOV_BAR) / 4) as usize;
                    if bar_idx < MAX_VF_BARS {
                        self.vf_bar_templates[bar_idx].store(value as u64, Ordering::Release);
                    }
                }
            }
        }
    }

    /// Get VF statistics
    pub fn get_stats(&self) -> SriovStats {
        let mut assigned = 0u16;
        let mut available = 0u16;
        
        let num_vfs = self.num_vfs_enabled.load(Ordering::Acquire) as usize;
        for i in 0..num_vfs {
            let vf = &self.vfs[i];
            if vf.owner_vm_id.load(Ordering::Acquire) != 0 {
                assigned += 1;
            } else if vf.is_available() {
                available += 1;
            }
        }
        
        SriovStats {
            total_vfs: self.total_vfs.load(Ordering::Acquire),
            enabled_vfs: self.num_vfs_enabled.load(Ordering::Acquire),
            assigned_vfs: assigned,
            available_vfs: available,
        }
    }
}

impl Default for SriovPfController {
    fn default() -> Self {
        Self::new()
    }
}

/// SR-IOV statistics
#[repr(C)]
pub struct SriovStats {
    pub total_vfs: u16,
    pub enabled_vfs: u16,
    pub assigned_vfs: u16,
    pub available_vfs: u16,
}

// ─────────────────────────────────────────────────────────────────────────────
// VF PCI Configuration Space Emulation
// ─────────────────────────────────────────────────────────────────────────────

/// Emulate VF PCI config read
pub fn vf_config_read(vf: &VirtualFunction, offset: u32) -> u32 {
    match offset {
        0x00 => {
            // Vendor ID, Device ID
            let vendor = 0x8086u16; // Would come from PF
            let device = vf.bdf.load(Ordering::Acquire); // Simplified
            (device as u32) << 16 | vendor as u32
        }
        0x04 => {
            // Command, Status
            let mut cmd = 0u16;
            for i in 0..MAX_VF_BARS {
                if vf.bar_enabled[i].load(Ordering::Acquire) {
                    cmd |= 0x02; // Memory Space Enable
                    break;
                }
            }
            if vf.msix_enabled.load(Ordering::Acquire) {
                cmd |= 0x0400; // Interrupt Disable (using MSI-X)
            }
            cmd as u32
        }
        0x08 => {
            // Revision ID, Class Code
            0x02000000 // Network controller
        }
        0x0C => {
            // Cache Line Size, Latency Timer, Header Type, BIST
            0x00 // Type 0 header
        }
        0x10..=0x24 => {
            // BAR0-5
            let bar_idx = ((offset - 0x10) / 4) as usize;
            if bar_idx < MAX_VF_BARS {
                vf.bars[bar_idx].load(Ordering::Acquire) as u32
            } else {
                0
            }
        }
        0x28 => {
            // CardBus CIS Pointer
            0
        }
        0x2C => {
            // Subsystem Vendor ID, Subsystem ID
            0
        }
        0x30 => {
            // Expansion ROM Base Address
            0
        }
        0x34 => {
            // Capabilities Pointer
            0x40
        }
        0x3C => {
            // Interrupt Line, Interrupt Pin
            if vf.msix_enabled.load(Ordering::Acquire) {
                0 // MSI-X, no legacy interrupt
            } else {
                0x01 // INTA#
            }
        }
        0x40.. => {
            // Capability registers (MSI-X, etc.)
            0
        }
        _ => 0,
    }
}

/// Emulate VF PCI config write
pub fn vf_config_write(vf: &VirtualFunction, offset: u32, value: u32) {
    match offset {
        0x04 => {
            // Command register - handle memory enable
            let _mem_enabled = (value & 0x02) != 0;
            // Would enable/disable VF BAR mappings
        }
        0x10..=0x24 => {
            // BAR0-5
            let bar_idx = ((offset - 0x10) / 4) as usize;
            if bar_idx < MAX_VF_BARS {
                let size = vf.bar_sizes[bar_idx].load(Ordering::Acquire);
                if size != 0 {
                    // Mask to alignment
                    let addr = (value as u64) & !(size - 1);
                    vf.bars[bar_idx].store(addr, Ordering::Release);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sriov_init() {
        let mut pf = SriovPfController::new();
        pf.init(0x0100, 0x8086, 0x1547, 0x1548, 64, 1, 1);
        
        assert_eq!(pf.total_vfs.load(Ordering::Acquire), 64);
        assert_eq!(pf.vf_offset.load(Ordering::Acquire), 1);
    }

    #[test]
    fn sriov_enable() {
        let mut pf = SriovPfController::new();
        pf.init(0x0100, 0x8086, 0x1547, 0x1548, 64, 1, 1);
        
        pf.enable_sriov(8).unwrap();
        
        assert_eq!(pf.num_vfs_enabled.load(Ordering::Acquire), 8);
        assert!(pf.ctrl.load(Ordering::Acquire) & SRIOV_CTRL_VFE != 0);
        
        // Check VFs are enabled
        for i in 0..8 {
            assert_eq!(pf.vfs[i].state.load(Ordering::Acquire), VfState::Enabled as u8);
        }
    }

    #[test]
    fn sriov_assign_vf() {
        let mut pf = SriovPfController::new();
        pf.init(0x0100, 0x8086, 0x1547, 0x1548, 64, 1, 1);
        pf.enable_sriov(8).unwrap();
        
        let bdf = pf.assign_vf(0, 1).unwrap();
        assert_ne!(bdf, 0);
        
        assert_eq!(pf.vfs[0].owner_vm_id.load(Ordering::Acquire), 1);
        assert_eq!(pf.vfs[0].state.load(Ordering::Acquire), VfState::Assigned as u8);
    }

    #[test]
    fn sriov_release_vf() {
        let mut pf = SriovPfController::new();
        pf.init(0x0100, 0x8086, 0x1547, 0x1548, 64, 1, 1);
        pf.enable_sriov(8).unwrap();
        pf.assign_vf(0, 1).unwrap();
        
        pf.release_vf(0).unwrap();
        
        assert_eq!(pf.vfs[0].owner_vm_id.load(Ordering::Acquire), 0);
        assert_eq!(pf.vfs[0].state.load(Ordering::Acquire), VfState::Enabled as u8);
    }

    #[test]
    fn sriov_stats() {
        let mut pf = SriovPfController::new();
        pf.init(0x0100, 0x8086, 0x1547, 0x1548, 64, 1, 1);
        pf.enable_sriov(8).unwrap();
        pf.assign_vf(0, 1).unwrap();
        pf.assign_vf(1, 2).unwrap();
        
        let stats = pf.get_stats();
        assert_eq!(stats.total_vfs, 64);
        assert_eq!(stats.enabled_vfs, 8);
        assert_eq!(stats.assigned_vfs, 2);
        assert_eq!(stats.available_vfs, 6);
    }

    #[test]
    fn vf_config() {
        let vf = VirtualFunction::new();
        vf.configure_bar(0, 0xF0000000, 0x10000);
        
        let bar0 = vf_config_read(&vf, 0x10);
        assert_eq!(bar0, 0xF0000000);
    }
}
