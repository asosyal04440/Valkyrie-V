//! APIC Virtualization (APICv / AVIC)
//!
//! Intel APICv and AMD AVIC support for efficient interrupt delivery.
//! Eliminates VM exits for APIC accesses and enables posted interrupts.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Intel APICv Constants
// ─────────────────────────────────────────────────────────────────────────────

/// VMCS Secondary Controls - APICv enable bits
pub const VMCS_CTRL_APIC_REG_VIRT: u32 = 1 << 0;
pub const VMCS_CTRL_VIRTUALIZE_APIC_ACCESSES: u32 = 1 << 1;
pub const VMCS_CTRL_VIRTUALIZE_X2APIC_MODE: u32 = 1 << 4;
pub const VMCS_CTRL_APIC_EXIT: u32 = 1 << 28;

/// APIC-access address (4KB page for virtual APIC)
pub const APIC_ACCESS_PAGE_SIZE: usize = 4096;

/// Virtual APIC page offsets
pub const APIC_OFFSET_ID: u32 = 0x020;
pub const APIC_OFFSET_VERSION: u32 = 0x030;
pub const APIC_OFFSET_TPR: u32 = 0x080;
pub const APIC_OFFSET_APR: u32 = 0x090;
pub const APIC_OFFSET_PPR: u32 = 0x0A0;
pub const APIC_OFFSET_EOI: u32 = 0x0B0;
pub const APIC_OFFSET_LDR: u32 = 0x0D0;
pub const APIC_OFFSET_DFR: u32 = 0x0E0;
pub const APIC_OFFSET_SVR: u32 = 0x0F0;
pub const APIC_OFFSET_ISR: u32 = 0x100;
pub const APIC_OFFSET_TMR: u32 = 0x180;
pub const APIC_OFFSET_IRR: u32 = 0x200;
pub const APIC_OFFSET_ESR: u32 = 0x280;
pub const APIC_OFFSET_ICR_LOW: u32 = 0x300;
pub const APIC_OFFSET_ICR_HIGH: u32 = 0x310;
pub const APIC_OFFSET_LVT_TIMER: u32 = 0x320;
pub const APIC_OFFSET_LVT_THERMAL: u32 = 0x330;
pub const APIC_OFFSET_LVT_PMC: u32 = 0x340;
pub const APIC_OFFSET_LVT_LINT0: u32 = 0x350;
pub const APIC_OFFSET_LVT_LINT1: u32 = 0x360;
pub const APIC_OFFSET_LVT_ERROR: u32 = 0x370;
pub const APIC_OFFSET_TIMER_ICR: u32 = 0x380;
pub const APIC_OFFSET_TIMER_CCR: u32 = 0x390;
pub const APIC_OFFSET_TIMER_DCR: u32 = 0x3E0;

// ─────────────────────────────────────────────────────────────────────────────
// Posted Interrupts
// ─────────────────────────────────────────────────────────────────────────────

/// Posted Interrupt Descriptor
/// Used for delivering interrupts directly to vCPU without VM exit
#[repr(C, align(64))]
pub struct PostedInterruptDesc {
    /// Posted interrupt request vector (PIV)
    pub piv: AtomicU64,
    /// Outstanding notification vector
    pub on: AtomicU8,
    /// Suppress notification
    pub sn: AtomicU8,
    /// Reserved
    _rsvd: [u8; 6],
    /// NV (notification vector)
    pub nv: AtomicU8,
    /// Reserved
    _rsvd2: [u8; 3],
    /// PIR (posted interrupt requests) - 256-bit bitmap
    pub pir: [AtomicU64; 4],
    /// Control bits
    pub control: AtomicU32,
}

impl PostedInterruptDesc {
    pub const fn new() -> Self {
        Self {
            piv: AtomicU64::new(0),
            on: AtomicU8::new(0),
            sn: AtomicU8::new(0),
            _rsvd: [0; 6],
            nv: AtomicU8::new(0),
            _rsvd2: [0; 3],
            pir: [const { AtomicU64::new(0) }; 4],
            control: AtomicU32::new(0),
        }
    }

    /// Check if there are pending interrupts
    pub fn has_pending(&self) -> bool {
        self.on.load(Ordering::Acquire) != 0
    }

    /// Post an interrupt vector
    pub fn post_vector(&self, vector: u8) {
        let idx = (vector / 64) as usize;
        let bit = vector % 64;
        self.pir[idx].fetch_or(1u64 << bit, Ordering::Release);
        self.on.store(1, Ordering::Release);
    }

    /// Clear a posted interrupt vector
    pub fn clear_vector(&self, vector: u8) {
        let idx = (vector / 64) as usize;
        let bit = vector % 64;
        self.pir[idx].fetch_and(!(1u64 << bit), Ordering::Release);
    }

    /// Get all pending vectors as a 256-bit bitmap
    pub fn get_pending_bitmap(&self) -> [u64; 4] {
        [
            self.pir[0].load(Ordering::Acquire),
            self.pir[1].load(Ordering::Acquire),
            self.pir[2].load(Ordering::Acquire),
            self.pir[3].load(Ordering::Acquire),
        ]
    }

    /// Acknowledge posted interrupt (called after processing)
    pub fn acknowledge(&self) {
        self.on.store(0, Ordering::Release);
    }

    /// Set notification vector
    pub fn set_notification_vector(&self, nv: u8) {
        self.nv.store(nv, Ordering::Release);
    }

    /// Enable/disable suppress notification
    pub fn set_suppress(&self, suppress: bool) {
        self.sn.store(suppress as u8, Ordering::Release);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtual APIC State
// ─────────────────────────────────────────────────────────────────────────────

/// Virtual APIC page (4KB)
#[repr(C, align(4096))]
pub struct VirtualApicPage {
    /// APIC register space (4KB)
    pub regs: [AtomicU32; 1024],
}

impl VirtualApicPage {
    pub const fn new() -> Self {
        Self {
            regs: [const { AtomicU32::new(0) }; 1024],
        }
    }

    /// Read APIC register
    pub fn read(&self, offset: u32) -> u32 {
        let idx = (offset / 4) as usize;
        if idx < 1024 {
            self.regs[idx].load(Ordering::Acquire)
        } else {
            0
        }
    }

    /// Write APIC register
    pub fn write(&self, offset: u32, value: u32) {
        let idx = (offset / 4) as usize;
        if idx < 1024 {
            self.regs[idx].store(value, Ordering::Release);
        }
    }

    /// Get TPR (Task Priority Register)
    pub fn get_tpr(&self) -> u8 {
        (self.read(APIC_OFFSET_TPR) & 0xFF) as u8
    }

    /// Set TPR
    pub fn set_tpr(&self, tpr: u8) {
        self.write(APIC_OFFSET_TPR, tpr as u32);
    }

    /// Get PPR (Processor Priority Register)
    pub fn get_ppr(&self) -> u8 {
        (self.read(APIC_OFFSET_PPR) & 0xFF) as u8
    }

    /// Signal EOI (End of Interrupt)
    pub fn signal_eoi(&self) {
        self.write(APIC_OFFSET_EOI, 0);
    }

    /// Get ICR (Interrupt Command Register) low
    pub fn get_icr_low(&self) -> u32 {
        self.read(APIC_OFFSET_ICR_LOW)
    }

    /// Get ICR high
    pub fn get_icr_high(&self) -> u32 {
        self.read(APIC_OFFSET_ICR_HIGH)
    }

    /// Set ICR low
    pub fn set_icr_low(&self, value: u32) {
        self.write(APIC_OFFSET_ICR_LOW, value);
    }

    /// Set ICR high
    pub fn set_icr_high(&self, value: u32) {
        self.write(APIC_OFFSET_ICR_HIGH, value);
    }

    /// Check if interrupt is pending in ISR
    pub fn has_isr_bit(&self, vector: u8) -> bool {
        let idx = (APIC_OFFSET_ISR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        (self.regs[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }

    /// Set ISR bit
    pub fn set_isr_bit(&self, vector: u8) {
        let idx = (APIC_OFFSET_ISR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        self.regs[idx].fetch_or(1 << bit, Ordering::Release);
    }

    /// Clear ISR bit
    pub fn clear_isr_bit(&self, vector: u8) {
        let idx = (APIC_OFFSET_ISR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        self.regs[idx].fetch_and(!(1 << bit), Ordering::Release);
    }

    /// Check IRR bit
    pub fn has_irr_bit(&self, vector: u8) -> bool {
        let idx = (APIC_OFFSET_IRR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        (self.regs[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }

    /// Set IRR bit (inject interrupt)
    pub fn set_irr_bit(&self, vector: u8) {
        let idx = (APIC_OFFSET_IRR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        self.regs[idx].fetch_or(1 << bit, Ordering::Release);
    }

    /// Clear IRR bit
    pub fn clear_irr_bit(&self, vector: u8) {
        let idx = (APIC_OFFSET_IRR as usize / 4) + ((vector / 32) as usize) * 4;
        let bit = vector % 32;
        self.regs[idx].fetch_and(!(1 << bit), Ordering::Release);
    }

    /// Find highest priority pending interrupt
    pub fn get_highest_irr(&self) -> Option<u8> {
        for i in (0..8).rev() {
            let idx = (APIC_OFFSET_IRR as usize / 4) + (i * 4);
            let irr = self.regs[idx].load(Ordering::Acquire);
            if irr != 0 {
                // Find highest set bit
                let vector_base = i * 32;
                for bit in (0..32).rev() {
                    if (irr & (1 << bit)) != 0 {
                        return Some((vector_base + bit) as u8);
                    }
                }
            }
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// APICv Controller
// ─────────────────────────────────────────────────────────────────────────────

/// APICv feature flags
#[derive(Clone, Copy, Debug)]
pub struct ApicvFeatures {
    pub virtualize_apic_accesses: bool,
    pub virtualize_x2apic: bool,
    pub posted_interrupts: bool,
    pub virtual_interrupt_delivery: bool,
    pub process_moved_interrupts: bool,
}

impl ApicvFeatures {
    pub fn detect() -> Self {
        // In real implementation, read MSRs to detect features
        Self {
            virtualize_apic_accesses: true,
            virtualize_x2apic: true,
            posted_interrupts: true,
            virtual_interrupt_delivery: true,
            process_moved_interrupts: false,
        }
    }
}

/// APICv controller per vCPU
pub struct ApicvController {
    /// Virtual APIC page
    pub vapic: VirtualApicPage,
    /// Posted interrupt descriptor
    pub pi_desc: PostedInterruptDesc,
    /// APIC-access page GPA
    pub apic_access_gpa: AtomicU64,
    /// Features
    pub features: ApicvFeatures,
    /// Current PPR
    pub ppr: AtomicU8,
    /// Virtual interrupt vector pending
    pub vi_pending: AtomicU8,
}

impl ApicvController {
    pub const fn new() -> Self {
        Self {
            vapic: VirtualApicPage::new(),
            pi_desc: PostedInterruptDesc::new(),
            apic_access_gpa: AtomicU64::new(0),
            features: ApicvFeatures {
                virtualize_apic_accesses: false,
                virtualize_x2apic: false,
                posted_interrupts: false,
                virtual_interrupt_delivery: false,
                process_moved_interrupts: false,
            },
            ppr: AtomicU8::new(0),
            vi_pending: AtomicU8::new(0),
        }
    }

    /// Initialize with detected features
    pub fn init(&mut self) {
        self.features = ApicvFeatures::detect();
    }

    /// Set APIC-access page GPA
    pub fn set_apic_access_page(&self, gpa: u64) {
        self.apic_access_gpa.store(gpa, Ordering::Release);
    }

    /// Inject interrupt via posted interrupt
    pub fn inject_interrupt(&self, vector: u8) -> Result<(), HvError> {
        if self.features.posted_interrupts {
            self.pi_desc.post_vector(vector);
            Ok(())
        } else {
            // Fallback: set IRR bit
            self.vapic.set_irr_bit(vector);
            Ok(())
        }
    }

    /// Check if interrupt can be delivered (PPR check)
    pub fn can_deliver(&self, vector: u8) -> bool {
        let ppr = self.ppr.load(Ordering::Acquire);
        let vector_prio = vector >> 4;
        let ppr_prio = ppr >> 4;
        vector_prio > ppr_prio
    }

    /// Update PPR based on TPR and ISR
    pub fn update_ppr(&self) {
        let tpr = self.vapic.get_tpr();
        let isr_prio = self.get_isr_priority();
        let ppr = tpr.max(isr_prio);
        self.ppr.store(ppr, Ordering::Release);
    }

    /// Get highest priority from ISR
    fn get_isr_priority(&self) -> u8 {
        // Simplified - would scan ISR for highest vector
        0
    }

    /// Process EOI
    pub fn process_eoi(&self) {
        // In real implementation, scan TMR to find vector and handle level-triggered
        self.vapic.signal_eoi();
    }

    /// Get VMCS controls for APICv
    pub fn get_vmcs_controls(&self) -> u32 {
        let mut controls = 0u32;
        
        if self.features.virtualize_apic_accesses {
            controls |= VMCS_CTRL_VIRTUALIZE_APIC_ACCESSES;
        }
        if self.features.virtualize_x2apic {
            controls |= VMCS_CTRL_VIRTUALIZE_X2APIC_MODE;
        }
        
        controls
    }
}

impl Default for ApicvController {
    fn default() -> Self {
        let mut ctrl = Self::new();
        ctrl.init();
        ctrl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posted_interrupt_basic() {
        let pi = PostedInterruptDesc::new();
        
        pi.post_vector(0x20);
        assert!(pi.has_pending());
        
        let bitmap = pi.get_pending_bitmap();
        assert_ne!(bitmap[0], 0);
        
        pi.acknowledge();
        assert!(!pi.has_pending());
    }

    #[test]
    fn virtual_apic_tpr() {
        let vapic = VirtualApicPage::new();
        
        vapic.set_tpr(0x10);
        assert_eq!(vapic.get_tpr(), 0x10);
    }

    #[test]
    fn virtual_apic_irr() {
        let vapic = VirtualApicPage::new();
        
        vapic.set_irr_bit(0x25);
        assert!(vapic.has_irr_bit(0x25));
        
        let highest = vapic.get_highest_irr();
        assert_eq!(highest, Some(0x25));
    }

    #[test]
    fn apicv_inject() {
        let mut ctrl = ApicvController::new();
        ctrl.init();
        
        ctrl.inject_interrupt(0x30).unwrap();
        assert!(ctrl.pi_desc.has_pending() || ctrl.vapic.has_irr_bit(0x30));
    }
}
