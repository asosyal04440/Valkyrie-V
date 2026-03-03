//! MSI / MSI-X interrupt delivery for virtual PCI devices.
//!
//! MSI (Message Signalled Interrupts) replaces legacy INTx pin-based
//! interrupts.  The device writes a "message" to a special LAPIC address
//! (0xFEE0_0000 region) which the interrupt controller decodes into a
//! vector + destination CPU.
//!
//! MSI message format (Intel):
//!   Address: 0xFEE0_0000 | (dest_id << 12) | redirect_hint | dest_mode
//!   Data:    vector[7:0] | delivery_mode[10:8] | level | trigger
//!
//! This module provides:
//!   - `MsiMessage`: parsed MSI address + data pair
//!   - `MsiCapability`: per-device MSI capability register emulation
//!   - `MsixTable`: per-device MSI-X table emulation
//!   - `deliver_msi()`: injects the MSI vector into the guest via PENDING_IRQ

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Maximum number of MSI-X vectors per device.
pub const MSIX_MAX_VECTORS: usize = 32;

/// MSI address base — writes to 0xFEE0_xxxx trigger interrupt delivery.
pub const MSI_ADDR_BASE: u64 = 0xFEE0_0000;
pub const MSI_ADDR_MASK: u64 = 0xFFF0_0000;

/// Parsed MSI message (address + data pair).
#[derive(Debug, Clone, Copy)]
pub struct MsiMessage {
    /// Target LAPIC ID (physical destination).
    pub dest_id: u8,
    /// Interrupt vector to inject.
    pub vector: u8,
    /// Delivery mode (0=Fixed, 1=LowPri, 2=SMI, 4=NMI, 5=INIT, 7=ExtINT).
    pub delivery_mode: u8,
    /// Trigger mode (0=edge, 1=level).
    pub trigger_mode: bool,
    /// Destination mode (0=physical, 1=logical).
    pub dest_mode: bool,
}

impl MsiMessage {
    /// Decode an MSI message from the raw address and data dwords.
    pub fn decode(address: u64, data: u32) -> Self {
        let dest_id = ((address >> 12) & 0xFF) as u8;
        let dest_mode = (address & (1 << 2)) != 0; // bit 2 of address
        let vector = (data & 0xFF) as u8;
        let delivery_mode = ((data >> 8) & 0x7) as u8;
        let trigger_mode = (data & (1 << 15)) != 0;
        Self {
            dest_id,
            vector,
            delivery_mode,
            trigger_mode,
            dest_mode,
        }
    }

    /// Encode back into (address, data) pair.
    pub fn encode(&self) -> (u64, u32) {
        let addr = MSI_ADDR_BASE
            | ((self.dest_id as u64) << 12)
            | if self.dest_mode { 1 << 2 } else { 0 };
        let data = (self.vector as u32)
            | ((self.delivery_mode as u32) << 8)
            | if self.trigger_mode { 1 << 15 } else { 0 };
        (addr, data)
    }
}

/// Per-device MSI capability registers.
///
/// PCI MSI capability structure (PCI spec §6.8):
///   Byte 0: Cap ID (0x05)
///   Byte 1: Next pointer
///   Byte 2-3: Message Control
///   Byte 4-7: Message Address (low 32)
///   Byte 8-11: Message Address (high 32, if 64-bit capable)
///   Byte 12-13: Message Data
pub struct MsiCapability {
    /// Message control register.
    ///   Bit 0: MSI Enable
    ///   Bits [6:4]: Multiple Message Capable (log2 of max vectors)
    ///   Bits [3:1]: Multiple Message Enable (log2 of allocated vectors)
    ///   Bit 7: 64-bit address capable
    ///   Bit 8: Per-vector masking capable
    pub control: AtomicU32,
    /// Message address (low 32 bits).
    pub addr_lo: AtomicU32,
    /// Message address (high 32 bits, for 64-bit capable).
    pub addr_hi: AtomicU32,
    /// Message data.
    pub data: AtomicU32,
    /// Mask bits (per-vector masking).
    pub mask: AtomicU32,
    /// Pending bits (read-only).
    pub pending: AtomicU32,
}

impl MsiCapability {
    pub const fn new() -> Self {
        Self {
            // 64-bit capable (bit 7), 1 vector capable (bits 6:4 = 000)
            control: AtomicU32::new(1 << 7),
            addr_lo: AtomicU32::new(0),
            addr_hi: AtomicU32::new(0),
            data: AtomicU32::new(0),
            mask: AtomicU32::new(0),
            pending: AtomicU32::new(0),
        }
    }

    /// Check if MSI is enabled.
    pub fn is_enabled(&self) -> bool {
        self.control.load(Ordering::Relaxed) & 1 != 0
    }

    /// Enable or disable MSI.
    pub fn set_enabled(&self, enabled: bool) {
        let old = self.control.load(Ordering::Relaxed);
        if enabled {
            self.control.store(old | 1, Ordering::Relaxed);
        } else {
            self.control.store(old & !1, Ordering::Relaxed);
        }
    }

    /// Get the configured MSI message.
    pub fn message(&self) -> MsiMessage {
        let lo = self.addr_lo.load(Ordering::Relaxed) as u64;
        let hi = self.addr_hi.load(Ordering::Relaxed) as u64;
        let addr = (hi << 32) | lo;
        let data = self.data.load(Ordering::Relaxed);
        MsiMessage::decode(addr, data)
    }

    /// Write a config register within the MSI capability.
    /// `offset`: byte offset within the capability (0-based).
    pub fn write_config(&self, offset: usize, value: u32) {
        match offset {
            // Message Control (only writable bits: enable, MME)
            0 => {
                let old = self.control.load(Ordering::Relaxed);
                // Allow writing: bit 0 (enable), bits 3:1 (MME)
                let writable = 0x0F;
                self.control.store(
                    (old & !writable) | (value & writable),
                    Ordering::Relaxed,
                );
            }
            // Message Address Low
            1 => self.addr_lo.store(value & 0xFFFF_FFFC, Ordering::Relaxed),
            // Message Address High
            2 => self.addr_hi.store(value, Ordering::Relaxed),
            // Message Data
            3 => self.data.store(value & 0xFFFF, Ordering::Relaxed),
            // Mask bits
            4 => self.mask.store(value, Ordering::Relaxed),
            _ => {}
        }
    }

    /// Read a config register within the MSI capability.
    pub fn read_config(&self, offset: usize) -> u32 {
        match offset {
            0 => self.control.load(Ordering::Relaxed),
            1 => self.addr_lo.load(Ordering::Relaxed),
            2 => self.addr_hi.load(Ordering::Relaxed),
            3 => self.data.load(Ordering::Relaxed),
            4 => self.mask.load(Ordering::Relaxed),
            5 => self.pending.load(Ordering::Relaxed),
            _ => 0,
        }
    }
}

/// Single MSI-X table entry.
#[derive(Debug)]
pub struct MsixEntry {
    /// Message address (lower 32).
    pub addr_lo: AtomicU32,
    /// Message address (upper 32).
    pub addr_hi: AtomicU32,
    /// Message data.
    pub data: AtomicU32,
    /// Vector control (bit 0 = masked).
    pub control: AtomicU32,
}

impl MsixEntry {
    pub const fn new() -> Self {
        Self {
            addr_lo: AtomicU32::new(0),
            addr_hi: AtomicU32::new(0),
            data: AtomicU32::new(0),
            control: AtomicU32::new(1), // masked by default
        }
    }

    pub fn is_masked(&self) -> bool {
        self.control.load(Ordering::Relaxed) & 1 != 0
    }

    pub fn message(&self) -> MsiMessage {
        let lo = self.addr_lo.load(Ordering::Relaxed) as u64;
        let hi = self.addr_hi.load(Ordering::Relaxed) as u64;
        let addr = (hi << 32) | lo;
        let data = self.data.load(Ordering::Relaxed);
        MsiMessage::decode(addr, data)
    }
}

/// MSI-X table with up to `MSIX_MAX_VECTORS` entries.
pub struct MsixTable {
    entries: [MsixEntry; MSIX_MAX_VECTORS],
    /// Number of configured vectors (set at init time).
    num_vectors: u32,
    /// MSI-X enabled (from PCI config space).
    enabled: AtomicU32,
    /// Function mask (bit 14 of MSI-X message control).
    function_mask: AtomicU32,
}

impl MsixTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { MsixEntry::new() }; MSIX_MAX_VECTORS],
            num_vectors: 0,
            enabled: AtomicU32::new(0),
            function_mask: AtomicU32::new(0),
        }
    }

    /// Initialise with the specified number of vectors.
    pub fn init(&mut self, num_vectors: u32) {
        self.num_vectors = num_vectors.min(MSIX_MAX_VECTORS as u32);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) != 0
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(if enabled { 1 } else { 0 }, Ordering::Relaxed);
    }

    pub fn is_function_masked(&self) -> bool {
        self.function_mask.load(Ordering::Relaxed) != 0
    }

    pub fn set_function_mask(&self, masked: bool) {
        self.function_mask.store(if masked { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Read a dword from the MSI-X table (MMIO access from guest).
    /// `offset`: byte offset within the table (each entry is 16 bytes).
    pub fn read_entry(&self, offset: u64) -> u32 {
        let entry_idx = (offset / 16) as usize;
        let field = ((offset % 16) / 4) as usize;
        if entry_idx >= self.num_vectors as usize {
            return 0;
        }
        let e = &self.entries[entry_idx];
        match field {
            0 => e.addr_lo.load(Ordering::Relaxed),
            1 => e.addr_hi.load(Ordering::Relaxed),
            2 => e.data.load(Ordering::Relaxed),
            3 => e.control.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Write a dword to the MSI-X table (MMIO access from guest).
    pub fn write_entry(&self, offset: u64, value: u32) {
        let entry_idx = (offset / 16) as usize;
        let field = ((offset % 16) / 4) as usize;
        if entry_idx >= self.num_vectors as usize {
            return;
        }
        let e = &self.entries[entry_idx];
        match field {
            0 => e.addr_lo.store(value & 0xFFFF_FFFC, Ordering::Relaxed),
            1 => e.addr_hi.store(value, Ordering::Relaxed),
            2 => e.data.store(value, Ordering::Relaxed),
            3 => e.control.store(value & 1, Ordering::Relaxed), // only bit 0 (mask)
            _ => {}
        }
    }

    /// Get the MSI-X vector for a given table index.
    pub fn get_vector(&self, idx: u32) -> Option<u8> {
        if idx >= self.num_vectors || !self.is_enabled() {
            return None;
        }
        let entry = &self.entries[idx as usize];
        if entry.is_masked() || self.is_function_masked() {
            return None;
        }
        Some(entry.message().vector)
    }
}

/// Per-vCPU pending IRQ storage
/// Each vCPU has its own pending IRQ vector.
pub static VCPU_PENDING_IRQ: [core::sync::atomic::AtomicU8; 64] = [
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
    core::sync::atomic::AtomicU8::new(0), core::sync::atomic::AtomicU8::new(0),
];

/// Delivery modes
pub mod delivery {
    pub const FIXED: u8 = 0;
    pub const LOWEST_PRIORITY: u8 = 1;
    pub const SMI: u8 = 2;
    pub const NMI: u8 = 4;
    pub const INIT: u8 = 5;
    pub const EXT_INT: u8 = 7;
}

/// Redirection hint (for lowest priority delivery)
pub mod redirect {
    pub const ALL: u8 = 0;      // Deliver to all vCPUs
    pub const LOWEST: u8 = 1;   // Deliver to lowest priority vCPU
    pub const SINGLE: u8 = 2;   // Deliver to single vCPU
}

/// Deliver an MSI interrupt to the guest.
///
/// This sets the pending IRQ for the target vCPU(s) based on dest_id.
/// Supports Fixed, Lowest Priority, and NMI delivery modes.
pub fn deliver_msi(msg: &MsiMessage) {
    if msg.vector == 0 {
        return;
    }
    
    let dest_id = msg.dest_id;
    let delivery_mode = msg.delivery_mode;
    
    match delivery_mode {
        delivery::FIXED => {
            // Fixed delivery: target specific vCPU(s)
            if msg.dest_mode == 0 {
                // Physical mode: dest_id is APIC ID
                let vcpu_id = dest_id as usize;
                if vcpu_id < 64 {
                    let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                        0,
                        msg.vector,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            } else {
                // Logical mode: dest_id is logical APIC ID
                // Check APIC LDR/DFR to determine which vCPUs should receive the interrupt
                // 
                // Logical destination mode uses two registers:
                // - DFR (Destination Format Register): determines cluster/flat model
                //   - 0xFFFFFFFF = Flat model (all bits set)
                //   - 0x0FXXXXXX = Cluster model
                // - LDR (Logical Destination Register): 32-bit value where each bit represents a CPU
                //
                // In flat model: interrupt delivered to all CPUs whose LDR bit matches dest_id
                // In cluster model: dest_id[28:24] = cluster ID, dest_id[19:16] = local ID
                
                for vcpu_id in 0..64usize {
                    // Get vCPU's LDR and DFR values
                    // LDR format: [31:24] = logical ID, [23:0] = bit mask (flat model)
                    // DFR format: [31:28] = model (0xF = flat, 0x0 = cluster)
                    let ldr = get_vcpu_ldr(vcpu_id);
                    let dfr = get_vcpu_dfr(vcpu_id);
                    
                    // Check if this vCPU should receive the interrupt
                    let matches = if dfr == 0xFFFFFFFF {
                        // Flat model: dest_id & LDR != 0
                        (dest_id as u32) & ldr != 0
                    } else {
                        // Cluster model: cluster ID match + local ID match
                        let dest_cluster = (dest_id as u32 >> 4) & 0xF;
                        let dest_local = (dest_id as u32) & 0xF;
                        let vcpu_cluster = (ldr >> 28) & 0xF;
                        let vcpu_local = (ldr >> 24) & 0xF;
                        dest_cluster == vcpu_cluster && dest_local == vcpu_local
                    };
                    
                    if matches {
                        let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                            0,
                            msg.vector,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        );
                    }
                }
            }
        }
        delivery::LOWEST_PRIORITY => {
            // Lowest priority: deliver to vCPU with lowest priority
            // For simplicity, find vCPU with lowest pending IRQ count
            let mut target_vcpu = 0usize;
            for i in 1..64 {
                if VCPU_PENDING_IRQ[i].load(Ordering::Acquire) == 0 {
                    target_vcpu = i;
                    break;
                }
            }
            let _ = VCPU_PENDING_IRQ[target_vcpu].compare_exchange(
                0,
                msg.vector,
                Ordering::AcqRel,
                Ordering::Relaxed,
            );
        }
        delivery::NMI => {
            // NMI: deliver as non-maskable interrupt
            // Use vector 2 (NMI vector) or the specified vector
            let nmi_vector = if msg.vector == 2 { 2 } else { 2 };
            if msg.dest_mode == 0 {
                let vcpu_id = dest_id as usize;
                if vcpu_id < 64 {
                    let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                        0,
                        nmi_vector,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            } else {
                // Broadcast NMI
                for i in 0..64usize {
                    let _ = VCPU_PENDING_IRQ[i].compare_exchange(
                        0,
                        nmi_vector,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            }
        }
        delivery::SMI => {
            // SMI: System Management Interrupt
            // SMI causes the CPU to enter System Management Mode (SMM)
            // In SMM, the CPU executes code from SMRAM (SMI handler)
            // 
            // For virtualization, we need to:
            // 1. Save current guest state
            // 2. Switch to SMM mode (set SMM flag in VMCS/VMCB)
            // 3. Load SMI handler from SMRAM
            // 4. Execute SMI handler
            // 5. Return from SMM via RSM instruction
            
            // For now, we implement a simplified SMI:
            // - Set SMI pending flag for the target vCPU
            // - The VMX/SVM loop will handle the actual SMM entry
            
            if msg.dest_mode == 0 {
                // Physical mode: target specific vCPU
                let vcpu_id = dest_id as usize;
                if vcpu_id < 64 {
                    // Set SMI pending (use special vector 0xFF for SMI)
                    let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                        0,
                        0xFF, // SMI indicator
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            } else {
                // Logical mode: broadcast SMI to all matching vCPUs
                for i in 0..64u8 {
                    if (dest_id as u8) & (1 << (i % 8)) != 0 {
                        let vcpu_id = i as usize;
                        if vcpu_id < 64 {
                            let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                                0,
                                0xFF,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
            }
        }
        delivery::INIT => {
            // INIT: Initialize CPU
            // INIT causes the CPU to reset to a known state
            // Similar to hardware reset but preserves some state
            //
            // For virtualization, we need to:
            // 1. Reset vCPU state to initial values
            // 2. Clear pending interrupts
            // 3. Reset APIC state
            // 4. Set instruction pointer to reset vector (0xFFFFFFF0)
            
            if msg.dest_mode == 0 {
                // Physical mode: target specific vCPU
                let vcpu_id = dest_id as usize;
                if vcpu_id < 64 {
                    // Clear all pending IRQs for this vCPU
                    VCPU_PENDING_IRQ[vcpu_id].store(0, Ordering::Release);
                    
                    // Set INIT pending flag (use special vector 0xFE for INIT)
                    let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                        0,
                        0xFE, // INIT indicator
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    );
                }
            } else {
                // Logical mode: broadcast INIT to all matching vCPUs
                for i in 0..64u8 {
                    if (dest_id as u8) & (1 << (i % 8)) != 0 {
                        let vcpu_id = i as usize;
                        if vcpu_id < 64 {
                            VCPU_PENDING_IRQ[vcpu_id].store(0, Ordering::Release);
                            let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                                0,
                                0xFE,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
            }
        }
        delivery::EXT_INT => {
            // External Interrupt: treat as fixed
            let vcpu_id = dest_id as usize;
            if vcpu_id < 64 {
                let _ = VCPU_PENDING_IRQ[vcpu_id].compare_exchange(
                    0,
                    msg.vector,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                );
            }
        }
        _ => {
            // Unknown delivery mode - ignore
        }
    }
}

/// Get pending IRQ for a specific vCPU
pub fn get_pending_irq(vcpu_id: usize) -> u8 {
    if vcpu_id < 64 {
        VCPU_PENDING_IRQ[vcpu_id].load(Ordering::Acquire)
    } else {
        0
    }
}

/// Clear pending IRQ for a specific vCPU
pub fn clear_pending_irq(vcpu_id: usize) {
    if vcpu_id < 64 {
        VCPU_PENDING_IRQ[vcpu_id].store(0, Ordering::Release);
    }
}

/// Get vCPU's Logical Destination Register (LDR)
/// LDR format: [31:24] = logical ID, [23:0] = bit mask (flat model)
pub fn get_vcpu_ldr(vcpu_id: usize) -> u32 {
    // In flat model, each vCPU has a unique bit in LDR
    // LDR = 1 << (vcpu_id % 24) for flat model
    // For simplicity, we use the vCPU ID as the logical ID
    if vcpu_id < 64 {
        // Flat model: each CPU has one bit set
        // Bit position = vcpu_id (mod 24 for 24-bit mask)
        let bit_pos = vcpu_id % 24;
        1 << bit_pos
    } else {
        0
    }
}

/// Get vCPU's Destination Format Register (DFR)
/// DFR = 0xFFFFFFFF for flat model, 0x0FXXXXXX for cluster model
pub fn get_vcpu_dfr(_vcpu_id: usize) -> u32 {
    // Flat model: all bits set (0xFFFFFFFF)
    // This means all vCPUs use flat logical destination mode
    0xFFFFFFFF
}

/// Legacy function for backward compatibility
pub fn deliver_msi_legacy(msg: &MsiMessage) {
    use crate::vmm::vmx_handler::PENDING_IRQ;
    if msg.vector == 0 {
        return;
    }
    if msg.delivery_mode != 0 {
        return;
    }
    let _ = PENDING_IRQ.compare_exchange(
        0,
        msg.vector,
        Ordering::AcqRel,
        Ordering::Relaxed,
    );
}

/// Convenience: deliver MSI from raw address + data.
pub fn deliver_msi_raw(address: u64, data: u32) {
    let msg = MsiMessage::decode(address, data);
    deliver_msi(&msg);
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_message_decode_encode_roundtrip() {
        let addr: u64 = 0xFEE0_1000; // dest_id = 1
        let data: u32 = 0x0030;       // vector = 0x30, delivery = Fixed(0)
        let msg = MsiMessage::decode(addr, data);
        assert_eq!(msg.dest_id, 1);
        assert_eq!(msg.vector, 0x30);
        assert_eq!(msg.delivery_mode, 0);
        assert!(!msg.trigger_mode);

        let (enc_addr, enc_data) = msg.encode();
        assert_eq!(enc_addr & MSI_ADDR_MASK, MSI_ADDR_BASE);
        assert_eq!((enc_addr >> 12) & 0xFF, 1); // dest_id
        assert_eq!(enc_data & 0xFF, 0x30);       // vector
    }

    #[test]
    fn msi_capability_enable_disable() {
        let cap = MsiCapability::new();
        assert!(!cap.is_enabled());
        cap.set_enabled(true);
        assert!(cap.is_enabled());
        cap.set_enabled(false);
        assert!(!cap.is_enabled());
    }

    #[test]
    fn msi_capability_message_readback() {
        let cap = MsiCapability::new();
        cap.addr_lo.store(0xFEE0_2000, Ordering::Relaxed); // dest_id=2
        cap.data.store(0x0041, Ordering::Relaxed);          // vector=0x41
        let msg = cap.message();
        assert_eq!(msg.dest_id, 2);
        assert_eq!(msg.vector, 0x41);
    }

    #[test]
    fn msix_table_read_write() {
        let mut table = MsixTable::new();
        table.init(4);
        table.set_enabled(true);

        // Write vector 0: addr_lo, addr_hi, data, control
        table.write_entry(0, 0xFEE0_3000);  // addr_lo
        table.write_entry(4, 0);              // addr_hi
        table.write_entry(8, 0x0050);         // data: vector=0x50
        table.write_entry(12, 0);             // control: unmasked

        assert_eq!(table.read_entry(0), 0xFEE0_3000);
        assert_eq!(table.read_entry(8), 0x0050);
        assert_eq!(table.get_vector(0), Some(0x50));
    }

    #[test]
    fn msix_masked_vector_returns_none() {
        let mut table = MsixTable::new();
        table.init(2);
        table.set_enabled(true);

        // Vector 0: unmasked
        table.write_entry(8, 0x60);
        table.write_entry(12, 0); // unmasked
        assert_eq!(table.get_vector(0), Some(0x60));

        // Vector 1: masked
        table.write_entry(16 + 8, 0x61);
        table.write_entry(16 + 12, 1); // masked
        assert_eq!(table.get_vector(1), None);
    }

    #[test]
    fn msix_function_mask_blocks_all() {
        let mut table = MsixTable::new();
        table.init(1);
        table.set_enabled(true);
        table.write_entry(8, 0x70);
        table.write_entry(12, 0); // unmasked

        assert_eq!(table.get_vector(0), Some(0x70));
        table.set_function_mask(true);
        assert_eq!(table.get_vector(0), None);
    }
}
