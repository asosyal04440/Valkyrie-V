#![allow(clippy::unnecessary_cast)]
#![allow(clippy::declare_interior_mutable_const)]

use crate::vmm::vcpu::{
    VcpuState, ICR_DELIVERY_INIT, ICR_DELIVERY_STARTUP, ICR_DEST_ALL, MAX_VCPUS,
};
use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

pub const IPI_VECTOR_BROADCAST: u8 = 0xFB;
pub const IPI_VECTOR_INIT: u8 = 0xFC;
pub const IPI_VECTOR_STARTUP: u8 = 0xFD;
pub const IPI_VECTOR_CALL_FUNCTION: u8 = 0xFA;
pub const IPI_VECTOR_CALL_FUNCTION_SINGLE: u8 = 0xF9;
pub const IPI_VECTOR_INVOKE_CALLEE: u8 = 0xFE;
pub const IPI_VECTOR_RESCHEDULE: u8 = 0xF8;
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 0xF7;
pub const IPI_VECTOR_WAKEUP: u8 = 0xF6;
pub const IPI_VECTOR_STOP: u8 = 0xF5;

/// Maximum pending TLB flush requests in the batch queue
pub const TLB_FLUSH_BATCH_SIZE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiType {
    Init,
    Startup,
    Reschedule,
    CallFunction,
    CallFunctionSingle,
    TlbShootdown,
    Nmi,
    Wakeup,
    Stop,
    Unknown,
}

impl IpiType {
    pub fn from_vector(vector: u8) -> Self {
        match vector {
            IPI_VECTOR_INIT => Self::Init,
            IPI_VECTOR_STARTUP => Self::Startup,
            IPI_VECTOR_RESCHEDULE => Self::Reschedule,
            IPI_VECTOR_CALL_FUNCTION => Self::CallFunction,
            IPI_VECTOR_CALL_FUNCTION_SINGLE => Self::CallFunctionSingle,
            IPI_VECTOR_TLB_SHOOTDOWN => Self::TlbShootdown,
            IPI_VECTOR_WAKEUP => Self::Wakeup,
            IPI_VECTOR_STOP => Self::Stop,
            IPI_VECTOR_INVOKE_CALLEE => Self::Unknown, // 0xFE reserved
            _ => Self::Unknown,
        }
    }

    pub fn to_vector(&self) -> u8 {
        match self {
            Self::Init => IPI_VECTOR_INIT,
            Self::Startup => IPI_VECTOR_STARTUP,
            Self::Reschedule => IPI_VECTOR_RESCHEDULE,
            Self::CallFunction => IPI_VECTOR_CALL_FUNCTION,
            Self::CallFunctionSingle => IPI_VECTOR_CALL_FUNCTION_SINGLE,
            Self::TlbShootdown => IPI_VECTOR_TLB_SHOOTDOWN,
            Self::Wakeup => IPI_VECTOR_WAKEUP,
            Self::Stop => IPI_VECTOR_STOP,
            Self::Nmi => 0x02,
            Self::Unknown => 0xFF,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct IpiMessage {
    pub dest_cpu: u32,
    pub vector: u8,
    pub ipi_type: IpiType,
    pub delivery_mode: u32,
    /// ICR bit 11: 0 = physical destination, 1 = logical destination.
    pub dest_mode: u32,
    /// ICR bits 19:18: destination shorthand (0=none, 1=self, 2=all-incl-self, 3=all-excl-self).
    pub shorthand: u8,
    pub level_triggered: bool,
    pub logical_dest: u8,
}

impl IpiMessage {
    pub fn from_icr(icr_low: u32, icr_high: u32) -> Self {
        let vector = (icr_low & 0xFF) as u8;
        let delivery_mode = icr_low & 0x700; // bits 10:8
        let dest_mode = icr_low & 0x800; // bit 11 (0=physical, 1=logical)
        let level_triggered = (icr_low & 0x8000) != 0;
        let shorthand = ((icr_low >> 18) & 3) as u8; // bits 19:18
        let dest_cpu = ((icr_high >> 24) & 0xFF) as u32;
        let logical_dest = ((icr_high >> 24) & 0xFF) as u8;

        Self {
            dest_cpu,
            vector,
            ipi_type: IpiType::from_vector(vector),
            delivery_mode,
            dest_mode,
            shorthand,
            level_triggered,
            logical_dest,
        }
    }

    /// Returns true if the ICR destination shorthand targets all vCPUs
    /// (shorthand 0b10 = all-including-self, 0b11 = all-excluding-self).
    pub fn is_broadcast(&self) -> bool {
        (self.shorthand & 2) != 0
    }

    pub fn is_self_ipi(&self) -> bool {
        (self.dest_mode & 0x40000) != 0
    }
}

pub struct IpiController {
    pending_ipis: [AtomicU32; MAX_VCPUS],
    ipi_counts: [AtomicU64; MAX_VCPUS],
    /// Batched TLB flush target bitmap - which vCPUs need TLB flush
    tlb_flush_pending: AtomicU64,
    /// Number of pending TLB flush requests in the batch
    tlb_flush_count: AtomicU8,
    /// Generation counter for TLB flush synchronization
    tlb_flush_gen: AtomicU64,
}

impl IpiController {
    pub const fn new() -> Self {
        const ZERO: AtomicU32 = AtomicU32::new(0);
        const ZERO64: AtomicU64 = AtomicU64::new(0);
        const ZERO8: AtomicU8 = AtomicU8::new(0);
        Self {
            pending_ipis: [ZERO; MAX_VCPUS],
            ipi_counts: [ZERO64; MAX_VCPUS],
            tlb_flush_pending: ZERO64,
            tlb_flush_count: ZERO8,
            tlb_flush_gen: ZERO64,
        }
    }

    pub fn send_ipi(&self, vcpu_state: &VcpuState, message: &IpiMessage) -> Result<(), HvError> {
        if message.is_self_ipi() {
            self.handle_ipi_local(0, message);
            return Ok(());
        }

        if message.is_broadcast() {
            let count = vcpu_state.get_count();
            for i in 0..count {
                self.handle_ipi_local(i, message);
            }
        } else if message.dest_cpu < MAX_VCPUS as u32 {
            self.handle_ipi_local(message.dest_cpu, message);
        } else {
            return Err(HvError::LogicalFault);
        }

        Ok(())
    }

    fn handle_ipi_local(&self, cpu: u32, message: &IpiMessage) {
        if cpu as usize >= MAX_VCPUS {
            return;
        }

        self.ipi_counts[cpu as usize].fetch_add(1, Ordering::Relaxed);

        match message.ipi_type {
            IpiType::Init => {
                // Set bit 0: signal INIT reset to target vCPU.
                self.pending_ipis[cpu as usize].fetch_or(0x0000_0001, Ordering::Release);
            }
            IpiType::Startup => {
                // Encode SIPI: bit 1 set + startup vector in bits 15:8.
                let val = 0x0000_0002u32 | ((message.vector as u32) << 8);
                self.pending_ipis[cpu as usize].store(val, Ordering::Release);
            }
            _ => {
                self.pending_ipis[cpu as usize].fetch_add(1, Ordering::Release);
            }
        }
    }

    pub fn check_pending_ipi(&self, cpu: u32) -> bool {
        if cpu as usize >= MAX_VCPUS {
            return false;
        }
        self.pending_ipis[cpu as usize].load(Ordering::Acquire) != 0
    }

    pub fn clear_pending_ipi(&self, cpu: u32) {
        if cpu as usize >= MAX_VCPUS {
            return;
        }
        self.pending_ipis[cpu as usize].store(0, Ordering::Release);
    }

    pub fn get_ipi_count(&self, cpu: u32) -> u64 {
        if cpu as usize >= MAX_VCPUS {
            return 0;
        }
        self.ipi_counts[cpu as usize].load(Ordering::Acquire)
    }

    pub fn process_ipi(&self, vcpu: &crate::vmm::vcpu::Vcpu) -> Option<u8> {
        let cpu_id = vcpu.id as usize;
        if cpu_id >= MAX_VCPUS {
            return None;
        }

        if !self.check_pending_ipi(vcpu.id) {
            return None;
        }

        self.clear_pending_ipi(vcpu.id);

        Some(0xFC)
    }

    pub fn broadcast_init(&self, vcpu_state: &VcpuState) {
        let message = IpiMessage {
            dest_cpu: 0xFF,
            vector: IPI_VECTOR_INIT,
            ipi_type: IpiType::Init,
            delivery_mode: ICR_DELIVERY_INIT,
            dest_mode: ICR_DEST_ALL,
            shorthand: 2, // all-including-self
            level_triggered: true,
            logical_dest: 0,
        };

        let count = vcpu_state.get_count();
        for _ in 0..count {
            let _ = self.send_ipi(vcpu_state, &message);
        }
    }

    pub fn broadcast_startup(&self, vcpu_state: &VcpuState, vector: u8) {
        let message = IpiMessage {
            dest_cpu: 0xFF,
            vector,
            ipi_type: IpiType::Startup,
            delivery_mode: ICR_DELIVERY_STARTUP,
            dest_mode: ICR_DEST_ALL,
            shorthand: 3, // all-excluding-self (APs only)
            level_triggered: false,
            logical_dest: 0,
        };

        let count = vcpu_state.get_count();
        for _ in 1..count {
            let _ = self.send_ipi(vcpu_state, &message);
        }
    }

    // ── TLB Shootdown Batching ───────────────────────────────────────────────

    /// Request a TLB flush for a specific vCPU.
    /// The flush is batched and will be sent with the next flush_batch() call.
    pub fn request_tlb_flush(&self, target_vcpu: u32) {
        if target_vcpu >= MAX_VCPUS as u32 {
            return;
        }
        
        // Set the bit for this vCPU in the pending bitmap
        self.tlb_flush_pending.fetch_or(1u64 << target_vcpu, Ordering::Release);
        
        // Increment the batch count
        let count = self.tlb_flush_count.fetch_add(1, Ordering::Release);
        
        // If batch is full, flush immediately
        if count >= TLB_FLUSH_BATCH_SIZE as u8 - 1 {
            self.flush_tlb_batch();
        }
    }

    /// Request TLB flush for multiple vCPUs at once.
    pub fn request_tlb_flush_batch(&self, target_mask: u64) {
        self.tlb_flush_pending.fetch_or(target_mask, Ordering::Release);
        self.tlb_flush_count.fetch_add(target_mask.count_ones() as u8, Ordering::Release);
    }

    /// Flush all pending TLB shootdown IPIs as a single broadcast.
    /// Returns the bitmap of vCPUs that were targeted.
    pub fn flush_tlb_batch(&self) -> u64 {
        let targets = self.tlb_flush_pending.swap(0, Ordering::AcqRel);
        if targets == 0 {
            return 0;
        }
        
        self.tlb_flush_count.store(0, Ordering::Release);
        let gen = self.tlb_flush_gen.fetch_add(1, Ordering::Release);
        
        // In a real implementation, this would send a single broadcast IPI
        // to all target vCPUs with the TLB shootdown vector.
        // For now, we just record the pending IPI for each target.
        let mut count = 0u32;
        while count < MAX_VCPUS as u32 {
            if (targets & (1u64 << count)) != 0 {
                // Set TLB shootdown pending bit for this vCPU
                // Bit 2 in pending_ipis indicates TLB flush needed
                self.pending_ipis[count as usize].fetch_or(0x0000_0004, Ordering::Release);
            }
            count += 1;
        }
        
        targets
    }

    /// Check if a vCPU has a pending TLB flush.
    pub fn has_pending_tlb_flush(&self, vcpu_id: u32) -> bool {
        if vcpu_id as usize >= MAX_VCPUS {
            return false;
        }
        (self.pending_ipis[vcpu_id as usize].load(Ordering::Acquire) & 0x0000_0004) != 0
    }

    /// Clear the pending TLB flush for a vCPU (called after vCPU completes INVLPG/INVEPT).
    pub fn clear_pending_tlb_flush(&self, vcpu_id: u32) {
        if vcpu_id as usize >= MAX_VCPUS {
            return;
        }
        self.pending_ipis[vcpu_id as usize].fetch_and(!0x0000_0004, Ordering::Release);
    }

    /// Get the current TLB flush generation counter.
    pub fn tlb_flush_generation(&self) -> u64 {
        self.tlb_flush_gen.load(Ordering::Acquire)
    }

    /// Send a reschedule IPI to a specific vCPU.
    pub fn send_reschedule(&self, target_vcpu: u32) {
        if target_vcpu as usize >= MAX_VCPUS {
            return;
        }
        // Bit 3 indicates reschedule request
        self.pending_ipis[target_vcpu as usize].fetch_or(0x0000_0008, Ordering::Release);
    }

    /// Check if a vCPU has a pending reschedule request.
    pub fn has_pending_reschedule(&self, vcpu_id: u32) -> bool {
        if vcpu_id as usize >= MAX_VCPUS {
            return false;
        }
        (self.pending_ipis[vcpu_id as usize].load(Ordering::Acquire) & 0x0000_0008) != 0
    }

    /// Clear the pending reschedule for a vCPU.
    pub fn clear_pending_reschedule(&self, vcpu_id: u32) {
        if vcpu_id as usize >= MAX_VCPUS {
            return;
        }
        self.pending_ipis[vcpu_id as usize].fetch_and(!0x0000_0008, Ordering::Release);
    }

    /// Send a wakeup IPI to a blocked vCPU.
    pub fn send_wakeup(&self, target_vcpu: u32, vcpu_state: &VcpuState) -> Result<(), HvError> {
        let message = IpiMessage {
            dest_cpu: target_vcpu,
            vector: IPI_VECTOR_WAKEUP,
            ipi_type: IpiType::Wakeup,
            delivery_mode: 0, // Fixed delivery
            dest_mode: 0,     // Physical destination
            shorthand: 0,     // No shorthand
            level_triggered: false,
            logical_dest: 0,
        };
        self.send_ipi(vcpu_state, &message)
    }

    /// Send a stop IPI to halt a vCPU.
    pub fn send_stop(&self, target_vcpu: u32, vcpu_state: &VcpuState) -> Result<(), HvError> {
        let message = IpiMessage {
            dest_cpu: target_vcpu,
            vector: IPI_VECTOR_STOP,
            ipi_type: IpiType::Stop,
            delivery_mode: 0,
            dest_mode: 0,
            shorthand: 0,
            level_triggered: false,
            logical_dest: 0,
        };
        self.send_ipi(vcpu_state, &message)
    }
}

impl Default for IpiController {
    fn default() -> Self {
        Self::new()
    }
}
