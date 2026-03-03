//! IOAT/DMA Engine Support
//!
//! Intel I/OAT (I/O Acceleration Technology) DMA engine for high-performance memory operations.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// IOAT Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum DMA channels
pub const MAX_DMA_CHANNELS: usize = 32;

/// Maximum DMA descriptors
pub const MAX_DMA_DESCRIPTORS: usize = 4096;

/// Maximum pending operations
pub const MAX_PENDING_OPS: usize = 1024;

/// DMA operation types
pub mod dma_op_type {
    pub const MEMCPY: u8 = 0;
    pub const MEMSET: u8 = 1;
    pub const MEMMOVE: u8 = 2;
    pub const XOR: u8 = 3;
    pub const PQ: u8 = 4;
    pub const FILL: u8 = 5;
}

/// DMA operation status
pub mod dma_status {
    pub const PENDING: u8 = 0;
    pub const SUBMITTED: u8 = 1;
    pub const IN_PROGRESS: u8 = 2;
    pub const COMPLETED: u8 = 3;
    pub const FAILED: u8 = 4;
    pub const CANCELLED: u8 = 5;
}

/// DMA priority levels
pub mod dma_priority {
    pub const LOW: u8 = 0;
    pub const NORMAL: u8 = 1;
    pub const HIGH: u8 = 2;
    pub const CRITICAL: u8 = 3;
}

/// IOAT register offsets
pub mod ioat_reg {
    pub const CHANCTRL: u64 = 0x00;
    pub const CHANSTS: u64 = 0x08;
    pub const CHANERR: u64 = 0x10;
    pub const CHANCMP: u64 = 0x18;
    pub const DCACTRL: u64 = 0x20;
    pub const CMD: u64 = 0x28;
    pub const DMACOUNT: u64 = 0x30;
    pub const CHANADDR: u64 = 0x38;
    pub const CHANERRMSK: u64 = 0x40;
    pub const CHANERRSET: u64 = 0x48;
    pub const CHANERRCLR: u64 = 0x50;
    pub const CHANERR_INT: u64 = 0x58;
    pub const CHANERR_SV: u64 = 0x60;
    pub const CHANERR_SV_MASK: u64 = 0x68;
    pub const CHANERR_SV_SET: u64 = 0x70;
    pub const CHANERR_SV_CLR: u64 = 0x78;
}

// ─────────────────────────────────────────────────────────────────────────────
// DMA Descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// DMA descriptor for IOAT
pub struct DmaDescriptor {
    /// Descriptor ID
    pub id: AtomicU32,
    /// Source address
    pub src_addr: AtomicU64,
    /// Destination address
    pub dst_addr: AtomicU64,
    /// Size in bytes
    pub size: AtomicU32,
    /// Control flags
    pub control: AtomicU32,
    /// Next descriptor address
    pub next: AtomicU64,
    /// Completion status
    pub status: AtomicU64,
    /// Operation type
    pub op_type: AtomicU8,
    /// Priority
    pub priority: AtomicU8,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Callback ID
    pub callback_id: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl DmaDescriptor {
    pub const fn new() -> Self {
        Self {
            id: AtomicU32::new(0),
            src_addr: AtomicU64::new(0),
            dst_addr: AtomicU64::new(0),
            size: AtomicU32::new(0),
            control: AtomicU32::new(0),
            next: AtomicU64::new(0),
            status: AtomicU64::new(0),
            op_type: AtomicU8::new(dma_op_type::MEMCPY),
            priority: AtomicU8::new(dma_priority::NORMAL),
            vm_id: AtomicU32::new(0),
            callback_id: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize descriptor
    pub fn init(&self, id: u32, src: u64, dst: u64, size: u32, op_type: u8) {
        self.id.store(id, Ordering::Release);
        self.src_addr.store(src, Ordering::Release);
        self.dst_addr.store(dst, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.op_type.store(op_type, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set control flags
    pub fn set_control(&self, flags: u32) {
        self.control.store(flags, Ordering::Release);
    }

    /// Set next descriptor
    pub fn set_next(&self, next: u64) {
        self.next.store(next, Ordering::Release);
    }

    /// Set completion status
    pub fn set_status(&self, status: u64) {
        self.status.store(status, Ordering::Release);
    }

    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.status.load(Ordering::Acquire) & 0x1 != 0
    }

    /// Has error
    pub fn has_error(&self) -> bool {
        self.status.load(Ordering::Acquire) & 0x2 != 0
    }
}

impl Default for DmaDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DMA Channel
// ─────────────────────────────────────────────────────────────────────────────

/// DMA channel state
pub struct DmaChannel {
    /// Channel ID
    pub channel_id: AtomicU8,
    /// Channel type
    pub channel_type: AtomicU8,
    /// MMIO base address
    pub mmio_base: AtomicU64,
    /// Descriptor ring base
    pub ring_base: AtomicU64,
    /// Ring size
    pub ring_size: AtomicU16,
    /// Head index
    pub head: AtomicU16,
    /// Tail index
    pub tail: AtomicU16,
    /// Pending count
    pub pending_count: AtomicU16,
    /// Descriptors
    pub descriptors: [DmaDescriptor; MAX_DMA_DESCRIPTORS],
    /// Enabled
    pub enabled: AtomicBool,
    /// Active
    pub active: AtomicBool,
    /// Interrupt enabled
    pub intr_enabled: AtomicBool,
    /// Interrupt vector
    pub intr_vector: AtomicU8,
    /// Operations completed
    pub ops_completed: AtomicU64,
    /// Bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Errors
    pub errors: AtomicU64,
    /// Last error code
    pub last_error: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl DmaChannel {
    pub const fn new() -> Self {
        Self {
            channel_id: AtomicU8::new(0),
            channel_type: AtomicU8::new(0),
            mmio_base: AtomicU64::new(0),
            ring_base: AtomicU64::new(0),
            ring_size: AtomicU16::new(MAX_DMA_DESCRIPTORS as u16),
            head: AtomicU16::new(0),
            tail: AtomicU16::new(0),
            pending_count: AtomicU16::new(0),
            descriptors: [const { DmaDescriptor::new() }; MAX_DMA_DESCRIPTORS],
            enabled: AtomicBool::new(false),
            active: AtomicBool::new(false),
            intr_enabled: AtomicBool::new(false),
            intr_vector: AtomicU8::new(0),
            ops_completed: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize channel
    pub fn init(&self, channel_id: u8, mmio_base: u64, ring_size: u16) {
        self.channel_id.store(channel_id, Ordering::Release);
        self.mmio_base.store(mmio_base, Ordering::Release);
        self.ring_size.store(ring_size, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable channel
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable channel
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        self.active.store(false, Ordering::Release);
    }

    /// Start channel
    pub fn start(&self) {
        self.active.store(true, Ordering::Release);
    }

    /// Stop channel
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
    }

    /// Submit descriptor
    pub fn submit(&self, desc_idx: u16) -> Result<(), HvError> {
        if !self.enabled.load(Ordering::Acquire) || !self.active.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let head = self.head.load(Ordering::Acquire);
        let size = self.ring_size.load(Ordering::Acquire);
        
        if self.pending_count.load(Ordering::Acquire) >= size {
            return Err(HvError::LogicalFault);
        }
        
        // Link to ring
        let desc = &self.descriptors[head as usize];
        
        // Update head
        self.head.store((head + 1) % size, Ordering::Release);
        self.pending_count.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Process completions
    pub fn process_completions(&self) -> u16 {
        let mut completed = 0u16;
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        
        let mut idx = tail;
        while idx != head {
            let desc = &self.descriptors[idx as usize];
            
            if desc.is_complete() {
                self.ops_completed.fetch_add(1, Ordering::Release);
                self.bytes_transferred.fetch_add(desc.size.load(Ordering::Acquire) as u64, Ordering::Release);
                
                if desc.has_error() {
                    self.errors.fetch_add(1, Ordering::Release);
                }
                
                desc.valid.store(false, Ordering::Release);
                completed += 1;
                self.pending_count.fetch_sub(1, Ordering::Release);
            } else {
                break;
            }
            
            idx = (idx + 1) % self.ring_size.load(Ordering::Acquire);
        }
        
        self.tail.store(idx, Ordering::Release);
        completed
    }

    /// Get available slots
    pub fn get_available(&self) -> u16 {
        let size = self.ring_size.load(Ordering::Acquire);
        let pending = self.pending_count.load(Ordering::Acquire);
        size - pending
    }

    /// Set interrupt
    pub fn set_interrupt(&self, enabled: bool, vector: u8) {
        self.intr_enabled.store(enabled, Ordering::Release);
        self.intr_vector.store(vector, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> ChannelStats {
        ChannelStats {
            enabled: self.enabled.load(Ordering::Acquire),
            active: self.active.load(Ordering::Acquire),
            pending: self.pending_count.load(Ordering::Acquire),
            ops_completed: self.ops_completed.load(Ordering::Acquire),
            bytes_transferred: self.bytes_transferred.load(Ordering::Acquire),
            errors: self.errors.load(Ordering::Acquire),
        }
    }
}

impl Default for DmaChannel {
    fn default() -> Self {
        Self::new()
    }
}

/// Channel statistics
#[repr(C)]
pub struct ChannelStats {
    pub enabled: bool,
    pub active: bool,
    pub pending: u16,
    pub ops_completed: u64,
    pub bytes_transferred: u64,
    pub errors: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// DMA Operation
// ─────────────────────────────────────────────────────────────────────────────

/// Pending DMA operation
pub struct DmaOperation {
    /// Operation ID
    pub op_id: AtomicU32,
    /// Operation type
    pub op_type: AtomicU8,
    /// Status
    pub status: AtomicU8,
    /// Priority
    pub priority: AtomicU8,
    /// Source address
    pub src_addr: AtomicU64,
    /// Destination address
    pub dst_addr: AtomicU64,
    /// Size in bytes
    pub size: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Channel ID
    pub channel_id: AtomicU8,
    /// Descriptor index
    pub desc_idx: AtomicU16,
    /// Submit timestamp
    pub submit_time: AtomicU64,
    /// Complete timestamp
    pub complete_time: AtomicU64,
    /// Callback ID
    pub callback_id: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl DmaOperation {
    pub const fn new() -> Self {
        Self {
            op_id: AtomicU32::new(0),
            op_type: AtomicU8::new(dma_op_type::MEMCPY),
            status: AtomicU8::new(dma_status::PENDING),
            priority: AtomicU8::new(dma_priority::NORMAL),
            src_addr: AtomicU64::new(0),
            dst_addr: AtomicU64::new(0),
            size: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            channel_id: AtomicU8::new(0xFF),
            desc_idx: AtomicU16::new(0),
            submit_time: AtomicU64::new(0),
            complete_time: AtomicU64::new(0),
            callback_id: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize operation
    pub fn init(&self, op_id: u32, op_type: u8, src: u64, dst: u64, size: u32, vm_id: u32) {
        self.op_id.store(op_id, Ordering::Release);
        self.op_type.store(op_type, Ordering::Release);
        self.src_addr.store(src, Ordering::Release);
        self.dst_addr.store(dst, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.status.store(dma_status::PENDING, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set status
    pub fn set_status(&self, status: u8) {
        self.status.store(status, Ordering::Release);
    }

    /// Set channel
    pub fn set_channel(&self, channel: u8, desc_idx: u16) {
        self.channel_id.store(channel, Ordering::Release);
        self.desc_idx.store(desc_idx, Ordering::Release);
    }

    /// Is complete
    pub fn is_complete(&self) -> bool {
        self.status.load(Ordering::Acquire) == dma_status::COMPLETED
    }

    /// Is failed
    pub fn is_failed(&self) -> bool {
        self.status.load(Ordering::Acquire) == dma_status::FAILED
    }

    /// Get latency
    pub fn get_latency(&self) -> u64 {
        let submit = self.submit_time.load(Ordering::Acquire);
        let complete = self.complete_time.load(Ordering::Acquire);
        
        if complete > submit {
            complete - submit
        } else {
            0
        }
    }
}

impl Default for DmaOperation {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DMA Controller
// ─────────────────────────────────────────────────────────────────────────────

/// DMA controller
pub struct DmaController {
    /// DMA channels
    pub channels: [DmaChannel; MAX_DMA_CHANNELS],
    /// Channel count
    pub channel_count: AtomicU8,
    /// Pending operations
    pub operations: [DmaOperation; MAX_PENDING_OPS],
    /// Operation count
    pub op_count: AtomicU16,
    /// Next operation ID
    pub next_op_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// IOAT version
    pub ioat_version: AtomicU8,
    /// Max transfer size
    pub max_xfer_size: AtomicU32,
    /// Max descriptors per channel
    pub max_desc_per_channel: AtomicU16,
    /// Supports DCA
    pub dca_supported: AtomicBool,
    /// Supports XOR
    pub xor_supported: AtomicBool,
    /// Supports PQ
    pub pq_supported: AtomicBool,
    /// Total operations
    pub total_ops: AtomicU64,
    /// Total bytes
    pub total_bytes: AtomicU64,
    /// Total errors
    pub total_errors: AtomicU64,
    /// Total latency (ns)
    pub total_latency: AtomicU64,
    /// Operations avoided (CPU memcpy)
    pub ops_avoided: AtomicU64,
    /// Bytes avoided
    pub bytes_avoided: AtomicU64,
}

impl DmaController {
    pub const fn new() -> Self {
        Self {
            channels: [const { DmaChannel::new() }; MAX_DMA_CHANNELS],
            channel_count: AtomicU8::new(0),
            operations: [const { DmaOperation::new() }; MAX_PENDING_OPS],
            op_count: AtomicU16::new(0),
            next_op_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            ioat_version: AtomicU8::new(3), // IOAT v3
            max_xfer_size: AtomicU32::new(16 * 1024 * 1024), // 16MB
            max_desc_per_channel: AtomicU16::new(MAX_DMA_DESCRIPTORS as u16),
            dca_supported: AtomicBool::new(false),
            xor_supported: AtomicBool::new(false),
            pq_supported: AtomicBool::new(false),
            total_ops: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            total_latency: AtomicU64::new(0),
            ops_avoided: AtomicU64::new(0),
            bytes_avoided: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, version: u8, max_xfer: u32) {
        self.ioat_version.store(version, Ordering::Release);
        self.max_xfer_size.store(max_xfer, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
        
        // Stop all channels
        for i in 0..self.channel_count.load(Ordering::Acquire) as usize {
            self.channels[i].stop();
        }
    }

    /// Register channel
    pub fn register_channel(&mut self, mmio_base: u64, channel_type: u8) -> Result<u8, HvError> {
        let count = self.channel_count.load(Ordering::Acquire);
        if count as usize >= MAX_DMA_CHANNELS {
            return Err(HvError::LogicalFault);
        }
        
        let channel = &self.channels[count as usize];
        channel.init(count, mmio_base, MAX_DMA_DESCRIPTORS as u16);
        channel.channel_type.store(channel_type, Ordering::Release);
        
        self.channel_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Get channel
    pub fn get_channel(&self, channel_id: u8) -> Option<&DmaChannel> {
        if channel_id as usize >= MAX_DMA_CHANNELS {
            return None;
        }
        Some(&self.channels[channel_id as usize])
    }

    /// Find best channel for operation
    pub fn find_best_channel(&self, size: u32, priority: u8) -> Option<u8> {
        let mut best_channel: Option<u8> = None;
        let mut best_available: u16 = 0;
        
        for i in 0..self.channel_count.load(Ordering::Acquire) as usize {
            let channel = &self.channels[i];
            
            if !channel.enabled.load(Ordering::Acquire) || 
               !channel.active.load(Ordering::Acquire) {
                continue;
            }
            
            let available = channel.get_available();
            
            // Prefer channels with more available slots
            if available > best_available {
                best_available = available;
                best_channel = Some(i as u8);
            }
        }
        
        best_channel
    }

    /// Submit DMA operation
    pub fn submit_op(&mut self, op_type: u8, src: u64, dst: u64, 
                     size: u32, vm_id: u32, priority: u8) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Check if DMA is beneficial
        if !self.should_use_dma(size) {
            self.ops_avoided.fetch_add(1, Ordering::Release);
            self.bytes_avoided.fetch_add(size as u64, Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        // Find channel
        let channel_id = self.find_best_channel(size, priority)
            .ok_or(HvError::LogicalFault)?;
        
        let channel = &self.channels[channel_id as usize];
        
        // Create operation
        let op_id = self.next_op_id.fetch_add(1, Ordering::Release);
        let op_slot = self.find_op_slot()?;
        
        let op = &self.operations[op_slot as usize];
        op.init(op_id, op_type, src, dst, size, vm_id);
        op.priority.store(priority, Ordering::Release);
        op.set_channel(channel_id, channel.head.load(Ordering::Acquire));
        op.submit_time.store(Self::get_timestamp(), Ordering::Release);
        
        // Create descriptor
        let desc_idx = channel.head.load(Ordering::Acquire);
        let desc = &channel.descriptors[desc_idx as usize];
        desc.init(op_id, src, dst, size, op_type);
        desc.vm_id.store(vm_id, Ordering::Release);
        desc.priority.store(priority, Ordering::Release);
        
        // Submit to channel
        channel.submit(desc_idx)?;
        
        op.set_status(dma_status::SUBMITTED);
        self.op_count.fetch_add(1, Ordering::Release);
        
        Ok(op_id)
    }

    /// Submit memcpy
    pub fn memcpy(&mut self, src: u64, dst: u64, size: u32, 
                  vm_id: u32, priority: u8) -> Result<u32, HvError> {
        self.submit_op(dma_op_type::MEMCPY, src, dst, size, vm_id, priority)
    }

    /// Submit memset
    pub fn memset(&mut self, dst: u64, value: u8, size: u32, 
                  vm_id: u32, priority: u8) -> Result<u32, HvError> {
        // For memset, src contains the fill value
        self.submit_op(dma_op_type::MEMSET, value as u64, dst, size, vm_id, priority)
    }

    /// Check if DMA is beneficial
    fn should_use_dma(&self, size: u32) -> bool {
        // DMA overhead vs CPU memcpy
        // For small sizes, CPU is faster
        // Threshold depends on hardware
        let min_dma_size = 4096; // 4KB
        size >= min_dma_size
    }

    /// Find free operation slot
    fn find_op_slot(&self) -> Result<u16, HvError> {
        for i in 0..MAX_PENDING_OPS {
            if !self.operations[i].valid.load(Ordering::Acquire) {
                return Ok(i as u16);
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Process completions
    pub fn process_completions(&self) -> u32 {
        let mut completed = 0u32;
        
        // Process each channel
        for i in 0..self.channel_count.load(Ordering::Acquire) as usize {
            let channel = &self.channels[i];
            if channel.active.load(Ordering::Acquire) {
                completed += channel.process_completions() as u32;
            }
        }
        
        // Update operations
        for i in 0..MAX_PENDING_OPS {
            let op = &self.operations[i];
            if op.valid.load(Ordering::Acquire) && 
               op.status.load(Ordering::Acquire) == dma_status::IN_PROGRESS {
                
                let channel_id = op.channel_id.load(Ordering::Acquire);
                if channel_id as usize >= MAX_DMA_CHANNELS {
                    continue;
                }
                
                let desc_idx = op.desc_idx.load(Ordering::Acquire) as usize;
                let desc = &self.channels[channel_id as usize].descriptors[desc_idx];
                
                if desc.is_complete() {
                    op.complete_time.store(Self::get_timestamp(), Ordering::Release);
                    
                    if desc.has_error() {
                        op.set_status(dma_status::FAILED);
                        self.total_errors.fetch_add(1, Ordering::Release);
                    } else {
                        op.set_status(dma_status::COMPLETED);
                        self.total_ops.fetch_add(1, Ordering::Release);
                        self.total_bytes.fetch_add(op.size.load(Ordering::Acquire) as u64, Ordering::Release);
                        self.total_latency.fetch_add(op.get_latency(), Ordering::Release);
                    }
                    
                    completed += 1;
                }
            }
        }
        
        completed
    }

    /// Cancel operation
    pub fn cancel_op(&self, op_id: u32) -> Result<(), HvError> {
        for i in 0..MAX_PENDING_OPS {
            let op = &self.operations[i];
            if op.valid.load(Ordering::Acquire) && 
               op.op_id.load(Ordering::Acquire) == op_id {
                op.set_status(dma_status::CANCELLED);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Get operation status
    pub fn get_op_status(&self, op_id: u32) -> Option<u8> {
        for i in 0..MAX_PENDING_OPS {
            if self.operations[i].op_id.load(Ordering::Acquire) == op_id {
                return Some(self.operations[i].status.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Wait for operation completion
    pub fn wait_op(&self, op_id: u32, timeout_ns: u64) -> u8 {
        let start = Self::get_timestamp();
        
        loop {
            if let Some(status) = self.get_op_status(op_id) {
                if status == dma_status::COMPLETED || 
                   status == dma_status::FAILED ||
                   status == dma_status::CANCELLED {
                    return status;
                }
            }
            
            let now = Self::get_timestamp();
            if now - start > timeout_ns {
                return dma_status::PENDING;
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> DmaStats {
        DmaStats {
            enabled: self.enabled.load(Ordering::Acquire),
            channel_count: self.channel_count.load(Ordering::Acquire),
            pending_ops: self.op_count.load(Ordering::Acquire),
            total_ops: self.total_ops.load(Ordering::Acquire),
            total_bytes: self.total_bytes.load(Ordering::Acquire),
            total_errors: self.total_errors.load(Ordering::Acquire),
            avg_latency_ns: self.get_avg_latency(),
            ops_avoided: self.ops_avoided.load(Ordering::Acquire),
            bytes_avoided: self.bytes_avoided.load(Ordering::Acquire),
        }
    }

    /// Get average latency
    fn get_avg_latency(&self) -> u64 {
        let ops = self.total_ops.load(Ordering::Acquire);
        if ops == 0 {
            return 0;
        }
        self.total_latency.load(Ordering::Acquire) / ops
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for DmaController {
    fn default() -> Self {
        Self::new()
    }
}

/// DMA statistics
#[repr(C)]
pub struct DmaStats {
    pub enabled: bool,
    pub channel_count: u8,
    pub pending_ops: u16,
    pub total_ops: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub avg_latency_ns: u64,
    pub ops_avoided: u64,
    pub bytes_avoided: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_channel() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        
        let id = ctrl.register_channel(0xFE000000, 0).unwrap();
        assert_eq!(ctrl.channel_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn channel_enable() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        ctrl.register_channel(0xFE000000, 0).unwrap();
        
        let channel = ctrl.get_channel(0).unwrap();
        channel.enable();
        channel.start();
        
        assert!(channel.enabled.load(Ordering::Acquire));
        assert!(channel.active.load(Ordering::Acquire));
    }

    #[test]
    fn submit_memcpy() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        ctrl.register_channel(0xFE000000, 0).unwrap();
        
        let channel = ctrl.get_channel(0).unwrap();
        channel.enable();
        channel.start();
        
        let op_id = ctrl.memcpy(0x1000000, 0x2000000, 8192, 1, dma_priority::NORMAL).unwrap();
        assert!(op_id > 0);
    }

    #[test]
    fn small_transfer_avoided() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        ctrl.register_channel(0xFE000000, 0).unwrap();
        
        let channel = ctrl.get_channel(0).unwrap();
        channel.enable();
        channel.start();
        
        // Small transfer should be avoided
        let result = ctrl.memcpy(0x1000000, 0x2000000, 256, 1, dma_priority::NORMAL);
        assert!(result.is_err());
        
        let stats = ctrl.get_stats();
        assert!(stats.ops_avoided > 0);
    }

    #[test]
    fn process_completions() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        ctrl.register_channel(0xFE000000, 0).unwrap();
        
        let channel = ctrl.get_channel(0).unwrap();
        channel.enable();
        channel.start();
        
        // Submit and manually complete
        let op_id = ctrl.memcpy(0x1000000, 0x2000000, 8192, 1, dma_priority::NORMAL).unwrap();
        
        // Simulate completion
        let desc_idx = ctrl.operations[0].desc_idx.load(Ordering::Acquire);
        channel.descriptors[desc_idx as usize].set_status(1);
        
        let completed = ctrl.process_completions();
        assert!(completed > 0);
    }

    #[test]
    fn find_best_channel() {
        let mut ctrl = DmaController::new();
        ctrl.enable(3, 16 * 1024 * 1024);
        ctrl.register_channel(0xFE000000, 0).unwrap();
        ctrl.register_channel(0xFE001000, 0).unwrap();
        
        // Enable both channels
        for i in 0..2 {
            let channel = ctrl.get_channel(i).unwrap();
            channel.enable();
            channel.start();
        }
        
        let best = ctrl.find_best_channel(8192, dma_priority::NORMAL);
        assert!(best.is_some());
    }
}
