//! Advanced I/O - IO Threads, Zero-Copy, io_uring
//!
//! High-performance asynchronous I/O with zero-copy operations.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, AtomicPtr, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// IO Thread Pool Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum IO threads
pub const MAX_IO_THREADS: usize = 16;
/// Maximum pending operations per thread
pub const MAX_PENDING_OPS: usize = 4096;
/// IO operation types
pub mod io_op {
    pub const READ: u8 = 0;
    pub const WRITE: u8 = 1;
    pub const READV: u8 = 2;
    pub const WRITEV: u8 = 3;
    pub const SYNC: u8 = 4;
    pub const DATASYNC: u8 = 5;
    pub const POLL: u8 = 6;
    pub const ACCEPT: u8 = 7;
    pub const CONNECT: u8 = 8;
    pub const SEND: u8 = 9;
    pub const RECV: u8 = 10;
    pub const SENDMSG: u8 = 11;
    pub const RECVMSG: u8 = 12;
    pub const TIMEOUT: u8 = 13;
    pub const CANCEL: u8 = 14;
}

/// IO operation flags
pub mod io_flag {
    pub const NOWAIT: u32 = 1 << 0;
    pub const DSYNC: u32 = 1 << 1;
    pub const RSYNC: u32 = 1 << 2;
    pub const DIRECT: u32 = 1 << 3;
    pub const APPEND: u32 = 1 << 4;
    pub const NONBLOCK: u32 = 1 << 5;
    pub const ZERO_COPY: u32 = 1 << 6;
    pub const FIXED_FILE: u32 = 1 << 7;
    pub const BUFFER_SELECT: u32 = 1 << 8;
}

// ─────────────────────────────────────────────────────────────────────────────
// IO Operation
// ─────────────────────────────────────────────────────────────────────────────

/// IO operation descriptor
pub struct IoOp {
    /// Operation ID
    pub id: AtomicU64,
    /// Operation type
    pub op_type: AtomicU8,
    /// Flags
    pub flags: AtomicU32,
    /// File descriptor / handle
    pub fd: AtomicU32,
    /// Buffer address (guest physical)
    pub buf_addr: AtomicU64,
    /// Buffer length
    pub buf_len: AtomicU64,
    /// Offset
    pub offset: AtomicU64,
    /// Result
    pub result: AtomicI64,
    /// Error code
    pub error: AtomicU32,
    /// Completion callback (would be function pointer)
    pub callback: AtomicU64,
    /// User data
    pub user_data: AtomicU64,
    /// Submitted
    pub submitted: AtomicBool,
    /// Completed
    pub completed: AtomicBool,
    /// Cancelled
    pub cancelled: AtomicBool,
}

impl IoOp {
    pub const fn new() -> Self {
        Self {
            id: AtomicU64::new(0),
            op_type: AtomicU8::new(0),
            flags: AtomicU32::new(0),
            fd: AtomicU32::new(0),
            buf_addr: AtomicU64::new(0),
            buf_len: AtomicU64::new(0),
            offset: AtomicU64::new(0),
            result: AtomicI64::new(0),
            error: AtomicU32::new(0),
            callback: AtomicU64::new(0),
            user_data: AtomicU64::new(0),
            submitted: AtomicBool::new(false),
            completed: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        }
    }

    /// Initialize operation
    pub fn init(&self, id: u64, op_type: u8, fd: u32, buf: u64, len: u64, offset: u64) {
        self.id.store(id, Ordering::Release);
        self.op_type.store(op_type, Ordering::Release);
        self.fd.store(fd, Ordering::Release);
        self.buf_addr.store(buf, Ordering::Release);
        self.buf_len.store(len, Ordering::Release);
        self.offset.store(offset, Ordering::Release);
        self.submitted.store(false, Ordering::Release);
        self.completed.store(false, Ordering::Release);
        self.cancelled.store(false, Ordering::Release);
    }

    /// Mark as submitted
    pub fn submit(&self) {
        self.submitted.store(true, Ordering::Release);
    }

    /// Complete with result
    pub fn complete(&self, result: i64, error: u32) {
        self.result.store(result, Ordering::Release);
        self.error.store(error, Ordering::Release);
        self.completed.store(true, Ordering::Release);
    }

    /// Cancel operation
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// Atomic signed 64-bit (workaround for no AtomicI64 in core)
pub struct AtomicI64 {
    inner: AtomicU64,
}

impl AtomicI64 {
    pub const fn new(v: i64) -> Self {
        Self { inner: AtomicU64::new(v as u64) }
    }
    pub fn load(&self, order: Ordering) -> i64 {
        self.inner.load(order) as i64
    }
    pub fn store(&self, v: i64, order: Ordering) {
        self.inner.store(v as u64, order);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IO Thread
// ─────────────────────────────────────────────────────────────────────────────

/// IO thread state
pub struct IoThread {
    /// Thread ID
    pub thread_id: AtomicU32,
    /// Pending operations
    pub pending_ops: [IoOp; MAX_PENDING_OPS],
    /// Pending count
    pub pending_count: AtomicU32,
    /// Completed operations (ring buffer indices)
    pub completed_head: AtomicU32,
    pub completed_tail: AtomicU32,
    /// Thread state
    pub state: AtomicU8,
    /// CPU affinity
    pub cpu_affinity: AtomicU64,
    /// Operations processed
    pub ops_processed: AtomicU64,
    /// Bytes read
    pub bytes_read: AtomicU64,
    /// Bytes written
    pub bytes_written: AtomicU64,
    /// Errors
    pub errors: AtomicU64,
    /// Wake pending
    pub wake_pending: AtomicBool,
}

impl IoThread {
    pub const fn new() -> Self {
        Self {
            thread_id: AtomicU32::new(0),
            pending_ops: [const { IoOp::new() }; MAX_PENDING_OPS],
            pending_count: AtomicU32::new(0),
            completed_head: AtomicU32::new(0),
            completed_tail: AtomicU32::new(0),
            state: AtomicU8::new(0),
            cpu_affinity: AtomicU64::new(0),
            ops_processed: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            wake_pending: AtomicBool::new(false),
        }
    }

    /// Initialize thread
    pub fn init(&self, thread_id: u32, cpu_affinity: u64) {
        self.thread_id.store(thread_id, Ordering::Release);
        self.cpu_affinity.store(cpu_affinity, Ordering::Release);
        self.state.store(1, Ordering::Release); // Running
    }

    /// Submit operation
    pub fn submit_op(&self, op: &IoOp) -> Result<u32, HvError> {
        let count = self.pending_count.load(Ordering::Acquire);
        if count as usize >= MAX_PENDING_OPS {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count as usize;
        let pending = &self.pending_ops[idx];
        
        pending.id.store(op.id.load(Ordering::Acquire), Ordering::Release);
        pending.op_type.store(op.op_type.load(Ordering::Acquire), Ordering::Release);
        pending.fd.store(op.fd.load(Ordering::Acquire), Ordering::Release);
        pending.buf_addr.store(op.buf_addr.load(Ordering::Acquire), Ordering::Release);
        pending.buf_len.store(op.buf_len.load(Ordering::Acquire), Ordering::Release);
        pending.offset.store(op.offset.load(Ordering::Acquire), Ordering::Release);
        pending.flags.store(op.flags.load(Ordering::Acquire), Ordering::Release);
        pending.submitted.store(true, Ordering::Release);
        pending.completed.store(false, Ordering::Release);
        
        self.pending_count.fetch_add(1, Ordering::Release);
        self.wake_pending.store(true, Ordering::Release);
        
        Ok(idx as u32)
    }

    /// Process pending operations
    pub fn process(&self) -> u32 {
        let mut processed = 0u32;
        let count = self.pending_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            let op = &self.pending_ops[i];
            if !op.submitted.load(Ordering::Acquire) || 
               op.completed.load(Ordering::Acquire) ||
               op.cancelled.load(Ordering::Acquire) {
                continue;
            }
            
            // Execute operation
            let result = self.execute_op(op);
            op.complete(result.0, result.1);
            
            processed += 1;
            self.ops_processed.fetch_add(1, Ordering::Release);
            
            if result.0 > 0 {
                match op.op_type.load(Ordering::Acquire) {
                    io_op::READ | io_op::READV | io_op::RECV => {
                        self.bytes_read.fetch_add(result.0 as u64, Ordering::Release);
                    }
                    io_op::WRITE | io_op::WRITEV | io_op::SEND => {
                        self.bytes_written.fetch_add(result.0 as u64, Ordering::Release);
                    }
                    _ => {}
                }
            }
            
            if result.1 != 0 {
                self.errors.fetch_add(1, Ordering::Release);
            }
        }
        
        // Clear processed
        self.pending_count.store(0, Ordering::Release);
        
        processed
    }

    /// Execute single operation
    fn execute_op(&self, op: &IoOp) -> (i64, u32) {
        // Would perform actual I/O
        let _ = op;
        (0, 0)
    }

    /// Get statistics
    pub fn get_stats(&self) -> IoThreadStats {
        IoThreadStats {
            thread_id: self.thread_id.load(Ordering::Acquire),
            ops_processed: self.ops_processed.load(Ordering::Acquire),
            bytes_read: self.bytes_read.load(Ordering::Acquire),
            bytes_written: self.bytes_written.load(Ordering::Acquire),
            errors: self.errors.load(Ordering::Acquire),
            pending_count: self.pending_count.load(Ordering::Acquire),
        }
    }
}

impl Default for IoThread {
    fn default() -> Self {
        Self::new()
    }
}

/// IO thread statistics
#[repr(C)]
pub struct IoThreadStats {
    pub thread_id: u32,
    pub ops_processed: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub pending_count: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// IO Thread Pool
// ─────────────────────────────────────────────────────────────────────────────

/// IO thread pool controller
pub struct IoThreadPool {
    /// IO threads
    pub threads: [IoThread; MAX_IO_THREADS],
    /// Thread count
    pub thread_count: AtomicU8,
    /// Next thread for submission (round-robin)
    pub next_thread: AtomicU8,
    /// Pool enabled
    pub enabled: AtomicBool,
    /// Zero-copy enabled
    pub zero_copy: AtomicBool,
    /// Batch size
    pub batch_size: AtomicU32,
    /// Total operations
    pub total_ops: AtomicU64,
    /// Total bytes
    pub total_bytes: AtomicU64,
}

impl IoThreadPool {
    pub const fn new() -> Self {
        Self {
            threads: [const { IoThread::new() }; MAX_IO_THREADS],
            thread_count: AtomicU8::new(0),
            next_thread: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            zero_copy: AtomicBool::new(true),
            batch_size: AtomicU32::new(64),
            total_ops: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
        }
    }

    /// Initialize pool
    pub fn init(&mut self, thread_count: u8) -> Result<(), HvError> {
        if thread_count as usize > MAX_IO_THREADS {
            return Err(HvError::LogicalFault);
        }
        
        for i in 0..thread_count as usize {
            let affinity = 1u64 << (i % 8); // Spread across CPUs
            self.threads[i].init(i as u32, affinity);
        }
        
        self.thread_count.store(thread_count, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        
        Ok(())
    }

    /// Submit operation
    pub fn submit(&self, op: &IoOp) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        // Round-robin thread selection
        let thread_idx = self.next_thread.fetch_add(1, Ordering::Release) % 
                         self.thread_count.load(Ordering::Acquire);
        
        let thread = &self.threads[thread_idx as usize];
        let result = thread.submit_op(op)?;
        
        self.total_ops.fetch_add(1, Ordering::Release);
        
        Ok(result)
    }

    /// Submit batch
    pub fn submit_batch(&self, ops: &[IoOp]) -> u32 {
        let mut submitted = 0u32;
        for op in ops {
            if self.submit(op).is_ok() {
                submitted += 1;
            }
        }
        submitted
    }

    /// Process all threads
    pub fn process_all(&self) -> u32 {
        let mut total = 0u32;
        let count = self.thread_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            total += self.threads[i].process();
        }
        
        total
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> IoPoolStats {
        let mut thread_stats = [IoThreadStats::default(); MAX_IO_THREADS];
        
        for i in 0..self.thread_count.load(Ordering::Acquire) as usize {
            thread_stats[i] = self.threads[i].get_stats();
        }
        
        IoPoolStats {
            thread_count: self.thread_count.load(Ordering::Acquire),
            total_ops: self.total_ops.load(Ordering::Acquire),
            total_bytes: self.total_bytes.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
            threads: thread_stats,
        }
    }
}

impl Default for IoThreadPool {
    fn default() -> Self {
        Self::new()
    }
}

/// IO pool statistics
#[repr(C)]
pub struct IoPoolStats {
    pub thread_count: u8,
    pub total_ops: u64,
    pub total_bytes: u64,
    pub enabled: bool,
    pub threads: [IoThreadStats; MAX_IO_THREADS],
}

// ─────────────────────────────────────────────────────────────────────────────
// Zero-Copy Buffer Pool
// ─────────────────────────────────────────────────────────────────────────────

/// Zero-copy buffer
pub struct ZeroCopyBuffer {
    /// Physical address
    pub phys_addr: AtomicU64,
    /// Size
    pub size: AtomicU32,
    /// In use
    pub in_use: AtomicBool,
    /// Pinned (non-swappable)
    pub pinned: AtomicBool,
    /// DMA mapped
    pub dma_mapped: AtomicBool,
}

impl ZeroCopyBuffer {
    pub const fn new() -> Self {
        Self {
            phys_addr: AtomicU64::new(0),
            size: AtomicU32::new(0),
            in_use: AtomicBool::new(false),
            pinned: AtomicBool::new(false),
            dma_mapped: AtomicBool::new(false),
        }
    }
}

/// Maximum zero-copy buffers
pub const MAX_ZERO_COPY_BUFFERS: usize = 1024;

/// Zero-copy buffer pool
pub struct ZeroCopyPool {
    /// Buffers
    pub buffers: [ZeroCopyBuffer; MAX_ZERO_COPY_BUFFERS],
    /// Buffer count
    pub buffer_count: AtomicU32,
    /// Free count
    pub free_count: AtomicU32,
    /// Total size
    pub total_size: AtomicU64,
    /// Buffer size (default)
    pub buffer_size: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
}

impl ZeroCopyPool {
    pub const fn new() -> Self {
        Self {
            buffers: [const { ZeroCopyBuffer::new() }; MAX_ZERO_COPY_BUFFERS],
            buffer_count: AtomicU32::new(0),
            free_count: AtomicU32::new(0),
            total_size: AtomicU64::new(0),
            buffer_size: AtomicU32::new(4096),
            enabled: AtomicBool::new(false),
        }
    }

    /// Initialize pool
    pub fn init(&mut self, count: u32, size: u32) -> Result<(), HvError> {
        if count as usize > MAX_ZERO_COPY_BUFFERS {
            return Err(HvError::LogicalFault);
        }
        
        for i in 0..count as usize {
            let buf = &self.buffers[i];
            buf.phys_addr.store((i as u64) * size as u64, Ordering::Release);
            buf.size.store(size, Ordering::Release);
            buf.in_use.store(false, Ordering::Release);
        }
        
        self.buffer_count.store(count, Ordering::Release);
        self.free_count.store(count, Ordering::Release);
        self.buffer_size.store(size, Ordering::Release);
        self.total_size.store(count as u64 * size as u64, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        
        Ok(())
    }

    /// Allocate buffer
    pub fn alloc(&self) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        for i in 0..self.buffer_count.load(Ordering::Acquire) as usize {
            let buf = &self.buffers[i];
            if !buf.in_use.load(Ordering::Acquire) {
                buf.in_use.store(true, Ordering::Release);
                self.free_count.fetch_sub(1, Ordering::Release);
                return Ok(i as u32);
            }
        }
        
        Err(HvError::LogicalFault)
    }

    /// Free buffer
    pub fn free(&self, index: u32) -> Result<(), HvError> {
        if index as usize >= MAX_ZERO_COPY_BUFFERS {
            return Err(HvError::LogicalFault);
        }
        
        let buf = &self.buffers[index as usize];
        if !buf.in_use.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        buf.in_use.store(false, Ordering::Release);
        self.free_count.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Pin buffer (prevent swap)
    pub fn pin(&self, index: u32) -> Result<(), HvError> {
        if index as usize >= MAX_ZERO_COPY_BUFFERS {
            return Err(HvError::LogicalFault);
        }
        
        let buf = &self.buffers[index as usize];
        buf.pinned.store(true, Ordering::Release);
        Ok(())
    }

    /// Unpin buffer
    pub fn unpin(&self, index: u32) -> Result<(), HvError> {
        if index as usize >= MAX_ZERO_COPY_BUFFERS {
            return Err(HvError::LogicalFault);
        }
        
        let buf = &self.buffers[index as usize];
        buf.pinned.store(false, Ordering::Release);
        Ok(())
    }

    /// Get buffer physical address
    pub fn get_phys_addr(&self, index: u32) -> Result<u64, HvError> {
        if index as usize >= MAX_ZERO_COPY_BUFFERS {
            return Err(HvError::LogicalFault);
        }
        
        Ok(self.buffers[index as usize].phys_addr.load(Ordering::Acquire))
    }
}

impl Default for ZeroCopyPool {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// io_uring Emulation
// ─────────────────────────────────────────────────────────────────────────────

/// io_uring SQE (submission queue entry)
#[repr(C)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off_or_addr2: u64,
    pub addr: u64,
    pub len: u32,
    pub opcode_flags: u32,
    pub user_data: u64,
    pub buf_group: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub pad: [u64; 2],
}

/// io_uring CQE (completion queue entry)
#[repr(C)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

/// io_uring ring size
pub const IO_URING_RING_SIZE: usize = 4096;

/// io_uring controller
pub struct IoUring {
    /// Submission queue
    pub sq: [IoUringSqe; IO_URING_RING_SIZE],
    /// Completion queue
    pub cq: [IoUringCqe; IO_URING_RING_SIZE],
    /// SQ head
    pub sq_head: AtomicU32,
    /// SQ tail
    pub sq_tail: AtomicU32,
    /// CQ head
    pub cq_head: AtomicU32,
    /// CQ tail
    pub cq_tail: AtomicU32,
    /// Ring mask
    pub ring_mask: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Features
    pub features: AtomicU32,
    /// Operations submitted
    pub submitted: AtomicU64,
    /// Operations completed
    pub completed: AtomicU64,
}

impl IoUring {
    pub const fn new() -> Self {
        Self {
            sq: [IoUringSqe { 
                opcode: 0, flags: 0, ioprio: 0, fd: 0, 
                off_or_addr2: 0, addr: 0, len: 0, opcode_flags: 0,
                user_data: 0, buf_group: 0, personality: 0, splice_fd_in: 0,
                pad: [0; 2]
            }; IO_URING_RING_SIZE],
            cq: [IoUringCqe { user_data: 0, res: 0, flags: 0 }; IO_URING_RING_SIZE],
            sq_head: AtomicU32::new(0),
            sq_tail: AtomicU32::new(0),
            cq_head: AtomicU32::new(0),
            cq_tail: AtomicU32::new(0),
            ring_mask: AtomicU32::new(IO_URING_RING_SIZE as u32 - 1),
            enabled: AtomicBool::new(false),
            features: AtomicU32::new(0),
            submitted: AtomicU64::new(0),
            completed: AtomicU64::new(0),
        }
    }

    /// Enable io_uring
    pub fn enable(&mut self, features: u32) {
        self.features.store(features, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Submit SQE
    pub fn submit_sqe(&self, sqe: &IoUringSqe) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let tail = self.sq_tail.load(Ordering::Acquire);
        let mask = self.ring_mask.load(Ordering::Acquire);
        let idx = tail & mask;
        
        self.sq[idx as usize] = *sqe;
        self.sq_tail.store(tail + 1, Ordering::Release);
        self.submitted.fetch_add(1, Ordering::Release);
        
        Ok(idx)
    }

    /// Process submission queue
    pub fn process_sq(&mut self) -> u32 {
        let mut processed = 0u32;
        let head = self.sq_head.load(Ordering::Acquire);
        let tail = self.sq_tail.load(Ordering::Acquire);
        let mask = self.ring_mask.load(Ordering::Acquire);
        
        while head != tail {
            let idx = head & mask;
            let sqe = &self.sq[idx as usize];
            
            // Execute operation
            let result = self.execute_sqe(sqe);
            
            // Post CQE
            self.post_cqe(sqe.user_data, result, 0);
            
            self.sq_head.store(head + processed + 1, Ordering::Release);
            processed += 1;
        }
        
        processed
    }

    /// Execute SQE
    fn execute_sqe(&self, sqe: &IoUringSqe) -> i32 {
        // Would perform actual I/O
        let _ = sqe;
        0
    }

    /// Post CQE
    pub fn post_cqe(&self, user_data: u64, res: i32, flags: u32) {
        let tail = self.cq_tail.load(Ordering::Acquire);
        let mask = self.ring_mask.load(Ordering::Acquire);
        let idx = tail & mask;
        
        self.cq[idx as usize].user_data = user_data;
        self.cq[idx as usize].res = res;
        self.cq[idx as usize].flags = flags;
        
        self.cq_tail.store(tail + 1, Ordering::Release);
        self.completed.fetch_add(1, Ordering::Release);
    }

    /// Peek CQE
    pub fn peek_cqe(&self) -> Option<&IoUringCqe> {
        let head = self.cq_head.load(Ordering::Acquire);
        let tail = self.cq_tail.load(Ordering::Acquire);
        
        if head != tail {
            let mask = self.ring_mask.load(Ordering::Acquire);
            Some(&self.cq[(head & mask) as usize])
        } else {
            None
        }
    }

    /// Advance CQ head
    pub fn advance_cq(&self, count: u32) {
        self.cq_head.fetch_add(count, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> IoUringStats {
        IoUringStats {
            submitted: self.submitted.load(Ordering::Acquire),
            completed: self.completed.load(Ordering::Acquire),
            sq_pending: self.sq_tail.load(Ordering::Acquire) - self.sq_head.load(Ordering::Acquire),
            cq_pending: self.cq_tail.load(Ordering::Acquire) - self.cq_head.load(Ordering::Acquire),
        }
    }
}

impl Default for IoUring {
    fn default() -> Self {
        Self::new()
    }
}

/// io_uring statistics
#[repr(C)]
pub struct IoUringStats {
    pub submitted: u64,
    pub completed: u64,
    pub sq_pending: u32,
    pub cq_pending: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_pool_init() {
        let mut pool = IoThreadPool::new();
        pool.init(4).unwrap();
        
        assert_eq!(pool.thread_count.load(Ordering::Acquire), 4);
    }

    #[test]
    fn io_submit() {
        let mut pool = IoThreadPool::new();
        pool.init(4).unwrap();
        
        let op = IoOp::new();
        op.init(1, io_op::READ, 0, 0x1000, 4096, 0);
        
        let idx = pool.submit(&op).unwrap();
        assert!(idx < MAX_PENDING_OPS as u32);
    }

    #[test]
    fn zero_copy_pool() {
        let mut pool = ZeroCopyPool::new();
        pool.init(64, 4096).unwrap();
        
        let idx = pool.alloc().unwrap();
        assert!(pool.buffers[idx as usize].in_use.load(Ordering::Acquire));
        
        pool.free(idx).unwrap();
        assert!(!pool.buffers[idx as usize].in_use.load(Ordering::Acquire));
    }

    #[test]
    fn io_uring_submit() {
        let mut ring = IoUring::new();
        ring.enable(0);
        
        let sqe = IoUringSqe { 
            opcode: io_op::READ, flags: 0, ioprio: 0, fd: 0,
            off_or_addr2: 0, addr: 0x1000, len: 4096, opcode_flags: 0,
            user_data: 123, buf_group: 0, personality: 0, splice_fd_in: 0,
            pad: [0; 2]
        };
        
        ring.submit_sqe(&sqe).unwrap();
        assert_eq!(ring.submitted.load(Ordering::Acquire), 1);
    }
}
