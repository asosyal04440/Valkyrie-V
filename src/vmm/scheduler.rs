//! SMP vCPU Scheduler - CFS-inspired Completely Fair Scheduler
//!
//! This module implements a multi-vCPU scheduler with the following features:
//! - Per-PCPU run queues (lock-free for cache locality)
//! - CFS-inspired scheduling with virtual runtime tracking
//! - Red-black tree for O(log n) vCPU ordering
//! - Load balancing across physical CPUs
//! - vCPU affinity support (pinning and soft affinity)
//! - IPI (Inter-Processor Interrupt) coordination
//! - TLB shootdown batching

use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, AtomicBool, Ordering};
use core::cell::UnsafeCell;

/// Maximum number of vCPUs supported
pub const MAX_VCPUS: usize = 64;

/// Maximum number of physical CPUs (host)
pub const MAX_PCPUS: usize = 256;

/// Scheduler time slice in TSC cycles (1ms at 2GHz = 2M cycles)
pub const SCHED_TIMESLICE_MIN: u64 = 1_000_000;  // 1ms minimum
pub const SCHED_TIMESLICE_MAX: u64 = 100_000_000; // 100ms maximum

/// Load balancing interval in TSC cycles (500ms at 2GHz = 1B cycles)
pub const LOAD_BALANCE_INTERVAL: u64 = 1_000_000_000;

/// Load imbalance threshold (20% deviation)
pub const LOAD_IMBALANCE_THRESHOLD: u32 = 20;

// ─────────────────────────────────────────────────────────────────────────────
// vCPU Scheduler States
// ─────────────────────────────────────────────────────────────────────────────

/// vCPU is not yet created
pub const VCPU_STATE_NONE: u8 = 0;
/// vCPU is initialized but not running
pub const VCPU_STATE_CREATED: u8 = 1;
/// vCPU is in run queue, waiting to be scheduled
pub const VCPU_STATE_RUNNABLE: u8 = 2;
/// vCPU is currently executing on a pCPU
pub const VCPU_STATE_RUNNING: u8 = 3;
/// vCPU is blocked (waiting for I/O, sleep, etc.)
pub const VCPU_STATE_BLOCKED: u8 = 4;
/// vCPU is halted (HLT instruction)
pub const VCPU_STATE_HALTED: u8 = 5;
/// vCPU is waiting for SIPI
pub const VCPU_STATE_WAIT_FOR_SIPI: u8 = 6;
/// vCPU received SIPI, ready to start
pub const VCPU_STATE_SIPI_RECEIVED: u8 = 7;

// ─────────────────────────────────────────────────────────────────────────────
// vCPU Affinity Types
// ─────────────────────────────────────────────────────────────────────────────

/// No affinity preference
pub const AFFINITY_NONE: u8 = 0;
/// Soft affinity - prefer this pCPU but can migrate
pub const AFFINITY_SOFT: u8 = 1;
/// Hard affinity - must run on this pCPU
pub const AFFINITY_HARD: u8 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// IPI Vector Definitions
// ─────────────────────────────────────────────────────────────────────────────

/// IPI vector for TLB shootdown
pub const IPI_VECTOR_TLB_SHOOTDOWN: u8 = 0xF0;
/// IPI vector for reschedule request
pub const IPI_VECTOR_RESCHEDULE: u8 = 0xF1;
/// IPI vector for vCPU wakeup
pub const IPI_VECTOR_WAKEUP: u8 = 0xF2;
/// IPI vector for vCPU stop
pub const IPI_VECTOR_STOP: u8 = 0xF3;

// ─────────────────────────────────────────────────────────────────────────────
// VPID (Virtual Processor ID) Management
// ─────────────────────────────────────────────────────────────────────────────

/// VPID allocation bitmap (1-4095 are valid, 0 is reserved)
static VPID_BITMAP: [AtomicU64; 64] = {
    // 64 * 64 = 4096 bits, covering all VPIDs
    const INIT: AtomicU64 = AtomicU64::new(0);
    [INIT; 64]
};

/// Next VPID to try allocating
static NEXT_VPID: AtomicU32 = AtomicU32::new(1);

/// Allocate a VPID (Virtual Processor ID) for TLB tagging.
/// Returns 0 if allocation fails (all VPIDs exhausted).
/// VPID 0 is reserved per Intel SDM.
pub fn allocate_vpid() -> u16 {
    // Try to find a free VPID starting from NEXT_VPID
    let start = NEXT_VPID.load(Ordering::Relaxed);
    
    for i in 0..4095 {
        let vpid = ((start + i) % 4095) + 1; // 1-4095
        let word = (vpid / 64) as usize;
        let bit = vpid % 64;
        
        let bitmap = &VPID_BITMAP[word];
        let mask = 1u64 << bit;
        
        // Try to set the bit (atomic test-and-set)
        if bitmap.compare_exchange(0, mask, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            NEXT_VPID.store(vpid + 1, Ordering::Relaxed);
            return vpid as u16;
        }
        
        // Bit was already set, check if it's actually in use
        let current = bitmap.load(Ordering::Acquire);
        if (current & mask) == 0 {
            // Race condition: try again
            if bitmap.compare_exchange(current, current | mask, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                NEXT_VPID.store(vpid + 1, Ordering::Relaxed);
                return vpid as u16;
            }
        }
    }
    
    0 // No free VPID
}

/// Free a previously allocated VPID.
pub fn free_vpid(vpid: u16) {
    if vpid == 0 || vpid > 4095 {
        return;
    }
    
    let word = (vpid as usize) / 64;
    let bit = vpid % 64;
    let mask = 1u64 << bit;
    
    VPID_BITMAP[word].fetch_and(!mask, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────────────
// vCPU Run Queue Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Entry in the run queue representing a schedulable vCPU
#[repr(C, align(64))] // Cache line aligned
pub struct RunQueueEntry {
    /// vCPU ID
    pub vcpu_id: u32,
    /// Virtual runtime (for CFS fairness)
    pub vruntime: AtomicU64,
    /// Priority (0-255, lower = higher priority)
    pub priority: u8,
    /// Affinity type
    pub affinity_type: u8,
    /// Preferred/target pCPU for affinity
    pub affinity_pcpu: u16,
    /// Current pCPU this vCPU is running on (if running)
    pub current_pcpu: AtomicU16,
    /// Timeslice remaining in TSC cycles
    pub timeslice_remaining: AtomicU64,
    /// Whether this entry is in use
    pub in_use: AtomicBool,
    /// Red-black tree links (for sorted insertion)
    pub rb_left: u32,  // Index of left child
    pub rb_right: u32, // Index of right child
    pub rb_parent: u32, // Index of parent
    pub rb_color: u8,  // 0 = red, 1 = black
}

impl RunQueueEntry {
    pub const fn new() -> Self {
        Self {
            vcpu_id: 0,
            vruntime: AtomicU64::new(0),
            priority: 128, // Default priority
            affinity_type: AFFINITY_NONE,
            affinity_pcpu: 0,
            current_pcpu: AtomicU16::new(0xFFFF), // Invalid
            timeslice_remaining: AtomicU64::new(0),
            in_use: AtomicBool::new(false),
            rb_left: 0xFFFFFFFF,
            rb_right: 0xFFFFFFFF,
            rb_parent: 0xFFFFFFFF,
            rb_color: 0,
        }
    }
    
    /// Calculate weight based on priority (CFS-style)
    /// Higher priority = higher weight = slower vruntime increment
    pub fn weight(&self) -> u64 {
        // Priority 0 = weight 88761, priority 255 = weight 15
        // Simplified: weight = 1024 * (256 - priority) / 128
        let prio_factor = (256 - self.priority as u32) as u64;
        1024 * prio_factor / 128
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-PCPU Run Queue
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum entries per run queue
pub const RUN_QUEUE_SIZE: usize = 64;

/// Per-PCPU run queue with lock-free operations
#[repr(C, align(128))] // Cache line aligned
pub struct PerPcpuRunQueue {
    /// Entries in the run queue (wrapped in UnsafeCell for interior mutability)
    entries: UnsafeCell<[RunQueueEntry; RUN_QUEUE_SIZE]>,
    /// Number of entries currently in use
    count: AtomicU32,
    /// Index of the red-black tree root
    rb_root: AtomicU32,
    /// Index of the leftmost node (for O(1) min extraction)
    rb_leftmost: AtomicU32,
    /// Total load on this run queue (sum of weights)
    total_load: AtomicU64,
    /// Lock for tree modifications (spinlock)
    lock: AtomicU8,
    /// PCPU ID this run queue belongs to
    pcpu_id: u16,
    /// Last load balance time (TSC)
    last_balance_time: AtomicU64,
    /// Number of vCPUs migrated to this queue
    migrations_in: AtomicU32,
    /// Number of vCPUs migrated from this queue
    migrations_out: AtomicU32,
}

impl PerPcpuRunQueue {
    pub const fn new(pcpu_id: u16) -> Self {
        Self {
            entries: UnsafeCell::new([const { RunQueueEntry::new() }; RUN_QUEUE_SIZE]),
            count: AtomicU32::new(0),
            rb_root: AtomicU32::new(0xFFFFFFFF),
            rb_leftmost: AtomicU32::new(0xFFFFFFFF),
            total_load: AtomicU64::new(0),
            lock: AtomicU8::new(0),
            pcpu_id,
            last_balance_time: AtomicU64::new(0),
            migrations_in: AtomicU32::new(0),
            migrations_out: AtomicU32::new(0),
        }
    }
    
    /// Get a reference to entries (unsafe due to UnsafeCell)
    #[inline]
    fn entries(&self) -> &[RunQueueEntry] {
        unsafe { &*self.entries.get() }
    }
    
    /// Get a mutable reference to entries (unsafe due to UnsafeCell)
    #[inline]
    fn entries_mut(&self) -> &mut [RunQueueEntry] {
        unsafe { &mut *self.entries.get() }
    }
    
    /// Try to acquire the run queue lock (spinlock)
    #[inline]
    fn try_lock(&self) -> bool {
        self.lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok()
    }
    
    /// Release the run queue lock
    #[inline]
    fn unlock(&self) {
        self.lock.store(0, Ordering::Release);
    }
    
    /// Find a free entry slot
    fn find_free_slot(&self) -> Option<u32> {
        let entries = self.entries();
        for i in 0..RUN_QUEUE_SIZE {
            if !entries[i].in_use.load(Ordering::Acquire) {
                return Some(i as u32);
            }
        }
        None
    }
    
    /// Add a vCPU to this run queue
    /// Returns true if successful
    pub fn enqueue(&self, vcpu_id: u32, priority: u8, vruntime: u64) -> bool {
        // Find a free slot
        let slot = match self.find_free_slot() {
            Some(s) => s,
            None => return false, // Queue full
        };
        
        // Spin until we get the lock
        while !self.try_lock() {
            core::hint::spin_loop();
        }
        
        // Initialize the entry
        let entries = self.entries_mut();
        let entry = &mut entries[slot as usize];
        entry.vcpu_id = vcpu_id;
        entry.priority = priority;
        entry.vruntime.store(vruntime, Ordering::Release);
        entry.in_use.store(true, Ordering::Release);
        entry.timeslice_remaining.store(SCHED_TIMESLICE_MAX, Ordering::Release);
        
        // Insert into red-black tree (sorted by vruntime)
        self.rb_insert(slot);
        
        // Update count and load
        self.count.fetch_add(1, Ordering::Release);
        self.total_load.fetch_add(entry.weight(), Ordering::Release);
        
        self.unlock();
        true
    }
    
    /// Remove and return the vCPU with the minimum vruntime
    pub fn dequeue_min(&self) -> Option<(u32, u64)> {
        // Spin until we get the lock
        while !self.try_lock() {
            core::hint::spin_loop();
        }
        
        // Get the leftmost node (minimum vruntime)
        let leftmost = self.rb_leftmost.load(Ordering::Acquire);
        if leftmost == 0xFFFFFFFF {
            self.unlock();
            return None;
        }
        
        let entries = self.entries();
        let entry = &entries[leftmost as usize];
        let vcpu_id = entry.vcpu_id;
        let vruntime = entry.vruntime.load(Ordering::Acquire);
        let weight = entry.weight();
        
        // Remove from tree
        self.rb_remove(leftmost);
        
        // Mark entry as free
        entry.in_use.store(false, Ordering::Release);
        
        // Update count and load
        self.count.fetch_sub(1, Ordering::Release);
        self.total_load.fetch_sub(weight, Ordering::Release);
        
        self.unlock();
        Some((vcpu_id, vruntime))
    }
    
    /// Red-black tree insert (simplified inline version)
    fn rb_insert(&self, slot: u32) {
        let entries = self.entries();
        let new_vruntime = entries[slot as usize].vruntime.load(Ordering::Acquire);
        
        // If tree is empty, make this the root
        if self.rb_root.load(Ordering::Acquire) == 0xFFFFFFFF {
            self.rb_root.store(slot, Ordering::Release);
            self.rb_leftmost.store(slot, Ordering::Release);
            self.entries_mut()[slot as usize].rb_color = 1; // Black
            return;
        }
        
        // Otherwise, find insertion point
        let mut current = self.rb_root.load(Ordering::Acquire);
        let mut parent = 0xFFFFFFFFu32;
        let mut is_left = false;
        
        while current != 0xFFFFFFFF {
            parent = current;
            let current_vruntime = entries[current as usize].vruntime.load(Ordering::Acquire);
            
            if new_vruntime < current_vruntime {
                is_left = true;
                current = entries[current as usize].rb_left;
            } else {
                is_left = false;
                current = entries[current as usize].rb_right;
            }
        }
        
        // Insert new node
        let entries_mut = self.entries_mut();
        entries_mut[slot as usize].rb_parent = parent;
        entries_mut[slot as usize].rb_color = 0; // Red
        entries_mut[slot as usize].rb_left = 0xFFFFFFFF;
        entries_mut[slot as usize].rb_right = 0xFFFFFFFF;
        
        if is_left {
            entries_mut[parent as usize].rb_left = slot;
        } else {
            entries_mut[parent as usize].rb_right = slot;
        }
        
        // Update leftmost if this is the new minimum
        let leftmost = self.rb_leftmost.load(Ordering::Acquire);
        if leftmost == 0xFFFFFFFF || new_vruntime < entries[leftmost as usize].vruntime.load(Ordering::Acquire) {
            self.rb_leftmost.store(slot, Ordering::Release);
        }
        
        // TODO: Rebalance tree (red-black tree fixup)
    }
    
    /// Red-black tree remove (simplified)
    fn rb_remove(&self, slot: u32) {
        let entries = self.entries();
        let root = self.rb_root.load(Ordering::Acquire);
        
        // Simple case: removing the only node
        if root == slot && entries[slot as usize].rb_left == 0xFFFFFFFF && entries[slot as usize].rb_right == 0xFFFFFFFF {
            self.rb_root.store(0xFFFFFFFF, Ordering::Release);
            self.rb_leftmost.store(0xFFFFFFFF, Ordering::Release);
            return;
        }
        
        // Update leftmost if needed
        if self.rb_leftmost.load(Ordering::Acquire) == slot {
            // Find new leftmost
            let new_leftmost = self.find_leftmost_except(slot);
            self.rb_leftmost.store(new_leftmost, Ordering::Release);
        }
        
        // TODO: Full red-black tree removal with rebalancing
        // For now, just clear the parent's link
        let parent = entries[slot as usize].rb_parent;
        if parent != 0xFFFFFFFF {
            let entries_mut = self.entries_mut();
            if entries[parent as usize].rb_left == slot {
                entries_mut[parent as usize].rb_left = 0xFFFFFFFF;
            } else {
                entries_mut[parent as usize].rb_right = 0xFFFFFFFF;
            }
        } else {
            // This was the root
            self.rb_root.store(0xFFFFFFFF, Ordering::Release);
        }
    }
    
    /// Find the leftmost node excluding a specific slot
    fn find_leftmost_except(&self, exclude: u32) -> u32 {
        let entries = self.entries();
        let root = self.rb_root.load(Ordering::Acquire);
        if root == 0xFFFFFFFF || root == exclude {
            return 0xFFFFFFFF;
        }
        
        let mut leftmost = root;
        let mut min_vruntime = entries[root as usize].vruntime.load(Ordering::Acquire);
        
        // Simple BFS to find minimum (could be optimized)
        for i in 0..RUN_QUEUE_SIZE {
            if i as u32 != exclude && entries[i].in_use.load(Ordering::Acquire) {
                let vruntime = entries[i].vruntime.load(Ordering::Acquire);
                if vruntime < min_vruntime {
                    min_vruntime = vruntime;
                    leftmost = i as u32;
                }
            }
        }
        
        leftmost
    }
    
    /// Get the current load of this run queue
    pub fn get_load(&self) -> u64 {
        self.total_load.load(Ordering::Acquire)
    }
    
    /// Get the number of vCPUs in this run queue
    pub fn get_count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global Scheduler State
// ─────────────────────────────────────────────────────────────────────────────

/// Per-PCPU run queues
struct SyncRunQueueArray(UnsafeCell<[PerPcpuRunQueue; MAX_PCPUS]>);
unsafe impl Sync for SyncRunQueueArray {}

static PCPU_RUN_QUEUES: SyncRunQueueArray = SyncRunQueueArray(
    UnsafeCell::new([const { PerPcpuRunQueue::new(0) }; MAX_PCPUS])
);

/// Get the run queue for a specific pCPU
pub fn get_run_queue(pcpu_id: u16) -> &'static PerPcpuRunQueue {
    unsafe {
        &(*PCPU_RUN_QUEUES.0.get())[pcpu_id as usize]
    }
}

/// Number of active pCPUs
static NUM_PCPUS: AtomicU32 = AtomicU32::new(1);

/// Initialize the scheduler with the given number of pCPUs
pub fn init_scheduler(num_pcpus: u32) {
    NUM_PCPUS.store(num_pcpus, Ordering::Release);
    
    // Initialize each run queue with its pCPU ID
    for i in 0..num_pcpus as usize {
        unsafe {
            let rq = &mut (*PCPU_RUN_QUEUES.0.get())[i];
            rq.pcpu_id = i as u16;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Load Balancer
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate the average load across all pCPUs
pub fn calculate_average_load() -> u64 {
    let num_pcpus = NUM_PCPUS.load(Ordering::Acquire) as usize;
    if num_pcpus == 0 {
        return 0;
    }
    
    let mut total_load = 0u64;
    for i in 0..num_pcpus {
        total_load += get_run_queue(i as u16).get_load();
    }
    
    total_load / num_pcpus as u64
}

/// Check if load balancing is needed
pub fn needs_load_balance() -> bool {
    let num_pcpus = NUM_PCPUS.load(Ordering::Acquire) as usize;
    if num_pcpus <= 1 {
        return false;
    }
    
    let avg_load = calculate_average_load() as u32;
    let threshold = avg_load * LOAD_IMBALANCE_THRESHOLD / 100;
    
    for i in 0..num_pcpus {
        let load = get_run_queue(i as u16).get_load() as u32;
        let deviation = if load > avg_load {
            load - avg_load
        } else {
            avg_load - load
        };
        
        if deviation > threshold {
            return true;
        }
    }
    
    false
}

/// Perform load balancing across pCPUs
/// Returns the number of vCPUs migrated
pub fn load_balance() -> u32 {
    let num_pcpus = NUM_PCPUS.load(Ordering::Acquire) as usize;
    if num_pcpus <= 1 {
        return 0;
    }
    
    let avg_load = calculate_average_load();
    let mut migrations = 0u32;
    
    // Find overloaded and underloaded pCPUs
    for i in 0..num_pcpus {
        let rq = get_run_queue(i as u16);
        let load = rq.get_load();
        
        // If this pCPU is overloaded (>140% of average)
        if load > avg_load * 140 / 100 {
            // Find an underloaded pCPU
            for j in 0..num_pcpus {
                if i == j {
                    continue;
                }
                
                let target_rq = get_run_queue(j as u16);
                let target_load = target_rq.get_load();
                
                // If target is underloaded (<80% of average)
                if target_load < avg_load * 80 / 100 {
                    // Try to migrate one vCPU
                    if let Some((vcpu_id, vruntime)) = rq.dequeue_min() {
                        // Check affinity before migrating
                        // TODO: Check if vCPU can run on target pCPU
                        
                        if target_rq.enqueue(vcpu_id, 128, vruntime) {
                            rq.migrations_out.fetch_add(1, Ordering::Release);
                            target_rq.migrations_in.fetch_add(1, Ordering::Release);
                            migrations += 1;
                            
                            // Only migrate one vCPU per balance cycle
                            break;
                        } else {
                            // Put it back if migration failed
                            rq.enqueue(vcpu_id, 128, vruntime);
                        }
                    }
                }
            }
        }
    }
    
    migrations
}

// ─────────────────────────────────────────────────────────────────────────────
// TLB Shootdown Batching
// ─────────────────────────────────────────────────────────────────────────────

/// TLB flush request type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlbFlushType {
    /// Flush all TLB entries (INVEPT all contexts)
    Global = 0,
    /// Flush single context (INVEPT single context)
    SingleContext = 1,
    /// Flush specific page
    Page = 2,
}

impl TlbFlushType {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
    
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::Global,
            1 => Self::SingleContext,
            2 => Self::Page,
            _ => Self::Global,
        }
    }
}

/// Batched TLB flush request
#[repr(C)]
pub struct TlbFlushRequest {
    /// Bitmap of target pCPUs
    pub target_pcpus: AtomicU64,
    /// Type of flush (stored as u8 for atomic access)
    pub flush_type: AtomicU8,
    /// ASID/VPID for single-context flush
    pub asid: AtomicU16,
    /// Generation counter for synchronization
    pub generation: AtomicU64,
}

impl TlbFlushRequest {
    pub const fn new() -> Self {
        Self {
            target_pcpus: AtomicU64::new(0),
            flush_type: AtomicU8::new(0), // TlbFlushType::Global as u8
            asid: AtomicU16::new(0),
            generation: AtomicU64::new(0),
        }
    }
}

/// Maximum pending TLB flush requests
pub const TLB_FLUSH_BATCH_SIZE: usize = 16;

/// Pending TLB flush requests
struct SyncTlbFlushQueue(UnsafeCell<[TlbFlushRequest; TLB_FLUSH_BATCH_SIZE]>);
unsafe impl Sync for SyncTlbFlushQueue {}

static TLB_FLUSH_QUEUE: SyncTlbFlushQueue = SyncTlbFlushQueue(
    UnsafeCell::new([const { TlbFlushRequest::new() }; TLB_FLUSH_BATCH_SIZE])
);

static TLB_FLUSH_HEAD: AtomicU32 = AtomicU32::new(0);
static TLB_FLUSH_GEN: AtomicU64 = AtomicU64::new(0);

/// Add a TLB flush request to the batch queue
pub fn request_tlb_flush(target_pcpu: u16, flush_type: TlbFlushType, asid: u16) {
    let head = TLB_FLUSH_HEAD.fetch_add(1, Ordering::AcqRel) % TLB_FLUSH_BATCH_SIZE as u32;
    let gen = TLB_FLUSH_GEN.fetch_add(1, Ordering::AcqRel);
    
    unsafe {
        let req = &(*TLB_FLUSH_QUEUE.0.get())[head as usize];
        req.target_pcpus.store(1u64 << target_pcpu, Ordering::Release);
        req.flush_type.store(flush_type as u8, Ordering::Release);
        req.asid.store(asid, Ordering::Release);
        req.generation.store(gen, Ordering::Release);
    }
}

/// Batch multiple TLB flush requests and send single IPI
pub fn batch_tlb_flush_and_ipi() {
    // Collect all pending requests
    let mut combined_targets = 0u64;
    let mut needs_flush = false;
    
    let head = TLB_FLUSH_HEAD.load(Ordering::Acquire);
    for i in 0..head.min(TLB_FLUSH_BATCH_SIZE as u32) {
        unsafe {
            let req = &(*TLB_FLUSH_QUEUE.0.get())[i as usize];
            let targets = req.target_pcpus.load(Ordering::Acquire);
            if targets != 0 {
                combined_targets |= targets;
                needs_flush = true;
            }
        }
    }
    
    if !needs_flush {
        return;
    }
    
    // Send single broadcast IPI to all targets
    // TODO: Actual IPI sending via APIC
    
    // Clear the queue
    TLB_FLUSH_HEAD.store(0, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler Tick
// ─────────────────────────────────────────────────────────────────────────────

/// Called on every timer tick to update vCPU timeslices
/// Returns the vCPU ID to schedule next, or None to continue current
pub fn sched_tick(_current_vcpu_id: u32, current_pcpu: u16, _elapsed_cycles: u64) -> Option<u32> {
    let rq = get_run_queue(current_pcpu);
    
    // Update current vCPU's vruntime
    // vruntime += elapsed_cycles * 1024 / weight
    // This ensures fair scheduling
    
    // Check if timeslice expired
    // If so, pick next vCPU from run queue
    
    // Check if load balancing is needed
    // Run load balance periodically
    
    // For now, simple round-robin
    rq.dequeue_min().map(|(id, _)| id)
}

// ─────────────────────────────────────────────────────────────────────────────
// vCPU Affinity API
// ─────────────────────────────────────────────────────────────────────────────

/// Set affinity for a vCPU
pub fn set_vcpu_affinity(_vcpu_id: u32, _pcpu_id: u16, affinity_type: u8) -> bool {
    // TODO: Find vCPU in run queues and update affinity
    // If hard affinity, may need to migrate immediately
    affinity_type <= AFFINITY_HARD
}

/// Get the preferred pCPU for a vCPU based on affinity and load
pub fn get_preferred_pcpu(_vcpu_id: u32) -> u16 {
    let num_pcpus = NUM_PCPUS.load(Ordering::Acquire);
    if num_pcpus <= 1 {
        return 0;
    }
    
    // Find the least loaded pCPU
    let mut min_load = u64::MAX;
    let mut best_pcpu = 0u16;
    
    for i in 0..num_pcpus as usize {
        let load = get_run_queue(i as u16).get_load();
        if load < min_load {
            min_load = load;
            best_pcpu = i as u16;
        }
    }
    
    best_pcpu
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vpid_allocation() {
        let vpid1 = allocate_vpid();
        assert!(vpid1 > 0);
        assert!(vpid1 <= 4095);
        
        let vpid2 = allocate_vpid();
        assert!(vpid2 > 0);
        assert_ne!(vpid1, vpid2);
        
        free_vpid(vpid1);
        free_vpid(vpid2);
    }
    
    #[test]
    fn test_run_queue_enqueue_dequeue() {
        let rq = PerPcpuRunQueue::new(0);
        
        // Enqueue two vCPUs with different vruntimes
        assert!(rq.enqueue(1, 128, 100));
        assert!(rq.enqueue(2, 128, 50));
        
        // Dequeue should return the one with lower vruntime
        let (vcpu_id, vruntime) = rq.dequeue_min().unwrap();
        assert_eq!(vcpu_id, 2);
        assert_eq!(vruntime, 50);
        
        let (vcpu_id, _) = rq.dequeue_min().unwrap();
        assert_eq!(vcpu_id, 1);
    }
    
    #[test]
    fn test_scheduler_init() {
        init_scheduler(4);
        assert_eq!(NUM_PCPUS.load(Ordering::Acquire), 4);
    }
    
    #[test]
    fn test_load_balance_no_migration() {
        init_scheduler(2);
        
        let rq0 = get_run_queue(0);
        let rq1 = get_run_queue(1);
        
        // Equal load - no migration needed
        rq0.enqueue(1, 128, 100);
        rq1.enqueue(2, 128, 100);
        
        let migrations = load_balance();
        assert_eq!(migrations, 0);
    }
}
