//! Advanced CPU Scheduler
//!
//! Multiple scheduling algorithms: Credit (Xen-style), SEDF (Real-time), Co-scheduling (SMP VMs).

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum vCPUs
pub const MAX_VCPUS: usize = 1024;

/// Maximum physical CPUs
pub const MAX_PCPUS: usize = 256;

/// Maximum VMs
pub const MAX_VMS: usize = 256;

/// Scheduler types
pub mod sched_type {
    pub const CREDIT: u8 = 0;      // Xen-style credit scheduler
    pub const SEDF: u8 = 1;        // Simple Earliest Deadline First
    pub const CO_SCHED: u8 = 2;    // Co-scheduling for SMP VMs
    pub const FIFO: u8 = 3;        // FIFO for real-time
    pub const RR: u8 = 4;          // Round-robin
}

/// vCPU states
pub mod vcpu_state {
    pub const IDLE: u8 = 0;
    pub const RUNNABLE: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const BLOCKED: u8 = 3;
    pub const YIELD: u8 = 4;
    pub const PREEMPTED: u8 = 5;
}

/// vCPU flags
pub mod vcpu_flag {
    pub const PINNED: u8 = 0x01;
    pub const YIELDING: u8 = 0x02;
    pub const BOOST: u8 = 0x04;
    pub const UNDERFLOW: u8 = 0x08;
    pub const OVERFLOW: u8 = 0x10;
    pub const REALTIME: u8 = 0x20;
    pub const CO_SCHED: u8 = 0x40;
}

/// Credit scheduler defaults
pub const CREDIT_INIT: i32 = 256;
pub const CREDIT_WEIGHT: u32 = 256;
pub const CREDIT_QUANTUM: u64 = 30_000_000; // 30ms in nanoseconds

// ─────────────────────────────────────────────────────────────────────────────
// vCPU Scheduling Data
// ─────────────────────────────────────────────────────────────────────────────

/// vCPU scheduling entry
pub struct VcpuSched {
    /// vCPU ID
    pub vcpu_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Current state
    pub state: AtomicU8,
    /// Flags
    pub flags: AtomicU8,
    /// Priority (0=highest, 255=lowest)
    pub priority: AtomicU8,
    /// Weight (for fair sharing)
    pub weight: AtomicU16,
    /// Current credit (for credit scheduler)
    pub credit: AtomicI32,
    /// Original credit cap
    pub credit_cap: AtomicU32,
    /// Runtime in current slice (ns)
    pub runtime: AtomicU64,
    /// Total runtime (ns)
    pub total_runtime: AtomicU64,
    /// Current pCPU
    pub pcpu: AtomicU16,
    /// Preferred pCPU (affinity)
    pub affinity: AtomicU16,
    /// Last scheduled timestamp
    pub last_schedule: AtomicU64,
    /// Wake timestamp
    pub wake_time: AtomicU64,
    /// Deadline (for SEDF)
    pub deadline: AtomicU64,
    /// Period (for SEDF)
    pub period: AtomicU64,
    /// Slice (for SEDF)
    pub slice: AtomicU64,
    /// Co-schedule group ID
    pub co_group: AtomicU16,
    /// Co-schedule index in group
    pub co_index: AtomicU8,
    /// Ready time (for co-scheduling)
    pub ready_time: AtomicU64,
    /// CPU ready time (waiting to run)
    pub ready_time_total: AtomicU64,
    /// Context switches
    pub context_switches: AtomicU64,
    /// Migrations
    pub migrations: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VcpuSched {
    pub const fn new() -> Self {
        Self {
            vcpu_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            state: AtomicU8::new(vcpu_state::IDLE),
            flags: AtomicU8::new(0),
            priority: AtomicU8::new(128),
            weight: AtomicU16::new(CREDIT_WEIGHT as u16),
            credit: AtomicI32::new(CREDIT_INIT),
            credit_cap: AtomicU32::new(0),
            runtime: AtomicU64::new(0),
            total_runtime: AtomicU64::new(0),
            pcpu: AtomicU16::new(0xFFFF),
            affinity: AtomicU16::new(0xFFFF),
            last_schedule: AtomicU64::new(0),
            wake_time: AtomicU64::new(0),
            deadline: AtomicU64::new(0),
            period: AtomicU64::new(10_000_000), // 10ms
            slice: AtomicU64::new(1_000_000),  // 1ms
            co_group: AtomicU16::new(0),
            co_index: AtomicU8::new(0),
            ready_time: AtomicU64::new(0),
            ready_time_total: AtomicU64::new(0),
            context_switches: AtomicU64::new(0),
            migrations: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize vCPU
    pub fn init(&self, vcpu_id: u32, vm_id: u32, priority: u8, weight: u16) {
        self.vcpu_id.store(vcpu_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.priority.store(priority, Ordering::Release);
        self.weight.store(weight, Ordering::Release);
        self.credit.store(CREDIT_INIT, Ordering::Release);
        self.valid.store(true, Ordering::Release);
        self.state.store(vcpu_state::IDLE, Ordering::Release);
    }

    /// Set runnable
    pub fn set_runnable(&self) {
        self.state.store(vcpu_state::RUNNABLE, Ordering::Release);
        self.wake_time.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Set running
    pub fn set_running(&self, pcpu: u16) {
        self.state.store(vcpu_state::RUNNING, Ordering::Release);
        self.pcpu.store(pcpu, Ordering::Release);
        self.last_schedule.store(Self::get_timestamp(), Ordering::Release);
        self.context_switches.fetch_add(1, Ordering::Release);
        
        // Update ready time
        let wake = self.wake_time.load(Ordering::Acquire);
        let now = Self::get_timestamp();
        if wake > 0 && now > wake {
            self.ready_time_total.fetch_add(now - wake, Ordering::Release);
        }
    }

    /// Set blocked
    pub fn set_blocked(&self) {
        self.state.store(vcpu_state::BLOCKED, Ordering::Release);
    }

    /// Set preempted
    pub fn set_preempted(&self) {
        self.state.store(vcpu_state::PREEMPTED, Ordering::Release);
    }

    /// Update runtime
    pub fn update_runtime(&self, runtime: u64) {
        self.runtime.store(runtime, Ordering::Release);
        self.total_runtime.fetch_add(runtime, Ordering::Release);
    }

    /// Consume credit
    pub fn consume_credit(&self, amount: i32) -> i32 {
        let old = self.credit.load(Ordering::Acquire);
        let new = old - amount;
        self.credit.store(new, Ordering::Release);
        new
    }

    /// Add credit
    pub fn add_credit(&self, amount: i32) -> i32 {
        let old = self.credit.load(Ordering::Acquire);
        let new = old + amount;
        self.credit.store(new, Ordering::Release);
        new
    }

    /// Set affinity
    pub fn set_affinity(&self, pcpu: u16) {
        self.affinity.store(pcpu, Ordering::Release);
        self.flags.fetch_or(vcpu_flag::PINNED, Ordering::Release);
    }

    /// Set real-time parameters
    pub fn set_realtime(&self, period: u64, slice: u64) {
        self.period.store(period, Ordering::Release);
        self.slice.store(slice, Ordering::Release);
        self.flags.fetch_or(vcpu_flag::REALTIME, Ordering::Release);
    }

    /// Set co-schedule group
    pub fn set_co_group(&self, group: u16, index: u8) {
        self.co_group.store(group, Ordering::Release);
        self.co_index.store(index, Ordering::Release);
        self.flags.fetch_or(vcpu_flag::CO_SCHED, Ordering::Release);
    }

    /// Get CPU ready time percentage
    pub fn get_ready_pct(&self) -> u32 {
        let total = self.total_runtime.load(Ordering::Acquire);
        let ready = self.ready_time_total.load(Ordering::Acquire);
        
        if total == 0 {
            return 0;
        }
        
        ((ready * 100) / total) as u32
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VcpuSched {
    fn default() -> Self {
        Self::new()
    }
}

/// Atomic I32
pub struct AtomicI32 {
    inner: AtomicU32,
}

impl AtomicI32 {
    pub const fn new(v: i32) -> Self {
        Self { inner: AtomicU32::new(v as u32) }
    }
    pub fn load(&self, order: Ordering) -> i32 {
        self.inner.load(order) as i32
    }
    pub fn store(&self, v: i32, order: Ordering) {
        self.inner.store(v as u32, order);
    }
    pub fn fetch_add(&self, v: i32, order: Ordering) -> i32 {
        self.inner.fetch_add(v as u32, order) as i32
    }
    pub fn fetch_sub(&self, v: i32, order: Ordering) -> i32 {
        self.inner.fetch_sub(v as u32, order) as i32
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// pCPU Run Queue
// ─────────────────────────────────────────────────────────────────────────────

/// Run queue entry
pub struct RunQueueEntry {
    /// vCPU index
    pub vcpu_idx: AtomicU32,
    /// Priority for sorting
    pub sort_key: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl RunQueueEntry {
    pub const fn new() -> Self {
        Self {
            vcpu_idx: AtomicU32::new(0),
            sort_key: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }
}

impl Default for RunQueueEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum run queue entries per pCPU
pub const MAX_RUNQ_ENTRIES: usize = 256;

/// pCPU run queue
pub struct PcpuRunQueue {
    /// pCPU ID
    pub pcpu_id: AtomicU16,
    /// Entries
    pub entries: [RunQueueEntry; MAX_RUNQ_ENTRIES],
    /// Entry count
    pub count: AtomicU16,
    /// Current vCPU running
    pub current_vcpu: AtomicU32,
    /// Idle vCPU
    pub idle_vcpu: AtomicU32,
    /// Load average (0-1000)
    pub load_avg: AtomicU32,
    /// Total scheduled
    pub total_scheduled: AtomicU64,
    /// Total time (ns)
    pub total_time: AtomicU64,
    /// Idle time (ns)
    pub idle_time: AtomicU64,
}

impl PcpuRunQueue {
    pub const fn new() -> Self {
        Self {
            pcpu_id: AtomicU16::new(0),
            entries: [const { RunQueueEntry::new() }; MAX_RUNQ_ENTRIES],
            count: AtomicU16::new(0),
            current_vcpu: AtomicU32::new(0xFFFF),
            idle_vcpu: AtomicU32::new(0xFFFF),
            load_avg: AtomicU32::new(0),
            total_scheduled: AtomicU64::new(0),
            total_time: AtomicU64::new(0),
            idle_time: AtomicU64::new(0),
        }
    }

    /// Initialize
    pub fn init(&self, pcpu_id: u16) {
        self.pcpu_id.store(pcpu_id, Ordering::Release);
    }

    /// Enqueue vCPU
    pub fn enqueue(&self, vcpu_idx: u32, sort_key: u64) -> bool {
        let count = self.count.load(Ordering::Acquire);
        if count as usize >= MAX_RUNQ_ENTRIES {
            return false;
        }
        
        let entry = &self.entries[count as usize];
        entry.vcpu_idx.store(vcpu_idx, Ordering::Release);
        entry.sort_key.store(sort_key, Ordering::Release);
        entry.valid.store(true, Ordering::Release);
        
        self.count.fetch_add(1, Ordering::Release);
        true
    }

    /// Dequeue highest priority vCPU
    pub fn dequeue_highest(&self) -> Option<u32> {
        let count = self.count.load(Ordering::Acquire);
        if count == 0 {
            return None;
        }
        
        // Find highest priority (lowest sort_key)
        let mut best_idx = 0;
        let mut best_key = u64::MAX;
        
        for i in 0..count as usize {
            if self.entries[i].valid.load(Ordering::Acquire) {
                let key = self.entries[i].sort_key.load(Ordering::Acquire);
                if key < best_key {
                    best_key = key;
                    best_idx = i;
                }
            }
        }
        
        // Remove entry
        let vcpu = self.entries[best_idx].vcpu_idx.load(Ordering::Acquire);
        self.entries[best_idx].valid.store(false, Ordering::Release);
        
        // Compact queue
        if best_idx < count as usize - 1 {
            let last = count as usize - 1;
            self.entries[best_idx].vcpu_idx.store(
                self.entries[last].vcpu_idx.load(Ordering::Acquire),
                Ordering::Release
            );
            self.entries[best_idx].sort_key.store(
                self.entries[last].sort_key.load(Ordering::Acquire),
                Ordering::Release
            );
            self.entries[best_idx].valid.store(true, Ordering::Release);
            self.entries[last].valid.store(false, Ordering::Release);
        }
        
        self.count.fetch_sub(1, Ordering::Release);
        Some(vcpu)
    }

    /// Remove vCPU from queue
    pub fn remove(&self, vcpu_idx: u32) -> bool {
        let count = self.count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            if self.entries[i].valid.load(Ordering::Acquire) &&
               self.entries[i].vcpu_idx.load(Ordering::Acquire) == vcpu_idx {
                self.entries[i].valid.store(false, Ordering::Release);
                self.count.fetch_sub(1, Ordering::Release);
                return true;
            }
        }
        
        false
    }

    /// Update load average
    pub fn update_load(&self) {
        let total = self.total_time.load(Ordering::Acquire);
        let idle = self.idle_time.load(Ordering::Acquire);
        
        if total == 0 {
            self.load_avg.store(0, Ordering::Release);
            return;
        }
        
        let load = ((total - idle) * 1000 / total) as u32;
        self.load_avg.store(load, Ordering::Release);
    }

    /// Get utilization percentage
    pub fn get_utilization(&self) -> u32 {
        self.load_avg.load(Ordering::Acquire) / 10
    }
}

impl Default for PcpuRunQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Co-Schedule Group
// ─────────────────────────────────────────────────────────────────────────────

/// Co-schedule group (for SMP VMs)
pub struct CoSchedGroup {
    /// Group ID
    pub group_id: AtomicU16,
    /// VM ID
    pub vm_id: AtomicU32,
    /// vCPU indices in group
    pub vcpu_indices: [AtomicU32; 64],
    /// vCPU count
    pub vcpu_count: AtomicU8,
    /// Synchronized state (all vCPUs runnable)
    pub synced: AtomicBool,
    /// Ready vCPU count
    pub ready_count: AtomicU8,
    /// Running vCPU count
    pub running_count: AtomicU8,
    /// Last sync time
    pub last_sync: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CoSchedGroup {
    pub const fn new() -> Self {
        Self {
            group_id: AtomicU16::new(0),
            vm_id: AtomicU32::new(0),
            vcpu_indices: [const { AtomicU32::new(0) }; 64],
            vcpu_count: AtomicU8::new(0),
            synced: AtomicBool::new(false),
            ready_count: AtomicU8::new(0),
            running_count: AtomicU8::new(0),
            last_sync: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize group
    pub fn init(&self, group_id: u16, vm_id: u32) {
        self.group_id.store(group_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add vCPU to group
    pub fn add_vcpu(&self, vcpu_idx: u32) {
        let count = self.vcpu_count.load(Ordering::Acquire) as usize;
        if count < 64 {
            self.vcpu_indices[count].store(vcpu_idx, Ordering::Release);
            self.vcpu_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Mark vCPU ready
    pub fn mark_ready(&self) -> bool {
        let count = self.ready_count.fetch_add(1, Ordering::Release) + 1;
        let total = self.vcpu_count.load(Ordering::Acquire);
        
        if count == total {
            self.synced.store(true, Ordering::Release);
            self.last_sync.store(Self::get_timestamp(), Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Mark vCPU running
    pub fn mark_running(&self) {
        self.running_count.fetch_add(1, Ordering::Release);
    }

    /// Mark vCPU stopped
    pub fn mark_stopped(&self) {
        self.running_count.fetch_sub(1, Ordering::Release);
        self.ready_count.fetch_sub(1, Ordering::Release);
        self.synced.store(false, Ordering::Release);
    }

    /// Check if all vCPUs can run
    pub fn can_run(&self) -> bool {
        self.synced.load(Ordering::Acquire)
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for CoSchedGroup {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum co-schedule groups
pub const MAX_CO_GROUPS: usize = 128;

// ─────────────────────────────────────────────────────────────────────────────
// Advanced CPU Scheduler
// ─────────────────────────────────────────────────────────────────────────────

/// Advanced CPU scheduler
pub struct AdvancedCpuScheduler {
    /// vCPU scheduling data
    pub vcpus: [VcpuSched; MAX_VCPUS],
    /// vCPU count
    pub vcpu_count: AtomicU32,
    /// pCPU run queues
    pub run_queues: [PcpuRunQueue; MAX_PCPUS],
    /// pCPU count
    pub pcpu_count: AtomicU16,
    /// Co-schedule groups
    pub co_groups: [CoSchedGroup; MAX_CO_GROUPS],
    /// Co-group count
    pub co_group_count: AtomicU8,
    /// Active scheduler type
    pub sched_type: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Time slice (ns)
    pub time_slice: AtomicU64,
    /// Credit balance interval (ns)
    pub credit_interval: AtomicU64,
    /// Last credit balance
    pub last_credit_balance: AtomicU64,
    /// Total context switches
    pub total_ctx_switches: AtomicU64,
    /// Total migrations
    pub total_migrations: AtomicU64,
    /// Total schedules
    pub total_schedules: AtomicU64,
    /// Load balance interval (ns)
    pub load_balance_interval: AtomicU64,
    /// Last load balance
    pub last_load_balance: AtomicU64,
}

impl AdvancedCpuScheduler {
    pub const fn new() -> Self {
        Self {
            vcpus: [const { VcpuSched::new() }; MAX_VCPUS],
            vcpu_count: AtomicU32::new(0),
            run_queues: [const { PcpuRunQueue::new() }; MAX_PCPUS],
            pcpu_count: AtomicU16::new(0),
            co_groups: [const { CoSchedGroup::new() }; MAX_CO_GROUPS],
            co_group_count: AtomicU8::new(0),
            sched_type: AtomicU8::new(sched_type::CREDIT),
            enabled: AtomicBool::new(false),
            time_slice: AtomicU64::new(CREDIT_QUANTUM),
            credit_interval: AtomicU64::new(10_000_000_000), // 10 seconds
            last_credit_balance: AtomicU64::new(0),
            total_ctx_switches: AtomicU64::new(0),
            total_migrations: AtomicU64::new(0),
            total_schedules: AtomicU64::new(0),
            load_balance_interval: AtomicU64::new(100_000_000), // 100ms
            last_load_balance: AtomicU64::new(0),
        }
    }

    /// Enable scheduler
    pub fn enable(&mut self, pcpu_count: u16, sched_type: u8) {
        self.pcpu_count.store(pcpu_count, Ordering::Release);
        self.sched_type.store(sched_type, Ordering::Release);
        
        // Initialize run queues
        for i in 0..pcpu_count as usize {
            self.run_queues[i].init(i as u16);
        }
        
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable scheduler
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register vCPU
    pub fn register_vcpu(&mut self, vcpu_id: u32, vm_id: u32, 
                         priority: u8, weight: u16) -> Result<u32, HvError> {
        let count = self.vcpu_count.load(Ordering::Acquire);
        if count as usize >= MAX_VCPUS {
            return Err(HvError::LogicalFault);
        }
        
        let idx = count;
        let vcpu = &self.vcpus[idx as usize];
        vcpu.init(vcpu_id, vm_id, priority, weight);
        
        self.vcpu_count.fetch_add(1, Ordering::Release);
        Ok(idx)
    }

    /// Create co-schedule group for SMP VM
    pub fn create_co_group(&mut self, vm_id: u32, vcpu_indices: &[u32]) -> Result<u16, HvError> {
        let count = self.co_group_count.load(Ordering::Acquire);
        if count as usize >= MAX_CO_GROUPS {
            return Err(HvError::LogicalFault);
        }
        
        let group_id = count as u16;
        let group = &self.co_groups[count as usize];
        group.init(group_id, vm_id);
        
        for (i, &vcpu_idx) in vcpu_indices.iter().enumerate() {
            if i >= 64 {
                break;
            }
            group.add_vcpu(vcpu_idx);
            self.vcpus[vcpu_idx as usize].set_co_group(group_id, i as u8);
        }
        
        self.co_group_count.fetch_add(1, Ordering::Release);
        Ok(group_id)
    }

    /// Wake vCPU
    pub fn wake_vcpu(&mut self, vcpu_idx: u32) -> Result<(), HvError> {
        if vcpu_idx as usize >= MAX_VCPUS {
            return Err(HvError::LogicalFault);
        }
        
        let vcpu = &self.vcpus[vcpu_idx as usize];
        if !vcpu.valid.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        vcpu.set_runnable();
        
        // Handle co-scheduling
        if vcpu.flags.load(Ordering::Acquire) & vcpu_flag::CO_SCHED != 0 {
            let group_id = vcpu.co_group.load(Ordering::Acquire);
            if group_id as usize < MAX_CO_GROUPS {
                self.co_groups[group_id as usize].mark_ready();
            }
        }
        
        // Add to run queue
        self.enqueue_vcpu(vcpu_idx)?;
        
        Ok(())
    }

    /// Enqueue vCPU to appropriate run queue
    fn enqueue_vcpu(&self, vcpu_idx: u32) -> Result<(), HvError> {
        let vcpu = &self.vcpus[vcpu_idx as usize];
        
        // Determine target pCPU
        let affinity = vcpu.affinity.load(Ordering::Acquire);
        let target_pcpu = if affinity != 0xFFFF {
            affinity as usize
        } else {
            // Find least loaded pCPU
            self.find_least_loaded_pcpu()
        };
        
        // Calculate sort key based on scheduler type
        let sort_key = match self.sched_type.load(Ordering::Acquire) {
            sched_type::CREDIT => {
                // Lower credit = higher priority
                (vcpu.credit.load(Ordering::Acquire() as u32) as u64) << 32 | 
                vcpu.priority.load(Ordering::Acquire) as u64
            }
            sched_type::SEDF => {
                // Earlier deadline = higher priority
                vcpu.deadline.load(Ordering::Acquire)
            }
            _ => {
                vcpu.priority.load(Ordering::Acquire) as u64
            }
        };
        
        self.run_queues[target_pcpu].enqueue(vcpu_idx, sort_key);
        
        Ok(())
    }

    /// Find least loaded pCPU
    fn find_least_loaded_pcpu(&self) -> usize {
        let pcpu_count = self.pcpu_count.load(Ordering::Acquire) as usize;
        let mut min_load = u32::MAX;
        let mut min_idx = 0;
        
        for i in 0..pcpu_count {
            let load = self.run_queues[i].load_avg.load(Ordering::Acquire);
            if load < min_load {
                min_load = load;
                min_idx = i;
            }
        }
        
        min_idx
    }

    /// Schedule next vCPU on pCPU
    pub fn schedule(&mut self, pcpu: u16) -> Option<u32> {
        if !self.enabled.load(Ordering::Acquire) {
            return None;
        }
        
        let rq = &self.run_queues[pcpu as usize];
        
        // Get next vCPU
        let next = rq.dequeue_highest();
        
        if let Some(vcpu_idx) = next {
            let vcpu = &self.vcpus[vcpu_idx as usize];
            
            // Check co-scheduling constraint
            if vcpu.flags.load(Ordering::Acquire) & vcpu_flag::CO_SCHED != 0 {
                let group_id = vcpu.co_group.load(Ordering::Acquire);
                if group_id as usize < MAX_CO_GROUPS {
                    let group = &self.co_groups[group_id as usize];
                    if !group.can_run() {
                        // Put back in queue
                        rq.enqueue(vcpu_idx, vcpu.priority.load(Ordering::Acquire) as u64);
                        return None;
                    }
                    group.mark_running();
                }
            }
            
            vcpu.set_running(pcpu);
            rq.current_vcpu.store(vcpu_idx, Ordering::Release);
            rq.total_scheduled.fetch_add(1, Ordering::Release);
            
            self.total_schedules.fetch_add(1, Ordering::Release);
            self.total_ctx_switches.fetch_add(1, Ordering::Release);
            
            return Some(vcpu_idx);
        }
        
        None
    }

    /// Preempt current vCPU
    pub fn preempt(&mut self, pcpu: u16) -> Option<u32> {
        let rq = &self.run_queues[pcpu as usize];
        let current = rq.current_vcpu.load(Ordering::Acquire);
        
        if current == 0xFFFF {
            return None;
        }
        
        let vcpu = &self.vcpus[current as usize];
        vcpu.set_preempted();
        
        // Update credit
        let runtime = Self::get_timestamp() - vcpu.last_schedule.load(Ordering::Acquire);
        vcpu.update_runtime(runtime);
        vcpu.consume_credit((runtime / 1_000_000) as i32); // Credit per ms
        
        // Re-enqueue if still runnable
        if vcpu.state.load(Ordering::Acquire) == vcpu_state::PREEMPTED {
            self.enqueue_vcpu(current).ok();
        }
        
        rq.current_vcpu.store(0xFFFF, Ordering::Release);
        
        // Schedule next
        self.schedule(pcpu)
    }

    /// Block vCPU
    pub fn block_vcpu(&mut self, vcpu_idx: u32) -> Result<(), HvError> {
        if vcpu_idx as usize >= MAX_VCPUS {
            return Err(HvError::LogicalFault);
        }
        
        let vcpu = &self.vcpus[vcpu_idx as usize];
        vcpu.set_blocked();
        
        // Update co-schedule group
        if vcpu.flags.load(Ordering::Acquire) & vcpu_flag::CO_SCHED != 0 {
            let group_id = vcpu.co_group.load(Ordering::Acquire);
            if group_id as usize < MAX_CO_GROUPS {
                self.co_groups[group_id as usize].mark_stopped();
            }
        }
        
        Ok(())
    }

    /// Yield vCPU
    pub fn yield_vcpu(&mut self, vcpu_idx: u32) -> Result<(), HvError> {
        if vcpu_idx as usize >= MAX_VCPUS {
            return Err(HvError::LogicalFault);
        }
        
        let vcpu = &self.vcpus[vcpu_idx as usize];
        vcpu.state.store(vcpu_state::YIELD, Ordering::Release);
        
        // Add credit bonus for yielding
        vcpu.add_credit(10);
        
        // Re-enqueue
        self.enqueue_vcpu(vcpu_idx)?;
        
        Ok(())
    }

    /// Balance credit across vCPUs
    pub fn balance_credits(&mut self) {
        let now = Self::get_timestamp();
        let interval = self.credit_interval.load(Ordering::Acquire);
        
        if now - self.last_credit_balance.load(Ordering::Acquire) < interval {
            return;
        }
        
        self.last_credit_balance.store(now, Ordering::Release);
        
        // Calculate total weight
        let mut total_weight = 0u64;
        let count = self.vcpu_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            if self.vcpus[i].valid.load(Ordering::Acquire) {
                total_weight += self.vcpus[i].weight.load(Ordering::Acquire) as u64;
            }
        }
        
        if total_weight == 0 {
            return;
        }
        
        // Distribute credits proportionally
        for i in 0..count as usize {
            let vcpu = &self.vcpus[i];
            if vcpu.valid.load(Ordering::Acquire) {
                let weight = vcpu.weight.load(Ordering::Acquire) as u64;
                let credit = ((weight * CREDIT_INIT as u64 * count as u64) / total_weight) as i32;
                vcpu.credit.store(credit, Ordering::Release);
            }
        }
    }

    /// Load balance across pCPUs
    pub fn load_balance(&mut self) {
        let now = Self::get_timestamp();
        let interval = self.load_balance_interval.load(Ordering::Acquire);
        
        if now - self.last_load_balance.load(Ordering::Acquire) < interval {
            return;
        }
        
        self.last_load_balance.store(now, Ordering::Release);
        
        let pcpu_count = self.pcpu_count.load(Ordering::Acquire) as usize;
        if pcpu_count < 2 {
            return;
        }
        
        // Find most and least loaded
        let mut max_load = 0u32;
        let mut max_idx = 0;
        let mut min_load = u32::MAX;
        let mut min_idx = 0;
        
        for i in 0..pcpu_count {
            let load = self.run_queues[i].load_avg.load(Ordering::Acquire);
            if load > max_load {
                max_load = load;
                max_idx = i;
            }
            if load < min_load {
                min_load = load;
                min_idx = i;
            }
        }
        
        // Migrate if imbalance > 20%
        if max_load > min_load * 120 / 100 {
            // Move one vCPU from max to min
            if let Some(vcpu_idx) = self.run_queues[max_idx].dequeue_highest() {
                let vcpu = &self.vcpus[vcpu_idx as usize];
                
                // Don't migrate pinned vCPUs
                if vcpu.flags.load(Ordering::Acquire) & vcpu_flag::PINNED == 0 {
                    let sort_key = vcpu.priority.load(Ordering::Acquire) as u64;
                    self.run_queues[min_idx].enqueue(vcpu_idx, sort_key);
                    vcpu.migrations.fetch_add(1, Ordering::Release);
                    self.total_migrations.fetch_add(1, Ordering::Release);
                } else {
                    // Put back
                    self.run_queues[max_idx].enqueue(vcpu_idx, vcpu.priority.load(Ordering::Acquire) as u64);
                }
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> SchedulerStats {
        let mut runnable = 0u32;
        let mut running = 0u32;
        let mut blocked = 0u32;
        
        for i in 0..self.vcpu_count.load(Ordering::Acquire) as usize {
            match self.vcpus[i].state.load(Ordering::Acquire) {
                vcpu_state::RUNNABLE => runnable += 1,
                vcpu_state::RUNNING => running += 1,
                vcpu_state::BLOCKED => blocked += 1,
                _ => {}
            }
        }
        
        SchedulerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            sched_type: self.sched_type.load(Ordering::Acquire),
            pcpu_count: self.pcpu_count.load(Ordering::Acquire),
            vcpu_count: self.vcpu_count.load(Ordering::Acquire),
            runnable,
            running,
            blocked,
            total_ctx_switches: self.total_ctx_switches.load(Ordering::Acquire),
            total_migrations: self.total_migrations.load(Ordering::Acquire),
            total_schedules: self.total_schedules.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for AdvancedCpuScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler statistics
#[repr(C)]
pub struct SchedulerStats {
    pub enabled: bool,
    pub sched_type: u8,
    pub pcpu_count: u16,
    pub vcpu_count: u32,
    pub runnable: u32,
    pub running: u32,
    pub blocked: u32,
    pub total_ctx_switches: u64,
    pub total_migrations: u64,
    pub total_schedules: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vcpu() {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        
        let idx = sched.register_vcpu(0, 1, 128, 256).unwrap();
        assert_eq!(sched.vcpu_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn wake_and_schedule() {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        
        let idx = sched.register_vcpu(0, 1, 128, 256).unwrap();
        sched.wake_vcpu(idx).unwrap();
        
        let next = sched.schedule(0);
        assert!(next.is_some());
    }

    #[test]
    fn co_scheduling() {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CO_SCHED);
        
        let v0 = sched.register_vcpu(0, 1, 128, 256).unwrap();
        let v1 = sched.register_vcpu(1, 1, 128, 256).unwrap();
        
        let group = sched.create_co_group(1, &[v0, v1]).unwrap();
        assert_eq!(group, 0);
    }

    #[test]
    fn credit_balance() {
        let mut sched = AdvancedCpuScheduler::new();
        sched.enable(4, sched_type::CREDIT);
        
        sched.register_vcpu(0, 1, 128, 256).unwrap();
        sched.register_vcpu(1, 1, 128, 512).unwrap();
        
        sched.balance_credits();
        
        // Higher weight should get more credit
        let c0 = sched.vcpus[0].credit.load(Ordering::Acquire);
        let c1 = sched.vcpus[1].credit.load(Ordering::Acquire());
        assert!(c1 > c0);
    }

    #[test]
    fn run_queue() {
        let rq = PcpuRunQueue::new();
        rq.init(0);
        
        rq.enqueue(1, 100);
        rq.enqueue(2, 50);  // Higher priority
        rq.enqueue(3, 200);
        
        let next = rq.dequeue_highest();
        assert_eq!(next, Some(2)); // Lowest sort_key = highest priority
    }
}
