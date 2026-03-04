//! PMU Integration Enhancement
//!
//! Performance Monitoring Unit integration for hypervisor and guest performance analysis.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// PMU Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum PMU counters per CPU
pub const MAX_PMU_COUNTERS: usize = 8;

/// Maximum CPUs with PMU
#[cfg(not(test))]
pub const MAX_PMU_CPUS: usize = 256;
/// Maximum CPUs with PMU (reduced for tests)
#[cfg(test)]
pub const MAX_PMU_CPUS: usize = 4;

/// Maximum event groups
#[cfg(not(test))]
pub const MAX_EVENT_GROUPS: usize = 64;
/// Maximum event groups (reduced for tests)
#[cfg(test)]
pub const MAX_EVENT_GROUPS: usize = 4;

/// Maximum sampling buffers
#[cfg(not(test))]
pub const MAX_SAMPLING_BUFFERS: usize = 32;
/// Maximum sampling buffers (reduced for tests)
#[cfg(test)]
pub const MAX_SAMPLING_BUFFERS: usize = 4;

/// Sampling buffer size (entries)
#[cfg(not(test))]
pub const SAMPLING_BUFFER_SIZE: usize = 4096;
/// Sampling buffer size (reduced for tests)
#[cfg(test)]
pub const SAMPLING_BUFFER_SIZE: usize = 64;

/// PMU event types
pub mod pmu_event {
    // CPU cycles
    pub const CPU_CYCLES: u16 = 0x003C;
    // Instructions retired
    pub const INSTRUCTIONS: u16 = 0x00C0;
    // Cache references
    pub const CACHE_REFERENCES: u16 = 0x004E;
    // Cache misses
    pub const CACHE_MISSES: u16 = 0x004F;
    // Branch instructions
    pub const BRANCH_INSTRUCTIONS: u16 = 0x00C4;
    // Branch misses
    pub const BRANCH_MISSES: u16 = 0x00C5;
    // Bus cycles
    pub const BUS_CYCLES: u16 = 0x003D;
    // Stalled cycles frontend
    pub const STALLED_CYCLES_FRONTEND: u16 = 0x0186;
    // Stalled cycles backend
    pub const STALLED_CYCLES_BACKEND: u16 = 0x0187;
    // L1D cache accesses
    pub const L1D_ACCESSES: u16 = 0x0040;
    // L1D cache misses
    pub const L1D_MISSES: u16 = 0x0041;
    // L1I cache accesses
    pub const L1I_ACCESSES: u16 = 0x0080;
    // L1I cache misses
    pub const L1I_MISSES: u16 = 0x0081;
    // LLC accesses
    pub const LLC_ACCESSES: u16 = 0x004E;
    // LLC misses
    pub const LLC_MISSES: u16 = 0x004F;
    // DTLB misses
    pub const DTLB_MISSES: u16 = 0x0049;
    // ITLB misses
    pub const ITLB_MISSES: u16 = 0x0085;
    // Memory loads
    pub const MEM_LOADS: u16 = 0x00CD;
    // Memory stores
    pub const MEM_STORES: u16 = 0x00D0;
    // VM exits
    pub const VM_EXITS: u16 = 0x1000;
    // VM entries
    pub const VM_ENTRIES: u16 = 0x1001;
    // EPT violations
    pub const EPT_VIOLATIONS: u16 = 0x1002;
    // TLB shootdowns
    pub const TLB_SHOOTDOWNS: u16 = 0x1003;
}

/// Counter modes
pub mod counter_mode {
    pub const USER: u8 = 1 << 0;
    pub const KERNEL: u8 = 1 << 1;
    pub const HYPERVISOR: u8 = 1 << 2;
    pub const GUEST: u8 = 1 << 3;
    pub const ALL: u8 = USER | KERNEL | HYPERVISOR | GUEST;
}

/// Sampling types
pub mod sampling_type {
    pub const NONE: u8 = 0;
    pub const IP: u8 = 1 << 0;
    pub const TID: u8 = 1 << 1;
    pub const TIME: u8 = 1 << 2;
    pub const ADDR: u8 = 1 << 3;
    pub const READ: u8 = 1 << 4;
    pub const CALLCHAIN: u8 = 1 << 5;
    pub const REGS: u8 = 1 << 6;
    pub const STACK: u8 = 1 << 7;
}

/// Counter states
pub mod counter_state {
    pub const DISABLED: u8 = 0;
    pub const ENABLED: u8 = 1;
    pub const ERROR: u8 = 2;
}

// ─────────────────────────────────────────────────────────────────────────────
// PMU Counter
// ─────────────────────────────────────────────────────────────────────────────

/// PMU counter
pub struct PmuCounter {
    /// Counter ID
    pub counter_id: AtomicU8,
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// Event type
    pub event: AtomicU16,
    /// Event mask (UMASK)
    pub event_mask: AtomicU8,
    /// Mode mask
    pub mode: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// Counter value
    pub value: AtomicU64,
    /// Reset value
    pub reset_value: AtomicU64,
    /// Sample period
    pub sample_period: AtomicU64,
    /// Sample frequency
    pub sample_freq: AtomicU32,
    /// Overflow count
    pub overflow_count: AtomicU64,
    /// Last overflow time
    pub last_overflow: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl PmuCounter {
    pub const fn new() -> Self {
        Self {
            counter_id: AtomicU8::new(0),
            cpu_id: AtomicU8::new(0),
            event: AtomicU16::new(0),
            event_mask: AtomicU8::new(0),
            mode: AtomicU8::new(counter_mode::ALL),
            state: AtomicU8::new(counter_state::DISABLED),
            value: AtomicU64::new(0),
            reset_value: AtomicU64::new(0),
            sample_period: AtomicU64::new(0),
            sample_freq: AtomicU32::new(0),
            overflow_count: AtomicU64::new(0),
            last_overflow: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize counter
    pub fn init(&self, counter_id: u8, cpu_id: u8, event: u16, event_mask: u8, mode: u8) {
        self.counter_id.store(counter_id, Ordering::Release);
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.event.store(event, Ordering::Release);
        self.event_mask.store(event_mask, Ordering::Release);
        self.mode.store(mode, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable counter
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
        self.state.store(counter_state::ENABLED, Ordering::Release);
    }

    /// Disable counter
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
        self.state.store(counter_state::DISABLED, Ordering::Release);
    }

    /// Read counter
    pub fn read(&self) -> u64 {
        self.value.load(Ordering::Acquire)
    }

    /// Write counter
    pub fn write(&self, value: u64) {
        self.value.store(value, Ordering::Release);
    }

    /// Reset counter
    pub fn reset(&self) {
        self.value.store(self.reset_value.load(Ordering::Acquire), Ordering::Release);
    }

    /// Set sample period
    pub fn set_sample_period(&self, period: u64) {
        self.sample_period.store(period, Ordering::Release);
    }

    /// Handle overflow
    pub fn handle_overflow(&self) -> bool {
        self.overflow_count.fetch_add(1, Ordering::Release);
        self.last_overflow.store(Self::get_timestamp(), Ordering::Release);
        
        if self.sample_period.load(Ordering::Acquire) > 0 {
            self.reset();
            true
        } else {
            false
        }
    }

    /// Update value (add delta)
    pub fn update(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for PmuCounter {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sample Entry
// ─────────────────────────────────────────────────────────────────────────────

/// Sample entry
pub struct SampleEntry {
    /// Entry ID
    pub entry_id: AtomicU64,
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// PID
    pub pid: AtomicU32,
    /// TID
    pub tid: AtomicU32,
    /// Timestamp
    pub timestamp: AtomicU64,
    /// Instruction pointer
    pub ip: AtomicU64,
    /// Address
    pub addr: AtomicU64,
    /// Counter value
    pub value: AtomicU64,
    /// Event type
    pub event: AtomicU16,
    /// Flags
    pub flags: AtomicU32,
    /// Callchain depth
    pub callchain_depth: AtomicU8,
    /// Callchain (simplified)
    pub callchain: [AtomicU64; 8],
    /// Valid
    pub valid: AtomicBool,
}

impl SampleEntry {
    pub const fn new() -> Self {
        Self {
            entry_id: AtomicU64::new(0),
            cpu_id: AtomicU8::new(0),
            pid: AtomicU32::new(0),
            tid: AtomicU32::new(0),
            timestamp: AtomicU64::new(0),
            ip: AtomicU64::new(0),
            addr: AtomicU64::new(0),
            value: AtomicU64::new(0),
            event: AtomicU16::new(0),
            flags: AtomicU32::new(0),
            callchain_depth: AtomicU8::new(0),
            callchain: [const { AtomicU64::new(0) }; 8],
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize entry
    pub fn init(&self, entry_id: u64, cpu_id: u8, event: u16, ip: u64, value: u64) {
        self.entry_id.store(entry_id, Ordering::Release);
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.event.store(event, Ordering::Release);
        self.ip.store(ip, Ordering::Release);
        self.value.store(value, Ordering::Release);
        self.timestamp.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set callchain
    pub fn set_callchain(&self, ips: &[u64]) {
        let depth = ips.len().min(8);
        self.callchain_depth.store(depth as u8, Ordering::Release);
        
        for i in 0..depth {
            self.callchain[i].store(ips[i], Ordering::Release);
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for SampleEntry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sampling Buffer
// ─────────────────────────────────────────────────────────────────────────────

/// Sampling buffer
pub struct SamplingBuffer {
    /// Buffer ID
    pub buffer_id: AtomicU32,
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// Sampling type mask
    pub sampling_type: AtomicU16,
    /// Sample entries
    pub entries: [SampleEntry; SAMPLING_BUFFER_SIZE],
    /// Head
    pub head: AtomicU32,
    /// Tail
    pub tail: AtomicU32,
    /// Entry count
    pub entry_count: AtomicU64,
    /// Samples dropped
    pub dropped: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl SamplingBuffer {
    pub const fn new() -> Self {
        Self {
            buffer_id: AtomicU32::new(0),
            cpu_id: AtomicU8::new(0),
            sampling_type: AtomicU16::new((sampling_type::IP | sampling_type::TIME) as u16),
            entries: [const { SampleEntry::new() }; SAMPLING_BUFFER_SIZE],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            entry_count: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize buffer
    pub fn init(&self, buffer_id: u32, cpu_id: u8, sampling_type: u16) {
        self.buffer_id.store(buffer_id, Ordering::Release);
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.sampling_type.store(sampling_type, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add sample
    pub fn add_sample(&self, event: u16, ip: u64, value: u64) -> Option<u64> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let size = SAMPLING_BUFFER_SIZE as u32;
        
        let next_head = (head + 1) % size;
        if next_head == tail {
            self.dropped.fetch_add(1, Ordering::Release);
            return None;
        }
        
        let entry_id = self.entry_count.fetch_add(1, Ordering::Release);
        let cpu_id = self.cpu_id.load(Ordering::Acquire);
        
        self.entries[head as usize].init(entry_id, cpu_id, event, ip, value);
        self.head.store(next_head, Ordering::Release);
        
        Some(entry_id)
    }

    /// Get sample
    pub fn get_sample(&self) -> Option<&SampleEntry> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        let entry = &self.entries[tail as usize];
        self.tail.store((tail + 1) % SAMPLING_BUFFER_SIZE as u32, Ordering::Release);
        
        Some(entry)
    }

    /// Peek sample
    pub fn peek_sample(&self) -> Option<&SampleEntry> {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        Some(&self.entries[tail as usize])
    }

    /// Get count
    pub fn count(&self) -> u32 {
        let head = self.head.load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Acquire);
        let size = SAMPLING_BUFFER_SIZE as u32;
        
        (head + size - tail) % size
    }

    /// Clear buffer
    pub fn clear(&self) {
        self.head.store(0, Ordering::Release);
        self.tail.store(0, Ordering::Release);
    }
}

impl Default for SamplingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Group
// ─────────────────────────────────────────────────────────────────────────────

/// Event group for coordinated counting
pub struct EventGroup {
    /// Group ID
    pub group_id: AtomicU32,
    /// Leader counter ID
    pub leader_id: AtomicU8,
    /// Member counter IDs
    pub members: [AtomicU8; MAX_PMU_COUNTERS],
    /// Member count
    pub member_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Read count
    pub read_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl EventGroup {
    pub const fn new() -> Self {
        Self {
            group_id: AtomicU32::new(0),
            leader_id: AtomicU8::new(0),
            members: [const { AtomicU8::new(0xFF) }; MAX_PMU_COUNTERS],
            member_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            read_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize group
    pub fn init(&self, group_id: u32, leader_id: u8) {
        self.group_id.store(group_id, Ordering::Release);
        self.leader_id.store(leader_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add member
    pub fn add_member(&self, counter_id: u8) -> Result<(), HvError> {
        let count = self.member_count.load(Ordering::Acquire);
        if count as usize >= MAX_PMU_COUNTERS {
            return Err(HvError::LogicalFault);
        }
        
        self.members[count as usize].store(counter_id, Ordering::Release);
        self.member_count.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Enable group
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable group
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Record read
    pub fn record_read(&self) {
        self.read_count.fetch_add(1, Ordering::Release);
    }
}

impl Default for EventGroup {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CPU PMU State
// ─────────────────────────────────────────────────────────────────────────────

/// CPU PMU state
pub struct CpuPmuState {
    /// CPU ID
    pub cpu_id: AtomicU8,
    /// Counters
    pub counters: [PmuCounter; MAX_PMU_COUNTERS],
    /// Counter count
    pub counter_count: AtomicU8,
    /// Sampling buffer
    pub sampling_buffer: SamplingBuffer,
    /// Event groups
    pub groups: [EventGroup; MAX_EVENT_GROUPS],
    /// Group count
    pub group_count: AtomicU8,
    /// PMU version
    pub pmu_version: AtomicU8,
    /// PMU capabilities
    pub pmu_caps: AtomicU32,
    /// Fixed counters available
    pub fixed_counters: AtomicU8,
    /// Programmable counters available
    pub prog_counters: AtomicU8,
    /// Counter width (bits)
    pub counter_width: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl CpuPmuState {
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicU8::new(0),
            counters: [const { PmuCounter::new() }; MAX_PMU_COUNTERS],
            counter_count: AtomicU8::new(0),
            sampling_buffer: SamplingBuffer::new(),
            groups: [const { EventGroup::new() }; MAX_EVENT_GROUPS],
            group_count: AtomicU8::new(0),
            pmu_version: AtomicU8::new(0),
            pmu_caps: AtomicU32::new(0),
            fixed_counters: AtomicU8::new(3),
            prog_counters: AtomicU8::new(4),
            counter_width: AtomicU8::new(48),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize CPU PMU
    pub fn init(&self, cpu_id: u8, version: u8, caps: u32, fixed: u8, prog: u8, width: u8) {
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.pmu_version.store(version, Ordering::Release);
        self.pmu_caps.store(caps, Ordering::Release);
        self.fixed_counters.store(fixed, Ordering::Release);
        self.prog_counters.store(prog, Ordering::Release);
        self.counter_width.store(width, Ordering::Release);
        self.sampling_buffer.init(cpu_id as u32, cpu_id, (sampling_type::IP | sampling_type::TIME) as u16);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable PMU
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable PMU
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Create counter
    pub fn create_counter(&self, event: u16, event_mask: u8, mode: u8) -> Result<u8, HvError> {
        let count = self.counter_count.load(Ordering::Acquire);
        let max = (self.fixed_counters.load(Ordering::Acquire) + 
                   self.prog_counters.load(Ordering::Acquire)) as usize;
        
        if count as usize >= max {
            return Err(HvError::LogicalFault);
        }
        
        self.counters[count as usize].init(count, self.cpu_id.load(Ordering::Acquire), 
                                            event, event_mask, mode);
        self.counter_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get counter
    pub fn get_counter(&self, counter_id: u8) -> Option<&PmuCounter> {
        if counter_id as usize >= MAX_PMU_COUNTERS {
            return None;
        }
        
        let counter = &self.counters[counter_id as usize];
        if counter.valid.load(Ordering::Acquire) {
            Some(counter)
        } else {
            None
        }
    }

    /// Create group
    pub fn create_group(&self, leader_id: u8) -> Result<u32, HvError> {
        let count = self.group_count.load(Ordering::Acquire);
        if count as usize >= MAX_EVENT_GROUPS {
            return Err(HvError::LogicalFault);
        }
        
        let group_id = count as u32 + 1;
        self.groups[count as usize].init(group_id, leader_id);
        self.group_count.fetch_add(1, Ordering::Release);
        
        Ok(group_id)
    }

    /// Read all counters
    pub fn read_all(&self, values: &mut [u64; MAX_PMU_COUNTERS]) -> u8 {
        let count = self.counter_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            values[i] = self.counters[i].read();
        }
        
        count
    }

    /// Reset all counters
    pub fn reset_all(&self) {
        for i in 0..self.counter_count.load(Ordering::Acquire) as usize {
            self.counters[i].reset();
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> CpuPmuStats {
        let mut total_value = 0u64;
        let mut total_overflows = 0u64;
        
        for i in 0..self.counter_count.load(Ordering::Acquire) as usize {
            total_value += self.counters[i].read();
            total_overflows += self.counters[i].overflow_count.load(Ordering::Acquire);
        }
        
        CpuPmuStats {
            cpu_id: self.cpu_id.load(Ordering::Acquire),
            enabled: self.enabled.load(Ordering::Acquire),
            counter_count: self.counter_count.load(Ordering::Acquire),
            group_count: self.group_count.load(Ordering::Acquire),
            total_value,
            total_overflows,
            samples: self.sampling_buffer.entry_count.load(Ordering::Acquire),
            samples_dropped: self.sampling_buffer.dropped.load(Ordering::Acquire),
        }
    }
}

impl Default for CpuPmuState {
    fn default() -> Self {
        Self::new()
    }
}

/// CPU PMU statistics
#[repr(C)]
pub struct CpuPmuStats {
    pub cpu_id: u8,
    pub enabled: bool,
    pub counter_count: u8,
    pub group_count: u8,
    pub total_value: u64,
    pub total_overflows: u64,
    pub samples: u64,
    pub samples_dropped: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PMU Controller
// ─────────────────────────────────────────────────────────────────────────────

/// PMU controller
pub struct PmuController {
    /// CPU states
    pub cpu_states: [CpuPmuState; MAX_PMU_CPUS],
    /// CPU count
    pub cpu_count: AtomicU16,
    /// Enabled
    pub enabled: AtomicBool,
    /// Sampling enabled
    pub sampling_enabled: AtomicBool,
    /// Default sampling type
    pub default_sampling_type: AtomicU16,
    /// Default sample period
    pub default_sample_period: AtomicU64,
    /// Global enable
    pub global_enable: AtomicBool,
    /// Total counters
    pub total_counters: AtomicU64,
    /// Total samples
    pub total_samples: AtomicU64,
    /// Total overflows
    pub total_overflows: AtomicU64,
    /// Total samples dropped
    pub total_dropped: AtomicU64,
}

impl PmuController {
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { CpuPmuState::new() }; MAX_PMU_CPUS],
            cpu_count: AtomicU16::new(0),
            enabled: AtomicBool::new(false),
            sampling_enabled: AtomicBool::new(false),
            default_sampling_type: AtomicU16::new((sampling_type::IP | sampling_type::TIME) as u16),
            default_sample_period: AtomicU64::new(1000000),
            global_enable: AtomicBool::new(false),
            total_counters: AtomicU64::new(0),
            total_samples: AtomicU64::new(0),
            total_overflows: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Enable PMU
    pub fn enable(&mut self, sampling: bool, sample_period: u64) {
        self.sampling_enabled.store(sampling, Ordering::Release);
        self.default_sample_period.store(sample_period, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable PMU
    pub fn disable(&mut self) {
        self.global_enable.store(false, Ordering::Release);
        self.enabled.store(false, Ordering::Release);
    }

    /// Start global counting
    pub fn start(&self) {
        self.global_enable.store(true, Ordering::Release);
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            self.cpu_states[i].enable();
            
            for j in 0..self.cpu_states[i].counter_count.load(Ordering::Acquire) as usize {
                self.cpu_states[i].counters[j].enable();
            }
        }
    }

    /// Stop global counting
    pub fn stop(&self) {
        self.global_enable.store(false, Ordering::Release);
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            self.cpu_states[i].disable();
            
            for j in 0..self.cpu_states[i].counter_count.load(Ordering::Acquire) as usize {
                self.cpu_states[i].counters[j].disable();
            }
        }
    }

    /// Register CPU
    pub fn register_cpu(&mut self, cpu_id: u8, version: u8, caps: u32, 
                        fixed: u8, prog: u8, width: u8) -> Result<u16, HvError> {
        let count = self.cpu_count.load(Ordering::Acquire);
        if count as usize >= MAX_PMU_CPUS {
            return Err(HvError::LogicalFault);
        }
        
        self.cpu_states[count as usize].init(cpu_id, version, caps, fixed, prog, width);
        self.cpu_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get CPU state
    pub fn get_cpu_state(&self, cpu_id: u8) -> Option<&CpuPmuState> {
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            if self.cpu_states[i].cpu_id.load(Ordering::Acquire) == cpu_id {
                return Some(&self.cpu_states[i]);
            }
        }
        None
    }

    /// Create counter on CPU
    pub fn create_counter(&self, cpu_id: u8, event: u16, 
                          event_mask: u8, mode: u8) -> Result<u8, HvError> {
        let cpu_state = self.get_cpu_state(cpu_id).ok_or(HvError::LogicalFault)?;
        
        let counter_id = cpu_state.create_counter(event, event_mask, mode)?;
        
        self.total_counters.fetch_add(1, Ordering::Release);
        
        Ok(counter_id)
    }

    /// Read counter
    pub fn read_counter(&self, cpu_id: u8, counter_id: u8) -> Option<u64> {
        let cpu_state = self.get_cpu_state(cpu_id)?;
        let counter = cpu_state.get_counter(counter_id)?;
        Some(counter.read())
    }

    /// Reset counter
    pub fn reset_counter(&self, cpu_id: u8, counter_id: u8) -> Result<(), HvError> {
        let cpu_state = self.get_cpu_state(cpu_id).ok_or(HvError::LogicalFault)?;
        let counter = cpu_state.get_counter(counter_id).ok_or(HvError::LogicalFault)?;
        counter.reset();
        Ok(())
    }

    /// Handle overflow
    pub fn handle_overflow(&self, cpu_id: u8, counter_id: u8) -> Result<bool, HvError> {
        let cpu_state = self.get_cpu_state(cpu_id).ok_or(HvError::LogicalFault)?;
        let counter = cpu_state.get_counter(counter_id).ok_or(HvError::LogicalFault)?;
        
        let sample = counter.handle_overflow();
        
        self.total_overflows.fetch_add(1, Ordering::Release);
        
        if sample {
            // Take sample
            let ip = 0; // Would get actual IP
            let event = counter.event.load(Ordering::Acquire);
            let value = counter.read();
            
            if let Some(entry_id) = cpu_state.sampling_buffer.add_sample(event, ip, value) {
                self.total_samples.fetch_add(1, Ordering::Release);
            } else {
                self.total_dropped.fetch_add(1, Ordering::Release);
            }
        }
        
        Ok(sample)
    }

    /// Get sample
    pub fn get_sample(&self, cpu_id: u8) -> Option<&SampleEntry> {
        let cpu_state = self.get_cpu_state(cpu_id)?;
        cpu_state.sampling_buffer.get_sample()
    }

    /// Read all counters on CPU
    pub fn read_all_counters(&self, cpu_id: u8, values: &mut [u64; MAX_PMU_COUNTERS]) -> Option<u8> {
        let cpu_state = self.get_cpu_state(cpu_id)?;
        Some(cpu_state.read_all(values))
    }

    /// Create event group
    pub fn create_group(&self, cpu_id: u8, leader_id: u8) -> Result<u32, HvError> {
        let cpu_state = self.get_cpu_state(cpu_id).ok_or(HvError::LogicalFault)?;
        cpu_state.create_group(leader_id)
    }

    /// Get statistics
    pub fn get_stats(&self) -> PmuControllerStats {
        let mut total_counters = 0u64;
        let mut total_samples = 0u64;
        let mut total_overflows = 0u64;
        let mut total_dropped = 0u64;
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            let stats = self.cpu_states[i].get_stats();
            total_counters += stats.counter_count as u64;
            total_samples += stats.samples;
            total_overflows += stats.total_overflows;
            total_dropped += stats.samples_dropped;
        }
        
        PmuControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            global_enable: self.global_enable.load(Ordering::Acquire),
            cpu_count: self.cpu_count.load(Ordering::Acquire),
            sampling_enabled: self.sampling_enabled.load(Ordering::Acquire),
            total_counters,
            total_samples,
            total_overflows,
            total_dropped,
        }
    }
}

impl Default for PmuController {
    fn default() -> Self {
        Self::new()
    }
}

/// PMU controller statistics
#[repr(C)]
pub struct PmuControllerStats {
    pub enabled: bool,
    pub global_enable: bool,
    pub cpu_count: u16,
    pub sampling_enabled: bool,
    pub total_counters: u64,
    pub total_samples: u64,
    pub total_overflows: u64,
    pub total_dropped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_pmu() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        
        assert!(ctrl.enabled.load(Ordering::Acquire));
        assert!(ctrl.sampling_enabled.load(Ordering::Acquire));
    }

    #[test]
    fn register_cpu() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        
        let idx = ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        assert_eq!(ctrl.cpu_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn create_counter() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        
        let id = ctrl.create_counter(0, pmu_event::CPU_CYCLES, 0, counter_mode::ALL).unwrap();
        assert!(id < 8);
        
        let cpu = ctrl.get_cpu_state(0).unwrap();
        assert_eq!(cpu.counter_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn read_counter() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        let id = ctrl.create_counter(0, pmu_event::CPU_CYCLES, 0, counter_mode::ALL).unwrap();
        
        ctrl.start();
        
        // Simulate counter increment
        let cpu = ctrl.get_cpu_state(0).unwrap();
        cpu.counters[id as usize].update(1000);
        
        let value = ctrl.read_counter(0, id).unwrap();
        assert_eq!(value, 1000);
    }

    #[test]
    fn sampling() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        
        let cpu = ctrl.get_cpu_state(0).unwrap();
        
        let entry_id = cpu.sampling_buffer.add_sample(pmu_event::CPU_CYCLES, 0x1000, 1000);
        assert!(entry_id.is_some());
        
        let sample = ctrl.get_sample(0);
        assert!(sample.is_some());
        assert_eq!(sample.unwrap().event.load(Ordering::Acquire), pmu_event::CPU_CYCLES);
    }

    #[test]
    fn event_group() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        
        let id1 = ctrl.create_counter(0, pmu_event::CPU_CYCLES, 0, counter_mode::ALL).unwrap();
        let id2 = ctrl.create_counter(0, pmu_event::INSTRUCTIONS, 0, counter_mode::ALL).unwrap();
        
        let cpu = ctrl.get_cpu_state(0).unwrap();
        let group_id = cpu.create_group(id1).unwrap();
        
        cpu.groups[(group_id - 1) as usize].add_member(id2).unwrap();
        
        assert_eq!(cpu.group_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn overflow_handling() {
        let mut ctrl = PmuController::new();
        ctrl.enable(true, 1000000);
        ctrl.register_cpu(0, 4, 0xFF, 3, 4, 48).unwrap();
        let id = ctrl.create_counter(0, pmu_event::CPU_CYCLES, 0, counter_mode::ALL).unwrap();
        
        let cpu = ctrl.get_cpu_state(0).unwrap();
        cpu.counters[id as usize].set_sample_period(1000);
        
        ctrl.handle_overflow(0, id).unwrap();
        
        let counter = cpu.get_counter(id).unwrap();
        assert_eq!(counter.overflow_count.load(Ordering::Acquire), 1);
    }
}
