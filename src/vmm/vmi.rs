//! Virtual Machine Introspection (VMI)
//!
//! Secure monitoring and analysis of guest VM state without guest cooperation.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// VMI Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum VMs with VMI
#[cfg(not(test))]
pub const MAX_VMI_VMS: usize = 128;
/// Maximum VMs with VMI (reduced for tests)
#[cfg(test)]
pub const MAX_VMI_VMS: usize = 4;

/// Maximum breakpoints per VM
#[cfg(not(test))]
pub const MAX_BREAKPOINTS: usize = 256;
/// Maximum breakpoints per VM (reduced for tests)
#[cfg(test)]
pub const MAX_BREAKPOINTS: usize = 16;

/// Maximum watchpoints per VM
#[cfg(not(test))]
pub const MAX_WATCHPOINTS: usize = 64;
/// Maximum watchpoints per VM (reduced for tests)
#[cfg(test)]
pub const MAX_WATCHPOINTS: usize = 4;

/// Maximum event subscriptions
#[cfg(not(test))]
pub const MAX_EVENT_SUBS: usize = 512;
/// Maximum event subscriptions (reduced for tests)
#[cfg(test)]
pub const MAX_EVENT_SUBS: usize = 16;

/// Maximum memory regions monitored
#[cfg(not(test))]
pub const MAX_MONITORED_REGIONS: usize = 32;
/// Maximum memory regions monitored (reduced for tests)
#[cfg(test)]
pub const MAX_MONITORED_REGIONS: usize = 4;

/// Event queue size
pub const EVENT_QUEUE_SIZE: u8 = 255;

/// Page size
pub const PAGE_SIZE: u64 = 4096;

/// VMI event types
pub mod vmi_event {
    pub const NONE: u16 = 0;
    pub const VM_EXIT: u16 = 1;
    pub const CR_WRITE: u16 = 2;
    pub const MSR_ACCESS: u16 = 3;
    pub const IO_PORT: u16 = 4;
    pub const MMIO: u16 = 5;
    pub const PAGE_FAULT: u16 = 6;
    pub const BREAKPOINT: u16 = 7;
    pub const WATCHPOINT: u16 = 8;
    pub const SYSCALL: u16 = 9;
    pub const INTERRUPT: u16 = 10;
    pub const EXCEPTION: u16 = 11;
    pub const TASK_SWITCH: u16 = 12;
    pub const MEMORY_WRITE: u16 = 13;
    pub const MEMORY_EXEC: u16 = 14;
    pub const PROCESS_CREATE: u16 = 15;
    pub const PROCESS_EXIT: u16 = 16;
    pub const MODULE_LOAD: u16 = 17;
    pub const REGISTRY_ACCESS: u16 = 18;
    pub const FILE_ACCESS: u16 = 19;
    pub const NETWORK_CONNECT: u16 = 20;
}

/// Breakpoint types
pub mod bp_type {
    pub const EXECUTE: u8 = 0;
    pub const WRITE: u8 = 1;
    pub const READ: u8 = 2;
    pub const ACCESS: u8 = 3;
}

/// Watchpoint sizes
pub mod wp_size {
    pub const BYTE: u8 = 1;
    pub const WORD: u8 = 2;
    pub const DWORD: u8 = 4;
    pub const QWORD: u8 = 8;
}

/// VMI states
pub mod vmi_state {
    pub const DISABLED: u8 = 0;
    pub const ENABLED: u8 = 1;
    pub const ACTIVE: u8 = 2;
    pub const PAUSED: u8 = 3;
    pub const ERROR: u8 = 4;
}

// ─────────────────────────────────────────────────────────────────────────────
// VMI Event
// ─────────────────────────────────────────────────────────────────────────────

/// VMI event structure
pub struct VmiEvent {
    /// Event ID
    pub event_id: AtomicU32,
    /// Event type
    pub event_type: AtomicU16,
    /// VM ID
    pub vm_id: AtomicU32,
    /// vCPU ID
    pub vcpu_id: AtomicU8,
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Guest virtual address
    pub gva: AtomicU64,
    /// Value (for register/memory)
    pub value: AtomicU64,
    /// Old value (for writes)
    pub old_value: AtomicU64,
    /// Timestamp
    pub timestamp: AtomicU64,
    /// Flags
    pub flags: AtomicU32,
    /// Process ID (if known)
    pub pid: AtomicU32,
    /// Thread ID (if known)
    pub tid: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl VmiEvent {
    pub const fn new() -> Self {
        Self {
            event_id: AtomicU32::new(0),
            event_type: AtomicU16::new(vmi_event::NONE),
            vm_id: AtomicU32::new(0),
            vcpu_id: AtomicU8::new(0),
            gpa: AtomicU64::new(0),
            gva: AtomicU64::new(0),
            value: AtomicU64::new(0),
            old_value: AtomicU64::new(0),
            timestamp: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            pid: AtomicU32::new(0),
            tid: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize event
    pub fn init(&self, event_id: u32, event_type: u16, vm_id: u32, vcpu_id: u8) {
        self.event_id.store(event_id, Ordering::Release);
        self.event_type.store(event_type, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.vcpu_id.store(vcpu_id, Ordering::Release);
        self.timestamp.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set address info
    pub fn set_address(&self, gpa: u64, gva: u64) {
        self.gpa.store(gpa, Ordering::Release);
        self.gva.store(gva, Ordering::Release);
    }

    /// Set value
    pub fn set_value(&self, value: u64, old_value: u64) {
        self.value.store(value, Ordering::Release);
        self.old_value.store(old_value, Ordering::Release);
    }

    /// Set process info
    pub fn set_process(&self, pid: u32, tid: u32) {
        self.pid.store(pid, Ordering::Release);
        self.tid.store(tid, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VmiEvent {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Breakpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Breakpoint structure
pub struct Breakpoint {
    /// Breakpoint ID
    pub bp_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Guest virtual address
    pub gva: AtomicU64,
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Type
    pub bp_type: AtomicU8,
    /// Size (for data breakpoints)
    pub size: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Hit count
    pub hit_count: AtomicU64,
    /// Last hit time
    pub last_hit: AtomicU64,
    /// Condition (simple expression hash)
    pub condition: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl Breakpoint {
    pub const fn new() -> Self {
        Self {
            bp_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            gva: AtomicU64::new(0),
            gpa: AtomicU64::new(0),
            bp_type: AtomicU8::new(bp_type::EXECUTE),
            size: AtomicU8::new(1),
            enabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
            last_hit: AtomicU64::new(0),
            condition: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize breakpoint
    pub fn init(&self, bp_id: u32, vm_id: u32, gva: u64, gpa: u64, bp_type: u8, size: u8) {
        self.bp_id.store(bp_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.gva.store(gva, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.bp_type.store(bp_type, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable breakpoint
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable breakpoint
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Record hit
    pub fn record_hit(&self) {
        self.hit_count.fetch_add(1, Ordering::Release);
        self.last_hit.store(Self::get_timestamp(), Ordering::Release);
    }

    /// Set condition
    pub fn set_condition(&self, condition: u64) {
        self.condition.store(condition, Ordering::Release);
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for Breakpoint {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Watchpoint
// ─────────────────────────────────────────────────────────────────────────────

/// Watchpoint structure
pub struct Watchpoint {
    /// Watchpoint ID
    pub wp_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Start GPA
    pub gpa_start: AtomicU64,
    /// Size in bytes
    pub size: AtomicU32,
    /// Access type mask
    pub access_mask: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Hit count
    pub hit_count: AtomicU64,
    /// Write count
    pub write_count: AtomicU64,
    /// Read count
    pub read_count: AtomicU64,
    /// Exec count
    pub exec_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl Watchpoint {
    pub const fn new() -> Self {
        Self {
            wp_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            gpa_start: AtomicU64::new(0),
            size: AtomicU32::new(0),
            access_mask: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            read_count: AtomicU64::new(0),
            exec_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize watchpoint
    pub fn init(&self, wp_id: u32, vm_id: u32, gpa_start: u64, size: u32, access_mask: u8) {
        self.wp_id.store(wp_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.gpa_start.store(gpa_start, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.access_mask.store(access_mask, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self, access_type: u8) {
        self.hit_count.fetch_add(1, Ordering::Release);
        
        match access_type {
            bp_type::WRITE => self.write_count.fetch_add(1, Ordering::Release),
            bp_type::READ => self.read_count.fetch_add(1, Ordering::Release),
            bp_type::EXECUTE => self.exec_count.fetch_add(1, Ordering::Release),
            _ => 0,
        };
    }

    /// Check if address is in range
    pub fn contains(&self, gpa: u64) -> bool {
        let start = self.gpa_start.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        gpa >= start && gpa < start + size as u64
    }
}

impl Default for Watchpoint {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Event Subscription
// ─────────────────────────────────────────────────────────────────────────────

/// Event subscription
pub struct EventSubscription {
    /// Subscription ID
    pub sub_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Event type mask
    pub event_mask: AtomicU32,
    /// Callback ID
    pub callback_id: AtomicU32,
    /// Priority
    pub priority: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Event count
    pub event_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl EventSubscription {
    pub const fn new() -> Self {
        Self {
            sub_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            event_mask: AtomicU32::new(0),
            callback_id: AtomicU32::new(0),
            priority: AtomicU8::new(128),
            enabled: AtomicBool::new(false),
            event_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize subscription
    pub fn init(&self, sub_id: u32, vm_id: u32, event_mask: u32, callback_id: u32, priority: u8) {
        self.sub_id.store(sub_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.event_mask.store(event_mask, Ordering::Release);
        self.callback_id.store(callback_id, Ordering::Release);
        self.priority.store(priority, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check if event matches
    pub fn matches(&self, event_type: u16) -> bool {
        self.event_mask.load(Ordering::Acquire) & (1 << event_type) != 0
    }

    /// Record event
    pub fn record_event(&self) {
        self.event_count.fetch_add(1, Ordering::Release);
    }
}

impl Default for EventSubscription {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Monitored Memory Region
// ─────────────────────────────────────────────────────────────────────────────

/// Monitored memory region
pub struct MonitoredRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Start GPA
    pub gpa_start: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Access type mask
    pub access_mask: AtomicU8,
    /// Read count
    pub read_count: AtomicU64,
    /// Write count
    pub write_count: AtomicU64,
    /// Execute count
    pub exec_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl MonitoredRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            gpa_start: AtomicU64::new(0),
            size: AtomicU64::new(0),
            access_mask: AtomicU8::new(0),
            read_count: AtomicU64::new(0),
            write_count: AtomicU64::new(0),
            exec_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, gpa_start: u64, size: u64, access_mask: u8) {
        self.region_id.store(region_id, Ordering::Release);
        self.gpa_start.store(gpa_start, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.access_mask.store(access_mask, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Check if address is in range
    pub fn contains(&self, gpa: u64) -> bool {
        let start = self.gpa_start.load(Ordering::Acquire);
        let size = self.size.load(Ordering::Acquire);
        
        gpa >= start && gpa < start + size
    }

    /// Record access
    pub fn record_access(&self, access_type: u8) {
        match access_type {
            bp_type::READ => self.read_count.fetch_add(1, Ordering::Release),
            bp_type::WRITE => self.write_count.fetch_add(1, Ordering::Release),
            bp_type::EXECUTE => self.exec_count.fetch_add(1, Ordering::Release),
            _ => 0,
        };
    }
}

impl Default for MonitoredRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM VMI State
// ─────────────────────────────────────────────────────────────────────────────

/// VM VMI state
pub struct VmVmiState {
    /// VM ID
    pub vm_id: AtomicU32,
    /// State
    pub state: AtomicU8,
    /// Breakpoints
    pub breakpoints: [Breakpoint; MAX_BREAKPOINTS],
    /// Breakpoint count
    pub bp_count: AtomicU16,
    /// Watchpoints
    pub watchpoints: [Watchpoint; MAX_WATCHPOINTS],
    /// Watchpoint count
    pub wp_count: AtomicU8,
    /// Monitored regions
    pub regions: [MonitoredRegion; MAX_MONITORED_REGIONS],
    /// Region count
    pub region_count: AtomicU8,
    /// Event subscriptions
    pub subscriptions: [EventSubscription; MAX_EVENT_SUBS],
    /// Subscription count
    pub sub_count: AtomicU16,
    /// Event queue (circular buffer)
    pub event_queue: [VmiEvent; 256],
    /// Event queue head
    pub event_head: AtomicU8,
    /// Event queue tail
    pub event_tail: AtomicU8,
    /// Event count
    pub event_count: AtomicU32,
    /// Events processed
    pub events_processed: AtomicU64,
    /// Events dropped
    pub events_dropped: AtomicU64,
    /// Breakpoint hits
    pub bp_hits: AtomicU64,
    /// Watchpoint hits
    pub wp_hits: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmVmiState {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            state: AtomicU8::new(vmi_state::DISABLED),
            breakpoints: [const { Breakpoint::new() }; MAX_BREAKPOINTS],
            bp_count: AtomicU16::new(0),
            watchpoints: [const { Watchpoint::new() }; MAX_WATCHPOINTS],
            wp_count: AtomicU8::new(0),
            regions: [const { MonitoredRegion::new() }; MAX_MONITORED_REGIONS],
            region_count: AtomicU8::new(0),
            subscriptions: [const { EventSubscription::new() }; MAX_EVENT_SUBS],
            sub_count: AtomicU16::new(0),
            event_queue: [const { VmiEvent::new() }; 256],
            event_head: AtomicU8::new(0),
            event_tail: AtomicU8::new(0),
            event_count: AtomicU32::new(0),
            events_processed: AtomicU64::new(0),
            events_dropped: AtomicU64::new(0),
            bp_hits: AtomicU64::new(0),
            wp_hits: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize VMI state
    pub fn init(&self, vm_id: u32) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.state.store(vmi_state::ENABLED, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable VMI
    pub fn enable(&self) {
        self.state.store(vmi_state::ACTIVE, Ordering::Release);
    }

    /// Disable VMI
    pub fn disable(&self) {
        self.state.store(vmi_state::DISABLED, Ordering::Release);
    }

    /// Add breakpoint
    pub fn add_breakpoint(&self, gva: u64, gpa: u64, bp_type: u8, size: u8) -> Result<u32, HvError> {
        let count = self.bp_count.load(Ordering::Acquire);
        if count as usize >= MAX_BREAKPOINTS {
            return Err(HvError::LogicalFault);
        }
        
        let bp_id = count as u32 + 1;
        self.breakpoints[count as usize].init(bp_id, self.vm_id.load(Ordering::Acquire), 
                                               gva, gpa, bp_type, size);
        self.bp_count.fetch_add(1, Ordering::Release);
        
        Ok(bp_id)
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&self, bp_id: u32) -> Result<(), HvError> {
        for i in 0..self.bp_count.load(Ordering::Acquire) as usize {
            if self.breakpoints[i].bp_id.load(Ordering::Acquire) == bp_id {
                self.breakpoints[i].valid.store(false, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Add watchpoint
    pub fn add_watchpoint(&self, gpa_start: u64, size: u32, access_mask: u8) -> Result<u32, HvError> {
        let count = self.wp_count.load(Ordering::Acquire);
        if count as usize >= MAX_WATCHPOINTS {
            return Err(HvError::LogicalFault);
        }
        
        let wp_id = count as u32 + 1;
        self.watchpoints[count as usize].init(wp_id, self.vm_id.load(Ordering::Acquire),
                                               gpa_start, size, access_mask);
        self.wp_count.fetch_add(1, Ordering::Release);
        
        Ok(wp_id)
    }

    /// Add monitored region
    pub fn add_region(&self, gpa_start: u64, size: u64, access_mask: u8) -> Result<u8, HvError> {
        let count = self.region_count.load(Ordering::Acquire);
        if count as usize >= MAX_MONITORED_REGIONS {
            return Err(HvError::LogicalFault);
        }
        
        self.regions[count as usize].init(count, gpa_start, size, access_mask);
        self.region_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Subscribe to events
    pub fn subscribe(&self, event_mask: u32, callback_id: u32, priority: u8) -> Result<u32, HvError> {
        let count = self.sub_count.load(Ordering::Acquire);
        if count as usize >= MAX_EVENT_SUBS {
            return Err(HvError::LogicalFault);
        }
        
        let sub_id = count as u32 + 1;
        self.subscriptions[count as usize].init(sub_id, self.vm_id.load(Ordering::Acquire),
                                                 event_mask, callback_id, priority);
        self.sub_count.fetch_add(1, Ordering::Release);
        
        Ok(sub_id)
    }

    /// Queue event
    pub fn queue_event(&self, event_type: u16, vcpu_id: u8, gpa: u64, gva: u64) -> Result<(), HvError> {
        let head = self.event_head.load(Ordering::Acquire);
        let tail = self.event_tail.load(Ordering::Acquire);
        
        // Check if queue is full
        let next_head = (head + 1) % EVENT_QUEUE_SIZE;
        if next_head == tail {
            self.events_dropped.fetch_add(1, Ordering::Release);
            return Err(HvError::LogicalFault);
        }
        
        let event = &self.event_queue[head as usize];
        event.init(self.event_count.fetch_add(1, Ordering::Release), event_type, 
                   self.vm_id.load(Ordering::Acquire), vcpu_id);
        event.set_address(gpa, gva);
        
        self.event_head.store(next_head, Ordering::Release);
        
        Ok(())
    }

    /// Dequeue event
    pub fn dequeue_event(&self) -> Option<&VmiEvent> {
        let head = self.event_head.load(Ordering::Acquire);
        let tail = self.event_tail.load(Ordering::Acquire);
        
        if head == tail {
            return None;
        }
        
        let event = &self.event_queue[tail as usize];
        self.event_tail.store((tail + 1) % EVENT_QUEUE_SIZE, Ordering::Release);
        self.events_processed.fetch_add(1, Ordering::Release);
        
        Some(event)
    }

    /// Check breakpoint hit
    pub fn check_breakpoint(&self, gpa: u64, access_type: u8) -> Option<&Breakpoint> {
        for i in 0..self.bp_count.load(Ordering::Acquire) as usize {
            let bp = &self.breakpoints[i];
            if bp.valid.load(Ordering::Acquire) && 
               bp.enabled.load(Ordering::Acquire) &&
               bp.gpa.load(Ordering::Acquire) == gpa &&
               bp.bp_type.load(Ordering::Acquire) == access_type {
                bp.record_hit();
                self.bp_hits.fetch_add(1, Ordering::Release);
                return Some(bp);
            }
        }
        None
    }

    /// Check watchpoint hit
    pub fn check_watchpoint(&self, gpa: u64, access_type: u8) -> Option<&Watchpoint> {
        for i in 0..self.wp_count.load(Ordering::Acquire) as usize {
            let wp = &self.watchpoints[i];
            if wp.valid.load(Ordering::Acquire) &&
               wp.enabled.load(Ordering::Acquire) &&
               wp.contains(gpa) &&
               (wp.access_mask.load(Ordering::Acquire) & (1 << access_type)) != 0 {
                wp.record_access(access_type);
                self.wp_hits.fetch_add(1, Ordering::Release);
                return Some(wp);
            }
        }
        None
    }

    /// Check monitored region
    pub fn check_region(&self, gpa: u64, access_type: u8) -> Option<&MonitoredRegion> {
        for i in 0..self.region_count.load(Ordering::Acquire) as usize {
            let region = &self.regions[i];
            if region.valid.load(Ordering::Acquire) &&
               region.contains(gpa) &&
               (region.access_mask.load(Ordering::Acquire) & (1 << access_type)) != 0 {
                region.record_access(access_type);
                return Some(region);
            }
        }
        None
    }

    /// Get statistics
    pub fn get_stats(&self) -> VmiStats {
        VmiStats {
            vm_id: self.vm_id.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            bp_count: self.bp_count.load(Ordering::Acquire),
            wp_count: self.wp_count.load(Ordering::Acquire),
            region_count: self.region_count.load(Ordering::Acquire),
            sub_count: self.sub_count.load(Ordering::Acquire),
            events_processed: self.events_processed.load(Ordering::Acquire),
            events_dropped: self.events_dropped.load(Ordering::Acquire),
            bp_hits: self.bp_hits.load(Ordering::Acquire),
            wp_hits: self.wp_hits.load(Ordering::Acquire),
        }
    }
}

impl Default for VmVmiState {
    fn default() -> Self {
        Self::new()
    }
}

/// VMI statistics
#[repr(C)]
pub struct VmiStats {
    pub vm_id: u32,
    pub state: u8,
    pub bp_count: u16,
    pub wp_count: u8,
    pub region_count: u8,
    pub sub_count: u16,
    pub events_processed: u64,
    pub events_dropped: u64,
    pub bp_hits: u64,
    pub wp_hits: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// VMI Controller
// ─────────────────────────────────────────────────────────────────────────────

/// VMI controller
pub struct VmiController {
    /// VM states
    pub vm_states: [VmVmiState; MAX_VMI_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Max breakpoints per VM
    pub max_bp: AtomicU16,
    /// Max watchpoints per VM
    pub max_wp: AtomicU8,
    /// Max event queue size
    pub max_event_queue: AtomicU16,
    /// Event coalescing enabled
    pub event_coalescing: AtomicBool,
    /// Total VMs monitored
    pub total_vms: AtomicU64,
    /// Total events
    pub total_events: AtomicU64,
    /// Total events processed
    pub total_processed: AtomicU64,
    /// Total events dropped
    pub total_dropped: AtomicU64,
    /// Total breakpoint hits
    pub total_bp_hits: AtomicU64,
    /// Total watchpoint hits
    pub total_wp_hits: AtomicU64,
}

impl VmiController {
    pub const fn new() -> Self {
        Self {
            vm_states: [const { VmVmiState::new() }; MAX_VMI_VMS],
            vm_count: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            max_bp: AtomicU16::new(MAX_BREAKPOINTS as u16),
            max_wp: AtomicU8::new(MAX_WATCHPOINTS as u8),
            max_event_queue: AtomicU16::new(256),
            event_coalescing: AtomicBool::new(true),
            total_vms: AtomicU64::new(0),
            total_events: AtomicU64::new(0),
            total_processed: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
            total_bp_hits: AtomicU64::new(0),
            total_wp_hits: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, coalescing: bool) {
        self.event_coalescing.store(coalescing, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register VM
    pub fn register_vm(&mut self, vm_id: u32) -> Result<u8, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_VMI_VMS {
            return Err(HvError::LogicalFault);
        }
        
        self.vm_states[count as usize].init(vm_id);
        
        self.vm_count.fetch_add(1, Ordering::Release);
        self.total_vms.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get VM state
    pub fn get_vm_state(&self, vm_id: u32) -> Option<&VmVmiState> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_states[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_states[i]);
            }
        }
        None
    }

    /// Enable VMI for VM
    pub fn enable_vmi(&self, vm_id: u32) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.enable();
        Ok(())
    }

    /// Disable VMI for VM
    pub fn disable_vmi(&self, vm_id: u32) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.disable();
        Ok(())
    }

    /// Add breakpoint
    pub fn add_breakpoint(&self, vm_id: u32, gva: u64, gpa: u64, 
                          bp_type: u8, size: u8) -> Result<u32, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.add_breakpoint(gva, gpa, bp_type, size)
    }

    /// Add watchpoint
    pub fn add_watchpoint(&self, vm_id: u32, gpa_start: u64, 
                          size: u32, access_mask: u8) -> Result<u32, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.add_watchpoint(gpa_start, size, access_mask)
    }

    /// Add monitored region
    pub fn add_region(&self, vm_id: u32, gpa_start: u64, 
                      size: u64, access_mask: u8) -> Result<u8, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.add_region(gpa_start, size, access_mask)
    }

    /// Subscribe to events
    pub fn subscribe(&self, vm_id: u32, event_mask: u32, 
                     callback_id: u32, priority: u8) -> Result<u32, HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        vm_state.subscribe(event_mask, callback_id, priority)
    }

    /// Handle memory access
    pub fn handle_mem_access(&self, vm_id: u32, gpa: u64, 
                              gva: u64, access_type: u8, vcpu_id: u8) -> Option<u16> {
        let vm_state = self.get_vm_state(vm_id)?;
        
        if vm_state.state.load(Ordering::Acquire) != vmi_state::ACTIVE {
            return None;
        }
        
        // Check breakpoint
        if vm_state.check_breakpoint(gpa, access_type).is_some() {
            self.total_bp_hits.fetch_add(1, Ordering::Release);
            return Some(vmi_event::BREAKPOINT);
        }
        
        // Check watchpoint
        if vm_state.check_watchpoint(gpa, access_type).is_some() {
            self.total_wp_hits.fetch_add(1, Ordering::Release);
            return Some(vmi_event::WATCHPOINT);
        }
        
        // Check monitored region
        vm_state.check_region(gpa, access_type);
        
        None
    }

    /// Queue event
    pub fn queue_event(&self, vm_id: u32, event_type: u16, 
                       vcpu_id: u8, gpa: u64, gva: u64) -> Result<(), HvError> {
        let vm_state = self.get_vm_state(vm_id).ok_or(HvError::LogicalFault)?;
        
        vm_state.queue_event(event_type, vcpu_id, gpa, gva)?;
        
        self.total_events.fetch_add(1, Ordering::Release);
        
        Ok(())
    }

    /// Process events
    pub fn process_events(&self, vm_id: u32, max_events: u32) -> u32 {
        let vm_state = match self.get_vm_state(vm_id) {
            Some(s) => s,
            None => return 0,
        };
        
        let mut processed = 0u32;
        
        while processed < max_events {
            if let Some(event) = vm_state.dequeue_event() {
                // Notify subscribers
                for i in 0..vm_state.sub_count.load(Ordering::Acquire) as usize {
                    let sub = &vm_state.subscriptions[i];
                    if sub.valid.load(Ordering::Acquire) &&
                       sub.enabled.load(Ordering::Acquire) &&
                       sub.matches(event.event_type.load(Ordering::Acquire)) {
                        sub.record_event();
                    }
                }
                
                processed += 1;
            } else {
                break;
            }
        }
        
        self.total_processed.fetch_add(processed as u64, Ordering::Release);
        processed
    }

    /// Get statistics
    pub fn get_stats(&self) -> VmiControllerStats {
        VmiControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            total_vms: self.total_vms.load(Ordering::Acquire),
            total_events: self.total_events.load(Ordering::Acquire),
            total_processed: self.total_processed.load(Ordering::Acquire),
            total_dropped: self.total_dropped.load(Ordering::Acquire),
            total_bp_hits: self.total_bp_hits.load(Ordering::Acquire),
            total_wp_hits: self.total_wp_hits.load(Ordering::Acquire),
        }
    }
}

impl Default for VmiController {
    fn default() -> Self {
        Self::new()
    }
}

/// VMI controller statistics
#[repr(C)]
pub struct VmiControllerStats {
    pub enabled: bool,
    pub vm_count: u8,
    pub total_vms: u64,
    pub total_events: u64,
    pub total_processed: u64,
    pub total_dropped: u64,
    pub total_bp_hits: u64,
    pub total_wp_hits: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_vm() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        
        let idx = ctrl.register_vm(1).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn add_breakpoint() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        
        let bp_id = ctrl.add_breakpoint(1, 0x1000, 0x2000, bp_type::EXECUTE, 1).unwrap();
        assert!(bp_id > 0);
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.bp_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn breakpoint_hit() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        ctrl.add_breakpoint(1, 0x1000, 0x2000, bp_type::EXECUTE, 1).unwrap();
        
        let event = ctrl.handle_mem_access(1, 0x2000, 0x1000, bp_type::EXECUTE, 0);
        assert_eq!(event, Some(vmi_event::BREAKPOINT));
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.bp_hits.load(Ordering::Acquire), 1);
    }

    #[test]
    fn watchpoint_hit() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        ctrl.add_watchpoint(1, 0x2000, 4096, (1 << bp_type::WRITE) | (1 << bp_type::READ)).unwrap();
        
        let event = ctrl.handle_mem_access(1, 0x2000, 0x1000, bp_type::WRITE, 0);
        assert_eq!(event, Some(vmi_event::WATCHPOINT));
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.wp_hits.load(Ordering::Acquire), 1);
    }

    #[test]
    fn event_queue() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        
        ctrl.queue_event(1, vmi_event::CR_WRITE, 0, 0x1000, 0).unwrap();
        ctrl.queue_event(1, vmi_event::MSR_ACCESS, 0, 0x2000, 0).unwrap();
        
        let vm = ctrl.get_vm_state(1).unwrap();
        assert_eq!(vm.event_count.load(Ordering::Acquire), 2);
        
        let processed = ctrl.process_events(1, 10);
        assert_eq!(processed, 2);
    }

    #[test]
    fn event_subscription() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        
        // Subscribe to CR writes and MSR accesses
        let mask = (1 << vmi_event::CR_WRITE) | (1 << vmi_event::MSR_ACCESS);
        let sub_id = ctrl.subscribe(1, mask, 1, 128).unwrap();
        
        ctrl.queue_event(1, vmi_event::CR_WRITE, 0, 0x1000, 0).unwrap();
        ctrl.process_events(1, 10);
        
        let vm = ctrl.get_vm_state(1).unwrap();
        let sub = &vm.subscriptions[0];
        assert_eq!(sub.event_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn monitored_region() {
        let mut ctrl = VmiController::new();
        ctrl.enable(true);
        ctrl.register_vm(1).unwrap();
        ctrl.enable_vmi(1).unwrap();
        // Region: [0x1000000, 0x1001000) - size 4096
        ctrl.add_region(1, 0x1000000, 4096, (1 << bp_type::WRITE)).unwrap();
        
        // Access within the region (0x1000FFF is last byte in range)
        ctrl.handle_mem_access(1, 0x1000FFF, 0, bp_type::WRITE, 0);
        
        let vm = ctrl.get_vm_state(1).unwrap();
        let region = &vm.regions[0];
        assert_eq!(region.write_count.load(Ordering::Acquire), 1);
    }
}
