//! Debug and Profiling Support
//!
//! GDB stub for remote debugging and performance counters.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, AtomicPtr, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// GDB Stub Constants
// ─────────────────────────────────────────────────────────────────────────────

/// GDB packet markers
pub const GDB_PACKET_START: u8 = b'$';
pub const GDB_PACKET_END: u8 = b'#';
pub const GDB_ACK: u8 = b'+';
pub const GDB_NACK: u8 = b'-';
pub const GDB_ESCAPE: u8 = b'}';
pub const GDB_RUNLEN_START: u8 = b'*';

/// GDB commands
pub mod gdb_cmd {
    pub const CONTINUE: u8 = b'c';
    pub const STEP: u8 = b's';
    pub const READ_REGS: u8 = b'g';
    pub const WRITE_REGS: u8 = b'G';
    pub const READ_MEM: u8 = b'm';
    pub const WRITE_MEM: u8 = b'M';
    pub const READ_REG: u8 = b'p';
    pub const WRITE_REG: u8 = b'P';
    pub const SET_BREAKPOINT: u8 = b'Z';
    pub const REMOVE_BREAKPOINT: u8 = b'z';
    pub const KILL: u8 = b'k';
    pub const DETACH: u8 = b'D';
    pub const QUERY: u8 = b'q';
    pub const SET_VAR: u8 = b'Q';
    pub const THREAD_INFO: u8 = b'H';
    pub const THREAD_ALIVE: u8 = b'T';
    pub const VCONT: u8 = b'v';
}

/// Breakpoint types
pub mod bp_type {
    pub const SOFTWARE: u8 = 0;
    pub const HARDWARE: u8 = 1;
    pub const WRITE_WATCH: u8 = 2;
    pub const READ_WATCH: u8 = 3;
    pub const ACCESS_WATCH: u8 = 4;
}

/// Maximum breakpoints
pub const MAX_BREAKPOINTS: usize = 32;
/// Maximum watchpoints
pub const MAX_WATCHPOINTS: usize = 8;
/// GDB buffer size
pub const GDB_BUFFER_SIZE: usize = 4096;

// ─────────────────────────────────────────────────────────────────────────────
// Breakpoint Management
// ─────────────────────────────────────────────────────────────────────────────

/// Breakpoint entry
pub struct Breakpoint {
    /// Address (GPA or RIP)
    pub addr: AtomicU64,
    /// Breakpoint type
    pub bp_type: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Hit count
    pub hit_count: AtomicU64,
    /// Original instruction (for software BP)
    pub orig_insn: AtomicU8,
    /// Condition (simplified - would be expression)
    pub condition: AtomicU64,
}

impl Breakpoint {
    pub const fn new() -> Self {
        Self {
            addr: AtomicU64::new(0),
            bp_type: AtomicU8::new(bp_type::SOFTWARE),
            enabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
            orig_insn: AtomicU8::new(0),
            condition: AtomicU64::new(0),
        }
    }
}

/// Watchpoint entry
pub struct Watchpoint {
    /// Address
    pub addr: AtomicU64,
    /// Size (1, 2, 4, 8 bytes)
    pub size: AtomicU8,
    /// Access type (read/write/both)
    pub access: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Hit count
    pub hit_count: AtomicU64,
}

impl Watchpoint {
    pub const fn new() -> Self {
        Self {
            addr: AtomicU64::new(0),
            size: AtomicU8::new(4),
            access: AtomicU8::new(3), // read+write
            enabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GDB Register Definitions
// ─────────────────────────────────────────────────────────────────────────────

/// x86-64 GDB register indices
pub mod reg {
    pub const RAX: usize = 0;
    pub const RBX: usize = 1;
    pub const RCX: usize = 2;
    pub const RDX: usize = 3;
    pub const RSI: usize = 4;
    pub const RDI: usize = 5;
    pub const RBP: usize = 6;
    pub const RSP: usize = 7;
    pub const R8: usize = 8;
    pub const R9: usize = 9;
    pub const R10: usize = 10;
    pub const R11: usize = 11;
    pub const R12: usize = 12;
    pub const R13: usize = 13;
    pub const R14: usize = 14;
    pub const R15: usize = 15;
    pub const RIP: usize = 16;
    pub const RFLAGS: usize = 17;
    pub const CS: usize = 18;
    pub const SS: usize = 19;
    pub const DS: usize = 20;
    pub const ES: usize = 21;
    pub const FS: usize = 22;
    pub const GS: usize = 23;
    pub const FS_BASE: usize = 24;
    pub const GS_BASE: usize = 25;
    pub const COUNT: usize = 26;
}

/// Register value (64-bit max)
pub union RegValue {
    pub u64: u64,
    pub u32: u32,
    pub u16: u16,
    pub u8: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// GDB Stub State
// ─────────────────────────────────────────────────────────────────────────────

/// GDB stub state
pub struct GdbStubState {
    /// Connected
    pub connected: AtomicBool,
    /// Debugging active
    pub active: AtomicBool,
    /// Current vCPU being debugged
    pub current_vcpu: AtomicU16,
    /// Breakpoints
    pub breakpoints: [Breakpoint; MAX_BREAKPOINTS],
    /// Watchpoints
    pub watchpoints: [Watchpoint; MAX_WATCHPOINTS],
    /// Rx buffer
    pub rx_buffer: [AtomicU8; GDB_BUFFER_SIZE],
    /// Rx length
    pub rx_len: AtomicU32,
    /// Tx buffer
    pub tx_buffer: [AtomicU8; GDB_BUFFER_SIZE],
    /// Tx length
    pub tx_len: AtomicU32,
    /// Pending signal
    pub pending_signal: AtomicU8,
    /// Stop reason
    pub stop_reason: AtomicU8,
    /// Single-step mode
    pub single_step: AtomicBool,
    /// Thread ID for operations
    pub thread_id: AtomicU32,
    /// Features supported
    pub features: AtomicU32,
    /// Packet checksum
    pub checksum: AtomicU8,
}

impl GdbStubState {
    pub const fn new() -> Self {
        Self {
            connected: AtomicBool::new(false),
            active: AtomicBool::new(false),
            current_vcpu: AtomicU16::new(0),
            breakpoints: [const { Breakpoint::new() }; MAX_BREAKPOINTS],
            watchpoints: [const { Watchpoint::new() }; MAX_WATCHPOINTS],
            rx_buffer: [const { AtomicU8::new(0) }; GDB_BUFFER_SIZE],
            rx_len: AtomicU32::new(0),
            tx_buffer: [const { AtomicU8::new(0) }; GDB_BUFFER_SIZE],
            tx_len: AtomicU32::new(0),
            pending_signal: AtomicU8::new(0),
            stop_reason: AtomicU8::new(0),
            single_step: AtomicBool::new(false),
            thread_id: AtomicU32::new(0),
            features: AtomicU32::new(0),
            checksum: AtomicU8::new(0),
        }
    }

    /// Set software breakpoint
    pub fn set_breakpoint(&self, addr: u64, bp_type: u8) -> Result<u32, HvError> {
        if bp_type != bp_type::SOFTWARE {
            return Err(HvError::LogicalFault);
        }
        
        // Find free slot
        for i in 0..MAX_BREAKPOINTS {
            let bp = &self.breakpoints[i];
            if !bp.enabled.load(Ordering::Acquire) {
                bp.addr.store(addr, Ordering::Release);
                bp.bp_type.store(bp_type, Ordering::Release);
                bp.enabled.store(true, Ordering::Release);
                bp.hit_count.store(0, Ordering::Release);
                return Ok(i as u32);
            }
        }
        
        Err(HvError::LogicalFault)
    }

    /// Remove breakpoint
    pub fn remove_breakpoint(&self, addr: u64, bp_type: u8) -> Result<(), HvError> {
        for i in 0..MAX_BREAKPOINTS {
            let bp = &self.breakpoints[i];
            if bp.addr.load(Ordering::Acquire) == addr &&
               bp.bp_type.load(Ordering::Acquire) == bp_type &&
               bp.enabled.load(Ordering::Acquire) {
                bp.enabled.store(false, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Set watchpoint
    pub fn set_watchpoint(&self, addr: u64, size: u8, access: u8) -> Result<u32, HvError> {
        for i in 0..MAX_WATCHPOINTS {
            let wp = &self.watchpoints[i];
            if !wp.enabled.load(Ordering::Acquire) {
                wp.addr.store(addr, Ordering::Release);
                wp.size.store(size, Ordering::Release);
                wp.access.store(access, Ordering::Release);
                wp.enabled.store(true, Ordering::Release);
                return Ok(i as u32);
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Check if address has breakpoint
    pub fn check_breakpoint(&self, rip: u64) -> bool {
        for bp in &self.breakpoints {
            if bp.enabled.load(Ordering::Acquire) &&
               bp.addr.load(Ordering::Acquire) == rip {
                bp.hit_count.fetch_add(1, Ordering::Release);
                return true;
            }
        }
        false
    }

    /// Check watchpoint hit
    pub fn check_watchpoint(&self, addr: u64, size: u8, is_write: bool) -> Option<u64> {
        for wp in &self.watchpoints {
            if !wp.enabled.load(Ordering::Acquire) {
                continue;
            }
            
            let wp_addr = wp.addr.load(Ordering::Acquire);
            let wp_size = wp.size.load(Ordering::Acquire);
            let wp_access = wp.access.load(Ordering::Acquire);
            
            // Check overlap
            if addr >= wp_addr && addr < wp_addr + wp_size as u64 {
                let access_ok = if is_write {
                    (wp_access & 2) != 0 // write
                } else {
                    (wp_access & 1) != 0 // read
                };
                
                if access_ok {
                    wp.hit_count.fetch_add(1, Ordering::Release);
                    return Some(wp_addr);
                }
            }
        }
        None
    }

    /// Process received packet
    pub fn process_packet(&mut self) -> Result<(), HvError> {
        let len = self.rx_len.load(Ordering::Acquire) as usize;
        if len == 0 {
            return Ok(());
        }
        
        // Verify checksum
        let data_end = len - 3; // Before #XX
        let mut calc_sum = 0u8;
        for i in 0..data_end {
            calc_sum = calc_sum.wrapping_add(self.rx_buffer[i].load(Ordering::Acquire));
        }
        
        let recv_sum = Self::parse_hex_byte(
            self.rx_buffer[data_end + 1].load(Ordering::Acquire),
            self.rx_buffer[data_end + 2].load(Ordering::Acquire),
        );
        
        if calc_sum != recv_sum {
            self.send_nack();
            return Err(HvError::LogicalFault);
        }
        
        self.send_ack();
        
        // Process command
        let cmd = self.rx_buffer[0].load(Ordering::Acquire);
        self.handle_command(cmd)?;
        
        Ok(())
    }

    /// Handle GDB command
    fn handle_command(&mut self, cmd: u8) -> Result<(), HvError> {
        match cmd {
            gdb_cmd::READ_REGS => self.handle_read_regs(),
            gdb_cmd::WRITE_REGS => self.handle_write_regs(),
            gdb_cmd::READ_MEM => self.handle_read_mem(),
            gdb_cmd::WRITE_MEM => self.handle_write_mem(),
            gdb_cmd::SET_BREAKPOINT => self.handle_set_bp(),
            gdb_cmd::REMOVE_BREAKPOINT => self.handle_remove_bp(),
            gdb_cmd::CONTINUE => self.handle_continue(),
            gdb_cmd::STEP => self.handle_step(),
            gdb_cmd::QUERY => self.handle_query(),
            _ => self.send_empty_response(),
        }
    }

    /// Handle read registers
    fn handle_read_regs(&self) -> Result<(), HvError> {
        // Would read all registers from vCPU
        // Format: each register as hex pairs
        self.send_empty_response()
    }

    /// Handle write registers
    fn handle_write_regs(&self) -> Result<(), HvError> {
        self.send_ok()
    }

    /// Handle read memory
    fn handle_read_mem(&self) -> Result<(), HvError> {
        // Parse address and length from packet
        self.send_empty_response()
    }

    /// Handle write memory
    fn handle_write_mem(&self) -> Result<(), HvError> {
        self.send_ok()
    }

    /// Handle set breakpoint
    fn handle_set_bp(&mut self) -> Result<(), HvError> {
        // Parse type, address, kind from packet
        self.send_ok()
    }

    /// Handle remove breakpoint
    fn handle_remove_bp(&mut self) -> Result<(), HvError> {
        self.send_ok()
    }

    /// Handle continue
    fn handle_continue(&mut self) -> Result<(), HvError> {
        self.active.store(true, Ordering::Release);
        self.single_step.store(false, Ordering::Release);
        Ok(())
    }

    /// Handle step
    fn handle_step(&mut self) -> Result<(), HvError> {
        self.active.store(true, Ordering::Release);
        self.single_step.store(true, Ordering::Release);
        Ok(())
    }

    /// Handle query
    fn handle_query(&self) -> Result<(), HvError> {
        // Parse query type
        self.send_empty_response()
    }

    /// Send ACK
    fn send_ack(&self) {
        // Would send '+' to GDB
    }

    /// Send NACK
    fn send_nack(&self) {
        // Would send '-' to GDB
    }

    /// Send OK response
    fn send_ok(&self) -> Result<(), HvError> {
        self.tx_buffer[0].store(b'O', Ordering::Release);
        self.tx_buffer[1].store(b'K', Ordering::Release);
        self.tx_len.store(2, Ordering::Release);
        Ok(())
    }

    /// Send empty response
    fn send_empty_response(&self) -> Result<(), HvError> {
        self.tx_len.store(0, Ordering::Release);
        Ok(())
    }

    /// Parse hex byte
    fn parse_hex_byte(hi: u8, lo: u8) -> u8 {
        let hi = Self::hex_to_nibble(hi);
        let lo = Self::hex_to_nibble(lo);
        (hi << 4) | lo
    }

    /// Hex char to nibble
    fn hex_to_nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }

    /// Nibble to hex char
    fn nibble_to_hex(n: u8) -> u8 {
        if n < 10 { b'0' + n } else { b'a' + n - 10 }
    }
}

impl Default for GdbStubState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Performance Counters
// ─────────────────────────────────────────────────────────────────────────────

/// PMU events
pub mod pmu_event {
    pub const CPU_CYCLES: u32 = 0x003C;
    pub const INSTRUCTIONS: u32 = 0x00C0;
    pub const CACHE_REFERENCES: u32 = 0x0043;
    pub const CACHE_MISSES: u32 = 0x0044;
    pub const BRANCH_INSTRUCTIONS: u32 = 0x00C4;
    pub const BRANCH_MISSES: u32 = 0x00C5;
    pub const STALLED_CYCLES_FRONTEND: u32 = 0x0000; // Fixed counter
    pub const STALLED_CYCLES_BACKEND: u32 = 0x0001; // Fixed counter
    pub const TLB_LOADS: u32 = 0x004D;
    pub const TLB_LOAD_MISSES: u32 = 0x004E;
    pub const TLB_STORES: u32 = 0x004F;
    pub const TLB_STORE_MISSES: u32 = 0x0050;
}

/// Maximum PMU counters
pub const MAX_PMU_COUNTERS: usize = 8;

/// PMU counter state
pub struct PmuCounter {
    /// Event select
    pub event: AtomicU32,
    /// Counter value
    pub value: AtomicU64,
    /// Enabled
    pub enabled: AtomicBool,
    /// Overflow count
    pub overflow_count: AtomicU64,
    /// Sample period
    pub sample_period: AtomicU64,
    /// Last sample time
    pub last_sample: AtomicU64,
}

impl PmuCounter {
    pub const fn new() -> Self {
        Self {
            event: AtomicU32::new(0),
            value: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            overflow_count: AtomicU64::new(0),
            sample_period: AtomicU64::new(0),
            last_sample: AtomicU64::new(0),
        }
    }
}

/// Performance monitoring unit
pub struct PmuController {
    /// Programmable counters
    pub counters: [PmuCounter; MAX_PMU_COUNTERS],
    /// Fixed counter 0: Instructions
    pub fixed_instructions: AtomicU64,
    /// Fixed counter 1: Cycles
    pub fixed_cycles: AtomicU64,
    /// Fixed counter 2: Reference cycles
    pub fixed_ref_cycles: AtomicU64,
    /// PMU enabled
    pub enabled: AtomicBool,
    /// Global control
    pub global_ctrl: AtomicU64,
    /// Global status (overflow)
    pub global_status: AtomicU64,
    /// Global overflow control
    pub global_ovf_ctrl: AtomicU64,
    /// Sample rate
    pub sample_rate: AtomicU32,
    /// Profiling active
    pub profiling: AtomicBool,
}

impl PmuController {
    pub const fn new() -> Self {
        Self {
            counters: [const { PmuCounter::new() }; MAX_PMU_COUNTERS],
            fixed_instructions: AtomicU64::new(0),
            fixed_cycles: AtomicU64::new(0),
            fixed_ref_cycles: AtomicU64::new(0),
            enabled: AtomicBool::new(false),
            global_ctrl: AtomicU64::new(0),
            global_status: AtomicU64::new(0),
            global_ovf_ctrl: AtomicU64::new(0),
            sample_rate: AtomicU32::new(1000),
            profiling: AtomicBool::new(false),
        }
    }

    /// Enable PMU
    pub fn enable(&mut self) {
        self.enabled.store(true, Ordering::Release);
        // Enable all counters
        self.global_ctrl.store(0xFF, Ordering::Release);
    }

    /// Disable PMU
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
        self.global_ctrl.store(0, Ordering::Release);
    }

    /// Configure counter
    pub fn configure_counter(&mut self, idx: usize, event: u32, sample_period: u64) -> Result<(), HvError> {
        if idx >= MAX_PMU_COUNTERS {
            return Err(HvError::LogicalFault);
        }
        
        let counter = &self.counters[idx];
        counter.event.store(event, Ordering::Release);
        counter.sample_period.store(sample_period, Ordering::Release);
        counter.value.store(0, Ordering::Release);
        counter.enabled.store(true, Ordering::Release);
        
        Ok(())
    }

    /// Read counter
    pub fn read_counter(&self, idx: usize) -> Result<u64, HvError> {
        if idx >= MAX_PMU_COUNTERS {
            return Err(HvError::LogicalFault);
        }
        Ok(self.counters[idx].value.load(Ordering::Acquire))
    }

    /// Update counter (called on VM exit)
    pub fn update_counter(&mut self, idx: usize, delta: u64) {
        if idx >= MAX_PMU_COUNTERS {
            return;
        }
        
        let counter = &self.counters[idx];
        if !counter.enabled.load(Ordering::Acquire) {
            return;
        }
        
        let new_val = counter.value.fetch_add(delta, Ordering::Release) + delta;
        let period = counter.sample_period.load(Ordering::Acquire);
        
        if period > 0 && new_val >= period {
            // Overflow/sampling event
            counter.overflow_count.fetch_add(1, Ordering::Release);
            counter.value.store(new_val % period, Ordering::Release);
            self.global_status.fetch_or(1 << idx, Ordering::Release);
        }
    }

    /// Start profiling session
    pub fn start_profiling(&mut self) {
        self.profiling.store(true, Ordering::Release);
        self.enable();
    }

    /// Stop profiling session
    pub fn stop_profiling(&mut self) {
        self.profiling.store(false, Ordering::Release);
        self.disable();
    }

    /// Get profiling stats
    pub fn get_stats(&self) -> ProfilingStats {
        let mut counter_values = [0u64; MAX_PMU_COUNTERS];
        for i in 0..MAX_PMU_COUNTERS {
            counter_values[i] = self.counters[i].value.load(Ordering::Acquire);
        }
        
        ProfilingStats {
            fixed_instructions: self.fixed_instructions.load(Ordering::Acquire),
            fixed_cycles: self.fixed_cycles.load(Ordering::Acquire),
            fixed_ref_cycles: self.fixed_ref_cycles.load(Ordering::Acquire),
            counter_values,
            overflow_status: self.global_status.load(Ordering::Acquire),
        }
    }

    /// Reset all counters
    pub fn reset(&mut self) {
        for counter in &self.counters {
            counter.value.store(0, Ordering::Release);
            counter.overflow_count.store(0, Ordering::Release);
        }
        self.fixed_instructions.store(0, Ordering::Release);
        self.fixed_cycles.store(0, Ordering::Release);
        self.fixed_ref_cycles.store(0, Ordering::Release);
        self.global_status.store(0, Ordering::Release);
    }
}

impl Default for PmuController {
    fn default() -> Self {
        Self::new()
    }
}

/// Profiling statistics
#[repr(C)]
pub struct ProfilingStats {
    pub fixed_instructions: u64,
    pub fixed_cycles: u64,
    pub fixed_ref_cycles: u64,
    pub counter_values: [u64; MAX_PMU_COUNTERS],
    pub overflow_status: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdb_set_breakpoint() {
        let gdb = GdbStubState::new();
        
        let id = gdb.set_breakpoint(0x1000, bp_type::SOFTWARE).unwrap();
        assert!(gdb.breakpoints[id as usize].enabled.load(Ordering::Acquire));
    }

    #[test]
    fn gdb_remove_breakpoint() {
        let gdb = GdbStubState::new();
        
        gdb.set_breakpoint(0x1000, bp_type::SOFTWARE).unwrap();
        gdb.remove_breakpoint(0x1000, bp_type::SOFTWARE).unwrap();
        
        assert!(!gdb.breakpoints[0].enabled.load(Ordering::Acquire));
    }

    #[test]
    fn gdb_check_breakpoint() {
        let gdb = GdbStubState::new();
        gdb.set_breakpoint(0x1000, bp_type::SOFTWARE).unwrap();
        
        assert!(gdb.check_breakpoint(0x1000));
        assert!(!gdb.check_breakpoint(0x2000));
    }

    #[test]
    fn pmu_configure() {
        let mut pmu = PmuController::new();
        
        pmu.configure_counter(0, pmu_event::INSTRUCTIONS, 10000).unwrap();
        
        assert!(pmu.counters[0].enabled.load(Ordering::Acquire));
        assert_eq!(pmu.counters[0].event.load(Ordering::Acquire), pmu_event::INSTRUCTIONS);
    }

    #[test]
    fn pmu_update() {
        let mut pmu = PmuController::new();
        pmu.enable();
        pmu.configure_counter(0, pmu_event::CPU_CYCLES, 0).unwrap();
        
        pmu.update_counter(0, 100);
        
        assert_eq!(pmu.counters[0].value.load(Ordering::Acquire), 100);
    }
}
