//! CPU Power Management
//!
//! P-state, C-state, DVFS integration for energy-efficient VM scheduling.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Power Management Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum pCPUs
pub const MAX_PCPUS: usize = 256;

/// Maximum P-states per CPU
pub const MAX_PSTATES: usize = 16;

/// Maximum C-states per CPU
pub const MAX_CSTATES: usize = 8;

/// P-state types
pub mod pstate_type {
    pub const PERFORMANCE: u8 = 0;  // Highest frequency
    pub const BALANCED: u8 = 1;     // Balanced
    pub const POWERSAVE: u8 = 2;    // Lowest frequency
    pub const USERSPACE: u8 = 3;    // User-defined
    pub const ONDEMAND: u8 = 4;     // Dynamic scaling
    pub const CONSERVATIVE: u8 = 5; // Conservative scaling
    pub const SCHEDUTIL: u8 = 6;    // Scheduler-driven
}

/// C-state types
pub mod cstate_type {
    pub const C0: u8 = 0;   // Active
    pub const C1: u8 = 1;   // Halt
    pub const C2: u8 = 2;   // Stop-clock
    pub const C3: u8 = 3;   // Sleep
    pub const C6: u8 = 4;   // Deep sleep
    pub const C7: u8 = 5;   // Deeper sleep
    pub const C8: u8 = 6;   // Even deeper
    pub const C10: u8 = 7;  // Deepest
}

// ─────────────────────────────────────────────────────────────────────────────
// P-State Entry
// ─────────────────────────────────────────────────────────────────────────────

/// P-state (performance state)
pub struct PState {
    /// State ID
    pub id: AtomicU8,
    /// Frequency in MHz
    pub frequency: AtomicU32,
    /// Voltage in mV
    pub voltage: AtomicU32,
    /// Power in mW
    pub power: AtomicU32,
    /// Latency to enter (us)
    pub latency: AtomicU32,
    /// Is turbo state
    pub is_turbo: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl PState {
    pub const fn new() -> Self {
        Self {
            id: AtomicU8::new(0),
            frequency: AtomicU32::new(0),
            voltage: AtomicU32::new(0),
            power: AtomicU32::new(0),
            latency: AtomicU32::new(0),
            is_turbo: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize P-state
    pub fn init(&self, id: u8, freq: u32, voltage: u32, power: u32, latency: u32, turbo: bool) {
        self.id.store(id, Ordering::Release);
        self.frequency.store(freq, Ordering::Release);
        self.voltage.store(voltage, Ordering::Release);
        self.power.store(power, Ordering::Release);
        self.latency.store(latency, Ordering::Release);
        self.is_turbo.store(turbo, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }
}

impl Default for PState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// C-State Entry
// ─────────────────────────────────────────────────────────────────────────────

/// C-state (idle state)
pub struct CState {
    /// State ID
    pub id: AtomicU8,
    /// C-state type
    pub cstate_type: AtomicU8,
    /// Power saving in mW
    pub power_saving: AtomicU32,
    /// Entry latency (us)
    pub entry_latency: AtomicU32,
    /// Exit latency (us)
    pub exit_latency: AtomicU32,
    /// Minimum residency (us)
    pub min_residency: AtomicU32,
    /// Target residency (us)
    pub target_residency: AtomicU32,
    /// Usage count
    pub usage: AtomicU64,
    /// Time spent (us)
    pub time: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CState {
    pub const fn new() -> Self {
        Self {
            id: AtomicU8::new(0),
            cstate_type: AtomicU8::new(cstate_type::C0),
            power_saving: AtomicU32::new(0),
            entry_latency: AtomicU32::new(0),
            exit_latency: AtomicU32::new(0),
            min_residency: AtomicU32::new(0),
            target_residency: AtomicU32::new(0),
            usage: AtomicU64::new(0),
            time: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize C-state
    pub fn init(&self, id: u8, cstate_type: u8, power_saving: u32, 
                entry_latency: u32, exit_latency: u32, min_residency: u32) {
        self.id.store(id, Ordering::Release);
        self.cstate_type.store(cstate_type, Ordering::Release);
        self.power_saving.store(power_saving, Ordering::Release);
        self.entry_latency.store(entry_latency, Ordering::Release);
        self.exit_latency.store(exit_latency, Ordering::Release);
        self.min_residency.store(min_residency, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enter C-state
    pub fn enter(&self) {
        self.usage.fetch_add(1, Ordering::Release);
    }

    /// Exit C-state
    pub fn exit(&self, time_us: u64) {
        self.time.fetch_add(time_us, Ordering::Release);
    }

    /// Check if worth entering
    pub fn is_worth_entering(&self, idle_time_us: u64) -> bool {
        let entry = self.entry_latency.load(Ordering::Acquire) as u64;
        let exit = self.exit_latency.load(Ordering::Acquire) as u64;
        let min_res = self.min_residency.load(Ordering::Acquire) as u64;
        
        // Only enter if idle time > entry + exit + min residency
        idle_time_us > entry + exit + min_res
    }
}

impl Default for CState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-CPU Power State
// ─────────────────────────────────────────────────────────────────────────────

/// Per-CPU power management state
pub struct CpuPowerState {
    /// CPU ID
    pub cpu_id: AtomicU16,
    /// Current P-state
    pub current_pstate: AtomicU8,
    /// Current C-state
    pub current_cstate: AtomicU8,
    /// Current frequency (MHz)
    pub current_freq: AtomicU32,
    /// Current voltage (mV)
    pub current_voltage: AtomicU32,
    /// Available P-states
    pub pstates: [PState; MAX_PSTATES],
    /// P-state count
    pub pstate_count: AtomicU8,
    /// Available C-states
    pub cstates: [CState; MAX_CSTATES],
    /// C-state count
    pub cstate_count: AtomicU8,
    /// Governor type
    pub governor: AtomicU8,
    /// Governor parameters
    pub gov_up_threshold: AtomicU8,
    pub gov_down_threshold: AtomicU8,
    pub gov_sampling_rate: AtomicU32,
    /// Idle time accumulator (us)
    pub idle_time: AtomicU64,
    /// Active time accumulator (us)
    pub active_time: AtomicU64,
    /// Last state change
    pub last_change: AtomicU64,
    /// Last idle enter
    pub idle_enter_time: AtomicU64,
    /// Is idle
    pub is_idle: AtomicBool,
    /// Turbo allowed
    pub turbo_allowed: AtomicBool,
    /// Turbo active
    pub turbo_active: AtomicBool,
    /// Energy consumed (mJ)
    pub energy_consumed: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl CpuPowerState {
    pub const fn new() -> Self {
        Self {
            cpu_id: AtomicU16::new(0),
            current_pstate: AtomicU8::new(0),
            current_cstate: AtomicU8::new(0),
            current_freq: AtomicU32::new(0),
            current_voltage: AtomicU32::new(0),
            pstates: [const { PState::new() }; MAX_PSTATES],
            pstate_count: AtomicU8::new(0),
            cstates: [const { CState::new() }; MAX_CSTATES],
            cstate_count: AtomicU8::new(0),
            governor: AtomicU8::new(pstate_type::ONDEMAND),
            gov_up_threshold: AtomicU8::new(80),
            gov_down_threshold: AtomicU8::new(20),
            gov_sampling_rate: AtomicU32::new(10000), // 10ms
            idle_time: AtomicU64::new(0),
            active_time: AtomicU64::new(0),
            last_change: AtomicU64::new(0),
            idle_enter_time: AtomicU64::new(0),
            is_idle: AtomicBool::new(false),
            turbo_allowed: AtomicBool::new(true),
            turbo_active: AtomicBool::new(false),
            energy_consumed: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize CPU
    pub fn init(&self, cpu_id: u16) {
        self.cpu_id.store(cpu_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add P-state
    pub fn add_pstate(&self, id: u8, freq: u32, voltage: u32, power: u32, latency: u32, turbo: bool) {
        let count = self.pstate_count.load(Ordering::Acquire) as usize;
        if count < MAX_PSTATES {
            self.pstates[count].init(id, freq, voltage, power, latency, turbo);
            self.pstate_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Add C-state
    pub fn add_cstate(&self, id: u8, cstate_type: u8, power_saving: u32,
                      entry_latency: u32, exit_latency: u32, min_residency: u32) {
        let count = self.cstate_count.load(Ordering::Acquire) as usize;
        if count < MAX_CSTATES {
            self.cstates[count].init(id, cstate_type, power_saving, entry_latency, exit_latency, min_residency);
            self.cstate_count.fetch_add(1, Ordering::Release);
        }
    }

    /// Set P-state
    pub fn set_pstate(&self, state_id: u8) -> Result<(), HvError> {
        for i in 0..self.pstate_count.load(Ordering::Acquire) as usize {
            if self.pstates[i].id.load(Ordering::Acquire) == state_id &&
               self.pstates[i].valid.load(Ordering::Acquire) {
                self.current_pstate.store(state_id, Ordering::Release);
                self.current_freq.store(self.pstates[i].frequency.load(Ordering::Acquire), Ordering::Release);
                self.current_voltage.store(self.pstates[i].voltage.load(Ordering::Acquire), Ordering::Release);
                self.turbo_active.store(self.pstates[i].is_turbo.load(Ordering::Acquire), Ordering::Release);
                self.last_change.store(Self::get_timestamp(), Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Enter C-state
    pub fn enter_cstate(&self, state_id: u8) -> Result<(), HvError> {
        for i in 0..self.cstate_count.load(Ordering::Acquire) as usize {
            if self.cstates[i].id.load(Ordering::Acquire) == state_id &&
               self.cstates[i].valid.load(Ordering::Acquire) {
                self.current_cstate.store(state_id, Ordering::Release);
                self.is_idle.store(true, Ordering::Release);
                self.idle_enter_time.store(Self::get_timestamp(), Ordering::Release);
                self.cstates[i].enter();
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Exit C-state
    pub fn exit_cstate(&self) {
        if self.is_idle.load(Ordering::Acquire) {
            let enter_time = self.idle_enter_time.load(Ordering::Acquire);
            let now = Self::get_timestamp();
            let duration = now.saturating_sub(enter_time);
            
            self.idle_time.fetch_add(duration, Ordering::Release);
            self.is_idle.store(false, Ordering::Release);
            self.current_cstate.store(cstate_type::C0, Ordering::Release);
            
            // Update C-state stats
            let cstate = self.current_cstate.load(Ordering::Acquire);
            for i in 0..self.cstate_count.load(Ordering::Acquire) as usize {
                if self.cstates[i].id.load(Ordering::Acquire) == cstate {
                    self.cstates[i].exit(duration);
                    break;
                }
            }
        }
    }

    /// Get utilization (0-100)
    pub fn get_utilization(&self) -> u32 {
        let idle = self.idle_time.load(Ordering::Acquire);
        let active = self.active_time.load(Ordering::Acquire);
        let total = idle + active;
        
        if total == 0 {
            return 0;
        }
        
        ((active * 100) / total) as u32
    }

    /// Calculate energy for duration
    pub fn calculate_energy(&self, duration_us: u64) -> u64 {
        let freq = self.current_freq.load(Ordering::Acquire) as u64;
        let voltage = self.current_voltage.load(Ordering::Acquire) as u64;
        
        // Simple energy model: E = V^2 * f * t
        (voltage * voltage * freq * duration_us) / 1_000_000_000
    }

    /// Get deepest suitable C-state
    pub fn get_deepest_cstate(&self, idle_time_us: u64) -> u8 {
        let mut deepest = cstate_type::C0;
        
        for i in 0..self.cstate_count.load(Ordering::Acquire) as usize {
            if self.cstates[i].is_worth_entering(idle_time_us) {
                deepest = self.cstates[i].id.load(Ordering::Acquire);
            }
        }
        
        deepest
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for CpuPowerState {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Power Management Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Power management controller
pub struct PowerManager {
    /// Per-CPU states
    pub cpu_states: [CpuPowerState; MAX_PCPUS],
    /// CPU count
    pub cpu_count: AtomicU16,
    /// Enabled
    pub enabled: AtomicBool,
    /// Global governor
    pub global_governor: AtomicU8,
    /// Performance bias (0=powersave, 100=performance)
    pub perf_bias: AtomicU8,
    /// Power budget (mW)
    pub power_budget: AtomicU32,
    /// Current power (mW)
    pub current_power: AtomicU32,
    /// Turbo enabled
    pub turbo_enabled: AtomicBool,
    /// DVFS enabled
    pub dvfs_enabled: AtomicBool,
    /// C-state enabled
    pub cstate_enabled: AtomicBool,
    /// Total energy consumed (mJ)
    pub total_energy: AtomicU64,
    /// Power saved (mJ)
    pub power_saved: AtomicU64,
    /// P-state transitions
    pub pstate_transitions: AtomicU64,
    /// C-state transitions
    pub cstate_transitions: AtomicU64,
    /// Last balance time
    pub last_balance: AtomicU64,
    /// Balance interval (us)
    pub balance_interval: AtomicU32,
}

impl PowerManager {
    pub const fn new() -> Self {
        Self {
            cpu_states: [const { CpuPowerState::new() }; MAX_PCPUS],
            cpu_count: AtomicU16::new(0),
            enabled: AtomicBool::new(false),
            global_governor: AtomicU8::new(pstate_type::ONDEMAND),
            perf_bias: AtomicU8::new(50),
            power_budget: AtomicU32::new(0),
            current_power: AtomicU32::new(0),
            turbo_enabled: AtomicBool::new(true),
            dvfs_enabled: AtomicBool::new(true),
            cstate_enabled: AtomicBool::new(true),
            total_energy: AtomicU64::new(0),
            power_saved: AtomicU64::new(0),
            pstate_transitions: AtomicU64::new(0),
            cstate_transitions: AtomicU64::new(0),
            last_balance: AtomicU64::new(0),
            balance_interval: AtomicU32::new(10000), // 10ms
        }
    }

    /// Enable power management
    pub fn enable(&mut self, cpu_count: u16, governor: u8, perf_bias: u8) {
        self.cpu_count.store(cpu_count, Ordering::Release);
        self.global_governor.store(governor, Ordering::Release);
        self.perf_bias.store(perf_bias, Ordering::Release);
        
        for i in 0..cpu_count as usize {
            self.cpu_states[i].init(i as u16);
            self.cpu_states[i].governor.store(governor, Ordering::Release);
        }
        
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable power management
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Set P-states for CPU
    pub fn set_cpu_pstates(&self, cpu: u16, pstates: &[(u8, u32, u32, u32, u32, bool)]) {
        if cpu as usize >= MAX_PCPUS {
            return;
        }
        
        let cpu_state = &self.cpu_states[cpu as usize];
        for &(id, freq, voltage, power, latency, turbo) in pstates {
            cpu_state.add_pstate(id, freq, voltage, power, latency, turbo);
        }
    }

    /// Set C-states for CPU
    pub fn set_cpu_cstates(&self, cpu: u16, cstates: &[(u8, u8, u32, u32, u32, u32)]) {
        if cpu as usize >= MAX_PCPUS {
            return;
        }
        
        let cpu_state = &self.cpu_states[cpu as usize];
        for &(id, cstate_type, power_saving, entry, exit, min_res) in cstates {
            cpu_state.add_cstate(id, cstate_type, power_saving, entry, exit, min_res);
        }
    }

    /// Run governor algorithm
    pub fn run_governor(&mut self) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        
        let now = Self::get_timestamp();
        let interval = self.balance_interval.load(Ordering::Acquire) as u64;
        
        if now - self.last_balance.load(Ordering::Acquire) < interval {
            return;
        }
        
        self.last_balance.store(now, Ordering::Release);
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            let cpu = &self.cpu_states[i];
            let governor = cpu.governor.load(Ordering::Acquire);
            
            match governor {
                pstate_type::ONDEMAND => self.run_ondemand(i),
                pstate_type::CONSERVATIVE => self.run_conservative(i),
                pstate_type::POWERSAVE => self.run_powersave(i),
                pstate_type::PERFORMANCE => self.run_performance(i),
                pstate_type::SCHEDUTIL => self.run_schedutil(i),
                _ => {}
            }
        }
        
        // Update total power
        self.update_total_power();
    }

    /// On-demand governor
    fn run_ondemand(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let util = cpu.get_utilization();
        let up_threshold = cpu.gov_up_threshold.load(Ordering::Acquire);
        let down_threshold = cpu.gov_down_threshold.load(Ordering::Acquire);
        
        if util >= up_threshold as u32 {
            // Go to highest frequency
            self.set_highest_pstate(cpu_idx);
        } else if util <= down_threshold as u32 {
            // Go to lowest frequency
            self.set_lowest_pstate(cpu_idx);
        }
    }

    /// Conservative governor
    fn run_conservative(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let util = cpu.get_utilization();
        let up_threshold = cpu.gov_up_threshold.load(Ordering::Acquire);
        let down_threshold = cpu.gov_down_threshold.load(Ordering::Acquire);
        
        if util >= up_threshold as u32 {
            // Step up one P-state
            self.step_up_pstate(cpu_idx);
        } else if util <= down_threshold as u32 {
            // Step down one P-state
            self.step_down_pstate(cpu_idx);
        }
    }

    /// Powersave governor
    fn run_powersave(&self, cpu_idx: usize) {
        self.set_lowest_pstate(cpu_idx);
    }

    /// Performance governor
    fn run_performance(&self, cpu_idx: usize) {
        if self.turbo_enabled.load(Ordering::Acquire) {
            self.set_turbo_pstate(cpu_idx);
        } else {
            self.set_highest_pstate(cpu_idx);
        }
    }

    /// Scheduler-driven governor
    fn run_schedutil(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let util = cpu.get_utilization();
        let perf_bias = self.perf_bias.load(Ordering::Acquire);
        
        // Adjust frequency based on utilization and perf bias
        let target_util = (util as u64 * (100 - perf_bias as u64) / 100) as u32;
        self.set_pstate_by_util(cpu_idx, target_util);
    }

    /// Set highest P-state
    fn set_highest_pstate(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let count = cpu.pstate_count.load(Ordering::Acquire);
        
        if count > 0 {
            // Find highest non-turbo
            for i in (0..count as usize).rev() {
                if !cpu.pstates[i].is_turbo.load(Ordering::Acquire) {
                    let id = cpu.pstates[i].id.load(Ordering::Acquire);
                    if cpu.set_pstate(id).is_ok() {
                        self.pstate_transitions.fetch_add(1, Ordering::Release);
                    }
                    break;
                }
            }
        }
    }

    /// Set lowest P-state
    fn set_lowest_pstate(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let count = cpu.pstate_count.load(Ordering::Acquire);
        
        if count > 0 {
            let id = cpu.pstates[0].id.load(Ordering::Acquire);
            if cpu.set_pstate(id).is_ok() {
                self.pstate_transitions.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Set turbo P-state
    fn set_turbo_pstate(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        
        if !self.turbo_enabled.load(Ordering::Acquire) || !cpu.turbo_allowed.load(Ordering::Acquire) {
            return;
        }
        
        let count = cpu.pstate_count.load(Ordering::Acquire);
        for i in 0..count as usize {
            if cpu.pstates[i].is_turbo.load(Ordering::Acquire) {
                let id = cpu.pstates[i].id.load(Ordering::Acquire);
                if cpu.set_pstate(id).is_ok() {
                    self.pstate_transitions.fetch_add(1, Ordering::Release);
                }
                break;
            }
        }
    }

    /// Step up P-state
    fn step_up_pstate(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let current = cpu.current_pstate.load(Ordering::Acquire);
        let count = cpu.pstate_count.load(Ordering::Acquire);
        
        for i in 0..count as usize {
            if cpu.pstates[i].id.load(Ordering::Acquire) == current {
                if i + 1 < count as usize {
                    let next_id = cpu.pstates[i + 1].id.load(Ordering::Acquire);
                    if cpu.set_pstate(next_id).is_ok() {
                        self.pstate_transitions.fetch_add(1, Ordering::Release);
                    }
                }
                break;
            }
        }
    }

    /// Step down P-state
    fn step_down_pstate(&self, cpu_idx: usize) {
        let cpu = &self.cpu_states[cpu_idx];
        let current = cpu.current_pstate.load(Ordering::Acquire);
        
        for i in 0..cpu.pstate_count.load(Ordering::Acquire) as usize {
            if cpu.pstates[i].id.load(Ordering::Acquire) == current {
                if i > 0 {
                    let prev_id = cpu.pstates[i - 1].id.load(Ordering::Acquire);
                    if cpu.set_pstate(prev_id).is_ok() {
                        self.pstate_transitions.fetch_add(1, Ordering::Release);
                    }
                }
                break;
            }
        }
    }

    /// Set P-state by utilization
    fn set_pstate_by_util(&self, cpu_idx: usize, util: u32) {
        let cpu = &self.cpu_states[cpu_idx];
        let count = cpu.pstate_count.load(Ordering::Acquire) as u32;
        
        if count == 0 {
            return;
        }
        
        let target_idx = ((count - 1) * util / 100) as usize;
        let id = cpu.pstates[target_idx].id.load(Ordering::Acquire);
        
        if cpu.set_pstate(id).is_ok() {
            self.pstate_transitions.fetch_add(1, Ordering::Release);
        }
    }

    /// Enter idle state
    pub fn enter_idle(&self, cpu: u16, predicted_idle_us: u64) {
        if !self.enabled.load(Ordering::Acquire) || !self.cstate_enabled.load(Ordering::Acquire) {
            return;
        }
        
        if cpu as usize >= MAX_PCPUS {
            return;
        }
        
        let cpu_state = &self.cpu_states[cpu as usize];
        let target_cstate = cpu_state.get_deepest_cstate(predicted_idle_us);
        
        if target_cstate != cstate_type::C0 {
            if cpu_state.enter_cstate(target_cstate).is_ok() {
                self.cstate_transitions.fetch_add(1, Ordering::Release);
            }
        }
    }

    /// Exit idle state
    pub fn exit_idle(&self, cpu: u16) {
        if cpu as usize >= MAX_PCPUS {
            return;
        }
        
        self.cpu_states[cpu as usize].exit_cstate();
    }

    /// Update total power consumption
    fn update_total_power(&self) {
        let mut total = 0u32;
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            let cpu = &self.cpu_states[i];
            let freq = cpu.current_freq.load(Ordering::Acquire);
            let voltage = cpu.current_voltage.load(Ordering::Acquire);
            
            // Simple power model: P ~ V^2 * f
            let power = (voltage * voltage * freq / 1_000_000) as u32;
            total += power;
        }
        
        self.current_power.store(total, Ordering::Release);
    }

    /// Set power budget
    pub fn set_power_budget(&mut self, budget_mw: u32) {
        self.power_budget.store(budget_mw, Ordering::Release);
        
        // If over budget, reduce frequencies
        if budget_mw > 0 {
            let current = self.current_power.load(Ordering::Acquire);
            if current > budget_mw {
                // Reduce all CPUs to lower P-states
                for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
                    self.step_down_pstate(i);
                }
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> PowerStats {
        let mut total_idle = 0u64;
        let mut total_active = 0u64;
        
        for i in 0..self.cpu_count.load(Ordering::Acquire) as usize {
            total_idle += self.cpu_states[i].idle_time.load(Ordering::Acquire);
            total_active += self.cpu_states[i].active_time.load(Ordering::Acquire);
        }
        
        PowerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            cpu_count: self.cpu_count.load(Ordering::Acquire),
            current_power: self.current_power.load(Ordering::Acquire),
            power_budget: self.power_budget.load(Ordering::Acquire),
            total_energy: self.total_energy.load(Ordering::Acquire),
            pstate_transitions: self.pstate_transitions.load(Ordering::Acquire),
            cstate_transitions: self.cstate_transitions.load(Ordering::Acquire),
            total_idle_time: total_idle,
            total_active_time: total_active,
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Power statistics
#[repr(C)]
pub struct PowerStats {
    pub enabled: bool,
    pub cpu_count: u16,
    pub current_power: u32,
    pub power_budget: u32,
    pub total_energy: u64,
    pub pstate_transitions: u64,
    pub cstate_transitions: u64,
    pub total_idle_time: u64,
    pub total_active_time: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_cpu() {
        let mut pm = PowerManager::new();
        pm.enable(4, pstate_type::ONDEMAND, 50);
        
        assert_eq!(pm.cpu_count.load(Ordering::Acquire), 4);
    }

    #[test]
    fn set_pstates() {
        let pm = PowerManager::new();
        pm.set_cpu_pstates(0, &[
            (0, 800, 800, 10000, 10, false),
            (1, 1200, 900, 15000, 10, false),
            (2, 2000, 1000, 25000, 10, false),
            (3, 3500, 1200, 45000, 10, true), // Turbo
        ]);
        
        assert_eq!(pm.cpu_states[0].pstate_count.load(Ordering::Acquire), 4);
    }

    #[test]
    fn set_cstates() {
        let pm = PowerManager::new();
        pm.set_cpu_cstates(0, &[
            (0, cstate_type::C1, 1000, 1, 1, 10),
            (1, cstate_type::C3, 5000, 10, 20, 100),
            (2, cstate_type::C6, 15000, 50, 100, 500),
        ]);
        
        assert_eq!(pm.cpu_states[0].cstate_count.load(Ordering::Acquire), 3);
    }

    #[test]
    fn change_pstate() {
        let pm = PowerManager::new();
        pm.set_cpu_pstates(0, &[
            (0, 800, 800, 10000, 10, false),
            (1, 2000, 1000, 25000, 10, false),
        ]);
        
        pm.cpu_states[0].set_pstate(1).unwrap();
        assert_eq!(pm.cpu_states[0].current_freq.load(Ordering::Acquire), 2000);
    }

    #[test]
    fn cstate_worth_entering() {
        let cstate = CState::new();
        cstate.init(0, cstate_type::C6, 15000, 50, 100, 500);
        
        // Too short idle
        assert!(!cstate.is_worth_entering(100));
        
        // Long enough
        assert!(cstate.is_worth_entering(1000));
    }

    #[test]
    fn ondemand_governor() {
        let mut pm = PowerManager::new();
        pm.enable(1, pstate_type::ONDEMAND, 50);
        pm.set_cpu_pstates(0, &[
            (0, 800, 800, 10000, 10, false),
            (1, 2000, 1000, 25000, 10, false),
        ]);
        
        // High utilization should trigger upscaling
        pm.cpu_states[0].active_time.store(900, Ordering::Release);
        pm.cpu_states[0].idle_time.store(100, Ordering::Release);
        
        pm.run_ondemand(0);
    }
}
