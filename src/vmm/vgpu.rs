//! vGPU Scheduling Enhancement - MIG Support
//!
//! NVIDIA MIG (Multi-Instance GPU) support for GPU virtualization with fair scheduling.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// vGPU Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum physical GPUs
pub const MAX_GPUS: usize = 16;

/// Maximum vGPUs per GPU
pub const MAX_VGPUS_PER_GPU: usize = 8;

/// Maximum total vGPUs
pub const MAX_TOTAL_VGPUS: usize = 128;

/// Maximum MIG instances per GPU
pub const MAX_MIG_INSTANCES: usize = 7;

/// Maximum VMs using vGPU
pub const MAX_VGPU_VMS: usize = 128;

/// GPU memory page size (64KB)
pub const GPU_PAGE_SIZE: u64 = 64 * 1024;

/// MIG profile types
pub mod mig_profile {
    pub const MIG_1G_5GB: u8 = 0;    // 1/7 GPU, 5GB
    pub const MIG_2G_10GB: u8 = 1;   // 2/7 GPU, 10GB
    pub const MIG_3G_20GB: u8 = 2;   // 3/7 GPU, 20GB
    pub const MIG_4G_20GB: u8 = 3;   // 4/7 GPU, 20GB
    pub const MIG_7G_40GB: u8 = 4;   // Full GPU, 40GB
    pub const MIG_1G_10GB: u8 = 5;   // 1/7 GPU, 10GB (A100)
    pub const MIG_2G_20GB: u8 = 6;   // 2/7 GPU, 20GB
    pub const MIG_3G_40GB: u8 = 7;   // 3/7 GPU, 40GB
    pub const MIG_4G_40GB: u8 = 8;   // 4/7 GPU, 40GB
    pub const MIG_7G_80GB: u8 = 9;   // Full GPU, 80GB (A100 80GB)
}

/// vGPU states
pub mod vgpu_state {
    pub const CREATED: u8 = 0;
    pub const READY: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const PAUSED: u8 = 3;
    pub const STOPPED: u8 = 4;
    pub const ERROR: u8 = 5;
    pub const MIGRATING: u8 = 6;
}

/// GPU types
pub mod gpu_type {
    pub const NVIDIA_A100_40GB: u16 = 0x20B0;
    pub const NVIDIA_A100_80GB: u16 = 0x20B1;
    pub const NVIDIA_A30: u16 = 0x20B2;
    pub const NVIDIA_H100: u16 = 0x20B3;
    pub const NVIDIA_H100_NVL: u16 = 0x20B4;
    pub const NVIDIA_L40: u16 = 0x20B5;
}

/// Scheduling policies
pub mod sched_policy {
    pub const FAIR: u8 = 0;       // Fair sharing
    pub const FIXED: u8 = 1;      // Fixed allocation
    pub const BURST: u8 = 2;      // Burst mode
    pub const PRIORITY: u8 = 3;   // Priority-based
}

// ─────────────────────────────────────────────────────────────────────────────
// MIG Instance
// ─────────────────────────────────────────────────────────────────────────────

/// MIG instance configuration
pub struct MigInstance {
    /// Instance ID
    pub instance_id: AtomicU8,
    /// GPU ID
    pub gpu_id: AtomicU8,
    /// Profile type
    pub profile: AtomicU8,
    /// SM count (streaming multiprocessors)
    pub sm_count: AtomicU16,
    /// Memory size (bytes)
    pub memory_size: AtomicU64,
    /// Memory slice count
    pub mem_slices: AtomicU8,
    /// Compute slice count
    pub compute_slices: AtomicU8,
    /// Assigned vGPU ID
    pub assigned_vgpu: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl MigInstance {
    pub const fn new() -> Self {
        Self {
            instance_id: AtomicU8::new(0),
            gpu_id: AtomicU8::new(0),
            profile: AtomicU8::new(mig_profile::MIG_1G_5GB),
            sm_count: AtomicU16::new(0),
            memory_size: AtomicU64::new(0),
            mem_slices: AtomicU8::new(1),
            compute_slices: AtomicU8::new(1),
            assigned_vgpu: AtomicU32::new(0),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize MIG instance
    pub fn init(&self, instance_id: u8, gpu_id: u8, profile: u8) {
        self.instance_id.store(instance_id, Ordering::Release);
        self.gpu_id.store(gpu_id, Ordering::Release);
        self.profile.store(profile, Ordering::Release);
        
        // Set profile-specific values
        match profile {
            mig_profile::MIG_1G_5GB => {
                self.sm_count.store(14, Ordering::Release);
                self.memory_size.store(5 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(1, Ordering::Release);
                self.compute_slices.store(1, Ordering::Release);
            }
            mig_profile::MIG_2G_10GB => {
                self.sm_count.store(28, Ordering::Release);
                self.memory_size.store(10 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(2, Ordering::Release);
                self.compute_slices.store(2, Ordering::Release);
            }
            mig_profile::MIG_3G_20GB => {
                self.sm_count.store(42, Ordering::Release);
                self.memory_size.store(20 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(4, Ordering::Release);
                self.compute_slices.store(3, Ordering::Release);
            }
            mig_profile::MIG_4G_20GB => {
                self.sm_count.store(56, Ordering::Release);
                self.memory_size.store(20 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(4, Ordering::Release);
                self.compute_slices.store(4, Ordering::Release);
            }
            mig_profile::MIG_7G_40GB => {
                self.sm_count.store(108, Ordering::Release);
                self.memory_size.store(40 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(8, Ordering::Release);
                self.compute_slices.store(7, Ordering::Release);
            }
            mig_profile::MIG_1G_10GB => {
                self.sm_count.store(14, Ordering::Release);
                self.memory_size.store(10 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(2, Ordering::Release);
                self.compute_slices.store(1, Ordering::Release);
            }
            mig_profile::MIG_2G_20GB => {
                self.sm_count.store(28, Ordering::Release);
                self.memory_size.store(20 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(4, Ordering::Release);
                self.compute_slices.store(2, Ordering::Release);
            }
            mig_profile::MIG_3G_40GB => {
                self.sm_count.store(42, Ordering::Release);
                self.memory_size.store(40 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(8, Ordering::Release);
                self.compute_slices.store(3, Ordering::Release);
            }
            mig_profile::MIG_4G_40GB => {
                self.sm_count.store(56, Ordering::Release);
                self.memory_size.store(40 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(8, Ordering::Release);
                self.compute_slices.store(4, Ordering::Release);
            }
            mig_profile::MIG_7G_80GB => {
                self.sm_count.store(132, Ordering::Release);
                self.memory_size.store(80 * 1024 * 1024 * 1024, Ordering::Release);
                self.mem_slices.store(16, Ordering::Release);
                self.compute_slices.store(7, Ordering::Release);
            }
            _ => {}
        }
        
        self.valid.store(true, Ordering::Release);
    }

    /// Assign to vGPU
    pub fn assign(&self, vgpu_id: u32) -> Result<(), HvError> {
        if self.assigned_vgpu.load(Ordering::Acquire) != 0 {
            return Err(HvError::LogicalFault);
        }
        
        self.assigned_vgpu.store(vgpu_id, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Release from vGPU
    pub fn release(&self) {
        self.assigned_vgpu.store(0, Ordering::Release);
        self.enabled.store(false, Ordering::Release);
    }

    /// Is available
    pub fn is_available(&self) -> bool {
        self.valid.load(Ordering::Acquire) && 
        !self.enabled.load(Ordering::Acquire) &&
        self.assigned_vgpu.load(Ordering::Acquire) == 0
    }
}

impl Default for MigInstance {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Physical GPU
// ─────────────────────────────────────────────────────────────────────────────

/// Physical GPU state
pub struct PhysicalGpu {
    /// GPU ID
    pub gpu_id: AtomicU8,
    /// GPU type
    pub gpu_type: AtomicU16,
    /// PCI BDF (Bus:Device:Function)
    pub pci_bdf: AtomicU32,
    /// Total SM count
    pub total_sms: AtomicU16,
    /// Total memory (bytes)
    pub total_memory: AtomicU64,
    /// Free memory
    pub free_memory: AtomicU64,
    /// MIG supported
    pub mig_supported: AtomicBool,
    /// MIG enabled
    pub mig_enabled: AtomicBool,
    /// MIG instances
    pub mig_instances: [MigInstance; MAX_MIG_INSTANCES],
    /// MIG instance count
    pub mig_count: AtomicU8,
    /// vGPU count
    pub vgpu_count: AtomicU8,
    /// Max vGPUs
    pub max_vgpus: AtomicU8,
    /// Compute utilization (0-100)
    pub compute_util: AtomicU8,
    /// Memory utilization (0-100)
    pub memory_util: AtomicU8,
    /// Power usage (mW)
    pub power_usage: AtomicU32,
    /// Power cap (mW)
    pub power_cap: AtomicU32,
    /// Temperature (C)
    pub temperature: AtomicU8,
    /// Clock SM (MHz)
    pub clock_sm: AtomicU32,
    /// Clock memory (MHz)
    pub clock_mem: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl PhysicalGpu {
    pub const fn new() -> Self {
        Self {
            gpu_id: AtomicU8::new(0),
            gpu_type: AtomicU16::new(0),
            pci_bdf: AtomicU32::new(0),
            total_sms: AtomicU16::new(108),
            total_memory: AtomicU64::new(40 * 1024 * 1024 * 1024),
            free_memory: AtomicU64::new(40 * 1024 * 1024 * 1024),
            mig_supported: AtomicBool::new(false),
            mig_enabled: AtomicBool::new(false),
            mig_instances: [const { MigInstance::new() }; MAX_MIG_INSTANCES],
            mig_count: AtomicU8::new(0),
            vgpu_count: AtomicU8::new(0),
            max_vgpus: AtomicU8::new(MAX_VGPUS_PER_GPU as u8),
            compute_util: AtomicU8::new(0),
            memory_util: AtomicU8::new(0),
            power_usage: AtomicU32::new(0),
            power_cap: AtomicU32::new(300000),
            temperature: AtomicU8::new(0),
            clock_sm: AtomicU32::new(0),
            clock_mem: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize GPU
    pub fn init(&self, gpu_id: u8, gpu_type: u16, pci_bdf: u32, 
                total_memory: u64, mig_supported: bool) {
        self.gpu_id.store(gpu_id, Ordering::Release);
        self.gpu_type.store(gpu_type, Ordering::Release);
        self.pci_bdf.store(pci_bdf, Ordering::Release);
        self.total_memory.store(total_memory, Ordering::Release);
        self.free_memory.store(total_memory, Ordering::Release);
        self.mig_supported.store(mig_supported, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Enable MIG
    pub fn enable_mig(&self) -> Result<(), HvError> {
        if !self.mig_supported.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.mig_enabled.store(true, Ordering::Release);
        Ok(())
    }

    /// Create MIG instance
    pub fn create_mig_instance(&self, profile: u8) -> Result<u8, HvError> {
        if !self.mig_enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.mig_count.load(Ordering::Acquire);
        if count as usize >= MAX_MIG_INSTANCES {
            return Err(HvError::LogicalFault);
        }
        
        // Check if profile fits
        let required_memory = match profile {
            mig_profile::MIG_1G_5GB => 5 * 1024 * 1024 * 1024,
            mig_profile::MIG_2G_10GB => 10 * 1024 * 1024 * 1024,
            mig_profile::MIG_3G_20GB => 20 * 1024 * 1024 * 1024,
            mig_profile::MIG_4G_20GB => 20 * 1024 * 1024 * 1024,
            mig_profile::MIG_7G_40GB => 40 * 1024 * 1024 * 1024,
            _ => return Err(HvError::LogicalFault),
        };
        
        if self.free_memory.load(Ordering::Acquire) < required_memory {
            return Err(HvError::LogicalFault);
        }
        
        let instance = &self.mig_instances[count as usize];
        instance.init(count, self.gpu_id.load(Ordering::Acquire), profile);
        
        self.free_memory.fetch_sub(required_memory, Ordering::Release);
        self.mig_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Find available MIG instance
    pub fn find_available_mig(&self, min_memory: u64) -> Option<u8> {
        for i in 0..self.mig_count.load(Ordering::Acquire) as usize {
            let instance = &self.mig_instances[i];
            if instance.is_available() && 
               instance.memory_size.load(Ordering::Acquire) >= min_memory {
                return Some(i as u8);
            }
        }
        None
    }

    /// Update utilization
    pub fn update_util(&self, compute: u8, memory: u8) {
        self.compute_util.store(compute, Ordering::Release);
        self.memory_util.store(memory, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> GpuStats {
        GpuStats {
            gpu_id: self.gpu_id.load(Ordering::Acquire),
            gpu_type: self.gpu_type.load(Ordering::Acquire),
            total_memory: self.total_memory.load(Ordering::Acquire),
            free_memory: self.free_memory.load(Ordering::Acquire),
            mig_enabled: self.mig_enabled.load(Ordering::Acquire),
            mig_count: self.mig_count.load(Ordering::Acquire),
            vgpu_count: self.vgpu_count.load(Ordering::Acquire),
            compute_util: self.compute_util.load(Ordering::Acquire),
            memory_util: self.memory_util.load(Ordering::Acquire),
            power_usage: self.power_usage.load(Ordering::Acquire),
            temperature: self.temperature.load(Ordering::Acquire),
        }
    }
}

impl Default for PhysicalGpu {
    fn default() -> Self {
        Self::new()
    }
}

/// GPU statistics
#[repr(C)]
pub struct GpuStats {
    pub gpu_id: u8,
    pub gpu_type: u16,
    pub total_memory: u64,
    pub free_memory: u64,
    pub mig_enabled: bool,
    pub mig_count: u8,
    pub vgpu_count: u8,
    pub compute_util: u8,
    pub memory_util: u8,
    pub power_usage: u32,
    pub temperature: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// vGPU Instance
// ─────────────────────────────────────────────────────────────────────────────

/// vGPU instance
pub struct VgpuInstance {
    /// vGPU ID
    pub vgpu_id: AtomicU32,
    /// VM ID
    pub vm_id: AtomicU32,
    /// Physical GPU ID
    pub gpu_id: AtomicU8,
    /// MIG instance ID (if using MIG)
    pub mig_instance: AtomicU8,
    /// Profile
    pub profile: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// Allocated memory
    pub allocated_memory: AtomicU64,
    /// Frame rate limit
    pub fps_limit: AtomicU16,
    /// Scheduling policy
    pub sched_policy: AtomicU8,
    /// Priority (0=highest, 255=lowest)
    pub priority: AtomicU8,
    /// Time slice (ms)
    pub time_slice: AtomicU32,
    /// Timeslice used (ns)
    pub timeslice_used: AtomicU64,
    /// Total GPU time (ns)
    pub total_gpu_time: AtomicU64,
    /// Total memory used
    pub memory_used: AtomicU64,
    /// Context switches
    pub context_switches: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VgpuInstance {
    pub const fn new() -> Self {
        Self {
            vgpu_id: AtomicU32::new(0),
            vm_id: AtomicU32::new(0),
            gpu_id: AtomicU8::new(0xFF),
            mig_instance: AtomicU8::new(0xFF),
            profile: AtomicU8::new(mig_profile::MIG_7G_40GB),
            state: AtomicU8::new(vgpu_state::CREATED),
            allocated_memory: AtomicU64::new(0),
            fps_limit: AtomicU16::new(60),
            sched_policy: AtomicU8::new(sched_policy::FAIR),
            priority: AtomicU8::new(128),
            time_slice: AtomicU32::new(10),
            timeslice_used: AtomicU64::new(0),
            total_gpu_time: AtomicU64::new(0),
            memory_used: AtomicU64::new(0),
            context_switches: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize vGPU
    pub fn init(&self, vgpu_id: u32, vm_id: u32, gpu_id: u8, profile: u8) {
        self.vgpu_id.store(vgpu_id, Ordering::Release);
        self.vm_id.store(vm_id, Ordering::Release);
        self.gpu_id.store(gpu_id, Ordering::Release);
        self.profile.store(profile, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set MIG instance
    pub fn set_mig(&self, mig_instance: u8) {
        self.mig_instance.store(mig_instance, Ordering::Release);
    }

    /// Set state
    pub fn set_state(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    /// Set scheduling
    pub fn set_scheduling(&self, policy: u8, priority: u8, time_slice: u32) {
        self.sched_policy.store(policy, Ordering::Release);
        self.priority.store(priority, Ordering::Release);
        self.time_slice.store(time_slice, Ordering::Release);
    }

    /// Set FPS limit
    pub fn set_fps_limit(&self, fps: u16) {
        self.fps_limit.store(fps, Ordering::Release);
    }

    /// Record GPU time
    pub fn record_gpu_time(&self, time_ns: u64) {
        self.timeslice_used.fetch_add(time_ns, Ordering::Release);
        self.total_gpu_time.fetch_add(time_ns, Ordering::Release);
    }

    /// Reset timeslice
    pub fn reset_timeslice(&self) {
        self.timeslice_used.store(0, Ordering::Release);
        self.context_switches.fetch_add(1, Ordering::Release);
    }

    /// Is timeslice exhausted
    pub fn is_timeslice_exhausted(&self) -> bool {
        let used = self.timeslice_used.load(Ordering::Acquire);
        let slice = self.time_slice.load(Ordering::Acquire) as u64 * 1_000_000;
        used >= slice
    }

    /// Get statistics
    pub fn get_stats(&self) -> VgpuStats {
        VgpuStats {
            vgpu_id: self.vgpu_id.load(Ordering::Acquire),
            vm_id: self.vm_id.load(Ordering::Acquire),
            gpu_id: self.gpu_id.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            allocated_memory: self.allocated_memory.load(Ordering::Acquire),
            total_gpu_time: self.total_gpu_time.load(Ordering::Acquire),
            context_switches: self.context_switches.load(Ordering::Acquire),
        }
    }
}

impl Default for VgpuInstance {
    fn default() -> Self {
        Self::new()
    }
}

/// vGPU statistics
#[repr(C)]
pub struct VgpuStats {
    pub vgpu_id: u32,
    pub vm_id: u32,
    pub gpu_id: u8,
    pub state: u8,
    pub allocated_memory: u64,
    pub total_gpu_time: u64,
    pub context_switches: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// vGPU Controller
// ─────────────────────────────────────────────────────────────────────────────

/// vGPU controller
pub struct VgpuController {
    /// Physical GPUs
    pub gpus: [PhysicalGpu; MAX_GPUS],
    /// GPU count
    pub gpu_count: AtomicU8,
    /// vGPU instances
    pub vgpus: [VgpuInstance; MAX_TOTAL_VGPUS],
    /// vGPU count
    pub vgpu_count: AtomicU16,
    /// Next vGPU ID
    pub next_vgpu_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// MIG enabled globally
    pub mig_enabled: AtomicBool,
    /// Default scheduling policy
    pub default_policy: AtomicU8,
    /// Default time slice (ms)
    pub default_time_slice: AtomicU32,
    /// Default FPS limit
    pub default_fps_limit: AtomicU16,
    /// Total vGPUs created
    pub total_vgpus: AtomicU64,
    /// Total GPU time (ns)
    pub total_gpu_time: AtomicU64,
    /// Total context switches
    pub total_context_switches: AtomicU64,
    /// Scheduling interval (us)
    pub sched_interval: AtomicU32,
    /// Last schedule time
    pub last_schedule: AtomicU64,
}

impl VgpuController {
    pub const fn new() -> Self {
        Self {
            gpus: [const { PhysicalGpu::new() }; MAX_GPUS],
            gpu_count: AtomicU8::new(0),
            vgpus: [const { VgpuInstance::new() }; MAX_TOTAL_VGPUS],
            vgpu_count: AtomicU16::new(0),
            next_vgpu_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            mig_enabled: AtomicBool::new(false),
            default_policy: AtomicU8::new(sched_policy::FAIR),
            default_time_slice: AtomicU32::new(10),
            default_fps_limit: AtomicU16::new(60),
            total_vgpus: AtomicU64::new(0),
            total_gpu_time: AtomicU64::new(0),
            total_context_switches: AtomicU64::new(0),
            sched_interval: AtomicU32::new(1000), // 1ms
            last_schedule: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, mig: bool, policy: u8, time_slice: u32) {
        self.mig_enabled.store(mig, Ordering::Release);
        self.default_policy.store(policy, Ordering::Release);
        self.default_time_slice.store(time_slice, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register GPU
    pub fn register_gpu(&mut self, gpu_type: u16, pci_bdf: u32, 
                        total_memory: u64, mig_supported: bool) -> Result<u8, HvError> {
        let count = self.gpu_count.load(Ordering::Acquire);
        if count as usize >= MAX_GPUS {
            return Err(HvError::LogicalFault);
        }
        
        let gpu = &self.gpus[count as usize];
        gpu.init(count, gpu_type, pci_bdf, total_memory, mig_supported);
        
        self.gpu_count.fetch_add(1, Ordering::Release);
        Ok(count)
    }

    /// Get GPU
    pub fn get_gpu(&self, gpu_id: u8) -> Option<&PhysicalGpu> {
        if gpu_id as usize >= MAX_GPUS {
            return None;
        }
        Some(&self.gpus[gpu_id as usize])
    }

    /// Enable MIG on GPU
    pub fn enable_mig(&self, gpu_id: u8) -> Result<(), HvError> {
        let gpu = self.get_gpu(gpu_id).ok_or(HvError::LogicalFault)?;
        gpu.enable_mig()
    }

    /// Create MIG instance
    pub fn create_mig(&self, gpu_id: u8, profile: u8) -> Result<u8, HvError> {
        let gpu = self.get_gpu(gpu_id).ok_or(HvError::LogicalFault)?;
        gpu.create_mig_instance(profile)
    }

    /// Create vGPU
    pub fn create_vgpu(&mut self, vm_id: u32, profile: u8, 
                        min_memory: u64) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.vgpu_count.load(Ordering::Acquire);
        if count as usize >= MAX_TOTAL_VGPUS {
            return Err(HvError::LogicalFault);
        }
        
        // Find suitable GPU
        let mut best_gpu: Option<u8> = None;
        let mut best_score = 0u32;
        
        for i in 0..self.gpu_count.load(Ordering::Acquire) as usize {
            let gpu = &self.gpus[i];
            
            // Check MIG first if enabled
            if self.mig_enabled.load(Ordering::Acquire) && gpu.mig_enabled.load(Ordering::Acquire) {
                if let Some(mig_idx) = gpu.find_available_mig(min_memory) {
                    let score = (100 - gpu.compute_util.load(Ordering::Acquire)) as u32;
                    if score > best_score {
                        best_score = score;
                        best_gpu = Some(i as u8);
                    }
                }
            } else {
                // Non-MIG: check free memory
                if gpu.free_memory.load(Ordering::Acquire) >= min_memory {
                    let score = (100 - gpu.compute_util.load(Ordering::Acquire)) as u32 +
                                (100 - gpu.memory_util.load(Ordering::Acquire)) as u32;
                    if score > best_score {
                        best_score = score;
                        best_gpu = Some(i as u8);
                    }
                }
            }
        }
        
        let gpu_id = best_gpu.ok_or(HvError::LogicalFault)?;
        let gpu = &self.gpus[gpu_id as usize];
        
        let vgpu_id = self.next_vgpu_id.fetch_add(1, Ordering::Release);
        let vgpu = &self.vgpus[count as usize];
        vgpu.init(vgpu_id, vm_id, gpu_id, profile);
        vgpu.set_scheduling(
            self.default_policy.load(Ordering::Acquire),
            128,
            self.default_time_slice.load(Ordering::Acquire)
        );
        vgpu.set_fps_limit(self.default_fps_limit.load(Ordering::Acquire));
        
        // Assign MIG instance if available
        if gpu.mig_enabled.load(Ordering::Acquire) {
            if let Some(mig_idx) = gpu.find_available_mig(min_memory) {
                vgpu.set_mig(mig_idx);
                gpu.mig_instances[mig_idx as usize].assign(vgpu_id)?;
            }
        }
        
        gpu.vgpu_count.fetch_add(1, Ordering::Release);
        gpu.free_memory.fetch_sub(min_memory, Ordering::Release);
        vgpu.allocated_memory.store(min_memory, Ordering::Release);
        
        self.vgpu_count.fetch_add(1, Ordering::Release);
        self.total_vgpus.fetch_add(1, Ordering::Release);
        
        Ok(vgpu_id)
    }

    /// Get vGPU
    pub fn get_vgpu(&self, vgpu_id: u32) -> Option<&VgpuInstance> {
        for i in 0..self.vgpu_count.load(Ordering::Acquire) as usize {
            if self.vgpus[i].vgpu_id.load(Ordering::Acquire) == vgpu_id {
                return Some(&self.vgpus[i]);
            }
        }
        None
    }

    /// Start vGPU
    pub fn start_vgpu(&self, vgpu_id: u32) -> Result<(), HvError> {
        let vgpu = self.get_vgpu(vgpu_id).ok_or(HvError::LogicalFault)?;
        vgpu.set_state(vgpu_state::RUNNING);
        Ok(())
    }

    /// Stop vGPU
    pub fn stop_vgpu(&self, vgpu_id: u32) -> Result<(), HvError> {
        let vgpu = self.get_vgpu(vgpu_id).ok_or(HvError::LogicalFault)?;
        vgpu.set_state(vgpu_state::STOPPED);
        Ok(())
    }

    /// Pause vGPU
    pub fn pause_vgpu(&self, vgpu_id: u32) -> Result<(), HvError> {
        let vgpu = self.get_vgpu(vgpu_id).ok_or(HvError::LogicalFault)?;
        vgpu.set_state(vgpu_state::PAUSED);
        Ok(())
    }

    /// Resume vGPU
    pub fn resume_vgpu(&self, vgpu_id: u32) -> Result<(), HvError> {
        let vgpu = self.get_vgpu(vgpu_id).ok_or(HvError::LogicalFault)?;
        vgpu.set_state(vgpu_state::RUNNING);
        Ok(())
    }

    /// Delete vGPU
    pub fn delete_vgpu(&mut self, vgpu_id: u32) -> Result<(), HvError> {
        let vgpu = self.get_vgpu(vgpu_id).ok_or(HvError::LogicalFault)?;
        
        // Release MIG instance
        let gpu_id = vgpu.gpu_id.load(Ordering::Acquire);
        let mig_idx = vgpu.mig_instance.load(Ordering::Acquire);
        
        if mig_idx != 0xFF {
            if let Some(gpu) = self.get_gpu(gpu_id) {
                gpu.mig_instances[mig_idx as usize].release();
            }
        }
        
        // Update GPU stats
        if let Some(gpu) = self.get_gpu(gpu_id) {
            gpu.vgpu_count.fetch_sub(1, Ordering::Release);
            gpu.free_memory.fetch_add(vgpu.allocated_memory.load(Ordering::Acquire), Ordering::Release);
        }
        
        vgpu.valid.store(false, Ordering::Release);
        vgpu.set_state(vgpu_state::STOPPED);
        
        Ok(())
    }

    /// Run scheduler
    pub fn run_scheduler(&mut self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) {
            return 0;
        }
        
        let now = Self::get_timestamp();
        let interval = self.sched_interval.load(Ordering::Acquire) as u64 * 1000;
        
        if now - self.last_schedule.load(Ordering::Acquire) < interval {
            return 0;
        }
        
        self.last_schedule.store(now, Ordering::Release);
        
        let mut switches = 0u32;
        
        // Check each vGPU
        for i in 0..self.vgpu_count.load(Ordering::Acquire) as usize {
            let vgpu = &self.vgpus[i];
            
            if vgpu.state.load(Ordering::Acquire) != vgpu_state::RUNNING {
                continue;
            }
            
            // Check timeslice
            if vgpu.is_timeslice_exhausted() {
                vgpu.reset_timeslice();
                switches += 1;
                self.total_context_switches.fetch_add(1, Ordering::Release);
            }
        }
        
        switches
    }

    /// Get statistics
    pub fn get_stats(&self) -> VgpuControllerStats {
        let mut running_vgpus = 0u16;
        let mut total_memory = 0u64;
        
        for i in 0..self.vgpu_count.load(Ordering::Acquire) as usize {
            let vgpu = &self.vgpus[i];
            if vgpu.valid.load(Ordering::Acquire) {
                if vgpu.state.load(Ordering::Acquire) == vgpu_state::RUNNING {
                    running_vgpus += 1;
                }
                total_memory += vgpu.allocated_memory.load(Ordering::Acquire);
            }
        }
        
        VgpuControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            gpu_count: self.gpu_count.load(Ordering::Acquire),
            vgpu_count: self.vgpu_count.load(Ordering::Acquire),
            running_vgpus,
            mig_enabled: self.mig_enabled.load(Ordering::Acquire),
            total_vgpus: self.total_vgpus.load(Ordering::Acquire),
            total_memory,
            total_gpu_time: self.total_gpu_time.load(Ordering::Acquire),
            total_context_switches: self.total_context_switches.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for VgpuController {
    fn default() -> Self {
        Self::new()
    }
}

/// vGPU controller statistics
#[repr(C)]
pub struct VgpuControllerStats {
    pub enabled: bool,
    pub gpu_count: u8,
    pub vgpu_count: u16,
    pub running_vgpus: u16,
    pub mig_enabled: bool,
    pub total_vgpus: u64,
    pub total_memory: u64,
    pub total_gpu_time: u64,
    pub total_context_switches: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_gpu() {
        let mut ctrl = VgpuController::new();
        ctrl.enable(true, sched_policy::FAIR, 10);
        
        let id = ctrl.register_gpu(gpu_type::NVIDIA_A100_40GB, 0x000010DE, 
                                    40 * 1024 * 1024 * 1024, true).unwrap();
        assert_eq!(ctrl.gpu_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn enable_mig() {
        let mut ctrl = VgpuController::new();
        ctrl.enable(true, sched_policy::FAIR, 10);
        ctrl.register_gpu(gpu_type::NVIDIA_A100_40GB, 0x000010DE, 
                          40 * 1024 * 1024 * 1024, true).unwrap();
        
        ctrl.enable_mig(0).unwrap();
        
        let gpu = ctrl.get_gpu(0).unwrap();
        assert!(gpu.mig_enabled.load(Ordering::Acquire));
    }

    #[test]
    fn create_mig_instance() {
        let mut ctrl = VgpuController::new();
        ctrl.enable(true, sched_policy::FAIR, 10);
        ctrl.register_gpu(gpu_type::NVIDIA_A100_40GB, 0x000010DE, 
                          40 * 1024 * 1024 * 1024, true).unwrap();
        ctrl.enable_mig(0).unwrap();
        
        let idx = ctrl.create_mig(0, mig_profile::MIG_2G_10GB).unwrap();
        
        let gpu = ctrl.get_gpu(0).unwrap();
        assert_eq!(gpu.mig_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn create_vgpu() {
        let mut ctrl = VgpuController::new();
        ctrl.enable(true, sched_policy::FAIR, 10);
        ctrl.register_gpu(gpu_type::NVIDIA_A100_40GB, 0x000010DE, 
                          40 * 1024 * 1024 * 1024, true).unwrap();
        ctrl.enable_mig(0).unwrap();
        ctrl.create_mig(0, mig_profile::MIG_2G_10GB).unwrap();
        
        let vgpu_id = ctrl.create_vgpu(1, mig_profile::MIG_2G_10GB, 
                                        10 * 1024 * 1024 * 1024).unwrap();
        
        assert_eq!(ctrl.vgpu_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn vgpu_states() {
        let mut ctrl = VgpuController::new();
        ctrl.enable(true, sched_policy::FAIR, 10);
        ctrl.register_gpu(gpu_type::NVIDIA_A100_40GB, 0x000010DE, 
                          40 * 1024 * 1024 * 1024, true).unwrap();
        ctrl.enable_mig(0).unwrap();
        ctrl.create_mig(0, mig_profile::MIG_2G_10GB).unwrap();
        
        let vgpu_id = ctrl.create_vgpu(1, mig_profile::MIG_2G_10GB, 
                                        10 * 1024 * 1024 * 1024).unwrap();
        
        ctrl.start_vgpu(vgpu_id).unwrap();
        let vgpu = ctrl.get_vgpu(vgpu_id).unwrap();
        assert_eq!(vgpu.state.load(Ordering::Acquire), vgpu_state::RUNNING);
        
        ctrl.pause_vgpu(vgpu_id).unwrap();
        assert_eq!(vgpu.state.load(Ordering::Acquire), vgpu_state::PAUSED);
        
        ctrl.resume_vgpu(vgpu_id).unwrap();
        assert_eq!(vgpu.state.load(Ordering::Acquire), vgpu_state::RUNNING);
    }

    #[test]
    fn timeslice() {
        let vgpu = VgpuInstance::new();
        vgpu.init(1, 1, 0, mig_profile::MIG_2G_10GB);
        vgpu.set_scheduling(sched_policy::FAIR, 128, 10);
        
        // Record GPU time
        vgpu.record_gpu_time(5_000_000); // 5ms
        assert!(!vgpu.is_timeslice_exhausted());
        
        vgpu.record_gpu_time(5_000_000); // Total 10ms
        assert!(vgpu.is_timeslice_exhausted());
        
        vgpu.reset_timeslice();
        assert!(!vgpu.is_timeslice_exhausted());
    }
}
