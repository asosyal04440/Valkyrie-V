//! MicroVM Mode - Firecracker-style Fast Boot
//!
//! Lightweight VM configuration optimized for fast boot and minimal overhead.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// MicroVM Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum MicroVMs
pub const MAX_MICROVMS: usize = 1024;

/// Maximum vCPUs per MicroVM
pub const MAX_MICROVM_VCPUS: usize = 8;

/// Maximum memory slots
pub const MAX_MEM_SLOTS: usize = 8;

/// Maximum devices
pub const MAX_MICROVM_DEVICES: usize = 16;

/// Boot timeout (ms)
pub const DEFAULT_BOOT_TIMEOUT_MS: u64 = 1000;

/// MicroVM states
pub mod microvm_state {
    pub const CREATED: u8 = 0;
    pub const CONFIGURING: u8 = 1;
    pub const READY: u8 = 2;
    pub const STARTING: u8 = 3;
    pub const RUNNING: u8 = 4;
    pub const PAUSED: u8 = 5;
    pub const STOPPING: u8 = 6;
    pub const STOPPED: u8 = 7;
    pub const ERROR: u8 = 8;
}

/// Boot sources
pub mod boot_source {
    pub const KERNEL: u8 = 0;
    pub const INITRD: u8 = 1;
    pub const KERNEL_DIRECT: u8 = 2;
}

/// Device types
pub mod microvm_dev_type {
    pub const SERIAL: u8 = 0;
    pub const BLOCK: u8 = 1;
    pub const NET: u8 = 2;
    pub const VSOCK: u8 = 3;
    pub const BALLOON: u8 = 4;
    pub const RNG: u8 = 5;
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Slot
// ─────────────────────────────────────────────────────────────────────────────

/// Memory slot for MicroVM
pub struct MemSlot {
    /// Slot ID
    pub slot_id: AtomicU8,
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Host physical address
    pub hpa: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// Flags
    pub flags: AtomicU32,
    /// Valid
    pub valid: AtomicBool,
}

impl MemSlot {
    pub const fn new() -> Self {
        Self {
            slot_id: AtomicU8::new(0),
            gpa: AtomicU64::new(0),
            hpa: AtomicU64::new(0),
            size: AtomicU64::new(0),
            flags: AtomicU32::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize slot
    pub fn init(&self, slot_id: u8, gpa: u64, hpa: u64, size: u64) {
        self.slot_id.store(slot_id, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.hpa.store(hpa, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }
}

impl Default for MemSlot {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MicroVM Device
// ─────────────────────────────────────────────────────────────────────────────

/// MicroVM device
pub struct MicroVmDevice {
    /// Device ID
    pub device_id: AtomicU32,
    /// Device type
    pub device_type: AtomicU8,
    /// Device index (for multiple of same type)
    pub device_idx: AtomicU8,
    /// PCI slot
    pub pci_slot: AtomicU8,
    /// PCI function
    pub pci_func: AtomicU8,
    /// Enabled
    pub enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl MicroVmDevice {
    pub const fn new() -> Self {
        Self {
            device_id: AtomicU32::new(0),
            device_type: AtomicU8::new(0),
            device_idx: AtomicU8::new(0),
            pci_slot: AtomicU8::new(0),
            pci_func: AtomicU8::new(0),
            enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize device
    pub fn init(&self, device_id: u32, device_type: u8, idx: u8) {
        self.device_id.store(device_id, Ordering::Release);
        self.device_type.store(device_type, Ordering::Release);
        self.device_idx.store(idx, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set PCI address
    pub fn set_pci(&self, slot: u8, func: u8) {
        self.pci_slot.store(slot, Ordering::Release);
        self.pci_func.store(func, Ordering::Release);
    }
}

impl Default for MicroVmDevice {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MicroVM vCPU
// ─────────────────────────────────────────────────────────────────────────────

/// MicroVM vCPU state
pub struct MicroVmCpu {
    /// vCPU ID
    pub vcpu_id: AtomicU8,
    /// CPU type
    pub cpu_type: AtomicU8,
    /// APIC ID
    pub apic_id: AtomicU32,
    /// State
    pub state: AtomicU8,
    /// Pending interrupt
    pub pending_irq: AtomicU8,
    /// Run count
    pub run_count: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl MicroVmCpu {
    pub const fn new() -> Self {
        Self {
            vcpu_id: AtomicU8::new(0),
            cpu_type: AtomicU8::new(0),
            apic_id: AtomicU32::new(0),
            state: AtomicU8::new(0),
            pending_irq: AtomicU8::new(0),
            run_count: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize vCPU
    pub fn init(&self, vcpu_id: u8, apic_id: u32) {
        self.vcpu_id.store(vcpu_id, Ordering::Release);
        self.apic_id.store(apic_id, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }
}

impl Default for MicroVmCpu {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MicroVM Instance
// ─────────────────────────────────────────────────────────────────────────────

/// MicroVM instance
pub struct MicroVmInstance {
    /// VM ID
    pub vm_id: AtomicU32,
    /// Instance ID (user-provided name hash)
    pub instance_id: AtomicU64,
    /// State
    pub state: AtomicU8,
    /// vCPUs
    pub vcpus: [MicroVmCpu; MAX_MICROVM_VCPUS],
    /// vCPU count
    pub vcpu_count: AtomicU8,
    /// Memory slots
    pub mem_slots: [MemSlot; MAX_MEM_SLOTS],
    /// Memory slot count
    pub mem_slot_count: AtomicU8,
    /// Total memory (bytes)
    pub total_memory: AtomicU64,
    /// Devices
    pub devices: [MicroVmDevice; MAX_MICROVM_DEVICES],
    /// Device count
    pub device_count: AtomicU8,
    /// Kernel GPA
    pub kernel_gpa: AtomicU64,
    /// Kernel size
    pub kernel_size: AtomicU64,
    /// Initrd GPA
    pub initrd_gpa: AtomicU64,
    /// Initrd size
    pub initrd_size: AtomicU64,
    /// Cmdline GPA
    pub cmdline_gpa: AtomicU64,
    /// Cmdline size
    pub cmdline_size: AtomicU64,
    /// Entry point
    pub entry_point: AtomicU64,
    /// Boot time (ns)
    pub boot_time: AtomicU64,
    /// Creation time
    pub creation_time: AtomicU64,
    /// Start time
    pub start_time: AtomicU64,
    /// Stop time
    pub stop_time: AtomicU64,
    /// Serial console enabled
    pub serial_enabled: AtomicBool,
    /// Metrics enabled
    pub metrics_enabled: AtomicBool,
    /// Valid
    pub valid: AtomicBool,
}

impl MicroVmInstance {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            instance_id: AtomicU64::new(0),
            state: AtomicU8::new(microvm_state::CREATED),
            vcpus: [const { MicroVmCpu::new() }; MAX_MICROVM_VCPUS],
            vcpu_count: AtomicU8::new(0),
            mem_slots: [const { MemSlot::new() }; MAX_MEM_SLOTS],
            mem_slot_count: AtomicU8::new(0),
            total_memory: AtomicU64::new(0),
            devices: [const { MicroVmDevice::new() }; MAX_MICROVM_DEVICES],
            device_count: AtomicU8::new(0),
            kernel_gpa: AtomicU64::new(0),
            kernel_size: AtomicU64::new(0),
            initrd_gpa: AtomicU64::new(0),
            initrd_size: AtomicU64::new(0),
            cmdline_gpa: AtomicU64::new(0),
            cmdline_size: AtomicU64::new(0),
            entry_point: AtomicU64::new(0),
            boot_time: AtomicU64::new(0),
            creation_time: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
            stop_time: AtomicU64::new(0),
            serial_enabled: AtomicBool::new(false),
            metrics_enabled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize instance
    pub fn init(&self, vm_id: u32, instance_id: u64) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.instance_id.store(instance_id, Ordering::Release);
        self.creation_time.store(Self::get_timestamp(), Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add vCPU
    pub fn add_vcpu(&self, apic_id: u32) -> Result<u8, HvError> {
        let count = self.vcpu_count.load(Ordering::Acquire);
        if count as usize >= MAX_MICROVM_VCPUS {
            return Err(HvError::LogicalFault);
        }
        
        self.vcpus[count as usize].init(count, apic_id);
        self.vcpu_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Add memory slot
    pub fn add_mem_slot(&self, gpa: u64, hpa: u64, size: u64) -> Result<u8, HvError> {
        let count = self.mem_slot_count.load(Ordering::Acquire);
        if count as usize >= MAX_MEM_SLOTS {
            return Err(HvError::LogicalFault);
        }
        
        self.mem_slots[count as usize].init(count, gpa, hpa, size);
        self.mem_slot_count.fetch_add(1, Ordering::Release);
        self.total_memory.fetch_add(size, Ordering::Release);
        
        Ok(count)
    }

    /// Add device
    pub fn add_device(&self, device_type: u8, device_id: u32) -> Result<u8, HvError> {
        let count = self.device_count.load(Ordering::Acquire);
        if count as usize >= MAX_MICROVM_DEVICES {
            return Err(HvError::LogicalFault);
        }
        
        // Count devices of same type
        let mut type_count = 0u8;
        for i in 0..count as usize {
            if self.devices[i].device_type.load(Ordering::Acquire) == device_type {
                type_count += 1;
            }
        }
        
        self.devices[count as usize].init(device_id, device_type, type_count);
        self.device_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Set kernel
    pub fn set_kernel(&self, gpa: u64, size: u64, entry: u64) {
        self.kernel_gpa.store(gpa, Ordering::Release);
        self.kernel_size.store(size, Ordering::Release);
        self.entry_point.store(entry, Ordering::Release);
    }

    /// Set initrd
    pub fn set_initrd(&self, gpa: u64, size: u64) {
        self.initrd_gpa.store(gpa, Ordering::Release);
        self.initrd_size.store(size, Ordering::Release);
    }

    /// Set cmdline
    pub fn set_cmdline(&self, gpa: u64, size: u64) {
        self.cmdline_gpa.store(gpa, Ordering::Release);
        self.cmdline_size.store(size, Ordering::Release);
    }

    /// Configure complete
    pub fn configure_done(&self) {
        self.state.store(microvm_state::READY, Ordering::Release);
    }

    /// Start VM
    pub fn start(&self) -> Result<(), HvError> {
        let state = self.state.load(Ordering::Acquire);
        if state != microvm_state::READY && state != microvm_state::STOPPED {
            return Err(HvError::LogicalFault);
        }
        
        self.state.store(microvm_state::STARTING, Ordering::Release);
        self.start_time.store(Self::get_timestamp(), Ordering::Release);
        
        // Enable all devices
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            self.devices[i].enabled.store(true, Ordering::Release);
        }
        
        self.state.store(microvm_state::RUNNING, Ordering::Release);
        
        // Calculate boot time
        let boot_ns = Self::get_timestamp() - self.start_time.load(Ordering::Acquire);
        self.boot_time.store(boot_ns, Ordering::Release);
        
        Ok(())
    }

    /// Stop VM
    pub fn stop(&self) -> Result<(), HvError> {
        let state = self.state.load(Ordering::Acquire);
        if state != microvm_state::RUNNING && state != microvm_state::PAUSED {
            return Err(HvError::LogicalFault);
        }
        
        self.state.store(microvm_state::STOPPING, Ordering::Release);
        self.stop_time.store(Self::get_timestamp(), Ordering::Release);
        
        // Disable all devices
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            self.devices[i].enabled.store(false, Ordering::Release);
        }
        
        self.state.store(microvm_state::STOPPED, Ordering::Release);
        Ok(())
    }

    /// Pause VM
    pub fn pause(&self) -> Result<(), HvError> {
        if self.state.load(Ordering::Acquire) != microvm_state::RUNNING {
            return Err(HvError::LogicalFault);
        }
        
        self.state.store(microvm_state::PAUSED, Ordering::Release);
        Ok(())
    }

    /// Resume VM
    pub fn resume(&self) -> Result<(), HvError> {
        if self.state.load(Ordering::Acquire) != microvm_state::PAUSED {
            return Err(HvError::LogicalFault);
        }
        
        self.state.store(microvm_state::RUNNING, Ordering::Release);
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> MicroVmStats {
        MicroVmStats {
            vm_id: self.vm_id.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            vcpu_count: self.vcpu_count.load(Ordering::Acquire),
            total_memory: self.total_memory.load(Ordering::Acquire),
            device_count: self.device_count.load(Ordering::Acquire),
            boot_time_ns: self.boot_time.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for MicroVmInstance {
    fn default() -> Self {
        Self::new()
    }
}

/// MicroVM statistics
#[repr(C)]
pub struct MicroVmStats {
    pub vm_id: u32,
    pub state: u8,
    pub vcpu_count: u8,
    pub total_memory: u64,
    pub device_count: u8,
    pub boot_time_ns: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MicroVM Controller
// ─────────────────────────────────────────────────────────────────────────────

/// MicroVM controller
pub struct MicroVmController {
    /// MicroVM instances
    pub instances: [MicroVmInstance; MAX_MICROVMS],
    /// Instance count
    pub instance_count: AtomicU16,
    /// Next VM ID
    pub next_vm_id: AtomicU32,
    /// Enabled
    pub enabled: AtomicBool,
    /// Fast boot enabled
    pub fast_boot: AtomicBool,
    /// Minimal devices
    pub minimal_devices: AtomicBool,
    /// Serial console
    pub serial_console: AtomicBool,
    /// Metrics collection
    pub metrics: AtomicBool,
    /// Boot timeout (ms)
    pub boot_timeout_ms: AtomicU64,
    /// Total VMs created
    pub total_created: AtomicU64,
    /// Total VMs started
    pub total_started: AtomicU64,
    /// Total VMs stopped
    pub total_stopped: AtomicU64,
    /// Total boot time (ns)
    pub total_boot_time: AtomicU64,
    /// Fastest boot (ns)
    pub fastest_boot: AtomicU64,
    /// Slowest boot (ns)
    pub slowest_boot: AtomicU64,
}

impl MicroVmController {
    pub const fn new() -> Self {
        Self {
            instances: [const { MicroVmInstance::new() }; MAX_MICROVMS],
            instance_count: AtomicU16::new(0),
            next_vm_id: AtomicU32::new(1),
            enabled: AtomicBool::new(false),
            fast_boot: AtomicBool::new(true),
            minimal_devices: AtomicBool::new(true),
            serial_console: AtomicBool::new(false),
            metrics: AtomicBool::new(true),
            boot_timeout_ms: AtomicU64::new(DEFAULT_BOOT_TIMEOUT_MS),
            total_created: AtomicU64::new(0),
            total_started: AtomicU64::new(0),
            total_stopped: AtomicU64::new(0),
            total_boot_time: AtomicU64::new(0),
            fastest_boot: AtomicU64::new(u64::MAX),
            slowest_boot: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, fast_boot: bool, minimal_devices: bool, serial: bool, metrics: bool) {
        self.fast_boot.store(fast_boot, Ordering::Release);
        self.minimal_devices.store(minimal_devices, Ordering::Release);
        self.serial_console.store(serial, Ordering::Release);
        self.metrics.store(metrics, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Create MicroVM
    pub fn create(&mut self, instance_id: u64, vcpu_count: u8, 
                  mem_size: u64) -> Result<u32, HvError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        let count = self.instance_count.load(Ordering::Acquire);
        if count as usize >= MAX_MICROVMS {
            return Err(HvError::LogicalFault);
        }
        
        let vm_id = self.next_vm_id.fetch_add(1, Ordering::Release);
        let instance = &self.instances[count as usize];
        instance.init(vm_id, instance_id);
        
        // Add vCPUs
        for i in 0..vcpu_count {
            instance.add_vcpu(i as u32)?;
        }
        
        // Add memory (single slot for simplicity)
        let gpa = 0x80000000; // 2GB base
        instance.add_mem_slot(gpa, 0, mem_size)?;
        
        // Add minimal devices
        if self.minimal_devices.load(Ordering::Acquire) {
            // Serial console
            if self.serial_console.load(Ordering::Acquire) {
                instance.add_device(microvm_dev_type::SERIAL, 1)?;
            }
            
            // Block device
            instance.add_device(microvm_dev_type::BLOCK, 1)?;
            
            // Network device
            instance.add_device(microvm_dev_type::NET, 1)?;
            
            // RNG
            instance.add_device(microvm_dev_type::RNG, 1)?;
        }
        
        instance.serial_enabled.store(self.serial_console.load(Ordering::Acquire), Ordering::Release);
        instance.metrics_enabled.store(self.metrics.load(Ordering::Acquire), Ordering::Release);
        
        self.instance_count.fetch_add(1, Ordering::Release);
        self.total_created.fetch_add(1, Ordering::Release);
        
        Ok(vm_id)
    }

    /// Get instance
    pub fn get_instance(&self, vm_id: u32) -> Option<&MicroVmInstance> {
        for i in 0..self.instance_count.load(Ordering::Acquire) as usize {
            if self.instances[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.instances[i]);
            }
        }
        None
    }

    /// Configure kernel
    pub fn configure_kernel(&self, vm_id: u32, gpa: u64, size: u64, 
                            entry: u64) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.set_kernel(gpa, size, entry);
        Ok(())
    }

    /// Configure initrd
    pub fn configure_initrd(&self, vm_id: u32, gpa: u64, size: u64) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.set_initrd(gpa, size);
        Ok(())
    }

    /// Configure cmdline
    pub fn configure_cmdline(&self, vm_id: u32, gpa: u64, size: u64) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.set_cmdline(gpa, size);
        Ok(())
    }

    /// Add device
    pub fn add_device(&self, vm_id: u32, device_type: u8, 
                      device_id: u32) -> Result<u8, HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.add_device(device_type, device_id)
    }

    /// Configure complete
    pub fn configure_done(&self, vm_id: u32) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.configure_done();
        Ok(())
    }

    /// Start MicroVM
    pub fn start(&self, vm_id: u32) -> Result<u64, HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.start()?;
        
        self.total_started.fetch_add(1, Ordering::Release);
        
        let boot_time = instance.boot_time.load(Ordering::Acquire);
        self.total_boot_time.fetch_add(boot_time, Ordering::Release);
        
        // Update fastest/slowest
        loop {
            let fastest = self.fastest_boot.load(Ordering::Acquire);
            if boot_time >= fastest {
                break;
            }
            if self.fastest_boot.compare_exchange(fastest, boot_time, Ordering::Release, Ordering::Acquire).is_ok() {
                break;
            }
        }
        
        loop {
            let slowest = self.slowest_boot.load(Ordering::Acquire);
            if boot_time <= slowest {
                break;
            }
            if self.slowest_boot.compare_exchange(slowest, boot_time, Ordering::Release, Ordering::Acquire).is_ok() {
                break;
            }
        }
        
        Ok(boot_time)
    }

    /// Stop MicroVM
    pub fn stop(&self, vm_id: u32) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.stop()?;
        
        self.total_stopped.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Pause MicroVM
    pub fn pause(&self, vm_id: u32) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.pause()
    }

    /// Resume MicroVM
    pub fn resume(&self, vm_id: u32) -> Result<(), HvError> {
        let instance = self.get_instance(vm_id).ok_or(HvError::LogicalFault)?;
        instance.resume()
    }

    /// Destroy MicroVM
    pub fn destroy(&mut self, vm_id: u32) -> Result<(), HvError> {
        for i in 0..self.instance_count.load(Ordering::Acquire) as usize {
            if self.instances[i].vm_id.load(Ordering::Acquire) == vm_id {
                let instance = &self.instances[i];
                
                // Stop if running
                if instance.state.load(Ordering::Acquire) == microvm_state::RUNNING {
                    instance.stop()?;
                }
                
                instance.valid.store(false, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Get statistics
    pub fn get_stats(&self) -> MicroVmControllerStats {
        let mut running = 0u16;
        let mut paused = 0u16;
        let mut stopped = 0u16;
        
        for i in 0..self.instance_count.load(Ordering::Acquire) as usize {
            match self.instances[i].state.load(Ordering::Acquire) {
                microvm_state::RUNNING => running += 1,
                microvm_state::PAUSED => paused += 1,
                microvm_state::STOPPED => stopped += 1,
                _ => {}
            }
        }
        
        let total_started = self.total_started.load(Ordering::Acquire);
        let avg_boot = if total_started > 0 {
            self.total_boot_time.load(Ordering::Acquire) / total_started
        } else {
            0
        };
        
        MicroVmControllerStats {
            enabled: self.enabled.load(Ordering::Acquire),
            instance_count: self.instance_count.load(Ordering::Acquire),
            running,
            paused,
            stopped,
            total_created: self.total_created.load(Ordering::Acquire),
            total_started: self.total_started.load(Ordering::Acquire),
            total_stopped: self.total_stopped.load(Ordering::Acquire),
            avg_boot_time_ns: avg_boot,
            fastest_boot_ns: self.fastest_boot.load(Ordering::Acquire),
            slowest_boot_ns: self.slowest_boot.load(Ordering::Acquire),
        }
    }
}

impl Default for MicroVmController {
    fn default() -> Self {
        Self::new()
    }
}

/// MicroVM controller statistics
#[repr(C)]
pub struct MicroVmControllerStats {
    pub enabled: bool,
    pub instance_count: u16,
    pub running: u16,
    pub paused: u16,
    pub stopped: u16,
    pub total_created: u64,
    pub total_started: u64,
    pub total_stopped: u64,
    pub avg_boot_time_ns: u64,
    pub fastest_boot_ns: u64,
    pub slowest_boot_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_microvm() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, false, true);
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        assert_eq!(ctrl.instance_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn configure_kernel() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, false, true);
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        ctrl.configure_kernel(vm_id, 0x80000000, 8 * 1024 * 1024, 0x80000000).unwrap();
        
        let instance = ctrl.get_instance(vm_id).unwrap();
        assert!(instance.kernel_size.load(Ordering::Acquire) > 0);
    }

    #[test]
    fn start_stop() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, false, true);
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        ctrl.configure_kernel(vm_id, 0x80000000, 8 * 1024 * 1024, 0x80000000).unwrap();
        ctrl.configure_done(vm_id).unwrap();
        
        let boot_time = ctrl.start(vm_id).unwrap();
        assert!(boot_time >= 0);
        
        let instance = ctrl.get_instance(vm_id).unwrap();
        assert_eq!(instance.state.load(Ordering::Acquire), microvm_state::RUNNING);
        
        ctrl.stop(vm_id).unwrap();
        assert_eq!(instance.state.load(Ordering::Acquire), microvm_state::STOPPED);
    }

    #[test]
    fn pause_resume() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, false, true);
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        ctrl.configure_kernel(vm_id, 0x80000000, 8 * 1024 * 1024, 0x80000000).unwrap();
        ctrl.configure_done(vm_id).unwrap();
        ctrl.start(vm_id).unwrap();
        
        ctrl.pause(vm_id).unwrap();
        let instance = ctrl.get_instance(vm_id).unwrap();
        assert_eq!(instance.state.load(Ordering::Acquire), microvm_state::PAUSED);
        
        ctrl.resume(vm_id).unwrap();
        assert_eq!(instance.state.load(Ordering::Acquire), microvm_state::RUNNING);
    }

    #[test]
    fn add_devices() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, true, true); // Enable minimal devices and serial
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        
        ctrl.add_device(vm_id, microvm_dev_type::BLOCK, 1).unwrap();
        ctrl.add_device(vm_id, microvm_dev_type::NET, 1).unwrap();
        ctrl.add_device(vm_id, microvm_dev_type::NET, 2).unwrap();
        
        let instance = ctrl.get_instance(vm_id).unwrap();
        // 3 minimal devices (serial, block, net) + 3 added = 6 total
        assert!(instance.device_count.load(Ordering::Acquire) >= 3);
    }

    #[test]
    fn boot_time_tracking() {
        let mut ctrl = MicroVmController::new();
        ctrl.enable(true, true, false, true);
        
        let vm_id = ctrl.create(0x12345678, 2, 128 * 1024 * 1024).unwrap();
        ctrl.configure_kernel(vm_id, 0x80000000, 8 * 1024 * 1024, 0x80000000).unwrap();
        ctrl.configure_done(vm_id).unwrap();
        
        ctrl.start(vm_id).unwrap();
        
        let stats = ctrl.get_stats();
        assert!(stats.total_started > 0);
        assert!(stats.fastest_boot_ns < u64::MAX);
    }
}
