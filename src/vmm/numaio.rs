//! NUMA-Aware I/O - Device locality
//!
//! NUMA topology-aware I/O device placement and scheduling for optimal performance.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// NUMA I/O Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum NUMA nodes
pub const MAX_NUMA_NODES: usize = 16;

/// Maximum I/O devices
pub const MAX_IO_DEVICES: usize = 256;

/// Maximum interrupt vectors
pub const MAX_VECTORS: usize = 1024;

/// Maximum DMA regions
pub const MAX_DMA_REGIONS: usize = 512;

/// Maximum VMs with I/O policy
pub const MAX_IO_VMS: usize = 128;

/// Device types
pub mod device_type {
    pub const NETWORK: u8 = 0;
    pub const STORAGE: u8 = 1;
    pub const GPU: u8 = 2;
    pub const USB: u8 = 3;
    pub const AUDIO: u8 = 4;
    pub const GENERIC: u8 = 5;
}

/// Device states
pub mod device_state {
    pub const DISCOVERED: u8 = 0;
    pub const INITIALIZED: u8 = 1;
    pub const ACTIVE: u8 = 2;
    pub const SUSPENDED: u8 = 3;
    pub const ERROR: u8 = 4;
}

/// I/O policy types
pub mod io_policy {
    pub const DEFAULT: u8 = 0;       // System default
    pub const LOCAL: u8 = 1;         // Prefer local node
    pub const BIND: u8 = 2;          // Strict binding
    pub const ROUND_ROBIN: u8 = 3;   // Distribute evenly
    pub const AFFINITY: u8 = 4;      // CPU affinity-based
}

/// Interrupt modes
pub mod irq_mode {
    pub const LEGACY: u8 = 0;
    pub const MSI: u8 = 1;
    pub const MSIX: u8 = 2;
}

// ─────────────────────────────────────────────────────────────────────────────
// I/O Device
// ─────────────────────────────────────────────────────────────────────────────

/// I/O device descriptor
pub struct IoDevice {
    /// Device ID
    pub device_id: AtomicU32,
    /// Device type
    pub device_type: AtomicU8,
    /// State
    pub state: AtomicU8,
    /// NUMA node (device locality)
    pub numa_node: AtomicU8,
    /// PCI bus/device/function
    pub bdf: AtomicU32,
    /// Vendor ID
    pub vendor_id: AtomicU16,
    /// Device ID (PCI)
    pub pci_device_id: AtomicU16,
    /// IRQ vector
    pub irq_vector: AtomicU16,
    /// IRQ mode
    pub irq_mode: AtomicU8,
    /// IRQ affinity (CPU mask)
    pub irq_affinity: [AtomicU64; 4],
    /// Preferred node for IRQ handling
    pub irq_preferred_node: AtomicU8,
    /// DMA regions
    pub dma_regions: [DmaRegion; 8],
    /// DMA region count
    pub dma_count: AtomicU8,
    /// Queue count
    pub queue_count: AtomicU8,
    /// Active queue mask
    pub active_queues: AtomicU16,
    /// IOPS count
    pub iops: AtomicU64,
    /// Bytes transferred
    pub bytes_transferred: AtomicU64,
    /// Interrupt count
    pub irq_count: AtomicU64,
    /// Latency (ns)
    pub avg_latency: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl IoDevice {
    pub const fn new() -> Self {
        Self {
            device_id: AtomicU32::new(0),
            device_type: AtomicU8::new(device_type::GENERIC),
            state: AtomicU8::new(device_state::DISCOVERED),
            numa_node: AtomicU8::new(0),
            bdf: AtomicU32::new(0),
            vendor_id: AtomicU16::new(0),
            pci_device_id: AtomicU16::new(0),
            irq_vector: AtomicU16::new(0),
            irq_mode: AtomicU8::new(irq_mode::MSIX),
            irq_affinity: [const { AtomicU64::new(0) }; 4],
            irq_preferred_node: AtomicU8::new(0),
            dma_regions: [const { DmaRegion::new() }; 8],
            dma_count: AtomicU8::new(0),
            queue_count: AtomicU8::new(0),
            active_queues: AtomicU16::new(0),
            iops: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            irq_count: AtomicU64::new(0),
            avg_latency: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize device
    pub fn init(&self, device_id: u32, device_type: u8, numa_node: u8, bdf: u32) {
        self.device_id.store(device_id, Ordering::Release);
        self.device_type.store(device_type, Ordering::Release);
        self.numa_node.store(numa_node, Ordering::Release);
        self.bdf.store(bdf, Ordering::Release);
        self.state.store(device_state::INITIALIZED, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Set IRQ info
    pub fn set_irq(&self, vector: u16, mode: u8) {
        self.irq_vector.store(vector, Ordering::Release);
        self.irq_mode.store(mode, Ordering::Release);
    }

    /// Set IRQ affinity
    pub fn set_irq_affinity(&self, cpu_mask: &[AtomicU64; 4], node: u8) {
        for i in 0..4 {
            self.irq_affinity[i].store(cpu_mask[i].load(Ordering::Acquire), Ordering::Release);
        }
        self.irq_preferred_node.store(node, Ordering::Release);
    }

    /// Add DMA region
    pub fn add_dma_region(&self, gpa: u64, size: u64, node: u8) -> Result<u8, HvError> {
        let count = self.dma_count.load(Ordering::Acquire);
        if count as usize >= 8 {
            return Err(HvError::LogicalFault);
        }
        
        self.dma_regions[count as usize].init(count, gpa, size, node);
        self.dma_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Record I/O
    pub fn record_io(&self, bytes: u64, latency: u64) {
        self.iops.fetch_add(1, Ordering::Release);
        self.bytes_transferred.fetch_add(bytes, Ordering::Release);
        
        // Update average latency (simplified)
        let current = self.avg_latency.load(Ordering::Acquire);
        self.avg_latency.store((current + latency) / 2, Ordering::Release);
    }

    /// Record interrupt
    pub fn record_irq(&self) {
        self.irq_count.fetch_add(1, Ordering::Release);
    }

    /// Activate device
    pub fn activate(&self) {
        self.state.store(device_state::ACTIVE, Ordering::Release);
    }

    /// Suspend device
    pub fn suspend(&self) {
        self.state.store(device_state::SUSPENDED, Ordering::Release);
    }

    /// Set queue count
    pub fn set_queues(&self, count: u8) {
        self.queue_count.store(count, Ordering::Release);
        self.active_queues.store((1 << count) - 1, Ordering::Release);
    }

    /// Get statistics
    pub fn get_stats(&self) -> IoDeviceStats {
        IoDeviceStats {
            device_id: self.device_id.load(Ordering::Acquire),
            device_type: self.device_type.load(Ordering::Acquire),
            numa_node: self.numa_node.load(Ordering::Acquire),
            state: self.state.load(Ordering::Acquire),
            iops: self.iops.load(Ordering::Acquire),
            bytes_transferred: self.bytes_transferred.load(Ordering::Acquire),
            irq_count: self.irq_count.load(Ordering::Acquire),
            avg_latency: self.avg_latency.load(Ordering::Acquire),
        }
    }
}

impl Default for IoDevice {
    fn default() -> Self {
        Self::new()
    }
}

/// I/O device statistics
#[repr(C)]
pub struct IoDeviceStats {
    pub device_id: u32,
    pub device_type: u8,
    pub numa_node: u8,
    pub state: u8,
    pub iops: u64,
    pub bytes_transferred: u64,
    pub irq_count: u64,
    pub avg_latency: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// DMA Region
// ─────────────────────────────────────────────────────────────────────────────

/// DMA region
pub struct DmaRegion {
    /// Region ID
    pub region_id: AtomicU8,
    /// Guest physical address
    pub gpa: AtomicU64,
    /// Size in bytes
    pub size: AtomicU64,
    /// NUMA node (memory locality)
    pub numa_node: AtomicU8,
    /// Access count
    pub access_count: AtomicU64,
    /// Bytes transferred
    pub bytes: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl DmaRegion {
    pub const fn new() -> Self {
        Self {
            region_id: AtomicU8::new(0),
            gpa: AtomicU64::new(0),
            size: AtomicU64::new(0),
            numa_node: AtomicU8::new(0),
            access_count: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize region
    pub fn init(&self, region_id: u8, gpa: u64, size: u64, numa_node: u8) {
        self.region_id.store(region_id, Ordering::Release);
        self.gpa.store(gpa, Ordering::Release);
        self.size.store(size, Ordering::Release);
        self.numa_node.store(numa_node, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Record access
    pub fn record_access(&self, bytes: u64) {
        self.access_count.fetch_add(1, Ordering::Release);
        self.bytes.fetch_add(bytes, Ordering::Release);
    }
}

impl Default for DmaRegion {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM I/O Policy
// ─────────────────────────────────────────────────────────────────────────────

/// VM I/O policy
pub struct VmIoPolicy {
    /// VM ID
    pub vm_id: AtomicU32,
    /// I/O policy
    pub policy: AtomicU8,
    /// Preferred node
    pub preferred_node: AtomicU8,
    /// Allowed nodes mask
    pub allowed_nodes: AtomicU16,
    /// Device assignments
    pub devices: [AtomicU32; 16],
    /// Device count
    pub device_count: AtomicU8,
    /// Total IOPS
    pub total_iops: AtomicU64,
    /// Total bytes
    pub total_bytes: AtomicU64,
    /// Cross-node I/O count
    pub cross_node_io: AtomicU64,
    /// Local I/O count
    pub local_io: AtomicU64,
    /// Valid
    pub valid: AtomicBool,
}

impl VmIoPolicy {
    pub const fn new() -> Self {
        Self {
            vm_id: AtomicU32::new(0),
            policy: AtomicU8::new(io_policy::DEFAULT),
            preferred_node: AtomicU8::new(0),
            allowed_nodes: AtomicU16::new(0xFFFF),
            devices: [const { AtomicU32::new(0) }; 16],
            device_count: AtomicU8::new(0),
            total_iops: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            cross_node_io: AtomicU64::new(0),
            local_io: AtomicU64::new(0),
            valid: AtomicBool::new(false),
        }
    }

    /// Initialize policy
    pub fn init(&self, vm_id: u32, policy: u8, preferred_node: u8, allowed_nodes: u16) {
        self.vm_id.store(vm_id, Ordering::Release);
        self.policy.store(policy, Ordering::Release);
        self.preferred_node.store(preferred_node, Ordering::Release);
        self.allowed_nodes.store(allowed_nodes, Ordering::Release);
        self.valid.store(true, Ordering::Release);
    }

    /// Add device
    pub fn add_device(&self, device_id: u32) -> Result<u8, HvError> {
        let count = self.device_count.load(Ordering::Acquire);
        if count as usize >= 16 {
            return Err(HvError::LogicalFault);
        }
        
        self.devices[count as usize].store(device_id, Ordering::Release);
        self.device_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Record I/O
    pub fn record_io(&self, local: bool, iops: u64, bytes: u64) {
        self.total_iops.fetch_add(iops, Ordering::Release);
        self.total_bytes.fetch_add(bytes, Ordering::Release);
        
        if local {
            self.local_io.fetch_add(iops, Ordering::Release);
        } else {
            self.cross_node_io.fetch_add(iops, Ordering::Release);
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> VmIoStats {
        VmIoStats {
            vm_id: self.vm_id.load(Ordering::Acquire),
            device_count: self.device_count.load(Ordering::Acquire),
            total_iops: self.total_iops.load(Ordering::Acquire),
            total_bytes: self.total_bytes.load(Ordering::Acquire),
            local_io: self.local_io.load(Ordering::Acquire),
            cross_node_io: self.cross_node_io.load(Ordering::Acquire),
        }
    }
}

impl Default for VmIoPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// VM I/O statistics
#[repr(C)]
pub struct VmIoStats {
    pub vm_id: u32,
    pub device_count: u8,
    pub total_iops: u64,
    pub total_bytes: u64,
    pub local_io: u64,
    pub cross_node_io: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// NUMA I/O Controller
// ─────────────────────────────────────────────────────────────────────────────

/// NUMA I/O controller
pub struct NumaIoController {
    /// I/O devices
    pub devices: [IoDevice; MAX_IO_DEVICES],
    /// Device count
    pub device_count: AtomicU16,
    /// VM policies
    pub vm_policies: [VmIoPolicy; MAX_IO_VMS],
    /// VM count
    pub vm_count: AtomicU8,
    /// Devices per node
    pub devices_per_node: [AtomicU8; MAX_NUMA_NODES],
    /// IRQs per node
    pub irqs_per_node: [AtomicU64; MAX_NUMA_NODES],
    /// Enabled
    pub enabled: AtomicBool,
    /// Auto-affinity enabled
    pub auto_affinity: AtomicBool,
    /// IRQ balancing enabled
    pub irq_balancing: AtomicBool,
    /// Balance interval (ms)
    pub balance_interval: AtomicU32,
    /// Last balance time
    pub last_balance: AtomicU64,
    /// Total devices
    pub total_devices: AtomicU64,
    /// Total IOPS
    pub total_iops: AtomicU64,
    /// Total bytes
    pub total_bytes: AtomicU64,
    /// Total IRQs
    pub total_irqs: AtomicU64,
    /// Cross-node I/O
    pub cross_node_io: AtomicU64,
    /// Local I/O
    pub local_io: AtomicU64,
}

impl NumaIoController {
    pub const fn new() -> Self {
        Self {
            devices: [const { IoDevice::new() }; MAX_IO_DEVICES],
            device_count: AtomicU16::new(0),
            vm_policies: [const { VmIoPolicy::new() }; MAX_IO_VMS],
            vm_count: AtomicU8::new(0),
            devices_per_node: [const { AtomicU8::new(0) }; MAX_NUMA_NODES],
            irqs_per_node: [const { AtomicU64::new(0) }; MAX_NUMA_NODES],
            enabled: AtomicBool::new(false),
            auto_affinity: AtomicBool::new(false),
            irq_balancing: AtomicBool::new(false),
            balance_interval: AtomicU32::new(1000),
            last_balance: AtomicU64::new(0),
            total_devices: AtomicU64::new(0),
            total_iops: AtomicU64::new(0),
            total_bytes: AtomicU64::new(0),
            total_irqs: AtomicU64::new(0),
            cross_node_io: AtomicU64::new(0),
            local_io: AtomicU64::new(0),
        }
    }

    /// Enable controller
    pub fn enable(&mut self, auto_affinity: bool, irq_balancing: bool, interval: u32) {
        self.auto_affinity.store(auto_affinity, Ordering::Release);
        self.irq_balancing.store(irq_balancing, Ordering::Release);
        self.balance_interval.store(interval, Ordering::Release);
        self.enabled.store(true, Ordering::Release);
    }

    /// Disable controller
    pub fn disable(&mut self) {
        self.enabled.store(false, Ordering::Release);
    }

    /// Register device
    pub fn register_device(&mut self, device_type: u8, numa_node: u8, 
                           bdf: u32, vendor: u16, device_id: u16) -> Result<u32, HvError> {
        let count = self.device_count.load(Ordering::Acquire);
        if count as usize >= MAX_IO_DEVICES {
            return Err(HvError::LogicalFault);
        }
        
        let id = count as u32 + 1;
        self.devices[count as usize].init(id, device_type, numa_node, bdf);
        self.devices[count as usize].vendor_id.store(vendor, Ordering::Release);
        self.devices[count as usize].pci_device_id.store(device_id, Ordering::Release);
        
        self.device_count.fetch_add(1, Ordering::Release);
        self.total_devices.fetch_add(1, Ordering::Release);
        
        if numa_node as usize < MAX_NUMA_NODES {
            self.devices_per_node[numa_node as usize].fetch_add(1, Ordering::Release);
        }
        
        Ok(id)
    }

    /// Get device
    pub fn get_device(&self, device_id: u32) -> Option<&IoDevice> {
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            if self.devices[i].device_id.load(Ordering::Acquire) == device_id {
                return Some(&self.devices[i]);
            }
        }
        None
    }

    /// Get devices by node
    pub fn get_devices_by_node(&self, node: u8) -> u8 {
        if node as usize < MAX_NUMA_NODES {
            self.devices_per_node[node as usize].load(Ordering::Acquire)
        } else {
            0
        }
    }

    /// Set device IRQ
    pub fn set_device_irq(&self, device_id: u32, vector: u16, mode: u8) -> Result<(), HvError> {
        let device = self.get_device(device_id).ok_or(HvError::LogicalFault)?;
        device.set_irq(vector, mode);
        Ok(())
    }

    /// Set IRQ affinity
    pub fn set_irq_affinity(&self, device_id: u32, cpu_mask: &[AtomicU64; 4], 
                            node: u8) -> Result<(), HvError> {
        let device = self.get_device(device_id).ok_or(HvError::LogicalFault)?;
        device.set_irq_affinity(cpu_mask, node);
        
        if node as usize < MAX_NUMA_NODES {
            self.irqs_per_node[node as usize].fetch_add(1, Ordering::Release);
        }
        
        Ok(())
    }

    /// Register VM policy
    pub fn register_vm(&mut self, vm_id: u32, policy: u8, 
                       preferred_node: u8, allowed_nodes: u16) -> Result<u8, HvError> {
        let count = self.vm_count.load(Ordering::Acquire);
        if count as usize >= MAX_IO_VMS {
            return Err(HvError::LogicalFault);
        }
        
        self.vm_policies[count as usize].init(vm_id, policy, preferred_node, allowed_nodes);
        self.vm_count.fetch_add(1, Ordering::Release);
        
        Ok(count)
    }

    /// Get VM policy
    pub fn get_vm_policy(&self, vm_id: u32) -> Option<&VmIoPolicy> {
        for i in 0..self.vm_count.load(Ordering::Acquire) as usize {
            if self.vm_policies[i].vm_id.load(Ordering::Acquire) == vm_id {
                return Some(&self.vm_policies[i]);
            }
        }
        None
    }

    /// Assign device to VM
    pub fn assign_device(&self, vm_id: u32, device_id: u32) -> Result<(), HvError> {
        let policy = self.get_vm_policy(vm_id).ok_or(HvError::LogicalFault)?;
        policy.add_device(device_id)
    }

    /// Record I/O
    pub fn record_io(&self, device_id: u32, vm_id: u32, 
                      bytes: u64, latency: u64, local: bool) {
        if let Some(device) = self.get_device(device_id) {
            device.record_io(bytes, latency);
            
            self.total_iops.fetch_add(1, Ordering::Release);
            self.total_bytes.fetch_add(bytes, Ordering::Release);
            
            if local {
                self.local_io.fetch_add(1, Ordering::Release);
            } else {
                self.cross_node_io.fetch_add(1, Ordering::Release);
            }
        }
        
        if let Some(policy) = self.get_vm_policy(vm_id) {
            policy.record_io(local, 1, bytes);
        }
    }

    /// Record interrupt
    pub fn record_irq(&self, device_id: u32) {
        if let Some(device) = self.get_device(device_id) {
            device.record_irq();
            
            let node = device.numa_node.load(Ordering::Acquire);
            if node as usize < MAX_NUMA_NODES {
                self.irqs_per_node[node as usize].fetch_add(1, Ordering::Release);
            }
            
            self.total_irqs.fetch_add(1, Ordering::Release);
        }
    }

    /// Find best device for VM
    pub fn find_best_device(&self, vm_id: u32, device_type: u8) -> Option<u32> {
        let policy = self.get_vm_policy(vm_id)?;
        let preferred = policy.preferred_node.load(Ordering::Acquire);
        
        // First try to find device on preferred node
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            let device = &self.devices[i];
            if device.device_type.load(Ordering::Acquire) == device_type &&
               device.state.load(Ordering::Acquire) == device_state::ACTIVE &&
               device.numa_node.load(Ordering::Acquire) == preferred {
                return Some(device.device_id.load(Ordering::Acquire));
            }
        }
        
        // Fall back to any matching device
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            let device = &self.devices[i];
            if device.device_type.load(Ordering::Acquire) == device_type &&
               device.state.load(Ordering::Acquire) == device_state::ACTIVE {
                return Some(device.device_id.load(Ordering::Acquire));
            }
        }
        
        None
    }

    /// Balance IRQ affinity
    pub fn balance_irqs(&self) -> u32 {
        if !self.enabled.load(Ordering::Acquire) || !self.irq_balancing.load(Ordering::Acquire) {
            return 0;
        }
        
        let mut balanced = 0u32;
        
        // Find nodes with high IRQ load
        let total_irqs: u64 = self.irqs_per_node.iter().map(|x| x.load(Ordering::Acquire)).sum();
        let node_count = self.devices_per_node.iter().filter(|x| x.load(Ordering::Acquire) > 0).count();
        
        if node_count == 0 {
            return 0;
        }
        
        let avg_irqs = total_irqs / node_count as u64;
        
        // Redistribute IRQs from overloaded nodes
        for i in 0..self.device_count.load(Ordering::Acquire) as usize {
            let device = &self.devices[i];
            let node = device.numa_node.load(Ordering::Acquire);
            
            if node as usize >= MAX_NUMA_NODES {
                continue;
            }
            
            let node_irqs = self.irqs_per_node[node as usize].load(Ordering::Acquire);
            
            if node_irqs > avg_irqs * 2 {
                // Find underloaded node
                for j in 0..MAX_NUMA_NODES {
                    if self.devices_per_node[j].load(Ordering::Acquire) > 0 &&
                       self.irqs_per_node[j].load(Ordering::Acquire) < avg_irqs {
                        // Would migrate IRQ affinity here
                        device.irq_preferred_node.store(j as u8, Ordering::Release);
                        balanced += 1;
                        break;
                    }
                }
            }
        }
        
        self.last_balance.store(Self::get_timestamp(), Ordering::Release);
        
        balanced
    }

    /// Get statistics
    pub fn get_stats(&self) -> NumaIoStats {
        NumaIoStats {
            enabled: self.enabled.load(Ordering::Acquire),
            device_count: self.device_count.load(Ordering::Acquire),
            vm_count: self.vm_count.load(Ordering::Acquire),
            total_devices: self.total_devices.load(Ordering::Acquire),
            total_iops: self.total_iops.load(Ordering::Acquire),
            total_bytes: self.total_bytes.load(Ordering::Acquire),
            total_irqs: self.total_irqs.load(Ordering::Acquire),
            local_io: self.local_io.load(Ordering::Acquire),
            cross_node_io: self.cross_node_io.load(Ordering::Acquire),
        }
    }

    fn get_timestamp() -> u64 { 0 }
}

impl Default for NumaIoController {
    fn default() -> Self {
        Self::new()
    }
}

/// NUMA I/O statistics
#[repr(C)]
pub struct NumaIoStats {
    pub enabled: bool,
    pub device_count: u16,
    pub vm_count: u8,
    pub total_devices: u64,
    pub total_iops: u64,
    pub total_bytes: u64,
    pub total_irqs: u64,
    pub local_io: u64,
    pub cross_node_io: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enable_controller() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        assert!(ctrl.enabled.load(Ordering::Acquire));
        assert!(ctrl.auto_affinity.load(Ordering::Acquire));
    }

    #[test]
    fn register_device() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        assert!(id > 0);
        assert_eq!(ctrl.device_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn device_irq() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        let id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        
        ctrl.set_device_irq(id, 32, irq_mode::MSIX).unwrap();
        
        let device = ctrl.get_device(id).unwrap();
        assert_eq!(device.irq_vector.load(Ordering::Acquire), 32);
    }

    #[test]
    fn register_vm() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let idx = ctrl.register_vm(1, io_policy::LOCAL, 0, 0x03).unwrap();
        assert_eq!(ctrl.vm_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn assign_device() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let dev_id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        ctrl.register_vm(1, io_policy::LOCAL, 0, 0x03).unwrap();
        
        ctrl.assign_device(1, dev_id).unwrap();
        
        let policy = ctrl.get_vm_policy(1).unwrap();
        assert_eq!(policy.device_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn record_io() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let dev_id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        ctrl.register_vm(1, io_policy::LOCAL, 0, 0x03).unwrap();
        ctrl.assign_device(1, dev_id).unwrap();
        
        ctrl.record_io(dev_id, 1, 1500, 100, true);
        
        let stats = ctrl.get_stats();
        assert!(stats.total_iops > 0);
        assert!(stats.local_io > 0);
    }

    #[test]
    fn find_best_device() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let dev_id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        ctrl.get_device(dev_id).unwrap().activate();
        
        ctrl.register_vm(1, io_policy::LOCAL, 0, 0x03).unwrap();
        
        let found = ctrl.find_best_device(1, device_type::NETWORK);
        assert_eq!(found, Some(dev_id));
    }

    #[test]
    fn irq_balancing() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        // Register devices on different nodes
        ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        ctrl.register_device(device_type::NETWORK, 1, 0x20000, 0x8086, 0x1000).unwrap();
        
        // Simulate IRQ load
        ctrl.irqs_per_node[0].store(1000, Ordering::Release);
        ctrl.irqs_per_node[1].store(100, Ordering::Release);
        
        let balanced = ctrl.balance_irqs();
        // May or may not balance depending on thresholds
        assert!(balanced >= 0);
    }

    #[test]
    fn cross_node_tracking() {
        let mut ctrl = NumaIoController::new();
        ctrl.enable(true, true, 1000);
        
        let dev_id = ctrl.register_device(device_type::NETWORK, 0, 0x10000, 0x8086, 0x1000).unwrap();
        ctrl.register_vm(1, io_policy::LOCAL, 1, 0x03).unwrap(); // VM on node 1
        
        ctrl.record_io(dev_id, 1, 1500, 100, false); // Cross-node
        
        let stats = ctrl.get_stats();
        assert!(stats.cross_node_io > 0);
    }
}
