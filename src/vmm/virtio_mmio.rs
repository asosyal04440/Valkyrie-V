use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// VirtIO devices use IRQ vector 0x2E (IRQ 14) for legacy interrupt injection.
/// Modern VirtIO devices can use MSI/MSI-X for per-queue interrupts.
pub const VIRTIO_IRQ_VECTOR: u8 = 0x2E;

/// MSI-X capability support
pub const VIRTIO_F_MSIX: u64 = 1 << 33;

/// MSI-X table size (max vectors per device)
pub const VIRTIO_MSIX_MAX_VECTORS: usize = 8;

pub const VIRTIO_MMIO_MAGIC: u32 = 0x74726976;
pub const VIRTIO_MMIO_VERSION: u32 = 1;

pub const VIRTIO_DEVICE_NET: u32 = 1;
pub const VIRTIO_DEVICE_BLOCK: u32 = 2;
pub const VIRTIO_DEVICE_CONSOLE: u32 = 3;
pub const VIRTIO_DEVICE_ENTROPY: u32 = 4;
pub const VIRTIO_DEVICE_BALLOON: u32 = 5;
pub const VIRTIO_DEVICE_IOMMU: u32 = 6;
pub const VIRTIO_DEVICE_GPU: u32 = 16;
pub const VIRTIO_DEVICE_FS: u32 = 26;

pub const VIRTIO_STATUS_ACKNOWLEDGE: u32 = 1;
pub const VIRTIO_STATUS_DRIVER: u32 = 2;
pub const VIRTIO_STATUS_DRIVER_OK: u32 = 4;
pub const VIRTIO_STATUS_FEATURES_OK: u32 = 8;
pub const VIRTIO_STATUS_NEEDS_RESET: u32 = 0x40;
pub const VIRTIO_STATUS_FAILED: u32 = 0x80;

pub const VIRTIO_CONFIG_S_DRIVER: u32 = 1;
pub const VIRTIO_CONFIG_S_DRIVER_OK: u32 = 2;
pub const VIRTIO_CONFIG_S_FEATURES_OK: u32 = 8;
pub const VIRTIO_CONFIG_S_NEEDS_RESET: u32 = 0x40;
pub const VIRTIO_CONFIG_S_FAILED: u32 = 0x80;

pub const VIRTIO_F_RING_INDIRECT_DESC: u64 = 1 << 28;
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

pub const VIRTIO_MMIO_REG_MAGIC: u32 = 0x000;
pub const VIRTIO_MMIO_REG_VERSION: u32 = 0x004;
pub const VIRTIO_MMIO_REG_DEVICE_ID: u32 = 0x008;
pub const VIRTIO_MMIO_REG_VENDOR_ID: u32 = 0x00C;
pub const VIRTIO_MMIO_REG_DEVICE_FEATURES: u32 = 0x010;
pub const VIRTIO_MMIO_REG_DEVICE_FEATURES_SEL: u32 = 0x014;
pub const VIRTIO_MMIO_REG_DRIVER_FEATURES: u32 = 0x020;
pub const VIRTIO_MMIO_REG_DRIVER_FEATURES_SEL: u32 = 0x024;
pub const VIRTIO_MMIO_REG_QUEUE_SEL: u32 = 0x030;
pub const VIRTIO_MMIO_REG_QUEUE_NUM_MAX: u32 = 0x034;
pub const VIRTIO_MMIO_REG_QUEUE_NUM: u32 = 0x038;
pub const VIRTIO_MMIO_REG_QUEUE_ALIGN: u32 = 0x03C;
pub const VIRTIO_MMIO_REG_QUEUE_PFN: u32 = 0x040;
pub const VIRTIO_MMIO_REG_QUEUE_SIZE_MAX: u32 = 0x044;
pub const VIRTIO_MMIO_REG_QUEUE_SELECT: u32 = 0x050;
pub const VIRTIO_MMIO_REG_QUEUE_NOTIFY: u32 = 0x054;
pub const VIRTIO_MMIO_REG_INTERRUPT_STATUS: u32 = 0x060;
pub const VIRTIO_MMIO_REG_INTERRUPT_ACK: u32 = 0x064;
pub const VIRTIO_MMIO_REG_STATUS: u32 = 0x070;
pub const VIRTIO_MMIO_REG_QUEUE_DESC_LOW: u32 = 0x080;
pub const VIRTIO_MMIO_REG_QUEUE_DESC_HIGH: u32 = 0x084;
pub const VIRTIO_MMIO_REG_QUEUE_AVAIL_LOW: u32 = 0x090;
pub const VIRTIO_MMIO_REG_QUEUE_AVAIL_HIGH: u32 = 0x094;
pub const VIRTIO_MMIO_REG_QUEUE_USED_LOW: u32 = 0x0A0;
pub const VIRTIO_MMIO_REG_QUEUE_USED_HIGH: u32 = 0x0A4;
pub const VIRTIO_MMIO_REG_CONFIG_GENERATION: u32 = 0x0FC;
pub const VIRTIO_MMIO_REG_CONFIG: u32 = 0x100;

pub const VIRTIO_MMIO_IRQ_CONFIG: u32 = 0x00000001;
pub const VIRTIO_MMIO_IRQ_VQ: u32 = 0x00000002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtIoDeviceType {
    None,
    Net,
    Block,
    Console,
    Entropy,
    Balloon,
    Gpu,
    Fs,
}

impl VirtIoDeviceType {
    pub fn from_u32(id: u32) -> Self {
        match id {
            VIRTIO_DEVICE_NET => Self::Net,
            VIRTIO_DEVICE_BLOCK => Self::Block,
            VIRTIO_DEVICE_CONSOLE => Self::Console,
            VIRTIO_DEVICE_ENTROPY => Self::Entropy,
            VIRTIO_DEVICE_BALLOON => Self::Balloon,
            VIRTIO_DEVICE_GPU => Self::Gpu,
            VIRTIO_DEVICE_FS => Self::Fs,
            _ => Self::None,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self {
            Self::None => 0,
            Self::Net => VIRTIO_DEVICE_NET,
            Self::Block => VIRTIO_DEVICE_BLOCK,
            Self::Console => VIRTIO_DEVICE_CONSOLE,
            Self::Entropy => VIRTIO_DEVICE_ENTROPY,
            Self::Balloon => VIRTIO_DEVICE_BALLOON,
            Self::Gpu => VIRTIO_DEVICE_GPU,
            Self::Fs => VIRTIO_DEVICE_FS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtQueueType {
    None,
    Request,
    Notify,
    Control,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtQueueConfig {
    pub queue_index: u32,
    pub size: u32,
    pub desc_addr: u64,
    pub avail_addr: u64,
    pub used_addr: u64,
    pub ready: bool,
}

impl VirtQueueConfig {
    pub const fn new(queue_index: u32) -> Self {
        Self {
            queue_index,
            size: 0,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            ready: false,
        }
    }
}

pub trait VirtIODevice {
    fn device_type(&self) -> VirtIoDeviceType;
    fn device_id(&self) -> u32;
    fn vendor_id(&self) -> u32;
    fn get_features(&self) -> u64;
    fn set_features(&mut self, features: u64) -> Result<(), HvError>;
    fn get_status(&self) -> u32;
    fn set_status(&mut self, status: u32) -> Result<(), HvError>;
    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError>;
    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError>;
    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError>;
}

pub enum VirtIoDeviceEnum {
    Block(crate::vmm::virtio_block::VirtIoBlock),
    Net(crate::vmm::virtio_net::VirtIoNet),
    Console(crate::vmm::virtio_console::VirtIoConsole),
}

impl VirtIODevice for VirtIoDeviceEnum {
    fn device_type(&self) -> VirtIoDeviceType {
        match self {
            VirtIoDeviceEnum::Block(d) => d.device_type(),
            VirtIoDeviceEnum::Net(d) => d.device_type(),
            VirtIoDeviceEnum::Console(d) => d.device_type(),
        }
    }

    fn device_id(&self) -> u32 {
        match self {
            VirtIoDeviceEnum::Block(d) => d.device_id(),
            VirtIoDeviceEnum::Net(d) => d.device_id(),
            VirtIoDeviceEnum::Console(d) => d.device_id(),
        }
    }

    fn vendor_id(&self) -> u32 {
        match self {
            VirtIoDeviceEnum::Block(d) => d.vendor_id(),
            VirtIoDeviceEnum::Net(d) => d.vendor_id(),
            VirtIoDeviceEnum::Console(d) => d.vendor_id(),
        }
    }

    fn get_features(&self) -> u64 {
        match self {
            VirtIoDeviceEnum::Block(d) => d.get_features(),
            VirtIoDeviceEnum::Net(d) => d.get_features(),
            VirtIoDeviceEnum::Console(d) => d.get_features(),
        }
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        match self {
            VirtIoDeviceEnum::Block(d) => d.set_features(features),
            VirtIoDeviceEnum::Net(d) => d.set_features(features),
            VirtIoDeviceEnum::Console(d) => d.set_features(features),
        }
    }

    fn get_status(&self) -> u32 {
        match self {
            VirtIoDeviceEnum::Block(d) => d.get_status(),
            VirtIoDeviceEnum::Net(d) => d.get_status(),
            VirtIoDeviceEnum::Console(d) => d.get_status(),
        }
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        match self {
            VirtIoDeviceEnum::Block(d) => d.set_status(status),
            VirtIoDeviceEnum::Net(d) => d.set_status(status),
            VirtIoDeviceEnum::Console(d) => d.set_status(status),
        }
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        match self {
            VirtIoDeviceEnum::Block(d) => d.read_config(offset, data),
            VirtIoDeviceEnum::Net(d) => d.read_config(offset, data),
            VirtIoDeviceEnum::Console(d) => d.read_config(offset, data),
        }
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        match self {
            VirtIoDeviceEnum::Block(d) => d.write_config(offset, data),
            VirtIoDeviceEnum::Net(d) => d.write_config(offset, data),
            VirtIoDeviceEnum::Console(d) => d.write_config(offset, data),
        }
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        match self {
            VirtIoDeviceEnum::Block(d) => d.queue_notify(queue),
            VirtIoDeviceEnum::Net(d) => d.queue_notify(queue),
            VirtIoDeviceEnum::Console(d) => d.queue_notify(queue),
        }
    }
}

pub struct VirtIoMmio {
    device: Option<VirtIoDeviceEnum>,
    device_features_sel: u32,
    driver_features_sel: u32,
    queue_select: u32,
    queue_num: u32,
    queue_desc_addr: u64,
    queue_avail_addr: u64,
    queue_used_addr: u64,
    queue_ready: bool,
    interrupt_status: u32,
    interrupt_pending: bool,
    config_generation: AtomicU32,
    /// True if VIRTIO_F_RING_EVENT_IDX feature is negotiated.
    event_idx_enabled: bool,
    /// MSI-X enabled flag
    msix_enabled: bool,
    /// MSI-X vector for each queue
    msix_vectors: [u16; VIRTIO_MSIX_MAX_VECTORS],
    /// MSI-X address for each vector
    msix_addrs: [u64; VIRTIO_MSIX_MAX_VECTORS],
}

impl VirtIoMmio {
    pub const fn new() -> Self {
        Self {
            device: None,
            device_features_sel: 0,
            driver_features_sel: 0,
            queue_select: 0,
            queue_num: 0,
            queue_desc_addr: 0,
            queue_avail_addr: 0,
            queue_used_addr: 0,
            queue_ready: false,
            interrupt_status: 0,
            interrupt_pending: false,
            config_generation: AtomicU32::new(0),
            event_idx_enabled: false,
            msix_enabled: false,
            msix_vectors: [0; VIRTIO_MSIX_MAX_VECTORS],
            msix_addrs: [0; VIRTIO_MSIX_MAX_VECTORS],
        }
    }

    pub fn set_device(&mut self, device: VirtIoDeviceEnum) {
        self.device = Some(device);
    }

    pub fn read(&self, offset: u32) -> u32 {
        if let Some(device) = &self.device {
            match offset {
                VIRTIO_MMIO_REG_MAGIC => VIRTIO_MMIO_MAGIC,
                VIRTIO_MMIO_REG_VERSION => VIRTIO_MMIO_VERSION,
                VIRTIO_MMIO_REG_DEVICE_ID => device.device_id(),
                VIRTIO_MMIO_REG_VENDOR_ID => device.vendor_id(),
                VIRTIO_MMIO_REG_DEVICE_FEATURES => {
                    let features = device.get_features();
                    if self.device_features_sel == 0 {
                        (features & 0xFFFFFFFF) as u32
                    } else {
                        ((features >> 32) & 0xFFFFFFFF) as u32
                    }
                }
                VIRTIO_MMIO_REG_STATUS => device.get_status(),
                VIRTIO_MMIO_REG_QUEUE_NUM_MAX => 256,
                VIRTIO_MMIO_REG_QUEUE_NUM => self.queue_num,
                VIRTIO_MMIO_REG_QUEUE_SELECT => self.queue_select,
                VIRTIO_MMIO_REG_QUEUE_DESC_LOW => self.queue_desc_addr as u32,
                VIRTIO_MMIO_REG_QUEUE_DESC_HIGH => (self.queue_desc_addr >> 32) as u32,
                VIRTIO_MMIO_REG_QUEUE_AVAIL_LOW => self.queue_avail_addr as u32,
                VIRTIO_MMIO_REG_QUEUE_AVAIL_HIGH => (self.queue_avail_addr >> 32) as u32,
                VIRTIO_MMIO_REG_QUEUE_USED_LOW => self.queue_used_addr as u32,
                VIRTIO_MMIO_REG_QUEUE_USED_HIGH => (self.queue_used_addr >> 32) as u32,
                VIRTIO_MMIO_REG_QUEUE_SIZE_MAX => self.queue_ready as u32,
                VIRTIO_MMIO_REG_INTERRUPT_STATUS => self.interrupt_status,
                VIRTIO_MMIO_REG_CONFIG_GENERATION => self.config_generation.load(Ordering::Relaxed),
                _ => 0,
            }
        } else {
            match offset {
                VIRTIO_MMIO_REG_MAGIC => VIRTIO_MMIO_MAGIC,
                VIRTIO_MMIO_REG_VERSION => VIRTIO_MMIO_VERSION,
                VIRTIO_MMIO_REG_DEVICE_ID => 0,
                VIRTIO_MMIO_REG_VENDOR_ID => 0,
                _ => 0,
            }
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) -> bool {
        if let Some(device) = &mut self.device {
            match offset {
                VIRTIO_MMIO_REG_DEVICE_FEATURES_SEL => {
                    self.device_features_sel = value;
                }
                VIRTIO_MMIO_REG_DRIVER_FEATURES_SEL => {
                    self.driver_features_sel = value;
                }
                VIRTIO_MMIO_REG_DRIVER_FEATURES => {
                    let mut features = device.get_features();
                    if self.driver_features_sel == 0 {
                        features = (features & 0xFFFFFFFF_00000000) | (value as u64);
                    } else {
                        features = (features & 0xFFFFFFFF) | ((value as u64) << 32);
                    }
                    let _ = device.set_features(features);
                    // Track if event_idx feature is negotiated for interrupt coalescing.
                    self.event_idx_enabled = (features & VIRTIO_F_RING_EVENT_IDX) != 0;
                }
                VIRTIO_MMIO_REG_STATUS => {
                    let _ = device.set_status(value);
                    // Config might change on status transitions (e.g., NEEDS_RESET)
                    self.config_generation.fetch_add(1, Ordering::Relaxed);
                }
                VIRTIO_MMIO_REG_QUEUE_SELECT => {
                    self.queue_select = value;
                }
                VIRTIO_MMIO_REG_QUEUE_NUM => {
                    self.queue_num = value;
                }
                VIRTIO_MMIO_REG_QUEUE_DESC_HIGH => {
                    self.queue_desc_addr =
                        (self.queue_desc_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
                }
                VIRTIO_MMIO_REG_QUEUE_AVAIL_HIGH => {
                    self.queue_avail_addr =
                        (self.queue_avail_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
                }
                VIRTIO_MMIO_REG_QUEUE_USED_HIGH => {
                    self.queue_used_addr =
                        (self.queue_used_addr & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32);
                }
                VIRTIO_MMIO_REG_QUEUE_SIZE_MAX => {
                    self.queue_ready = (value & 1) != 0;
                    match device {
                        VirtIoDeviceEnum::Block(d) => d.set_ready(self.queue_ready),
                        VirtIoDeviceEnum::Net(d) => {
                            if self.queue_select == 0 {
                                d.set_tx_ready(self.queue_ready);
                            } else if self.queue_select == 1 {
                                d.set_rx_ready(self.queue_ready);
                            }
                        }
                        VirtIoDeviceEnum::Console(d) => match self.queue_select {
                            0 => d.set_rx_ready(self.queue_ready),
                            1 => d.set_tx_ready(self.queue_ready),
                            2 => d.set_control_ready(self.queue_ready),
                            _ => {}
                        },
                    }
                }
                VIRTIO_MMIO_REG_QUEUE_NOTIFY => match device.queue_notify(self.queue_select) {
                    Ok(needs_interrupt) => {
                        if needs_interrupt {
                            self.trigger_interrupt();
                        }
                    }
                    Err(_) => return false,
                },
                VIRTIO_MMIO_REG_INTERRUPT_ACK => {
                    self.interrupt_status &= !value;
                }
                _ => return false,
            }
            true
        } else {
            false
        }
    }

    pub fn write_64(&mut self, offset: u32, value: u64) -> bool {
        if self.device.is_some() {
            match offset {
                VIRTIO_MMIO_REG_QUEUE_DESC_LOW => {
                    self.queue_desc_addr = value;
                }
                VIRTIO_MMIO_REG_QUEUE_AVAIL_LOW => {
                    self.queue_avail_addr = value;
                }
                VIRTIO_MMIO_REG_QUEUE_USED_LOW => {
                    self.queue_used_addr = value;
                }
                _ => return false,
            }
            true
        } else {
            false
        }
    }

    pub fn trigger_interrupt(&mut self) {
        // EVENT_IDX optimization: check used_event from the driver's avail ring
        // and suppress notification if the driver doesn't need to be notified.
        if self.event_idx_enabled {
            // Full implementation would read used_event via DMA
            // For now, we proceed with interrupt
        }
        
        self.interrupt_status |= VIRTIO_MMIO_IRQ_VQ;
        self.interrupt_pending = true;
        
        // Check if MSI-X is enabled
        if self.msix_enabled {
            // Use MSI-X interrupt for the current queue
            let queue_idx = self.queue_select as usize;
            if queue_idx < VIRTIO_MSIX_MAX_VECTORS {
                let vector = self.msix_vectors[queue_idx];
                let addr = self.msix_addrs[queue_idx];
                
                if vector != 0 && addr != 0 {
                    // Deliver MSI-X interrupt
                    use crate::vmm::msi::{MsiMessage, deliver_msi};
                    let msg = MsiMessage {
                        addr: addr,
                        data: vector as u32,
                        vector: vector as u8,
                        delivery_mode: 0,
                        trigger_mode: false,
                        dest_id: (addr >> 12) as u32 & 0xFF,
                        dest_mode: ((addr >> 2) & 1) as u8,
                    };
                    deliver_msi(&msg);
                    return;
                }
            }
        }
        
        // Fallback to legacy IRQ interrupt
        use crate::vmm::vmx_handler::PENDING_IRQ;
        let _ = PENDING_IRQ.compare_exchange(
            0,
            VIRTIO_IRQ_VECTOR,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }
    
    /// Enable MSI-X for this device
    pub fn enable_msix(&mut self) {
        self.msix_enabled = true;
    }
    
    /// Set MSI-X vector for a queue
    pub fn set_msix_vector(&mut self, queue_idx: usize, vector: u16, addr: u64) {
        if queue_idx < VIRTIO_MSIX_MAX_VECTORS {
            self.msix_vectors[queue_idx] = vector;
            self.msix_addrs[queue_idx] = addr;
        }
    }
    
    /// Check if MSI-X is enabled
    pub fn is_msix_enabled(&self) -> bool {
        self.msix_enabled
    }

    /// Check if interrupt should be triggered based on EVENT_IDX.
    /// Returns true if interrupt is needed, false if it can be suppressed.
    pub fn should_notify(&self, old_used_idx: u16, new_used_idx: u16, used_event: u16) -> bool {
        if !self.event_idx_enabled {
            return true;  // Always notify without EVENT_IDX
        }
        
        // EVENT_IDX notification suppression condition:
        // Notify if: (new_used_idx - used_event - 1) < (new_used_idx - old_used_idx)
        // This wraps correctly with u16 arithmetic
        let used_idx_diff = new_used_idx.wrapping_sub(old_used_idx);
        let event_diff = new_used_idx.wrapping_sub(used_event).wrapping_sub(1);
        
        // Notify if we've added fewer entries than the driver expects
        event_diff < used_idx_diff || used_idx_diff == 0
    }
    
    /// Read used_event from guest memory via DMA
    /// used_event is at offset: flags(2) + idx(2) + ring[queue_size](queue_size*2)
    pub fn read_used_event(&self, queue_size: u16) -> u16 {
        if !self.event_idx_enabled {
            return 0;
        }
        
        // Calculate used_event offset in avail ring
        // struct virtq_avail {
        //     le16 flags;       // offset 0
        //     le16 idx;         // offset 2
        //     le16 ring[];      // offset 4, size = queue_size * 2
        //     le16 used_event;  // offset 4 + queue_size * 2
        // }
        let used_event_offset = 4 + (queue_size as u64 * 2);
        let used_event_gpa = self.queue_avail_addr + used_event_offset;
        
        // Use DMA engine to read used_event from guest memory
        crate::vmm::virtio_direct().dma.read_u16(used_event_gpa).unwrap_or(0)
    }
    
    /// Trigger interrupt with EVENT_IDX optimization
    pub fn trigger_interrupt_optimized(&mut self, queue_size: u16, old_used_idx: u16, new_used_idx: u16) {
        let used_event = self.read_used_event(queue_size);
        
        if !self.should_notify(old_used_idx, new_used_idx, used_event) {
            return; // Suppress notification
        }
        
        self.trigger_interrupt();
    }

    pub fn has_pending_interrupt(&self) -> bool {
        self.interrupt_pending
    }

    pub fn clear_interrupt(&mut self) {
        self.interrupt_pending = false;
    }

    pub fn stats(&self) -> (u64, u64, u64, u64, u64, u64) {
        match &self.device {
            Some(VirtIoDeviceEnum::Net(net)) => {
                let (rx_packets, tx_packets, rx_bytes, tx_bytes) = net.get_stats();
                (rx_packets, tx_packets, rx_bytes, tx_bytes, 0, 0)
            }
            Some(VirtIoDeviceEnum::Block(block)) => {
                let (reads, writes, _errors) = block.get_stats();
                (0, 0, 0, 0, reads, writes)
            }
            Some(VirtIoDeviceEnum::Console(_)) | None => (0, 0, 0, 0, 0, 0),
        }
    }
}

impl Default for VirtIoMmio {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_64_updates_queue_addresses() {
        let mut mmio = VirtIoMmio::new();
        mmio.set_device(VirtIoDeviceEnum::Block(
            crate::vmm::virtio_block::VirtIoBlock::new(1024),
        ));

        assert!(mmio.write_64(VIRTIO_MMIO_REG_QUEUE_DESC_LOW, 0x1122_3344_5566_7788));
        assert_eq!(mmio.read(VIRTIO_MMIO_REG_QUEUE_DESC_LOW), 0x5566_7788);
        assert_eq!(mmio.read(VIRTIO_MMIO_REG_QUEUE_DESC_HIGH), 0x1122_3344);
    }

    #[test]
    fn queue_notify_triggers_interrupt_when_device_notifies() {
        let mut mmio = VirtIoMmio::new();
        mmio.set_device(VirtIoDeviceEnum::Block(
            crate::vmm::virtio_block::VirtIoBlock::new(1024),
        ));
        assert!(mmio.write(VIRTIO_MMIO_REG_QUEUE_SIZE_MAX, 1));
        assert!(mmio.write(VIRTIO_MMIO_REG_QUEUE_SELECT, 0));
        assert!(mmio.write(VIRTIO_MMIO_REG_QUEUE_NOTIFY, 0));
        assert!(mmio.has_pending_interrupt());
        assert_ne!(
            mmio.read(VIRTIO_MMIO_REG_INTERRUPT_STATUS) & VIRTIO_MMIO_IRQ_VQ,
            0
        );
    }
}
