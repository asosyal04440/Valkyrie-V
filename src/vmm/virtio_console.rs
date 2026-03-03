use crate::vmm::virtio_mmio::{VirtIODevice, VirtIoDeviceType};
use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

pub const VIRTIO_CONSOLE_F_SIZE: u32 = 0;
pub const VIRTIO_CONSOLE_F_MULTIPORT: u32 = 1;

pub const VIRTIO_CONSOLE_DEVICE_ID: u32 = 3;

pub const VIRTIO_CONSOLE_MAX_PORTS: u32 = 16;
pub const VIRTIO_CONSOLE_QUEUE_SIZE: u32 = 16;

#[derive(Debug, Clone, Copy)]
pub struct VirtConsoleConfig {
    pub cols: u16,
    pub rows: u16,
    pub max_nr_ports: u32,
}

impl VirtConsoleConfig {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols,
            rows,
            max_nr_ports: VIRTIO_CONSOLE_MAX_PORTS,
        }
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        if buf.len() < 8 {
            return;
        }
        buf[0..2].copy_from_slice(&self.cols.to_le_bytes());
        buf[2..4].copy_from_slice(&self.rows.to_le_bytes());
        buf[4..8].copy_from_slice(&self.max_nr_ports.to_le_bytes());
    }
}

impl Default for VirtConsoleConfig {
    fn default() -> Self {
        Self::new(80, 25)
    }
}

pub struct VirtIoConsole {
    config: VirtConsoleConfig,
    status: AtomicU8,
    features: AtomicU64,
    _port_count: AtomicU32,
    control_ready: AtomicU8,
    rx_ready: AtomicU8,
    tx_ready: AtomicU8,
}

impl VirtIoConsole {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            config: VirtConsoleConfig::new(cols, rows),
            status: AtomicU8::new(0),
            features: AtomicU64::new(0),
            _port_count: AtomicU32::new(1),
            control_ready: AtomicU8::new(0),
            rx_ready: AtomicU8::new(0),
            tx_ready: AtomicU8::new(0),
        }
    }

    pub fn set_control_ready(&self, ready: bool) {
        self.control_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }

    pub fn set_rx_ready(&self, ready: bool) {
        self.rx_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }

    pub fn set_tx_ready(&self, ready: bool) {
        self.tx_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }
}

impl Default for VirtIoConsole {
    fn default() -> Self {
        Self::new(80, 25)
    }
}

impl VirtIODevice for VirtIoConsole {
    fn device_type(&self) -> VirtIoDeviceType {
        VirtIoDeviceType::Console
    }

    fn device_id(&self) -> u32 {
        VIRTIO_CONSOLE_DEVICE_ID
    }

    fn vendor_id(&self) -> u32 {
        0x1AF4
    }

    fn get_features(&self) -> u64 {
        let mut features: u64 = 0;
        features |= 1 << VIRTIO_CONSOLE_F_SIZE;
        features |= 1 << VIRTIO_CONSOLE_F_MULTIPORT;
        features
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.features.store(features, Ordering::Release);
        Ok(())
    }

    fn get_status(&self) -> u32 {
        self.status.load(Ordering::Acquire) as u32
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.status.store(status as u8, Ordering::Release);
        Ok(())
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        let config_bytes = &mut [0u8; 8];
        self.config.to_bytes(config_bytes);

        let start = offset as usize;
        let end = (start + data.len()).min(8);

        if start >= 8 {
            return Err(HvError::LogicalFault);
        }

        data[..(end - start)].copy_from_slice(&config_bytes[start..end]);
        Ok(())
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        if offset == 0 && data.len() >= 4 {
            let cols = u16::from_le_bytes([data[0], data[1]]);
            let rows = u16::from_le_bytes([data[2], data[3]]);
            self.config = VirtConsoleConfig::new(cols, rows);
        }
        Ok(())
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        match queue {
            0 => Ok(self.rx_ready.load(Ordering::Acquire) != 0),
            1 => Ok(self.tx_ready.load(Ordering::Acquire) != 0),
            2 => Ok(self.control_ready.load(Ordering::Acquire) != 0),
            _ => Ok(false),
        }
    }
}

pub struct VirtIoConsoleBackend {
    console: VirtIoConsole,
}

impl VirtIoConsoleBackend {
    pub fn new() -> Self {
        Self {
            console: VirtIoConsole::new(80, 25),
        }
    }
}

impl Default for VirtIoConsoleBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtIODevice for VirtIoConsoleBackend {
    fn device_type(&self) -> VirtIoDeviceType {
        self.console.device_type()
    }

    fn device_id(&self) -> u32 {
        self.console.device_id()
    }

    fn vendor_id(&self) -> u32 {
        self.console.vendor_id()
    }

    fn get_features(&self) -> u64 {
        self.console.get_features()
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.console.set_features(features)
    }

    fn get_status(&self) -> u32 {
        self.console.get_status()
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.console.set_status(status)
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        self.console.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        self.console.write_config(offset, data)
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        self.console.queue_notify(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_requires_queue_ready() {
        let mut console = VirtIoConsole::new(80, 25);
        assert!(!console.queue_notify(0).unwrap());
        console.set_rx_ready(true);
        assert!(console.queue_notify(0).unwrap());
    }

    #[test]
    fn invalid_queue_notify_returns_false() {
        let mut console = VirtIoConsole::new(80, 25);
        assert!(!console.queue_notify(99).unwrap());
    }
}
