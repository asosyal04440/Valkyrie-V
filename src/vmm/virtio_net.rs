use crate::vmm::virtio_mmio::{VirtIODevice, VirtIoDeviceType, VIRTIO_DEVICE_NET};
use crate::vmm::virtio_queue::{DescChainElem, SplitVirtqueue};
use crate::vmm::{HvError, HvResult};
use core::sync::atomic::{AtomicU64, AtomicU8, AtomicU16, Ordering};

pub const VIRTIO_NET_F_CSUM: u32 = 0;
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
pub const VIRTIO_NET_F_STATUS: u32 = 16;

pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;

pub const VIRTIO_NET_QUEUE_SIZE: u32 = 256;

#[derive(Debug, Clone, Copy)]
pub struct VirtNetHdr {
    pub flags: u8,
    /// virtio spec: gso_type is u8, not u16
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}

impl VirtNetHdr {
    pub const fn new() -> Self {
        Self {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }

    pub fn to_le_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0] = self.flags;
        bytes[1] = self.gso_type;
        bytes[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        bytes[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        bytes[10..12].copy_from_slice(&self.num_buffers.to_le_bytes());
        bytes
    }

    pub const fn size() -> usize {
        12
    }
}

impl Default for VirtNetHdr {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VirtNetConfig {
    pub mac: [u8; 6],
    pub status: u16,
    pub max_virtqueue_pairs: u16,
    pub mtu: u16,
}

impl VirtNetConfig {
    pub const fn new() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            status: 0,
            max_virtqueue_pairs: 1,
            mtu: 1500,
        }
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    pub fn to_bytes(&self, buf: &mut [u8]) {
        if buf.len() < 10 {
            return;
        }
        buf[0..6].copy_from_slice(&self.mac);
        buf[6..8].copy_from_slice(&self.status.to_le_bytes());
        buf[8..10].copy_from_slice(&self.max_virtqueue_pairs.to_le_bytes());
    }
}

impl Default for VirtNetConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VirtIoNet {
    config: VirtNetConfig,
    status: AtomicU8,
    features: AtomicU64,
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    tx_queue_ready: AtomicU8,
    rx_queue_ready: AtomicU8,
}

impl VirtIoNet {
    pub fn new() -> Self {
        Self {
            config: VirtNetConfig::new(),
            status: AtomicU8::new(0),
            features: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            tx_queue_ready: AtomicU8::new(0),
            rx_queue_ready: AtomicU8::new(0),
        }
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.config.set_mac(mac);
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.config.mtu = mtu;
    }

    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.rx_packets.load(Ordering::Acquire),
            self.tx_packets.load(Ordering::Acquire),
            self.rx_bytes.load(Ordering::Acquire),
            self.tx_bytes.load(Ordering::Acquire),
        )
    }

    pub fn set_tx_ready(&self, ready: bool) {
        self.tx_queue_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }

    pub fn set_rx_ready(&self, ready: bool) {
        self.rx_queue_ready
            .store(if ready { 1 } else { 0 }, Ordering::Release);
    }
}

impl Default for VirtIoNet {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtIODevice for VirtIoNet {
    fn device_type(&self) -> VirtIoDeviceType {
        VirtIoDeviceType::Net
    }

    fn device_id(&self) -> u32 {
        VIRTIO_DEVICE_NET
    }

    fn vendor_id(&self) -> u32 {
        0x1AF4
    }

    fn get_features(&self) -> u64 {
        let mut features: u64 = 0;
        features |= 1 << VIRTIO_NET_F_CSUM;
        features |= 1 << VIRTIO_NET_F_MAC;
        features |= 1 << VIRTIO_NET_F_HOST_TSO4;
        features |= 1 << VIRTIO_NET_F_HOST_TSO6;
        features |= 1 << VIRTIO_NET_F_MRG_RXBUF;
        features |= 1 << VIRTIO_NET_F_STATUS;
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
        let config_bytes = &mut [0u8; 10];
        self.config.to_bytes(config_bytes);

        let start = offset as usize;
        let end = (start + data.len()).min(10);

        if start >= 10 {
            return Err(HvError::LogicalFault);
        }

        data[..(end - start)].copy_from_slice(&config_bytes[start..end]);
        Ok(())
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        if offset == 0 && data.len() >= 6 {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&data[..6]);
            self.config.set_mac(mac);
        }
        Ok(())
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        match queue {
            0 => {
                if self.tx_queue_ready.load(Ordering::Acquire) == 0 {
                    return Ok(false);
                }
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(64, Ordering::Relaxed);
                Ok(true)
            }
            1 => {
                if self.rx_queue_ready.load(Ordering::Acquire) == 0 {
                    return Ok(false);
                }
                self.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.rx_bytes.fetch_add(64, Ordering::Relaxed);
                Ok(true)
            }
            _ => Ok(false),
        }
    }
}

/// Maximum packet buffer size (64KB)
pub const VIRTIO_NET_MAX_PACKET_SIZE: usize = 65536;
/// Maximum packets in RX/TX ring buffers
pub const VIRTIO_NET_MAX_PACKETS: usize = 256;

/// TAP/TUN interface handle
pub struct TapInterface {
    /// File descriptor for TAP device (Windows: handle)
    handle: AtomicU64,
    /// Whether interface is open
    is_open: AtomicU8,
    /// Interface name (e.g., "tap0")
    name: [u8; 16],
    /// MAC address of TAP interface
    mac: [u8; 6],
}

impl TapInterface {
    pub const fn new() -> Self {
        Self {
            handle: AtomicU64::new(0),
            is_open: AtomicU8::new(0),
            name: [0u8; 16],
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // Default QEMU-style MAC
        }
    }

    /// Open TAP interface
    pub fn open(&mut self, name: &[u8]) -> bool {
        // Copy interface name
        let len = name.len().min(15);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0; // Null terminate
        
        // On Windows, we would use CreateFile/DeviceIoControl
        // For now, mark as open with a pseudo-handle
        self.handle.store(1, Ordering::Release);
        self.is_open.store(1, Ordering::Release);
        true
    }

    /// Close TAP interface
    pub fn close(&mut self) {
        self.handle.store(0, Ordering::Release);
        self.is_open.store(0, Ordering::Release);
    }

    /// Check if interface is open
    pub fn is_open(&self) -> bool {
        self.is_open.load(Ordering::Acquire) != 0
    }

    /// Read packet from TAP interface
    /// Returns number of bytes read, or 0 on error
    pub fn read(&self, buf: &mut [u8]) -> usize {
        if !self.is_open() {
            return 0;
        }
        // In a real implementation, this would call ReadFile on Windows
        // or read() on Linux. For now, return 0 (no data)
        0
    }

    /// Write packet to TAP interface
    /// Returns true on success
    pub fn write(&self, data: &[u8]) -> bool {
        if !self.is_open() {
            return false;
        }
        // In a real implementation, this would call WriteFile on Windows
        // or write() on Linux. For now, return true (success)
        !data.is_empty()
    }

    /// Get MAC address
    pub fn mac(&self) -> &[u8; 6] {
        &self.mac
    }

    /// Set MAC address
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }
}

/// Simple packet buffer for in-memory networking.
/// Interfaces with TAP/TUN for external network access.
pub struct NetPacketBuffer {
    /// RX packet queue (packets to be received by guest)
    rx_packets: [[u8; VIRTIO_NET_MAX_PACKET_SIZE]; 16],
    rx_lengths: [u16; 16],
    rx_head: AtomicU8,
    rx_tail: AtomicU8,
    /// TX packet queue (packets sent by guest)
    tx_packets: [[u8; VIRTIO_NET_MAX_PACKET_SIZE]; 16],
    tx_lengths: [u16; 16],
    tx_head: AtomicU8,
    tx_tail: AtomicU8,
    /// TAP/TUN interface for external network
    tap: TapInterface,
    /// Whether to use TAP for TX
    use_tap_tx: AtomicU8,
    /// Whether to use TAP for RX
    use_tap_rx: AtomicU8,
}

impl NetPacketBuffer {
    pub const fn new() -> Self {
        Self {
            rx_packets: [[0u8; VIRTIO_NET_MAX_PACKET_SIZE]; 16],
            rx_lengths: [0u16; 16],
            rx_head: AtomicU8::new(0),
            rx_tail: AtomicU8::new(0),
            tx_packets: [[0u8; VIRTIO_NET_MAX_PACKET_SIZE]; 16],
            tx_lengths: [0u16; 16],
            tx_head: AtomicU8::new(0),
            tx_tail: AtomicU8::new(0),
            tap: TapInterface::new(),
            use_tap_tx: AtomicU8::new(0),
            use_tap_rx: AtomicU8::new(0),
        }
    }

    /// Enable TAP/TUN interface for TX
    pub fn enable_tap_tx(&self) {
        self.use_tap_tx.store(1, Ordering::Release);
    }

    /// Enable TAP/TUN interface for RX
    pub fn enable_tap_rx(&self) {
        self.use_tap_rx.store(1, Ordering::Release);
    }

    /// Open TAP interface
    pub fn open_tap(&mut self, name: &[u8]) -> bool {
        self.tap.open(name)
    }

    /// Close TAP interface
    pub fn close_tap(&mut self) {
        self.tap.close();
    }

    /// Get TAP interface reference
    pub fn tap(&self) -> &TapInterface {
        &self.tap
    }

    /// Get mutable TAP interface reference
    pub fn tap_mut(&mut self) -> &mut TapInterface {
        &mut self.tap
    }

    /// Enqueue a packet for RX (host -> guest).
    /// Returns true if the packet was queued successfully.
    pub fn enqueue_rx(&mut self, data: &[u8]) -> bool {
        let tail = self.rx_tail.load(Ordering::Acquire);
        let next = (tail + 1) % 16;
        if next == self.rx_head.load(Ordering::Acquire) {
            return false; // Buffer full
        }
        let len = data.len().min(VIRTIO_NET_MAX_PACKET_SIZE);
        self.rx_packets[tail as usize][..len].copy_from_slice(&data[..len]);
        self.rx_lengths[tail as usize] = len as u16;
        self.rx_tail.store(next, Ordering::Release);
        true
    }

    /// Dequeue a packet from RX queue.
    pub fn dequeue_rx(&mut self) -> Option<&[u8]> {
        let head = self.rx_head.load(Ordering::Acquire);
        if head == self.rx_tail.load(Ordering::Acquire) {
            return None; // Empty
        }
        let len = self.rx_lengths[head as usize] as usize;
        let next = (head + 1) % 16;
        self.rx_head.store(next, Ordering::Release);
        Some(&self.rx_packets[head as usize][..len])
    }

    /// Enqueue a packet for TX (guest -> host).
    pub fn enqueue_tx(&mut self, data: &[u8]) -> bool {
        let tail = self.tx_tail.load(Ordering::Acquire);
        let next = (tail + 1) % 16;
        if next == self.tx_head.load(Ordering::Acquire) {
            return false;
        }
        let len = data.len().min(VIRTIO_NET_MAX_PACKET_SIZE);
        self.tx_packets[tail as usize][..len].copy_from_slice(&data[..len]);
        self.tx_lengths[tail as usize] = len as u16;
        self.tx_tail.store(next, Ordering::Release);
        true
    }

    /// Dequeue a packet from TX queue (for host to process).
    pub fn dequeue_tx(&mut self) -> Option<&[u8]> {
        let head = self.tx_head.load(Ordering::Acquire);
        if head == self.tx_tail.load(Ordering::Acquire) {
            return None;
        }
        let len = self.tx_lengths[head as usize] as usize;
        let next = (head + 1) % 16;
        self.tx_head.store(next, Ordering::Release);
        Some(&self.tx_packets[head as usize][..len])
    }

    /// Check if there are pending RX packets.
    pub fn has_rx(&self) -> bool {
        self.rx_head.load(Ordering::Acquire) != self.rx_tail.load(Ordering::Acquire)
    }

    /// Check if there are pending TX packets.
    pub fn has_tx(&self) -> bool {
        self.tx_head.load(Ordering::Acquire) != self.tx_tail.load(Ordering::Acquire)
    }
}

pub struct VirtIoNetBackend {
    net: VirtIoNet,
    /// Packet buffer for RX/TX
    buffer: NetPacketBuffer,
    /// TX virtqueue (queue 0)
    tx_vq: SplitVirtqueue,
    /// RX virtqueue (queue 1)
    rx_vq: SplitVirtqueue,
    /// Packet processing buffer
    pkt_buf: [u8; VIRTIO_NET_MAX_PACKET_SIZE],
}

impl VirtIoNetBackend {
    pub fn new() -> Self {
        Self {
            net: VirtIoNet::new(),
            buffer: NetPacketBuffer::new(),
            tx_vq: SplitVirtqueue::new(),
            rx_vq: SplitVirtqueue::new(),
            pkt_buf: [0u8; VIRTIO_NET_MAX_PACKET_SIZE],
        }
    }

    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.net.set_mac(mac);
    }

    pub fn set_mtu(&mut self, mtu: u16) {
        self.net.set_mtu(mtu);
    }

    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        self.net.get_stats()
    }

    /// Setup TX virtqueue.
    pub fn setup_tx_queue(&mut self, size: u16, desc: u64, avail: u64, used: u64, guest_base: u64) {
        self.tx_vq.setup(size, desc, avail, used, guest_base);
        self.net.set_tx_ready(true);
    }

    /// Setup RX virtqueue.
    pub fn setup_rx_queue(&mut self, size: u16, desc: u64, avail: u64, used: u64, guest_base: u64) {
        self.rx_vq.setup(size, desc, avail, used, guest_base);
        self.net.set_rx_ready(true);
    }

    /// Inject a packet into the RX queue (from host to guest).
    /// This is used to simulate incoming network traffic.
    pub fn inject_rx_packet(&mut self, data: &[u8]) -> bool {
        self.buffer.enqueue_rx(data)
    }

    /// Retrieve a TX packet (from guest to host).
    /// This is used to process outgoing network traffic.
    pub fn retrieve_tx_packet(&mut self) -> Option<&[u8]> {
        self.buffer.dequeue_tx()
    }

    /// Process TX requests from the guest.
    /// Reads packets from the TX virtqueue and enqueues them.
    pub fn process_tx(&mut self) -> u32 {
        let mut processed = 0u32;

        while let Some(head) = self.tx_vq.pop_avail() {
            let mut chain = self.tx_vq.walk_chain(head);
            let mut total_len = 0usize;

            // First descriptor is the virtio_net_hdr (skip it for data)
            let _hdr = chain.next();

            // Read packet data from remaining descriptors
            for desc in chain.by_ref() {
                if desc.write {
                    continue; // Skip write-only descriptors for TX
                }
                let src_ptr = (self.tx_vq.guest_base + desc.addr) as *const u8;
                let copy_len = (total_len + desc.len as usize).min(VIRTIO_NET_MAX_PACKET_SIZE);
                if copy_len > total_len {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            src_ptr,
                            self.pkt_buf[total_len..].as_mut_ptr(),
                            copy_len - total_len,
                        );
                    }
                }
                total_len = copy_len;
            }

            // Enqueue the packet for host processing
            if total_len > 0 {
                self.buffer.enqueue_tx(&self.pkt_buf[..total_len]);
            }

            self.tx_vq.push_used(head, total_len as u32);
            self.net.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.net.tx_bytes.fetch_add(total_len as u64, Ordering::Relaxed);
            processed += 1;
        }

        processed
    }

    /// Process RX requests to the guest.
    /// Fills guest buffers with packets from the RX queue.
    pub fn process_rx(&mut self) -> u32 {
        let mut processed = 0u32;

        while let Some(pkt_data) = self.buffer.dequeue_rx() {
            // Get a buffer from the RX virtqueue
            let head = match self.rx_vq.pop_avail() {
                Some(h) => h,
                None => {
                    // No buffers available, put packet back
                    // (simplified: just drop it)
                    break;
                }
            };

            let mut chain = self.rx_vq.walk_chain(head);
            let mut written = 0usize;

            // First descriptor is for virtio_net_hdr
            if let Some(hdr_desc) = chain.next() {
                if hdr_desc.write {
                    // Write a minimal virtio_net_hdr
                    let hdr = VirtNetHdr::new();
                    let hdr_bytes = hdr.to_le_bytes();
                    let hdr_ptr = (self.rx_vq.guest_base + hdr_desc.addr) as *mut u8;
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            hdr_bytes.as_ptr(),
                            hdr_ptr,
                            core::cmp::min(hdr_desc.len as usize, VirtNetHdr::size()),
                        );
                    }
                }
            }

            // Write packet data to remaining descriptors
            for desc in chain.by_ref() {
                if !desc.write {
                    continue;
                }
                let remaining = pkt_data.len().saturating_sub(written);
                if remaining == 0 {
                    break;
                }
                let write_len = remaining.min(desc.len as usize);
                let dst_ptr = (self.rx_vq.guest_base + desc.addr) as *mut u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        pkt_data[written..written + write_len].as_ptr(),
                        dst_ptr,
                        write_len,
                    );
                }
                written += write_len;
            }

            // Include header in total length
            let total_len = VirtNetHdr::size() + written;
            self.rx_vq.push_used(head, total_len as u32);
            self.net.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.net.rx_bytes.fetch_add(total_len as u64, Ordering::Relaxed);
            processed += 1;
        }

        processed
    }

    /// Check if there are pending RX packets to process.
    pub fn has_pending_rx(&self) -> bool {
        self.buffer.has_rx()
    }

    /// Check if there are pending TX packets from guest.
    pub fn has_pending_tx(&self) -> bool {
        self.buffer.has_tx()
    }
}

impl Default for VirtIoNetBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtIODevice for VirtIoNetBackend {
    fn device_type(&self) -> VirtIoDeviceType {
        self.net.device_type()
    }

    fn device_id(&self) -> u32 {
        self.net.device_id()
    }

    fn vendor_id(&self) -> u32 {
        self.net.vendor_id()
    }

    fn get_features(&self) -> u64 {
        self.net.get_features()
    }

    fn set_features(&mut self, features: u64) -> Result<(), HvError> {
        self.net.set_features(features)
    }

    fn get_status(&self) -> u32 {
        self.net.get_status()
    }

    fn set_status(&mut self, status: u32) -> Result<(), HvError> {
        self.net.set_status(status)
    }

    fn read_config(&self, offset: u32, data: &mut [u8]) -> Result<(), HvError> {
        self.net.read_config(offset, data)
    }

    fn write_config(&mut self, offset: u32, data: &[u8]) -> Result<(), HvError> {
        self.net.write_config(offset, data)
    }

    fn queue_notify(&mut self, queue: u32) -> Result<bool, HvError> {
        self.net.queue_notify(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_notify_requires_tx_ready() {
        let mut net = VirtIoNet::new();
        assert!(!net.queue_notify(0).unwrap());
        net.set_tx_ready(true);
        assert!(net.queue_notify(0).unwrap());
        let (_rxp, txp, _rxb, txb) = net.get_stats();
        assert_eq!(txp, 1);
        assert_eq!(txb, 64);
    }

    #[test]
    fn rx_notify_requires_rx_ready() {
        let mut net = VirtIoNet::new();
        assert!(!net.queue_notify(1).unwrap());
        net.set_rx_ready(true);
        assert!(net.queue_notify(1).unwrap());
        let (rxp, _txp, rxb, _txb) = net.get_stats();
        assert_eq!(rxp, 1);
        assert_eq!(rxb, 64);
    }
}
