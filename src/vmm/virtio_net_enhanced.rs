//! VirtIO Network Enhancements
//!
//! RSS (Receive Side Scaling), hash offload, and performance optimizations.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// VirtIO-Net Feature Flags
// ─────────────────────────────────────────────────────────────────────────────

pub const VIRTIO_NET_F_CSUM: u32 = 0;           // Host handles partial csum
pub const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;     // Guest handles partial csum
pub const VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u32 = 2;
pub const VIRTIO_NET_F_MTU: u32 = 3;
pub const VIRTIO_NET_F_MAC: u32 = 5;
pub const VIRTIO_NET_F_GSO: u32 = 6;
pub const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
pub const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
pub const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
pub const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
pub const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
pub const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
pub const VIRTIO_NET_F_HOST_ECN: u32 = 13;
pub const VIRTIO_NET_F_HOST_UFO: u32 = 14;
pub const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
pub const VIRTIO_NET_F_STATUS: u32 = 16;
pub const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
pub const VIRTIO_NET_F_CTRL_RX: u32 = 18;
pub const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
pub const VIRTIO_NET_F_GUEST_ANNOUNCE: u32 = 21;
pub const VIRTIO_NET_F_MQ: u32 = 22;
pub const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;
pub const VIRTIO_NET_F_HASH_TUNNEL: u32 = 51;
pub const VIRTIO_NET_F_HASH_REPORT: u32 = 57;
pub const VIRTIO_NET_F_RSS: u32 = 60;
pub const VIRTIO_NET_F_RSC_EXT: u32 = 61;
pub const VIRTIO_NET_F_STANDBY: u32 = 62;
pub const VIRTIO_NET_F_SPEED_DUPLEX: u32 = 63;

// ─────────────────────────────────────────────────────────────────────────────
// RSS Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum RSS indirection table entries
pub const RSS_MAX_INDIRECTION: usize = 128;

/// RSS hash types
pub mod rss_hash {
    pub const IPV4: u32 = 1 << 0;
    pub const TCPV4: u32 = 1 << 1;
    pub const UDPV4: u32 = 1 << 2;
    pub const IPV6: u32 = 1 << 3;
    pub const TCPV6: u32 = 1 << 4;
    pub const UDPV6: u32 = 1 << 5;
    pub const IPV6_EX: u32 = 1 << 6;
    pub const TCPV6_EX: u32 = 1 << 7;
    pub const UDPV6_EX: u32 = 1 << 8;
    pub const ESPV4: u32 = 1 << 9;
    pub const AHV4: u32 = 1 << 10;
    pub const ESPV6: u32 = 1 << 11;
    pub const AHV6: u32 = 1 << 12;
    pub const SCTPV4: u32 = 1 << 13;
    pub const SCTPV6: u32 = 1 << 14;
}

/// RSS configuration
#[repr(C)]
pub struct RssConfig {
    /// Supported hash types
    pub supported_hashes: AtomicU32,
    /// Enabled hash types
    pub enabled_hashes: AtomicU32,
    /// Hash key (40 bytes for Toeplitz)
    pub hash_key: [AtomicU8; 40],
    /// Indirection table (maps hash to queue)
    pub indirection_table: [AtomicU16; RSS_MAX_INDIRECTION],
    /// Number of queues for RSS
    pub num_queues: AtomicU16,
    /// RSS enabled
    pub enabled: AtomicU8,
    /// Max key size
    pub max_key_size: AtomicU16,
    /// Max indirection table size
    pub max_indirection_size: AtomicU16,
}

impl RssConfig {
    pub const fn new() -> Self {
        Self {
            supported_hashes: AtomicU32::new(
                rss_hash::IPV4 | rss_hash::TCPV4 | rss_hash::UDPV4 |
                rss_hash::IPV6 | rss_hash::TCPV6 | rss_hash::UDPV6
            ),
            enabled_hashes: AtomicU32::new(0),
            hash_key: [const { AtomicU8::new(0) }; 40],
            indirection_table: [const { AtomicU16::new(0) }; RSS_MAX_INDIRECTION],
            num_queues: AtomicU16::new(1),
            enabled: AtomicU8::new(0),
            max_key_size: AtomicU16::new(40),
            max_indirection_size: AtomicU16::new(RSS_MAX_INDIRECTION as u16),
        }
    }

    /// Configure RSS
    pub fn configure(&self, hash_types: u32, num_queues: u16) -> Result<(), HvError> {
        if hash_types & !self.supported_hashes.load(Ordering::Acquire) != 0 {
            return Err(HvError::LogicalFault);
        }
        
        self.enabled_hashes.store(hash_types, Ordering::Release);
        self.num_queues.store(num_queues, Ordering::Release);
        self.enabled.store(1, Ordering::Release);
        
        // Initialize indirection table with round-robin
        for i in 0..RSS_MAX_INDIRECTION {
            self.indirection_table[i].store((i % num_queues as usize) as u16, Ordering::Release);
        }
        
        Ok(())
    }

    /// Set hash key
    pub fn set_hash_key(&self, key: &[u8; 40]) {
        for i in 0..40 {
            self.hash_key[i].store(key[i], Ordering::Release);
        }
    }

    /// Set indirection table entry
    pub fn set_indirection(&self, index: usize, queue: u16) -> Result<(), HvError> {
        if index >= RSS_MAX_INDIRECTION {
            return Err(HvError::LogicalFault);
        }
        if queue >= self.num_queues.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        
        self.indirection_table[index].store(queue, Ordering::Release);
        Ok(())
    }

    /// Calculate Toeplitz hash
    pub fn calculate_hash(&self, data: &[u8]) -> u32 {
        let key: [u8; 40] = core::array::from_fn(|i| self.hash_key[i].load(Ordering::Acquire));
        
        // Toeplitz hash algorithm
        let mut result = 0u32;
        let mut key_bit = 0usize;
        
        for byte in data {
            for bit in (0..8).rev() {
                if (byte >> bit) & 1 != 0 {
                    result ^= u32::from_be_bytes([
                        key[key_bit / 8],
                        if key_bit / 8 + 1 < 40 { key[key_bit / 8 + 1] } else { 0 },
                        if key_bit / 8 + 2 < 40 { key[key_bit / 8 + 2] } else { 0 },
                        if key_bit / 8 + 3 < 40 { key[key_bit / 8 + 3] } else { 0 },
                    ]) << (key_bit % 8);
                }
                key_bit += 1;
            }
        }
        
        result
    }

    /// Get queue for hash
    pub fn get_queue_for_hash(&self, hash: u32) -> u16 {
        let idx = (hash as usize) % RSS_MAX_INDIRECTION;
        self.indirection_table[idx].load(Ordering::Acquire)
    }

    /// Disable RSS
    pub fn disable(&self) {
        self.enabled.store(0, Ordering::Release);
        self.enabled_hashes.store(0, Ordering::Release);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hash Report
// ─────────────────────────────────────────────────────────────────────────────

/// Hash report in packet metadata
#[repr(C)]
pub struct HashReport {
    /// Hash value
    pub hash: u32,
    /// Hash type
    pub hash_type: u16,
    /// Reserved
    pub reserved: u16,
}

/// Hash types for reporting
pub mod hash_type {
    pub const IPV4: u16 = 1;
    pub const TCPV4: u16 = 2;
    pub const UDPV4: u16 = 3;
    pub const IPV6: u16 = 4;
    pub const TCPV6: u16 = 5;
    pub const UDPV6: u16 = 6;
    pub const IPV6_EX: u16 = 7;
    pub const TCPV6_EX: u16 = 8;
    pub const UDPV6_EX: u16 = 9;
    pub const ESPV4: u16 = 10;
    pub const AHV4: u16 = 11;
    pub const ESPV6: u16 = 12;
    pub const AHV6: u16 = 13;
    pub const SCTPV4: u16 = 14;
    pub const SCTPV6: u16 = 15;
}

// ─────────────────────────────────────────────────────────────────────────────
// Offload Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Offload features
#[repr(C)]
pub struct OffloadConfig {
    /// TX checksum offload
    pub tx_csum: AtomicU8,
    /// TX TCP segmentation offload
    pub tx_tso: AtomicU8,
    /// TX UDP fragmentation offload
    pub tx_ufo: AtomicU8,
    /// TX ECN support
    pub tx_ecn: AtomicU8,
    /// RX checksum offload
    pub rx_csum: AtomicU8,
    /// RX TCP segmentation coalescing
    pub rx_tso: AtomicU8,
    /// RX UDP fragmentation coalescing
    pub rx_ufo: AtomicU8,
    /// RX ECN support
    pub rx_ecn: AtomicU8,
    /// Generic segmentation offload
    pub gso: AtomicU8,
    /// Generic receive offload
    pub gro: AtomicU8,
    /// Maximum segment size
    pub max_segment_size: AtomicU16,
}

impl OffloadConfig {
    pub const fn new() -> Self {
        Self {
            tx_csum: AtomicU8::new(1),
            tx_tso: AtomicU8::new(1),
            tx_ufo: AtomicU8::new(0),
            tx_ecn: AtomicU8::new(1),
            rx_csum: AtomicU8::new(1),
            rx_tso: AtomicU8::new(1),
            rx_ufo: AtomicU8::new(0),
            rx_ecn: AtomicU8::new(1),
            gso: AtomicU8::new(1),
            gro: AtomicU8::new(1),
            max_segment_size: AtomicU16::new(65535),
        }
    }

    /// Get supported offload features
    pub fn get_features(&self) -> u32 {
        let mut features = 0u32;
        
        if self.tx_csum.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_CSUM;
        }
        if self.rx_csum.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_GUEST_CSUM;
        }
        if self.tx_tso.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6;
        }
        if self.rx_tso.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6;
        }
        if self.tx_ecn.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_HOST_ECN;
        }
        if self.rx_ecn.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_GUEST_ECN;
        }
        if self.gso.load(Ordering::Acquire) != 0 {
            features |= VIRTIO_NET_F_GSO;
        }
        
        features
    }

    /// Configure offloads from feature bits
    pub fn configure(&self, features: u32) {
        self.tx_csum.store(
            ((features & VIRTIO_NET_F_CSUM) != 0) as u8,
            Ordering::Release
        );
        self.rx_csum.store(
            ((features & VIRTIO_NET_F_GUEST_CSUM) != 0) as u8,
            Ordering::Release
        );
        self.tx_tso.store(
            ((features & (VIRTIO_NET_F_HOST_TSO4 | VIRTIO_NET_F_HOST_TSO6)) != 0) as u8,
            Ordering::Release
        );
        self.rx_tso.store(
            ((features & (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6)) != 0) as u8,
            Ordering::Release
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtIO-Net Control Commands
// ─────────────────────────────────────────────────────────────────────────────

/// Control queue commands
pub mod ctrl_cmd {
    pub const VIRTIO_NET_CTRL_RX: u8 = 0;
    pub const VIRTIO_NET_CTRL_MAC: u8 = 1;
    pub const VIRTIO_NET_CTRL_VLAN: u8 = 2;
    pub const VIRTIO_NET_CTRL_ANNOUNCE: u8 = 3;
    pub const VIRTIO_NET_CTRL_MQ: u8 = 4;
    pub const VIRTIO_NET_CTRL_OFFLOADS: u8 = 5;
    pub const VIRTIO_NET_CTRL_RSS: u8 = 6;
}

/// RX mode commands
pub mod rx_cmd {
    pub const PROMISC: u8 = 0;
    pub const ALLMULTI: u8 = 1;
    pub const NONE: u8 = 2;
    pub const NOMULTI: u8 = 3;
    pub const NOUNI: u8 = 4;
    pub const NOBCAST: u8 = 5;
}

/// MQ commands
pub mod mq_cmd {
    pub const VQ_PAIRS_SET: u8 = 0;
    pub const VQ_PAIRS_MIN: u16 = 1;
    pub const VQ_PAIRS_MAX: u16 = 256;
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtIO-Net Enhanced Controller
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum queue pairs
pub const MAX_QUEUE_PAIRS: usize = 256;

/// VirtIO-Net enhanced controller
pub struct VirtioNetEnhanced {
    /// MAC address
    pub mac: [AtomicU8; 6],
    /// Status (link up, etc.)
    pub status: AtomicU16,
    /// Maximum queue pairs
    pub max_queue_pairs: AtomicU16,
    /// Current queue pairs
    pub curr_queue_pairs: AtomicU16,
    /// MTU
    pub mtu: AtomicU16,
    /// Speed (Mbps)
    pub speed: AtomicU32,
    /// Duplex (0=half, 1=full)
    pub duplex: AtomicU8,
    /// RSS configuration
    pub rss: RssConfig,
    /// Offload configuration
    pub offloads: OffloadConfig,
    /// RX mode
    pub rx_mode: AtomicU8,
    /// Promiscuous mode
    pub promisc: AtomicBool,
    /// All-multicast mode
    pub allmulti: AtomicBool,
    /// MAC filter table
    pub mac_table: [AtomicU64; 32], // 32 MAC addresses
    /// MAC table size
    pub mac_table_size: AtomicU16,
    /// VLAN filter table
    pub vlan_table: [AtomicU16; 4096 / 16], // 4096 VLANs bitmap
    /// Features negotiated
    pub features: AtomicU64,
    /// Hash report enabled
    pub hash_report: AtomicBool,
}

impl VirtioNetEnhanced {
    pub const fn new() -> Self {
        Self {
            mac: [const { AtomicU8::new(0) }; 6],
            status: AtomicU16::new(1), // Link up
            max_queue_pairs: AtomicU16::new(MAX_QUEUE_PAIRS as u16),
            curr_queue_pairs: AtomicU16::new(1),
            mtu: AtomicU16::new(1500),
            speed: AtomicU32::new(10000), // 10 Gbps
            duplex: AtomicU8::new(1), // Full duplex
            rss: RssConfig::new(),
            offloads: OffloadConfig::new(),
            rx_mode: AtomicU8::new(0),
            promisc: AtomicBool::new(false),
            allmulti: AtomicBool::new(false),
            mac_table: [const { AtomicU64::new(0) }; 32],
            mac_table_size: AtomicU16::new(0),
            vlan_table: [const { AtomicU16::new(0) }; 4096 / 16],
            features: AtomicU64::new(0),
            hash_report: AtomicBool::new(false),
        }
    }

    /// Initialize with MAC address
    pub fn init(&mut self, mac: [u8; 6]) {
        for i in 0..6 {
            self.mac[i].store(mac[i], Ordering::Release);
        }
    }

    /// Set link status
    pub fn set_link_status(&self, up: bool) {
        if up {
            self.status.fetch_or(1, Ordering::Release);
        } else {
            self.status.fetch_and(!1, Ordering::Release);
        }
    }

    /// Set queue pairs
    pub fn set_queue_pairs(&self, pairs: u16) -> Result<(), HvError> {
        if pairs == 0 || pairs > self.max_queue_pairs.load(Ordering::Acquire) {
            return Err(HvError::LogicalFault);
        }
        self.curr_queue_pairs.store(pairs, Ordering::Release);
        Ok(())
    }

    /// Add MAC to filter table
    pub fn add_mac(&self, mac: [u8; 6]) -> Result<(), HvError> {
        let size = self.mac_table_size.load(Ordering::Acquire);
        if size as usize >= self.mac_table.len() {
            return Err(HvError::LogicalFault);
        }
        
        // Store as u64 (6 bytes MAC + 2 bytes padding)
        let mac_val = (mac[0] as u64)
            | ((mac[1] as u64) << 8)
            | ((mac[2] as u64) << 16)
            | ((mac[3] as u64) << 24)
            | ((mac[4] as u64) << 32)
            | ((mac[5] as u64) << 40);
        
        self.mac_table[size as usize].store(mac_val, Ordering::Release);
        self.mac_table_size.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Remove MAC from filter table
    pub fn remove_mac(&self, mac: [u8; 6]) -> Result<(), HvError> {
        let mac_val = (mac[0] as u64)
            | ((mac[1] as u64) << 8)
            | ((mac[2] as u64) << 16)
            | ((mac[3] as u64) << 24)
            | ((mac[4] as u64) << 32)
            | ((mac[5] as u64) << 40);
        
        let size = self.mac_table_size.load(Ordering::Acquire);
        for i in 0..size as usize {
            if self.mac_table[i].load(Ordering::Acquire) == mac_val {
                // Shift remaining entries
                for j in i..(size as usize - 1) {
                    let next = self.mac_table[j + 1].load(Ordering::Acquire);
                    self.mac_table[j].store(next, Ordering::Release);
                }
                self.mac_table_size.fetch_sub(1, Ordering::Release);
                return Ok(());
            }
        }
        Err(HvError::LogicalFault)
    }

    /// Add VLAN to filter
    pub fn add_vlan(&self, vlan_id: u16) {
        let idx = vlan_id as usize / 16;
        let bit = vlan_id % 16;
        self.vlan_table[idx].fetch_or(1 << bit, Ordering::Release);
    }

    /// Remove VLAN from filter
    pub fn remove_vlan(&self, vlan_id: u16) {
        let idx = vlan_id as usize / 16;
        let bit = vlan_id % 16;
        self.vlan_table[idx].fetch_and(!(1 << bit), Ordering::Release);
    }

    /// Check if VLAN is allowed
    pub fn is_vlan_allowed(&self, vlan_id: u16) -> bool {
        let idx = vlan_id as usize / 16;
        let bit = vlan_id % 16;
        (self.vlan_table[idx].load(Ordering::Acquire) & (1 << bit)) != 0
    }

    /// Process control command
    pub fn process_ctrl(&mut self, class: u8, cmd: u8, data: &[u8]) -> Result<u8, HvError> {
        match class {
            ctrl_cmd::VIRTIO_NET_CTRL_RX => {
                match cmd {
                    rx_cmd::PROMISC => {
                        self.promisc.store(data[0] != 0, Ordering::Release);
                        self.rx_mode.store(data[0], Ordering::Release);
                    }
                    rx_cmd::ALLMULTI => {
                        self.allmulti.store(data[0] != 0, Ordering::Release);
                    }
                    _ => return Err(HvError::LogicalFault),
                }
            }
            ctrl_cmd::VIRTIO_NET_CTRL_MAC => {
                // MAC table set/add
                let _entries = data[0] as usize;
                // Would process MAC entries
            }
            ctrl_cmd::VIRTIO_NET_CTRL_VLAN => {
                let vlan_id = u16::from_le_bytes([data[0], data[1]]);
                if cmd == 0 {
                    self.add_vlan(vlan_id);
                } else {
                    self.remove_vlan(vlan_id);
                }
            }
            ctrl_cmd::VIRTIO_NET_CTRL_MQ => {
                let pairs = u16::from_le_bytes([data[0], data[1]]);
                self.set_queue_pairs(pairs)?;
            }
            ctrl_cmd::VIRTIO_NET_CTRL_OFFLOADS => {
                let offloads = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3],
                    data[4], data[5], data[6], data[7],
                ]);
                self.configure_offloads(offloads);
            }
            ctrl_cmd::VIRTIO_NET_CTRL_RSS => {
                self.configure_rss(data)?;
            }
            _ => return Err(HvError::LogicalFault),
        }
        Ok(0) // VIRTIO_NET_OK
    }

    /// Configure offloads
    fn configure_offloads(&self, offloads: u64) {
        self.offloads.tx_csum.store(((offloads >> 0) & 1) as u8, Ordering::Release);
        self.offloads.tx_tso.store(((offloads >> 1) & 1) as u8, Ordering::Release);
        self.offloads.tx_ufo.store(((offloads >> 2) & 1) as u8, Ordering::Release);
        self.offloads.tx_ecn.store(((offloads >> 3) & 1) as u8, Ordering::Release);
        self.offloads.rx_csum.store(((offloads >> 5) & 1) as u8, Ordering::Release);
        self.offloads.rx_tso.store(((offloads >> 6) & 1) as u8, Ordering::Release);
        self.offloads.rx_ufo.store(((offloads >> 7) & 1) as u8, Ordering::Release);
        self.offloads.rx_ecn.store(((offloads >> 8) & 1) as u8, Ordering::Release);
    }

    /// Configure RSS from control data
    fn configure_rss(&self, data: &[u8]) -> Result<(), HvError> {
        if data.len() < 4 {
            return Err(HvError::LogicalFault);
        }
        
        let hash_types = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let num_queues = self.curr_queue_pairs.load(Ordering::Acquire);
        
        self.rss.configure(hash_types, num_queues)
    }

    /// Calculate packet hash for RSS
    pub fn calculate_packet_hash(&self, packet: &[u8], hash_types: u32) -> (u32, u16) {
        // Parse packet headers and calculate hash
        let (hash_data, ht) = self.extract_hash_data(packet, hash_types);
        
        let hash = self.rss.calculate_hash(&hash_data);
        (hash, ht)
    }

    /// Extract data for hashing from packet
    fn extract_hash_data(&self, packet: &[u8], hash_types: u32) -> ([u8; 64], u16) {
        let mut data = [0u8; 64];
        let mut data_len = 0;
        let mut ht = hash_type::IPV4;
        
        // Simple IPv4/TCP extraction (would be full parser in production)
        if packet.len() < 20 {
            return (data, ht);
        }
        
        let ip_version = (packet[0] >> 4) & 0xF;
        
        if ip_version == 4 && (hash_types & rss_hash::IPV4) != 0 {
            // IPv4: src IP, dst IP
            if packet.len() >= 20 {
                data[data_len..data_len + 4].copy_from_slice(&packet[12..16]); // Src IP
                data_len += 4;
                data[data_len..data_len + 4].copy_from_slice(&packet[16..20]); // Dst IP
                data_len += 4;
                
                let protocol = packet[9];
                let ip_hdr_len = (packet[0] & 0xF) as usize * 4;
                
                if protocol == 6 && (hash_types & rss_hash::TCPV4) != 0 && packet.len() >= ip_hdr_len + 4 {
                    // TCP: src port, dst port
                    data[data_len..data_len + 2].copy_from_slice(&packet[ip_hdr_len..ip_hdr_len + 2]);
                    data[data_len..data_len + 4].copy_from_slice(&packet[ip_hdr_len + 2..ip_hdr_len + 4]);
                    ht = hash_type::TCPV4;
                } else if protocol == 17 && (hash_types & rss_hash::UDPV4) != 0 && packet.len() >= ip_hdr_len + 4 {
                    // UDP: src port, dst port
                    data[data_len..data_len + 2].copy_from_slice(&packet[ip_hdr_len..ip_hdr_len + 2]);
                    data[data_len..data_len + 4].copy_from_slice(&packet[ip_hdr_len + 2..ip_hdr_len + 4]);
                    ht = hash_type::UDPV4;
                }
            }
        }
        
        (data, ht)
    }

    /// Get RX queue for packet
    pub fn get_rx_queue(&self, packet: &[u8]) -> u16 {
        if self.rss.enabled.load(Ordering::Acquire) == 0 {
            return 0;
        }
        
        let hash_types = self.rss.enabled_hashes.load(Ordering::Acquire);
        let (hash, _) = self.calculate_packet_hash(packet, hash_types);
        self.rss.get_queue_for_hash(hash)
    }

    /// Get config bytes
    pub fn get_config(&self) -> [u8; 64] {
        let mut config = [0u8; 64];
        
        // MAC address (6 bytes)
        for i in 0..6 {
            config[i] = self.mac[i].load(Ordering::Acquire);
        }
        
        // Status (2 bytes)
        config[6] = self.status.load(Ordering::Acquire) as u8;
        config[7] = (self.status.load(Ordering::Acquire) >> 8) as u8;
        
        // Max queue pairs (2 bytes)
        config[8] = self.max_queue_pairs.load(Ordering::Acquire) as u8;
        config[9] = (self.max_queue_pairs.load(Ordering::Acquire) >> 8) as u8;
        
        // MTU (2 bytes)
        config[10] = self.mtu.load(Ordering::Acquire) as u8;
        config[11] = (self.mtu.load(Ordering::Acquire) >> 8) as u8;
        
        // Speed (4 bytes)
        let speed = self.speed.load(Ordering::Acquire);
        config[12..16].copy_from_slice(&speed.to_le_bytes());
        
        // Duplex (1 byte)
        config[16] = self.duplex.load(Ordering::Acquire);
        
        config
    }
}

impl Default for VirtioNetEnhanced {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rss_configure() {
        let rss = RssConfig::new();
        
        rss.configure(rss_hash::TCPV4 | rss_hash::TCPV6, 4).unwrap();
        
        assert_eq!(rss.num_queues.load(Ordering::Acquire), 4);
        assert!(rss.enabled.load(Ordering::Acquire) != 0);
    }

    #[test]
    fn rss_hash() {
        let rss = RssConfig::new();
        rss.configure(rss_hash::IPV4, 2).unwrap();
        
        // Set a non-zero hash key (default is all zeros which produces 0 hash)
        let key: [u8; 40] = core::array::from_fn(|i| (i + 1) as u8);
        rss.set_hash_key(&key);
        
        let hash = rss.calculate_hash(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_ne!(hash, 0);
    }

    #[test]
    fn net_init() {
        let mut net = VirtioNetEnhanced::new();
        net.init([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        
        let config = net.get_config();
        assert_eq!(config[0..6], [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    }

    #[test]
    fn net_vlan_filter() {
        let net = VirtioNetEnhanced::new();
        
        net.add_vlan(100);
        assert!(net.is_vlan_allowed(100));
        assert!(!net.is_vlan_allowed(101));
        
        net.remove_vlan(100);
        assert!(!net.is_vlan_allowed(100));
    }

    #[test]
    fn net_mac_filter() {
        let net = VirtioNetEnhanced::new();
        
        net.add_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
        assert_eq!(net.mac_table_size.load(Ordering::Acquire), 1);
        
        net.remove_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
        assert_eq!(net.mac_table_size.load(Ordering::Acquire), 0);
    }

    #[test]
    fn net_queue_pairs() {
        let net = VirtioNetEnhanced::new();
        
        net.set_queue_pairs(8).unwrap();
        assert_eq!(net.curr_queue_pairs.load(Ordering::Acquire), 8);
    }
}
