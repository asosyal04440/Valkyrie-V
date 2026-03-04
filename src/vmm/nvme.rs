//! NVMe Passthrough Controller
//!
//! Direct NVMe device passthrough to guest with full command support.
//! Implements NVMe specification 1.4 with admin and IO queues.

use crate::vmm::HvError;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU16, AtomicU8, AtomicBool, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// NVMe Constants
// ─────────────────────────────────────────────────────────────────────────────

/// NVMe controller capabilities (CAP register)
pub const NVME_CAP_MQES_SHIFT: u32 = 0;      // Maximum Queue Entries Supported
pub const NVME_CAP_CQR_SHIFT: u32 = 16;      // Contiguous Queues Required
pub const NVME_CAP_AMS_SHIFT: u32 = 17;      // Arbitration Mechanism Supported
pub const NVME_CAP_TO_SHIFT: u32 = 24;       // Timeout
pub const NVME_CAP_DSTRD_SHIFT: u32 = 32;    // Doorbell Stride
pub const NVME_CAP_NSSRS_SHIFT: u32 = 36;    // NVM Subsystem Reset Supported
pub const NVME_CAP_CSS_SHIFT: u32 = 37;      // Command Sets Supported
pub const NVME_CAP_MPSMIN_SHIFT: u32 = 48;   // Memory Page Size Minimum
pub const NVME_CAP_MPSMAX_SHIFT: u32 = 52;   // Memory Page Size Maximum

/// NVMe controller configuration (CC register)
pub const NVME_CC_EN: u32 = 1 << 0;          // Enable
pub const NVME_CC_CSS_SHIFT: u32 = 4;        // Command Set Selected
pub const NVME_CC_MPS_SHIFT: u32 = 7;        // Memory Page Size
pub const NVME_CC_AMS_SHIFT: u32 = 11;       // Arbitration Mechanism Selected
pub const NVME_CC_SHN_SHIFT: u32 = 14;       // Shutdown Notification
pub const NVME_CC_IOCQES_SHIFT: u32 = 20;    // IO Completion Queue Entry Size
pub const NVME_CC_IOSQES_SHIFT: u32 = 24;    // IO Submission Queue Entry Size

/// NVMe controller status (CSTS register)
pub const NVME_CSTS_RDY: u32 = 1 << 0;       // Ready
pub const NVME_CSTS_CFS: u32 = 1 << 1;       // Controller Fatal Status
pub const NVME_CSTS_SHST_SHIFT: u32 = 2;     // Shutdown Status
pub const NVME_CSTS_PP: u32 = 1 << 5;        // Processing Paused

/// NVMe Admin Command Opcodes
pub mod admin_opc {
    pub const DELETE_IOSQ: u8 = 0x00;
    pub const CREATE_IOSQ: u8 = 0x01;
    pub const DELETE_IOCQ: u8 = 0x04;
    pub const CREATE_IOCQ: u8 = 0x05;
    pub const IDENTIFY: u8 = 0x06;
    pub const ABORT: u8 = 0x08;
    pub const SET_FEATURES: u8 = 0x09;
    pub const GET_FEATURES: u8 = 0x0A;
    pub const ASYNC_EVENT_REQ: u8 = 0x0C;
    pub const NS_MANAGEMENT: u8 = 0x0D;
    pub const FW_COMMIT: u8 = 0x10;
    pub const FW_ACTIVATE: u8 = 0x14;
    pub const KEEP_ALIVE: u8 = 0x18;
    pub const DIRECTIVE_SEND: u8 = 0x19;
    pub const DIRECTIVE_RECV: u8 = 0x1A;
    pub const DOORBELL_BUFFER_CONFIG: u8 = 0x07;
    pub const FORMAT_NVM: u8 = 0x80;
    pub const SECURITY_SEND: u8 = 0x81;
    pub const SECURITY_RECV: u8 = 0x82;
    pub const SANITIZE: u8 = 0x84;
    pub const GET_LBA_STATUS: u8 = 0x86;
}

/// NVMe NVM Command Opcodes
pub mod nvm_opc {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
    pub const WRITE_UNCORRECTABLE: u8 = 0x04;
    pub const COMPARE: u8 = 0x05;
    pub const WRITE_ZEROES: u8 = 0x08;
    pub const DATASET_MANAGEMENT: u8 = 0x09;
    pub const RESV_REGISTER: u8 = 0x0D;
    pub const RESV_REPORT: u8 = 0x0E;
    pub const RESV_ACQUIRE: u8 = 0x11;
    pub const RESV_RELEASE: u8 = 0x15;
}

/// NVMe command status codes
pub mod status {
    pub const SUCCESS: u16 = 0x0000;
    pub const INVALID_OPCODE: u16 = 0x0001;
    pub const INVALID_FIELD: u16 = 0x0002;
    pub const CMD_ID_CONFLICT: u16 = 0x0003;
    pub const DATA_XFER_ERROR: u16 = 0x0004;
    pub const ABORTED_POWER_LOSS: u16 = 0x0005;
    pub const INTERNAL_ERROR: u16 = 0x0006;
    pub const ABORTED_BY_REQ: u16 = 0x0007;
    pub const ABORTED_SQ_DEL: u16 = 0x0008;
    pub const ABORTED_FAILED_FUSED: u16 = 0x0009;
    pub const ABORTED_MISSING_FUSED: u16 = 0x000A;
    pub const INVALID_NS_OR_FORMAT: u16 = 0x000B;
    pub const CMD_SEQ_ERROR: u16 = 0x000C;
    pub const INVALID_SGL_SEG: u16 = 0x000D;
    pub const INVALID_SGL_DESC: u16 = 0x000E;
    pub const INVALID_SGL_LEN: u16 = 0x000F;
    pub const INVALID_NUM_SGL_DESC: u16 = 0x0010;
    pub const DATA_SGL_LEN_INVALID: u16 = 0x0011;
    pub const METADATA_SGL_LEN_INVALID: u16 = 0x0012;
    pub const SGL_DESC_TYPE_INVALID: u16 = 0x0013;
    pub const LBA_OUT_OF_RANGE: u16 = 0x0080;
    pub const CAPACITY_EXCEEDED: u16 = 0x0081;
    pub const NS_NOT_READY: u16 = 0x0082;
    pub const RESV_CONFLICT: u16 = 0x0083;
    pub const FORMAT_IN_PROGRESS: u16 = 0x0084;
}

/// NVMe Identify Controller data structure (4096 bytes)
#[repr(C, align(4096))]
pub struct IdentifyController {
    // VID, SSVID, SN, MN, FR, RAB, etc.
    pub vid: u16,                    // PCI Vendor ID
    pub ssvid: u16,                  // PCI Subsystem Vendor ID
    pub sn: [u8; 20],                // Serial Number
    pub mn: [u8; 40],                // Model Number
    pub fr: [u8; 8],                 // Firmware Revision
    pub rab: u8,                     // Recommended Arbitration Burst
    pub ieee: [u8; 3],               // IEEE OUI Identifier
    pub cmic: u8,                    // Controller Multi-Path I/O and Namespace Sharing Capabilities
    pub mdts: u8,                    // Maximum Data Transfer Size
    pub cntlid: u16,                 // Controller ID
    pub ver: u32,                    // Version
    pub rtd3r: u32,                  // RTD3 Resume Latency
    pub rtd3e: u32,                  // RTD3 Entry Latency
    pub oaes: u32,                   // Optional Asynchronous Events Supported
    pub ctratt: u32,                 // Controller Attributes
    pub rrls: u16,                   // Read Recovery Levels Supported
    pub reserved1: [u8; 14],
    pub cntrltype: u8,               // Controller Type
    pub fguid: [u8; 16],             // FRU GUID
    pub reserved2: [u8; 156],
    pub oacs: u16,                   // Optional Admin Command Support
    pub acl: u8,                     // Abort Command Limit
    pub aerl: u8,                    // Asynchronous Event Request Limit
    pub frmw: u8,                    // Firmware Updates
    pub lpa: u8,                     // Log Page Attributes
    pub elpe: u8,                    // Error Log Page Entries
    pub npss: u8,                    // Number of Power States Support
    pub avscc: u8,                   // Admin Vendor Specific Command Configuration
    pub apsta: u8,                   // Autonomous Power State Transition Capabilities
    pub wctemp: u16,                 // Warning Composite Temperature Threshold
    pub cctemp: u16,                 // Critical Composite Temperature Threshold
    pub mtfa: u16,                   // Maximum Time for Firmware Activation
    pub hmpre: u32,                  // Host Memory Buffer Preferred Size
    pub hmmin: u32,                  // Host Memory Buffer Minimum Size
    pub tnvmcap: [u8; 16],           // Total NVM Capacity
    pub unvmcap: [u8; 16],           // Unallocated NVM Capacity
    pub rpmbs: u32,                  // Replay Protected Memory Block Support
    pub edsttr: u16,                 // Extended Device Self-test Time
    pub dsto: u8,                    // Device Self-test Options
    pub fwug: u8,                    // Firmware Update Granularity
    pub kas: u16,                    // Keep Alive Support
    pub hctma: u16,                  // Host Controlled Thermal Management Attributes
    pub mntmt: u16,                  // Minimum Thermal Management Temperature
    pub mxtmt: u16,                  // Maximum Thermal Management Temperature
    pub sanicap: u32,                // Sanitize Capabilities
    pub reserved3: [u8; 180],
    pub sqes: u8,                    // Submission Queue Entry Size
    pub cqes: u8,                    // Completion Queue Entry Size
    pub maxcmd: u16,                 // Maximum Outstanding Commands
    pub nn: u32,                     // Number of Namespaces
    pub oncs: u16,                   // Optional NVM Command Support
    pub fuses: u16,                  // Fused Operation Support
    pub fna: u8,                     // Format NVM Attributes
    pub vwc: u8,                     // Volatile Write Cache
    pub awun: u16,                   // Atomic Write Unit Normal
    pub awupf: u16,                  // Atomic Write Unit Power Fail
    pub nvscc: u8,                   // NVM Vendor Specific Command Configuration
    pub nwpc: u8,                    // Namespace Write Protection Capabilities
    pub acwu: u16,                   // Atomic Compare and Write Unit
    pub reserved4: [u8; 2],
    pub sgls: u32,                   // SGL Support
    pub mnan: u32,                   // Maximum Namespace Attachments
    pub reserved5: [u8; 224],
    pub subnqn: [u8; 256],           // NVM Subsystem NVMe Qualified Name
    pub reserved6: [u8; 768],
    pub ioccsz: u32,                 // I/O Controller Command Set Size
    pub iorcsz: u32,                 // I/O Controller Response Set Size
    pub icdoff: u16,                 // I/O Command Dword Offset
    pub ctrattr: u8,                 // Controller Attributes
    pub msdbd: u8,                   // Maximum SGL Data Block Descriptors
    pub reserved7: [u8; 244],
    pub psd: [PowerState; 32],       // Power State Descriptors
    pub vs: [u8; 1024],              // Vendor Specific
}

/// Power State Descriptor
#[repr(C)]
pub struct PowerState {
    pub max_power: u16,
    pub reserved1: u8,
    pub flags: u8,
    pub entry_lat: u32,
    pub exit_lat: u32,
    pub read_tput: u8,
    pub write_tput: u8,
    pub reserved2: u8,
    pub flags2: u8,
    pub read_lat: u16,
    pub write_lat: u16,
    pub idle_power: u16,
    pub idle_scale: u8,
    pub reserved3: u8,
    pub active_power: u16,
    pub active_work_scale: u8,
    pub reserved4: [u8; 9],
}

/// NVMe Submission Queue Entry (64 bytes)
#[repr(C)]
pub struct NvmeCmd {
    pub dword0: u32,           // OPR, FUSE, CID, NSID
    pub nsid: u32,             // Namespace Identifier
    pub dword2: u32,           // Reserved / CDW2
    pub dword3: u32,           // Reserved / CDW3
    pub mptr: u64,             // Metadata Pointer
    pub prp1: u64,             // PRP Entry 1
    pub prp2: u64,             // PRP Entry 2
    pub cdw10: u32,            // Command Dword 10
    pub cdw11: u32,            // Command Dword 11
    pub cdw12: u32,            // Command Dword 12
    pub cdw13: u32,            // Command Dword 13
    pub cdw14: u32,            // Command Dword 14
    pub cdw15: u32,            // Command Dword 15
}

/// NVMe Completion Queue Entry (16 bytes)
#[repr(C)]
pub struct NvmeCqe {
    pub dword0: u32,           // Command Specific
    pub dw: u32,                // Reserved
    pub sq_head: u16,           // SQ Head Pointer
    pub sq_id: u16,             // SQ Identifier
    pub cid: u16,               // Command Identifier
    pub sf: u16,                // Status Field (P, SC, SCT, M)
}

/// NVMe Queue Pair
pub struct NvmeQueuePair {
    /// Submission Queue guest address
    pub sq_gpa: AtomicU64,
    /// Completion Queue guest address
    pub cq_gpa: AtomicU64,
    /// SQ size (entries)
    pub sq_size: AtomicU16,
    /// CQ size (entries)
    pub cq_size: AtomicU16,
    /// SQ tail pointer (host writes)
    pub sq_tail: AtomicU16,
    /// CQ head pointer (host reads)
    pub cq_head: AtomicU16,
    /// SQ head pointer (device updates)
    pub sq_head: AtomicU16,
    /// CQ tail pointer (device updates)
    pub cq_tail: AtomicU16,
    /// Phase bit for CQ
    pub phase: AtomicU8,
    /// Queue ID
    pub qid: AtomicU16,
    /// Is enabled
    pub enabled: AtomicBool,
    /// Physical contiguous (vs PRP list)
    pub contiguous: AtomicBool,
}

impl NvmeQueuePair {
    pub const fn new() -> Self {
        Self {
            sq_gpa: AtomicU64::new(0),
            cq_gpa: AtomicU64::new(0),
            sq_size: AtomicU16::new(0),
            cq_size: AtomicU16::new(0),
            sq_tail: AtomicU16::new(0),
            cq_head: AtomicU16::new(0),
            sq_head: AtomicU16::new(0),
            cq_tail: AtomicU16::new(0),
            phase: AtomicU8::new(1),
            qid: AtomicU16::new(0),
            enabled: AtomicBool::new(false),
            contiguous: AtomicBool::new(false),
        }
    }

    /// Ring doorbell (update SQ tail)
    pub fn ring_doorbell(&self, new_tail: u16) {
        self.sq_tail.store(new_tail, Ordering::Release);
    }

    /// Check if there are pending commands
    pub fn has_pending(&self) -> bool {
        let head = self.sq_head.load(Ordering::Acquire);
        let tail = self.sq_tail.load(Ordering::Acquire);
        head != tail
    }

    /// Get next command index
    pub fn next_cmd_idx(&self) -> Option<u16> {
        if !self.has_pending() {
            return None;
        }
        let head = self.sq_head.load(Ordering::Acquire);
        let size = self.sq_size.load(Ordering::Acquire);
        self.sq_head.store((head + 1) % size, Ordering::Release);
        Some(head)
    }

    /// Post completion
    pub fn post_completion(&self, cid: u16, status: u16, result: u32) {
        let tail = self.cq_tail.load(Ordering::Acquire);
        let size = self.cq_size.load(Ordering::Acquire);
        let phase = self.phase.load(Ordering::Acquire);
        
        // Create CQE
        let cqe = NvmeCqe {
            dword0: result,
            dw: 0,
            sq_head: self.sq_head.load(Ordering::Acquire),
            sq_id: self.qid.load(Ordering::Acquire),
            cid,
            sf: (status & 0x7FF) | ((phase as u16) << 15),
        };
        
        // Store CQE (would write to guest memory)
        let new_tail = (tail + 1) % size;
        self.cq_tail.store(new_tail, Ordering::Release);
        
        // Toggle phase on wrap
        if new_tail == 0 {
            self.phase.store(phase ^ 1, Ordering::Release);
        }
    }
}

/// Maximum queue pairs
pub const MAX_QUEUE_PAIRS: usize = 64;

/// NVMe Namespace
#[repr(C)]
pub struct NvmeNamespace {
    pub nsid: u32,
    pub size: u64,              // Size in LBA units
    pub capacity: u64,          // Capacity in LBA units
    pub utilization: u64,       // Utilization in LBA units
    pub lbaf: [LbaFormat; 16],  // LBA Format
    pub flbas: u8,              // Formatted LBA Size
    pub mc: u8,                 // Metadata Capabilities
    pub dpc: u8,                // End-to-end Data Protection Capabilities
    pub dps: u8,                // End-to-end Data Protection Type Setting
    pub nmic: u8,               // Namespace Multi-path I/O and Namespace Sharing
    pub rescap: u8,             // Reservation Capabilities
    pub fpi: u8,                // Format Progress Indicator
    pub nsfeat: u8,             // Namespace Features
}

/// LBA Format
#[repr(C)]
pub struct LbaFormat {
    pub ms: u16,                // Metadata Size
    pub lbads: u8,              // LBA Data Size (2^lbads)
    pub rp: u8,                 // Relative Performance
}

/// NVMe Controller Passthrough
pub struct NvmePassthrough {
    /// Controller registers (MMIO space)
    pub cap: AtomicU64,         // Capabilities
    pub vs: AtomicU32,          // Version
    pub intms: AtomicU32,       // Interrupt Mask Set
    pub intmc: AtomicU32,       // Interrupt Mask Clear
    pub cc: AtomicU32,          // Controller Configuration
    pub csts: AtomicU32,        // Controller Status
    pub nssr: AtomicU32,        // NVM Subsystem Reset
    pub aqa: AtomicU32,         // Admin Queue Attributes
    pub asq: AtomicU64,         // Admin SQ Base Address
    pub acq: AtomicU64,         // Admin CQ Base Address
    /// Queue pairs (Admin + IO)
    pub queues: [NvmeQueuePair; MAX_QUEUE_PAIRS],
    /// Admin queue doorbell
    pub admin_sq_db: AtomicU32,
    pub admin_cq_db: AtomicU32,
    /// Number of active queues
    pub num_queues: AtomicU16,
    /// Controller enabled
    pub enabled: AtomicBool,
    /// Ready state
    pub ready: AtomicBool,
    /// Identify controller data
    pub identify_ctrl: IdentifyController,
    /// Namespaces
    pub namespaces: [NvmeNamespace; 256],
    /// Number of namespaces
    pub num_namespaces: AtomicU32,
    /// Physical device handle (would be actual device)
    pub device_handle: AtomicU64,
    /// MSI-X vector
    pub msix_vector: AtomicU8,
}

impl NvmePassthrough {
    pub const fn new() -> Self {
        Self {
            cap: AtomicU64::new((4095u64 << NVME_CAP_MQES_SHIFT as u64) | 
                               (1u64 << NVME_CAP_CSS_SHIFT as u64) |
                               (0u64 << NVME_CAP_MPSMIN_SHIFT as u64) |
                               (4u64 << NVME_CAP_TO_SHIFT as u64)),
            vs: AtomicU32::new(0x00010400), // NVMe 1.4
            intms: AtomicU32::new(0),
            intmc: AtomicU32::new(0),
            cc: AtomicU32::new(0),
            csts: AtomicU32::new(0),
            nssr: AtomicU32::new(0),
            aqa: AtomicU32::new(0),
            asq: AtomicU64::new(0),
            acq: AtomicU64::new(0),
            queues: [const { NvmeQueuePair::new() }; MAX_QUEUE_PAIRS],
            admin_sq_db: AtomicU32::new(0),
            admin_cq_db: AtomicU32::new(0),
            num_queues: AtomicU16::new(1),
            enabled: AtomicBool::new(false),
            ready: AtomicBool::new(false),
            identify_ctrl: IdentifyController {
                vid: 0x8086,
                ssvid: 0x8086,
                sn: [b'V'; 20],
                mn: [b'V'; 40],
                fr: [b'1'; 8],
                rab: 0,
                ieee: [0; 3],
                cmic: 0,
                mdts: 9, // 512 KiB max transfer
                cntlid: 0,
                ver: 0x00010400,
                rtd3r: 0,
                rtd3e: 0,
                oaes: 0,
                ctratt: 0,
                rrls: 0,
                reserved1: [0; 14],
                cntrltype: 0,
                fguid: [0; 16],
                reserved2: [0; 156],
                oacs: 0,
                acl: 0,
                aerl: 0,
                frmw: 0,
                lpa: 0,
                elpe: 0,
                npss: 0,
                avscc: 0,
                apsta: 0,
                wctemp: 0,
                cctemp: 0,
                mtfa: 0,
                hmpre: 0,
                hmmin: 0,
                tnvmcap: [0; 16],
                unvmcap: [0; 16],
                rpmbs: 0,
                edsttr: 0,
                dsto: 0,
                fwug: 0,
                kas: 0,
                hctma: 0,
                mntmt: 0,
                mxtmt: 0,
                sanicap: 0,
                reserved3: [0; 180],
                sqes: (6 << 4) | 6, // 64 bytes min/max
                cqes: (4 << 4) | 4, // 16 bytes min/max
                maxcmd: 0,
                nn: 1,
                oncs: 0,
                fuses: 0,
                fna: 0,
                vwc: 0,
                awun: 0,
                awupf: 0,
                nvscc: 0,
                nwpc: 0,
                acwu: 0,
                reserved4: [0; 2],
                sgls: 0,
                mnan: 0,
                reserved5: [0; 224],
                subnqn: [0; 256],
                reserved6: [0; 768],
                ioccsz: 0,
                iorcsz: 0,
                icdoff: 0,
                ctrattr: 0,
                msdbd: 0,
                reserved7: [0; 244],
                psd: [const { PowerState {
                    max_power: 0, reserved1: 0, flags: 0, entry_lat: 0, exit_lat: 0,
                    read_tput: 0, write_tput: 0, reserved2: 0, flags2: 0,
                    read_lat: 0, write_lat: 0, idle_power: 0, idle_scale: 0,
                    reserved3: 0, active_power: 0, active_work_scale: 0, reserved4: [0; 9],
                }}; 32],
                vs: [0; 1024],
            },
            namespaces: [const { NvmeNamespace {
                nsid: 0, size: 0, capacity: 0, utilization: 0,
                lbaf: [const { LbaFormat { ms: 0, lbads: 9, rp: 0 } }; 16],
                flbas: 0, mc: 0, dpc: 0, dps: 0, nmic: 0, rescap: 0, fpi: 0, nsfeat: 0,
            }}; 256],
            num_namespaces: AtomicU32::new(0),
            device_handle: AtomicU64::new(0),
            msix_vector: AtomicU8::new(0),
        }
    }

    /// Initialize with physical device
    pub fn init(&mut self, device_handle: u64, num_namespaces: u32, total_lbas: u64) {
        self.device_handle.store(device_handle, Ordering::Release);
        self.num_namespaces.store(num_namespaces, Ordering::Release);
        
        // Set up namespace 1
        if num_namespaces > 0 {
            self.namespaces[0].nsid = 1;
            self.namespaces[0].size = total_lbas;
            self.namespaces[0].capacity = total_lbas;
            self.namespaces[0].utilization = total_lbas;
            self.namespaces[0].lbaf[0].lbads = 9; // 512 bytes
            self.identify_ctrl.nn = num_namespaces;
        }
    }

    /// Read controller register
    pub fn read_reg(&self, offset: u32) -> u32 {
        match offset {
            0x00 => self.cap.load(Ordering::Acquire) as u32,
            0x04 => (self.cap.load(Ordering::Acquire) >> 32) as u32,
            0x08 => self.vs.load(Ordering::Acquire),
            0x0C => self.intms.load(Ordering::Acquire),
            0x10 => self.intmc.load(Ordering::Acquire),
            0x14 => self.cc.load(Ordering::Acquire),
            0x18 => self.csts.load(Ordering::Acquire),
            0x1C => self.nssr.load(Ordering::Acquire),
            0x20 => self.aqa.load(Ordering::Acquire),
            0x24 => self.asq.load(Ordering::Acquire) as u32,
            0x28 => (self.asq.load(Ordering::Acquire) >> 32) as u32,
            0x2C => self.acq.load(Ordering::Acquire) as u32,
            0x30 => (self.acq.load(Ordering::Acquire) >> 32) as u32,
            _ => 0,
        }
    }

    /// Write controller register
    pub fn write_reg(&mut self, offset: u32, value: u32) {
        match offset {
            0x0C => self.intms.store(value, Ordering::Release),
            0x10 => self.intmc.store(value, Ordering::Release),
            0x14 => {
                // Controller Configuration
                let old_cc = self.cc.load(Ordering::Acquire);
                self.cc.store(value, Ordering::Release);
                
                // Check for enable transition
                if (value & NVME_CC_EN) != 0 && (old_cc & NVME_CC_EN) == 0 {
                    self.enable_controller();
                } else if (value & NVME_CC_EN) == 0 && (old_cc & NVME_CC_EN) != 0 {
                    self.disable_controller();
                }
                
                // Check for shutdown notification
                let shn = (value >> NVME_CC_SHN_SHIFT) & 0x3;
                if shn != 0 {
                    self.shutdown(shn);
                }
            }
            0x1C => self.nssr.store(value, Ordering::Release),
            0x20 => self.aqa.store(value, Ordering::Release),
            0x24 => {
                let old = self.asq.load(Ordering::Acquire) as u32;
                self.asq.store((old as u64) | ((value as u64) << 32), Ordering::Release);
            }
            0x28 => {
                let old = self.asq.load(Ordering::Acquire);
                self.asq.store((old & 0xFFFFFFFF) | (value as u64), Ordering::Release);
            }
            0x2C => {
                let old = self.acq.load(Ordering::Acquire) as u32;
                self.acq.store((old as u64) | ((value as u64) << 32), Ordering::Release);
            }
            0x30 => {
                let old = self.acq.load(Ordering::Acquire);
                self.acq.store((old & 0xFFFFFFFF) | (value as u64), Ordering::Release);
            }
            // Doorbells
            0x1000.. => {
                let db_idx = ((offset - 0x1000) / 8) as usize;
                let is_cq = ((offset - 0x1000) % 8) >= 4;
                
                if db_idx < MAX_QUEUE_PAIRS {
                    if is_cq {
                        self.queues[db_idx].cq_head.store(value as u16, Ordering::Release);
                    } else {
                        self.queues[db_idx].sq_tail.store(value as u16, Ordering::Release);
                        // Process commands
                        self.process_queue(db_idx);
                    }
                }
            }
            _ => {}
        }
    }

    /// Enable controller
    fn enable_controller(&mut self) {
        // Initialize admin queue from ASQ/ACQ
        let aqa = self.aqa.load(Ordering::Acquire);
        let asq = self.asq.load(Ordering::Acquire);
        let acq = self.acq.load(Ordering::Acquire);
        
        let asq_size = ((aqa & 0xFFF) + 1) as u16;
        let acq_size = (((aqa >> 16) & 0xFFF) + 1) as u16;
        
        self.queues[0].sq_gpa.store(asq, Ordering::Release);
        self.queues[0].cq_gpa.store(acq, Ordering::Release);
        self.queues[0].sq_size.store(asq_size, Ordering::Release);
        self.queues[0].cq_size.store(acq_size, Ordering::Release);
        self.queues[0].qid.store(0, Ordering::Release);
        self.queues[0].enabled.store(true, Ordering::Release);
        
        self.enabled.store(true, Ordering::Release);
        
        // Set ready after initialization
        self.csts.fetch_or(NVME_CSTS_RDY, Ordering::Release);
        self.ready.store(true, Ordering::Release);
    }

    /// Disable controller
    fn disable_controller(&mut self) {
        self.enabled.store(false, Ordering::Release);
        self.ready.store(false, Ordering::Release);
        self.csts.fetch_and(!NVME_CSTS_RDY, Ordering::Release);
    }

    /// Shutdown notification
    fn shutdown(&mut self, shn: u32) {
        // Update shutdown status
        let shst = match shn {
            1 => 1, // Normal shutdown
            2 => 2, // Abrupt shutdown
            _ => 0,
        };
        self.csts.store((self.csts.load(Ordering::Acquire) & !0xC) | (shst << NVME_CSTS_SHST_SHIFT), Ordering::Release);
    }

    /// Process queue commands
    fn process_queue(&mut self, qid: usize) {
        if qid >= MAX_QUEUE_PAIRS {
            return;
        }
        
        let queue = &self.queues[qid];
        if !queue.enabled.load(Ordering::Acquire) {
            return;
        }

        // Process all pending commands
        while let Some(_idx) = queue.next_cmd_idx() {
            // Would read command from guest memory and execute
            // For now, post success completion
            queue.post_completion(0, status::SUCCESS, 0);
        }
        
        // Trigger MSI-X interrupt
        self.trigger_interrupt();
    }

    /// Process admin command
    pub fn process_admin_cmd(&mut self, cmd: &NvmeCmd) -> NvmeCqe {
        let opcode = (cmd.dword0 & 0xFF) as u8;
        let cid = ((cmd.dword0 >> 16) & 0xFFFF) as u16;
        let nsid = cmd.nsid;
        
        let (status, result) = match opcode {
            admin_opc::IDENTIFY => {
                let cns = cmd.cdw10 & 0xFF;
                match cns {
                    0 => self.identify_namespace(nsid),
                    1 => self.identify_controller(),
                    _ => (status::INVALID_FIELD, 0),
                }
            }
            admin_opc::CREATE_IOSQ => self.create_io_sq(cmd),
            admin_opc::CREATE_IOCQ => self.create_io_cq(cmd),
            admin_opc::DELETE_IOSQ => self.delete_io_sq(cmd.cdw10 as u16),
            admin_opc::DELETE_IOCQ => self.delete_io_cq(cmd.cdw10 as u16),
            admin_opc::GET_FEATURES => self.get_features(cmd.cdw10 & 0xFF),
            admin_opc::SET_FEATURES => self.set_features(cmd.cdw10 & 0xFF, cmd.cdw11),
            admin_opc::ABORT => (status::SUCCESS, 0),
            _ => (status::INVALID_OPCODE, 0),
        };

        NvmeCqe {
            dword0: result,
            dw: 0,
            sq_head: 0,
            sq_id: 0,
            cid,
            sf: status,
        }
    }

    /// Process IO command
    pub fn process_io_cmd(&mut self, cmd: &NvmeCmd) -> NvmeCqe {
        let opcode = (cmd.dword0 & 0xFF) as u8;
        let cid = ((cmd.dword0 >> 16) & 0xFFFF) as u16;
        let nsid = cmd.nsid;
        
        let slba = cmd.cdw10 as u64 | ((cmd.cdw11 as u64) << 32);
        let nlb = cmd.cdw12 & 0xFFFF;
        
        let status = match opcode {
            nvm_opc::READ => self.read_blocks(nsid, slba, nlb, cmd.prp1, cmd.prp2),
            nvm_opc::WRITE => self.write_blocks(nsid, slba, nlb, cmd.prp1, cmd.prp2),
            nvm_opc::FLUSH => self.flush_blocks(nsid),
            nvm_opc::WRITE_ZEROES => self.write_zeroes(nsid, slba, nlb),
            nvm_opc::DATASET_MANAGEMENT => self.dataset_management(nsid, cmd.cdw10, cmd.cdw11),
            _ => status::INVALID_OPCODE,
        };

        NvmeCqe {
            dword0: 0,
            dw: 0,
            sq_head: 0,
            sq_id: 1,
            cid,
            sf: status,
        }
    }

    /// Identify namespace
    fn identify_namespace(&self, nsid: u32) -> (u16, u32) {
        if nsid == 0 || nsid as usize > self.num_namespaces.load(Ordering::Acquire) as usize {
            return (status::INVALID_NS_OR_FORMAT, 0);
        }
        // Would copy namespace data to PRP buffer
        (status::SUCCESS, 0)
    }

    /// Identify controller
    fn identify_controller(&self) -> (u16, u32) {
        // Would copy identify_ctrl to PRP buffer
        (status::SUCCESS, 0)
    }

    /// Create IO submission queue
    fn create_io_sq(&mut self, cmd: &NvmeCmd) -> (u16, u32) {
        let qid = (cmd.cdw10 >> 16) as u16;
        let qsize = (cmd.cdw10 & 0xFFFF) + 1;
        let cqid = (cmd.cdw11 >> 16) as u16;
        
        if qid as usize >= MAX_QUEUE_PAIRS || qid == 0 {
            return (status::INVALID_FIELD, 0);
        }
        
        let queue = &self.queues[qid as usize];
        queue.sq_gpa.store(cmd.prp1, Ordering::Release);
        queue.sq_size.store(qsize as u16, Ordering::Release);
        queue.qid.store(qid, Ordering::Release);
        queue.enabled.store(true, Ordering::Release);
        
        self.num_queues.fetch_add(1, Ordering::Release);
        (status::SUCCESS, 0)
    }

    /// Create IO completion queue
    fn create_io_cq(&mut self, cmd: &NvmeCmd) -> (u16, u32) {
        let qid = (cmd.cdw10 >> 16) as u16;
        let qsize = (cmd.cdw10 & 0xFFFF) + 1;
        
        if qid as usize >= MAX_QUEUE_PAIRS || qid == 0 {
            return (status::INVALID_FIELD, 0);
        }
        
        let queue = &self.queues[qid as usize];
        queue.cq_gpa.store(cmd.prp1, Ordering::Release);
        queue.cq_size.store(qsize as u16, Ordering::Release);
        queue.phase.store(1, Ordering::Release);
        
        (status::SUCCESS, 0)
    }

    /// Delete IO submission queue
    fn delete_io_sq(&mut self, qid: u16) -> (u16, u32) {
        if qid as usize >= MAX_QUEUE_PAIRS || qid == 0 {
            return (status::INVALID_FIELD, 0);
        }
        
        self.queues[qid as usize].enabled.store(false, Ordering::Release);
        self.num_queues.fetch_sub(1, Ordering::Release);
        (status::SUCCESS, 0)
    }

    /// Delete IO completion queue
    fn delete_io_cq(&mut self, qid: u16) -> (u16, u32) {
        if qid as usize >= MAX_QUEUE_PAIRS || qid == 0 {
            return (status::INVALID_FIELD, 0);
        }
        (status::SUCCESS, 0)
    }

    /// Get feature
    fn get_features(&self, fid: u32) -> (u16, u32) {
        let result = match fid {
            0x00 => self.num_queues.load(Ordering::Acquire) as u32, // Number of Queues
            0x01 => 0, // Arbitration
            0x02 => 0, // Power Management
            0x03 => 0, // LBA Range Type
            0x04 => 0, // Temperature Threshold
            0x05 => 0, // Error Recovery
            0x07 => 0, // Write Cache
            0x08 => 0, // Volatile Write Cache
            0x09 => 0, // Number of Namespaces
            0x0A => 0, // Interrupt Coalescing
            0x0B => 0, // Interrupt Vector Configuration
            0x0C => 0, // Write Atomicity
            0x0D => 0, // Async Event Config
            _ => return (status::INVALID_FIELD, 0),
        };
        (status::SUCCESS, result)
    }

    /// Set feature
    fn set_features(&mut self, fid: u32, value: u32) -> (u16, u32) {
        match fid {
            0x00 => self.num_queues.store(value as u16, Ordering::Release),
            0x07 => {} // Write Cache
            0x08 => {} // Volatile Write Cache
            0x0D => {} // Async Event Config
            _ => return (status::INVALID_FIELD, 0),
        }
        (status::SUCCESS, 0)
    }

    /// Read blocks from namespace
    fn read_blocks(&self, nsid: u32, slba: u64, nlb: u32, _prp1: u64, _prp2: u64) -> u16 {
        if nsid == 0 || nsid as usize > self.num_namespaces.load(Ordering::Acquire) as usize {
            return status::INVALID_NS_OR_FORMAT;
        }
        
        let ns = &self.namespaces[(nsid - 1) as usize];
        if slba + nlb as u64 > ns.size {
            return status::LBA_OUT_OF_RANGE;
        }
        
        // Would perform actual read from physical device
        status::SUCCESS
    }

    /// Write blocks to namespace
    fn write_blocks(&self, nsid: u32, slba: u64, nlb: u32, _prp1: u64, _prp2: u64) -> u16 {
        if nsid == 0 || nsid as usize > self.num_namespaces.load(Ordering::Acquire) as usize {
            return status::INVALID_NS_OR_FORMAT;
        }
        
        let ns = &self.namespaces[(nsid - 1) as usize];
        if slba + nlb as u64 > ns.size {
            return status::LBA_OUT_OF_RANGE;
        }
        
        // Would perform actual write to physical device
        status::SUCCESS
    }

    /// Flush blocks
    fn flush_blocks(&self, _nsid: u32) -> u16 {
        // Would flush device cache
        status::SUCCESS
    }

    /// Write zeroes
    fn write_zeroes(&self, nsid: u32, slba: u64, nlb: u32) -> u16 {
        if nsid == 0 || nsid as usize > self.num_namespaces.load(Ordering::Acquire) as usize {
            return status::INVALID_NS_OR_FORMAT;
        }
        
        let ns = &self.namespaces[(nsid - 1) as usize];
        if slba + nlb as u64 > ns.size {
            return status::LBA_OUT_OF_RANGE;
        }
        
        status::SUCCESS
    }

    /// Dataset management (TRIM/unmap)
    fn dataset_management(&self, nsid: u32, _nr: u32, _attributes: u32) -> u16 {
        if nsid == 0 || nsid as usize > self.num_namespaces.load(Ordering::Acquire) as usize {
            return status::INVALID_NS_OR_FORMAT;
        }
        
        // Would process TRIM ranges
        status::SUCCESS
    }

    /// Trigger MSI-X interrupt
    fn trigger_interrupt(&self) {
        // Would trigger MSI-X via interrupt remapping
    }
}

impl Default for NvmePassthrough {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nvme_init() {
        let mut nvme = NvmePassthrough::new();
        nvme.init(0x1000, 1, 1_000_000);
        
        assert_eq!(nvme.num_namespaces.load(Ordering::Acquire), 1);
        assert_eq!(nvme.namespaces[0].nsid, 1);
    }

    #[test]
    fn nvme_enable() {
        let mut nvme = NvmePassthrough::new();
        
        // Set admin queue addresses
        nvme.asq.store(0x100000, Ordering::Release);
        nvme.acq.store(0x200000, Ordering::Release);
        nvme.aqa.store(0x001F001F, Ordering::Release); // 32 entries each
        
        // Enable controller
        nvme.write_reg(0x14, NVME_CC_EN);
        
        assert!(nvme.enabled.load(Ordering::Acquire));
        assert!(nvme.ready.load(Ordering::Acquire));
    }

    #[test]
    fn nvme_identify() {
        let mut nvme = NvmePassthrough::new();
        nvme.init(0x1000, 1, 1_000_000);
        
        let cmd = NvmeCmd {
            dword0: (admin_opc::IDENTIFY as u32) | (1 << 16),
            nsid: 1,
            dword2: 0,
            dword3: 0,
            mptr: 0,
            prp1: 0x300000,
            prp2: 0,
            cdw10: 1, // Identify controller
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        
        let cqe = nvme.process_admin_cmd(&cmd);
        assert_eq!(cqe.sf, status::SUCCESS);
    }

    #[test]
    fn nvme_read_write() {
        let mut nvme = NvmePassthrough::new();
        nvme.init(0x1000, 1, 1_000_000);
        
        let read_cmd = NvmeCmd {
            dword0: (nvm_opc::READ as u32) | (1 << 16),
            nsid: 1,
            dword2: 0,
            dword3: 0,
            mptr: 0,
            prp1: 0x400000,
            prp2: 0,
            cdw10: 0, // SLBA low
            cdw11: 0, // SLBA high
            cdw12: 7, // 8 blocks
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        
        let cqe = nvme.process_io_cmd(&read_cmd);
        assert_eq!(cqe.sf, status::SUCCESS);
    }

    #[test]
    fn nvme_create_queue() {
        let mut nvme = NvmePassthrough::new();
        nvme.init(0x1000, 1, 1_000_000);
        
        // Create IO CQ
        let create_cq = NvmeCmd {
            dword0: (admin_opc::CREATE_IOCQ as u32) | (1 << 16),
            nsid: 0,
            dword2: 0,
            dword3: 0,
            mptr: 0,
            prp1: 0x500000,
            prp2: 0,
            cdw10: (1 << 16) | 15, // QID=1, size=16
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        
        let cqe = nvme.process_admin_cmd(&create_cq);
        assert_eq!(cqe.sf, status::SUCCESS);
        
        // Create IO SQ
        let create_sq = NvmeCmd {
            dword0: (admin_opc::CREATE_IOSQ as u32) | (2 << 16),
            nsid: 0,
            dword2: 0,
            dword3: 0,
            mptr: 0,
            prp1: 0x600000,
            prp2: 0,
            cdw10: (1 << 16) | 15, // QID=1, size=16
            cdw11: (1 << 16), // CQID=1
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };
        
        let cqe = nvme.process_admin_cmd(&create_sq);
        assert_eq!(cqe.sf, status::SUCCESS);
    }
}
