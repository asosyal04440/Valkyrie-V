use crate::vmm::guest_memory::{BootParams, GuestMemory, MemoryType, KERNEL_MAX_SIZE, PAGE_SIZE};
use crate::vmm::{HvError, HvResult};

pub const KERNEL_VERSION_2_6: u8 = 0x20;
pub const KERNEL_VERSION_3: u8 = 0x30;
pub const KERNEL_VERSION_4: u8 = 0x40;
pub const KERNEL_VERSION_5: u8 = 0x50;
pub const KERNEL_VERSION_6: u8 = 0x60;

pub const KERNEL_BOOT_FLAG_RAW: u16 = 0x01;
pub const KERNEL_BOOT_FLAG_EFI32: u16 = 0x02;
pub const KERNEL_BOOT_FLAG_EFI64: u16 = 0x04;
pub const KERNEL_BOOT_FLAG_PRELOAD: u16 = 0x08;
pub const KERNEL_BOOT_FLAG_MULTIBOOT: u16 = 0x10;

pub const BOOT_PROTOCOL_V2_10: u16 = 0x020A;
pub const BOOT_PROTOCOL_V2_11: u16 = 0x020B;
pub const BOOT_PROTOCOL_V2_12: u16 = 0x020C;
pub const BOOT_PROTOCOL_V2_13: u16 = 0x020D;
pub const BOOT_PROTOCOL_V2_14: u16 = 0x020E;
pub const BOOT_PROTOCOL_V2_15: u16 = 0x020F;
pub const BOOT_PROTOCOL_V2_16: u16 = 0x0210;
pub const BOOT_PROTOCOL_V2_17: u16 = 0x0211;

#[derive(Debug, Clone, Copy)]
pub struct KernelHeader {
    pub setup_secs: u8,
    pub root_flags: u16,
    pub boot_flag: u16,
    pub header: u32,
    pub version: u16,
    pub kernel_alignment: u32,
    pub relocatable: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub initrd_addr_max: u32,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub loader_type: u8,
}

impl KernelHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 0x206 {
            return None;
        }

        // Linux x86 boot protocol: "HdrS" magic is at offset 0x202 (not 0x201)
        let header_magic = u32::from_le_bytes([data[0x202], data[0x203], data[0x204], data[0x205]]);
        if header_magic != u32::from_le_bytes([b'H', b'd', b'r', b'S']) {
            return None;
        }

        Some(Self {
            setup_secs: data[0x1f1],
            root_flags: u16::from_le_bytes([data[0x1f2], data[0x1f3]]),
            boot_flag: u16::from_le_bytes([data[0x1fe], data[0x1ff]]),
            header: header_magic,
            version: u16::from_le_bytes([data[0x206], data[0x207]]),
            kernel_alignment: u32::from_le_bytes([
                data[0x230],
                data[0x231],
                data[0x232],
                data[0x233],
            ]),
            relocatable: data[0x234],
            xloadflags: u16::from_le_bytes([data[0x236], data[0x237]]),
            cmdline_size: u32::from_le_bytes([data[0x218], data[0x219], data[0x21a], data[0x21b]]),
            initrd_addr_max: u32::from_le_bytes([
                data[0x21c],
                data[0x21d],
                data[0x21e],
                data[0x21f],
            ]),
            pref_address: u64::from_le_bytes([
                data[0x258],
                data[0x259],
                data[0x25a],
                data[0x25b],
                data[0x25c],
                data[0x25d],
                data[0x25e],
                data[0x25f],
            ]),
            init_size: u32::from_le_bytes([data[0x260], data[0x261], data[0x262], data[0x263]]),
            handover_offset: u32::from_le_bytes([
                data[0x264],
                data[0x265],
                data[0x266],
                data[0x267],
            ]),
            loader_type: data[0x210],
        })
    }

    pub fn protocol_version(&self) -> u16 {
        if self.header == u32::from_le_bytes([b'H', b'd', b'r', b'S']) {
            let ver = (self.version >> 8) as u8;
            let rev = self.version as u8;
            if ver >= KERNEL_VERSION_6 {
                return BOOT_PROTOCOL_V2_17;
            } else if ver >= KERNEL_VERSION_5 {
                if rev >= 0x14 {
                    return BOOT_PROTOCOL_V2_16;
                } else if rev >= 0x12 {
                    return BOOT_PROTOCOL_V2_15;
                } else if rev >= 0x10 {
                    return BOOT_PROTOCOL_V2_14;
                } else if rev >= 8 {
                    return BOOT_PROTOCOL_V2_13;
                } else if rev >= 5 {
                    return BOOT_PROTOCOL_V2_12;
                } else if rev >= 2 {
                    return BOOT_PROTOCOL_V2_11;
                }
            }
            return BOOT_PROTOCOL_V2_10;
        }
        0
    }

    pub fn supports_64bit(&self) -> bool {
        (self.xloadflags & 0x01) != 0
    }

    pub fn supports_relocatable(&self) -> bool {
        self.relocatable != 0
    }
}

pub struct KernelLoader {
    header: Option<KernelHeader>,
    loaded_address: u64,
    entry_point: u64,
    setup_size: u64,
    kernel_size: u64,
}

impl KernelLoader {
    pub const fn new() -> Self {
        Self {
            header: None,
            loaded_address: 0,
            entry_point: 0,
            setup_size: 0,
            kernel_size: 0,
        }
    }

    pub fn load(&mut self, data: &[u8], guest_mem: &mut GuestMemory) -> HvResult<(u64, u64)> {
        let header = KernelHeader::parse(data).ok_or(HvError::LogicalFault)?;

        let protocol = header.protocol_version();
        if protocol < BOOT_PROTOCOL_V2_10 {
            return Err(HvError::LogicalFault);
        }

        self.header = Some(header);
        let hdr = self.header.as_ref().unwrap();

        self.setup_size = (hdr.setup_secs as u64 + 1) * 512;
        if self.setup_size > data.len() as u64 {
            return Err(HvError::LogicalFault);
        }

        let kernel_load_addr = if hdr.supports_64bit() {
            0x100000
        } else {
            0x10000
        };

        let alignment = if hdr.supports_relocatable() {
            hdr.kernel_alignment as u64
        } else {
            PAGE_SIZE
        };

        self.loaded_address = guest_mem.allocate(KERNEL_MAX_SIZE, alignment)?;

        let kernel_offset = kernel_load_addr;
        let kernel_src = &data[self.setup_size as usize..];
        let actual_kernel_size = kernel_src.len() as u64;
        self.kernel_size = actual_kernel_size;

        guest_mem.add_region(
            self.loaded_address + kernel_offset,
            actual_kernel_size,
            MemoryType::Kernel,
        )?;

        // Copy kernel bytes into guest RAM.
        guest_mem.write_bytes(self.loaded_address + kernel_offset, kernel_src)?;

        self.entry_point = if hdr.supports_64bit() {
            self.loaded_address + 0x200
        } else {
            self.loaded_address + kernel_offset
        };

        Ok((self.entry_point, self.loaded_address))
    }

    pub fn get_boot_params(&self, guest_mem: &GuestMemory) -> HvResult<BootParams> {
        let mut params = BootParams::new();

        if let Some(hdr) = &self.header {
            params.setup_secs = hdr.setup_secs;
            params.loader_type = hdr.loader_type;
            params.kernel_alignment = hdr.kernel_alignment;
            params.init_size = hdr.init_size;
            params.pref_address = hdr.pref_address;

            if hdr.handover_offset != 0 {
                params.handover_offset = hdr.handover_offset;
            }
        }

        params.mem_magic = 0x5372;
        params.kernel_alignment = 0x1000000;

        params.finalize(guest_mem);

        Ok(params)
    }

    pub fn get_setup_size(&self) -> u64 {
        self.setup_size
    }

    pub fn get_kernel_size(&self) -> u64 {
        self.kernel_size
    }

    pub fn get_entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn get_loaded_address(&self) -> u64 {
        self.loaded_address
    }
}

impl Default for KernelLoader {
    fn default() -> Self {
        Self::new()
    }
}
