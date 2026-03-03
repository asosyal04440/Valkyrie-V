//! Multiboot2 protocol support for loading kernels like echOS.
//!
//! Multiboot2 is a boot protocol that provides a standardized way to pass
//! boot information to the kernel. echOS supports this protocol.

use crate::vmm::guest_memory::{BootParams, GuestMemory, MemoryType};
use crate::vmm::{HvError, HvResult};

/// Multiboot2 magic number in the kernel header
pub const MULTIBOOT2_MAGIC: u32 = 0xE85250D6;

/// Multiboot2 boot information magic (passed to kernel in EAX)
pub const MULTIBOOT2_BOOT_MAGIC: u32 = 0x36D76289;

/// Multiboot2 header alignment
pub const MULTIBOOT2_HEADER_ALIGN: u64 = 8;

/// Multiboot2 header tags
pub mod tags {
    pub const END: u16 = 0;
    pub const ADDRESS: u16 = 1;
    pub const ENTRY_ADDRESS: u16 = 3;
    pub const FLAGS: u16 = 4;
    pub const FRAMEBUFFER: u16 = 5;
    pub const MODULES_ALIGN: u16 = 6;
    pub const EFI_BOOT_SERVICES: u16 = 7;
    pub const EFI_I386_ENTRY_ADDR: u16 = 8;
    pub const EFI_AMD64_ENTRY_ADDR: u16 = 9;
    pub const EFI_BOOT_SERVICES_X86_64: u16 = 10;
    pub const EFI_BOOT_SERVICES_IA32: u16 = 11;
    pub const ENTRY_ADDRESS_ALT: u16 = 12;
}

/// Multiboot2 header (variable length, minimum 16 bytes)
#[derive(Debug, Clone, Copy)]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
    pub entry_addr: Option<u64>,
    pub load_addr: Option<u64>,
    pub load_end_addr: Option<u64>,
    pub bss_end_addr: Option<u64>,
}

impl Multiboot2Header {
    /// Parse a Multiboot2 header from raw bytes.
    /// The header must be 8-byte aligned within the first 32KB of the kernel.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        // Search for the magic number (must be 8-byte aligned)
        for offset in (0..data.len().min(32768)).step_by(8) {
            if offset + 16 > data.len() {
                break;
            }

            let magic = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);

            if magic != MULTIBOOT2_MAGIC {
                continue;
            }

            let arch = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let header_length = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            let checksum = u32::from_le_bytes([
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);

            // Verify checksum: magic + arch + header_length + checksum = 0
            if magic.wrapping_add(arch).wrapping_add(header_length).wrapping_add(checksum) != 0 {
                continue;
            }

            let mut header = Self {
                magic,
                architecture: arch,
                header_length,
                checksum,
                entry_addr: None,
                load_addr: None,
                load_end_addr: None,
                bss_end_addr: None,
            };

            // Parse optional tags
            let mut tag_offset = offset + 16;
            let header_end = offset + header_length as usize;

            while tag_offset + 8 <= header_end && tag_offset + 8 <= data.len() {
                let tag_type = u16::from_le_bytes([data[tag_offset], data[tag_offset + 1]]);
                let tag_size = u16::from_le_bytes([data[tag_offset + 2], data[tag_offset + 3]]);

                match tag_type {
                    tags::ENTRY_ADDRESS => {
                        if tag_offset + 16 <= data.len() {
                            header.entry_addr = Some(u64::from_le_bytes([
                                data[tag_offset + 8],
                                data[tag_offset + 9],
                                data[tag_offset + 10],
                                data[tag_offset + 11],
                                data[tag_offset + 12],
                                data[tag_offset + 13],
                                data[tag_offset + 14],
                                data[tag_offset + 15],
                            ]));
                        }
                    }
                    tags::ADDRESS => {
                        if tag_offset + 28 <= data.len() {
                            header.load_addr = Some(u64::from_le_bytes([
                                data[tag_offset + 8],
                                data[tag_offset + 9],
                                data[tag_offset + 10],
                                data[tag_offset + 11],
                                data[tag_offset + 12],
                                data[tag_offset + 13],
                                data[tag_offset + 14],
                                data[tag_offset + 15],
                            ]));
                            header.load_end_addr = Some(u64::from_le_bytes([
                                data[tag_offset + 16],
                                data[tag_offset + 17],
                                data[tag_offset + 18],
                                data[tag_offset + 19],
                                data[tag_offset + 20],
                                data[tag_offset + 21],
                                data[tag_offset + 22],
                                data[tag_offset + 23],
                            ]));
                            header.bss_end_addr = Some(u64::from_le_bytes([
                                data[tag_offset + 24],
                                data[tag_offset + 25],
                                data[tag_offset + 26],
                                data[tag_offset + 27],
                                data[tag_offset + 28],
                                data[tag_offset + 29],
                                data[tag_offset + 30],
                                data[tag_offset + 31],
                            ]));
                        }
                    }
                    tags::END => break,
                    _ => {}
                }

                // Move to next tag (aligned to 8 bytes)
                let next_offset = tag_offset + ((tag_size as usize + 7) & !7);
                if next_offset <= tag_offset {
                    break;
                }
                tag_offset = next_offset;
            }

            return Some(header);
        }

        None
    }

    /// Check if this is a 64-bit kernel (architecture 0x02 = x86-64)
    pub fn is_64bit(&self) -> bool {
        self.architecture == 0x02
    }
}

/// Memory map entry types (Multiboot2)
pub mod mmap_type {
    pub const AVAILABLE: u32 = 1;      // Available RAM
    pub const RESERVED: u32 = 2;       // Reserved (not usable)
    pub const ACPI_RECLAIM: u32 = 3;   // ACPI Reclaimable
    pub const ACPI_NVS: u32 = 4;       // ACPI NVS (non-volatile)
    pub const BAD_MEMORY: u32 = 5;     // Bad memory
    pub const BOOTLOADER: u32 = 6;     // Bootloader reclaimable
    pub const KERNEL: u32 = 7;         // Kernel and modules
    pub const FRAMEBUFFER: u32 = 8;    // Framebuffer
}

/// 32-bit kernel boot parameters
#[derive(Debug, Clone, Copy)]
pub struct BootParams32 {
    pub entry: u32,
    pub boot_info_addr: u32,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
}

/// Memory map entry for Multiboot2
#[derive(Debug, Clone, Copy)]
pub struct MmapEntry {
    pub base: u64,
    pub length: u64,
    pub entry_type: u32,
    pub attributes: u32,
}

impl MmapEntry {
    pub const fn new(base: u64, length: u64, entry_type: u32) -> Self {
        Self {
            base,
            length,
            entry_type,
            attributes: 1, // Present
        }
    }
}

/// Maximum number of memory map entries
pub const MAX_MMAP_ENTRIES: usize = 16;

/// Multiboot2 boot information passed to the kernel
#[derive(Debug, Clone, Copy)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
    pub cmdline: Option<u64>,
    pub memory_lower: u32,
    pub memory_upper: u32,
    pub mmap_addr: u64,
    pub mmap_length: u32,
    pub mmap_entries: [MmapEntry; MAX_MMAP_ENTRIES],
    pub mmap_count: u8,
}

impl Multiboot2Info {
    pub const fn new() -> Self {
        Self {
            total_size: 0,
            reserved: 0,
            cmdline: None,
            memory_lower: 0,
            memory_upper: 0,
            mmap_addr: 0,
            mmap_length: 0,
            mmap_entries: [MmapEntry::new(0, 0, 0); MAX_MMAP_ENTRIES],
            mmap_count: 0,
        }
    }

    /// Add a memory map entry
    pub fn add_mmap_entry(&mut self, base: u64, length: u64, entry_type: u32) -> bool {
        if self.mmap_count as usize >= MAX_MMAP_ENTRIES {
            return false;
        }
        self.mmap_entries[self.mmap_count as usize] = MmapEntry::new(base, length, entry_type);
        self.mmap_count += 1;
        true
    }

    /// Build standard memory map entries for a VM
    pub fn build_standard_mmap(&mut self, total_mem: u64, framebuffer_addr: u64, framebuffer_size: u64) {
        self.mmap_count = 0;
        
        // Entry 0: Low memory (0x0 - 0x7FFFF, 512KB)
        self.add_mmap_entry(0x0, 0x80000, mmap_type::AVAILABLE);
        
        // Entry 1: EBDA and reserved (0x80000 - 0xFFFFF, 512KB)
        self.add_mmap_entry(0x80000, 0x80000, mmap_type::RESERVED);
        
        // Entry 2: Extended memory (1MB - total_mem)
        let extended_start = 0x10_0000u64;
        if total_mem > extended_start {
            self.add_mmap_entry(extended_start, total_mem - extended_start, mmap_type::AVAILABLE);
        }
        
        // Entry 3: Framebuffer (if present)
        if framebuffer_size > 0 {
            self.add_mmap_entry(framebuffer_addr, framebuffer_size, mmap_type::FRAMEBUFFER);
        }
        
        // Entry 4: ACPI Reclaimable region (typical location: 0x7FFD0000 - 0x7FFE0000)
        self.add_mmap_entry(0x7FFD_0000, 0x1_0000, mmap_type::ACPI_RECLAIM);
        
        // Entry 5: ACPI NVS region (typical location: 0x7FFE0000 - 0x7FFF0000)
        self.add_mmap_entry(0x7FFE_0000, 0x1_0000, mmap_type::ACPI_NVS);
    }

    /// Build the boot information structure in guest memory.
    /// Returns the physical address where it was placed.
    pub fn build(&self, guest_mem: &mut GuestMemory, base_addr: u64) -> HvResult<u64> {
        // Calculate total size needed
        // Basic header: 8 bytes
        // Memory map tag: 16 + (entry_count * 24)
        // Command line tag: 8 + cmdline_len + padding
        // End tag: 8 bytes

        let entry_count = self.mmap_count as u32;
        let mmap_tag_size = 16 + (entry_count * 24);
        
        let mut info_size = 8u32; // header
        info_size += 8; // end tag
        info_size += mmap_tag_size;

        // Align to 8 bytes
        info_size = (info_size + 7) & !7;

        let mut buf = [0u8; 1024]; // Larger buffer for multiple entries
        let mut offset = 0usize;

        // Total size (will be updated)
        buf[offset..offset + 4].copy_from_slice(&info_size.to_le_bytes());
        offset += 8; // + reserved

        // Memory map tag (type = 21, size = 16 + entries * 24)
        buf[offset] = 21; // tag type: MMAP
        buf[offset + 1] = 0;
        buf[offset + 2..offset + 4].copy_from_slice(&(mmap_tag_size as u16).to_le_bytes());
        offset += 4;

        // Entry size = 24, Entry version = 0
        buf[offset..offset + 4].copy_from_slice(&24u32.to_le_bytes());
        offset += 4;
        buf[offset..offset + 4].copy_from_slice(&0u32.to_le_bytes()); // version
        offset += 4;

        // Write all memory map entries
        for i in 0..entry_count as usize {
            let entry = &self.mmap_entries[i];
            buf[offset..offset + 8].copy_from_slice(&entry.base.to_le_bytes());
            offset += 8;
            buf[offset..offset + 8].copy_from_slice(&entry.length.to_le_bytes());
            offset += 8;
            buf[offset..offset + 4].copy_from_slice(&entry.entry_type.to_le_bytes());
            offset += 4;
            buf[offset..offset + 4].copy_from_slice(&entry.attributes.to_le_bytes());
            offset += 4;
        }

        // End tag
        buf[offset] = 0; // type = 0
        offset += 1;
        buf[offset] = 0;
        offset += 1;
        buf[offset + 2..offset + 4].copy_from_slice(&8u16.to_le_bytes()); // size = 8

        // Write to guest memory
        guest_mem.write_bytes(base_addr, &buf[..info_size as usize])?;

        Ok(base_addr)
    }
}

/// Multiboot2 kernel loader
pub struct Multiboot2Loader {
    header: Option<Multiboot2Header>,
    loaded_address: u64,
    entry_point: u64,
    kernel_size: u64,
    is_32bit: bool,
}

impl Multiboot2Loader {
    pub const fn new() -> Self {
        Self {
            header: None,
            loaded_address: 0,
            entry_point: 0,
            kernel_size: 0,
            is_32bit: false,
        }
    }

    /// Check if the loaded kernel is 32-bit
    pub fn is_32bit(&self) -> bool {
        self.is_32bit
    }

    /// Load a Multiboot2 kernel into guest memory.
    /// Returns (entry_point, boot_info_addr).
    pub fn load(&mut self, data: &[u8], guest_mem: &mut GuestMemory) -> HvResult<(u64, u64)> {
        let header = Multiboot2Header::parse(data).ok_or(HvError::LogicalFault)?;

        self.header = Some(header);
        self.is_32bit = !header.is_64bit();

        // Load address: default to 1MB if not specified
        let load_addr = header.load_addr.unwrap_or(0x100000);
        self.loaded_address = load_addr;

        // Load the entire kernel image
        guest_mem.add_region(load_addr, data.len() as u64, MemoryType::Kernel)?;
        guest_mem.write_bytes(load_addr, data)?;
        self.kernel_size = data.len() as u64;

        // Entry point: from header or default
        self.entry_point = header.entry_addr.unwrap_or(load_addr);

        // Build boot info at a fixed location (below 1MB)
        let boot_info_addr: u64 = 0x9000;
        let mut info = Multiboot2Info::new();
        info.memory_lower = 640; // conventional memory in KB
        info.memory_upper = (guest_mem.memory_limit() / 1024) as u32; // extended memory in KB
        info.build(guest_mem, boot_info_addr)?;

        Ok((self.entry_point, boot_info_addr))
    }

    /// Get boot parameters for 32-bit kernel
    /// Returns (eax, ebx) - eax = magic, ebx = boot info address
    pub fn get_32bit_boot_params(&self, boot_info_addr: u64) -> (u32, u32) {
        (MULTIBOOT2_BOOT_MAGIC, boot_info_addr as u32)
    }

    /// Setup 32-bit kernel state (for VMX/SVM)
    /// Sets up segment registers and initial state for 32-bit protected mode
    pub fn setup_32bit_state(&self) -> BootParams32 {
        BootParams32 {
            entry: self.entry_point as u32,
            boot_info_addr: 0x9000,
            // 32-bit protected mode segments
            cs: 0x08, // Kernel code segment
            ds: 0x10, // Kernel data segment
            es: 0x10,
            fs: 0x10,
            gs: 0x10,
            ss: 0x10,
        }
    }

    pub fn get_entry_point(&self) -> u64 {
        self.entry_point
    }

    pub fn get_loaded_address(&self) -> u64 {
        self.loaded_address
    }

    pub fn get_kernel_size(&self) -> u64 {
        self.kernel_size
    }
}

impl Default for Multiboot2Loader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_header() {
        let data = [0u8; 16];
        assert!(Multiboot2Header::parse(&data).is_none());
    }

    #[test]
    fn parse_valid_header() {
        // Minimal Multiboot2 header
        let mut data = [0u8; 32];
        // Magic
        data[0..4].copy_from_slice(&MULTIBOOT2_MAGIC.to_le_bytes());
        // Architecture (x86-64)
        data[4..8].copy_from_slice(&0x02u32.to_le_bytes());
        // Header length
        data[8..12].copy_from_slice(&24u32.to_le_bytes());
        // Checksum (magic + arch + length + checksum = 0)
        let checksum = !(MULTIBOOT2_MAGIC.wrapping_add(0x02).wrapping_add(24));
        data[12..16].copy_from_slice(&checksum.to_le_bytes());
        // End tag
        data[16..20].copy_from_slice(&0u32.to_le_bytes());
        data[20..24].copy_from_slice(&8u32.to_le_bytes());

        let header = Multiboot2Header::parse(&data);
        assert!(header.is_some());
        let h = header.unwrap();
        assert_eq!(h.magic, MULTIBOOT2_MAGIC);
        assert!(h.is_64bit());
    }
}
