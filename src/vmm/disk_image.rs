//! Disk image creation for echOS guest VMs.
//!
//! Provides utilities to create and manage disk images that can be
//! attached to VirtIO Block devices for guest VMs.

use crate::vmm::{HvError, HvResult};

/// Sector size for disk images (512 bytes)
pub const SECTOR_SIZE: u64 = 512;

/// Default disk image size (64 MB)
pub const DEFAULT_DISK_SIZE: u64 = 64 * 1024 * 1024;

/// MBR partition table signature
pub const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// Partition types
pub mod partition_type {
    pub const FAT32_LBA: u8 = 0x0C;
    pub const LINUX: u8 = 0x83;
    pub const EXT4: u8 = 0x83;
}

/// MBR partition entry (16 bytes)
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct MbrPartitionEntry {
    pub boot_indicator: u8,
    pub starting_chs: [u8; 3],
    pub partition_type: u8,
    pub ending_chs: [u8; 3],
    pub starting_lba: u32,
    pub size_lba: u32,
}

impl MbrPartitionEntry {
    pub const fn new() -> Self {
        Self {
            boot_indicator: 0,
            starting_chs: [0, 0, 0],
            partition_type: 0,
            ending_chs: [0, 0, 0],
            size_lba: 0,
            starting_lba: 0,
        }
    }

    /// Create a bootable partition entry.
    pub fn bootable(partition_type: u8, start_lba: u32, size_lba: u32) -> Self {
        Self {
            boot_indicator: 0x80, // Bootable
            starting_chs: [0xFE, 0xFF, 0xFF], // Dummy CHS (LBA used)
            partition_type,
            ending_chs: [0xFE, 0xFF, 0xFF],
            starting_lba: start_lba,
            size_lba: size_lba,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// FAT32 BIOS Parameter Block (BPB)
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Fat32Bpb {
    pub jump_boot: [u8; 3],
    pub oem_name: [u8; 8],
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub root_entry_count: u16,
    pub total_sectors_16: u16,
    pub media_type: u8,
    pub sectors_per_fat_16: u16,
    pub sectors_per_track: u16,
    pub num_heads: u16,
    pub hidden_sectors: u32,
    pub total_sectors_32: u32,
    // FAT32 extended
    pub sectors_per_fat_32: u32,
    pub ext_flags: u16,
    pub fs_version: u16,
    pub root_cluster: u32,
    pub fs_info_sector: u16,
    pub backup_boot_sector: u16,
    pub reserved: [u8; 12],
    pub drive_number: u8,
    pub reserved1: u8,
    pub boot_signature: u8,
    pub volume_id: u32,
    pub volume_label: [u8; 11],
    pub file_system_type: [u8; 8],
}

impl Fat32Bpb {
    /// Create a FAT32 BPB for a disk of the given size.
    pub fn new(total_sectors: u32) -> Self {
        let sectors_per_cluster = if total_sectors >= 2_097_152 { 64 }
        else if total_sectors >= 1_048_576 { 32 }
        else if total_sectors >= 524_288 { 16 }
        else if total_sectors >= 262_144 { 8 }
        else { 4 };

        // Calculate sectors per FAT (simplified)
        let sectors_per_fat = (total_sectors / (sectors_per_cluster as u32 * 128)) + 1;

        Self {
            jump_boot: [0xEB, 0x58, 0x90],
            oem_name: *b"Valkyrie",
            bytes_per_sector: 512,
            sectors_per_cluster,
            reserved_sectors: 32,
            num_fats: 2,
            root_entry_count: 0, // FAT32 uses root_cluster
            total_sectors_16: 0, // Use total_sectors_32
            media_type: 0xF8,
            sectors_per_fat_16: 0,
            sectors_per_track: 32,
            num_heads: 2,
            hidden_sectors: 0,
            total_sectors_32: total_sectors,
            sectors_per_fat_32: sectors_per_fat,
            ext_flags: 0,
            fs_version: 0,
            root_cluster: 2,
            fs_info_sector: 1,
            backup_boot_sector: 6,
            reserved: [0; 12],
            drive_number: 0x80,
            reserved1: 0,
            boot_signature: 0x29,
            volume_id: 0x12345678,
            volume_label: *b"Valkyrie   ",
            file_system_type: *b"FAT32   ",
        }
    }

    pub fn to_bytes(&self) -> [u8; 90] {
        unsafe { core::mem::transmute_copy(self) }
    }
}

/// Disk image builder for echOS VMs.
pub struct DiskImageBuilder {
    size: u64,
    partitions: [Option<MbrPartitionEntry>; 4],
    partition_count: usize,
}

impl DiskImageBuilder {
    pub fn new() -> Self {
        Self {
            size: DEFAULT_DISK_SIZE,
            partitions: [None, None, None, None],
            partition_count: 0,
        }
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Add a FAT32 partition (bootable).
    pub fn add_fat32_partition(mut self, size_mb: u64) -> Self {
        if self.partition_count >= 4 {
            return self;
        }
        let start_lba = if self.partition_count == 0 {
            2048 // 1MB offset for alignment
        } else {
            // Start after previous partition
            let prev = &self.partitions[self.partition_count - 1];
            prev.map(|p| p.starting_lba + p.size_lba).unwrap_or(2048)
        };
        let size_lba = ((size_mb * 1024 * 1024) / SECTOR_SIZE) as u32;
        
        self.partitions[self.partition_count] = Some(
            MbrPartitionEntry::bootable(partition_type::FAT32_LBA, start_lba, size_lba)
        );
        self.partition_count += 1;
        self
    }

    /// Add a Linux/EXT4 partition.
    pub fn add_linux_partition(mut self, size_mb: u64) -> Self {
        if self.partition_count >= 4 {
            return self;
        }
        let start_lba = if self.partition_count == 0 {
            2048
        } else {
            let prev = &self.partitions[self.partition_count - 1];
            prev.map(|p| p.starting_lba + p.size_lba).unwrap_or(2048)
        };
        let size_lba = ((size_mb * 1024 * 1024) / SECTOR_SIZE) as u32;
        
        self.partitions[self.partition_count] = Some(
            MbrPartitionEntry::bootable(partition_type::LINUX, start_lba, size_lba)
        );
        self.partition_count += 1;
        self
    }

    /// Build the MBR sector.
    pub fn build_mbr(&self) -> [u8; 512] {
        let mut mbr = [0u8; 512];

        // Boot code area (first 446 bytes) - real MBR boot loader
        // This code finds a bootable partition, loads its boot sector, and jumps to it
        
        // Boot loader code (x86 real mode, 16-bit)
        // Entry point at 0x7C00 (where BIOS loads MBR)
        let boot_code: &[u8] = &[
            // JMP short to code (skip data)
            0xEB, 0x3C, 0x90,              // jmp short +0x3C; nop
            
            // OEM name (8 bytes)
            b'V', b'A', b'L', b'K', b'Y', b'R', b'I', b'E',
            
            // Boot code starts here (offset 0x0B)
            // CLI - disable interrupts
            0xFA,                           // cli
            
            // XOR AX, AX - zero AX
            0x31, 0xC0,                     // xor ax, ax
            
            // MOV DS, AX - set DS to 0
            0x8E, 0xD8,                     // mov ds, ax
            
            // MOV ES, AX - set ES to 0
            0x8E, 0xC0,                     // mov es, ax
            
            // MOV SS, AX - set SS to 0
            0x8E, 0xD0,                     // mov ss, ax
            
            // MOV SP, 0x7C00 - set up stack below MBR
            0xBC, 0x00, 0x7C,               // mov sp, 0x7C00
            
            // STI - enable interrupts
            0xFB,                           // sti
            
            // Find bootable partition (scan partition table at 0x7C00 + 0x1BE)
            // MOV SI, 0x7C00 + 0x1BE (partition table)
            0xBE, 0xBE, 0x7C,               // mov si, 0x7CBE
            
            // MOV CL, 4 - 4 partition entries
            0xB1, 0x04,                     // mov cl, 4
            
            // Loop through partitions
            // check_partition:
            0x80, 0x3C, 0x80,               // cmp byte [si], 0x80 (bootable?)
            0x74, 0x0E,                     // jz found_bootable
            
            // ADD SI, 16 - next partition entry
            0x83, 0xC6, 0x10,               // add si, 16
            
            // LOOP check_partition
            0xE2, 0xF5,                     // loop -11
            
            // No bootable partition - halt
            // INT 0x18 - boot failure
            0xCD, 0x18,                     // int 0x18
            
            // found_bootable:
            // MOV BP, SI - save partition entry pointer
            0x89, 0xEE,                     // mov bp, si
            
            // Load boot sector from partition
            // MOV DI, 5 - retry count
            0xBF, 0x05, 0x00,               // mov di, 5
            
            // read_retry:
            // MOV SI, BP - restore partition pointer
            0x89, 0xEE,                     // mov si, bp
            
            // MOV AH, 0 - reset disk
            0xB4, 0x00,                     // mov ah, 0
            
            // MOV DL, 0x80 - first hard disk
            0xB2, 0x80,                     // mov dl, 0x80
            
            // INT 0x13 - BIOS disk service
            0xCD, 0x13,                     // int 0x13
            
            // Load LBA of boot sector from partition entry
            // MOV EAX, [SI+8] - LBA low dword
            0x66, 0x8B, 0x44, 0x08,         // mov eax, [si+8]
            
            // MOV [LBA], EAX - store for DAP
            0x66, 0xA3, 0x80, 0x7C,         // mov [0x7C80], eax
            
            // MOV EAX, [SI+12] - LBA high dword
            0x66, 0x8B, 0x44, 0x0C,         // mov eax, [si+12]
            
            // MOV [LBA+4], EAX - store for DAP
            0x66, 0xA3, 0x84, 0x7C,         // mov [0x7C84], eax
            
            // Set up Disk Address Packet (DAP) at 0x7C78
            // MOV byte [0x7C78], 0x10 - DAP size
            0xC6, 0x06, 0x78, 0x7C, 0x10,   // mov byte [0x7C78], 16
            
            // MOV byte [0x7C79], 0x00 - reserved
            0xC6, 0x06, 0x79, 0x7C, 0x00,   // mov byte [0x7C79], 0
            
            // MOV word [0x7C7A], 0x0001 - 1 sector
            0xC7, 0x06, 0x7A, 0x7C, 0x01, 0x00, // mov word [0x7C7A], 1
            
            // MOV word [0x7C7C], 0x7C00 - buffer at 0x7C00
            0xC7, 0x06, 0x7C, 0x7C, 0x00, 0x7C, // mov word [0x7C7C], 0x7C00
            
            // MOV word [0x7C7E], 0x0000 - buffer segment
            0xC7, 0x06, 0x7E, 0x7C, 0x00, 0x00, // mov word [0x7C7E], 0
            
            // MOV AH, 0x42 - extended read
            0xB4, 0x42,                     // mov ah, 0x42
            
            // MOV DL, 0x80 - first hard disk
            0xB2, 0x80,                     // mov dl, 0x80
            
            // MOV SI, 0x7C78 - DAP pointer
            0xBE, 0x78, 0x7C,               // mov si, 0x7C78
            
            // INT 0x13 - BIOS disk service
            0xCD, 0x13,                     // int 0x13
            
            // JC read_failed - if carry, read failed
            0x72, 0x03,                     // jc +3
            
            // JMP 0x0000:0x7C00 - jump to boot sector
            0xEA, 0x00, 0x7C, 0x00, 0x00,   // jmp 0x0000:0x7C00
            
            // read_failed:
            // DEC DI - decrement retry count
            0x4F,                           // dec di
            
            // JNZ read_retry - retry if not zero
            0x75, 0xB7,                     // jnz -73
            
            // Too many failures - halt
            0xEB, 0xFE,                     // jmp $ (halt)
            
            // Padding to reach 0x1BE
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        
        // Copy boot code to MBR
        mbr[..boot_code.len()].copy_from_slice(boot_code);

        // Partition entries at offset 446
        let mut offset = 446;
        for i in 0..4 {
            if let Some(ref part) = self.partitions[i] {
                let bytes = part.to_bytes();
                mbr[offset..offset + 16].copy_from_slice(&bytes);
            }
            offset += 16;
        }

        // MBR signature
        mbr[510] = MBR_SIGNATURE[0];
        mbr[511] = MBR_SIGNATURE[1];

        mbr
    }

    /// Build a FAT32 boot sector for the first partition.
    pub fn build_fat32_boot(&self) -> [u8; 512] {
        let mut boot = [0u8; 512];
        
        if let Some(ref part) = self.partitions[0] {
            let bpb = Fat32Bpb::new(part.size_lba);
            let bpb_bytes = bpb.to_bytes();
            boot[..bpb_bytes.len()].copy_from_slice(&bpb_bytes);
        }

        // Boot sector signature
        boot[510] = 0x55;
        boot[511] = 0xAA;

        boot
    }

    /// Get total size in bytes.
    pub fn total_size(&self) -> u64 {
        self.size
    }

    /// Get total sectors.
    pub fn total_sectors(&self) -> u64 {
        self.size / SECTOR_SIZE
    }
}

impl Default for DiskImageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create a minimal bootable disk image for echOS.
/// Returns a vector of bytes representing the disk image.
pub fn create_echos_boot_disk() -> HvResult<[u8; DEFAULT_DISK_SIZE as usize]> {
    let builder = DiskImageBuilder::new()
        .add_fat32_partition(32); // 32 MB FAT32 partition

    let mut disk = [0u8; DEFAULT_DISK_SIZE as usize];

    // Write MBR at sector 0
    let mbr = builder.build_mbr();
    disk[..512].copy_from_slice(&mbr);

    // Write FAT32 boot sector at partition start (sector 2048)
    let fat_boot = builder.build_fat32_boot();
    let partition_start = 2048 * 512;
    disk[partition_start..partition_start + 512].copy_from_slice(&fat_boot);

    Ok(disk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mbr_partition_entry() {
        let entry = MbrPartitionEntry::bootable(partition_type::FAT32_LBA, 2048, 1024);
        // Copy values from packed struct to avoid unaligned reference
        let boot = entry.boot_indicator;
        let ptype = entry.partition_type;
        let start = entry.starting_lba;
        let size = entry.size_lba;
        assert_eq!(boot, 0x80);
        assert_eq!(ptype, partition_type::FAT32_LBA);
        assert_eq!(start, 2048);
        assert_eq!(size, 1024);
    }

    #[test]
    fn disk_builder() {
        let builder = DiskImageBuilder::new()
            .add_fat32_partition(32);
        
        let mbr = builder.build_mbr();
        assert_eq!(mbr[510], 0x55);
        assert_eq!(mbr[511], 0xAA);
    }
}
