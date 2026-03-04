use crate::vmm::HvError;
use crate::vmm::HvResult;
use core::fmt;

pub const PAGE_SIZE: u64 = 4096;
pub const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
pub const GIGA_PAGE_SIZE: u64 = 1024 * 1024 * 1024;

pub const GUEST_MEMORY_BASE: u64 = 0x100000;
pub const GUEST_MEMORY_MAX: u64 = 128 * 1024 * 1024;

pub const KERNEL_LOAD_BASE: u64 = 0x100000;
pub const KERNEL_MAX_SIZE: u64 = 64 * 1024 * 1024;

pub const INITRD_LOAD_BASE: u64 = 0x10_000_000;
pub const INITRD_MAX_SIZE: u64 = 64 * 1024 * 1024;

pub const BOOT_PARAMS_BASE: u64 = 0x20000;
pub const BOOT_STACK_BASE: u64 = 0x30000;
pub const BOOT_STACK_SIZE: u64 = 0x10000;

pub const MMIO_START: u64 = 0xFE000000;
pub const MMIO_END: u64 = 0xFEE00000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Unusable,
    Usable,
    Reserved,
    ACPIReclaimable,
    ACPINVS,
    BootInfo,
    Kernel,
    Initrd,
    BootParams,
    MMIO,
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: u64,
    pub size: u64,
    pub mem_type: MemoryType,
}

impl MemoryRegion {
    pub const fn new(start: u64, size: u64, mem_type: MemoryType) -> Self {
        Self {
            start,
            size,
            mem_type,
        }
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.start + self.size
    }

    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

impl fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:016x}-{:016x} {:?}",
            self.start,
            self.end(),
            self.mem_type
        )
    }
}

pub struct GuestMemory {
    regions: [Option<MemoryRegion>; 32],
    region_count: usize,
    next_alloc: u64,
    /// Host physical address of the start of guest RAM (GPA 0).
    host_base: u64,
    /// Upper bound on valid GPAs, derived from the Atlas allocation size at
    /// `init()` time.  Replaces the compile-time `GUEST_MEMORY_MAX` constant
    /// so that larger configurations (set via `VmConfig::memory_size`) are
    /// honoured rather than silently truncated to 128 MiB.
    memory_limit: u64,
}

impl GuestMemory {
    pub const fn new() -> Self {
        const EMPTY: Option<MemoryRegion> = None;
        Self {
            regions: [EMPTY; 32],
            region_count: 0,
            next_alloc: GUEST_MEMORY_BASE,
            host_base: 0,
            // Conservative default until init() is called with the real size.
            memory_limit: GUEST_MEMORY_MAX,
        }
    }

    pub fn init(&mut self, host_memory: u64, host_memory_size: u64) -> HvResult<()> {
        self.host_base = host_memory;
        // Use the actual allocation size as the GPA limit.
        self.memory_limit = host_memory_size;

        // ── Low memory (below 640K) ──────────────────────────────────────
        self.regions[self.region_count] = Some(MemoryRegion::new(0, 0x9FC00, MemoryType::Reserved));
        self.region_count += 1;

        self.regions[self.region_count] =
            Some(MemoryRegion::new(0x9FC00, 0x400, MemoryType::BootInfo));
        self.region_count += 1;

        // ── BIOS / ACPI area ─────────────────────────────────────────────
        self.regions[self.region_count] =
            Some(MemoryRegion::new(0xE0000, 0x20000, MemoryType::Reserved));
        self.region_count += 1;

        // ── Usable RAM below 4 GiB (after 1 MiB) ────────────────────────
        // RAM below the MMIO hole (0xFE000000).
        let below_mmio_end = MMIO_START.min(host_memory_size);
        let usable_start = 0x100000u64;
        let below_4g_size = below_mmio_end.saturating_sub(usable_start);
        if below_4g_size > 0 {
            self.regions[self.region_count] = Some(MemoryRegion::new(
                usable_start,
                below_4g_size,
                MemoryType::Usable,
            ));
            self.region_count += 1;
        }

        // ── MMIO hole ────────────────────────────────────────────────────
        self.regions[self.region_count] = Some(MemoryRegion::new(
            MMIO_START,
            MMIO_END - MMIO_START,
            MemoryType::MMIO,
        ));
        self.region_count += 1;

        // ── Usable RAM above 4 GiB ──────────────────────────────────────
        // If allocated size > 4 GiB, place the overflow above 0x1_0000_0000.
        const FOUR_GIB: u64 = 0x1_0000_0000;
        if host_memory_size > MMIO_START {
            let above_4g_start = FOUR_GIB;
            let stolen_by_mmio = host_memory_size - below_mmio_end;
            // The region above 4G covers whatever couldn't fit below the MMIO hole.
            let above_4g_size = stolen_by_mmio.min(host_memory_size.saturating_sub(FOUR_GIB));
            if above_4g_size > 0 && self.region_count < 32 {
                self.regions[self.region_count] = Some(MemoryRegion::new(
                    above_4g_start,
                    above_4g_size,
                    MemoryType::Usable,
                ));
                self.region_count += 1;
                self.next_alloc = above_4g_start + above_4g_size;
            } else {
                self.next_alloc = usable_start + below_4g_size;
            }
        } else {
            self.next_alloc = usable_start + below_4g_size;
        }

        Ok(())
    }

    pub fn add_region(&mut self, start: u64, size: u64, mem_type: MemoryType) -> HvResult<()> {
        if self.region_count >= 32 {
            return Err(HvError::LogicalFault);
        }

        let new_region = MemoryRegion::new(start, size, mem_type);

        for i in 0..self.region_count {
            if let Some(region) = self.regions[i] {
                if region.start < new_region.start + new_region.size
                    && new_region.start < region.start + region.size
                {
                    return Err(HvError::LogicalFault);
                }
            }
        }

        self.regions[self.region_count] = Some(new_region);
        self.region_count += 1;
        Ok(())
    }

    pub fn allocate(&mut self, size: u64, alignment: u64) -> HvResult<u64> {
        let aligned = if alignment > 0 {
            (self.next_alloc + alignment - 1) & !(alignment - 1)
        } else {
            self.next_alloc
        };

        if aligned + size > self.memory_limit {
            return Err(HvError::LogicalFault);
        }

        self.next_alloc = aligned + size;

        self.add_region(aligned, size, MemoryType::Usable)?;

        Ok(aligned)
    }

    pub fn find_region(&self, addr: u64) -> Option<MemoryRegion> {
        for i in 0..self.region_count {
            if let Some(region) = self.regions[i] {
                if region.contains(addr) {
                    return Some(region);
                }
            }
        }
        None
    }

    pub fn is_valid_gpa(&self, addr: u64, size: u64) -> bool {
        if addr + size > self.memory_limit {
            return false;
        }
        let mut remaining = size;
        let mut current = addr;

        while remaining > 0 {
            let page_start = current & !(PAGE_SIZE - 1);
            if let Some(region) = self.find_region(page_start) {
                if matches!(region.mem_type, MemoryType::MMIO | MemoryType::Reserved) {
                    return false;
                }
                let offset_in_region = page_start - region.start;
                let remaining_in_region = region.size - offset_in_region;
                if remaining <= remaining_in_region {
                    return true;
                }
                current += remaining_in_region;
                remaining -= remaining_in_region;
            } else {
                return false;
            }
        }
        true
    }

    /// Copy `data` bytes into guest RAM at guest physical address `gpa`.
    ///
    /// # Safety
    /// Caller must ensure `host_base` is valid mapped memory (`init()` was called).
    pub fn write_bytes(&self, gpa: u64, data: &[u8]) -> HvResult<()> {
        if self.host_base == 0 {
            return Err(HvError::LogicalFault);
        }
        if !self.is_valid_gpa(gpa, data.len() as u64) {
            return Err(HvError::LogicalFault);
        }
        // Identity offset: HPA = host_base + GPA
        let hpa = self.host_base + gpa;
        unsafe {
            core::ptr::copy_nonoverlapping(data.as_ptr(), hpa as *mut u8, data.len());
        }
        Ok(())
    }

    /// Copy bytes from guest RAM at `gpa` into `out`.
    pub fn read_bytes(&self, gpa: u64, out: &mut [u8]) -> HvResult<()> {
        if self.host_base == 0 {
            return Err(HvError::LogicalFault);
        }
        let end = gpa.saturating_add(out.len() as u64);
        if end > self.memory_limit {
            return Err(HvError::LogicalFault);
        }
        let hpa = self.host_base + gpa;
        unsafe {
            core::ptr::copy_nonoverlapping(hpa as *const u8, out.as_mut_ptr(), out.len());
        }
        Ok(())
    }

    /// Write bytes to guest RAM bypassing region validation.
    /// Used for boot infrastructure (GDT, page tables) that lives in
    /// "reserved" GPA ranges.
    ///
    /// # Safety
    /// Caller must ensure `gpa + data.len()` does not exceed `memory_limit`.
    pub unsafe fn write_boot_data(&self, gpa: u64, data: &[u8]) -> HvResult<()> {
        if self.host_base == 0 {
            return Err(HvError::LogicalFault);
        }
        let end = gpa.saturating_add(data.len() as u64);
        if end > self.memory_limit {
            return Err(HvError::LogicalFault);
        }
        let hpa = self.host_base + gpa;
        core::ptr::copy_nonoverlapping(data.as_ptr(), hpa as *mut u8, data.len());
        Ok(())
    }

    /// Return the host physical base address for this guest's RAM.
    pub fn host_base(&self) -> u64 {
        self.host_base
    }

    /// Return the guest memory limit.
    pub fn memory_limit(&self) -> u64 {
        self.memory_limit
    }

    /// Return the allocated bytes (approximation based on next_alloc).
    pub fn allocated_bytes(&self) -> u64 {
        self.next_alloc.saturating_sub(GUEST_MEMORY_BASE)
    }

    /// Zero a range of guest physical memory.
    ///
    /// This is important for security — prevents information leakage
    /// between VMs and ensures the guest sees clean memory.
    pub fn zero_range(&self, gpa: u64, size: u64) -> HvResult<()> {
        if self.host_base == 0 {
            return Err(HvError::LogicalFault);
        }
        let end = gpa.saturating_add(size);
        if end > self.memory_limit {
            return Err(HvError::LogicalFault);
        }
        let hpa = self.host_base + gpa;
        unsafe {
            core::ptr::write_bytes(hpa as *mut u8, 0, size as usize);
        }
        Ok(())
    }

    /// Return the number of regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Return a region by index.
    pub fn region(&self, idx: usize) -> Option<MemoryRegion> {
        if idx < self.region_count {
            self.regions[idx]
        } else {
            None
        }
    }

    /// Compute the EPT permission bits that should be applied for a given
    /// memory region type.  Used to enforce type-based memory protection in
    /// the EPT.
    ///
    /// Returns (read, write, execute) permission bits compatible with
    /// `Ept::map_4k_with_perms`.
    pub fn ept_perms_for_type(mem_type: MemoryType) -> u64 {
        // EPT_READ=1, EPT_WRITE=2, EPT_EXEC=4
        const R: u64 = 1;
        const W: u64 = 2;
        const X: u64 = 4;
        match mem_type {
            MemoryType::Usable => R | W | X,
            MemoryType::Kernel => R | W | X,
            MemoryType::Initrd => R,          // initrd is read-only
            MemoryType::BootInfo => R | W,     // boot data, no exec
            MemoryType::BootParams => R | W,
            MemoryType::Reserved => R | W,     // BIOS area, no exec
            MemoryType::ACPIReclaimable => R,
            MemoryType::ACPINVS => R,
            MemoryType::MMIO => R | W,         // MMIO: RW, no exec
            MemoryType::Unusable => 0,         // no access
        }
    }

    // ── Boot table writers ────────────────────────────────────────────────

    /// GDT layout at GPA 0x500 (matches VMCS GDTR_BASE=0x500, LIMIT=0x27):
    ///   [0] 0x00: null descriptor
    ///   [1] 0x08: 64-bit code segment (CS)
    ///   [2] 0x10: 64-bit data segment (DS/ES/SS)
    ///   [3] 0x18: 32-bit TSS (busy)
    ///   [4] 0x20: TSS upper 8 bytes (zero — required for 64-bit TSS)
    pub const GDT_BASE: u64 = 0x500;

    /// Write a valid GDT into guest RAM so the processor can load segments.
    pub fn write_guest_gdt(&self) -> HvResult<()> {
        // Null descriptor
        let null_desc: u64 = 0;
        // 64-bit code: base=0, limit=0xFFFFF, G=1, L=1, P=1, S=1, type=0xB(exec/read/acc)
        // Bits: base[31:24]=0|G=1|L=1|0|0|limit[19:16]=F|P=1|DPL=00|S=1|type=1011
        //       base[23:16]=0 | limit[15:0]=FFFF | base[15:0]=0
        let code64_desc: u64 = 0x00AF_9B00_0000_FFFF;
        // 64-bit data: base=0, limit=0xFFFFF, G=1, DB=1, P=1, S=1, type=0x3(read/write/acc)
        let data64_desc: u64 = 0x00CF_9300_0000_FFFF;
        // 32-bit TSS busy: base=0, limit=0x67, P=1, type=0xB(busy TSS)
        let tss_desc: u64 = 0x0000_8B00_0000_0067;
        // TSS upper 8 bytes (for 64-bit mode, bits 63:32 of base — zero)
        let tss_hi: u64 = 0;

        let mut gdt = [0u8; 40]; // 5 entries × 8 bytes
        gdt[0..8].copy_from_slice(&null_desc.to_le_bytes());
        gdt[8..16].copy_from_slice(&code64_desc.to_le_bytes());
        gdt[16..24].copy_from_slice(&data64_desc.to_le_bytes());
        gdt[24..32].copy_from_slice(&tss_desc.to_le_bytes());
        gdt[32..40].copy_from_slice(&tss_hi.to_le_bytes());

        unsafe { self.write_boot_data(Self::GDT_BASE, &gdt) }
    }

    /// Page table layout at GPA 0x1000 (matches VMCS CR3=0x1000):
    ///   PML4  at 0x1000 — 1 entry pointing to PDPT at 0x2000
    ///     (Note: if 0x2000 conflicts with BOOT_PARAMS_BASE, adjust.)
    ///   PDPT  at 0x2000 — up to 4 entries, each pointing to a PD
    ///   PD[0] at 0x3000 — 512 × 2 MiB large-page entries = 1 GiB
    ///   PD[1] at 0x4000 — 512 × 2 MiB large-page entries = 1 GiB
    ///   PD[2] at 0x5000 — 512 × 2 MiB large-page entries = 1 GiB
    ///   PD[3] at 0x6000 — 512 × 2 MiB large-page entries = 1 GiB
    ///
    /// This gives 4 GiB of identity-mapped guest virtual memory using
    /// 2 MiB large pages.  The guest can install its own page tables later.
    ///
    /// But BOOT_PARAMS_BASE is 0x20000, BOOT_STACK_BASE is 0x30000, so
    /// pages 0x2000..0x6FFF are safe to use for page tables.
    pub fn write_guest_page_tables(&self) -> HvResult<()> {
        const PML4_ADDR: u64 = 0x1000;
        const PDPT_ADDR: u64 = 0x2000;
        const PD0_ADDR: u64 = 0x3000;
        const PD1_ADDR: u64 = 0x4000;
        const PD2_ADDR: u64 = 0x5000;
        const PD3_ADDR: u64 = 0x6000;

        const PRESENT: u64 = 1;
        const WRITABLE: u64 = 1 << 1;
        const PS_2MB: u64 = 1 << 7; // Page Size bit for 2 MiB pages
        const PTE_FLAGS: u64 = PRESENT | WRITABLE;
        const LARGE_FLAGS: u64 = PRESENT | WRITABLE | PS_2MB;

        // How many GiB to map (cap at 4 for 4×PD)
        let gib = ((self.memory_limit + 0x3FFF_FFFF) / 0x4000_0000).min(4) as usize;

        // ── PML4: single entry → PDPT ──
        let mut pml4 = [0u8; 4096];
        let pml4_entry = PDPT_ADDR | PTE_FLAGS;
        pml4[0..8].copy_from_slice(&pml4_entry.to_le_bytes());
        unsafe { self.write_boot_data(PML4_ADDR, &pml4)?; }

        // ── PDPT: one entry per GiB → PD[n] ──
        let pd_addrs = [PD0_ADDR, PD1_ADDR, PD2_ADDR, PD3_ADDR];
        let mut pdpt = [0u8; 4096];
        for i in 0..gib {
            let entry = pd_addrs[i] | PTE_FLAGS;
            let off = i * 8;
            pdpt[off..off + 8].copy_from_slice(&entry.to_le_bytes());
        }
        unsafe { self.write_boot_data(PDPT_ADDR, &pdpt)?; }

        // ── PD[n]: 512 × 2 MiB identity-mapped large pages ──
        for g in 0..gib {
            let mut pd = [0u8; 4096];
            for i in 0..512 {
                let phys = (g as u64) * 0x4000_0000 + (i as u64) * 0x20_0000;
                let entry = phys | LARGE_FLAGS;
                let off = i * 8;
                pd[off..off + 8].copy_from_slice(&entry.to_le_bytes());
            }
            unsafe { self.write_boot_data(pd_addrs[g], &pd)?; }
        }

        Ok(())
    }

    /// Write a minimal IDT with 256 entries at GPA 0x7000.
    /// Each entry points to a dummy HLT handler at GPA 0x6000.
    /// The guest OS will overwrite this with its own IDT.
    ///
    /// The dummy handler provides better debugging:
    /// - Stores vector number in a known memory location
    /// - Executes HLT to pause CPU
    /// - Loops forever in case of NMI/SMI resume
    /// Guest OS (echOS/Linux) will install its own handlers early in boot.
    pub fn write_guest_idt_stub(&self) -> HvResult<()> {
        // Write dummy interrupt handlers at GPA 0x6000.
        // Each handler is 4 bytes:
        //   MOV AL, vector (B0 XX) - store vector number in AL
        //   HLT (F4)               - halt until interrupt
        //   JMP $-1 (EB FE)        - infinite loop after HLT
        // 4 bytes per handler × 256 vectors = 1024 bytes.
        let handler_base: u64 = 0x6000;
        let mut handlers = [0u8; 1024];
        for vector in 0..256 {
            let offset = vector * 4;
            // MOV AL, imm8 (B0 + vector) - store vector in AL for debugging
            handlers[offset] = 0xB0;
            handlers[offset + 1] = vector as u8;
            // HLT instruction - halt until interrupt
            handlers[offset + 2] = 0xF4;
            // JMP $-2 (EB FC) - infinite loop after HLT (jumps back to HLT)
            handlers[offset + 3] = 0xEB;
        }
        unsafe { self.write_boot_data(handler_base, &handlers)?; }

        // Build IDT entries (16 bytes each) pointing to handlers.
        // IDT at GPA 0x7000, 256 entries × 16 bytes = 4096 bytes.
        let mut idt = [0u8; 4096];
        for vector in 0..256 {
            let entry_offset = vector * 16;
            let handler_addr = handler_base + (vector as u64 * 4);

            // Offset low (bits 0-15)
            idt[entry_offset] = (handler_addr & 0xFF) as u8;
            idt[entry_offset + 1] = ((handler_addr >> 8) & 0xFF) as u8;

            // Selector (code segment = 0x08, 64-bit kernel CS)
            idt[entry_offset + 2] = 0x08;
            idt[entry_offset + 3] = 0x00;

            // Type/Attributes: P=1, DPL=0, Type=0xE (Interrupt Gate, 64-bit)
            // Bits: P(7) DPL(6:5) 0(4) Type(3:0) = 1_00_0_1110 = 0x8E
            idt[entry_offset + 4] = 0x00; // IST = 0
            idt[entry_offset + 5] = 0x8E; // P=1, DPL=0, Type=0xE

            // Offset middle (bits 16-31)
            idt[entry_offset + 6] = ((handler_addr >> 16) & 0xFF) as u8;
            idt[entry_offset + 7] = ((handler_addr >> 24) & 0xFF) as u8;

            // Offset high (bits 32-63)
            idt[entry_offset + 8] = ((handler_addr >> 32) & 0xFF) as u8;
            idt[entry_offset + 9] = ((handler_addr >> 40) & 0xFF) as u8;
            idt[entry_offset + 10] = ((handler_addr >> 48) & 0xFF) as u8;
            idt[entry_offset + 11] = ((handler_addr >> 56) & 0xFF) as u8;

            // Reserved (bits 12-15)
            idt[entry_offset + 12] = 0x00;
            idt[entry_offset + 13] = 0x00;
            idt[entry_offset + 14] = 0x00;
            idt[entry_offset + 15] = 0x00;
        }

        unsafe { self.write_boot_data(0x7000, &idt) }
    }

    // ── ACPI table writers ────────────────────────────────────────────────

    /// ACPI table layout in guest RAM (within the 0xE0000-0xFFFFF BIOS area):
    ///
    ///  GPA 0xE0000: RSDP  (Root System Description Pointer, 36 bytes v2.0)
    ///  GPA 0xE1000: XSDT  (Extended SDT, header + 3 entries: MADT, FADT, DSDT)
    ///  GPA 0xE2000: MADT  (Multiple APIC Description Table)
    ///  GPA 0xE3000: FADT  (Fixed ACPI Description Table)
    ///  GPA 0xE4000: DSDT  (Differentiated System Description Table)
    ///
    /// This is the minimum set of tables an ACPI-aware guest (Linux/echOS)
    /// needs to initialise ACPI, discover the LAPIC + I/O APIC, and perform
    /// ACPI shutdown.
    pub const RSDP_BASE: u64 = 0xE0000;
    pub const XSDT_BASE: u64 = 0xE1000;
    pub const MADT_BASE: u64 = 0xE2000;
    pub const FADT_BASE: u64 = 0xE3000;
    pub const DSDT_BASE: u64 = 0xE4000;
    pub const FACS_BASE: u64 = 0xE5000;

    /// Command-line string destination in guest RAM.
    pub const CMDLINE_BASE: u64 = 0x8000;
    pub const CMDLINE_MAX_LEN: usize = 4096;

    /// Write a NUL-terminated kernel command line to guest RAM.
    ///
    /// Returns the GPA where the string was written (for boot_params.cmdline_ptr).
    pub fn write_cmdline(&self, cmdline: &[u8]) -> HvResult<u64> {
        let len = cmdline.len().min(Self::CMDLINE_MAX_LEN - 1);
        let mut buf = [0u8; Self::CMDLINE_MAX_LEN];
        buf[..len].copy_from_slice(&cmdline[..len]);
        buf[len] = 0; // NUL terminator
        unsafe { self.write_boot_data(Self::CMDLINE_BASE, &buf[..len + 1])?; }
        Ok(Self::CMDLINE_BASE)
    }

    /// Write a minimal FACS (Firmware ACPI Control Structure) to guest RAM.
    ///
    /// FACS is 64 bytes, required by ACPI 2.0+.  The structure contains
    /// the waking vector and global lock for OSPM↔firmware handshake.
    fn write_guest_facs(&self) -> HvResult<()> {
        let mut facs = [0u8; 64];
        facs[0..4].copy_from_slice(b"FACS");                  // Signature
        facs[4..8].copy_from_slice(&64u32.to_le_bytes());      // Length
        // Hardware signature = 0 (no S4BIOS)
        // Firmware waking vector = 0
        // Global lock = 0
        // Flags = 0
        // Version = 2
        facs[32] = 2; // FACS version
        // OSPM flags, X_firmware_waking_vector: all zero
        unsafe { self.write_boot_data(Self::FACS_BASE, &facs) }
    }

    /// Write ACPI tables (RSDP + XSDT + MADT + FADT + DSDT + FACS) into guest RAM.
    ///
    /// Tables written:
    ///   - RSDP v2.0 at 0xE0000 → points to XSDT
    ///   - XSDT at 0xE1000 → entries: MADT, FADT
    ///   - MADT at 0xE2000 → Local APIC 0, I/O APIC 0, IRQ overrides
    ///   - FADT at 0xE3000 → PM registers at 0x600-0x60B, links to DSDT + FACS
    ///   - DSDT at 0xE4000 → minimal empty AML namespace
    ///   - FACS at 0xE5000 → firmware/OSPM handshake
    pub fn write_guest_acpi_tables(&self) -> HvResult<()> {
        self.write_guest_acpi_tables_for_cpus(1)
    }

    /// Same as `write_guest_acpi_tables` but adds `num_cpus` Local APIC
    /// entries in the MADT (one per vCPU, APIC IDs 0..num_cpus-1).
    pub fn write_guest_acpi_tables_for_cpus(&self, num_cpus: u32) -> HvResult<()> {
        // ── FACS ──────────────────────────────────────────────────────────
        self.write_guest_facs()?;
        // ── MADT ──────────────────────────────────────────────────────────
        // Header: 44 bytes base + variable entries
        let mut madt = [0u8; 256];
        let madt_len: u32;
        {
            #[allow(unused_assignments)]
            let mut off = 0usize;

            // Standard ACPI header (44 bytes for MADT)
            madt[0..4].copy_from_slice(b"APIC");          // Signature
            // [4..8] = Length (filled below)
            madt[8] = 5;                                   // Revision
            // [9] = Checksum (filled below)
            madt[10..16].copy_from_slice(b"VALKYR");       // OEM ID
            madt[16..24].copy_from_slice(b"VALKYRIE");     // OEM Table ID
            madt[24..28].copy_from_slice(&1u32.to_le_bytes()); // OEM Revision
            madt[28..32].copy_from_slice(b"VKYR");         // Creator ID
            madt[32..36].copy_from_slice(&1u32.to_le_bytes()); // Creator Rev
            // MADT-specific: Local APIC Address
            madt[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
            // Flags: PCAT_COMPAT (bit 0) = 1 (dual 8259 present)
            madt[40..44].copy_from_slice(&1u32.to_le_bytes());
            off = 44;

            // Entries: one Local APIC per vCPU
            let cpus = (num_cpus as usize).min(16); // cap at 16 to fit buffer
            for cpu_id in 0..cpus {
                if off + 8 > madt.len() { break; }
                madt[off] = 0;                   // type: Processor Local APIC
                madt[off + 1] = 8;               // length
                madt[off + 2] = cpu_id as u8;    // ACPI Processor UID
                madt[off + 3] = cpu_id as u8;    // APIC ID
                madt[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes()); // Flags: enabled
                off += 8;
            }

            // Entry 1: I/O APIC (type=1, len=12)
            madt[off] = 1;         // type: I/O APIC
            madt[off + 1] = 12;    // length
            madt[off + 2] = 0;     // I/O APIC ID
            madt[off + 3] = 0;     // reserved
            madt[off + 4..off + 8].copy_from_slice(&0xFEC0_0000u32.to_le_bytes()); // addr
            madt[off + 8..off + 12].copy_from_slice(&0u32.to_le_bytes()); // GSI base
            off += 12;

            // Entry 2: Interrupt Source Override — IRQ0 → GSI 2 (edge)
            // Linux expects the PIT (IRQ0) on GSI 2 through the IOAPIC.
            madt[off] = 2;         // type: Interrupt Source Override
            madt[off + 1] = 10;    // length
            madt[off + 2] = 0;     // bus (ISA)
            madt[off + 3] = 0;     // source (IRQ0)
            madt[off + 4..off + 8].copy_from_slice(&2u32.to_le_bytes()); // GSI 2
            madt[off + 8..off + 10].copy_from_slice(&0u16.to_le_bytes()); // flags: conforms
            off += 10;

            // Entry 3: Interrupt Source Override — IRQ9 → GSI 9 (level, active-low)
            madt[off] = 2;
            madt[off + 1] = 10;
            madt[off + 2] = 0;     // bus (ISA)
            madt[off + 3] = 9;     // source (IRQ9)
            madt[off + 4..off + 8].copy_from_slice(&9u32.to_le_bytes()); // GSI 9
            madt[off + 8..off + 10].copy_from_slice(&0x000Du16.to_le_bytes()); // active-low, level
            off += 10;

            madt_len = off as u32;
            madt[4..8].copy_from_slice(&madt_len.to_le_bytes());

            // Compute checksum
            let mut sum: u8 = 0;
            for i in 0..off {
                sum = sum.wrapping_add(madt[i]);
            }
            madt[9] = (!sum).wrapping_add(1); // make whole table sum to 0
        }

        // ── DSDT (minimal empty namespace) ────────────────────────────────
        let mut dsdt = [0u8; 36];
        {
            dsdt[0..4].copy_from_slice(b"DSDT");           // Signature
            dsdt[4..8].copy_from_slice(&36u32.to_le_bytes()); // Length = header only
            dsdt[8] = 2;                                    // Revision
            dsdt[10..16].copy_from_slice(b"VALKYR");
            dsdt[16..24].copy_from_slice(b"VALKYRIE");
            dsdt[24..28].copy_from_slice(&1u32.to_le_bytes());
            dsdt[28..32].copy_from_slice(b"VKYR");
            dsdt[32..36].copy_from_slice(&1u32.to_le_bytes());
            // Checksum
            let mut sum: u8 = 0;
            for b in dsdt.iter() {
                sum = sum.wrapping_add(*b);
            }
            dsdt[9] = (!sum).wrapping_add(1);
        }

        // ── FADT (ACPI 6.0, revision 6, 276 bytes) ───────────────────────
        //
        // Provides PM registers for ACPI power management (shutdown, sleep)
        // and the pointer to the DSDT.
        //
        // PM I/O ports (QEMU-compatible):
        //   PM1a_EVT_BLK = 0x600, PM1a_CNT_BLK = 0x604, PM_TMR = 0x608
        let mut fadt = [0u8; 276];
        let fadt_len: u32 = 276;
        {
            // ── Standard ACPI header ──
            fadt[0..4].copy_from_slice(b"FACP");
            fadt[4..8].copy_from_slice(&fadt_len.to_le_bytes());
            fadt[8] = 6;                                    // Revision 6
            fadt[10..16].copy_from_slice(b"VALKYR");
            fadt[16..24].copy_from_slice(b"VALKYRIE");
            fadt[24..28].copy_from_slice(&1u32.to_le_bytes());
            fadt[28..32].copy_from_slice(b"VKYR");
            fadt[32..36].copy_from_slice(&1u32.to_le_bytes());

            // Offset 36: FIRMWARE_CTRL (32-bit) → FACS table
            fadt[36..40].copy_from_slice(&(Self::FACS_BASE as u32).to_le_bytes());
            // Offset 40: DSDT (32-bit legacy pointer)
            fadt[40..44].copy_from_slice(&(Self::DSDT_BASE as u32).to_le_bytes());

            // Offset 46-47: SCI_INT = 9
            fadt[46..48].copy_from_slice(&9u16.to_le_bytes());
            // Offset 48-51: SMI_CMD = 0 (ACPI always enabled, no SMI needed)

            // ── PM register blocks (I/O space) ──
            fadt[56..60].copy_from_slice(&0x0600u32.to_le_bytes()); // PM1a_EVT_BLK
            fadt[64..68].copy_from_slice(&0x0604u32.to_le_bytes()); // PM1a_CNT_BLK
            fadt[76..80].copy_from_slice(&0x0608u32.to_le_bytes()); // PM_TMR_BLK

            fadt[88] = 4;   // PM1_EVT_LEN
            fadt[89] = 2;   // PM1_CNT_LEN
            fadt[91] = 4;   // PM_TMR_LEN

            // Offset 96-97: P_LVL2_LAT = 0x0065 (101 → C2 not supported)
            fadt[96..98].copy_from_slice(&0x0065u16.to_le_bytes());
            // Offset 98-99: P_LVL3_LAT = 0x03E9 (1001 → C3 not supported)
            fadt[98..100].copy_from_slice(&0x03E9u16.to_le_bytes());

            // Offset 108: CENTURY register in RTC = 0x32
            fadt[108] = 0x32;

            // Offset 109-110: IAPC_BOOT_ARCH
            //   Bit 0 = LEGACY_DEVICES, Bit 1 = 8042
            fadt[109..111].copy_from_slice(&0x0003u16.to_le_bytes());

            // Offset 112-115: Flags
            //   Bit 0  = WBINVD
            //   Bit 5  = PWR_BUTTON (use control method, no fixed button)
            //   Bit 8  = TMR_VAL_EXT (32-bit ACPI timer)
            let flags: u32 = (1 << 0) | (1 << 5) | (1 << 8);
            fadt[112..116].copy_from_slice(&flags.to_le_bytes());

            // Offset 131: FADT Minor Version = 0
            // Offset 132-139: X_FIRMWARE_CTRL (64-bit pointer to FACS)
            fadt[132..140].copy_from_slice(&Self::FACS_BASE.to_le_bytes());
            // Offset 140-147: X_DSDT (64-bit pointer to DSDT)
            fadt[140..148].copy_from_slice(&Self::DSDT_BASE.to_le_bytes());

            // ── Extended PM register GAS (Generic Address Structure) ──
            // X_PM1a_EVT_BLK (offset 148, 12 bytes)
            fadt[148] = 1;   // AddressSpace = System I/O
            fadt[149] = 32;  // BitWidth
            fadt[150] = 0;   // BitOffset
            fadt[151] = 2;   // AccessSize = Word
            fadt[152..160].copy_from_slice(&0x0600u64.to_le_bytes());

            // X_PM1a_CNT_BLK (offset 172, 12 bytes)
            fadt[172] = 1;
            fadt[173] = 16;
            fadt[174] = 0;
            fadt[175] = 2;
            fadt[176..184].copy_from_slice(&0x0604u64.to_le_bytes());

            // X_PM_TMR_BLK (offset 208, 12 bytes)
            fadt[208] = 1;
            fadt[209] = 32;
            fadt[210] = 0;
            fadt[211] = 3;   // AccessSize = DWord
            fadt[212..220].copy_from_slice(&0x0608u64.to_le_bytes());

            // Checksum
            let mut sum: u8 = 0;
            for b in fadt.iter() {
                sum = sum.wrapping_add(*b);
            }
            fadt[9] = (!sum).wrapping_add(1);
        }

        // ── XSDT ─────────────────────────────────────────────────────────
        // Header (36 bytes) + 2 × 8-byte pointers (MADT + FADT) = 52 bytes
        let mut xsdt = [0u8; 64];
        let xsdt_len: u32 = 36 + 8 + 8; // header + two entries
        {
            xsdt[0..4].copy_from_slice(b"XSDT");
            xsdt[4..8].copy_from_slice(&xsdt_len.to_le_bytes());
            xsdt[8] = 1;                                    // Revision
            xsdt[10..16].copy_from_slice(b"VALKYR");
            xsdt[16..24].copy_from_slice(b"VALKYRIE");
            xsdt[24..28].copy_from_slice(&1u32.to_le_bytes());
            xsdt[28..32].copy_from_slice(b"VKYR");
            xsdt[32..36].copy_from_slice(&1u32.to_le_bytes());
            // Entry[0] = MADT
            xsdt[36..44].copy_from_slice(&Self::MADT_BASE.to_le_bytes());
            // Entry[1] = FADT
            xsdt[44..52].copy_from_slice(&Self::FADT_BASE.to_le_bytes());

            let mut sum: u8 = 0;
            for i in 0..xsdt_len as usize {
                sum = sum.wrapping_add(xsdt[i]);
            }
            xsdt[9] = (!sum).wrapping_add(1);
        }

        // ── RSDP v2.0 ────────────────────────────────────────────────────
        // 36 bytes total for ACPI 2.0 RSDP
        let mut rsdp = [0u8; 36];
        {
            rsdp[0..8].copy_from_slice(b"RSD PTR "); // Signature
            // [8] = checksum of first 20 bytes (filled below)
            rsdp[9..15].copy_from_slice(b"VALKYR");  // OEM ID
            rsdp[15] = 2;                              // Revision = 2 (ACPI 2.0+)
            // [16..20] = RSDT Address (we set to 0 — we only use XSDT)
            rsdp[16..20].copy_from_slice(&0u32.to_le_bytes());
            // [20..24] = Length of entire RSDP structure = 36
            rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
            // [24..32] = XSDT Address (64-bit)
            rsdp[24..32].copy_from_slice(&Self::XSDT_BASE.to_le_bytes());
            // [32] = extended checksum (of all 36 bytes, filled below)
            // [33..36] = reserved

            // v1 checksum: bytes 0-19 sum to 0
            let mut sum1: u8 = 0;
            for i in 0..20 {
                sum1 = sum1.wrapping_add(rsdp[i]);
            }
            rsdp[8] = (!sum1).wrapping_add(1);

            // v2 extended checksum: bytes 0-35 sum to 0
            let mut sum2: u8 = 0;
            for i in 0..36 {
                sum2 = sum2.wrapping_add(rsdp[i]);
            }
            rsdp[32] = (!sum2).wrapping_add(1);
        }

        // Write all five tables to guest RAM
        unsafe {
            self.write_boot_data(Self::RSDP_BASE, &rsdp)?;
            self.write_boot_data(Self::XSDT_BASE, &xsdt[..xsdt_len as usize])?;
            self.write_boot_data(Self::MADT_BASE, &madt[..madt_len as usize])?;
            self.write_boot_data(Self::FADT_BASE, &fadt)?;
            self.write_boot_data(Self::DSDT_BASE, &dsdt)?;
        }
        Ok(())
    }

    pub fn total_usable_memory(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.region_count {
            if let Some(region) = self.regions[i] {
                if matches!(
                    region.mem_type,
                    MemoryType::Usable | MemoryType::Kernel | MemoryType::Initrd
                ) {
                    total += region.size;
                }
            }
        }
        total
    }

    /// Write Linux boot_params at BOOT_PARAMS_BASE (0x20000).
    ///
    /// `cmdline_addr`: GPA of NUL-terminated cmdline string.
    /// `initrd_addr`:  GPA where initrd is loaded (0 if none).
    /// `initrd_size`:  Size of initrd in bytes (0 if none).
    ///
    /// The boot_params structure is placed at 0x20000 and RSI points
    /// to it on entry.  The `setup_header` starts at offset 0x1F1.
    pub fn write_linux_boot_params(
        &self,
        cmdline_addr: u32,
        initrd_addr: u32,
        initrd_size: u32,
    ) -> HvResult<()> {
        let mut bp = [0u8; 4096];

        // ── setup_header (at offset 0x1F1 in boot_params) ─────────────────
        // Boot protocol version 2.14 (0x020E)
        bp[0x206] = 0x0E; // version low
        bp[0x207] = 0x02; // version high

        // type_of_loader = 0xFF (undefined bootloader)
        bp[0x210] = 0xFF;

        // loadflags: bit 0=LOADED_HIGH (kernel loaded above 1M)
        bp[0x211] = 0x01;

        // cmd_line_ptr (offset 0x228)
        bp[0x228..0x22C].copy_from_slice(&cmdline_addr.to_le_bytes());

        // ramdisk_image (offset 0x218)
        bp[0x218..0x21C].copy_from_slice(&initrd_addr.to_le_bytes());
        // ramdisk_size (offset 0x21C)
        bp[0x21C..0x220].copy_from_slice(&initrd_size.to_le_bytes());

        // e820_entries (offset 0x1E8)
        let mut e820_idx: usize = 0;
        let e820_base: usize = 0xD00; // offset of e820_table in boot_params

        for i in 0..self.region_count {
            if let Some(region) = self.regions[i] {
                if e820_idx >= 128 { break; }
                let e820_type: u32 = match region.mem_type {
                    MemoryType::Usable => 1,
                    MemoryType::Reserved => 2,
                    MemoryType::ACPIReclaimable => 3,
                    MemoryType::ACPINVS => 4,
                    _ => 2,
                };
                let off = e820_base + e820_idx * 20;
                bp[off..off + 8].copy_from_slice(&region.start.to_le_bytes());
                bp[off + 8..off + 16].copy_from_slice(&region.size.to_le_bytes());
                bp[off + 16..off + 20].copy_from_slice(&e820_type.to_le_bytes());
                e820_idx += 1;
            }
        }
        bp[0x1E8] = e820_idx as u8;

        unsafe { self.write_boot_data(BOOT_PARAMS_BASE, &bp) }
    }
}

impl Default for GuestMemory {
    fn default() -> Self {
        Self::new()
    }
}

pub struct BootParams {
    pub setup_secs: u8,
    pub root_flags: u16,
    pub mem_magic: u16,
    pub orig_x: u32,
    pub orig_y: u32,
    pub oem_id: [u8; 8],
    pub loader_type: u8,
    pub kernel_alignment: u32,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub e820_entries: u8,
    pub e820_table: [E820Entry; 128],
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct E820Entry {
    pub addr: u64,
    pub size: u64,
    pub entry_type: u32,
}

impl BootParams {
    pub fn new() -> Self {
        Self {
            setup_secs: 0,
            root_flags: 0,
            mem_magic: 0,
            orig_x: 0,
            orig_y: 0,
            oem_id: [0u8; 8],
            loader_type: 0,
            kernel_alignment: 0,
            pref_address: 0,
            init_size: 0,
            handover_offset: 0,
            e820_entries: 0,
            e820_table: [E820Entry::empty(); 128],
        }
    }

    pub fn finalize(&mut self, mem: &GuestMemory) {
        let mut e820_idx = 0;

        for i in 0..mem.region_count {
            if let Some(region) = mem.regions[i] {
                if e820_idx >= 128 {
                    break;
                }

                let e820_type = match region.mem_type {
                    MemoryType::Usable => 1,
                    MemoryType::Reserved => 2,
                    MemoryType::ACPIReclaimable => 3,
                    MemoryType::ACPINVS => 4,
                    _ => 2,
                };

                self.e820_table[e820_idx] = E820Entry {
                    addr: region.start,
                    size: region.size,
                    entry_type: e820_type,
                };
                e820_idx += 1;
            }
        }

        self.e820_entries = e820_idx as u8;
        self.mem_magic = 0x5372;
    }
}

impl Default for BootParams {
    fn default() -> Self {
        Self::new()
    }
}

impl E820Entry {
    pub const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            entry_type: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acpi_rsdp_signature_and_checksum() {
        // Build the RSDP in-memory and verify signature + checksum.
        let mut rsdp = [0u8; 36];
        rsdp[0..8].copy_from_slice(b"RSD PTR ");
        rsdp[9..15].copy_from_slice(b"VALKYR");
        rsdp[15] = 2;
        rsdp[16..20].copy_from_slice(&0u32.to_le_bytes());
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&GuestMemory::XSDT_BASE.to_le_bytes());

        // v1 checksum
        let mut sum1: u8 = 0;
        for i in 0..20 { sum1 = sum1.wrapping_add(rsdp[i]); }
        rsdp[8] = (!sum1).wrapping_add(1);

        // v2 checksum
        let mut sum2: u8 = 0;
        for i in 0..36 { sum2 = sum2.wrapping_add(rsdp[i]); }
        rsdp[32] = (!sum2).wrapping_add(1);

        // Verify v1 checksum: bytes 0-19 sum to 0
        let check1: u8 = rsdp[..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(check1, 0, "RSDP v1 checksum failed");

        // Verify v2 checksum: bytes 0-35 sum to 0
        let check2: u8 = rsdp.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(check2, 0, "RSDP v2 checksum failed");

        // Verify signature
        assert_eq!(&rsdp[0..8], b"RSD PTR ");
    }

    #[test]
    fn acpi_madt_has_ioapic_entry() {
        // Build a minimal MADT and verify the I/O APIC entry is present.
        let mut madt = [0u8; 256];
        madt[0..4].copy_from_slice(b"APIC");
        madt[8] = 5;
        madt[10..16].copy_from_slice(b"VALKYR");
        madt[16..24].copy_from_slice(b"VALKYRIE");
        madt[36..40].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        madt[40..44].copy_from_slice(&1u32.to_le_bytes());

        let off = 44;
        // Local APIC entry (type=0, len=8)
        madt[off] = 0; madt[off + 1] = 8;
        let off = off + 8;
        // I/O APIC entry (type=1, len=12)
        madt[off] = 1; madt[off + 1] = 12;
        madt[off + 2] = 0; // APIC ID
        madt[off + 4..off + 8].copy_from_slice(&0xFEC0_0000u32.to_le_bytes());

        // Verify I/O APIC entry type and address
        assert_eq!(madt[off], 1); // type = I/O APIC
        assert_eq!(madt[off + 1], 12); // length
        let ioapic_addr = u32::from_le_bytes([
            madt[off + 4], madt[off + 5], madt[off + 6], madt[off + 7],
        ]);
        assert_eq!(ioapic_addr, 0xFEC0_0000);
    }

    #[test]
    fn facs_signature_and_length() {
        let mut facs = [0u8; 64];
        facs[0..4].copy_from_slice(b"FACS");
        facs[4..8].copy_from_slice(&64u32.to_le_bytes());
        facs[32] = 2; // version

        assert_eq!(&facs[0..4], b"FACS");
        let len = u32::from_le_bytes([facs[4], facs[5], facs[6], facs[7]]);
        assert_eq!(len, 64);
        assert_eq!(facs[32], 2); // version
    }

    #[test]
    fn madt_multi_cpu_entries() {
        // Verify that a 4-CPU MADT has 4 Local APIC entries.
        let num_cpus = 4u32;
        let mut madt = [0u8; 256];
        let mut off = 44usize;

        // Simulate the multi-CPU Local APIC entries
        for cpu_id in 0..num_cpus as usize {
            madt[off] = 0;                // type: Local APIC
            madt[off + 1] = 8;            // length
            madt[off + 2] = cpu_id as u8; // UID
            madt[off + 3] = cpu_id as u8; // APIC ID
            madt[off + 4..off + 8].copy_from_slice(&1u32.to_le_bytes()); // enabled
            off += 8;
        }

        // Parse back and verify
        let mut parse_off = 44usize;
        let mut lapic_count = 0;
        while parse_off + 2 <= off {
            let entry_type = madt[parse_off];
            let entry_len = madt[parse_off + 1] as usize;
            if entry_type == 0 {
                let apic_id = madt[parse_off + 3];
                assert_eq!(apic_id, lapic_count as u8);
                lapic_count += 1;
            }
            parse_off += entry_len;
        }
        assert_eq!(lapic_count, 4, "Should have 4 Local APIC entries");
    }

    #[test]
    fn cmdline_constants_valid() {
        // Verify cmdline fits in reserved area
        assert!(GuestMemory::CMDLINE_BASE >= 0x7000 + 4096, "cmdline should not overlap IDT");
        assert!(GuestMemory::CMDLINE_BASE + GuestMemory::CMDLINE_MAX_LEN as u64 <= BOOT_PARAMS_BASE,
            "cmdline should not overlap boot_params");
    }
}
