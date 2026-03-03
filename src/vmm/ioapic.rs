//! I/O APIC (Intel 82093AA) Emulation
//!
//! Provides interrupt routing for ISA IRQs (0-23) to guest LAPIC vectors.
//! The guest accesses the I/O APIC via two MMIO registers at 0xFEC00000:
//!   - IOREGSEL (0x00): selects the internal register to read/write
//!   - IOWIN   (0x10): data window for the selected register
//!
//! Internal registers:
//!   0x00: IOAPICID
//!   0x01: IOAPICVER (version + max redirection entries)
//!   0x02: IOAPICARB (arbitration ID)
//!   0x10-0x3F: Redirection Table (24 entries × 2 dwords each)
//!
//! Each redirection entry is 64 bits:
//!   [7:0]   = vector
//!   [10:8]  = delivery mode (000=Fixed, 001=LowPri, 010=SMI, 100=NMI, 101=INIT, 111=ExtINT)
//!   [11]    = dest mode (0=physical, 1=logical)
//!   [12]    = delivery status (read-only)
//!   [13]    = pin polarity (0=active-high, 1=active-low)
//!   [14]    = remote IRR (read-only)
//!   [15]    = trigger mode (0=edge, 1=level)
//!   [16]    = mask (1=masked)
//!   [63:56] = destination (APIC ID or logical dest)

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Base address of the I/O APIC in guest physical memory.
pub const IOAPIC_BASE: u64 = 0xFEC0_0000;
/// Size of the I/O APIC MMIO region (1 page).
pub const IOAPIC_SIZE: u64 = 0x1000;

/// Number of redirection entries (IRQ pins) — standard 82093AA has 24.
const MAX_REDIR_ENTRIES: usize = 24;

/// Default redirection entry value: masked, edge-triggered, fixed delivery,
/// physical destination, vector 0.
const DEFAULT_REDIR: u64 = 1 << 16; // masked

pub struct IoApic {
    /// IOREGSEL — currently selected internal register index.
    regsel: AtomicU32,
    /// I/O APIC ID (reported via register 0x00).
    id: AtomicU32,
    /// Redirection table: 24 entries, each 64 bits.
    redir: [AtomicU64; MAX_REDIR_ENTRIES],
}

unsafe impl Sync for IoApic {}

impl IoApic {
    pub const fn new() -> Self {
        const DEFAULT: AtomicU64 = AtomicU64::new(DEFAULT_REDIR);
        Self {
            regsel: AtomicU32::new(0),
            id: AtomicU32::new(0),
            redir: [DEFAULT; MAX_REDIR_ENTRIES],
        }
    }

    // ── MMIO interface ──────────────────────────────────────────────────────

    /// Handle an MMIO read from the I/O APIC region.
    /// `offset`: byte offset from IOAPIC_BASE (0x00 or 0x10).
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            // IOREGSEL
            0x00 => self.regsel.load(Ordering::Relaxed),
            // IOWIN — read the currently selected register
            0x10 => self.read_reg(self.regsel.load(Ordering::Relaxed)),
            _ => 0,
        }
    }

    /// Handle an MMIO write to the I/O APIC region.
    pub fn mmio_write(&self, offset: u64, value: u32) {
        match offset {
            // IOREGSEL — select internal register
            0x00 => { self.regsel.store(value, Ordering::Relaxed); }
            // IOWIN — write the currently selected register
            0x10 => { self.write_reg(self.regsel.load(Ordering::Relaxed), value); }
            _ => {}
        }
    }

    // ── Internal register access ────────────────────────────────────────────

    fn read_reg(&self, reg: u32) -> u32 {
        match reg {
            // IOAPICID
            0x00 => self.id.load(Ordering::Relaxed) << 24,
            // IOAPICVER: version 0x20 (82093AA), max entries = 23
            0x01 => 0x0017_0020, // [23:16] = max redir entry, [7:0] = version
            // IOAPICARB: arbitration ID (always 0 for single IOAPIC)
            0x02 => 0,
            // Redirection table: even registers = low 32 bits, odd = high 32 bits
            0x10..=0x3F => {
                let entry_idx = ((reg - 0x10) / 2) as usize;
                if entry_idx >= MAX_REDIR_ENTRIES {
                    return 0;
                }
                let val = self.redir[entry_idx].load(Ordering::Relaxed);
                if reg & 1 == 0 {
                    val as u32 // low 32 bits
                } else {
                    (val >> 32) as u32 // high 32 bits (destination)
                }
            }
            _ => 0,
        }
    }

    fn write_reg(&self, reg: u32, value: u32) {
        match reg {
            0x00 => { self.id.store((value >> 24) & 0xF, Ordering::Relaxed); }
            0x01 | 0x02 => {} // read-only
            0x10..=0x3F => {
                let entry_idx = ((reg - 0x10) / 2) as usize;
                if entry_idx >= MAX_REDIR_ENTRIES {
                    return;
                }
                let old = self.redir[entry_idx].load(Ordering::Relaxed);
                let new = if reg & 1 == 0 {
                    // Write low 32 bits, preserve high 32 bits.
                    // Mask off read-only bits (delivery status bit 12, remote IRR bit 14).
                    let writable = value & !((1 << 12) | (1 << 14));
                    (old & 0xFFFF_FFFF_0000_0000) | writable as u64
                } else {
                    // Write high 32 bits (destination), preserve low 32 bits.
                    (old & 0x0000_0000_FFFF_FFFF) | ((value as u64) << 32)
                };
                self.redir[entry_idx].store(new, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    // ── Interrupt delivery ──────────────────────────────────────────────────

    /// Check if the given IRQ pin has a pending unmasked interrupt.
    /// Returns `Some(vector)` if the entry is unmasked.
    pub fn route_irq(&self, irq: u8) -> Option<u8> {
        if irq as usize >= MAX_REDIR_ENTRIES {
            return None;
        }
        let entry = self.redir[irq as usize].load(Ordering::Relaxed);
        // Bit 16 = mask — if set, interrupt is masked.
        if entry & (1 << 16) != 0 {
            return None;
        }
        let vector = (entry & 0xFF) as u8;
        if vector < 0x10 {
            return None; // vectors 0-15 are reserved
        }
        Some(vector)
    }

    /// Get the full redirection entry for diagnostics / snapshot.
    pub fn get_redir_entry(&self, irq: u8) -> u64 {
        if (irq as usize) < MAX_REDIR_ENTRIES {
            self.redir[irq as usize].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Set a redirection entry programmatically (used during ACPI boot).
    pub fn set_redir_entry(&self, irq: u8, entry: u64) {
        if (irq as usize) < MAX_REDIR_ENTRIES {
            self.redir[irq as usize].store(entry, Ordering::Relaxed);
        }
    }
}

static IOAPIC: IoApic = IoApic::new();

/// Global accessor for the I/O APIC instance.
pub fn ioapic() -> &'static IoApic {
    &IOAPIC
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioapic_version_register() {
        let apic = IoApic::new();
        apic.mmio_write(0x00, 0x01); // select IOAPICVER
        let ver = apic.mmio_read(0x10);
        assert_eq!(ver & 0xFF, 0x20); // version 0x20
        assert_eq!((ver >> 16) & 0xFF, 23); // 24 entries (max entry = 23)
    }

    #[test]
    fn ioapic_redir_read_write() {
        let apic = IoApic::new();
        // Write low 32 bits of redir entry 0 (register 0x10)
        apic.mmio_write(0x00, 0x10); // select redir[0] low
        apic.mmio_write(0x10, 0x0000_0020); // vector=0x20, unmasked
        // Write high 32 bits of redir entry 0 (register 0x11)
        apic.mmio_write(0x00, 0x11);
        apic.mmio_write(0x10, 0x00); // dest APIC ID = 0

        // Verify: should route IRQ0 → vector 0x20
        let vec = apic.route_irq(0);
        assert_eq!(vec, Some(0x20));

        // Verify masked entry returns None
        apic.mmio_write(0x00, 0x12); // redir[1] low
        // Default is masked (0x10000)
        assert!(apic.route_irq(1).is_none());
    }
}
