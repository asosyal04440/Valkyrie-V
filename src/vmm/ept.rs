#![allow(clippy::new_without_default)]
#![allow(clippy::missing_safety_doc)]

use crate::vmm::HvError;
use core::sync::atomic::{AtomicUsize, Ordering};

const EPT_READ: u64 = 1;
const EPT_WRITE: u64 = 1 << 1;
const EPT_EXEC: u64 = 1 << 2;
const EPT_LARGE: u64 = 1 << 7;
const EPT_ACCESSED: u64 = 1 << 8;
const EPT_DIRTY: u64 = 1 << 9;
const EPT_MEMTYPE_WB: u64 = 6;
const EPT_RWX: u64 = EPT_READ | EPT_WRITE | EPT_EXEC;

/// Enable dirty flag tracking in EPTP (bit 6).
const EPTP_AD_ENABLE: u64 = 1 << 6;

// ── Dynamic EPT Page Table Pool ──────────────────────────────────────────────
// 256 pages × 4 KiB = 1 MiB BSS.  Enough for 16 GiB of 4K-mapped guest RAM
// (1 PML4 + up to 4 PDPTs + up to 2048 PDs + remaining PTs).
// A lock-free bump allocator hands out pages; they are never freed (EPT tables
// live for the lifetime of the VM).

/// Number of pages in the global pool.
pub const EPT_POOL_SIZE: usize = 256;

#[repr(align(4096))]
pub struct EptTable {
    entries: [u64; 512],
}

impl EptTable {
    pub const fn new() -> Self {
        Self { entries: [0; 512] }
    }
}

/// Global pool of 4 KiB-aligned EPT pages.
static mut EPT_POOL: [EptTable; EPT_POOL_SIZE] = [const { EptTable::new() }; EPT_POOL_SIZE];
/// Bump-allocator cursor — next free index into `EPT_POOL`.
static EPT_POOL_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Allocate one zeroed `EptTable` from the global pool.
/// Returns a raw pointer to the page, or `HvError::LogicalFault` if exhausted.
fn pool_alloc() -> Result<*mut EptTable, HvError> {
    let idx = EPT_POOL_NEXT.fetch_add(1, Ordering::SeqCst);
    if idx >= EPT_POOL_SIZE {
        // Roll back so repeated calls don't silently overflow the counter.
        EPT_POOL_NEXT.store(EPT_POOL_SIZE, Ordering::SeqCst);
        return Err(HvError::LogicalFault);
    }
    Ok(unsafe { &mut EPT_POOL[idx] as *mut EptTable })
}

/// Reset the pool allocator (test-only — avoids leaking across tests).
#[cfg(test)]
pub fn pool_reset() {
    EPT_POOL_NEXT.store(0, Ordering::SeqCst);
    // Zero all pages so state doesn't leak between tests.
    for i in 0..EPT_POOL_SIZE {
        unsafe {
            EPT_POOL[i].entries = [0; 512];
        }
    }
}

// ── Ept struct ───────────────────────────────────────────────────────────────
// Owns only the PML4 (root) page index into the pool.  All intermediate tables
// (PDPT, PD, PT) are allocated on demand from the same pool.

pub struct Ept {
    /// Index of the PML4 page within `EPT_POOL`.
    pml4_idx: usize,
    violation_count: u64,
    window_start: u64,
    window_count: u32,
}

impl Ept {
    /// Create a new EPT with a fresh PML4 from the pool.
    /// Panics (in debug) if the pool is exhausted — should never happen at
    /// init time when only a handful of VMs are created.
    pub const fn new() -> Self {
        // `const fn` cannot call `pool_alloc`, so we use a sentinel.
        // The real PML4 is lazily allocated on first use via `ensure_pml4`.
        Self {
            pml4_idx: usize::MAX,
            violation_count: 0,
            window_start: 0,
            window_count: 0,
        }
    }

    /// Ensure the PML4 page is allocated.  Returns a mutable reference.
    #[inline]
    fn ensure_pml4(&mut self) -> Result<&mut EptTable, HvError> {
        if self.pml4_idx == usize::MAX {
            let ptr = pool_alloc()?;
            // Compute pool index from pointer.
            let base = unsafe { &EPT_POOL[0] as *const EptTable as usize };
            self.pml4_idx = (ptr as usize - base) / core::mem::size_of::<EptTable>();
        }
        Ok(unsafe { &mut EPT_POOL[self.pml4_idx] })
    }

    /// Get a reference to the PML4 page (must already be allocated).
    #[inline]
    fn pml4(&self) -> &EptTable {
        if self.pml4_idx == usize::MAX {
            // Fallback: return zeroed page (safe — reads will see no mappings).
            unsafe { &EPT_POOL[0] }
        } else {
            unsafe { &EPT_POOL[self.pml4_idx] }
        }
    }

    pub fn eptp(&self) -> u64 {
        let pml4_addr = self.pml4() as *const EptTable as u64;
        let page_walk = 3u64 << 3; // 4-level walk (3 = bits 5:3)
        EPT_MEMTYPE_WB | page_walk | EPTP_AD_ENABLE
            | (pml4_addr & 0xFFFF_FFFF_FFFF_F000)
    }

    // ── Helper: get-or-allocate a child table from a parent entry ────────────
    // If `parent[idx]` already points to a table, return it.
    // Otherwise allocate a fresh page, wire it in with RWX, and return it.
    #[inline]
    fn get_or_alloc(parent: &mut EptTable, idx: usize) -> Result<&'static mut EptTable, HvError> {
        let entry = parent.entries[idx];
        if entry & EPT_RWX != 0 && entry & EPT_LARGE == 0 {
            // Already points to a sub-table — extract address.
            let addr = (entry & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable;
            return Ok(unsafe { &mut *addr });
        }
        // Allocate a new table.
        let child = pool_alloc()?;
        parent.entries[idx] = (child as u64) | EPT_RWX;
        Ok(unsafe { &mut *child })
    }

    pub fn map_1g(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0x3FFF_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        pdpt.entries[pdpt_idx] = (hpa & 0xFFFF_FFFF_C000_0000)
            | EPT_RWX
            | EPT_LARGE
            | (EPT_MEMTYPE_WB << 3);
        Ok(())
    }

    pub fn map_2m(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0x1F_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        pd.entries[pd_idx] = (hpa & 0xFFFF_FFFF_FFE0_0000)
            | EPT_RWX
            | EPT_LARGE
            | (EPT_MEMTYPE_WB << 3);
        Ok(())
    }

    pub fn map_4k(&mut self, gpa: u64, hpa: u64) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pt = Self::get_or_alloc(pd, pd_idx)?;
        pt.entries[pt_idx] =
            (hpa & 0xFFFF_FFFF_FFFF_F000) | EPT_RWX | (EPT_MEMTYPE_WB << 3)
            | EPT_ACCESSED | EPT_DIRTY;
        Ok(())
    }

    pub fn map_range_huge(&mut self, base: u64, size: u64) -> Result<(), HvError> {
        let mut offset = 0u64;
        while offset < size {
            let gpa = base.wrapping_add(offset);
            let remaining = size - offset;
            if gpa & 0x3FFF_FFFF == 0 && remaining >= 0x4000_0000 {
                self.map_1g(gpa, gpa)?;
                offset = offset.wrapping_add(0x4000_0000);
                continue;
            }
            if gpa & 0x1F_FFFF == 0 && remaining >= 0x20_0000 {
                self.map_2m(gpa, gpa)?;
                offset = offset.wrapping_add(0x20_0000);
                continue;
            }
            self.map_4k(gpa, gpa)?;
            offset = offset.wrapping_add(0x1000);
        }
        Ok(())
    }

    // ── Dirty page tracking (EPT A/D bits) ──────────────────────────────────

    /// Scan all 4K leaf EPT entries and collect GPAs that have the dirty
    /// bit (bit 9) set.  Each found entry has its dirty bit atomically
    /// cleared so that subsequent scans only report newly dirtied pages.
    ///
    /// `out`: caller-provided buffer; returns the number of GPAs written.
    ///
    /// This walks the full 4-level table tree.  For huge pages (1G/2M) the
    /// dirty bit on the leaf is checked but the GPA is reported as the base
    /// of the huge page.
    pub fn scan_dirty_pages(&mut self, out: &mut [u64]) -> usize {
        if self.pml4_idx == usize::MAX {
            return 0;
        }
        let pml4 = unsafe { &mut EPT_POOL[self.pml4_idx] };
        let mut count = 0usize;

        for pml4_i in 0..512 {
            let pml4e = pml4.entries[pml4_i];
            if pml4e & EPT_RWX == 0 { continue; }
            let pdpt = unsafe { &mut *((pml4e & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };

            for pdpt_i in 0..512 {
                let pdpte = pdpt.entries[pdpt_i];
                if pdpte & EPT_RWX == 0 { continue; }
                if pdpte & EPT_LARGE != 0 {
                    // 1 GiB huge page
                    if pdpte & EPT_DIRTY != 0 {
                        pdpt.entries[pdpt_i] = pdpte & !EPT_DIRTY;
                        let gpa = ((pml4_i as u64) << 39) | ((pdpt_i as u64) << 30);
                        if count < out.len() { out[count] = gpa; count += 1; }
                    }
                    continue;
                }
                let pd = unsafe { &mut *((pdpte & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };

                for pd_i in 0..512 {
                    let pde = pd.entries[pd_i];
                    if pde & EPT_RWX == 0 { continue; }
                    if pde & EPT_LARGE != 0 {
                        // 2 MiB large page
                        if pde & EPT_DIRTY != 0 {
                            pd.entries[pd_i] = pde & !EPT_DIRTY;
                            let gpa = ((pml4_i as u64) << 39)
                                | ((pdpt_i as u64) << 30)
                                | ((pd_i as u64) << 21);
                            if count < out.len() { out[count] = gpa; count += 1; }
                        }
                        continue;
                    }
                    let pt = unsafe { &mut *((pde & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };

                    for pt_i in 0..512 {
                        let pte = pt.entries[pt_i];
                        if pte & EPT_RWX == 0 { continue; }
                        if pte & EPT_DIRTY != 0 {
                            pt.entries[pt_i] = pte & !EPT_DIRTY;
                            let gpa = ((pml4_i as u64) << 39)
                                | ((pdpt_i as u64) << 30)
                                | ((pd_i as u64) << 21)
                                | ((pt_i as u64) << 12);
                            if count < out.len() { out[count] = gpa; count += 1; }
                        }
                    }
                }
            }
        }
        count
    }

    pub fn throttle(&mut self, now: u64) -> bool {
        const WINDOW: u64 = 100_000;
        const LIMIT: u32 = 64;
        self.violation_count = self.violation_count.wrapping_add(1);
        if now.wrapping_sub(self.window_start) > WINDOW {
            self.window_start = now;
            self.window_count = 0;
        }
        self.window_count = self.window_count.wrapping_add(1);
        self.window_count > LIMIT
    }

    // ── Per-page permission control ─────────────────────────────────────────

    /// Map a 4 KiB page with explicit RWX permission bits.
    ///
    /// `perms` should be a combination of `EPT_READ`, `EPT_WRITE`, `EPT_EXEC`.
    /// If `perms` is 0 the entry is effectively unmapped (no access).
    pub fn map_4k_with_perms(
        &mut self,
        gpa: u64,
        hpa: u64,
        perms: u64,
    ) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pt = Self::get_or_alloc(pd, pd_idx)?;
        pt.entries[pt_idx] =
            (hpa & 0xFFFF_FFFF_FFFF_F000)
            | (perms & EPT_RWX)
            | (EPT_MEMTYPE_WB << 3)
            | EPT_ACCESSED | EPT_DIRTY;
        Ok(())
    }

    /// Map a 4 KiB MMIO region with UC (uncacheable) memory type.
    ///
    /// MMIO ranges must be mapped UC to prevent speculative reads and to
    /// match the behaviour expected by device drivers.
    pub fn map_mmio(&mut self, gpa: u64, hpa: u64, perms: u64) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx   = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx   = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd   = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pt   = Self::get_or_alloc(pd, pd_idx)?;
        // Memory type 0 = UC (uncacheable)
        pt.entries[pt_idx] =
            (hpa & 0xFFFF_FFFF_FFFF_F000)
            | (perms & EPT_RWX)
            | EPT_ACCESSED;
        Ok(())
    }

    /// Unmap a 4 KiB page by clearing its PTE to zero.
    ///
    /// Returns `Ok(())` if the PTE was found and cleared, or
    /// `Err(LogicalFault)` if any intermediate table is missing (page was
    /// never mapped).
    pub fn unmap_4k(&mut self, gpa: u64) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx   = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx   = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.pml4();
        let pml4e = pml4.entries[pml4_idx];
        if pml4e & EPT_RWX == 0 { return Err(HvError::LogicalFault); }
        let pdpt = unsafe { &mut *((pml4e & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        let pdpte = pdpt.entries[pdpt_idx];
        if pdpte & EPT_RWX == 0 || pdpte & EPT_LARGE != 0 {
            return Err(HvError::LogicalFault);
        }
        let pd = unsafe { &mut *((pdpte & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        let pde = pd.entries[pd_idx];
        if pde & EPT_RWX == 0 || pde & EPT_LARGE != 0 {
            return Err(HvError::LogicalFault);
        }
        let pt = unsafe { &mut *((pde & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        pt.entries[pt_idx] = 0;
        Ok(())
    }

    /// Update the permission bits on an existing 4 KiB mapping in-place.
    ///
    /// `perms` should be a combination of `EPT_READ`, `EPT_WRITE`, `EPT_EXEC`.
    /// Returns `Err(LogicalFault)` if the page is not mapped.
    pub fn set_permissions(&mut self, gpa: u64, perms: u64) -> Result<(), HvError> {
        if gpa & 0xFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa >> 30) & 0x1FF) as usize;
        let pd_idx   = ((gpa >> 21) & 0x1FF) as usize;
        let pt_idx   = ((gpa >> 12) & 0x1FF) as usize;

        let pml4 = self.pml4();
        let pml4e = pml4.entries[pml4_idx];
        if pml4e & EPT_RWX == 0 { return Err(HvError::LogicalFault); }
        let pdpt = unsafe { &mut *((pml4e & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        let pdpte = pdpt.entries[pdpt_idx];
        if pdpte & EPT_RWX == 0 || pdpte & EPT_LARGE != 0 {
            return Err(HvError::LogicalFault);
        }
        let pd = unsafe { &mut *((pdpte & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        let pde = pd.entries[pd_idx];
        if pde & EPT_RWX == 0 || pde & EPT_LARGE != 0 {
            return Err(HvError::LogicalFault);
        }
        let pt = unsafe { &mut *((pde & 0xFFFF_FFFF_FFFF_F000) as *mut EptTable) };
        let old = pt.entries[pt_idx];
        if old & EPT_RWX == 0 {
            return Err(HvError::LogicalFault);
        }
        // Preserve HPA + memtype, replace permission bits.
        pt.entries[pt_idx] = (old & !EPT_RWX) | (perms & EPT_RWX);
        Ok(())
    }

    /// Split a 2 MiB large page mapping into 512 individual 4 KiB mappings,
    /// each inheriting the same contiguous HPA and permissions from the
    /// original large page.
    ///
    /// This is needed when we want to apply per-4K permissions within a
    /// region that was originally mapped as a 2 MiB huge page.
    pub fn split_2m_to_4k(&mut self, gpa_2m: u64) -> Result<(), HvError> {
        if gpa_2m & 0x1F_FFFF != 0 {
            return Err(HvError::LogicalFault);
        }
        let pml4_idx = ((gpa_2m >> 39) & 0x1FF) as usize;
        let pdpt_idx = ((gpa_2m >> 30) & 0x1FF) as usize;
        let pd_idx   = ((gpa_2m >> 21) & 0x1FF) as usize;

        let pml4 = self.ensure_pml4()?;
        let pdpt = Self::get_or_alloc(pml4, pml4_idx)?;
        let pd   = Self::get_or_alloc(pdpt, pdpt_idx)?;
        let pde  = pd.entries[pd_idx];

        // Must be a 2M large page.
        if pde & EPT_LARGE == 0 || pde & EPT_RWX == 0 {
            return Err(HvError::LogicalFault);
        }

        let base_hpa = pde & 0xFFFF_FFFF_FFE0_0000;
        let perms = pde & EPT_RWX;
        let memtype_bits = pde & (0x7 << 3); // memory type in bits [5:3]

        // Allocate a new PT page.
        let pt = pool_alloc()?;
        let pt_ref = unsafe { &mut *pt };

        // Fill 512 entries, each mapping a contiguous 4K page.
        for i in 0..512 {
            let hpa = base_hpa + (i as u64) * 0x1000;
            pt_ref.entries[i] = hpa | perms | memtype_bits | EPT_ACCESSED;
        }

        // Replace the PD entry: point to the new PT (no LARGE bit).
        pd.entries[pd_idx] = (pt as u64) | EPT_RWX;
        Ok(())
    }
}

pub unsafe fn invept_single(eptp: u64) -> Result<(), HvError> {
    let mut status: u8;
    let descriptor = [eptp, 0];
    core::arch::asm!(
        "invept {ty}, [{desc}]",
        "setna {status}",
        desc = in(reg) &descriptor,
        ty = in(reg) 1u64,
        status = out(reg_byte) status,
        options(nostack, preserves_flags)
    );
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

/// Invalidate all EPT-derived translations (type 2 = global).
pub unsafe fn invept_global() -> Result<(), HvError> {
    let mut status: u8;
    let descriptor = [0u64, 0];
    core::arch::asm!(
        "invept {ty}, [{desc}]",
        "setna {status}",
        desc = in(reg) &descriptor,
        ty = in(reg) 2u64,
        status = out(reg_byte) status,
        options(nostack, preserves_flags)
    );
    if status == 0 {
        Ok(())
    } else {
        Err(HvError::HardwareFault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ept_dirty_tracking_4k() {
        pool_reset();
        let mut ept = Ept::new();
        // Map two 4K pages
        ept.map_4k(0x1000, 0x1000).unwrap();
        ept.map_4k(0x2000, 0x2000).unwrap();

        // Both should have dirty bit set (set during map_4k)
        let mut buf = [0u64; 16];
        let n = ept.scan_dirty_pages(&mut buf);
        assert_eq!(n, 2);
        assert!(buf[..n].contains(&0x1000));
        assert!(buf[..n].contains(&0x2000));

        // Second scan: dirty bits were cleared, so nothing should show up
        let n2 = ept.scan_dirty_pages(&mut buf);
        assert_eq!(n2, 0);
    }

    #[test]
    fn eptp_has_ad_enable_bit() {
        pool_reset();
        let mut ept = Ept::new();
        let _ = ept.ensure_pml4(); // force allocation
        let eptp = ept.eptp();
        // Bit 6 = A/D enable
        assert_ne!(eptp & EPTP_AD_ENABLE, 0, "EPTP should have A/D enable bit set");
    }

    #[test]
    fn map_4k_with_perms_read_only() {
        pool_reset();
        let mut ept = Ept::new();
        ept.map_4k_with_perms(0x3000, 0x3000, EPT_READ).unwrap();

        // Walk tables to verify the PTE has only READ bit set.
        let pml4 = ept.pml4();
        let pdpt_addr = pml4.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pdpt = unsafe { &*(pdpt_addr as *const EptTable) };
        let pd_addr = pdpt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pd = unsafe { &*(pd_addr as *const EptTable) };
        let pt_addr = pd.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pt = unsafe { &*(pt_addr as *const EptTable) };
        let pte = pt.entries[3];
        assert_ne!(pte & EPT_READ, 0, "READ bit should be set");
        assert_eq!(pte & EPT_WRITE, 0, "WRITE bit should NOT be set");
        assert_eq!(pte & EPT_EXEC, 0, "EXEC bit should NOT be set");
    }

    #[test]
    fn unmap_4k_removes_mapping() {
        pool_reset();
        let mut ept = Ept::new();
        ept.map_4k(0x4000, 0x4000).unwrap();
        ept.unmap_4k(0x4000).unwrap();

        // Walk to the PT and verify the entry is now zero.
        let pml4 = ept.pml4();
        let pdpt_addr = pml4.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pdpt = unsafe { &*(pdpt_addr as *const EptTable) };
        let pd_addr = pdpt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pd = unsafe { &*(pd_addr as *const EptTable) };
        let pt_addr = pd.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pt = unsafe { &*(pt_addr as *const EptTable) };
        assert_eq!(pt.entries[4], 0, "Unmapped page should have zero PTE");
    }

    #[test]
    fn set_permissions_changes_rwx() {
        pool_reset();
        let mut ept = Ept::new();
        ept.map_4k(0x5000, 0x5000).unwrap();
        // Should start as RWX
        ept.set_permissions(0x5000, EPT_READ | EPT_EXEC).unwrap();

        let pml4 = ept.pml4();
        let pdpt_addr = pml4.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pdpt = unsafe { &*(pdpt_addr as *const EptTable) };
        let pd_addr = pdpt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pd = unsafe { &*(pd_addr as *const EptTable) };
        let pt_addr = pd.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pt = unsafe { &*(pt_addr as *const EptTable) };
        let pte = pt.entries[5];
        assert_ne!(pte & EPT_READ, 0);
        assert_eq!(pte & EPT_WRITE, 0, "WRITE should be cleared");
        assert_ne!(pte & EPT_EXEC, 0);
    }

    #[test]
    fn split_2m_to_4k_preserves_mappings() {
        pool_reset();
        let mut ept = Ept::new();
        ept.map_2m(0x20_0000, 0x20_0000).unwrap();
        ept.split_2m_to_4k(0x20_0000).unwrap();

        // After split, the PD entry should no longer have LARGE bit.
        let pml4 = ept.pml4();
        let pdpt_addr = pml4.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pdpt = unsafe { &*(pdpt_addr as *const EptTable) };
        let pd_addr = pdpt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pd = unsafe { &*(pd_addr as *const EptTable) };
        let pde = pd.entries[1]; // index 1 for 0x200000
        assert_eq!(pde & EPT_LARGE, 0, "PDE should no longer be large after split");
        assert_ne!(pde & EPT_RWX, 0, "PDE should still be present");

        // Walk into the PT and check a few entries.
        let pt_addr = pde & 0xFFFF_FFFF_FFFF_F000;
        let pt = unsafe { &*(pt_addr as *const EptTable) };
        // Entry 0 should map 0x200000
        let hpa_0 = pt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        assert_eq!(hpa_0, 0x20_0000);
        // Entry 256 should map 0x300000
        let hpa_256 = pt.entries[256] & 0xFFFF_FFFF_FFFF_F000;
        assert_eq!(hpa_256, 0x30_0000);
    }

    #[test]
    fn map_mmio_uses_uc_memtype() {
        pool_reset();
        let mut ept = Ept::new();
        ept.map_mmio(0x6000, 0x6000, EPT_READ | EPT_WRITE).unwrap();

        let pml4 = ept.pml4();
        let pdpt_addr = pml4.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pdpt = unsafe { &*(pdpt_addr as *const EptTable) };
        let pd_addr = pdpt.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pd = unsafe { &*(pd_addr as *const EptTable) };
        let pt_addr = pd.entries[0] & 0xFFFF_FFFF_FFFF_F000;
        let pt = unsafe { &*(pt_addr as *const EptTable) };
        let pte = pt.entries[6];
        // UC memtype = 0, so bits [5:3] should be 0.
        assert_eq!(pte & (0x7 << 3), 0, "MMIO mapping should use UC memory type");
        assert_ne!(pte & EPT_READ, 0);
        assert_ne!(pte & EPT_WRITE, 0);
        assert_eq!(pte & EPT_EXEC, 0, "MMIO should not be executable");
    }
}
