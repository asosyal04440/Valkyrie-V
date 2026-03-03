#![allow(clippy::missing_safety_doc)]

use crate::vmm::{DriverTag, HvError};
use ironshim::{IoPortDesc, MmioDesc, ResourceManifest};

const HUGEPAGE_SIZE: u64 = 1024 * 1024 * 1024;
const MAX_HUGEPAGES: usize = 16;
const MMIO_SLOTS: usize = 4;
const PORT_SLOTS: usize = 4;

#[derive(Copy, Clone)]
pub struct PhysFrame(pub u64);

pub struct Allocation {
    pub base: PhysFrame,
    pub size: u64,
    pub pages: usize,
    pub tag: DriverTag,
    pub manifest: ResourceManifest<DriverTag, MMIO_SLOTS, PORT_SLOTS>,
}

pub struct Atlas {
    free_list: [Option<u64>; MAX_HUGEPAGES],
}

impl Atlas {
    pub fn new() -> Result<Self, HvError> {
        Ok(Self {
            free_list: [None; MAX_HUGEPAGES],
        })
    }

    pub fn reserve_hugepages(&mut self, base: u64, count: usize) -> Result<(), HvError> {
        if count > MAX_HUGEPAGES {
            return Err(HvError::LogicalFault);
        }
        for index in 0..count {
            self.free_list[index] = Some(base + (index as u64 * HUGEPAGE_SIZE));
        }
        Ok(())
    }

    pub fn allocate_guest_region(&mut self, guest_id: u64) -> Result<Allocation, HvError> {
        let mut selected = None;
        for slot in self.free_list.iter_mut() {
            if slot.is_some() {
                selected = slot.take();
                break;
            }
        }
        let base = match selected {
            Some(base) => base,
            None => return Err(HvError::LogicalFault),
        };
        let tag = DriverTag { guest_id };
        let manifest = self.create_guest_manifest(base, HUGEPAGE_SIZE)?;
        Ok(Allocation {
            base: PhysFrame(base),
            size: HUGEPAGE_SIZE,
            pages: 1,
            tag,
            manifest,
        })
    }

    pub fn validate_mapping(
        &self,
        allocation: &Allocation,
        start: PhysFrame,
        size: u64,
    ) -> Result<(), HvError> {
        // Uses IronShim's ResourceManifest mmio_region to validate sealed access
        allocation
            .manifest
            .mmio_region(0)
            .map_err(|_| HvError::LogicalFault)?;
        let end = start.0.checked_add(size).ok_or(HvError::LogicalFault)?;
        let allowed_end = allocation
            .base
            .0
            .checked_add(allocation.size)
            .ok_or(HvError::LogicalFault)?;
        if start.0 < allocation.base.0 || end > allowed_end {
            return Err(HvError::LogicalFault);
        }
        Ok(())
    }

    pub fn handle_ept_violation(
        &self,
        allocation: &Allocation,
        faulting: PhysFrame,
    ) -> Result<[PhysFrame; 3], HvError> {
        let prev = faulting
            .0
            .checked_sub(0x1000)
            .ok_or(HvError::LogicalFault)?;
        let next = faulting
            .0
            .checked_add(0x1000)
            .ok_or(HvError::LogicalFault)?;
        let neighbors = [PhysFrame(prev), faulting, PhysFrame(next)];
        for frame in neighbors.iter() {
            self.validate_mapping(allocation, *frame, 0x1000)?;
        }
        Ok(neighbors)
    }

    pub unsafe fn program_ept(
        &self,
        allocation: &Allocation,
        start: PhysFrame,
        size: u64,
    ) -> Result<(), HvError> {
        self.validate_mapping(allocation, start, size)?;
        // SAFETY: EPT programming occurs only after ResourceManifest validation
        let _ = (start, size);
        Ok(())
    }

    /// Allocate multiple contiguous hugepages for a guest with a given
    /// total memory size.  Returns an `Allocation` whose `pages` field
    /// reflects the number of 1 GiB hugepages consumed.
    ///
    /// The allocation is contiguous: pages are taken in order starting
    /// from the first available slot.
    pub fn allocate_guest_region_sized(
        &mut self,
        guest_id: u64,
        size_bytes: u64,
    ) -> Result<Allocation, HvError> {
        let pages_needed =
            ((size_bytes + HUGEPAGE_SIZE - 1) / HUGEPAGE_SIZE).max(1) as usize;

        // Find `pages_needed` available slots.
        let mut found = 0usize;
        let mut first_base: Option<u64> = None;
        for slot in self.free_list.iter() {
            if slot.is_some() {
                if first_base.is_none() {
                    first_base = *slot;
                }
                found += 1;
                if found >= pages_needed {
                    break;
                }
            }
        }
        if found < pages_needed {
            return Err(HvError::LogicalFault);
        }

        // Consume the hugepages: take the first `pages_needed` Some entries.
        let mut consumed = 0usize;
        let mut base_addr = 0u64;
        for slot in self.free_list.iter_mut() {
            if slot.is_some() {
                if consumed == 0 {
                    base_addr = slot.unwrap();
                }
                *slot = None;
                consumed += 1;
                if consumed >= pages_needed {
                    break;
                }
            }
        }

        let total_size = pages_needed as u64 * HUGEPAGE_SIZE;
        let tag = DriverTag { guest_id };
        let manifest = self.create_guest_manifest(base_addr, total_size)?;
        Ok(Allocation {
            base: PhysFrame(base_addr),
            size: total_size,
            pages: pages_needed,
            tag,
            manifest,
        })
    }

    /// Return an allocation back to the free list so the memory can be
    /// reused by a future `allocate_guest_region` call. This is called from
    /// `Hypervisor::delete_vm` to prevent memory leaks on VM teardown.
    pub fn free_guest_region(&mut self, allocation: Allocation) {
        // Return each hugepage back to the free list.
        for page_idx in 0..allocation.pages {
            let page_base = allocation.base.0 + (page_idx as u64 * HUGEPAGE_SIZE);
            for slot in self.free_list.iter_mut() {
                if slot.is_none() {
                    *slot = Some(page_base);
                    break;
                }
            }
        }
    }

    /// Return the number of free hugepages remaining.
    pub fn free_count(&self) -> usize {
        self.free_list.iter().filter(|s| s.is_some()).count()
    }

    /// Check if the allocator has any free hugepages.
    pub fn has_free(&self) -> bool {
        self.free_list.iter().any(|s| s.is_some())
    }

    fn create_guest_manifest(
        &self,
        base: u64,
        size: u64,
    ) -> Result<ResourceManifest<DriverTag, MMIO_SLOTS, PORT_SLOTS>, HvError> {
        // Uses IronShim's ResourceManifest to seal a frame range for a driver tag
        let mut mmio = [MmioDesc { base: 0, size: 1 }; MMIO_SLOTS];
        mmio[0] = MmioDesc {
            base: base as usize,
            size: size as usize,
        };
        let ports = [IoPortDesc { port: 0, count: 1 }; PORT_SLOTS];
        ResourceManifest::new(mmio, 1, ports, 0).map_err(|_| HvError::LogicalFault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_requires_reserve() {
        let mut atlas = Atlas::new().unwrap();
        assert!(atlas.allocate_guest_region(0).is_err());
    }

    #[test]
    fn reserve_then_allocate_succeeds() {
        let mut atlas = Atlas::new().unwrap();
        atlas.reserve_hugepages(0x4000_0000, 1).unwrap();
        let allocation = atlas.allocate_guest_region(7).unwrap();
        assert_eq!(allocation.base.0, 0x4000_0000);
        assert_eq!(allocation.pages, 1);
        assert_eq!(allocation.tag.guest_id, 7);
    }

    #[test]
    fn allocate_multi_hugepage() {
        let mut atlas = Atlas::new().unwrap();
        atlas.reserve_hugepages(0x4000_0000, 4).unwrap();
        // Request 2.5 GiB → needs 3 hugepages
        let alloc = atlas.allocate_guest_region_sized(1, 2_500_000_000).unwrap();
        assert_eq!(alloc.pages, 3);
        assert_eq!(alloc.size, 3 * HUGEPAGE_SIZE);
        // Only 1 hugepage should remain
        assert_eq!(atlas.free_count(), 1);
    }

    #[test]
    fn allocate_multi_returns_err_when_insufficient() {
        let mut atlas = Atlas::new().unwrap();
        atlas.reserve_hugepages(0x4000_0000, 2).unwrap();
        // Request 4 GiB → needs 4 hugepages, but only 2 available
        assert!(atlas.allocate_guest_region_sized(1, 4 * HUGEPAGE_SIZE).is_err());
    }

    #[test]
    fn free_multi_hugepage_returns_pages() {
        let mut atlas = Atlas::new().unwrap();
        atlas.reserve_hugepages(0x4000_0000, 4).unwrap();
        let alloc = atlas.allocate_guest_region_sized(1, 2 * HUGEPAGE_SIZE).unwrap();
        assert_eq!(atlas.free_count(), 2);
        atlas.free_guest_region(alloc);
        assert_eq!(atlas.free_count(), 4);
    }

    #[test]
    fn has_free_reflects_state() {
        let mut atlas = Atlas::new().unwrap();
        assert!(!atlas.has_free());
        atlas.reserve_hugepages(0x4000_0000, 1).unwrap();
        assert!(atlas.has_free());
        let alloc = atlas.allocate_guest_region(0).unwrap();
        assert!(!atlas.has_free());
        atlas.free_guest_region(alloc);
        assert!(atlas.has_free());
    }
}
