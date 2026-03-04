//! VirtIO split virtqueue descriptor-chain walker.
//!
//! Implements the split virtqueue layout from the VirtIO 1.0 specification
//! (§2.6).  The three ring components live in guest RAM at addresses
//! configured by the driver:
//!
//!   Descriptor Table :  desc_addr   — array of VirtqDesc
//!   Available Ring   :  avail_addr  — ring of descriptor head indices
//!   Used Ring        :  used_addr   — ring of (index, length) pairs
//!
//! This module provides:
//!   - `VirtqDesc`: in-memory descriptor layout
//!   - `DescChainIter`: walks a descriptor chain yielding (addr, len, write)
//!   - `SplitVirtqueue`: full virtqueue state with avail/used ring management

#![allow(dead_code)]

/// VirtIO descriptor flags.
pub const VRING_DESC_F_NEXT: u16 = 1;
pub const VRING_DESC_F_WRITE: u16 = 2;
pub const VRING_DESC_F_INDIRECT: u16 = 4;

/// Maximum descriptors to walk in a single chain (prevents infinite loops).
const MAX_CHAIN_LEN: usize = 256;

/// A single virtqueue descriptor (16 bytes, matches VirtIO spec).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtqDesc {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Descriptor flags (NEXT, WRITE, INDIRECT).
    pub flags: u16,
    /// Index of the next descriptor in the chain (if NEXT flag set).
    pub next: u16,
}

impl VirtqDesc {
    pub const fn zeroed() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }

    /// Read a descriptor from guest RAM.
    ///
    /// `desc_table_gpa`: GPA of the descriptor table base.
    /// `index`: descriptor index within the table.
    /// `guest_base`: host virtual address corresponding to GPA 0.
    pub fn read_from_guest(desc_table_gpa: u64, index: u16, guest_base: u64) -> Self {
        let offset = desc_table_gpa + (index as u64) * 16;
        let ptr = (guest_base + offset) as *const Self;
        unsafe { core::ptr::read_volatile(ptr) }
    }

    pub fn has_next(&self) -> bool {
        self.flags & VRING_DESC_F_NEXT != 0
    }

    pub fn is_write(&self) -> bool {
        self.flags & VRING_DESC_F_WRITE != 0
    }

    pub fn is_indirect(&self) -> bool {
        self.flags & VRING_DESC_F_INDIRECT != 0
    }
}

/// A single element yielded while walking a descriptor chain.
#[derive(Debug, Clone, Copy)]
pub struct DescChainElem {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// True if this buffer is to be written by the device (WRITE flag set).
    pub write: bool,
}

/// Iterator that walks a descriptor chain starting from a head index.
pub struct DescChainIter {
    desc_table_gpa: u64,
    guest_base: u64,
    queue_size: u16,
    current: Option<u16>,
    count: usize,
    /// If Some, we're walking a nested indirect descriptor table: (table_gpa, table_size).
    indirect_table: Option<(u64, u16)>,
    /// Current index within the indirect table.
    indirect_idx: u16,
}

impl DescChainIter {
    /// Create a new chain iterator.
    ///
    /// `head`: starting descriptor index (from the avail ring).
    /// `desc_table_gpa`: GPA of the descriptor table.
    /// `guest_base`: host address of GPA 0.
    /// `queue_size`: number of descriptors in the table.
    pub fn new(head: u16, desc_table_gpa: u64, guest_base: u64, queue_size: u16) -> Self {
        Self {
            desc_table_gpa,
            guest_base,
            queue_size,
            current: Some(head),
            count: 0,
            indirect_table: None,
            indirect_idx: 0,
        }
    }

    /// Walk the chain, collecting up to `max` elements into an array.
    /// Returns the number of elements written.
    pub fn collect_into(&mut self, out: &mut [DescChainElem]) -> usize {
        let mut n = 0;
        for elem in self.by_ref() {
            if n >= out.len() {
                break;
            }
            out[n] = elem;
            n += 1;
        }
        n
    }

    /// Count remaining elements in the chain (consumes the iterator).
    pub fn count_remaining(self) -> usize {
        self.count()
    }

    /// Check if the iterator has yielded any elements yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0 && self.current.is_none()
    }

    /// Get the number of elements yielded so far.
    pub fn yielded_count(&self) -> usize {
        self.count
    }
}

impl Iterator for DescChainIter {
    type Item = DescChainElem;

    fn next(&mut self) -> Option<Self::Item> {
        // If we're walking an indirect table, read from there.
        if let Some((indirect_gpa, indirect_size)) = self.indirect_table {
            if self.indirect_idx >= indirect_size {
                // Finished indirect table, return to main chain.
                self.indirect_table = None;
                return self.next();
            }
            if self.count >= MAX_CHAIN_LEN {
                self.current = None;
                self.indirect_table = None;
                return None;
            }

            let desc = VirtqDesc::read_from_guest(
                indirect_gpa,
                self.indirect_idx,
                self.guest_base,
            );
            self.count += 1;

            if desc.has_next() && desc.next < indirect_size {
                self.indirect_idx = desc.next;
            } else {
                // End of indirect chain.
                self.indirect_table = None;
            }

            return Some(DescChainElem {
                addr: desc.addr,
                len: desc.len,
                write: desc.is_write(),
            });
        }

        // Normal (non-indirect) path.
        let idx = self.current?;
        if self.count >= MAX_CHAIN_LEN {
            self.current = None;
            return None;
        }
        if idx >= self.queue_size {
            self.current = None;
            return None;
        }

        let desc = VirtqDesc::read_from_guest(
            self.desc_table_gpa,
            idx,
            self.guest_base,
        );
        self.count += 1;

        // Check if this descriptor is an indirect descriptor.
        if desc.is_indirect() {
            // desc.addr is the GPA of the nested descriptor table.
            // desc.len is the table size in bytes (num_descriptors * 16).
            let indirect_size = (desc.len / 16) as u16;
            if indirect_size > 0 {
                self.indirect_table = Some((desc.addr, indirect_size));
                self.indirect_idx = 0;
                // Advance main chain.
                if desc.has_next() && desc.next < self.queue_size {
                    self.current = Some(desc.next);
                } else {
                    self.current = None;
                }
                // Recursively yield from indirect table.
                return self.next();
            }
        }

        if desc.has_next() && desc.next < self.queue_size {
            self.current = Some(desc.next);
        } else {
            self.current = None;
        }

        Some(DescChainElem {
            addr: desc.addr,
            len: desc.len,
            write: desc.is_write(),
        })
    }
}

/// Split virtqueue state.
///
/// Manages the avail and used rings for one virtqueue.
pub struct SplitVirtqueue {
    /// Number of descriptors in the queue.
    pub queue_size: u16,
    /// GPA of the descriptor table.
    pub desc_table: u64,
    /// GPA of the available ring.
    pub avail_ring: u64,
    /// GPA of the used ring.
    pub used_ring: u64,
    /// Host address corresponding to GPA 0 (for pointer arithmetic).
    pub guest_base: u64,
    /// Last avail index consumed by the device.
    pub last_avail_idx: u16,
}

impl SplitVirtqueue {
    pub const fn new() -> Self {
        Self {
            queue_size: 0,
            desc_table: 0,
            avail_ring: 0,
            used_ring: 0,
            guest_base: 0,
            last_avail_idx: 0,
        }
    }

    /// Initialise the virtqueue with addresses from the MMIO transport.
    pub fn setup(
        &mut self,
        size: u16,
        desc: u64,
        avail: u64,
        used: u64,
        guest_base: u64,
    ) {
        self.queue_size = size;
        self.desc_table = desc;
        self.avail_ring = avail;
        self.used_ring = used;
        self.guest_base = guest_base;
        self.last_avail_idx = 0;
    }

    /// Read the avail ring's `idx` field (the next index the driver will write).
    fn avail_idx(&self) -> u16 {
        // struct virtq_avail { u16 flags; u16 idx; u16 ring[]; }
        let ptr = (self.guest_base + self.avail_ring + 2) as *const u16;
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Read the used ring's `idx` field.
    fn used_idx(&self) -> u16 {
        let ptr = (self.guest_base + self.used_ring + 2) as *const u16;
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Check if there are pending descriptor chains to process.
    pub fn has_pending(&self) -> bool {
        self.avail_idx() != self.last_avail_idx
    }

    /// Pop the next available descriptor chain head index.
    /// Returns `None` if the avail ring is empty.
    pub fn pop_avail(&mut self) -> Option<u16> {
        let avail_idx = self.avail_idx();
        if avail_idx == self.last_avail_idx {
            return None;
        }
        // struct virtq_avail { u16 flags; u16 idx; u16 ring[size]; }
        // ring entry at offset 4 + (last_avail_idx % queue_size) * 2
        let ring_offset = 4 + (self.last_avail_idx % self.queue_size) as u64 * 2;
        let ptr = (self.guest_base + self.avail_ring + ring_offset) as *const u16;
        let head = unsafe { core::ptr::read_volatile(ptr) };
        self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
        Some(head)
    }

    /// Walk the descriptor chain starting at `head`.
    pub fn walk_chain(&self, head: u16) -> DescChainIter {
        DescChainIter::new(head, self.desc_table, self.guest_base, self.queue_size)
    }

    /// Write a used ring entry and advance the used index.
    ///
    /// `head_idx`: the descriptor chain head index being completed.
    /// `bytes_written`: total bytes written to WRITE buffers.
    pub fn push_used(&mut self, head_idx: u16, bytes_written: u32) {
        let used_idx = self.used_idx();
        // struct virtq_used { u16 flags; u16 idx; struct { u32 id; u32 len; } ring[]; }
        // Each ring entry is 8 bytes, starting at offset 4.
        let ring_offset = 4 + (used_idx % self.queue_size) as u64 * 8;
        let entry_ptr = (self.guest_base + self.used_ring + ring_offset) as *mut u32;
        unsafe {
            // Write id (descriptor chain head index)
            core::ptr::write_volatile(entry_ptr, head_idx as u32);
            // Write len (total bytes)
            core::ptr::write_volatile(entry_ptr.add(1), bytes_written);
        }
        // Advance used idx
        let new_used = used_idx.wrapping_add(1);
        let idx_ptr = (self.guest_base + self.used_ring + 2) as *mut u16;
        unsafe {
            core::ptr::write_volatile(idx_ptr, new_used);
        }
    }

    /// Process all pending descriptor chains, calling `handler` for each.
    ///
    /// `handler(head, chain_iter) -> bytes_written`
    ///
    /// Returns the number of chains processed.
    pub fn process_pending<F>(&mut self, mut handler: F) -> u32
    where
        F: FnMut(u16, DescChainIter) -> u32,
    {
        let mut count = 0u32;
        while let Some(head) = self.pop_avail() {
            let chain = self.walk_chain(head);
            let written = handler(head, chain);
            self.push_used(head, written);
            count += 1;
        }
        count
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    /// Create a mock descriptor table in a local buffer and test chain walking.
    #[test]
    fn desc_chain_walk_three_elements() {
        // Allocate a buffer simulating guest RAM.
        let mut ram = vec![0u8; 8192];

        // Place descriptors at offset 0 (desc_table_gpa = 0).
        // Desc 0: addr=0x1000, len=512, flags=NEXT, next=1
        let desc0 = VirtqDesc {
            addr: 0x1000,
            len: 512,
            flags: VRING_DESC_F_NEXT,
            next: 1,
        };
        // Desc 1: addr=0x2000, len=1024, flags=WRITE|NEXT, next=2
        let desc1 = VirtqDesc {
            addr: 0x2000,
            len: 1024,
            flags: VRING_DESC_F_WRITE | VRING_DESC_F_NEXT,
            next: 2,
        };
        // Desc 2: addr=0x3000, len=1, flags=WRITE (terminal)
        let desc2 = VirtqDesc {
            addr: 0x3000,
            len: 1,
            flags: VRING_DESC_F_WRITE,
            next: 0,
        };

        // Write descriptors into the buffer.
        unsafe {
            let base = ram.as_mut_ptr();
            core::ptr::write(base as *mut VirtqDesc, desc0);
            core::ptr::write(base.add(16) as *mut VirtqDesc, desc1);
            core::ptr::write(base.add(32) as *mut VirtqDesc, desc2);
        }

        // Walk starting from head=0, desc_table=0, guest_base = buffer addr.
        let guest_base = ram.as_ptr() as u64;
        let mut iter = DescChainIter::new(0, 0, guest_base, 256);

        let e0 = iter.next().unwrap();
        assert_eq!(e0.addr, 0x1000);
        assert_eq!(e0.len, 512);
        assert!(!e0.write);

        let e1 = iter.next().unwrap();
        assert_eq!(e1.addr, 0x2000);
        assert_eq!(e1.len, 1024);
        assert!(e1.write);

        let e2 = iter.next().unwrap();
        assert_eq!(e2.addr, 0x3000);
        assert_eq!(e2.len, 1);
        assert!(e2.write);

        // Chain ends.
        assert!(iter.next().is_none());
    }

    #[test]
    fn split_virtqueue_avail_used_ring() {
        // Layout: desc_table at 0, avail ring at 4096, used ring at 8192.
        // Queue size = 4.
        let mut ram = vec![0u8; 16384];
        let guest_base = ram.as_ptr() as u64;

        let mut vq = SplitVirtqueue::new();
        vq.setup(4, 0, 4096, 8192, guest_base);

        // Simulate driver adding one entry to avail ring.
        // struct virtq_avail { u16 flags; u16 idx; u16 ring[4]; }
        let avail_flags_ptr = (guest_base + 4096) as *mut u16;
        let avail_idx_ptr = (guest_base + 4096 + 2) as *mut u16;
        let avail_ring_ptr = (guest_base + 4096 + 4) as *mut u16;
        unsafe {
            core::ptr::write_volatile(avail_flags_ptr, 0);  // no flags
            core::ptr::write_volatile(avail_ring_ptr, 0);   // ring[0] = desc head 0
            core::ptr::write_volatile(avail_idx_ptr, 1);    // idx = 1 (one entry)
        }

        // Place a single descriptor (no chain).
        let desc0 = VirtqDesc {
            addr: 0x5000,
            len: 256,
            flags: 0,
            next: 0,
        };
        unsafe {
            core::ptr::write(ram.as_mut_ptr() as *mut VirtqDesc, desc0);
        }

        assert!(vq.has_pending());

        // Pop and verify.
        let head = vq.pop_avail().unwrap();
        assert_eq!(head, 0);
        assert!(!vq.has_pending()); // no more

        // Walk the single-element chain.
        let mut chain = vq.walk_chain(head);
        let elem = chain.next().unwrap();
        assert_eq!(elem.addr, 0x5000);
        assert_eq!(elem.len, 256);
        assert!(!elem.write);
        assert!(chain.next().is_none());

        // Complete: push used entry.
        vq.push_used(head, 128);

        // Read back used ring: idx should be 1.
        let used_idx_ptr = (guest_base + 8192 + 2) as *const u16;
        let used_entry_id = (guest_base + 8192 + 4) as *const u32;
        let used_entry_len = (guest_base + 8192 + 8) as *const u32;
        unsafe {
            assert_eq!(core::ptr::read_volatile(used_idx_ptr), 1);
            assert_eq!(core::ptr::read_volatile(used_entry_id), 0); // head idx
            assert_eq!(core::ptr::read_volatile(used_entry_len), 128);
        }
    }

    #[test]
    fn process_pending_calls_handler() {
        let mut ram = vec![0u8; 16384];
        let guest_base = ram.as_ptr() as u64;

        let mut vq = SplitVirtqueue::new();
        vq.setup(4, 0, 4096, 8192, guest_base);

        // Add 2 entries to the avail ring.
        let desc0 = VirtqDesc { addr: 0x100, len: 64, flags: 0, next: 0 };
        let desc1 = VirtqDesc { addr: 0x200, len: 128, flags: 0, next: 0 };
        unsafe {
            let base = ram.as_mut_ptr();
            core::ptr::write(base as *mut VirtqDesc, desc0);
            core::ptr::write(base.add(16) as *mut VirtqDesc, desc1);

            let avail_idx_ptr = (guest_base + 4096 + 2) as *mut u16;
            let avail_ring = (guest_base + 4096 + 4) as *mut u16;
            core::ptr::write_volatile(avail_ring, 0);      // ring[0] = 0
            core::ptr::write_volatile(avail_ring.add(1), 1); // ring[1] = 1
            core::ptr::write_volatile(avail_idx_ptr, 2);    // idx = 2
        }

        let mut processed = 0u32;
        let count = vq.process_pending(|_head, mut chain| {
            processed += 1;
            let elem = chain.next().unwrap();
            elem.len
        });
        assert_eq!(count, 2);
        assert_eq!(processed, 2);
    }
}
