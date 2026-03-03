#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

extern crate alloc;

mod vmm;

#[cfg(test)]
extern crate std;

use alloc::alloc::{GlobalAlloc, Layout};

#[cfg(not(test))]
unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.alloc(&layout)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[cfg(not(test))]
struct BumpAllocator {
    ptr: core::sync::atomic::AtomicUsize,
}

#[cfg(not(test))]
impl BumpAllocator {
    const fn new() -> Self {
        Self {
            ptr: core::sync::atomic::AtomicUsize::new(0x200000),
        }
    }

    unsafe fn alloc(&self, layout: &Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        let mut old = self.ptr.load(core::sync::atomic::Ordering::Relaxed);
        loop {
            // Round up to required alignment before handing out the pointer.
            let aligned = (old + align - 1) & !(align - 1);
            let new_top = aligned + size;
            match self.ptr.compare_exchange_weak(
                old,
                new_top,
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => return aligned as *mut u8,
                Err(actual) => old = actual,
            }
        }
    }
}

#[cfg(not(test))]
#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator::new();

#[cfg(not(test))]
use core::panic::PanicInfo;

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    vmm::run()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
