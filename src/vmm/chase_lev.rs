//! Chase-Lev Lock-Free Work-Stealing Deque
//!
//! A high-performance, lock-free double-ended queue implementing the Chase-Lev
//! algorithm for work-stealing schedulers. This is the foundation for parallel
//! task execution across up to 8192 cores.
//!
//! Properties:
//! - Single producer (owner) can push/pop from the bottom
//! - Multiple consumers (thieves) can steal from the top
//! - Lock-free and wait-free for the owner
//! - Lock-free for thieves (may retry on contention)
//!
//! Reference: "Dynamic Circular Work-Stealing Deque" - Chase & Lev, SPAA 2005

#![allow(dead_code)]

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicIsize, AtomicPtr, AtomicUsize, Ordering};

// ─── Cache Line Padding ────────────────────────────────────────────────────────

/// Cache line size for x86-64 (64 bytes)
const CACHE_LINE_SIZE: usize = 64;

/// Padding to prevent false sharing between atomic variables
#[repr(C)]
struct CacheLinePad<T> {
    value: T,
    _pad: [u8; CACHE_LINE_SIZE - core::mem::size_of::<AtomicIsize>()],
}

impl<T> CacheLinePad<T> {
    const fn new(value: T) -> Self {
        Self {
            value,
            _pad: [0u8; CACHE_LINE_SIZE - core::mem::size_of::<AtomicIsize>()],
        }
    }
}

// ─── Circular Buffer ───────────────────────────────────────────────────────────

/// Initial capacity (must be power of 2)
const INITIAL_CAPACITY: usize = 1024;

/// Maximum capacity (1M entries)
const MAX_CAPACITY: usize = 1 << 20;

/// A growable circular buffer for the deque
pub struct CircularBuffer<T> {
    /// Pointer to the data array
    data: *mut MaybeUninit<T>,
    /// Capacity (always power of 2)
    capacity: usize,
    /// Mask for fast modulo (capacity - 1)
    mask: usize,
}

impl<T> CircularBuffer<T> {
    /// Create a new buffer with given capacity (must be power of 2)
    fn new(capacity: usize) -> Self {
        debug_assert!(capacity.is_power_of_two());
        let layout = core::alloc::Layout::array::<MaybeUninit<T>>(capacity).unwrap();
        // In no_std we use a static pool; for now use a simple bump allocator pattern
        // This is safe because we only grow, never shrink
        let data = unsafe {
            let ptr = alloc_zeroed_pages(layout.size());
            ptr as *mut MaybeUninit<T>
        };
        Self {
            data,
            capacity,
            mask: capacity - 1,
        }
    }

    /// Get element at index (wrapping)
    #[inline]
    unsafe fn get(&self, index: isize) -> &MaybeUninit<T> {
        let idx = (index as usize) & self.mask;
        &*self.data.add(idx)
    }

    /// Put element at index (wrapping)
    #[inline]
    unsafe fn put(&self, index: isize, value: T) {
        let idx = (index as usize) & self.mask;
        self.data.add(idx).write(MaybeUninit::new(value));
    }

    /// Grow the buffer to a new capacity, copying elements from [top, bottom)
    fn grow(&self, top: isize, bottom: isize, new_capacity: usize) -> Self {
        debug_assert!(new_capacity.is_power_of_two());
        debug_assert!(new_capacity > self.capacity);

        let new_buf = Self::new(new_capacity);

        // Copy elements from old buffer to new buffer
        let mut i = top;
        while i < bottom {
            unsafe {
                let val = self.get(i).assume_init_read();
                new_buf.put(i, val);
            }
            i += 1;
        }

        new_buf
    }

    fn capacity(&self) -> usize {
        self.capacity
    }
}

// ─── Static Buffer Pool ────────────────────────────────────────────────────────

/// Buffer pool for no_std allocation
/// 16 MB total pool for deque buffers
const BUFFER_POOL_SIZE: usize = 16 * 1024 * 1024;

#[repr(align(4096))]
struct BufferPool {
    data: UnsafeCell<[u8; BUFFER_POOL_SIZE]>,
    cursor: AtomicUsize,
}

unsafe impl Sync for BufferPool {}

static BUFFER_POOL: BufferPool = BufferPool {
    data: UnsafeCell::new([0u8; BUFFER_POOL_SIZE]),
    cursor: AtomicUsize::new(0),
};

/// Allocate zeroed pages from the static pool
fn alloc_zeroed_pages(size: usize) -> *mut u8 {
    let aligned_size = (size + 4095) & !4095; // Align to 4KB
    let offset = BUFFER_POOL.cursor.fetch_add(aligned_size, Ordering::SeqCst);
    if offset + aligned_size > BUFFER_POOL_SIZE {
        // Pool exhausted - fatal error
        // In production hypervisor, this should trigger a system halt
        // For now, use a panic that will halt execution
        panic!("Chase-Lev buffer pool exhausted - fatal error");
    }
    unsafe { (*BUFFER_POOL.data.get()).as_mut_ptr().add(offset) }
}

// ─── Chase-Lev Deque ───────────────────────────────────────────────────────────

/// Steal result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StealResult<T> {
    /// Successfully stole an item
    Success(T),
    /// Deque was empty
    Empty,
    /// Lost race with another thief or the owner - retry
    Retry,
}

/// Chase-Lev work-stealing deque
///
/// The owner thread uses `push_bottom()` and `pop_bottom()`.
/// Worker threads use `steal()` to take work from the top.
pub struct ChaseLevDeque<T> {
    /// Bottom index (only modified by owner)
    bottom: CacheLinePad<AtomicIsize>,
    /// Top index (modified by owner and thieves)
    top: CacheLinePad<AtomicIsize>,
    /// Pointer to the current circular buffer (may be swapped on grow)
    buffer: AtomicPtr<CircularBuffer<T>>,
}

unsafe impl<T: Send> Send for ChaseLevDeque<T> {}
unsafe impl<T: Send> Sync for ChaseLevDeque<T> {}

impl<T> ChaseLevDeque<T> {
    /// Create a new empty deque
    pub fn new() -> Self {
        let buf = Box::new(CircularBuffer::new(INITIAL_CAPACITY));
        let buf_ptr = Box::into_raw(buf);
        Self {
            bottom: CacheLinePad::new(AtomicIsize::new(0)),
            top: CacheLinePad::new(AtomicIsize::new(0)),
            buffer: AtomicPtr::new(buf_ptr),
        }
    }

    /// Create a deque with specified initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.next_power_of_two().max(INITIAL_CAPACITY);
        let buf = Box::new(CircularBuffer::new(cap));
        let buf_ptr = Box::into_raw(buf);
        Self {
            bottom: CacheLinePad::new(AtomicIsize::new(0)),
            top: CacheLinePad::new(AtomicIsize::new(0)),
            buffer: AtomicPtr::new(buf_ptr),
        }
    }

    /// Push an item to the bottom of the deque (owner only)
    ///
    /// This is wait-free - it never blocks or retries.
    pub fn push_bottom(&self, value: T) {
        let bottom = self.bottom.value.load(Ordering::Relaxed);
        let top = self.top.value.load(Ordering::Acquire);
        let buf_ptr = self.buffer.load(Ordering::Relaxed);
        let buf = unsafe { &*buf_ptr };

        let size = bottom.wrapping_sub(top);

        // Check if we need to grow
        if size >= buf.capacity() as isize - 1 {
            // Grow the buffer
            let new_capacity = (buf.capacity() * 2).min(MAX_CAPACITY);
            if new_capacity <= buf.capacity() {
                // At max capacity - drop the item (shouldn't happen in practice)
                return;
            }
            let new_buf = buf.grow(top, bottom, new_capacity);
            let new_buf_ptr = Box::into_raw(Box::new(new_buf));
            self.buffer.store(new_buf_ptr, Ordering::Release);
            // Old buffer is leaked (acceptable in no_std static pool)
            unsafe {
                (*new_buf_ptr).put(bottom, value);
            }
        } else {
            unsafe {
                buf.put(bottom, value);
            }
        }

        // Release fence to ensure the write is visible before bottom is updated
        core::sync::atomic::fence(Ordering::Release);
        self.bottom.value.store(bottom.wrapping_add(1), Ordering::Relaxed);
    }

    /// Pop an item from the bottom of the deque (owner only)
    ///
    /// Returns `None` if the deque is empty.
    pub fn pop_bottom(&self) -> Option<T> {
        let bottom = self.bottom.value.load(Ordering::Relaxed).wrapping_sub(1);
        self.bottom.value.store(bottom, Ordering::Relaxed);

        // Full memory barrier
        core::sync::atomic::fence(Ordering::SeqCst);

        let top = self.top.value.load(Ordering::Relaxed);
        let size = bottom.wrapping_sub(top);

        if size < 0 {
            // Deque was empty
            self.bottom.value.store(top, Ordering::Relaxed);
            return None;
        }

        let buf_ptr = self.buffer.load(Ordering::Relaxed);
        let buf = unsafe { &*buf_ptr };
        let value = unsafe { buf.get(bottom).assume_init_read() };

        if size > 0 {
            // More than one element - no race with steal
            Some(value)
        } else {
            // Last element - race with steal
            // Try to claim it by CAS on top
            let result = self.top.value.compare_exchange(
                top,
                top.wrapping_add(1),
                Ordering::SeqCst,
                Ordering::Relaxed,
            );

            // Reset bottom regardless of CAS result
            self.bottom.value.store(top.wrapping_add(1), Ordering::Relaxed);

            if result.is_ok() {
                Some(value)
            } else {
                // Lost race - thief got it
                None
            }
        }
    }

    /// Steal an item from the top of the deque (thieves)
    ///
    /// Returns:
    /// - `Success(T)` if an item was stolen
    /// - `Empty` if the deque is empty
    /// - `Retry` if lost race with another thief or the owner
    pub fn steal(&self) -> StealResult<T> {
        let top = self.top.value.load(Ordering::Acquire);

        // Acquire fence ensures we see the latest buffer pointer
        core::sync::atomic::fence(Ordering::SeqCst);

        let bottom = self.bottom.value.load(Ordering::Acquire);

        let size = bottom.wrapping_sub(top);

        if size <= 0 {
            return StealResult::Empty;
        }

        let buf_ptr = self.buffer.load(Ordering::Acquire);
        let buf = unsafe { &*buf_ptr };
        let value = unsafe { buf.get(top).assume_init_read() };

        // Try to increment top
        let result = self.top.value.compare_exchange(
            top,
            top.wrapping_add(1),
            Ordering::SeqCst,
            Ordering::Relaxed,
        );

        if result.is_ok() {
            StealResult::Success(value)
        } else {
            // Lost race
            StealResult::Retry
        }
    }

    /// Check if the deque is empty
    pub fn is_empty(&self) -> bool {
        let bottom = self.bottom.value.load(Ordering::Relaxed);
        let top = self.top.value.load(Ordering::Relaxed);
        bottom.wrapping_sub(top) <= 0
    }

    /// Get the current number of items (approximate, may be stale)
    pub fn len(&self) -> usize {
        let bottom = self.bottom.value.load(Ordering::Relaxed);
        let top = self.top.value.load(Ordering::Relaxed);
        let size = bottom.wrapping_sub(top);
        if size < 0 { 0 } else { size as usize }
    }
}

impl<T> Default for ChaseLevDeque<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Work-Stealing Scheduler ───────────────────────────────────────────────────

/// Maximum number of worker threads
pub const MAX_WORKERS: usize = 64;

/// Work item trait for schedulable tasks
pub trait WorkItem: Send + 'static {
    fn execute(self);
}

/// A simple function pointer work item
pub struct FnWork {
    func: fn(),
}

impl FnWork {
    pub const fn new(func: fn()) -> Self {
        Self { func }
    }
}

impl WorkItem for FnWork {
    fn execute(self) {
        (self.func)();
    }
}

/// Global work-stealing scheduler state
pub struct WorkStealingScheduler<T: WorkItem> {
    /// Per-worker deques
    deques: [Option<ChaseLevDeque<T>>; MAX_WORKERS],
    /// Number of active workers
    worker_count: AtomicUsize,
    /// Global shutdown flag
    shutdown: AtomicUsize,
}

impl<T: WorkItem> WorkStealingScheduler<T> {
    /// Create a new scheduler
    pub const fn new() -> Self {
        Self {
            deques: [const { None }; MAX_WORKERS],
            worker_count: AtomicUsize::new(0),
            shutdown: AtomicUsize::new(0),
        }
    }

    /// Register a worker and get its ID
    pub fn register_worker(&mut self) -> Option<usize> {
        let id = self.worker_count.fetch_add(1, Ordering::SeqCst);
        if id >= MAX_WORKERS {
            self.worker_count.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        self.deques[id] = Some(ChaseLevDeque::new());
        Some(id)
    }

    /// Submit work to a specific worker's deque
    pub fn submit(&self, worker_id: usize, work: T) -> bool {
        if let Some(ref deque) = self.deques[worker_id] {
            deque.push_bottom(work);
            true
        } else {
            false
        }
    }

    /// Try to get work from own deque
    pub fn pop_local(&self, worker_id: usize) -> Option<T> {
        self.deques[worker_id].as_ref()?.pop_bottom()
    }

    /// Try to steal work from another worker
    pub fn steal_from(&self, victim_id: usize) -> StealResult<T> {
        if let Some(ref deque) = self.deques[victim_id] {
            deque.steal()
        } else {
            StealResult::Empty
        }
    }

    /// Get the number of active workers
    pub fn worker_count(&self) -> usize {
        self.worker_count.load(Ordering::Relaxed)
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(1, Ordering::Release);
    }

    /// Check if shutdown was requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) != 0
    }
}

impl<T: WorkItem> Default for WorkStealingScheduler<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deque_push_pop_single() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();
        assert!(deque.is_empty());

        deque.push_bottom(42);
        assert!(!deque.is_empty());
        assert_eq!(deque.len(), 1);

        let val = deque.pop_bottom();
        assert_eq!(val, Some(42));
        assert!(deque.is_empty());
    }

    #[test]
    fn deque_push_pop_many() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();

        for i in 0..100 {
            deque.push_bottom(i);
        }
        assert_eq!(deque.len(), 100);

        // Pop in LIFO order (bottom)
        for i in (0..100).rev() {
            let val = deque.pop_bottom();
            assert_eq!(val, Some(i));
        }
        assert!(deque.is_empty());
    }

    #[test]
    fn deque_steal_single() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();

        deque.push_bottom(42);

        // Steal from top
        match deque.steal() {
            StealResult::Success(val) => assert_eq!(val, 42),
            _ => panic!("Expected successful steal"),
        }

        // Now empty
        assert!(matches!(deque.steal(), StealResult::Empty));
    }

    #[test]
    fn deque_steal_fifo() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();

        for i in 0..10 {
            deque.push_bottom(i);
        }

        // Steal gets items in FIFO order (from top)
        for i in 0..10 {
            match deque.steal() {
                StealResult::Success(val) => assert_eq!(val, i),
                StealResult::Retry => {
                    // Retry the same index
                    match deque.steal() {
                        StealResult::Success(val) => assert_eq!(val, i),
                        _ => panic!("Failed after retry"),
                    }
                }
                StealResult::Empty => panic!("Unexpected empty at {}", i),
            }
        }
    }

    #[test]
    fn deque_mixed_operations() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();

        // Push 5 items
        for i in 0..5 {
            deque.push_bottom(i);
        }

        // Steal 2 from top (0, 1)
        assert!(matches!(deque.steal(), StealResult::Success(0)));
        assert!(matches!(deque.steal(), StealResult::Success(1)));

        // Pop 2 from bottom (4, 3)
        assert_eq!(deque.pop_bottom(), Some(4));
        assert_eq!(deque.pop_bottom(), Some(3));

        // One left (2)
        assert_eq!(deque.len(), 1);
        assert_eq!(deque.pop_bottom(), Some(2));
    }

    #[test]
    fn deque_empty_operations() {
        let deque: ChaseLevDeque<u64> = ChaseLevDeque::new();

        assert!(deque.is_empty());
        assert_eq!(deque.pop_bottom(), None);
        assert!(matches!(deque.steal(), StealResult::Empty));
    }

    #[test]
    fn scheduler_basic() {
        let mut sched: WorkStealingScheduler<FnWork> = WorkStealingScheduler::new();

        let id = sched.register_worker().unwrap();
        assert_eq!(id, 0);
        assert_eq!(sched.worker_count(), 1);

        static mut COUNTER: u32 = 0;

        fn increment() {
            unsafe { COUNTER += 1; }
        }

        sched.submit(0, FnWork::new(increment));

        let work = sched.pop_local(0).unwrap();
        work.execute();

        unsafe { assert_eq!(COUNTER, 1); }
    }

    #[test]
    fn cache_line_padding_size() {
        // Ensure our padding struct is at least cache line sized
        assert!(core::mem::size_of::<CacheLinePad<AtomicIsize>>() >= CACHE_LINE_SIZE);
    }
}
