//! Valkyrie-V public C ABI
//!
//! This is the entry point for the `staticlib` / `rlib` output consumed by echOS-x64.
//! echOS links against this crate and drives the GamingBridge through the functions
//! below instead of through the bare-metal `_start` entry point.
//!
//! Typical call sequence from echOS:
//!
//! ```c
//! // 1. Initialise a bridge instance (up to 4 concurrent)
//! uint8_t handle = valkyrie_init(&cfg);
//!
//! // 2. Option A — pre-loaded kernel blob
//! valkyrie_begin_fetch(handle, kernel_size);
//! valkyrie_receive_chunk(handle, kernel_ptr, kernel_len);
//! valkyrie_set_sig(handle, hmac_sig);
//!
//! // 3. Scheduler tick loop (poll from echOS scheduler callback)
//! while (valkyrie_tick(handle) != BRIDGE_RUNNING) { /* yield */ }
//!
//! // 4. Forward smoltcp packets into the VM
//! valkyrie_net_inject(handle, pkt_buf, pkt_len);
//!
//! // 5. Submit DXVK/D3DMetal GPU opcode stream
//! valkyrie_gpu_submit(handle, cmd_buf, cmd_len);
//!
//! // 6. Snapshot on suspend
//! uint32_t snap_id = valkyrie_snapshot(handle);
//! ```

#![cfg_attr(all(not(any(test, doctest)), feature = "baremetal-lib"), no_std)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::assertions_on_constants)]

pub mod vmm;

use core::cell::UnsafeCell;
#[cfg(all(not(any(test, doctest)), feature = "baremetal-lib"))]
use core::panic::PanicInfo;
use vmm::game_bridge::{BridgeConfig, BridgeStatus, GamingBridge};

#[cfg(all(not(any(test, doctest)), feature = "baremetal-lib"))]
#[panic_handler]
fn valkyrie_panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Bridge slot pool — up to MAX_BRIDGES concurrent game sessions
// ---------------------------------------------------------------------------

const MAX_BRIDGES: usize = 4;

struct BridgePool([UnsafeCell<Option<GamingBridge>>; MAX_BRIDGES]);
unsafe impl Sync for BridgePool {}

static POOL: BridgePool = BridgePool([
    const { UnsafeCell::new(None) },
    const { UnsafeCell::new(None) },
    const { UnsafeCell::new(None) },
    const { UnsafeCell::new(None) },
]);

#[inline(always)]
fn slot(handle: u8) -> Option<&'static UnsafeCell<Option<GamingBridge>>> {
    POOL.0.get(handle as usize)
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Initialise a new GamingBridge with the supplied configuration.
///
/// Returns a handle in [0, 3] on success, or `0xFF` if all slots are occupied
/// or `cfg` is null.
#[no_mangle]
pub extern "C" fn valkyrie_init(cfg: *const BridgeConfig) -> u8 {
    if cfg.is_null() {
        return 0xFF;
    }
    for (i, cell) in POOL.0.iter().enumerate() {
        let opt = unsafe { &mut *cell.get() };
        if opt.is_none() {
            *opt = Some(GamingBridge::new());
            // Apply the config
            if !cfg.is_null() {
                unsafe {
                    let c = &*cfg;
                    let bridge_cfg = BridgeConfig {
                        vcpu_count: c.vcpu_count,
                        memory_mb: c.memory_mb,
                        kernel_ptr: c.kernel_ptr,
                        kernel_len: c.kernel_len,
                        mac_addr: c.mac_addr,
                        _pad: c._pad,
                    };
                    opt.as_mut().unwrap().configure(bridge_cfg);
                }
            }
            return i as u8;
        }
    }
    0xFF
}

/// Single polling tick. Returns the current [`BridgeStatus`] as a `u8`.
///
/// Call this from the echOS scheduler at whatever granularity is convenient;
/// the bridge is purely cooperative (no blocking, no async).
#[no_mangle]
pub extern "C" fn valkyrie_tick(handle: u8) -> u8 {
    match slot(handle) {
        Some(cell) => match unsafe { &mut *cell.get() } {
            Some(b) => b.tick() as u8,
            None => BridgeStatus::Fault as u8,
        },
        None => BridgeStatus::Fault as u8,
    }
}

/// Tell the bridge to expect `total_size` bytes of game binary arriving via
/// `valkyrie_receive_chunk`. Transitions the bridge to `Fetching` state.
#[no_mangle]
pub extern "C" fn valkyrie_begin_fetch(handle: u8, total_size: usize) {
    if let Some(cell) = slot(handle) {
        if let Some(b) = unsafe { &mut *cell.get() } {
            b.begin_fetch(total_size);
        }
    }
}

/// Deliver a chunk of binary data. Safe to call multiple times until the
/// full payload has been delivered; the bridge accumulates bytes internally.
#[no_mangle]
pub extern "C" fn valkyrie_receive_chunk(handle: u8, buf: *const u8, len: usize) {
    if buf.is_null() || len == 0 {
        return;
    }
    if let Some(cell) = slot(handle) {
        if let Some(b) = unsafe { &mut *cell.get() } {
            let data = unsafe { core::slice::from_raw_parts(buf, len) };
            b.receive_chunk(data);
        }
    }
}

/// Set the expected IronShim HMAC-SHA256 signature (32 bytes) for the binary.
/// Must be called before the bridge transitions through `Validating`.
#[no_mangle]
pub extern "C" fn valkyrie_set_sig(handle: u8, sig: *const u8) {
    if sig.is_null() {
        return;
    }
    if let Some(cell) = slot(handle) {
        if let Some(b) = unsafe { &mut *cell.get() } {
            let arr: &[u8; 32] = unsafe { &*(sig as *const [u8; 32]) };
            b.set_expected_sig(arr);
        }
    }
}

/// Inject a host-side network packet into the VM's VirtIO-Net RX ring.
///
/// Call this from the smoltcp RX callback in echOS when a packet arrives
/// destined for the guest.
///
/// Returns `true` if the packet was queued, `false` if the ring is full.
#[no_mangle]
pub extern "C" fn valkyrie_net_inject(handle: u8, buf: *const u8, len: usize) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    match slot(handle) {
        Some(cell) => match unsafe { &*cell.get() } {
            Some(b) => {
                let data = unsafe { core::slice::from_raw_parts(buf, len) };
                b.inject_net_packet(data)
            }
            None => false,
        },
        None => false,
    }
}

/// Submit a GPU command buffer (DXVK D3D opcode stream) for the echOS backend
/// (Metal / Vulkan / SwiftShader) to consume via `GpuCommandRing::pop`.
///
/// Returns `true` if enqueued, `false` if the GPU ring is full.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_submit(handle: u8, cmdbuf: *const u8, len: usize) -> bool {
    if cmdbuf.is_null() || len == 0 {
        return false;
    }
    match slot(handle) {
        Some(cell) => match unsafe { &*cell.get() } {
            Some(b) => {
                let data = unsafe { core::slice::from_raw_parts(cmdbuf, len) };
                b.submit_gpu_cmd(data)
            }
            None => false,
        },
        None => false,
    }
}

/// Pop the next GPU command from the bridge's `GpuCommandRing` into `dst`.
///
/// Returns the number of bytes written, or 0 if the ring is empty or the
/// handle is invalid. Used by the echOS GPU backend dispatcher.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_pop(handle: u8, dst: *mut u8, dst_len: usize) -> usize {
    if dst.is_null() || dst_len == 0 {
        return 0;
    }
    match slot(handle) {
        Some(cell) => match unsafe { &*cell.get() } {
            Some(b) => {
                let buf = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
                b.gpu_ring.pop(buf).unwrap_or(0)
            }
            None => 0,
        },
        None => 0,
    }
}

/// Snapshot the active VM. Returns the VM id used as a snapshot handle,
/// or `u32::MAX` if no VM is running or the handle is invalid.
#[no_mangle]
pub extern "C" fn valkyrie_snapshot(handle: u8) -> u32 {
    match slot(handle) {
        Some(cell) => match unsafe { &*cell.get() } {
            Some(b) => b.active_vm_id().unwrap_or(u32::MAX),
            None => u32::MAX,
        },
        None => u32::MAX,
    }
}

/// Return the current [`BridgeStatus`] without advancing the state machine.
#[no_mangle]
pub extern "C" fn valkyrie_status(handle: u8) -> u8 {
    match slot(handle) {
        Some(cell) => match unsafe { &*cell.get() } {
            Some(b) => b.status() as u8,
            None => BridgeStatus::Fault as u8,
        },
        None => BridgeStatus::Fault as u8,
    }
}

/// Free a bridge slot. Safe to call even if no bridge is allocated at `handle`.
#[no_mangle]
pub extern "C" fn valkyrie_destroy(handle: u8) {
    if let Some(cell) = slot(handle) {
        unsafe { *cell.get() = None };
    }
}

// ---------------------------------------------------------------------------
// UGES GPU C ABI — Phase 1 (echOS ↔ Valkyrie-V direct GPU path)
// ---------------------------------------------------------------------------

/// ABI version tag — lock-free completion API starts at v2.
pub const VALKYRIE_ABI_VERSION: u32 = 2;

/// Returns the compiled ABI version of this Valkyrie-V library.
#[no_mangle]
pub extern "C" fn valkyrie_abi_version() -> u32 {
    VALKYRIE_ABI_VERSION
}

/// Initialise the UEFI GOP framebuffer that the soft-rasterizer writes to.
///
/// `base`   — physical address of `EFI_GRAPHICS_OUTPUT_PROTOCOL::FrameBufferBase`  
/// `stride` — scanline length in pixels (not bytes)  
///
/// Call once at boot before submitting any draw commands.
#[no_mangle]
pub extern "C" fn valkyrie_framebuffer_init(base: u64, width: u32, height: u32, stride: u32) {
    vmm::soft_raster::init_framebuffer(base, width, height, stride);
}

/// Submit a raw batch of `UGCommand` structs to `GPU_QUEUE`.
///
/// `cmds` — pointer to an array of `UGCommand` (each 64 bytes, `repr(C,align(64))`)  
/// `len`  — byte length of the buffer; commands extracted as `len / 64`  
///
/// Commands are enqueued at `Normal` priority.  Returns the number of
/// commands actually enqueued (may be less than total if the ring is full),
/// or 0 on invalid input.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_submit_batch(cmds: *const u8, len: usize) -> u32 {
    use core::mem::{size_of, MaybeUninit};
    use vmm::ugir::UGCommand;
    use vmm::{GpuQueuePriority, GPU_QUEUE};

    const CMD_SIZE: usize = size_of::<UGCommand>();
    if cmds.is_null() || len < CMD_SIZE {
        return 0;
    }
    let total_bytes = (len / CMD_SIZE) * CMD_SIZE;
    let bytes = unsafe { core::slice::from_raw_parts(cmds, total_bytes) };

    let mut submitted = 0u32;
    let mut offset = 0usize;
    while offset + CMD_SIZE <= bytes.len() {
        let mut cmd = MaybeUninit::<UGCommand>::uninit();
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr().add(offset),
                cmd.as_mut_ptr() as *mut u8,
                CMD_SIZE,
            );
        }
        let cmd = unsafe { cmd.assume_init() };
        if GPU_QUEUE.submit(GpuQueuePriority::Normal, core::slice::from_ref(&cmd)) {
            submitted += 1;
        }
        offset += CMD_SIZE;
    }
    submitted
}

/// Drain the GPU command queue and render pending commands to the GOP
/// framebuffer.  Call from the echOS render thread once per frame.
///
/// Returns the number of queue entries (batches) consumed.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_flush() -> u32 {
    vmm::soft_raster::flush_gpu_queue()
}

/// Returns the latest lock-free GPU completion sequence id.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_completion_latest() -> u32 {
    vmm::soft_raster::completion_latest_seq()
}

/// Non-blocking completion poll.
///
/// `next_seq` should be the next sequence to fetch (typically `last + 1`).
/// On success writes fence id to `out_fence` and returns `true`.
/// Returns `false` when there is no event at `next_seq`.
#[no_mangle]
pub extern "C" fn valkyrie_gpu_completion_poll(next_seq: u32, out_fence: *mut u32) -> bool {
    if out_fence.is_null() {
        return false;
    }
    match vmm::soft_raster::completion_fence_at(next_seq) {
        Some(fence) => {
            unsafe {
                *out_fence = fence;
            }
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_returns_valid_handle() {
        let cfg = BridgeConfig {
            vcpu_count: 1,
            memory_mb: 128,
            kernel_ptr: 0,
            kernel_len: 0,
            mac_addr: [0x52, 0x54, 0, 0, 0, 1],
            _pad: [0; 2],
        };
        let h = valkyrie_init(&cfg as *const _);
        assert!(h < MAX_BRIDGES as u8, "expected valid handle, got {h}");
        valkyrie_destroy(h);
    }

    #[test]
    fn tick_on_uninit_handle_returns_fault() {
        assert_eq!(valkyrie_tick(0xFE), BridgeStatus::Fault as u8);
    }

    #[test]
    fn null_config_returns_0xff() {
        assert_eq!(valkyrie_init(core::ptr::null()), 0xFF);
    }

    #[test]
    fn net_inject_on_valid_handle() {
        let cfg = BridgeConfig {
            vcpu_count: 1,
            memory_mb: 64,
            kernel_ptr: 0,
            kernel_len: 0,
            mac_addr: [0x52, 0x54, 0, 0, 0, 2],
            _pad: [0; 2],
        };
        let h = valkyrie_init(&cfg as *const _);
        assert!(h < MAX_BRIDGES as u8);
        let pkt = [0xAAu8; 32];
        assert!(valkyrie_net_inject(h, pkt.as_ptr(), pkt.len()));
        valkyrie_destroy(h);
    }

    #[test]
    fn gpu_submit_and_pop_roundtrip() {
        let cfg = BridgeConfig {
            vcpu_count: 1,
            memory_mb: 64,
            kernel_ptr: 0,
            kernel_len: 0,
            mac_addr: [0x52, 0x54, 0, 0, 0, 3],
            _pad: [0; 2],
        };
        let h = valkyrie_init(&cfg as *const _);
        assert!(h < MAX_BRIDGES as u8);
        let cmd = [0xDEu8, 0xAD, 0xBE, 0xEF];
        assert!(valkyrie_gpu_submit(h, cmd.as_ptr(), cmd.len()));
        let mut out = [0u8; 256];
        let n = valkyrie_gpu_pop(h, out.as_mut_ptr(), out.len());
        assert_eq!(n, 4);
        assert_eq!(&out[..4], &cmd);
        valkyrie_destroy(h);
    }

    // ----- UGES GPU ABI tests -----

    #[test]
    fn abi_version_is_nonzero() {
        assert_eq!(valkyrie_abi_version(), VALKYRIE_ABI_VERSION);
        assert!(VALKYRIE_ABI_VERSION >= 2);
    }

    #[test]
    fn framebuffer_init_and_check() {
        // base = 0 (null) is fine — we only test the initialized flag.
        valkyrie_framebuffer_init(0, 320, 240, 320);
        assert!(
            vmm::soft_raster::framebuffer_initialized(),
            "framebuffer should be marked initialized after valkyrie_framebuffer_init"
        );
    }

    #[test]
    fn submit_batch_null_returns_zero() {
        let result = valkyrie_gpu_submit_batch(core::ptr::null(), 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn submit_batch_and_flush_fence_completion_poll() {
        use core::mem::size_of;
        use vmm::ugir::{UGCommand, UGCommandKind, UGPayload};

        const FENCE_ID: u32 = 0xCAFE_0001;
        let cmd = UGCommand {
            kind: UGCommandKind::Fence,
            _pad: [0; 3],
            p: UGPayload::fence(FENCE_ID as u64),
        };

        // Submit the single UGCommand via the raw-bytes path.
        let raw: &[u8] = unsafe {
            core::slice::from_raw_parts(
                &cmd as *const UGCommand as *const u8,
                size_of::<UGCommand>(),
            )
        };
        let submitted = valkyrie_gpu_submit_batch(raw.as_ptr(), raw.len());
        assert_eq!(submitted, 1, "one command should be enqueued");

        // Flush executes the Fence command → updates LAST_FENCE.
        let batches = valkyrie_gpu_flush();
        assert!(batches >= 1, "at least one batch should be drained");

        let latest = valkyrie_gpu_completion_latest();
        assert!(latest >= 1, "completion sequence should advance");

        let mut fence_out = 0u32;
        assert!(
            valkyrie_gpu_completion_poll(latest, &mut fence_out as *mut u32),
            "completion event should be readable"
        );
        assert_eq!(
            fence_out, FENCE_ID,
            "fence {FENCE_ID:#x} should be completed"
        );
    }

    #[test]
    fn submit_batch_unaligned_pointer_is_safe() {
        use core::mem::size_of;
        use vmm::ugir::{UGCommand, UGCommandKind, UGPayload};

        let cmd = UGCommand {
            kind: UGCommandKind::Fence,
            _pad: [0; 3],
            p: UGPayload::fence(0x77),
        };

        let cmd_bytes = unsafe {
            core::slice::from_raw_parts(
                &cmd as *const UGCommand as *const u8,
                size_of::<UGCommand>(),
            )
        };

        let mut unaligned = [0u8; 1 + size_of::<UGCommand>()];
        unaligned[1..].copy_from_slice(cmd_bytes);
        let submitted = valkyrie_gpu_submit_batch(unaligned[1..].as_ptr(), cmd_bytes.len());
        assert_eq!(
            submitted, 1,
            "unaligned batch should still be accepted safely"
        );
    }
}
