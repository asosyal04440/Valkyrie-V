#![allow(clippy::new_without_default)]
#![allow(clippy::declare_interior_mutable_const)]

//! D3D9 / D3D10 / D3D11 / D3D12 Interceptor (Pillar 2)
//!
//! Patches the COM vtable of D3D interface pointers inside a guest Windows VM,
//! redirecting draw calls into echOS's universal UGCommand pipeline.
//!
//! Architecture
//! ─────────────
//!   Guest userspace calls e.g. ID3D11DeviceContext::DrawIndexed.
//!   Valkyrie-V VMX handler detects EPT violation or VMCALL from the IronShim
//!   agent, and calls into this module.
//!
//!   d3d_intercept.rs captures the arguments, normalises them to UGCommand,
//!   pushes to GpuCommandQueue, then returns a faked S_OK to the guest.
//!
//! No std::ffi / Windows SDK types are used — everything is raw const pointers
//! and integer registers as the HV sees them.

use crate::vmm::ugir::{
    DeltaStateTracker, ShaderStage, UGCommand, UGCommandKind, UGHandle, UGPayload,
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ─── COM error codes ──────────────────────────────────────────────────────────

pub const S_OK: u32 = 0x0000_0000;
pub const E_NOTIMPL: u32 = 0x8000_4001;
pub const E_FAIL: u32 = 0x8000_4005;
pub const E_INVALIDARG: u32 = 0x8007_0057;
pub const DXGI_ERR_DEV: u32 = 0x887A_0005;

// ─── D3D API version tags ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum D3DVersion {
    D3D9 = 9,
    D3D10 = 10,
    D3D11 = 11,
    D3D12 = 12,
    Unknown = 0,
}

// ─── Vtable slot definitions ──────────────────────────────────────────────────

/// ID3D9Device vtable slots (offset in pointer-widths from the start of vtbl).
pub mod d3d9_slot {
    pub const QUERY_INTERFACE: usize = 0;
    pub const ADD_REF: usize = 1;
    pub const RELEASE: usize = 2;
    pub const DRAW_PRIMITIVE: usize = 54;
    pub const DRAW_INDEXED_PRIMITIVE: usize = 55;
    pub const SET_VERTEX_SHADER: usize = 92;
    pub const SET_PIXEL_SHADER: usize = 101;
    pub const PRESENT: usize = 17;
    pub const CLEAR: usize = 43;
    pub const BEGIN_SCENE: usize = 41;
    pub const END_SCENE: usize = 42;
}

/// ID3D11DeviceContext vtable slots.
pub mod d3d11_slot {
    pub const DRAW: usize = 13;
    pub const DRAW_INDEXED: usize = 12;
    pub const DRAW_INSTANCED: usize = 15;
    pub const DRAW_INDEXED_INSTANCED: usize = 20;
    pub const VS_SET_SHADER: usize = 11;
    pub const PS_SET_SHADER: usize = 9;
    pub const IA_SET_VERTEX_BUFFERS: usize = 4;
    pub const IA_SET_INDEX_BUFFER: usize = 5;
    pub const RS_SET_VIEWPORTS: usize = 44;
    pub const OM_SET_RENDER_TARGETS: usize = 33;
    pub const CLEAR_RENDER_TARGET: usize = 50;
    pub const DISPATCH: usize = 41;
    pub const FINISH_COMMAND_LIST: usize = 49;
}

/// ID3D12CommandList vtable slots.
pub mod d3d12_slot {
    pub const DRAW_INDEXED_INSTANCED: usize = 28;
    pub const DRAW_INSTANCED: usize = 27;
    pub const DISPATCH: usize = 29;
    pub const SET_PIPELINE_STATE: usize = 46;
    pub const SET_GRAPHICS_ROOT_SIG: usize = 36;
    pub const EXECUTE_COMMAND_LISTS: usize = 66;
    pub const PRESENT: usize = 3; // IDXGISwapChain::Present
}

// ─── Vtable hook record ───────────────────────────────────────────────────────

/// A single patched vtable entry.  Stores the original function pointer so it
/// can be called through (trampoline) or restored on device teardown.
#[derive(Clone, Copy)]
pub struct VtableHook {
    /// The COM object pointer whose vtable was patched.
    pub object_ptr: u64,
    /// Slot index patched.
    pub slot: u32,
    /// Address of original (overwritten) function.
    pub original_fn: u64,
    /// Address of our hook stub.
    pub hook_fn: u64,
    pub active: bool,
    pub api: D3DVersion,
}

impl VtableHook {
    pub const fn inactive() -> Self {
        Self {
            object_ptr: 0,
            slot: 0,
            original_fn: 0,
            hook_fn: 0,
            active: false,
            api: D3DVersion::Unknown,
        }
    }
}

/// Maximum number of simultaneous vtable hooks across all D3D devices.
pub const MAX_HOOKS: usize = 128;

/// Hook table — global registry.
pub struct HookTable {
    entries: [VtableHook; MAX_HOOKS],
    count: AtomicU32,
}

impl HookTable {
    pub const fn new() -> Self {
        Self {
            entries: [const { VtableHook::inactive() }; MAX_HOOKS],
            count: AtomicU32::new(0),
        }
    }

    /// Register a hook.  Returns the index or an error.
    pub fn insert(&mut self, h: VtableHook) -> Result<usize, HookError> {
        let idx = self.count.load(Ordering::Relaxed) as usize;
        if idx >= MAX_HOOKS {
            return Err(HookError::TableFull);
        }
        self.entries[idx] = h;
        self.count.store((idx + 1) as u32, Ordering::Release);
        Ok(idx)
    }

    pub fn count(&self) -> usize {
        self.count.load(Ordering::Acquire) as usize
    }

    pub fn get(&self, idx: usize) -> Option<&VtableHook> {
        if idx < self.count() {
            Some(&self.entries[idx])
        } else {
            None
        }
    }

    /// Find the hook for a given object pointer + slot.
    pub fn find(&self, object_ptr: u64, slot: u32) -> Option<&VtableHook> {
        let n = self.count();
        for i in 0..n {
            let e = &self.entries[i];
            if e.active && e.object_ptr == object_ptr && e.slot == slot {
                return Some(e);
            }
        }
        None
    }

    /// Deactivate all hooks for an object (called on Release()).
    pub fn remove_object(&mut self, object_ptr: u64) -> usize {
        let mut removed = 0usize;
        let n = self.count.load(Ordering::Acquire) as usize;
        for i in 0..n {
            if self.entries[i].object_ptr == object_ptr && self.entries[i].active {
                self.entries[i].active = false;
                removed += 1;
            }
        }
        removed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookError {
    TableFull,
    AlreadyHooked,
    InvalidPointer,
}

// ─── HLSL / DXBC blob capture ─────────────────────────────────────────────────

/// Maximum captured shader blobs.
pub const MAX_SHADER_BLOBS: usize = 512;
/// Maximum DXBC blob size we will capture (256 KB).
pub const MAX_BLOB_BYTES: usize = 256 * 1024;

/// A captured DXBC shader blob.
pub struct ShaderBlob {
    pub handle: UGHandle,
    pub stage: ShaderStage,
    pub size: usize,
    pub data: [u8; MAX_BLOB_BYTES],
}

impl ShaderBlob {
    pub const fn empty() -> Self {
        Self {
            handle: UGHandle(0),
            stage: ShaderStage::Vertex,
            size: 0,
            data: [0u8; MAX_BLOB_BYTES],
        }
    }

    /// Fill from a guest GPA slice.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        let len = src.len().min(MAX_BLOB_BYTES);
        self.data[..len].copy_from_slice(&src[..len]);
        self.size = len;
    }
}

/// Pool of captured DXBC blobs.
pub struct HlslBlobCapture {
    blobs: [ShaderBlob; MAX_SHADER_BLOBS],
    count: AtomicU32,
}

impl HlslBlobCapture {
    /// NOTE: Initializing this type on the stack would cause a stack overflow
    /// (256 KB × 512 = 128 MB).  Always use as a `static` or boxed.
    pub const fn new() -> Self {
        Self {
            blobs: [const { ShaderBlob::empty() }; MAX_SHADER_BLOBS],
            count: AtomicU32::new(0),
        }
    }

    pub fn capture(&mut self, stage: ShaderStage, data: &[u8]) -> Option<u32> {
        let idx = self.count.load(Ordering::Relaxed) as usize;
        if idx >= MAX_SHADER_BLOBS {
            return None;
        }
        self.blobs[idx].stage = stage;
        self.blobs[idx].size = data.len().min(MAX_BLOB_BYTES);
        let len = self.blobs[idx].size;
        self.blobs[idx].data[..len].copy_from_slice(&data[..len]);
        self.count.store((idx + 1) as u32, Ordering::Release);
        Some(idx as u32)
    }

    pub fn get(&self, idx: u32) -> Option<&ShaderBlob> {
        let n = self.count.load(Ordering::Acquire) as usize;
        let i = idx as usize;
        if i < n {
            Some(&self.blobs[i])
        } else {
            None
        }
    }

    pub fn total_captured(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

// ─── D3D state tracker ────────────────────────────────────────────────────────

/// Wraps `DeltaStateTracker` from ugir with D3D-version-aware state normalisation.
pub struct D3DStateTracker {
    pub delta: DeltaStateTracker,
    pub api: D3DVersion,
    vs_id: u32,
    ps_id: u32,
}

impl D3DStateTracker {
    pub const fn new(api: D3DVersion) -> Self {
        Self {
            delta: DeltaStateTracker::new(),
            api,
            vs_id: u32::MAX,
            ps_id: u32::MAX,
        }
    }

    /// Set the vertex shader handle; returns true if the state changed.
    pub fn set_vs(&mut self, handle: UGHandle) -> bool {
        if self.vs_id == handle.0 {
            return false;
        }
        self.vs_id = handle.0;
        self.delta.set_vs(handle.0);
        true
    }

    /// Set the pixel shader handle; returns true if the state changed.
    pub fn set_ps(&mut self, handle: UGHandle) -> bool {
        if self.ps_id == handle.0 {
            return false;
        }
        self.ps_id = handle.0;
        self.delta.set_ps(handle.0);
        true
    }
}

// ─── Interceptor core ─────────────────────────────────────────────────────────

/// Maximum UGCommands the interceptor can queue before flush.
pub const INTERCEPT_BATCH_CAP: usize = 1024;

/// D3D API-agnostic interceptor.  Intercept methods parse the guest register
/// arguments, validate them, and push normalised UGCommands.
pub struct D3DInterceptor {
    pub state: D3DStateTracker,
    pub hooks: HookTable,
    pub batch: [UGCommand; INTERCEPT_BATCH_CAP],
    pub batch_len: usize,
    pub version: D3DVersion,
    armed: AtomicBool,
}

impl D3DInterceptor {
    pub const fn new(version: D3DVersion) -> Self {
        const NOP_CMD: UGCommand = UGCommand {
            kind: UGCommandKind::Nop,
            _pad: [0; 3],
            p: UGPayload::zeroed(),
            x: 0,
            y: 0,
            z: 0,
            src_addr: 0,
            dst_addr: 0,
            size: 0,
            clear_value: 0.0,
            width: 0,
            height: 0,
            handle: UGHandle::NULL,
            pipeline_id: 0,
            descriptor_id: 0,
            descriptor_set: 0,
            binding: 0,
            buffer_addr: 0,
            stride: 0,
            index_type: 0,
            buffer_id: 0,
            offset: 0,
        };
        Self {
            state: D3DStateTracker::new(version),
            hooks: HookTable::new(),
            batch: [NOP_CMD; INTERCEPT_BATCH_CAP],
            batch_len: 0,
            version,
            armed: AtomicBool::new(false),
        }
    }

    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Acquire)
    }

    // ── Intercept handlers ────────────────────────────────────────────────

    /// Handle DrawIndexed / DrawIndexedPrimitive.
    pub fn on_draw_indexed(
        &mut self,
        index_count: u32,
        instance_count: u32,
        start_index: u32,
        base_vertex: i32,
        _start_instance: u32,
    ) -> u32 {
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::DrawIndexed,
                _pad: [0; 3],
                p: UGPayload::draw_indexed(
                    0,
                    index_count,
                    base_vertex,
                    instance_count,
                    start_index,
                ),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle Draw / DrawPrimitive.
    pub fn on_draw(
        &mut self,
        vertex_count: u32,
        instance_count: u32,
        start_vertex: u32,
        _start_instance: u32,
    ) -> u32 {
        if self.batch_len < INTERCEPT_BATCH_CAP {
            let mut draw_p = UGPayload::zeroed();
            draw_p.u64s[0] = vertex_count as u64;
            draw_p.u64s[1] = instance_count as u64;
            draw_p.u64s[2] = start_vertex as u64;
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::DrawPrimitive,
                _pad: [0; 3],
                p: draw_p,
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle VSSetShader / SetVertexShader.
    pub fn on_vs_set_shader(&mut self, handle_raw: u32) -> u32 {
        let handle = UGHandle(handle_raw);
        self.state.set_vs(handle);
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::SetShader,
                _pad: [0; 3],
                p: UGPayload::set_shader(handle, ShaderStage::Vertex),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle PSSetShader / SetPixelShader.
    pub fn on_ps_set_shader(&mut self, handle_raw: u32) -> u32 {
        let handle = UGHandle(handle_raw);
        self.state.set_ps(handle);
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::SetShader,
                _pad: [0; 3],
                p: UGPayload::set_shader(handle, ShaderStage::Pixel),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle Dispatch (compute).
    pub fn on_dispatch(&mut self, x: u32, y: u32, z: u32) -> u32 {
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::Dispatch,
                _pad: [0; 3],
                p: UGPayload::dispatch(x, y, z),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle Present / IDXGISwapChain::Present.
    pub fn on_present(&mut self, swap_chain_handle: u32) -> u32 {
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::Present,
                _pad: [0; 3],
                p: UGPayload::present(swap_chain_handle),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Handle ClearRenderTargetView / Clear.
    pub fn on_clear_color(&mut self, target: u32, r: f32, g: f32, b: f32, a: f32) -> u32 {
        if self.batch_len < INTERCEPT_BATCH_CAP {
            self.batch[self.batch_len] = UGCommand {
                kind: UGCommandKind::ClearColor,
                _pad: [0; 3],
                p: UGPayload::clear_color(r, g, b, a, UGHandle(target)),
                ..UGCommand::default()
            };
            self.batch_len += 1;
        }
        S_OK
    }

    /// Flush the current batch out to the caller.
    /// Returns the number of commands flushed.
    pub fn flush_batch(&mut self, out: &mut [UGCommand]) -> usize {
        let n = self.batch_len.min(out.len());
        out[..n].copy_from_slice(&self.batch[..n]);
        self.batch_len = 0;
        n
    }

    pub fn batch_len(&self) -> usize {
        self.batch_len
    }
}

// ─── Universal interceptor manager ───────────────────────────────────────────

/// Auto-detecting multi-version manager.  Contains one interceptor per API
/// version (they never coexist on the same guest, but we allocate all four so
/// the manager is statically sized).
pub struct UniversalInterceptorManager {
    pub d3d9: D3DInterceptor,
    pub d3d11: D3DInterceptor,
    pub d3d12: D3DInterceptor,
    pub active_api: D3DVersion,
    pub total_draws: AtomicU32,
    pub total_frames: AtomicU32,
}

impl UniversalInterceptorManager {
    pub const fn new() -> Self {
        Self {
            d3d9: D3DInterceptor::new(D3DVersion::D3D9),
            d3d11: D3DInterceptor::new(D3DVersion::D3D11),
            d3d12: D3DInterceptor::new(D3DVersion::D3D12),
            active_api: D3DVersion::Unknown,
            total_draws: AtomicU32::new(0),
            total_frames: AtomicU32::new(0),
        }
    }

    /// Call when the IronShim agent detects a D3D device creation.
    pub fn detect_api(&mut self, version: D3DVersion) {
        self.active_api = version;
        match version {
            D3DVersion::D3D9 => self.d3d9.arm(),
            D3DVersion::D3D11 => self.d3d11.arm(),
            D3DVersion::D3D12 => self.d3d12.arm(),
            _ => {}
        }
    }

    /// Route a VMCALL event from the VMX handler to the active interceptor.
    ///
    /// `slot` is the vtable slot that triggered the intercept.
    /// `args` contains up to 6 guest registers (RCX–R9 on Windows x64 ABI).
    ///
    /// Returns a HRESULT to write back to the guest RAX.
    pub fn handle_vmcall(&mut self, slot: u32, args: [u64; 6]) -> u32 {
        match self.active_api {
            D3DVersion::D3D9 => self.dispatch_d3d9(slot, args),
            D3DVersion::D3D11 => self.dispatch_d3d11(slot, args),
            D3DVersion::D3D12 => self.dispatch_d3d12(slot, args),
            _ => E_NOTIMPL,
        }
    }

    fn dispatch_d3d9(&mut self, slot: u32, args: [u64; 6]) -> u32 {
        match slot as usize {
            d3d9_slot::DRAW_PRIMITIVE => {
                let _prim_type = args[1] as u32;
                let start_vertex = args[2] as u32;
                let count = args[3] as u32;
                let hr = self.d3d9.on_draw(count * 3, 1, start_vertex, 0);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d9_slot::DRAW_INDEXED_PRIMITIVE => {
                let _prim_type = args[1] as u32;
                let base_vtx = args[2] as i32;
                let _start_vtx = args[3] as u32;
                let _num_vtx = args[4] as u32;
                let start_idx = args[5] as u32;
                let pr_count = args[5] as u32;
                let hr = self
                    .d3d9
                    .on_draw_indexed(pr_count * 3, 1, start_idx, base_vtx, 0);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d9_slot::SET_VERTEX_SHADER => self.d3d9.on_vs_set_shader(args[1] as u32),
            d3d9_slot::SET_PIXEL_SHADER => self.d3d9.on_ps_set_shader(args[1] as u32),
            d3d9_slot::PRESENT => {
                let hr = self.d3d9.on_present(0);
                self.total_frames.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d9_slot::CLEAR => self.d3d9.on_clear_color(0, 0.0, 0.0, 0.0, 1.0),
            _ => S_OK,
        }
    }

    fn dispatch_d3d11(&mut self, slot: u32, args: [u64; 6]) -> u32 {
        match slot as usize {
            d3d11_slot::DRAW => {
                let vertex_count = args[1] as u32;
                let start_vertex = args[2] as u32;
                let hr = self.d3d11.on_draw(vertex_count, 1, start_vertex, 0);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d11_slot::DRAW_INDEXED => {
                let index_count = args[1] as u32;
                let start_index = args[2] as u32;
                let base_vertex = args[3] as i32;
                let hr = self
                    .d3d11
                    .on_draw_indexed(index_count, 1, start_index, base_vertex, 0);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d11_slot::DRAW_INSTANCED => {
                let vc = args[1] as u32;
                let ic = args[2] as u32;
                self.d3d11.on_draw(vc, ic, 0, 0);
                S_OK
            }
            d3d11_slot::DRAW_INDEXED_INSTANCED => {
                let icount = args[1] as u32;
                let ic = args[2] as u32;
                let si = args[3] as u32;
                let bv = args[4] as i32;
                let sti = args[5] as u32;
                self.d3d11.on_draw_indexed(icount, ic, si, bv, sti);
                S_OK
            }
            d3d11_slot::VS_SET_SHADER => self.d3d11.on_vs_set_shader(args[1] as u32),
            d3d11_slot::PS_SET_SHADER => self.d3d11.on_ps_set_shader(args[1] as u32),
            d3d11_slot::DISPATCH => {
                let x = args[1] as u32;
                let y = args[2] as u32;
                let z = args[3] as u32;
                self.d3d11.on_dispatch(x, y, z)
            }
            d3d11_slot::CLEAR_RENDER_TARGET => {
                let rt = args[1] as u32;
                self.d3d11.on_clear_color(rt, 0.0, 0.0, 0.0, 1.0)
            }
            _ => S_OK,
        }
    }

    fn dispatch_d3d12(&mut self, slot: u32, args: [u64; 6]) -> u32 {
        match slot as usize {
            d3d12_slot::DRAW_INDEXED_INSTANCED => {
                let icount = args[1] as u32;
                let ic = args[2] as u32;
                let si = args[3] as u32;
                let bv = args[4] as i32;
                let sti = args[5] as u32;
                let hr = self.d3d12.on_draw_indexed(icount, ic, si, bv, sti);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d12_slot::DRAW_INSTANCED => {
                let vc = args[1] as u32;
                let ic = args[2] as u32;
                let hr = self.d3d12.on_draw(vc, ic, 0, 0);
                self.total_draws.fetch_add(1, Ordering::Relaxed);
                hr
            }
            d3d12_slot::DISPATCH => {
                let x = args[1] as u32;
                let y = args[2] as u32;
                let z = args[3] as u32;
                self.d3d12.on_dispatch(x, y, z)
            }
            d3d12_slot::PRESENT => {
                let hr = self.d3d12.on_present(0);
                self.total_frames.fetch_add(1, Ordering::Relaxed);
                hr
            }
            _ => S_OK,
        }
    }

    /// Flush all queued commands from the active interceptor.
    pub fn flush_active(&mut self, out: &mut [UGCommand]) -> usize {
        match self.active_api {
            D3DVersion::D3D9 => self.d3d9.flush_batch(out),
            D3DVersion::D3D11 => self.d3d11.flush_batch(out),
            D3DVersion::D3D12 => self.d3d12.flush_batch(out),
            _ => 0,
        }
    }

    pub fn total_draws(&self) -> u32 {
        self.total_draws.load(Ordering::Relaxed)
    }
    pub fn total_frames(&self) -> u32 {
        self.total_frames.load(Ordering::Relaxed)
    }
}

impl Default for UniversalInterceptorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vmm::ugir::UGCommandKind;

    // ── HookTable ────────────────────────────────────────────────────────

    #[test]
    fn hook_table_insert_and_find() {
        let mut table = HookTable::new();
        let hook = VtableHook {
            object_ptr: 0xDEAD_BEEF,
            slot: d3d11_slot::DRAW_INDEXED as u32,
            original_fn: 0x1000,
            hook_fn: 0x2000,
            active: true,
            api: D3DVersion::D3D11,
        };
        let idx = table.insert(hook).unwrap();
        assert_eq!(idx, 0);
        let found = table.find(0xDEAD_BEEF, d3d11_slot::DRAW_INDEXED as u32);
        assert!(found.is_some());
        assert_eq!(found.unwrap().hook_fn, 0x2000);
    }

    #[test]
    fn hook_table_remove_object() {
        let mut table = HookTable::new();
        for slot in [0u32, 1, 2] {
            table
                .insert(VtableHook {
                    object_ptr: 0xAAAA,
                    slot,
                    original_fn: 0,
                    hook_fn: 0,
                    active: true,
                    api: D3DVersion::D3D11,
                })
                .unwrap();
        }
        let removed = table.remove_object(0xAAAA);
        assert_eq!(removed, 3);
        assert!(table.find(0xAAAA, 0).is_none());
    }

    // ── D3DInterceptor ───────────────────────────────────────────────────

    #[test]
    fn interceptor_draw_indexed_queues_command() {
        let mut intercept = D3DInterceptor::new(D3DVersion::D3D11);
        let hr = intercept.on_draw_indexed(36, 1, 0, 0, 0);
        assert_eq!(hr, S_OK);
        assert_eq!(intercept.batch_len(), 1);
        assert_eq!(intercept.batch[0].kind, UGCommandKind::DrawIndexed);
    }

    #[test]
    fn interceptor_flush_clears_batch() {
        let mut intercept = D3DInterceptor::new(D3DVersion::D3D11);
        intercept.on_draw(6, 1, 0, 0);
        intercept.on_present(0);
        assert_eq!(intercept.batch_len(), 2);

        let mut out = [UGCommand::default(); 8];
        let flushed = intercept.flush_batch(&mut out);
        assert_eq!(flushed, 2);
        assert_eq!(intercept.batch_len(), 0);
        assert_eq!(out[0].kind, UGCommandKind::DrawPrimitive);
        assert_eq!(out[1].kind, UGCommandKind::Present);
    }

    #[test]
    fn d3d11_dispatch_routes_correctly() {
        let mut intercept = D3DInterceptor::new(D3DVersion::D3D11);
        let hr = intercept.on_dispatch(8, 8, 1);
        assert_eq!(hr, S_OK);
        assert_eq!(intercept.batch_len(), 1);
        assert_eq!(intercept.batch[0].kind, UGCommandKind::Dispatch);
    }

    // ── UniversalInterceptorManager ─────────────────────────────────────

    #[test]
    fn universal_manager_d3d11_draw_indexed() {
        let mut mgr = UniversalInterceptorManager::new();
        mgr.detect_api(D3DVersion::D3D11);

        // Simulate DrawIndexed(36, 1, 0, 0, 0) vmcall
        let args = [0u64, 36, 0, 0, 0, 0]; // args[0] = this ptr (ignored)
        let hr = mgr.handle_vmcall(d3d11_slot::DRAW_INDEXED as u32, args);
        assert_eq!(hr, S_OK);
        assert_eq!(mgr.total_draws(), 1);
    }

    #[test]
    fn universal_manager_d3d9_present_counts_frame() {
        let mut mgr = UniversalInterceptorManager::new();
        mgr.detect_api(D3DVersion::D3D9);

        let args = [0u64; 6];
        mgr.handle_vmcall(d3d9_slot::PRESENT as u32, args);
        assert_eq!(mgr.total_frames(), 1);
    }

    #[test]
    fn universal_manager_d3d12_dispatch() {
        let mut mgr = UniversalInterceptorManager::new();
        mgr.detect_api(D3DVersion::D3D12);

        let args = [0u64, 16, 16, 1, 0, 0];
        let hr = mgr.handle_vmcall(d3d12_slot::DISPATCH as u32, args);
        assert_eq!(hr, S_OK);
    }

    #[test]
    fn universal_manager_flush_active() {
        let mut mgr = UniversalInterceptorManager::new();
        mgr.detect_api(D3DVersion::D3D11);

        let args = [0u64, 6, 0, 0, 0, 0];
        mgr.handle_vmcall(d3d11_slot::DRAW_INDEXED as u32, args);

        let mut out = [UGCommand::default(); 16];
        let n = mgr.flush_active(&mut out);
        assert_eq!(n, 1);
        assert_eq!(out[0].kind, UGCommandKind::DrawIndexed);
    }

    #[test]
    fn d3d_state_tracker_dedup() {
        let mut tracker = D3DStateTracker::new(D3DVersion::D3D11);
        // First set — dirty
        assert!(tracker.set_vs(UGHandle(42)));
        // Second set with same handle — not dirty
        assert!(!tracker.set_vs(UGHandle(42)));
        // Different handle — dirty again
        assert!(tracker.set_vs(UGHandle(99)));
    }
}
