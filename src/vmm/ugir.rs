#![allow(dead_code)]

//! UGIR (Universal GPU IR) — Pillar 3
//! UGIR — Universal Graphics Intermediate Representation
//!
//! All D3D9/10/11/12 API calls are translated into `UGCommand` variants before
//! being forwarded through the IronShim-rs GPU tunnel to either the VFIO PCIe
//! hardware backend or the bare-metal software rasterizer.  No `std`, no heap.

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// ─── Primitive types ─────────────────────────────────────────────────────────

/// Generational handle for GPU resources (textures, buffers, shaders).
/// Upper 8 bits = generation, lower 24 bits = index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct UGHandle(pub u32);

impl UGHandle {
    pub const NULL: UGHandle = UGHandle(0xFFFF_FFFF);

    #[inline]
    pub fn new(generation: u8, index: u32) -> Self {
        debug_assert!(index < (1 << 24));
        UGHandle(((generation as u32) << 24) | (index & 0x00FF_FFFF))
    }

    #[inline]
    pub fn generation(self) -> u8 {
        (self.0 >> 24) as u8
    }

    #[inline]
    pub fn index(self) -> usize {
        (self.0 & 0x00FF_FFFF) as usize
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self == Self::NULL
    }
}

// ─── Texture / buffer formats ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UGFormat {
    Unknown = 0,
    R8G8B8A8Unorm,
    R8G8B8A8Srgb,
    B8G8R8A8Unorm,
    R16F,
    R16G16F,
    R16G16B16A16F,
    R32F,
    R32G32F,
    R32G32B32A32F,
    D24S8,
    D32F,
    // Block-compressed
    Bc1Unorm,
    Bc2Unorm,
    Bc3Unorm,
    Bc4Unorm,
    Bc5Unorm,
    Bc6HUf16,
    Bc7Unorm,
}

// ─── Shader stage ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShaderStage {
    Vertex = 0,
    Pixel,
    Compute,
    Geometry,
    Hull,
    Domain,
}

// ─── Buffer kind ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BufferKind {
    Vertex = 0,
    Index,
    Constant,
    Unordered,
    Staging,
}

// ─── Blend / depth-stencil / rasterizer state (packed to ≤ 64 bytes) ────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct UGBlendState {
    pub enable: u8,
    pub src_factor: u8,
    pub dst_factor: u8,
    pub op: u8,
    pub src_alpha_factor: u8,
    pub dst_alpha_factor: u8,
    pub alpha_op: u8,
    pub write_mask: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct UGDepthState {
    pub depth_test: u8,
    pub depth_write: u8,
    pub depth_func: u8,
    pub stencil_enable: u8,
    pub stencil_ref: u8,
    pub stencil_read_mask: u8,
    pub stencil_write_mask: u8,
    pub _pad: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct UGRasterizerState {
    pub fill_mode: u8, // 0=solid, 1=wireframe
    pub cull_mode: u8, // 0=none, 1=front, 2=back
    pub front_ccw: u8,
    pub depth_clip: u8,
    pub scissor_enable: u8,
    pub msaa: u8,
    pub _pad: [u8; 2],
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct UGPipelineState {
    pub blend: UGBlendState,
    pub depth: UGDepthState,
    pub raster: UGRasterizerState,
    pub vs_id: u32,
    pub ps_id: u32,
    pub gs_id: u32,
    pub hs_id: u32,
    pub ds_id: u32,
    pub prim_topo: u8, // 0=tri, 1=line, 2=point, 3=tri-strip
    pub _pad: [u8; 19],
}

const _PSO_SIZE: () = assert!(core::mem::size_of::<UGPipelineState>() <= 64);

// ─── Viewport / Scissor ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UGViewport {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub min_depth: f32,
    pub max_depth: f32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UGScissorRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

// ─── Shader blob ─────────────────────────────────────────────────────────────

pub const UG_SHADER_BYTECODE_MAX: usize = 4096;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct UGShader {
    pub id: u32,
    pub stage: ShaderStage,
    pub _pad: [u8; 3],
    pub bytecode_len: u16,
    pub _pad2: [u8; 2],
    pub bytecode: [u8; UG_SHADER_BYTECODE_MAX],
}

impl core::fmt::Debug for UGShader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "UGShader {{ id: {}, stage: {:?}, len: {} }}",
            self.id, self.stage, self.bytecode_len
        )
    }
}

// ─── Resource descriptors ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UGBuffer {
    pub handle: UGHandle,
    pub kind: BufferKind,
    pub _pad: [u8; 3],
    pub stride: u16,
    pub _pad2: [u8; 2],
    pub size: u32,
    /// Host-visible GPA of the backing memory.
    pub gpa: u64,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UGTexture {
    pub handle: UGHandle,
    pub format: UGFormat,
    pub mips: u8,
    pub _pad: [u8; 2],
    pub width: u16,
    pub height: u16,
    pub depth: u16,
    /// GPA of mip 0 data.
    pub gpa: u64,
}

// ─── The Universal Command enum ───────────────────────────────────────────────

/// A single renderable or state-change command in API-agnostic form.
///
/// Serialised into a flat `[u8; 512]` slot inside `GpuCommandQueue` for
/// zero-copy IPC across the Valkyrie-V IronShim-rs tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UGCommandKind {
    Nop = 0,
    DrawPrimitive,
    DrawIndexed,
    DrawInstanced,
    DrawIndexedInstanced,
    Dispatch,
    ClearColor,
    ClearDepth,
    ClearStencil,
    SetRenderTarget,
    SetDepthStencilTarget,
    SetShader,
    SetConstantBuffer,
    SetVertexBuffer,
    SetIndexBuffer,
    SetTexture,
    SetViewport,
    SetScissor,
    SetPipelineState,
    CopyResource,
    CopySubresource,
    UpdateSubresource,
    ResolveSubresource,
    Present,
    Fence,
}

/// Fixed-size command packet.  Fits in exactly one cache line × 8.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub struct UGCommand {
    pub kind: UGCommandKind,
    pub _pad: [u8; 3],
    /// Packed payload — interpretation depends on `kind`.
    pub p: UGPayload,
}

impl core::fmt::Debug for UGCommand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UGCommand {{ kind: {:?} }}", self.kind)
    }
}

/// Union-like payload (we use a flat struct + const accessors; no `union` in
/// safe Rust `no_std`).
#[derive(Clone, Copy)]
#[repr(C)]
pub struct UGPayload {
    pub u64s: [u64; 7],
}

impl core::fmt::Debug for UGPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "UGPayload([{:#018x}, ...])", self.u64s[0])
    }
}

// Payload constructors — typed API over the raw u64 array.
impl UGPayload {
    #[inline]
    pub const fn zeroed() -> Self {
        Self { u64s: [0; 7] }
    }

    #[inline]
    pub fn draw_indexed(
        vertex_count: u32,
        index_count: u32,
        base_vertex: i32,
        instance_count: u32,
        start_index: u32,
    ) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = vertex_count as u64;
        p.u64s[1] = index_count as u64;
        p.u64s[2] = base_vertex as u64;
        p.u64s[3] = instance_count as u64;
        p.u64s[4] = start_index as u64;
        p
    }

    #[inline]
    pub fn dispatch(x: u32, y: u32, z: u32) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = x as u64;
        p.u64s[1] = y as u64;
        p.u64s[2] = z as u64;
        p
    }

    #[inline]
    pub fn clear_color(r: f32, g: f32, b: f32, a: f32, handle: UGHandle) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = ((r.to_bits() as u64) << 32) | g.to_bits() as u64;
        p.u64s[1] = ((b.to_bits() as u64) << 32) | a.to_bits() as u64;
        p.u64s[2] = handle.0 as u64;
        p
    }

    #[inline]
    pub fn set_shader(handle: UGHandle, stage: ShaderStage) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = handle.0 as u64;
        p.u64s[1] = stage as u64;
        p
    }

    #[inline]
    pub fn set_viewport(vp: UGViewport) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = ((vp.x.to_bits() as u64) << 32) | vp.y.to_bits() as u64;
        p.u64s[1] = ((vp.width.to_bits() as u64) << 32) | vp.height.to_bits() as u64;
        p.u64s[2] = ((vp.min_depth.to_bits() as u64) << 32) | vp.max_depth.to_bits() as u64;
        p
    }

    #[inline]
    pub fn set_render_target(handle: UGHandle, slot: u8) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = (handle.0 as u64) | ((slot as u64) << 32);
        p
    }

    #[inline]
    pub fn present(sync_interval: u32) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = sync_interval as u64;
        p
    }

    #[inline]
    pub fn fence(id: u64) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = id;
        p
    }

    #[inline]
    pub fn update_subresource(dst: UGHandle, src_gpa: u64, size: u32) -> Self {
        let mut p = Self::zeroed();
        p.u64s[0] = dst.0 as u64;
        p.u64s[1] = src_gpa;
        p.u64s[2] = size as u64;
        p
    }
}

// ─── Command batch (one frame's draw calls) ───────────────────────────────────

pub const BATCH_CMD_MAX: usize = 256;

/// A complete frame command batch tunnelled in one GpuCommandQueue slot series.
#[repr(C)]
pub struct CommandBatch {
    pub cmds: [UGCommand; BATCH_CMD_MAX],
    pub count: u16,
    pub _pad: [u8; 6],
}

impl CommandBatch {
    pub const fn new() -> Self {
        const NOP: UGCommand = UGCommand {
            kind: UGCommandKind::Nop,
            _pad: [0; 3],
            p: UGPayload { u64s: [0; 7] },
        };
        Self {
            cmds: [NOP; BATCH_CMD_MAX],
            count: 0,
            _pad: [0; 6],
        }
    }

    /// Push a command.  Returns `false` when batch is full.
    #[inline]
    pub fn push(&mut self, cmd: UGCommand) -> bool {
        if self.count as usize >= BATCH_CMD_MAX {
            return false;
        }
        self.cmds[self.count as usize] = cmd;
        self.count += 1;
        true
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// Serialise the batch header + command array into raw bytes for the ring queue.
    pub fn to_bytes(&self, dst: &mut [u8]) -> usize {
        let needed = 2 + core::mem::size_of::<UGCommand>() * self.count as usize;
        if dst.len() < needed {
            return 0;
        }
        dst[0..2].copy_from_slice(&self.count.to_le_bytes());
        for i in 0..self.count as usize {
            let off = 2 + i * core::mem::size_of::<UGCommand>();
            let raw = unsafe {
                core::slice::from_raw_parts(
                    &self.cmds[i] as *const UGCommand as *const u8,
                    core::mem::size_of::<UGCommand>(),
                )
            };
            dst[off..off + raw.len()].copy_from_slice(raw);
        }
        needed
    }
}

impl Default for CommandBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Generational resource arena ─────────────────────────────────────────────

pub struct UGResourceArena<T: Copy, const N: usize> {
    slots: [Option<T>; N],
    generations: [u8; N],
    free_head: AtomicUsize,
    count: AtomicU32,
}

impl<T: Copy, const N: usize> UGResourceArena<T, N> {
    pub const fn new_uninit() -> Self {
        // const-compatible: can't call `[None; N]` with runtime-sized N in stable,
        // but we overlay with MaybeUninit and zeroed bytes.
        Self {
            slots: [None; N],
            generations: [0u8; N],
            free_head: AtomicUsize::new(0),
            count: AtomicU32::new(0),
        }
    }

    pub fn allocate(&mut self, value: T) -> Option<UGHandle> {
        for i in 0..N {
            if self.slots[i].is_none() {
                self.slots[i] = Some(value);
                self.count.fetch_add(1, Ordering::Relaxed);
                return Some(UGHandle::new(self.generations[i], i as u32));
            }
        }
        None
    }

    pub fn get(&self, handle: UGHandle) -> Option<&T> {
        let idx = handle.index();
        if idx >= N {
            return None;
        }
        if self.generations[idx] != handle.generation() {
            return None;
        }
        self.slots[idx].as_ref()
    }

    pub fn get_mut(&mut self, handle: UGHandle) -> Option<&mut T> {
        let idx = handle.index();
        if idx >= N {
            return None;
        }
        if self.generations[idx] != handle.generation() {
            return None;
        }
        self.slots[idx].as_mut()
    }

    pub fn free(&mut self, handle: UGHandle) -> bool {
        let idx = handle.index();
        if idx >= N {
            return false;
        }
        if self.generations[idx] != handle.generation() {
            return false;
        }
        self.slots[idx] = None;
        self.generations[idx] = self.generations[idx].wrapping_add(1);
        self.count.fetch_sub(1, Ordering::Relaxed);
        true
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Relaxed)
    }
}

// ─── Delta-state tracker ──────────────────────────────────────────────────────

/// Tracks which pipeline state fields have changed since the last flush so
/// only diffs are sent through the tunnel (bandwidth optimisation).
pub struct DeltaStateTracker {
    current_vs: u32,
    current_ps: u32,
    current_rt: [UGHandle; 8],
    current_ds: UGHandle,
    current_vp: UGViewport,
    dirty_bits: u32,
}

// dirty_bits flags
pub const DIRTY_VS: u32 = 1 << 0;
pub const DIRTY_PS: u32 = 1 << 1;
pub const DIRTY_RT: u32 = 1 << 2;
pub const DIRTY_DS: u32 = 1 << 3;
pub const DIRTY_VP: u32 = 1 << 4;

impl DeltaStateTracker {
    pub const fn new() -> Self {
        Self {
            current_vs: u32::MAX,
            current_ps: u32::MAX,
            current_rt: [UGHandle::NULL; 8],
            current_ds: UGHandle::NULL,
            current_vp: UGViewport {
                x: 0.0,
                y: 0.0,
                width: 0.0,
                height: 0.0,
                min_depth: 0.0,
                max_depth: 1.0,
            },
            dirty_bits: 0xFFFF_FFFF, // all dirty on init
        }
    }

    pub fn set_vs(&mut self, id: u32) {
        if self.current_vs != id {
            self.current_vs = id;
            self.dirty_bits |= DIRTY_VS;
        }
    }

    pub fn set_ps(&mut self, id: u32) {
        if self.current_ps != id {
            self.current_ps = id;
            self.dirty_bits |= DIRTY_PS;
        }
    }

    pub fn set_render_target(&mut self, slot: usize, handle: UGHandle) {
        if slot < 8 && self.current_rt[slot] != handle {
            self.current_rt[slot] = handle;
            self.dirty_bits |= DIRTY_RT;
        }
    }

    pub fn set_viewport(&mut self, vp: UGViewport) {
        self.current_vp = vp;
        self.dirty_bits |= DIRTY_VP;
    }

    /// Drain dirty bits and emit delta commands into `batch`.
    pub fn flush_into(&mut self, batch: &mut CommandBatch) {
        if self.dirty_bits & DIRTY_VS != 0 && self.current_vs != u32::MAX {
            batch.push(UGCommand {
                kind: UGCommandKind::SetShader,
                _pad: [0; 3],
                p: UGPayload::set_shader(UGHandle(self.current_vs), ShaderStage::Vertex),
            });
        }
        if self.dirty_bits & DIRTY_PS != 0 && self.current_ps != u32::MAX {
            batch.push(UGCommand {
                kind: UGCommandKind::SetShader,
                _pad: [0; 3],
                p: UGPayload::set_shader(UGHandle(self.current_ps), ShaderStage::Pixel),
            });
        }
        if self.dirty_bits & DIRTY_RT != 0 {
            batch.push(UGCommand {
                kind: UGCommandKind::SetRenderTarget,
                _pad: [0; 3],
                p: UGPayload::set_render_target(self.current_rt[0], 0),
            });
        }
        if self.dirty_bits & DIRTY_VP != 0 {
            batch.push(UGCommand {
                kind: UGCommandKind::SetViewport,
                _pad: [0; 3],
                p: UGPayload::set_viewport(self.current_vp),
            });
        }
        self.dirty_bits = 0;
    }
}

impl Default for DeltaStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_roundtrip() {
        let h = UGHandle::new(7, 0x123456);
        assert_eq!(h.generation(), 7);
        assert_eq!(h.index(), 0x123456);
        assert!(!h.is_null());
        assert!(UGHandle::NULL.is_null());
    }

    #[test]
    fn command_batch_push_and_serialise() {
        let mut batch = CommandBatch::new();
        assert!(batch.is_empty());

        let cmd = UGCommand {
            kind: UGCommandKind::Present,
            _pad: [0; 3],
            p: UGPayload::present(0),
        };
        assert!(batch.push(cmd));
        assert_eq!(batch.len(), 1);

        let mut buf = [0u8; 8192];
        let written = batch.to_bytes(&mut buf);
        assert!(written > 2);
        let count = u16::from_le_bytes([buf[0], buf[1]]);
        assert_eq!(count, 1);
    }

    #[test]
    fn resource_arena_alloc_free() {
        let mut arena: UGResourceArena<u32, 4> = UGResourceArena::new_uninit();
        let h1 = arena.allocate(42u32).unwrap();
        let h2 = arena.allocate(99u32).unwrap();
        assert_eq!(*arena.get(h1).unwrap(), 42);
        assert_eq!(arena.count(), 2);
        arena.free(h1);
        assert_eq!(arena.count(), 1);
        // Stale handle rejected after generation bump
        assert!(arena.get(h1).is_none());
        let h3 = arena.allocate(7u32).unwrap();
        assert_ne!(h3.generation(), h1.generation()); // generation bumped
        let _ = (h2, h3);
    }

    #[test]
    fn delta_state_tracker_only_emits_dirty() {
        let mut tracker = DeltaStateTracker::new();
        let mut batch = CommandBatch::new();
        // Initial flush emits everything dirty
        tracker.flush_into(&mut batch);
        let initial_len = batch.len();
        assert!(initial_len > 0);

        // Second flush with no changes emits nothing
        let mut batch2 = CommandBatch::new();
        tracker.flush_into(&mut batch2);
        assert_eq!(batch2.len(), 0);

        // Change VS → only VS emitted
        let mut batch3 = CommandBatch::new();
        tracker.set_vs(5);
        tracker.flush_into(&mut batch3);
        assert_eq!(batch3.len(), 1);
        assert!(matches!(batch3.cmds[0].kind, UGCommandKind::SetShader));
    }

    #[test]
    fn pipeline_state_size_bound() {
        assert!(core::mem::size_of::<UGPipelineState>() <= 64);
    }
}
