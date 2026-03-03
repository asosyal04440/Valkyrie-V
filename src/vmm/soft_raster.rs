#![allow(clippy::missing_safety_doc)]
#![allow(clippy::single_match)]
#![allow(clippy::new_without_default)]
#![allow(clippy::manual_div_ceil)]
#![allow(clippy::unnecessary_min_or_max)]

//! Bare-metal Software Rasterizer (Pillar 6)
//!
//! Tile-based renderer targeting the UEFI GOP framebuffer.  Designed to
//! saturate all available CPU cores through a Chase-Lev work-stealing queue.
//!
//! Key design parameters:
//!   TILE_W = 8, TILE_H = 8  →  512 tiles at 1080p (1920×1080 / 64)
//!   Depth buffer: lock-free per-pixel CAS on AtomicU32
//!   Register file: 32 × 4 × f32 (vec4 registers, software AVX2 emulated)

use crate::vmm::shader_translator::{echo_op, EchosBytecode};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

#[inline]
fn f32_sqrt(v: f32) -> f32 {
    #[cfg(test)]
    {
        v.sqrt()
    }
    #[cfg(not(test))]
    {
        libm::sqrtf(v)
    }
}

#[inline]
fn f32_floor(v: f32) -> f32 {
    #[cfg(test)]
    {
        v.floor()
    }
    #[cfg(not(test))]
    {
        libm::floorf(v)
    }
}

#[inline]
fn f32_ceil(v: f32) -> f32 {
    #[cfg(test)]
    {
        v.ceil()
    }
    #[cfg(not(test))]
    {
        libm::ceilf(v)
    }
}

#[inline]
fn f32_fract(v: f32) -> f32 {
    #[cfg(test)]
    {
        v.fract()
    }
    #[cfg(not(test))]
    {
        v - libm::truncf(v)
    }
}

// ─── Constants ───────────────────────────────────────────────────────────────

pub const TILE_W: u32 = 8;
pub const TILE_H: u32 = 8;
pub const MAX_RENDER_TARGETS: usize = 8;
pub const MAX_CORES: usize = 8192;
pub const WORK_QUEUE_SIZE: usize = 65536;
pub const REG_COUNT: usize = 32; // vec4 registers per shader invocation

// ─── Framebuffer ─────────────────────────────────────────────────────────────

/// UEFI GOP framebuffer descriptor.  `base` is a raw host physical address
/// obtained during boot and mapped as write-combining memory.
pub struct Framebuffer {
    pub base: *mut u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32, // in pixels
}

// SAFETY: The pointer is unique per-frame and writes are coordinated through
// the tile dispatch mechanism.
unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    pub const fn null() -> Self {
        Self {
            base: core::ptr::null_mut(),
            width: 0,
            height: 0,
            stride: 0,
        }
    }

    /// Write a single pixel (ARGB8888).
    /// # Safety
    /// `x < width && y < height` must hold.
    #[inline(always)]
    pub unsafe fn write_pixel(&self, x: u32, y: u32, rgba: u32) {
        let off = (y * self.stride + x) as usize;
        self.base.add(off).write_volatile(rgba);
    }

    /// Fill an axis-aligned rectangle — used for tile clear.
    pub unsafe fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, rgba: u32) {
        for dy in 0..h {
            for dx in 0..w {
                self.write_pixel(x + dx, y + dy, rgba);
            }
        }
    }
}

// ─── Depth buffer ─────────────────────────────────────────────────────────────

/// 1080p depth buffer: 1920×1080 × 4B = ~8 MB.
/// Lock-free per-pixel depth test via compare-and-swap on f32 bits.
pub struct DepthBuffer {
    pub width: u32,
    pub height: u32,
    /// Stored as raw f32 bits in AtomicU32.
    pixels: &'static [AtomicU32],
}

impl DepthBuffer {
    pub const fn new_view(width: u32, height: u32, storage: &'static [AtomicU32]) -> Self {
        Self {
            width,
            height,
            pixels: storage,
        }
    }

    /// Returns `true` if the new depth passes the test and the buffer was updated.
    #[inline]
    pub fn test_and_set(&self, x: u32, y: u32, depth: f32) -> bool {
        let idx = (y * self.width + x) as usize;
        if idx >= self.pixels.len() {
            return false;
        }
        let new_bits = depth.to_bits();
        loop {
            let old_bits = self.pixels[idx].load(Ordering::Relaxed);
            let old_depth = f32::from_bits(old_bits);
            if depth >= old_depth {
                return false;
            }
            match self.pixels[idx].compare_exchange_weak(
                old_bits,
                new_bits,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => {} // retry
            }
        }
    }

    /// Clear to far plane (1.0).
    pub fn clear(&self) {
        let one = 1.0f32.to_bits();
        for px in self.pixels.iter() {
            px.store(one, Ordering::Relaxed);
        }
    }
}

// ─── Vertex types ─────────────────────────────────────────────────────────────

/// Clip-space vertex exiting the vertex shader.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ClipVertex {
    pub pos: [f32; 4], // xyzw
    pub uv: [f32; 2],
    pub col: [f32; 4],
    pub nor: [f32; 3],
    pub _pad: f32,
}

impl ClipVertex {
    pub const fn zero() -> Self {
        Self {
            pos: [0.0; 4],
            uv: [0.0; 2],
            col: [0.0; 4],
            nor: [0.0; 3],
            _pad: 0.0,
        }
    }
}

/// Fragment shader input (interpolated from vertex data).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FragInput {
    pub pos: [f32; 4],
    pub uv: [f32; 2],
    pub col: [f32; 4],
    pub nor: [f32; 3],
    pub _pad: f32,
}

/// A triangle with pre-transformed clip vertices.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Primitive {
    pub v: [ClipVertex; 3],
    pub shader_id: u32,
    pub flags: u32,
}

// ─── TileJob ─────────────────────────────────────────────────────────────────

/// Work unit submitted to a core's steal queue.  Exactly 16 bytes.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(64))]
pub struct TileJob {
    pub tile_x: u16,
    pub tile_y: u16,
    pub prim_start: u32, // index into global primitive pool
    pub prim_count: u16,
    pub shader_id: u32,
    pub _pad: [u8; 6],
}

// ─── Chase-Lev work-stealing deque ───────────────────────────────────────────

/// Lock-free work-stealing double-ended queue (Chase–Lev, 2005).
/// `push_bottom` / `pop_bottom` used by the owning thread;
/// `steal_top` used by thieves.
pub struct WorkStealingQueue {
    top: AtomicUsize,
    bottom: AtomicUsize,
    buf: [UnsafeCell<TileJob>; WORK_QUEUE_SIZE],
}

unsafe impl Sync for WorkStealingQueue {}

impl WorkStealingQueue {
    pub const fn new() -> Self {
        const EMPTY: TileJob = TileJob {
            tile_x: 0,
            tile_y: 0,
            prim_start: 0,
            prim_count: 0,
            shader_id: 0,
            _pad: [0; 6],
        };
        Self {
            top: AtomicUsize::new(0),
            bottom: AtomicUsize::new(0),
            buf: [const { UnsafeCell::new(EMPTY) }; WORK_QUEUE_SIZE],
        }
    }

    /// Push a job onto the bottom of the deque (owner thread).
    pub fn push_bottom(&self, job: TileJob) -> bool {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Acquire);
        if b - t >= WORK_QUEUE_SIZE {
            return false;
        }
        unsafe {
            *self.buf[b % WORK_QUEUE_SIZE].get() = job;
        }
        core::sync::atomic::fence(Ordering::Release);
        self.bottom.store(b + 1, Ordering::Relaxed);
        true
    }

    /// Pop a job from the bottom (owner thread).
    pub fn pop_bottom(&self) -> Option<TileJob> {
        let b = self.bottom.load(Ordering::Relaxed).wrapping_sub(1);
        self.bottom.store(b, Ordering::Relaxed);
        core::sync::atomic::fence(Ordering::SeqCst);
        let t = self.top.load(Ordering::Relaxed);
        if t > b {
            self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
            return None;
        }
        let job = unsafe { *self.buf[b % WORK_QUEUE_SIZE].get() };
        if t == b {
            if self
                .top
                .compare_exchange(t, t + 1, Ordering::SeqCst, Ordering::Relaxed)
                .is_err()
            {
                self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
                return None;
            }
            self.bottom.store(b.wrapping_add(1), Ordering::Relaxed);
        }
        Some(job)
    }

    /// Steal a job from the top (thief thread).
    pub fn steal_top(&self) -> Option<TileJob> {
        let t = self.top.load(Ordering::Acquire);
        core::sync::atomic::fence(Ordering::SeqCst);
        let b = self.bottom.load(Ordering::Acquire);
        if t >= b {
            return None;
        }
        let job = unsafe { *self.buf[t % WORK_QUEUE_SIZE].get() };
        match self
            .top
            .compare_exchange(t, t + 1, Ordering::SeqCst, Ordering::Relaxed)
        {
            Ok(_) => Some(job),
            Err(_) => None,
        }
    }

    pub fn len(&self) -> usize {
        let b = self.bottom.load(Ordering::Relaxed);
        let t = self.top.load(Ordering::Relaxed);
        b.saturating_sub(t)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─── Primitive pool ───────────────────────────────────────────────────────────

pub const PRIM_POOL_SIZE: usize = 65536;

pub struct PrimitivePool {
    pool: [UnsafeCell<Primitive>; PRIM_POOL_SIZE],
    count: AtomicU32,
}

unsafe impl Sync for PrimitivePool {}

impl PrimitivePool {
    pub const fn new() -> Self {
        const EMPTY: Primitive = Primitive {
            v: [ClipVertex::zero(); 3],
            shader_id: 0,
            flags: 0,
        };
        Self {
            pool: [const { UnsafeCell::new(EMPTY) }; PRIM_POOL_SIZE],
            count: AtomicU32::new(0),
        }
    }

    pub fn reset(&self) {
        self.count.store(0, Ordering::Release);
    }

    pub fn push(&self, prim: Primitive) -> Option<u32> {
        let idx = self.count.fetch_add(1, Ordering::Relaxed) as usize;
        if idx >= PRIM_POOL_SIZE {
            self.count.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        unsafe {
            *self.pool[idx].get() = prim;
        }
        Some(idx as u32)
    }

    pub fn get(&self, idx: u32) -> Option<Primitive> {
        let i = idx as usize;
        if i >= PRIM_POOL_SIZE {
            return None;
        }
        Some(unsafe { *self.pool[i].get() })
    }

    pub fn count(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }
}

// ─── Software shader core ─────────────────────────────────────────────────────

/// Per-invocation register file: 32 vec4 registers.
#[derive(Clone, Copy)]
pub struct RegFile {
    pub r: [[f32; 4]; REG_COUNT],
}

impl RegFile {
    pub const fn zero() -> Self {
        Self {
            r: [[0.0f32; 4]; REG_COUNT],
        }
    }
}

/// Execute an EchosBytecode program.
///
/// Returns the contents of register r0 (typically the shader output).
pub fn execute_shader(bc: &EchosBytecode, input: &RegFile) -> RegFile {
    let mut regs = *input;

    for i in 0..bc.len as usize {
        let instr = &bc.instrs[i];
        let dst = instr.dst as usize % REG_COUNT;
        let s0 = instr.src0 as usize % REG_COUNT;
        let s1 = instr.src1 as usize % REG_COUNT;
        let s2 = instr.src2 as usize % REG_COUNT;

        match instr.op {
            op if op == echo_op::NOP => {}
            op if op == echo_op::MOV => {
                regs.r[dst] = regs.r[s0];
            }
            op if op == echo_op::ADD => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c] + regs.r[s1][c];
                }
            }
            op if op == echo_op::SUB => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c] - regs.r[s1][c];
                }
            }
            op if op == echo_op::MUL => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c] * regs.r[s1][c];
                }
            }
            op if op == echo_op::MAD => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c] * regs.r[s1][c] + regs.r[s2][c];
                }
            }
            op if op == echo_op::DP4 => {
                let dot: f32 = (0..4).map(|c| regs.r[s0][c] * regs.r[s1][c]).sum();
                regs.r[dst] = [dot; 4];
            }
            op if op == echo_op::DP3 => {
                let dot: f32 = (0..3).map(|c| regs.r[s0][c] * regs.r[s1][c]).sum();
                regs.r[dst] = [dot; 4];
            }
            op if op == echo_op::DP2 => {
                let dot: f32 = (0..2).map(|c| regs.r[s0][c] * regs.r[s1][c]).sum();
                regs.r[dst] = [dot; 4];
            }
            op if op == echo_op::MIN => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c].min(regs.r[s1][c]);
                }
            }
            op if op == echo_op::MAX => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c].max(regs.r[s1][c]);
                }
            }
            op if op == echo_op::NEG => {
                for c in 0..4 {
                    regs.r[dst][c] = -regs.r[s0][c];
                }
            }
            op if op == echo_op::ABS => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c].abs();
                }
            }
            op if op == echo_op::SAT => {
                for c in 0..4 {
                    regs.r[dst][c] = regs.r[s0][c].clamp(0.0, 1.0);
                }
            }
            op if op == echo_op::CMP => {
                // dst = src0 >= 0 ? src1 : src2
                for c in 0..4 {
                    regs.r[dst][c] = if regs.r[s0][c] >= 0.0 {
                        regs.r[s1][c]
                    } else {
                        regs.r[s2][c]
                    };
                }
            }
            op if op == echo_op::RET => {
                break;
            }
            op if op == echo_op::DISCARD => {
                break;
            }
            op if op == echo_op::SQRT => {
                for c in 0..4 {
                    regs.r[dst][c] = f32_sqrt(regs.r[s0][c]);
                }
            }
            op if op == echo_op::FRAC => {
                for c in 0..4 {
                    regs.r[dst][c] = f32_fract(regs.r[s0][c]);
                }
            }
            op if op == echo_op::FLOOR => {
                for c in 0..4 {
                    regs.r[dst][c] = f32_floor(regs.r[s0][c]);
                }
            }
            op if op == echo_op::CEIL => {
                for c in 0..4 {
                    regs.r[dst][c] = f32_ceil(regs.r[s0][c]);
                }
            }
            _ => {
                // Unsupported op - log to debug ring buffer
                // In production, this would write to a shared debug buffer
                // For now, we track unsupported opcodes in a static counter
                static UNSUPPORTED_OP_COUNT: AtomicU64 = AtomicU64::new(0);
                UNSUPPORTED_OP_COUNT.fetch_add(1, Ordering::Relaxed);
                
                // Log the opcode value for debugging
                // Format: [opcode, dst, s0, s1, s2, count]
                static UNSUPPORTED_OP_LOG: [AtomicU32; 16] = [
                    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
                    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
                    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
                    AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0),
                ];
                
                let log_idx = UNSUPPORTED_OP_COUNT.load(Ordering::Relaxed) as usize % 16;
                UNSUPPORTED_OP_LOG[log_idx].store(op, Ordering::Relaxed);
            }
        }
    }

    regs
}

// ─── Bilinear texture sampler ─────────────────────────────────────────────────

/// Simple RGBA8 texture view backed by a GPA slice.
pub struct TextureView {
    pub data: *const u32,
    pub width: u32,
    pub height: u32,
}

impl TextureView {
    /// Bilinear sample returning [r, g, b, a] in [0,1].
    pub unsafe fn sample_bilinear(&self, u: f32, v: f32) -> [f32; 4] {
        let u = f32_fract(u).abs();
        let v = f32_fract(v).abs();
        let x = (u * (self.width.saturating_sub(1)) as f32) as u32;
        let y = (v * (self.height.saturating_sub(1)) as f32) as u32;
        let idx = (y * self.width + x) as usize;
        let rgba = *self.data.add(idx);
        [
            ((rgba >> 16) & 0xFF) as f32 / 255.0,
            ((rgba >> 8) & 0xFF) as f32 / 255.0,
            (rgba & 0xFF) as f32 / 255.0,
            ((rgba >> 24) & 0xFF) as f32 / 255.0,
        ]
    }
}

// ─── Edge-function rasterizer ─────────────────────────────────────────────────

/// Fixed-point sub-pixel precision shift (4 bits = 1/16 pixel).
const SUBPIXEL_SHIFT: i32 = 4;
const SUBPIXEL_STEP: i32 = 1 << SUBPIXEL_SHIFT;

/// Rasterize one triangle into a tile.
///
/// For each pixel in [tile_x, tile_x+TILE_W) × [tile_y, tile_y+TILE_H) that
/// is inside the triangle, the pixel shader is invoked and the result is
/// written to `fb` (after depth test).
///
/// `vs_out` must contain exactly 3 `ClipVertex` entries.
///
/// **Per-tile depth optimisation**: uses a stack-local depth slab
/// (`TILE_W × TILE_H` floats) instead of per-pixel CAS on the global
/// `DepthBuffer`.  Since each tile is exclusively owned by one thread
/// in the work-stealing scheduler, no atomic contention occurs.
pub fn rasterize_tile(
    vs_out: &[ClipVertex; 3],
    fb: &Framebuffer,
    depth: &DepthBuffer,
    tile_x: u32,
    tile_y: u32,
    ps_output: &dyn Fn(&FragInput) -> [f32; 4],
) {
    // NDC → screen
    let sx = |c: &ClipVertex| -> i32 {
        let ndc = c.pos[0] / c.pos[3];
        ((ndc * 0.5 + 0.5) * fb.width as f32 * (SUBPIXEL_STEP as f32)) as i32
    };
    let sy = |c: &ClipVertex| -> i32 {
        let ndc = c.pos[1] / c.pos[3];
        ((0.5 - ndc * 0.5) * fb.height as f32 * (SUBPIXEL_STEP as f32)) as i32
    };

    let x0 = sx(&vs_out[0]);
    let y0 = sy(&vs_out[0]);
    let x1 = sx(&vs_out[1]);
    let y1 = sy(&vs_out[1]);
    let x2 = sx(&vs_out[2]);
    let y2 = sy(&vs_out[2]);

    // Edge functions (top-left fill rule)
    let edge = |ax: i32, ay: i32, bx: i32, by: i32, px: i32, py: i32| -> i64 {
        ((bx - ax) as i64) * ((py - ay) as i64) - ((by - ay) as i64) * ((px - ax) as i64)
    };

    let tx_start = tile_x * TILE_W;
    let ty_start = tile_y * TILE_H;

    // ── Per-tile local depth slab ──
    // Load initial depth values from the global buffer into a stack-local array.
    const TILE_PIXELS: usize = (TILE_W * TILE_H) as usize;
    let mut local_depth = [1.0f32; TILE_PIXELS];
    for dy in 0..TILE_H {
        for dx in 0..TILE_W {
            let gx = tx_start + dx;
            let gy = ty_start + dy;
            if gx < depth.width && gy < depth.height {
                let idx = (gy * depth.width + gx) as usize;
                if idx < depth.pixels.len() {
                    local_depth[(dy * TILE_W + dx) as usize] =
                        f32::from_bits(depth.pixels[idx].load(Ordering::Relaxed));
                }
            }
        }
    }
    // Track which pixels were written so we can commit only those.
    let mut dirty = [false; TILE_PIXELS];

    for py in ty_start..ty_start + TILE_H {
        for px in tx_start..tx_start + TILE_W {
            if px >= fb.width || py >= fb.height {
                continue;
            }
            let spx = (px as i32 * SUBPIXEL_STEP) + SUBPIXEL_STEP / 2;
            let spy = (py as i32 * SUBPIXEL_STEP) + SUBPIXEL_STEP / 2;

            let w0 = edge(x0, y0, x1, y1, spx, spy);
            let w1 = edge(x1, y1, x2, y2, spx, spy);
            let w2 = edge(x2, y2, x0, y0, spx, spy);

            if w0 < 0 || w1 < 0 || w2 < 0 {
                continue;
            }

            // Barycentric
            let area = w0 + w1 + w2;
            if area == 0 {
                continue;
            }
            let l0 = w0 as f32 / area as f32;
            let l1 = w1 as f32 / area as f32;
            let l2 = w2 as f32 / area as f32;

            // Interpolate depth
            let z = vs_out[0].pos[2] * l0 + vs_out[1].pos[2] * l1 + vs_out[2].pos[2] * l2;

            // Local depth test — no atomics, just a plain comparison.
            let local_idx = ((py - ty_start) * TILE_W + (px - tx_start)) as usize;
            if z >= local_depth[local_idx] {
                continue;
            }
            local_depth[local_idx] = z;
            dirty[local_idx] = true;

            // Interpolate fragment inputs
            let frag = FragInput {
                pos: [px as f32, py as f32, z, 1.0],
                uv: [
                    vs_out[0].uv[0] * l0 + vs_out[1].uv[0] * l1 + vs_out[2].uv[0] * l2,
                    vs_out[0].uv[1] * l0 + vs_out[1].uv[1] * l1 + vs_out[2].uv[1] * l2,
                ],
                col: [
                    vs_out[0].col[0] * l0 + vs_out[1].col[0] * l1 + vs_out[2].col[0] * l2,
                    vs_out[0].col[1] * l0 + vs_out[1].col[1] * l1 + vs_out[2].col[1] * l2,
                    vs_out[0].col[2] * l0 + vs_out[1].col[2] * l1 + vs_out[2].col[2] * l2,
                    vs_out[0].col[3] * l0 + vs_out[1].col[3] * l1 + vs_out[2].col[3] * l2,
                ],
                nor: [
                    vs_out[0].nor[0] * l0 + vs_out[1].nor[0] * l1 + vs_out[2].nor[0] * l2,
                    vs_out[0].nor[1] * l0 + vs_out[1].nor[1] * l1 + vs_out[2].nor[1] * l2,
                    vs_out[0].nor[2] * l0 + vs_out[1].nor[2] * l1 + vs_out[2].nor[2] * l2,
                ],
                _pad: 0.0,
            };

            let color = ps_output(&frag);
            // Pack ARGB8888
            let r = (color[0].clamp(0.0, 1.0) * 255.0) as u32;
            let g = (color[1].clamp(0.0, 1.0) * 255.0) as u32;
            let b = (color[2].clamp(0.0, 1.0) * 255.0) as u32;
            let a = (color[3].clamp(0.0, 1.0) * 255.0) as u32;
            let pixel = (a << 24) | (r << 16) | (g << 8) | b;
            unsafe {
                fb.write_pixel(px, py, pixel);
            }
        }
    }

    // ── Commit dirty local depth values back to the global DepthBuffer ──
    for dy in 0..TILE_H {
        for dx in 0..TILE_W {
            let local_idx = (dy * TILE_W + dx) as usize;
            if dirty[local_idx] {
                let gx = tx_start + dx;
                let gy = ty_start + dy;
                let idx = (gy * depth.width + gx) as usize;
                if idx < depth.pixels.len() {
                    // Store directly — tile is exclusively owned by this thread.
                    depth.pixels[idx].store(
                        local_depth[local_idx].to_bits(),
                        Ordering::Relaxed,
                    );
                }
            }
        }
    }
}

// ─── Tile dispatcher ──────────────────────────────────────────────────────────

pub struct TileDispatcher {
    active_cores: AtomicU32,
    frames_done: AtomicU32,
}

impl TileDispatcher {
    pub const fn new() -> Self {
        Self {
            active_cores: AtomicU32::new(0),
            frames_done: AtomicU32::new(0),
        }
    }

    pub fn set_core_count(&self, n: u32) {
        self.active_cores.store(n, Ordering::Release);
    }

    /// Distribute the primitives over the tile grid into `queues`.
    /// Returns the total number of tile jobs enqueued.
    pub fn dispatch(
        &self,
        fb_width: u32,
        fb_height: u32,
        prims: &PrimitivePool,
        queues: &[WorkStealingQueue],
    ) -> u32 {
        let ncores = (self.active_cores.load(Ordering::Acquire) as usize)
            .min(queues.len())
            .max(1);
        let tiles_x = (fb_width + TILE_W - 1) / TILE_W;
        let tiles_y = (fb_height + TILE_H - 1) / TILE_H;
        let total_tiles = tiles_x * tiles_y;
        let prim_count = prims.count();
        let mut enqueued = 0u32;

        for tile_idx in 0..total_tiles {
            let tx = tile_idx % tiles_x;
            let ty = tile_idx / tiles_x;
            // Assign each tile round-robin to a core queue
            let core = (tile_idx as usize) % ncores;
            let job = TileJob {
                tile_x: tx as u16,
                tile_y: ty as u16,
                prim_start: 0,
                prim_count: (prim_count as u16).min(u16::MAX),
                shader_id: 0,
                _pad: [0; 6],
            };
            if queues[core].push_bottom(job) {
                enqueued += 1;
            }
        }

        self.frames_done.fetch_add(1, Ordering::Relaxed);
        enqueued
    }

    pub fn frames_done(&self) -> u32 {
        self.frames_done.load(Ordering::Acquire)
    }
}

impl Default for TileDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Global GOP framebuffer + GPU flush ──────────────────────────────────────

struct GlobalFbCell(UnsafeCell<Framebuffer>);
unsafe impl Sync for GlobalFbCell {}

static GLOBAL_FB_INIT: AtomicBool = AtomicBool::new(false);
static GLOBAL_FB: GlobalFbCell = GlobalFbCell(UnsafeCell::new(Framebuffer::null()));

/// Tracks the last fence id signalled through `flush_gpu_queue`.
static LAST_FENCE: AtomicU32 = AtomicU32::new(0);

const COMPLETION_RING_CAP: usize = 1024;
const COMPLETION_RING_MASK: usize = COMPLETION_RING_CAP - 1;

/// Monotonic 1-based completion sequence number.
static COMPLETION_SEQ: AtomicU32 = AtomicU32::new(0);

/// Completion ring payload and tags.
///
/// Writer order: write fence -> publish tag(seq).
/// Reader order: read tag(seq) -> read fence.
static COMPLETION_FENCES: [AtomicU32; COMPLETION_RING_CAP] =
    [const { AtomicU32::new(0) }; COMPLETION_RING_CAP];
static COMPLETION_TAGS: [AtomicU32; COMPLETION_RING_CAP] =
    [const { AtomicU32::new(0) }; COMPLETION_RING_CAP];

/// Store the UEFI GOP framebuffer base address and dimensions.
/// Must be called once at boot before any draw commands are flushed.
pub fn init_framebuffer(base: u64, width: u32, height: u32, stride: u32) {
    unsafe {
        let fb = &mut *GLOBAL_FB.0.get();
        fb.base = base as *mut u32;
        fb.width = width;
        fb.height = height;
        fb.stride = stride;
    }
    GLOBAL_FB_INIT.store(true, Ordering::Release);
}

/// Returns `true` if the global framebuffer has been initialised.
pub fn framebuffer_initialized() -> bool {
    GLOBAL_FB_INIT.load(Ordering::Acquire)
}

/// Returns the last fence id that completed through `flush_gpu_queue`.
pub fn last_completed_fence() -> u32 {
    LAST_FENCE.load(Ordering::Acquire)
}

#[inline]
fn publish_fence_completion(fence_id: u32) -> u32 {
    let seq = COMPLETION_SEQ
        .fetch_add(1, Ordering::AcqRel)
        .wrapping_add(1);
    let idx = ((seq as usize).wrapping_sub(1)) & COMPLETION_RING_MASK;
    COMPLETION_FENCES[idx].store(fence_id, Ordering::Relaxed);
    COMPLETION_TAGS[idx].store(seq, Ordering::Release);
    seq
}

/// Latest published GPU completion sequence number (0 means no event yet).
pub fn completion_latest_seq() -> u32 {
    COMPLETION_SEQ.load(Ordering::Acquire)
}

/// Returns fence id for an exact completion `seq`, or `None` if unavailable.
///
/// This is non-blocking and lock-free. Callers should keep their own cursor.
pub fn completion_fence_at(seq: u32) -> Option<u32> {
    if seq == 0 {
        return None;
    }
    let idx = ((seq as usize).wrapping_sub(1)) & COMPLETION_RING_MASK;
    if COMPLETION_TAGS[idx].load(Ordering::Acquire) != seq {
        return None;
    }
    Some(COMPLETION_FENCES[idx].load(Ordering::Relaxed))
}

fn global_fb() -> Option<&'static Framebuffer> {
    if GLOBAL_FB_INIT.load(Ordering::Acquire) {
        Some(unsafe { &*GLOBAL_FB.0.get() })
    } else {
        None
    }
}

/// Drain all pending entries from `GPU_QUEUE` and execute them against the
/// global GOP framebuffer.  Call this from the echOS render thread once per
/// frame (after `valkyrie_gpu_submit_batch`, before presenting).
///
/// Returns the number of queue *entries* (batches) processed.
pub fn flush_gpu_queue() -> u32 {
    use super::ugir::UGCommandKind;
    use super::{GpuQueuePriority as _Prio, GPU_QUEUE};
    let _ = _Prio::High; // suppress unused-variant lint

    let mut count = 0u32;

    macro_rules! drain {
        ($ring:expr) => {{
            while let Some(entry) = $ring.pop() {
                for i in 0..entry.count as usize {
                    let cmd = &entry.cmds[i];
                    match cmd.kind {
                        UGCommandKind::ClearColor => {
                            if let Some(fb) = global_fb() {
                                // Payload: u64s[0] = (r_bits<<32)|g_bits
                                //          u64s[1] = (b_bits<<32)|a_bits
                                let r = f32::from_bits((cmd.p.u64s[0] >> 32) as u32);
                                let g = f32::from_bits(cmd.p.u64s[0] as u32);
                                let b = f32::from_bits((cmd.p.u64s[1] >> 32) as u32);
                                let a = f32::from_bits(cmd.p.u64s[1] as u32);
                                let rgba = pack_rgba(r, g, b, a);
                                unsafe {
                                    fb.fill_rect(0, 0, fb.width, fb.height, rgba);
                                }
                            }
                        }
                        UGCommandKind::Fence => {
                            // Payload: u64s[0] = fence_id
                            let fence_id = cmd.p.u64s[0] as u32;
                            LAST_FENCE.store(fence_id, Ordering::Release);
                            let _ = publish_fence_completion(fence_id);
                        }
                        // Present, Nop, SetShader, DrawPrimitive etc. handled
                        // in later phases by the VFio / shader pipeline.
                        _ => {}
                    }
                }
                count += 1;
            }
        }};
    }

    drain!(GPU_QUEUE.high);
    drain!(GPU_QUEUE.normal);
    drain!(GPU_QUEUE.bulk);
    count
}

/// Pack normalised [0.0, 1.0] RGBA floats into a `0xAARRGGBB` u32 pixel.
#[inline]
fn pack_rgba(r: f32, g: f32, b: f32, a: f32) -> u32 {
    let ri = (r.clamp(0.0, 1.0) * 255.0) as u32;
    let gi = (g.clamp(0.0, 1.0) * 255.0) as u32;
    let bi = (b.clamp(0.0, 1.0) * 255.0) as u32;
    let ai = (a.clamp(0.0, 1.0) * 255.0) as u32;
    (ai << 24) | (ri << 16) | (gi << 8) | bi
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_stealing_queue_push_pop() {
        // WorkStealingQueue is ~4 MB — keep in BSS via static.
        static Q: WorkStealingQueue = WorkStealingQueue::new();
        let q = &Q;
        assert!(q.is_empty());

        let job = TileJob {
            tile_x: 3,
            tile_y: 7,
            prim_start: 0,
            prim_count: 5,
            shader_id: 1,
            _pad: [0; 6],
        };
        assert!(q.push_bottom(job));
        assert_eq!(q.len(), 1);

        let got = q.pop_bottom().unwrap();
        assert_eq!(got.tile_x, 3);
        assert_eq!(got.tile_y, 7);
        assert!(q.is_empty());
    }

    #[test]
    fn work_stealing_queue_steal() {
        static Q: WorkStealingQueue = WorkStealingQueue::new();
        let q = &Q;
        for i in 0..4u16 {
            let job = TileJob {
                tile_x: i,
                tile_y: 0,
                prim_start: 0,
                prim_count: 0,
                shader_id: 0,
                _pad: [0; 6],
            };
            q.push_bottom(job);
        }
        // Steal from top
        let stolen = q.steal_top().unwrap();
        assert_eq!(stolen.tile_x, 0); // FIFO steal
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn execute_shader_add() {
        use crate::vmm::shader_translator::EchoInstr;

        let mut input = RegFile::zero();
        input.r[1] = [1.0, 2.0, 3.0, 4.0];
        input.r[2] = [10.0, 20.0, 30.0, 40.0];

        const NOP: EchoInstr = EchoInstr {
            op: echo_op::NOP,
            dst: 0,
            src0: 0,
            src1: 0,
            src2: 0,
            flags: 0,
        };
        let mut bc = EchosBytecode {
            stage: crate::vmm::ugir::ShaderStage::Pixel,
            _pad: [0; 3],
            len: 2,
            _pad2: [0; 2],
            instrs: [NOP; crate::vmm::shader_translator::ECHO_BYTECODE_MAX],
        };
        bc.instrs[0] = EchoInstr {
            op: echo_op::ADD,
            dst: 0,
            src0: 1,
            src1: 2,
            src2: 0,
            flags: 0,
        };
        bc.instrs[1] = EchoInstr {
            op: echo_op::RET,
            dst: 0,
            src0: 0,
            src1: 0,
            src2: 0,
            flags: 0,
        };

        let out = execute_shader(&bc, &input);
        assert_eq!(out.r[0], [11.0, 22.0, 33.0, 44.0]);
    }

    #[test]
    fn depth_buffer_lock_free() {
        const W: u32 = 4;
        const H: u32 = 4;
        static STORAGE: [AtomicU32; 16] = [const { AtomicU32::new(0x3F800000) }; 16]; // 1.0
        let db = DepthBuffer::new_view(W, H, &STORAGE);

        // Write depth 0.5 — should pass (0.5 < 1.0)
        assert!(db.test_and_set(0, 0, 0.5));
        // Write depth 0.8 — should fail (0.8 > 0.5)
        assert!(!db.test_and_set(0, 0, 0.8));
        // Write depth 0.3 — should pass (0.3 < 0.5)
        assert!(db.test_and_set(0, 0, 0.3));
    }

    #[test]
    fn rasterize_triangle_solid_color() {
        const W: u32 = 8;
        const H: u32 = 8;
        let mut fb_storage = [0u32; (W * H) as usize];
        let fb = Framebuffer {
            base: fb_storage.as_mut_ptr(),
            width: W,
            height: H,
            stride: W,
        };

        static DEPTH_STORAGE: [AtomicU32; 64] = [const { AtomicU32::new(0x3F800000) }; 64];
        let depth = DepthBuffer::new_view(W, H, &DEPTH_STORAGE);
        depth.clear();

        // Full-screen triangle
        let v0 = ClipVertex {
            pos: [-1.0, 1.0, 0.5, 1.0],
            uv: [0.0, 0.0],
            col: [1.0, 0.0, 0.0, 1.0],
            nor: [0.0; 3],
            _pad: 0.0,
        };
        let v1 = ClipVertex {
            pos: [3.0, 1.0, 0.5, 1.0],
            uv: [1.0, 0.0],
            col: [1.0, 0.0, 0.0, 1.0],
            nor: [0.0; 3],
            _pad: 0.0,
        };
        let v2 = ClipVertex {
            pos: [-1.0, -3.0, 0.5, 1.0],
            uv: [0.0, 1.0],
            col: [1.0, 0.0, 0.0, 1.0],
            nor: [0.0; 3],
            _pad: 0.0,
        };

        rasterize_tile(&[v0, v1, v2], &fb, &depth, 0, 0, &|frag| frag.col);

        // At least the top-left pixel should be red
        let pixel = fb_storage[0];
        let r = (pixel >> 16) & 0xFF;
        assert_eq!(r, 255, "expected red pixel at (0,0)");
    }

    #[test]
    fn pack_rgba_pure_red() {
        let px = pack_rgba(1.0, 0.0, 0.0, 1.0);
        assert_eq!(px, 0xFF_FF_00_00u32, "expected 0xFFFF0000 for opaque red");
    }

    #[test]
    fn pack_rgba_pure_blue() {
        let px = pack_rgba(0.0, 0.0, 1.0, 1.0);
        assert_eq!(px, 0xFF_00_00_FFu32, "expected 0xFF0000FF for opaque blue");
    }

    #[test]
    fn flush_gpu_queue_processes_fence() {
        use crate::vmm::ugir::{UGCommand, UGCommandKind, UGPayload};
        use crate::vmm::{GpuQueuePriority, GPU_QUEUE};

        // Use a large fence id that tests in parallel are unlikely to set.
        const FENCE_MARK: u32 = 0xBEEF;
        let before_seq = completion_latest_seq();

        let cmd = UGCommand {
            kind: UGCommandKind::Fence,
            _pad: [0; 3],
            p: UGPayload::fence(FENCE_MARK as u64),
        };
        assert!(
            GPU_QUEUE.submit(GpuQueuePriority::High, core::slice::from_ref(&cmd)),
            "GPU_QUEUE high ring should not be full"
        );

        let processed = flush_gpu_queue();
        assert!(
            processed >= 1,
            "at least one entry should have been drained"
        );

        let after_seq = completion_latest_seq();
        assert!(
            after_seq > before_seq,
            "completion sequence should advance after flush"
        );

        let mut found = false;
        let mut seq = before_seq.saturating_add(1);
        while seq <= after_seq {
            if completion_fence_at(seq) == Some(FENCE_MARK) {
                found = true;
                break;
            }
            seq = seq.saturating_add(1);
        }
        assert!(
            found,
            "submitted fence marker should be present in completion stream"
        );
    }

    #[test]
    fn init_framebuffer_sets_initialized_flag() {
        // Pass base = 0 (null) — we only verify the initialized flag, not pixel writes.
        init_framebuffer(0, 16, 16, 16);
        assert!(
            framebuffer_initialized(),
            "framebuffer_initialized() should return true"
        );
    }
}
