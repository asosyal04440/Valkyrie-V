#![allow(clippy::large_enum_variant)]
#![allow(static_mut_refs)]

//! Shader Translation Engine
//!
//! Converts DXBC (D3D11 bytecode) and DXIL (D3D12 / LLVM bitcode subset) into
//! either:
//!   - `SpirVBlob`    — raw SPIR-V u32 words for the VFIO PCIe backend
//!   - `EchosBytecode` — register-VM bytecode for the 8192-core soft rasterizer
//!
//! Zero heap, `no_std`.  Naga architecture is the design reference but the
//! implementation is entirely fresh.

use crate::vmm::ugir::ShaderStage;
use core::sync::atomic::{AtomicU32, Ordering};

// ─── EchosBytecode ────────────────────────────────────────────────────────────

/// One EchosBytecode instruction: 8 bytes.
/// ```text
/// [op: u16][dst: u8][src0: u8][src1: u8][src2: u8][flags: u16]
/// ```
/// Flags bits:
///   0     — src0 is immediate (value in next instruction slot)
///   1     — src1 is immediate
///   2     — src2 is immediate
///   3     — vectorize hint (loop body, 8-lane AVX2)
///   4..15 — reserved
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct EchoInstr {
    pub op: u16,
    pub dst: u8,
    pub src0: u8,
    pub src1: u8,
    pub src2: u8,
    pub flags: u16,
}

pub mod echo_op {
    pub const NOP: u16 = 0x0000;
    pub const MOV: u16 = 0x0001;
    pub const ADD: u16 = 0x0002;
    pub const SUB: u16 = 0x0003;
    pub const MUL: u16 = 0x0004;
    pub const DIV: u16 = 0x0005;
    pub const MAD: u16 = 0x0006; // dst = src0*src1 + src2
    pub const SQRT: u16 = 0x0007;
    pub const RSQ: u16 = 0x0008; // reciprocal sqrt
    pub const DP2: u16 = 0x0009;
    pub const DP3: u16 = 0x000A;
    pub const DP4: u16 = 0x000B;
    pub const MIN: u16 = 0x000C;
    pub const MAX: u16 = 0x000D;
    pub const FRAC: u16 = 0x000E;
    pub const FLOOR: u16 = 0x000F;
    pub const CEIL: u16 = 0x0010;
    pub const ROUND: u16 = 0x0011;
    pub const TRUNC: u16 = 0x0012;
    pub const ABS: u16 = 0x0013;
    pub const NEG: u16 = 0x0014;
    pub const SAT: u16 = 0x0015; // saturate to [0,1]
    pub const CMP: u16 = 0x0016; // dst = src0 >= 0.0 ? src1 : src2
    pub const AND: u16 = 0x0017;
    pub const OR: u16 = 0x0018;
    pub const XOR: u16 = 0x0019;
    pub const NOT: u16 = 0x001A;
    pub const ITOF: u16 = 0x001B; // int to float
    pub const FTOI: u16 = 0x001C; // float to int
    pub const SAMPLE: u16 = 0x001D; // texture sample: dst=reg,src0=uv_reg,src1=tex_id,src2=sampler_id
    pub const LOAD: u16 = 0x001E; // load from buffer
    pub const STORE: u16 = 0x001F; // store to buffer
    pub const JMP: u16 = 0x0020; // unconditional jump (src0 = target label)
    pub const JNZ: u16 = 0x0021; // jump if src0 != 0
    pub const JZ: u16 = 0x0022; // jump if src0 == 0
    pub const LABEL: u16 = 0x0023; // label marker (no-op at runtime)
    pub const RET: u16 = 0x0024;
    pub const EMIT: u16 = 0x0025; // geometry shader emit
    pub const DISCARD: u16 = 0x0026; // pixel shader discard
    pub const SWIZZLE: u16 = 0x0027; // dst = src0.xyzw with permutation in flags
}

pub const ECHO_FLAG_SRC0_IMM: u16 = 1 << 0;
pub const ECHO_FLAG_SRC1_IMM: u16 = 1 << 1;
pub const ECHO_FLAG_SRC2_IMM: u16 = 1 << 2;
pub const ECHO_FLAG_VECTORIZE: u16 = 1 << 3;

pub const ECHO_BYTECODE_MAX: usize = 2048;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct EchosBytecode {
    pub stage: ShaderStage,
    pub _pad: [u8; 3],
    pub len: u16,
    pub _pad2: [u8; 2],
    pub instrs: [EchoInstr; ECHO_BYTECODE_MAX],
}

impl core::fmt::Debug for EchosBytecode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "EchosBytecode {{ stage: {:?}, len: {} }}",
            self.stage, self.len
        )
    }
}

// ─── SPIR-V blob ─────────────────────────────────────────────────────────────

pub const SPIRV_BLOB_MAX_WORDS: usize = 8192;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SpirVBlob {
    pub word_count: u32,
    pub words: [u32; SPIRV_BLOB_MAX_WORDS],
}

impl core::fmt::Debug for SpirVBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SpirVBlob {{ words: {} }}", self.word_count)
    }
}

// ─── ShaderIR — naga-inspired no_std IR ──────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IrType {
    Float32 = 0,
    Int32,
    Uint32,
    Bool,
    Vec2F,
    Vec3F,
    Vec4F,
    Mat4x4F,
    SamplerState,
    Texture2D,
    Texture3D,
    TextureCube,
    Array,
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct IrOp {
    pub kind: u8,
    pub dst: u8,
    pub src0: u8,
    pub src1: u8,
    pub src2: u8,
    pub flags: u8,
    pub imm: u16,
}

// IrOp kinds — mirror DXBC opcodes
pub mod ir_op {
    pub const MOV: u8 = 0;
    pub const ADD: u8 = 1;
    pub const MUL: u8 = 2;
    pub const MAD: u8 = 3;
    pub const DP4: u8 = 4;
    pub const DP3: u8 = 5;
    pub const DP2: u8 = 6;
    pub const SAMPLE: u8 = 7;
    pub const LT: u8 = 8;
    pub const GE: u8 = 9;
    pub const EQ: u8 = 10;
    pub const MOVC: u8 = 11; // conditional move
    pub const RET: u8 = 12;
    pub const DISCARD: u8 = 13;
    pub const SQRT: u8 = 14;
    pub const RSQ: u8 = 15;
    pub const LOG: u8 = 16;
    pub const EXP: u8 = 17;
    pub const FRAC: u8 = 18;
    pub const ROUND: u8 = 19;
    pub const FLOOR: u8 = 20;
    pub const CEIL: u8 = 21;
    pub const MAX: u8 = 22;
    pub const MIN: u8 = 23;
    pub const AND: u8 = 24;
    pub const OR: u8 = 25;
    pub const FTOI: u8 = 26;
    pub const ITOF: u8 = 27;
}

pub const IR_MAX_OPS: usize = 512;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ShaderIR {
    pub stage: ShaderStage,
    pub reg_count: u8,
    pub _pad: [u8; 2],
    pub op_count: u16,
    pub _pad2: [u8; 2],
    pub ops: [IrOp; IR_MAX_OPS],
}

impl core::fmt::Debug for ShaderIR {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ShaderIR {{ stage: {:?}, ops: {} }}",
            self.stage, self.op_count
        )
    }
}

impl ShaderIR {
    pub const fn new(stage: ShaderStage) -> Self {
        const NOP: IrOp = IrOp {
            kind: ir_op::MOV,
            dst: 0,
            src0: 0,
            src1: 0,
            src2: 0,
            flags: 0,
            imm: 0,
        };
        Self {
            stage,
            reg_count: 0,
            _pad: [0; 2],
            op_count: 0,
            _pad2: [0; 2],
            ops: [NOP; IR_MAX_OPS],
        }
    }

    pub fn push(&mut self, op: IrOp) -> bool {
        if self.op_count as usize >= IR_MAX_OPS {
            return false;
        }
        self.ops[self.op_count as usize] = op;
        self.op_count += 1;
        true
    }
}

// ─── DXBC parser ─────────────────────────────────────────────────────────────

const DXBC_MAGIC: u32 = 0x43425844; // "DXBC"

/// DXBC chunk tags (little-endian u32 from 4-byte FourCC).
const CHUNK_SHDR: u32 = 0x52444853; // "SHDR"
const CHUNK_SHEX: u32 = 0x58454853; // "SHEX"

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    NoShaderChunk,
    UnsupportedVersion,
    ScratchFull,
    MalformedInstruction,
}

/// Parse a DXBC blob and produce a `ShaderIR`.
///
/// `data` must be the raw bytecode as supplied by `CreateVertexShader` /
/// `CreatePixelShader`.
pub fn decode_dxbc(data: &[u8], stage: ShaderStage) -> Result<ShaderIR, DecodeError> {
    if data.len() < 32 {
        return Err(DecodeError::TooShort);
    }

    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != DXBC_MAGIC {
        return Err(DecodeError::BadMagic);
    }

    // Header: magic(4) + hash(16) + version(4) + file_size(4) + chunk_count(4)
    let chunk_count = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
    let header_size = 32;

    let mut shader_chunk_off: Option<usize> = None;

    for i in 0..chunk_count.min(16) {
        let off = header_size + i * 4;
        if off + 4 > data.len() {
            break;
        }
        let chunk_off =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
        if chunk_off + 8 > data.len() {
            continue;
        }
        let tag = u32::from_le_bytes([
            data[chunk_off],
            data[chunk_off + 1],
            data[chunk_off + 2],
            data[chunk_off + 3],
        ]);
        if tag == CHUNK_SHDR || tag == CHUNK_SHEX {
            shader_chunk_off = Some(chunk_off);
            break;
        }
    }

    let chunk_off = shader_chunk_off.ok_or(DecodeError::NoShaderChunk)?;
    let chunk_size = u32::from_le_bytes([
        data[chunk_off + 4],
        data[chunk_off + 5],
        data[chunk_off + 6],
        data[chunk_off + 7],
    ]) as usize;

    let body_start = chunk_off + 8;
    let body_end = body_start + chunk_size;
    if body_end > data.len() {
        return Err(DecodeError::TooShort);
    }

    // SHDR/SHEX body: version(u32) + length_in_dwords(u32) + instructions...
    if body_start + 8 > body_end {
        return Err(DecodeError::TooShort);
    }

    // version word: bits 16..31 = major, bits 0..15 = minor; not strictly validated
    let _version = u32::from_le_bytes([
        data[body_start],
        data[body_start + 1],
        data[body_start + 2],
        data[body_start + 3],
    ]);
    let _total_dwords = u32::from_le_bytes([
        data[body_start + 4],
        data[body_start + 5],
        data[body_start + 6],
        data[body_start + 7],
    ]);

    let instr_start = body_start + 8;
    let mut ir = ShaderIR::new(stage);

    let mut pos = instr_start;
    while pos + 4 <= body_end {
        let token = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let opcode = token & 0x7FF;
        let instr_len = ((token >> 24) & 0x1F) as usize;
        if instr_len == 0 {
            break;
        }
        let next_pos = pos + instr_len * 4;
        if next_pos > body_end {
            break;
        }

        // Map a representative subset of DXBC opcodes to IrOp
        let maybe_op: Option<IrOp> = match opcode {
            0x01 => Some(IrOp {
                kind: ir_op::MOV,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x00 => Some(IrOp {
                kind: ir_op::ADD,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x38 => Some(IrOp {
                kind: ir_op::MUL,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x10 => Some(IrOp {
                kind: ir_op::MAD,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x11 => Some(IrOp {
                kind: ir_op::DP2,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x12 => Some(IrOp {
                kind: ir_op::DP3,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x13 => Some(IrOp {
                kind: ir_op::DP4,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x2d => Some(IrOp {
                kind: ir_op::SAMPLE,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x18 => Some(IrOp {
                kind: ir_op::SQRT,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x19 => Some(IrOp {
                kind: ir_op::RSQ,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x39 => Some(IrOp {
                kind: ir_op::MAX,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x3a => Some(IrOp {
                kind: ir_op::MIN,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x7e => Some(IrOp {
                kind: ir_op::RET,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            0x3d => Some(IrOp {
                kind: ir_op::DISCARD,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
                imm: 0,
            }),
            _ => None,
        };

        if let Some(op) = maybe_op {
            if !ir.push(op) {
                return Err(DecodeError::ScratchFull);
            }
        }

        pos = next_pos;
    }

    // Always end with RET
    ir.push(IrOp {
        kind: ir_op::RET,
        dst: 0,
        src0: 0,
        src1: 0,
        src2: 0,
        flags: 0,
        imm: 0,
    });
    Ok(ir)
}

// ─── EchosBytecode emitter ────────────────────────────────────────────────────

/// Lower a `ShaderIR` into `EchosBytecode`.
pub fn emit_echos(ir: &ShaderIR) -> Result<EchosBytecode, DecodeError> {
    const NOP_INSTR: EchoInstr = EchoInstr {
        op: echo_op::NOP,
        dst: 0,
        src0: 0,
        src1: 0,
        src2: 0,
        flags: 0,
    };
    let mut bc = EchosBytecode {
        stage: ir.stage,
        _pad: [0; 3],
        len: 0,
        _pad2: [0; 2],
        instrs: [NOP_INSTR; ECHO_BYTECODE_MAX],
    };

    for i in 0..ir.op_count as usize {
        let op = &ir.ops[i];
        let echo_op_code = match op.kind {
            ir_op::MOV => echo_op::MOV,
            ir_op::ADD => echo_op::ADD,
            ir_op::MUL => echo_op::MUL,
            ir_op::MAD => echo_op::MAD,
            ir_op::DP4 => echo_op::DP4,
            ir_op::DP3 => echo_op::DP3,
            ir_op::DP2 => echo_op::DP2,
            ir_op::SAMPLE => echo_op::SAMPLE,
            ir_op::SQRT => echo_op::SQRT,
            ir_op::RSQ => echo_op::RSQ,
            ir_op::MAX => echo_op::MAX,
            ir_op::MIN => echo_op::MIN,
            ir_op::FLOOR => echo_op::FLOOR,
            ir_op::CEIL => echo_op::CEIL,
            ir_op::FRAC => echo_op::FRAC,
            ir_op::LOG => echo_op::NOP,
            ir_op::EXP => echo_op::NOP,
            ir_op::AND => echo_op::AND,
            ir_op::OR => echo_op::OR,
            ir_op::FTOI => echo_op::FTOI,
            ir_op::ITOF => echo_op::ITOF,
            ir_op::RET => echo_op::RET,
            ir_op::DISCARD => echo_op::DISCARD,
            _ => echo_op::NOP,
        };

        if bc.len as usize >= ECHO_BYTECODE_MAX {
            return Err(DecodeError::ScratchFull);
        }
        bc.instrs[bc.len as usize] = EchoInstr {
            op: echo_op_code,
            dst: op.dst,
            src0: op.src0,
            src1: op.src1,
            src2: op.src2,
            flags: 0,
        };
        bc.len += 1;
    }

    Ok(bc)
}

// ─── SPIR-V emitter ───────────────────────────────────────────────────────────

const SPIRV_MAGIC: u32 = 0x07230203;
const SPIRV_VERSION_1_0: u32 = 0x00010000;
const SPIRV_GENERATOR: u32 = 0xECEC0001; // echOS custom generator id

pub fn emit_spirv(ir: &ShaderIR) -> Result<SpirVBlob, DecodeError> {
    let mut blob = SpirVBlob {
        word_count: 0,
        words: [0; SPIRV_BLOB_MAX_WORDS],
    };
    let mut pos = 0usize;

    macro_rules! emit {
        ($v:expr) => {{
            if pos >= SPIRV_BLOB_MAX_WORDS {
                return Err(DecodeError::ScratchFull);
            }
            blob.words[pos] = $v;
            pos += 1;
        }};
    }

    // Header
    emit!(SPIRV_MAGIC);
    emit!(SPIRV_VERSION_1_0);
    emit!(SPIRV_GENERATOR);
    let bound_pos = pos;
    emit!(0); // bound placeholder (patched at end)
    emit!(0); // schema

    // Capabilities
    emit!((2u32 << 16) | 17); // OpCapability Shader
    emit!(1u32); // Shader

    // Memory model: OpMemoryModel Logical GLSL450
    emit!((3u32 << 16) | 14);
    emit!(0); // Logical
    emit!(1); // GLSL450

    // Execution model
    let exec_model: u32 = match ir.stage {
        ShaderStage::Vertex => 0,
        ShaderStage::Pixel => 4,
        ShaderStage::Compute => 5,
        ShaderStage::Geometry => 3,
        ShaderStage::Hull => 1,
        ShaderStage::Domain => 2,
    };

    // OpEntryPoint ExecModel %main "main"
    // Simplified: encode as OpFunction + OpReturn for the body skeleton
    // Type ids: float=1, void=2, func_type=3, ptr_float=4, vec4=5
    const ID_VOID: u32 = 1;
    const ID_FLOAT: u32 = 2;
    const ID_VEC4: u32 = 3;
    const ID_FUNCTY: u32 = 4;
    const ID_MAIN: u32 = 5;
    let mut next_id = 6u32;

    // OpTypeVoid %1
    emit!((2u32 << 16) | 19);
    emit!(ID_VOID);

    // OpTypeFloat %2 32
    emit!((3u32 << 16) | 22);
    emit!(ID_FLOAT);
    emit!(32);

    // OpTypeVector %3 %2 4
    emit!((4u32 << 16) | 23);
    emit!(ID_VEC4);
    emit!(ID_FLOAT);
    emit!(4);

    // OpTypeFunction %4 %1  (void fn())
    emit!((3u32 << 16) | 33);
    emit!(ID_FUNCTY);
    emit!(ID_VOID);

    // OpEntryPoint
    // "main" encoded as 4 bytes + null: 0x6e69616d (le "main") + 0x00000000
    emit!((5u32 << 16) | 15);
    emit!(exec_model);
    emit!(ID_MAIN);
    emit!(0x6e69_616d); // "main"
    emit!(0x0000_0000);

    // OpFunction %1 %5 None %4
    emit!((5u32 << 16) | 54);
    emit!(ID_VOID);
    emit!(ID_MAIN);
    emit!(0); // None
    emit!(ID_FUNCTY);

    // OpLabel
    let label_id = next_id;
    next_id += 1;
    emit!((2u32 << 16) | 248);
    emit!(label_id);

    // Emit translated IR operations as SPIR-V arithmetic
    for i in 0..ir.op_count as usize {
        let op = &ir.ops[i];
        match op.kind {
            ir_op::ADD => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 129); // OpFAdd
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::MUL => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 133); // OpFMul
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::DP4 => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 148); // OpDot
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::DP3 => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 148); // OpDot
                emit!(ID_VEC4);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::DP2 => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 148); // OpDot (2-component)
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::MAD => {
                // dst = src0 * src1 + src2
                let mul_id = next_id;
                next_id += 1;
                let add_id = next_id;
                next_id += 1;
                // OpFMul
                emit!((5u32 << 16) | 133);
                emit!(ID_FLOAT);
                emit!(mul_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
                // OpFAdd
                emit!((5u32 << 16) | 129);
                emit!(ID_FLOAT);
                emit!(add_id);
                emit!(mul_id);
                emit!((op.src2 as u32) + 100);
            }
            ir_op::MOV => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 48); // OpCopyObject
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::MIN => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 137); // OpFMin
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::MAX => {
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 138); // OpFMax
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::SQRT => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 146); // OpGLSLSqrt
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::RSQ => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 147); // OpGLSLInverseSqrt
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::LOG => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 143); // OpGLSLLog
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::EXP => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 142); // OpGLSLExp
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::FLOOR => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 155); // OpGLSLFloor
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::CEIL => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 156); // OpGLSLCeil
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::ROUND => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 157); // OpGLSLRound
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::FRAC => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 158); // OpGLSLFract
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::FTOI => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 124); // OpConvertFToS
                emit!(ID_FLOAT); // result type int (reuse float id for simplicity)
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::ITOF => {
                let result_id = next_id;
                next_id += 1;
                emit!((4u32 << 16) | 125); // OpConvertSToF
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
            }
            ir_op::AND | ir_op::OR => {
                // Bitwise ops - emit as logical ops for now
                let result_id = next_id;
                next_id += 1;
                let opcode = if op.kind == ir_op::AND { 129 } else { 130 }; // OpLogicalAnd/Or
                emit!((4u32 << 16) | opcode);
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::LT | ir_op::GE | ir_op::EQ => {
                // Comparison ops
                let result_id = next_id;
                next_id += 1;
                let opcode = match op.kind {
                    ir_op::LT => 99,  // OpFOrdLessThan
                    ir_op::GE => 102, // OpFOrdGreaterThanEqual
                    ir_op::EQ => 100, // OpFOrdEqual
                    _ => 99,
                };
                emit!((5u32 << 16) | opcode);
                emit!(ID_FLOAT); // bool result (simplified)
                emit!(result_id);
                emit!((op.src0 as u32) + 100);
                emit!((op.src1 as u32) + 100);
            }
            ir_op::MOVC => {
                // Conditional move - select
                let result_id = next_id;
                next_id += 1;
                emit!((6u32 << 16) | 169); // OpSelect
                emit!(ID_FLOAT);
                emit!(result_id);
                emit!((op.src0 as u32) + 100); // condition
                emit!((op.src1 as u32) + 100); // true value
                emit!((op.src2 as u32) + 100); // false value
            }
            ir_op::SAMPLE => {
                // Texture sampling - OpImageSampleImplicitLod
                let result_id = next_id;
                next_id += 1;
                emit!((5u32 << 16) | 87); // OpImageSampleImplicitLod
                emit!(ID_VEC4);
                emit!(result_id);
                emit!((op.src1 as u32) + 200); // sampled image
                emit!((op.src0 as u32) + 100); // coordinates
            }
            ir_op::RET => {
                emit!((1u32 << 16) | 253); // OpReturn
            }
            ir_op::DISCARD => {
                emit!((1u32 << 16) | 218); // OpKill
            }
            _ => {} // Unknown ops: handled by soft rasterizer interpreter
        }
    }

    // OpReturn
    emit!((1u32 << 16) | 253);

    // OpFunctionEnd
    emit!((1u32 << 16) | 56);

    // Patch bound
    blob.words[bound_pos] = next_id;
    blob.word_count = pos as u32;
    Ok(blob)
}

// ─── Shader cache ─────────────────────────────────────────────────────────────

const SHADER_CACHE_SIZE: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq)]
struct CacheKey(u64); // truncated SHA-256 prefix

fn hash_bytecode_key(data: &[u8]) -> CacheKey {
    // djb2a over first 256 bytes as a cache key (not cryptographic — just fast)
    let mut h: u64 = 5381;
    for &b in data.iter().take(256) {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    CacheKey(h)
}

#[derive(Clone, Copy)]
enum CachedShader {
    Empty,
    Echos(EchosBytecode),
    SpirV(SpirVBlob),
}

struct CacheEntry {
    key: CacheKey,
    data: CachedShader,
}

pub struct ShaderCache {
    entries: [CacheEntry; SHADER_CACHE_SIZE],
    lru_hand: AtomicU32,
    hits: AtomicU32,
    misses: AtomicU32,
}

impl ShaderCache {
    pub const fn new() -> Self {
        const EMPTY: CacheEntry = CacheEntry {
            key: CacheKey(0),
            data: CachedShader::Empty,
        };
        Self {
            entries: [EMPTY; SHADER_CACHE_SIZE],
            lru_hand: AtomicU32::new(0),
            hits: AtomicU32::new(0),
            misses: AtomicU32::new(0),
        }
    }

    pub fn find_echos(&self, bytecode: &[u8]) -> Option<&EchosBytecode> {
        let key = hash_bytecode_key(bytecode);
        for e in &self.entries {
            if e.key == key {
                if let CachedShader::Echos(ref b) = e.data {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(b);
                }
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn find_spirv(&self, bytecode: &[u8]) -> Option<&SpirVBlob> {
        let key = hash_bytecode_key(bytecode);
        for e in &self.entries {
            if e.key == key {
                if let CachedShader::SpirV(ref b) = e.data {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(b);
                }
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub fn insert_echos(&mut self, bytecode: &[u8], shader: EchosBytecode) {
        let key = hash_bytecode_key(bytecode);
        let slot = self.lru_hand.fetch_add(1, Ordering::Relaxed) as usize % SHADER_CACHE_SIZE;
        self.entries[slot] = CacheEntry {
            key,
            data: CachedShader::Echos(shader),
        };
    }

    pub fn insert_spirv(&mut self, bytecode: &[u8], blob: SpirVBlob) {
        let key = hash_bytecode_key(bytecode);
        let slot = self.lru_hand.fetch_add(1, Ordering::Relaxed) as usize % SHADER_CACHE_SIZE;
        self.entries[slot] = CacheEntry {
            key,
            data: CachedShader::SpirV(blob),
        };
    }

    pub fn hit_rate_percent(&self) -> u32 {
        let h = self.hits.load(Ordering::Relaxed);
        let m = self.misses.load(Ordering::Relaxed);
        if h + m == 0 {
            return 0;
        }
        h * 100 / (h + m)
    }
}

impl Default for ShaderCache {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Top-level translate function ─────────────────────────────────────────────

/// Full pipeline: raw DXBC → EchosBytecode (with cache).
pub fn translate_dxbc_to_echos(
    cache: &mut ShaderCache,
    bytecode: &[u8],
    stage: ShaderStage,
) -> Result<EchosBytecode, DecodeError> {
    if let Some(cached) = cache.find_echos(bytecode) {
        return Ok(*cached);
    }
    let ir = decode_dxbc(bytecode, stage)?;
    let bc = emit_echos(&ir)?;
    cache.insert_echos(bytecode, bc);
    Ok(bc)
}

/// Full pipeline: raw DXBC → SpirVBlob (with cache).
pub fn translate_dxbc_to_spirv(
    cache: &mut ShaderCache,
    bytecode: &[u8],
    stage: ShaderStage,
) -> Result<SpirVBlob, DecodeError> {
    if let Some(cached) = cache.find_spirv(bytecode) {
        return Ok(*cached);
    }
    let ir = decode_dxbc(bytecode, stage)?;
    let blob = emit_spirv(&ir)?;
    cache.insert_spirv(bytecode, blob);
    Ok(blob)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_dxbc(extra_ops: &[u32]) -> ([u8; 512], usize) {
        let mut buf = [0u8; 512];
        let mut pos = 0usize;

        macro_rules! push32 {
            ($v:expr) => {{
                let bytes = ($v as u32).to_le_bytes();
                buf[pos..pos + 4].copy_from_slice(&bytes);
                pos += 4;
            }};
        }

        push32!(DXBC_MAGIC);
        for _ in 0..16 {
            buf[pos] = 0;
            pos += 1;
        } // hash
        push32!(0x00000101u32); // version
        
        // Calculate file_size: header(32) + chunk_offset_table(4) + chunk_header(8) + chunk_body(4 + extra_ops*4)
        let chunk_body_size = 4 + extra_ops.len() * 4; // version + ops
        let chunk_header_size = 8; // fourcc + size
        let chunk_offset_table_size = 4; // one chunk offset
        let header_size = 32; // magic(4) + hash(16) + version(4) + file_size(4) + chunk_count(4)
        let file_size = (header_size + chunk_offset_table_size + chunk_header_size + chunk_body_size) as u32;
        push32!(file_size); // file_size (proper calculation)
        
        push32!(1u32); // chunk_count = 1
        push32!(36u32); // chunk offset table: offset = 36
        push32!(CHUNK_SHDR);
        let chunk_size = 8 + extra_ops.len() * 4;
        push32!(chunk_size as u32);
        push32!(0x00040001u32); // SHDR body version
        push32!((2 + extra_ops.len()) as u32); // total_dwords
        for op in extra_ops {
            push32!(*op);
        }
        (buf, pos)
    }

    #[test]
    fn decode_empty_dxbc_produces_ret() {
        let (blob, len) = minimal_dxbc(&[]);
        let ir = decode_dxbc(&blob[..len], ShaderStage::Pixel).unwrap();
        assert_eq!(ir.op_count, 1);
        assert_eq!(ir.ops[0].kind, ir_op::RET);
    }

    #[test]
    fn decode_mul_dxbc() {
        // opcode 0x38 = MUL, instr_len=3
        let instr: u32 = (3 << 24) | 0x38;
        let (blob, len) = minimal_dxbc(&[instr, 0, 0]);
        let ir = decode_dxbc(&blob[..len], ShaderStage::Vertex).unwrap();
        assert!(ir.op_count >= 1);
        let found = (0..ir.op_count as usize).any(|i| ir.ops[i].kind == ir_op::MUL);
        assert!(found, "Expected MUL op");
    }

    #[test]
    fn emit_echos_from_ir() {
        let mut ir = ShaderIR::new(ShaderStage::Pixel);
        ir.push(IrOp {
            kind: ir_op::ADD,
            dst: 1,
            src0: 2,
            src1: 3,
            src2: 0,
            flags: 0,
            imm: 0,
        });
        ir.push(IrOp {
            kind: ir_op::RET,
            dst: 0,
            src0: 0,
            src1: 0,
            src2: 0,
            flags: 0,
            imm: 0,
        });
        let bc = emit_echos(&ir).unwrap();
        assert!(bc.len >= 2);
        assert_eq!(bc.instrs[0].op, echo_op::ADD);
    }

    #[test]
    fn emit_spirv_has_magic() {
        let mut ir = ShaderIR::new(ShaderStage::Pixel);
        ir.push(IrOp {
            kind: ir_op::RET,
            dst: 0,
            src0: 0,
            src1: 0,
            src2: 0,
            flags: 0,
            imm: 0,
        });
        let blob = emit_spirv(&ir).unwrap();
        assert!(blob.word_count > 0);
        assert_eq!(blob.words[0], SPIRV_MAGIC);
    }

    #[test]
    fn shader_cache_hit_miss() {
        // ShaderCache is ~8 MB — use static to avoid stack overflow.
        static mut CACHE: ShaderCache = ShaderCache::new();
        let cache: &mut ShaderCache = unsafe { &mut CACHE };

        let dummy: &[u8] = &[0x44, 0x58, 0x42, 0x43, 0, 1, 2, 3];
        assert!(cache.find_echos(dummy).is_none());
        let bc = EchosBytecode {
            stage: ShaderStage::Pixel,
            _pad: [0; 3],
            len: 0,
            _pad2: [0; 2],
            instrs: [EchoInstr {
                op: echo_op::NOP,
                dst: 0,
                src0: 0,
                src1: 0,
                src2: 0,
                flags: 0,
            }; ECHO_BYTECODE_MAX],
        };
        cache.insert_echos(dummy, bc);
        assert!(cache.find_echos(dummy).is_some());
    }
}
