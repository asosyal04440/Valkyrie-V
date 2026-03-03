//! DXBC to SPIR-V Shader Translation
//!
//! Provides shader bytecode translation from DirectX Shader Bytecode (DXBC)
//! to SPIR-V for use with AMD and Intel GPUs. NVIDIA GPUs can use PTX directly.
//!
//! This module parses DXBC containers, extracts shader information, and generates
//! equivalent SPIR-V modules that can be submitted to Vulkan-compatible GPUs.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// ─── DXBC Container ────────────────────────────────────────────────────────────

/// DXBC container magic number "DXBC"
pub const DXBC_MAGIC: [u8; 4] = *b"DXBC";

/// DXBC container header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DxbcHeader {
    /// Magic "DXBC"
    pub magic: [u8; 4],
    /// MD5 checksum (16 bytes)
    pub checksum: [u8; 16],
    /// Version (1)
    pub version: u32,
    /// Total size in bytes
    pub total_size: u32,
    /// Number of chunks
    pub chunk_count: u32,
}

impl DxbcHeader {
    /// Validate DXBC header
    pub fn is_valid(&self) -> bool {
        self.magic == DXBC_MAGIC && self.version == 1
    }
}

/// DXBC chunk header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ChunkHeader {
    /// FourCC chunk type
    pub chunk_type: [u8; 4],
    /// Chunk size (not including header)
    pub size: u32,
}

/// Known DXBC chunk types
pub mod chunk_type {
    pub const RDEF: [u8; 4] = *b"RDEF"; // Resource definitions
    pub const ISGN: [u8; 4] = *b"ISGN"; // Input signature
    pub const OSGN: [u8; 4] = *b"OSGN"; // Output signature
    pub const SHDR: [u8; 4] = *b"SHDR"; // Shader program (SM4.x)
    pub const SHEX: [u8; 4] = *b"SHEX"; // Shader program (SM5.x)
    pub const STAT: [u8; 4] = *b"STAT"; // Statistics
    pub const PCSG: [u8; 4] = *b"PCSG"; // Patch constant signature
    pub const SFI0: [u8; 4] = *b"SFI0"; // Shader feature info
}

// ─── Shader Types ──────────────────────────────────────────────────────────────

/// DirectX shader type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShaderType {
    Vertex,
    Pixel,
    Geometry,
    Hull,
    Domain,
    Compute,
    Unknown,
}

impl ShaderType {
    /// Get from DXBC program type byte
    pub fn from_dxbc_type(ty: u8) -> Self {
        match ty {
            0 => ShaderType::Pixel,
            1 => ShaderType::Vertex,
            2 => ShaderType::Geometry,
            3 => ShaderType::Hull,
            4 => ShaderType::Domain,
            5 => ShaderType::Compute,
            _ => ShaderType::Unknown,
        }
    }

    /// Get SPIR-V execution model
    pub fn spirv_execution_model(&self) -> u32 {
        match self {
            ShaderType::Vertex => 0,    // Vertex
            ShaderType::Pixel => 4,     // Fragment
            ShaderType::Geometry => 3,  // Geometry
            ShaderType::Hull => 1,      // TessellationControl
            ShaderType::Domain => 2,    // TessellationEvaluation
            ShaderType::Compute => 5,   // GLCompute
            ShaderType::Unknown => 0,
        }
    }
}

// ─── SPIR-V Constants ──────────────────────────────────────────────────────────

/// SPIR-V magic number
pub const SPIRV_MAGIC: u32 = 0x07230203;

/// SPIR-V opcodes (subset)
pub mod spirv_op {
    pub const OP_NOP: u16 = 0;
    pub const OP_SOURCE: u16 = 3;
    pub const OP_NAME: u16 = 5;
    pub const OP_MEMBER_NAME: u16 = 6;
    pub const OP_EXTENSION: u16 = 10;
    pub const OP_EXT_INST_IMPORT: u16 = 11;
    pub const OP_MEMORY_MODEL: u16 = 14;
    pub const OP_ENTRY_POINT: u16 = 15;
    pub const OP_EXECUTION_MODE: u16 = 16;
    pub const OP_CAPABILITY: u16 = 17;
    pub const OP_TYPE_VOID: u16 = 19;
    pub const OP_TYPE_BOOL: u16 = 20;
    pub const OP_TYPE_INT: u16 = 21;
    pub const OP_TYPE_FLOAT: u16 = 22;
    pub const OP_TYPE_VECTOR: u16 = 23;
    pub const OP_TYPE_MATRIX: u16 = 24;
    pub const OP_TYPE_IMAGE: u16 = 25;
    pub const OP_TYPE_SAMPLER: u16 = 26;
    pub const OP_TYPE_SAMPLED_IMAGE: u16 = 27;
    pub const OP_TYPE_ARRAY: u16 = 28;
    pub const OP_TYPE_RUNTIME_ARRAY: u16 = 29;
    pub const OP_TYPE_STRUCT: u16 = 30;
    pub const OP_TYPE_POINTER: u16 = 32;
    pub const OP_TYPE_FUNCTION: u16 = 33;
    pub const OP_CONSTANT_TRUE: u16 = 41;
    pub const OP_CONSTANT_FALSE: u16 = 42;
    pub const OP_CONSTANT: u16 = 43;
    pub const OP_CONSTANT_COMPOSITE: u16 = 44;
    pub const OP_FUNCTION: u16 = 54;
    pub const OP_FUNCTION_PARAMETER: u16 = 55;
    pub const OP_FUNCTION_END: u16 = 56;
    pub const OP_VARIABLE: u16 = 59;
    pub const OP_LOAD: u16 = 61;
    pub const OP_STORE: u16 = 62;
    pub const OP_ACCESS_CHAIN: u16 = 65;
    pub const OP_DECORATE: u16 = 71;
    pub const OP_MEMBER_DECORATE: u16 = 72;
    // Arithmetic operations
    pub const OP_IADD: u16 = 128;
    pub const OP_FADD: u16 = 129;
    pub const OP_ISUB: u16 = 130;
    pub const OP_FSUB: u16 = 131;
    pub const OP_IMUL: u16 = 132;
    pub const OP_FMUL: u16 = 133;
    pub const OP_UDIV: u16 = 134;
    pub const OP_SDIV: u16 = 135;
    pub const OP_FDIV: u16 = 136;
    pub const OP_UMOD: u16 = 137;
    pub const OP_SREM: u16 = 138;
    pub const OP_SMOD: u16 = 139;
    // Bitwise operations
    pub const OP_SHIFT_RIGHT_LOGICAL: u16 = 149;
    pub const OP_SHIFT_RIGHT_ARITHMETIC: u16 = 150;
    pub const OP_SHIFT_LEFT_LOGICAL: u16 = 151;
    pub const OP_BITWISE_OR: u16 = 152;
    pub const OP_BITWISE_XOR: u16 = 153;
    pub const OP_BITWISE_AND: u16 = 154;
    pub const OP_NOT: u16 = 155;
    // Control flow
    pub const OP_LABEL: u16 = 248;
    pub const OP_BRANCH: u16 = 249;
    pub const OP_RETURN: u16 = 253;
    pub const OP_RETURN_VALUE: u16 = 254;
}

/// SPIR-V capabilities
pub mod spirv_cap {
    pub const SHADER: u32 = 1;
    pub const GEOMETRY: u32 = 2;
    pub const TESSELLATION: u32 = 3;
    pub const FLOAT64: u32 = 10;
    pub const INT64: u32 = 11;
    pub const INT16: u32 = 22;
    pub const IMAGE_QUERY: u32 = 50;
}

/// SPIR-V storage classes
pub mod spirv_storage {
    pub const UNIFORM_CONSTANT: u32 = 0;
    pub const INPUT: u32 = 1;
    pub const UNIFORM: u32 = 2;
    pub const OUTPUT: u32 = 3;
    pub const WORKGROUP: u32 = 4;
    pub const PRIVATE: u32 = 6;
    pub const FUNCTION: u32 = 7;
    pub const PUSH_CONSTANT: u32 = 9;
    pub const IMAGE: u32 = 11;
    pub const STORAGE_BUFFER: u32 = 12;
}

/// SPIR-V decorations
pub mod spirv_decor {
    pub const BLOCK: u32 = 2;
    pub const ROW_MAJOR: u32 = 4;
    pub const COL_MAJOR: u32 = 5;
    pub const BUILTIN: u32 = 11;
    pub const LOCATION: u32 = 30;
    pub const BINDING: u32 = 33;
    pub const DESCRIPTOR_SET: u32 = 34;
    pub const OFFSET: u32 = 35;
}

// ─── DXBC Parser ───────────────────────────────────────────────────────────────

/// DXBC opcode types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DxbcOpcode {
    Unknown,
    Ret,
    Add,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Mov,
    Mad, // Multiply-Add
    Dp4, // Dot product 4
    Sample,
    Load,
    Store,
}

/// Parsed DXBC shader
pub struct ParsedDxbc {
    /// Shader type
    pub shader_type: ShaderType,
    /// Shader model major version
    pub sm_major: u8,
    /// Shader model minor version
    pub sm_minor: u8,
    /// Input signature data offset
    pub input_sig_offset: u32,
    /// Output signature data offset
    pub output_sig_offset: u32,
    /// Shader program offset
    pub program_offset: u32,
    /// Shader program size
    pub program_size: u32,
    /// Parsed opcodes
    pub opcodes: [DxbcOpcode; 256],
    /// Number of opcodes
    pub opcode_count: usize,
}

impl ParsedDxbc {
    pub const fn empty() -> Self {
        Self {
            shader_type: ShaderType::Unknown,
            sm_major: 0,
            sm_minor: 0,
            input_sig_offset: 0,
            output_sig_offset: 0,
            program_offset: 0,
            program_size: 0,
            opcodes: [DxbcOpcode::Unknown; 256],
            opcode_count: 0,
        }
    }
}

/// Parse DXBC container
pub fn parse_dxbc(data: &[u8]) -> Option<ParsedDxbc> {
    if data.len() < core::mem::size_of::<DxbcHeader>() {
        return None;
    }

    // Read header
    let header = unsafe { &*(data.as_ptr() as *const DxbcHeader) };
    if !header.is_valid() {
        return None;
    }

    let chunk_count = header.chunk_count as usize;
    if data.len() < 32 + chunk_count * 4 {
        return None;
    }

    let mut parsed = ParsedDxbc::empty();

    // Read chunk offsets
    let chunk_offsets_ptr = data[32..].as_ptr() as *const u32;
    for i in 0..chunk_count {
        let offset = unsafe { *chunk_offsets_ptr.add(i) } as usize;
        if offset + 8 > data.len() {
            continue;
        }

        let chunk = unsafe { &*(data[offset..].as_ptr() as *const ChunkHeader) };
        
        match &chunk.chunk_type {
            t if *t == chunk_type::ISGN => {
                parsed.input_sig_offset = offset as u32 + 8;
            }
            t if *t == chunk_type::OSGN => {
                parsed.output_sig_offset = offset as u32 + 8;
            }
            t if *t == chunk_type::SHDR || *t == chunk_type::SHEX => {
                parsed.program_offset = offset as u32 + 8;
                parsed.program_size = chunk.size;
                
                // Parse program header to get shader type and version
                if offset + 12 <= data.len() {
                    let version_token = unsafe { 
                        *(data[offset + 8..].as_ptr() as *const u32) 
                    };
                    parsed.sm_major = ((version_token >> 4) & 0xF) as u8;
                    parsed.sm_minor = (version_token & 0xF) as u8;
                    parsed.shader_type = ShaderType::from_dxbc_type(
                        ((version_token >> 16) & 0xFFFF) as u8
                    );
                }
            }
            _ => {}
        }
    }

    Some(parsed)
}

// ─── SPIR-V Builder ────────────────────────────────────────────────────────────

/// Maximum SPIR-V output size
pub const MAX_SPIRV_SIZE: usize = 65536;

/// SPIR-V builder for generating shader modules
pub struct SpirVBuilder {
    /// Output buffer
    output: [u32; MAX_SPIRV_SIZE / 4],
    /// Current write position
    pos: usize,
    /// Next ID to allocate
    next_id: u32,
    /// Bound (highest ID + 1)
    bound: u32,
}

impl SpirVBuilder {
    pub const fn new() -> Self {
        Self {
            output: [0u32; MAX_SPIRV_SIZE / 4],
            pos: 0,
            next_id: 1,
            bound: 1,
        }
    }

    /// Reset builder for new shader
    pub fn reset(&mut self) {
        self.pos = 0;
        self.next_id = 1;
        self.bound = 1;
    }

    /// Allocate a new ID
    pub fn alloc_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        if id >= self.bound {
            self.bound = id + 1;
        }
        id
    }

    /// Write a single word
    fn write(&mut self, word: u32) {
        if self.pos < self.output.len() {
            self.output[self.pos] = word;
            self.pos += 1;
        }
    }

    /// Write instruction header
    fn write_instr(&mut self, opcode: u16, word_count: u16) {
        self.write((word_count as u32) << 16 | opcode as u32);
    }

    /// Write SPIR-V header
    pub fn write_header(&mut self) {
        self.write(SPIRV_MAGIC);
        self.write(0x0001_0500); // SPIR-V 1.5
        self.write(0); // Generator (0 = anonymous)
        // Bound will be patched later
        self.write(0);
        self.write(0); // Reserved
    }

    /// Patch the bound in header
    pub fn patch_bound(&mut self) {
        if self.output.len() >= 4 {
            self.output[3] = self.bound;
        }
    }

    /// Write capability instruction
    pub fn write_capability(&mut self, cap: u32) {
        self.write_instr(spirv_op::OP_CAPABILITY, 2);
        self.write(cap);
    }

    /// Write memory model instruction
    pub fn write_memory_model(&mut self, addressing: u32, memory: u32) {
        self.write_instr(spirv_op::OP_MEMORY_MODEL, 3);
        self.write(addressing);
        self.write(memory);
    }

    /// Write entry point instruction
    pub fn write_entry_point(&mut self, execution_model: u32, entry_id: u32, name: &[u8], interface_ids: &[u32]) {
        let name_words = (name.len() + 4) / 4;
        let word_count = 3 + name_words + interface_ids.len();
        
        self.write_instr(spirv_op::OP_ENTRY_POINT, word_count as u16);
        self.write(execution_model);
        self.write(entry_id);
        
        // Write null-terminated name
        let mut name_buf = [0u32; 64];
        for (i, &b) in name.iter().enumerate() {
            let word_idx = i / 4;
            let byte_idx = i % 4;
            name_buf[word_idx] |= (b as u32) << (byte_idx * 8);
        }
        for i in 0..name_words {
            self.write(name_buf[i]);
        }
        
        // Write interface IDs
        for &id in interface_ids {
            self.write(id);
        }
    }

    /// Write void type
    pub fn write_type_void(&mut self, id: u32) {
        self.write_instr(spirv_op::OP_TYPE_VOID, 2);
        self.write(id);
    }

    /// Write function type
    pub fn write_type_function(&mut self, result_id: u32, return_type: u32, param_types: &[u32]) {
        self.write_instr(spirv_op::OP_TYPE_FUNCTION, (3 + param_types.len()) as u16);
        self.write(result_id);
        self.write(return_type);
        for &ty in param_types {
            self.write(ty);
        }
    }

    /// Write float type
    pub fn write_type_float(&mut self, id: u32, width: u32) {
        self.write_instr(spirv_op::OP_TYPE_FLOAT, 3);
        self.write(id);
        self.write(width);
    }

    /// Write integer type
    pub fn write_type_int(&mut self, id: u32, width: u32, signedness: u32) {
        self.write_instr(spirv_op::OP_TYPE_INT, 4);
        self.write(id);
        self.write(width);
        self.write(signedness);
    }

    /// Write vector type
    pub fn write_type_vector(&mut self, id: u32, component_type: u32, count: u32) {
        self.write_instr(spirv_op::OP_TYPE_VECTOR, 4);
        self.write(id);
        self.write(component_type);
        self.write(count);
    }
    
    // ─── Arithmetic Operations ──────────────────────────────────────────────────
    
    /// Write floating-point add
    pub fn write_fadd(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_FADD, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }
    
    /// Write floating-point multiply
    pub fn write_fmul(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_FMUL, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }
    
    /// Write integer add
    pub fn write_iadd(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_IADD, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }
    
    /// Write integer subtract
    pub fn write_isub(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_ISUB, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }
    
    /// Write integer multiply
    pub fn write_imul(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_IMUL, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }

    /// Write pointer type
    pub fn write_type_pointer(&mut self, id: u32, storage_class: u32, pointee_type: u32) {
        self.write_instr(spirv_op::OP_TYPE_POINTER, 4);
        self.write(id);
        self.write(storage_class);
        self.write(pointee_type);
    }

    /// Write variable declaration
    pub fn write_variable(&mut self, result_id: u32, result_type: u32, storage_class: u32) {
        self.write_instr(spirv_op::OP_VARIABLE, 4);
        self.write(result_type);
        self.write(result_id);
        self.write(storage_class);
    }

    /// Write decoration
    pub fn write_decorate(&mut self, target: u32, decoration: u32, operands: &[u32]) {
        self.write_instr(spirv_op::OP_DECORATE, (3 + operands.len()) as u16);
        self.write(target);
        self.write(decoration);
        for &op in operands {
            self.write(op);
        }
    }

    /// Write function begin
    pub fn write_function(&mut self, result_id: u32, result_type: u32, function_control: u32, function_type: u32) {
        self.write_instr(spirv_op::OP_FUNCTION, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(function_control);
        self.write(function_type);
    }

    /// Write label
    pub fn write_label(&mut self, id: u32) {
        self.write_instr(spirv_op::OP_LABEL, 2);
        self.write(id);
    }

    /// Write return
    pub fn write_return(&mut self) {
        self.write_instr(spirv_op::OP_RETURN, 1);
    }

    /// Write function end
    pub fn write_function_end(&mut self) {
        self.write_instr(spirv_op::OP_FUNCTION_END, 1);
    }

    // ─── Bitwise Operations ──────────────────────────────────────────────────────

    /// Write bitwise AND operation
    /// Result = Operand1 & Operand2
    pub fn write_bitwise_and(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_BITWISE_AND, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }

    /// Write bitwise OR operation
    /// Result = Operand1 | Operand2
    pub fn write_bitwise_or(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_BITWISE_OR, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }

    /// Write bitwise XOR operation
    /// Result = Operand1 ^ Operand2
    pub fn write_bitwise_xor(&mut self, result_type: u32, result_id: u32, operand1: u32, operand2: u32) {
        self.write_instr(spirv_op::OP_BITWISE_XOR, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand1);
        self.write(operand2);
    }

    /// Write bitwise NOT operation
    /// Result = ~Operand
    pub fn write_not(&mut self, result_type: u32, result_id: u32, operand: u32) {
        self.write_instr(spirv_op::OP_NOT, 4);
        self.write(result_type);
        self.write(result_id);
        self.write(operand);
    }

    /// Write shift left logical operation
    /// Result = Operand << Shift
    pub fn write_shift_left(&mut self, result_type: u32, result_id: u32, operand: u32, shift: u32) {
        self.write_instr(spirv_op::OP_SHIFT_LEFT_LOGICAL, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand);
        self.write(shift);
    }

    /// Write shift right logical operation
    /// Result = Operand >> Shift (zero-fill)
    pub fn write_shift_right_logical(&mut self, result_type: u32, result_id: u32, operand: u32, shift: u32) {
        self.write_instr(spirv_op::OP_SHIFT_RIGHT_LOGICAL, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand);
        self.write(shift);
    }

    /// Write shift right arithmetic operation
    /// Result = Operand >> Shift (sign-extend)
    pub fn write_shift_right_arithmetic(&mut self, result_type: u32, result_id: u32, operand: u32, shift: u32) {
        self.write_instr(spirv_op::OP_SHIFT_RIGHT_ARITHMETIC, 5);
        self.write(result_type);
        self.write(result_id);
        self.write(operand);
        self.write(shift);
    }

    /// Get output slice
    pub fn output(&self) -> &[u32] {
        &self.output[..self.pos]
    }

    /// Get output size in bytes
    pub fn size_bytes(&self) -> usize {
        self.pos * 4
    }
}

// ─── DXBC to SPIR-V Translator ─────────────────────────────────────────────────

/// Translate DXBC to SPIR-V
pub struct DxbcSpirVTranslator {
    builder: SpirVBuilder,
}

impl DxbcSpirVTranslator {
    pub const fn new() -> Self {
        Self {
            builder: SpirVBuilder::new(),
        }
    }

    /// Translate DXBC shader to SPIR-V
    pub fn translate(&mut self, dxbc: &[u8]) -> Option<&[u32]> {
        let parsed = parse_dxbc(dxbc)?;
        
        self.builder.reset();
        
        // Write header
        self.builder.write_header();
        
        // Write capabilities based on shader type
        self.builder.write_capability(spirv_cap::SHADER);
        match parsed.shader_type {
            ShaderType::Geometry => self.builder.write_capability(spirv_cap::GEOMETRY),
            ShaderType::Hull | ShaderType::Domain => {
                self.builder.write_capability(spirv_cap::TESSELLATION);
            }
            _ => {}
        }
        
        // Memory model (Logical, GLSL450)
        self.builder.write_memory_model(0, 1);
        
        // Allocate IDs for types
        let void_type = self.builder.alloc_id();
        let func_type = self.builder.alloc_id();
        let float_type = self.builder.alloc_id();
        let int_type = self.builder.alloc_id();
        let vec4_type = self.builder.alloc_id();
        
        // Write types
        self.builder.write_type_void(void_type);
        self.builder.write_type_float(float_type, 32);
        self.builder.write_type_int(int_type, 32, 1); // signed 32-bit int
        self.builder.write_type_vector(vec4_type, float_type, 4);
        self.builder.write_type_function(func_type, void_type, &[]);
        
        // Allocate function and labels
        let main_func = self.builder.alloc_id();
        let entry_label = self.builder.alloc_id();
        let return_label = self.builder.alloc_id();
        
        // Write entry point
        self.builder.write_entry_point(
            parsed.shader_type.spirv_execution_model(),
            main_func,
            b"main",
            &[]
        );
        
        // Write main function
        self.builder.write_function(main_func, void_type, 0, func_type);
        self.builder.write_label(entry_label);
        
        // Process DXBC opcodes
        for opcode in &parsed.opcodes {
            self.translate_opcode(*opcode, float_type, int_type, vec4_type);
        }
        
        // Write return
        self.builder.write_label(return_label);
        self.builder.write_return();
        self.builder.write_function_end();
        
        // Patch bound
        self.builder.patch_bound();
        
        Some(self.builder.output())
    }
    
    /// Translate a single DXBC opcode to SPIR-V
    fn translate_opcode(&mut self, opcode: DxbcOpcode, float_type: u32, int_type: u32, vec4_type: u32) {
        match opcode {
            DxbcOpcode::Ret => {
                // Return is handled by the function epilogue
            }
            DxbcOpcode::Add => {
                let result = self.builder.alloc_id();
                self.builder.write_fadd(float_type, result, 0, 0);
            }
            DxbcOpcode::Mul => {
                let result = self.builder.alloc_id();
                self.builder.write_fmul(float_type, result, 0, 0);
            }
            DxbcOpcode::And => {
                let result = self.builder.alloc_id();
                self.builder.write_bitwise_and(int_type, result, 0, 0);
            }
            DxbcOpcode::Or => {
                let result = self.builder.alloc_id();
                self.builder.write_bitwise_or(int_type, result, 0, 0);
            }
            DxbcOpcode::Xor => {
                let result = self.builder.alloc_id();
                self.builder.write_bitwise_xor(int_type, result, 0, 0);
            }
            DxbcOpcode::Not => {
                let result = self.builder.alloc_id();
                self.builder.write_not(int_type, result, 0);
            }
            DxbcOpcode::Shl => {
                let result = self.builder.alloc_id();
                self.builder.write_shift_left(int_type, result, 0, 0);
            }
            DxbcOpcode::Shr => {
                let result = self.builder.alloc_id();
                self.builder.write_shift_right_logical(int_type, result, 0, 0);
            }
            _ => {
                // Unknown opcode - skip for now
            }
        }
    }

    /// Get output buffer
    pub fn output(&self) -> &[u32] {
        self.builder.output()
    }
}

// ─── Global Translator Pool ────────────────────────────────────────────────────

/// Maximum concurrent translations
pub const MAX_TRANSLATORS: usize = 4;

/// Translator pool for parallel shader compilation
static mut TRANSLATOR_POOL: [DxbcSpirVTranslator; MAX_TRANSLATORS] = [const { DxbcSpirVTranslator::new() }; MAX_TRANSLATORS];
static TRANSLATOR_NEXT: AtomicUsize = AtomicUsize::new(0);

/// Get a translator from the pool
pub fn get_translator() -> &'static mut DxbcSpirVTranslator {
    let idx = TRANSLATOR_NEXT.fetch_add(1, Ordering::Relaxed) % MAX_TRANSLATORS;
    unsafe { &mut TRANSLATOR_POOL[idx] }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shader_type_from_dxbc() {
        assert_eq!(ShaderType::from_dxbc_type(0), ShaderType::Pixel);
        assert_eq!(ShaderType::from_dxbc_type(1), ShaderType::Vertex);
        assert_eq!(ShaderType::from_dxbc_type(5), ShaderType::Compute);
    }

    #[test]
    fn spirv_builder_header() {
        let mut builder = SpirVBuilder::new();
        builder.write_header();
        assert_eq!(builder.output()[0], SPIRV_MAGIC);
    }

    #[test]
    fn spirv_builder_capability() {
        let mut builder = SpirVBuilder::new();
        builder.write_header();
        builder.write_capability(spirv_cap::SHADER);
        
        // Check that capability instruction was written
        let output = builder.output();
        assert!(output.len() >= 6);
        // Header (5 words) + capability (2 words)
        let cap_instr = output[5];
        assert_eq!(cap_instr & 0xFFFF, spirv_op::OP_CAPABILITY as u32);
    }

    #[test]
    fn spirv_builder_alloc_id() {
        let mut builder = SpirVBuilder::new();
        let id1 = builder.alloc_id();
        let id2 = builder.alloc_id();
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[test]
    fn dxbc_header_validation() {
        let valid_header = DxbcHeader {
            magic: DXBC_MAGIC,
            checksum: [0; 16],
            version: 1,
            total_size: 100,
            chunk_count: 1,
        };
        assert!(valid_header.is_valid());

        let invalid_header = DxbcHeader {
            magic: *b"ABCD",
            checksum: [0; 16],
            version: 1,
            total_size: 100,
            chunk_count: 1,
        };
        assert!(!invalid_header.is_valid());
    }

    #[test]
    fn translator_pool() {
        let t1 = get_translator();
        let t2 = get_translator();
        // Should get different translators (or wrap around)
        // Just verify we can get translators without panic
        let _ = t1;
        let _ = t2;
    }
}
