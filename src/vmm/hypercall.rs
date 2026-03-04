//! Paravirtual hypercall interface for guest OS communication.
//!
//! Provides a standardized hypercall mechanism for guest OSes like echOS
//! to communicate with the hypervisor for operations like:
//! - Console I/O
//! - Memory management
//! - Shutdown/reboot
//! - Time synchronization

use crate::vmm::{HvError, HvResult};

/// Hypercall numbers (passed in RAX)
pub mod hypercall {
    pub const NOP: u64 = 0;
    pub const CONSOLE_WRITE: u64 = 1;
    pub const CONSOLE_READ: u64 = 2;
    pub const GET_TIME: u64 = 3;
    pub const SET_TIME: u64 = 4;
    pub const SHUTDOWN: u64 = 5;
    pub const REBOOT: u64 = 6;
    pub const GET_MEMORY_INFO: u64 = 7;
    pub const MAP_PAGE: u64 = 8;
    pub const UNMAP_PAGE: u64 = 9;
    pub const GRANT_DMA: u64 = 10;
    pub const REVOKE_DMA: u64 = 11;
    pub const SEND_IPI: u64 = 12;
    pub const GET_VCPU_COUNT: u64 = 13;
    pub const SET_VCPU_STATE: u64 = 14;
    pub const VM_DEBUG: u64 = 15;
    pub const GET_FEATURES: u64 = 16;
    pub const REGISTER_IRQ_HANDLER: u64 = 17;
    pub const ACK_IRQ: u64 = 18;
}

/// Hypercall result codes (returned in RAX)
pub mod result {
    pub const SUCCESS: u64 = 0;
    pub const ERROR_INVALID_ARG: u64 = 1;
    pub const ERROR_NOT_SUPPORTED: u64 = 2;
    pub const ERROR_NO_MEMORY: u64 = 3;
    pub const ERROR_PERMISSION_DENIED: u64 = 4;
    pub const ERROR_BUSY: u64 = 5;
    pub const ERROR_IO_ERROR: u64 = 6;
}

/// Hypercall feature flags
pub mod feature {
    pub const CONSOLE: u64 = 1 << 0;
    pub const TIME: u64 = 1 << 1;
    pub const SHUTDOWN: u64 = 1 << 2;
    pub const MEMORY: u64 = 1 << 3;
    pub const DMA: u64 = 1 << 4;
    pub const IPI: u64 = 1 << 5;
    pub const VCPU_CONTROL: u64 = 1 << 6;
    pub const IRQ_HANDLERS: u64 = 1 << 7;
    pub const ALL: u64 = CONSOLE | TIME | SHUTDOWN | MEMORY | DMA | IPI | VCPU_CONTROL | IRQ_HANDLERS;
}

/// Console output buffer (circular buffer)
pub const CONSOLE_BUFFER_SIZE: usize = 4096;

/// Hypercall context passed from guest
#[derive(Debug, Clone, Copy)]
pub struct HypercallContext {
    /// Hypercall number (RAX)
    pub number: u64,
    /// Arguments (RBX, RCX, RDX, RSI, RDI, R8)
    pub args: [u64; 6],
    /// Guest physical address for data transfer (if needed)
    pub data_gpa: u64,
    /// Data length
    pub data_len: u64,
    /// Optional GuestMemory reference for memory queries
    pub guest_mem: Option<*const crate::vmm::guest_memory::GuestMemory>,
}

impl HypercallContext {
    pub fn new(number: u64, args: [u64; 6]) -> Self {
        Self {
            number,
            args,
            data_gpa: 0,
            data_len: 0,
            guest_mem: None,
        }
    }

    /// Create context with GuestMemory reference
    pub fn with_guest_mem(number: u64, args: [u64; 6], guest_mem: *const crate::vmm::guest_memory::GuestMemory) -> Self {
        Self {
            number,
            args,
            data_gpa: 0,
            data_len: 0,
            guest_mem: Some(guest_mem),
        }
    }
}

/// Hypercall handler trait
pub trait HypercallHandler {
    /// Handle a hypercall and return the result code.
    fn handle(&mut self, ctx: &HypercallContext) -> u64;
}

/// Default hypercall handler for basic operations
pub struct DefaultHypercallHandler {
    /// Console output buffer
    console_buffer: [u8; CONSOLE_BUFFER_SIZE],
    console_head: usize,
    console_tail: usize,
    /// VM shutdown request flag
    shutdown_requested: bool,
    /// Reboot request flag
    reboot_requested: bool,
    /// Number of vCPUs
    vcpu_count: u32,
}

impl DefaultHypercallHandler {
    pub const fn new() -> Self {
        Self {
            console_buffer: [0u8; CONSOLE_BUFFER_SIZE],
            console_head: 0,
            console_tail: 0,
            shutdown_requested: false,
            reboot_requested: false,
            vcpu_count: 1,
        }
    }

    pub fn with_vcpu_count(mut self, count: u32) -> Self {
        self.vcpu_count = count;
        self
    }

    /// Check if shutdown was requested
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Check if reboot was requested
    pub fn is_reboot_requested(&self) -> bool {
        self.reboot_requested
    }

    /// Get console output buffer content
    pub fn get_console_output(&self) -> &[u8] {
        if self.console_tail <= self.console_head {
            &self.console_buffer[self.console_tail..self.console_head]
        } else {
            // Wrapped - return partial, caller should call again
            &self.console_buffer[self.console_tail..]
        }
    }

    /// Clear consumed console output
    pub fn consume_console_output(&mut self, len: usize) {
        self.console_tail = (self.console_tail + len) % CONSOLE_BUFFER_SIZE;
    }

    /// Handle console write hypercall
    fn handle_console_write(&mut self, ctx: &HypercallContext) -> u64 {
        // ctx.args[0] = pointer to string in guest memory (GPA)
        // ctx.args[1] = length of string
        // ctx.data_gpa = alternative data source (set by VMX handler)
        let gpa = if ctx.data_gpa != 0 { ctx.data_gpa } else { ctx.args[0] };
        let len = ctx.args[1] as usize;

        if len == 0 {
            return result::SUCCESS;
        }

        // Limit write length to buffer capacity
        let write_len = len.min(CONSOLE_BUFFER_SIZE / 2);
        
        // Use DMA engine to read from guest memory
        for i in 0..write_len {
            let idx = (self.console_head + i) % CONSOLE_BUFFER_SIZE;
            let byte_gpa = gpa + i as u64;
            
            // Read byte from guest memory via DMA
            let byte = crate::vmm::virtio_direct().dma.read_u8(byte_gpa);
            match byte {
                Some(b) => self.console_buffer[idx] = b,
                None => self.console_buffer[idx] = b'?', // Replacement for unreadable
            }
        }
        self.console_head = (self.console_head + write_len) % CONSOLE_BUFFER_SIZE;

        result::SUCCESS
    }

    /// Handle console write with actual data buffer (called from VMX handler)
    pub fn handle_console_write_data(&mut self, data: &[u8]) -> u64 {
        let write_len = data.len().min(CONSOLE_BUFFER_SIZE / 2);
        
        for i in 0..write_len {
            let idx = (self.console_head + i) % CONSOLE_BUFFER_SIZE;
            self.console_buffer[idx] = data[i];
        }
        self.console_head = (self.console_head + write_len) % CONSOLE_BUFFER_SIZE;

        result::SUCCESS
    }

    /// Handle get time hypercall
    fn handle_get_time(&self, ctx: &HypercallContext) -> u64 {
        // Return TSC value or formatted time
        // ctx.args[0] = pointer to receive time structure
        
        #[cfg(target_arch = "x86_64")]
        let tsc = unsafe { core::arch::x86_64::_rdtsc() };
        #[cfg(not(target_arch = "x86_64"))]
        let tsc = 0u64;

        // Return TSC in result
        tsc
    }

    /// Handle shutdown hypercall
    fn handle_shutdown(&mut self) -> u64 {
        self.shutdown_requested = true;
        result::SUCCESS
    }

    /// Handle reboot hypercall
    fn handle_reboot(&mut self) -> u64 {
        self.reboot_requested = true;
        result::SUCCESS
    }

    /// Handle get memory info hypercall
    fn handle_get_memory_info(&self, ctx: &HypercallContext) -> u64 {
        // ctx.args[0] = pointer to memory info structure in guest memory
        // ctx.guest_mem = optional reference to GuestMemory for actual query
        
        // Query actual memory info from GuestMemory if available
        let (total_kb, free_kb) = if let Some(guest_mem) = ctx.guest_mem {
            // guest_mem is a raw pointer, need unsafe deref
            let gm = unsafe { &*guest_mem };
            let total = gm.memory_limit() / 1024;
            let used = gm.allocated_bytes() / 1024;
            (total, total.saturating_sub(used))
        } else {
            // Fallback: estimate based on vcpu_count
            let total_kb = (self.vcpu_count as u64) * 32 * 1024; // 32MB per vCPU
            (total_kb, total_kb / 2)
        };
        
        // Return: total_memory_kb in low 32 bits, free_memory_kb in high 32 bits
        ((free_kb & 0xFFFF_FFFF) << 32) | (total_kb & 0xFFFF_FFFF)
    }

    /// Handle get vCPU count hypercall
    fn handle_get_vcpu_count(&self) -> u64 {
        self.vcpu_count as u64
    }

    /// Handle get features hypercall
    fn handle_get_features() -> u64 {
        feature::ALL
    }
}

impl HypercallHandler for DefaultHypercallHandler {
    fn handle(&mut self, ctx: &HypercallContext) -> u64 {
        match ctx.number {
            hypercall::NOP => result::SUCCESS,
            hypercall::CONSOLE_WRITE => self.handle_console_write(ctx),
            hypercall::CONSOLE_READ => result::ERROR_NOT_SUPPORTED,
            hypercall::GET_TIME => self.handle_get_time(ctx),
            hypercall::SET_TIME => result::ERROR_NOT_SUPPORTED,
            hypercall::SHUTDOWN => self.handle_shutdown(),
            hypercall::REBOOT => self.handle_reboot(),
            hypercall::GET_MEMORY_INFO => self.handle_get_memory_info(ctx),
            hypercall::MAP_PAGE => result::ERROR_NOT_SUPPORTED,
            hypercall::UNMAP_PAGE => result::ERROR_NOT_SUPPORTED,
            hypercall::GRANT_DMA => result::ERROR_NOT_SUPPORTED,
            hypercall::REVOKE_DMA => result::ERROR_NOT_SUPPORTED,
            hypercall::SEND_IPI => result::ERROR_NOT_SUPPORTED,
            hypercall::GET_VCPU_COUNT => self.handle_get_vcpu_count(),
            hypercall::SET_VCPU_STATE => result::ERROR_NOT_SUPPORTED,
            hypercall::VM_DEBUG => {
                // Debug hypercall - could trigger logging or breakpoint
                result::SUCCESS
            }
            hypercall::GET_FEATURES => Self::handle_get_features(),
            hypercall::REGISTER_IRQ_HANDLER => result::ERROR_NOT_SUPPORTED,
            hypercall::ACK_IRQ => result::ERROR_NOT_SUPPORTED,
            _ => result::ERROR_NOT_SUPPORTED,
        }
    }
}

impl Default for DefaultHypercallHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatch a hypercall from the VMX exit handler.
/// Returns the result code to be written to guest RAX.
pub fn dispatch_hypercall(ctx: &HypercallContext, handler: &mut DefaultHypercallHandler) -> u64 {
    handler.handle(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nop_hypercall() {
        let mut handler = DefaultHypercallHandler::new();
        let ctx = HypercallContext::new(hypercall::NOP, [0; 6]);
        assert_eq!(handler.handle(&ctx), result::SUCCESS);
    }

    #[test]
    fn shutdown_hypercall() {
        let mut handler = DefaultHypercallHandler::new();
        let ctx = HypercallContext::new(hypercall::SHUTDOWN, [0; 6]);
        assert_eq!(handler.handle(&ctx), result::SUCCESS);
        assert!(handler.is_shutdown_requested());
    }

    #[test]
    fn get_vcpu_count() {
        let mut handler = DefaultHypercallHandler::new().with_vcpu_count(4);
        let ctx = HypercallContext::new(hypercall::GET_VCPU_COUNT, [0; 6]);
        assert_eq!(handler.handle(&ctx), 4);
    }

    #[test]
    fn get_features() {
        let mut handler = DefaultHypercallHandler::new();
        let ctx = HypercallContext::new(hypercall::GET_FEATURES, [0; 6]);
        let features = handler.handle(&ctx);
        assert!(features & feature::CONSOLE != 0);
        assert!(features & feature::SHUTDOWN != 0);
    }
}
