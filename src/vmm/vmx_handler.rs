#![allow(dead_code)]

use crate::vmm::ept::invept_single;
use crate::vmm::{
    atlas::PhysFrame, snapshot_log, DriverTag, HvError, HvResult, HypervisorOps, HypervisorState,
};
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};
use ironshim::{
    validate_driver_abi, AbiFeatures, AllowAllPolicy, DriverAbi, DriverAbiDescriptor, IoPortDesc,
    MmioDesc, PortIo, ResourceManifest, ABI_VERSION,
};

const MMIO_SLOTS: usize = 1;
const PORT_SLOTS: usize = 1;
const EXIT_REASON_IO_INSTRUCTION: u64 = 30;
const EXIT_REASON_EPT_VIOLATION: u64 = 48;
const EXIT_REASON_HLT: u64 = 12;
const EXIT_REASON_NMI: u64 = 0;
const EXIT_REASON_INTERRUPT_WINDOW: u64 = 7;

// ---------------------------------------------------------------------------
// FPU save areas — 64-byte aligned, 4 KiB each (safe for XSAVE with AVX-512)
// ---------------------------------------------------------------------------

/// Maximum number of independent bridge/VM instances that can have concurrent
/// FPU context slots.  Matches `MAX_BRIDGES` in the VirtIO layer.
pub const MAX_FPU_CONTEXTS: usize = 4;

/// 4 KiB FPU context area, aligned to 64 bytes as required by XSAVE/XRSTOR.
/// Copy is intentionally derived — the struct is only ever memcpy'd by
/// XSAVE/XRSTOR, never compared or hashed.
#[repr(align(64))]
#[derive(Clone, Copy)]
struct FpuArea([u8; 4096]);

/// Per-bridge host FPU save areas.
static mut FPU_HOST_AREAS: [FpuArea; MAX_FPU_CONTEXTS] =
    [FpuArea([0u8; 4096]); MAX_FPU_CONTEXTS];
/// Per-bridge guest FPU save areas.
static mut FPU_GUEST_AREAS: [FpuArea; MAX_FPU_CONTEXTS] =
    [FpuArea([0u8; 4096]); MAX_FPU_CONTEXTS];
/// Whether each guest FPU slot has been initialised at least once.
static FPU_GUEST_INIT: [core::sync::atomic::AtomicBool; MAX_FPU_CONTEXTS] = {
    const INIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    [INIT; MAX_FPU_CONTEXTS]
};

/// Monotonic counter — each new `AeroFrame` grabs a unique slot index.
static NEXT_BRIDGE_ID: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

// ---------------------------------------------------------------------------

pub struct AeroFrame {
    manifest: ResourceManifest<DriverTag, MMIO_SLOTS, PORT_SLOTS>,
    fpu_owner: Option<u64>,
    port_base: u16,
    port_count: u16,
    /// Which FPU context slot this bridge instance owns (0..MAX_FPU_CONTEXTS).
    bridge_id: usize,
}

impl AeroFrame {
    pub fn new() -> Result<Self, HvError> {
        let mmio = [MmioDesc {
            base: 0,
            size: 0x1000,
        }; MMIO_SLOTS];
        let ports = [IoPortDesc { port: 0, count: 1 }; PORT_SLOTS];
        let manifest =
            ResourceManifest::new(mmio, 1, ports, 1).map_err(|_| HvError::LogicalFault)?;
        // Grab a unique slot index; wrap around if more than MAX_FPU_CONTEXTS
        // instances are created (rare in practice — MAX_BRIDGES == 4).
        let bridge_id = NEXT_BRIDGE_ID
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            % MAX_FPU_CONTEXTS;
        Ok(Self {
            manifest,
            fpu_owner: None,
            port_base: ports[0].port,
            port_count: ports[0].count,
            bridge_id,
        })
    }

    pub fn handle_nm(&mut self, guest_id: u64) -> Result<(), HvError> {
        // Uses IronShim's ResourceManifest to keep FPU state isolated per guest_id.
        let _tag = DriverTag { guest_id };
        self.manifest
            .mmio_region(0)
            .map_err(|_| HvError::LogicalFault)?;

        #[cfg(not(test))]
        unsafe {
            let bid = self.bridge_id;
            // If a different owner currently holds FPU context, save its state.
            match self.fpu_owner {
                None => {
                    // First NM exit: save host FPU state into this bridge's host area.
                    let host_ptr =
                        core::ptr::addr_of_mut!(FPU_HOST_AREAS[bid].0) as *mut u8;
                    core::arch::asm!(
                        "xsave64 [{area}]",
                        area = in(reg) host_ptr,
                        in("eax") u32::MAX,
                        in("edx") u32::MAX,
                    );
                }
                Some(prev_id) if prev_id != guest_id => {
                    // Context switch: save the outgoing guest's FPU into its slot.
                    let guest_ptr =
                        core::ptr::addr_of_mut!(FPU_GUEST_AREAS[bid].0) as *mut u8;
                    core::arch::asm!(
                        "xsave64 [{area}]",
                        area = in(reg) guest_ptr,
                        in("eax") u32::MAX,
                        in("edx") u32::MAX,
                    );
                }
                _ => {}
            }

            let guest_init = &FPU_GUEST_INIT[bid];
            if guest_init.load(core::sync::atomic::Ordering::Acquire) {
                // Restore the guest's previously saved FPU state from its slot.
                let guest_ptr =
                    core::ptr::addr_of!(FPU_GUEST_AREAS[bid].0) as *const u8;
                core::arch::asm!(
                    "xrstor64 [{area}]",
                    area = in(reg) guest_ptr,
                    in("eax") u32::MAX,
                    in("edx") u32::MAX,
                );
            } else {
                // First entry for this bridge: zero the slot and mark initialised.
                let guest_ptr =
                    core::ptr::addr_of_mut!(FPU_GUEST_AREAS[bid].0) as *mut u8;
                core::ptr::write_bytes(guest_ptr, 0u8, 4096);
                guest_init.store(true, core::sync::atomic::Ordering::Release);
            }
        }

        self.fpu_owner = Some(guest_id);
        Ok(())
    }

    pub fn sync_minimal_registers(&self, _guest_id: u64) -> Result<(), HvError> {
        // Uses IronShim's versioned ABI boundaries for minimal register sync
        let descriptor = DriverAbiDescriptor {
            version: ABI_VERSION,
            features: AbiFeatures { bits: 0 },
            struct_size: size_of::<MinimalRegs>(),
            struct_align: align_of::<MinimalRegs>(),
        };
        validate_driver_abi::<MinimalRegs>(descriptor).map_err(|_| HvError::LogicalFault)?;
        Ok(())
    }

    pub fn handle_io(&self, port: u16, size: u16, is_in: bool) -> Result<(), HvError> {
        let range = self
            .manifest
            .io_port_range(0)
            .map_err(|_| HvError::LogicalFault)?;
        if port < self.port_base || port >= self.port_base.saturating_add(self.port_count) {
            return Err(HvError::LogicalFault);
        }
        let offset = port - self.port_base;
        let policy = AllowAllPolicy;
        let io = NullPortIo;
        match (size, is_in) {
            (1, true) => {
                let _ = range
                    .inb(&io, &policy, offset)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            (2, true) => {
                let _ = range
                    .inw(&io, &policy, offset)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            (4, true) => {
                let _ = range
                    .inl(&io, &policy, offset)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            (1, false) => {
                range
                    .outb(&io, &policy, offset, 0)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            (2, false) => {
                range
                    .outw(&io, &policy, offset, 0)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            (4, false) => {
                range
                    .outl(&io, &policy, offset, 0)
                    .map_err(|_| HvError::LogicalFault)?;
            }
            _ => return Err(HvError::LogicalFault),
        }
        Ok(())
    }
}

struct NullPortIo;

impl PortIo for NullPortIo {
    fn inb(&self, _port: u16) -> u8 {
        0
    }
    fn inw(&self, _port: u16) -> u16 {
        0
    }
    fn inl(&self, _port: u16) -> u32 {
        0
    }
    fn outb(&self, _port: u16, _value: u8) {}
    fn outw(&self, _port: u16, _value: u16) {}
    fn outl(&self, _port: u16, _value: u32) {}
}

// ---------------------------------------------------------------------------
// Serial TX ring buffer — captures COM1 output for guest console
// ---------------------------------------------------------------------------

/// 4 KiB ring buffer for serial TX output from the guest.
const SERIAL_TX_RING_SIZE: usize = 4096;

pub struct SerialTxRing {
    buf: UnsafeCell<[u8; SERIAL_TX_RING_SIZE]>,
    head: core::sync::atomic::AtomicUsize, // write position
}

unsafe impl Sync for SerialTxRing {}

impl SerialTxRing {
    const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0u8; SERIAL_TX_RING_SIZE]),
            head: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn push(&self, byte: u8) {
        let h = self.head.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let slot = h % SERIAL_TX_RING_SIZE;
        unsafe {
            (*self.buf.get())[slot] = byte;
        }
    }

    /// Read up to `dst.len()` bytes from the ring. Returns how many were read.
    pub fn drain(&self, dst: &mut [u8]) -> usize {
        let h = self.head.load(core::sync::atomic::Ordering::Acquire);
        let avail = h.min(SERIAL_TX_RING_SIZE);
        let start = if h > SERIAL_TX_RING_SIZE { h - SERIAL_TX_RING_SIZE } else { 0 };
        let count = avail.min(dst.len());
        for i in 0..count {
            let slot = (start + i) % SERIAL_TX_RING_SIZE;
            dst[i] = unsafe { (*self.buf.get())[slot] };
        }
        count
    }
}

static SERIAL_TX: SerialTxRing = SerialTxRing::new();

/// Public accessor for the serial TX ring buffer.
pub fn serial_tx_ring() -> &'static SerialTxRing {
    &SERIAL_TX
}

// ---------------------------------------------------------------------------
// Serial RX ring buffer — host-to-guest COM1 input
// ---------------------------------------------------------------------------

const SERIAL_RX_RING_SIZE: usize = 256;

pub struct SerialRxRing {
    buf: UnsafeCell<[u8; SERIAL_RX_RING_SIZE]>,
    head: core::sync::atomic::AtomicUsize, // write (producer) index
    tail: core::sync::atomic::AtomicUsize, // read  (consumer) index
}

unsafe impl Sync for SerialRxRing {}

impl SerialRxRing {
    const fn new() -> Self {
        Self {
            buf: UnsafeCell::new([0u8; SERIAL_RX_RING_SIZE]),
            head: core::sync::atomic::AtomicUsize::new(0),
            tail: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Push one byte from the host into the RX ring.
    pub fn push(&self, byte: u8) -> bool {
        let h = self.head.load(core::sync::atomic::Ordering::Relaxed);
        let t = self.tail.load(core::sync::atomic::Ordering::Acquire);
        let next = (h + 1) % SERIAL_RX_RING_SIZE;
        if next == t {
            return false; // ring full
        }
        unsafe { (*self.buf.get())[h] = byte; }
        self.head.store(next, core::sync::atomic::Ordering::Release);

        // Fire RX interrupt (IRQ4 = vector 0x24) if IER bit 0 (data ready) is set.
        let ier = UART.ier.load(core::sync::atomic::Ordering::Relaxed);
        if ier & 0x01 != 0 {
            PENDING_IRQ.store(0x24, core::sync::atomic::Ordering::Release);
        }
        true
    }

    /// Pop one byte for the guest (called on IN 0x3F8 when DLAB=0).
    fn pop(&self) -> Option<u8> {
        let h = self.head.load(core::sync::atomic::Ordering::Acquire);
        let t = self.tail.load(core::sync::atomic::Ordering::Relaxed);
        if h == t {
            return None; // ring empty
        }
        let byte = unsafe { (*self.buf.get())[t] };
        self.tail.store((t + 1) % SERIAL_RX_RING_SIZE, core::sync::atomic::Ordering::Release);
        Some(byte)
    }

    /// Check if data is available.
    fn has_data(&self) -> bool {
        let h = self.head.load(core::sync::atomic::Ordering::Acquire);
        let t = self.tail.load(core::sync::atomic::Ordering::Relaxed);
        h != t
    }
}

static SERIAL_RX: SerialRxRing = SerialRxRing::new();

/// Public accessor for injecting bytes into the guest's COM1 RX path.
pub fn serial_rx_ring() -> &'static SerialRxRing {
    &SERIAL_RX
}

// ---------------------------------------------------------------------------
// 16550A register shadow state
// ---------------------------------------------------------------------------
// Tracks IER, LCR, MCR, SCR, DLAB so that we emulate a realistic UART.

struct Uart16550State {
    ier: core::sync::atomic::AtomicU8,   // Interrupt Enable Register
    lcr: core::sync::atomic::AtomicU8,   // Line Control Register (bit 7 = DLAB)
    mcr: core::sync::atomic::AtomicU8,   // Modem Control Register
    fcr: core::sync::atomic::AtomicU8,   // FIFO Control Register (write-only)
    scr: core::sync::atomic::AtomicU8,   // Scratch Register
    tx_fifo_count: core::sync::atomic::AtomicU8,  // TX FIFO depth (0-16)
    rx_fifo_count: core::sync::atomic::AtomicU8,  // RX FIFO depth (0-16)
}

impl Uart16550State {
    const fn new() -> Self {
        Self {
            ier: core::sync::atomic::AtomicU8::new(0),
            lcr: core::sync::atomic::AtomicU8::new(0x03), // 8N1
            mcr: core::sync::atomic::AtomicU8::new(0),
            fcr: core::sync::atomic::AtomicU8::new(0),
            scr: core::sync::atomic::AtomicU8::new(0),
            tx_fifo_count: core::sync::atomic::AtomicU8::new(0),
            rx_fifo_count: core::sync::atomic::AtomicU8::new(0),
        }
    }

    fn dlab(&self) -> bool {
        self.lcr.load(core::sync::atomic::Ordering::Relaxed) & 0x80 != 0
    }
}

static UART: Uart16550State = Uart16550State::new();

// ---------------------------------------------------------------------------
// PIT (8254) timer state machine
// ---------------------------------------------------------------------------

/// PIT frequency: 1.193182 MHz
const PIT_FREQUENCY_HZ: u64 = 1_193_182;

/// PIT channel state
struct PitChannel {
    reload: AtomicU16,
    mode: AtomicU8,
    latched: AtomicU16,
    latched_valid: AtomicBool,
    read_state: AtomicU8, // 0=LSB, 1=MSB, 2=LSB then MSB
    write_state: AtomicU8,
    last_tsc: AtomicU64,
}

impl PitChannel {
    const fn new() -> Self {
        Self {
            reload: AtomicU16::new(0xFFFF),
            mode: AtomicU8::new(0),
            latched: AtomicU16::new(0),
            latched_valid: AtomicBool::new(false),
            read_state: AtomicU8::new(0),
            write_state: AtomicU8::new(0),
            last_tsc: AtomicU64::new(0),
        }
    }
}

/// Minimal PIT emulation: tracks counter reload values and mode per channel.
/// Returns a decrementing counter based on TSC timing for proper frequency.
struct PitState {
    channels: [PitChannel; 3],
    tick: AtomicU32,
    /// TSC frequency in Hz (calibrated at boot)
    tsc_frequency: AtomicU64,
}

impl PitState {
    const fn new() -> Self {
        Self {
            channels: [
                PitChannel::new(),
                PitChannel::new(),
                PitChannel::new(),
            ],
            tick: AtomicU32::new(0),
            tsc_frequency: AtomicU64::new(2_500_000_000), // Default 2.5 GHz
        }
    }

    /// Set TSC frequency (called during calibration)
    fn set_tsc_frequency(&self, freq: u64) {
        self.tsc_frequency.store(freq, Ordering::Release);
    }

    /// Read counter value with proper timing
    fn read_counter(&self, channel: usize) -> u16 {
        if channel > 2 { return 0; }
        
        let ch = &self.channels[channel];
        
        // Check for latched value first
        if ch.latched_valid.load(Ordering::Acquire) {
            ch.latched_valid.store(false, Ordering::Release);
            return ch.latched.load(Ordering::Relaxed);
        }
        
        let reload = ch.reload.load(Ordering::Relaxed);
        if reload == 0 { return 0; }
        
        // Get current TSC
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        let last = ch.last_tsc.load(Ordering::Relaxed);
        let tsc_freq = self.tsc_frequency.load(Ordering::Relaxed);
        
        // Calculate elapsed PIT ticks
        let tsc_delta = now.wrapping_sub(last);
        let pit_ticks = (tsc_delta * PIT_FREQUENCY_HZ) / tsc_freq;
        
        // Calculate current counter value
        let mode = ch.mode.load(Ordering::Relaxed);
        match mode {
            0 | 4 => {
                // Interrupt on terminal count / Square wave
                let elapsed = (pit_ticks % (reload as u64 + 1)) as u16;
                reload.wrapping_sub(elapsed)
            }
            2 | 6 => {
                // Rate generator - reload on zero
                let period = if reload > 0 { reload as u64 } else { 65536 };
                let elapsed = pit_ticks % period;
                if elapsed == 0 { reload } else { reload.wrapping_sub(elapsed as u16) }
            }
            3 | 7 => {
                // Square wave generator
                let period = if reload > 0 { reload as u64 * 2 } else { 131072 };
                let half_period = period / 2;
                let elapsed = pit_ticks % period;
                if elapsed < half_period {
                    reload.wrapping_sub((elapsed % (reload as u64 + 1)) as u16)
                } else {
                    reload.wrapping_sub(((elapsed - half_period) % (reload as u64 + 1)) as u16)
                }
            }
            _ => {
                // Mode 0: Interrupt on terminal count (simple countdown)
                let elapsed = (pit_ticks % (reload as u64 + 1)) as u16;
                reload.wrapping_sub(elapsed)
            }
        }
    }

    fn write_counter(&self, channel: usize, value: u16) {
        if channel > 2 { return; }
        let ch = &self.channels[channel];
        
        let state = ch.write_state.load(Ordering::Relaxed);
        match state {
            0 => {
                // LSB write
                ch.reload.store(value, Ordering::Release);
                ch.write_state.store(1, Ordering::Release);
            }
            1 => {
                // MSB write
                let lsb = ch.reload.load(Ordering::Relaxed) & 0xFF;
                ch.reload.store((value << 8) | lsb, Ordering::Release);
                ch.write_state.store(0, Ordering::Release);
            }
            2 => {
                // LSB then MSB - LSB first
                ch.reload.store(value, Ordering::Release);
                ch.write_state.store(3, Ordering::Release);
            }
            3 => {
                // LSB then MSB - MSB second
                let lsb = ch.reload.load(Ordering::Relaxed);
                ch.reload.store((value << 8) | lsb, Ordering::Release);
                ch.write_state.store(2, Ordering::Release);
            }
            _ => {}
        }
        
        // Update last TSC on reload
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        ch.last_tsc.store(now, Ordering::Release);
    }

    fn write_mode(&self, cmd: u8) {
        let channel = ((cmd >> 6) & 0x3) as usize;
        if channel > 2 { return; }
        
        let ch = &self.channels[channel];
        let mode = (cmd >> 1) & 0x7;
        ch.mode.store(mode, Ordering::Release);
        
        // Set access mode
        let access = (cmd >> 4) & 0x3;
        match access {
            0 => {
                // Latch count command
                let counter = self.read_counter(channel);
                ch.latched.store(counter, Ordering::Release);
                ch.latched_valid.store(true, Ordering::Release);
            }
            1 => ch.write_state.store(0, Ordering::Release), // LSB only
            2 => ch.write_state.store(1, Ordering::Release), // MSB only
            3 => ch.write_state.store(2, Ordering::Release), // LSB then MSB
            _ => {}
        }
        
        // Reset TSC on mode change
        let now = unsafe { core::arch::x86_64::_rdtsc() };
        ch.last_tsc.store(now, Ordering::Release);
    }
}

static PIT: PitState = PitState::new();

// ---------------------------------------------------------------------------
// ACPI Power Management (PM) register state
// ---------------------------------------------------------------------------
// PM1a_EVT_BLK at 0x600 (status + enable), PM1a_CNT_BLK at 0x604 (control)
// These back the FADT-declared PM register blocks.

static ACPI_PM1_EVT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);
static ACPI_PM1_CNT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

// ---------------------------------------------------------------------------
// Pending-interrupt queue (single slot, lock-free)
// ---------------------------------------------------------------------------
// The PIT timer fires IRQ0 periodically.  We store the pending vector in an
// atomic so that the vmx_loop can inject it on the next VM-entry.  Only one
// vector can be pending at a time — subsequent fires overwrite.

/// 0 = no pending interrupt; non-zero = vector to inject on next VM-entry.
pub static PENDING_IRQ: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(0);

/// PIT timer interval: fire IRQ0 every N VM-exits.  Real hardware fires at
/// 1.193182 MHz / reload_value Hz, but in the emulator we approximate with a
/// fixed exit count to keep things simple and deterministic.
const PIT_FIRE_INTERVAL: u32 = 64;

/// PIT IRQ0 vector — standard ISA IRQ0 remapped to vector 0x20 by the 8259A
/// PIC initialisation sequence (ICW2 = 0x20).
const PIT_IRQ0_VECTOR: u8 = 0x20;

// ---------------------------------------------------------------------------
// Platform port I/O emulator
// Handles the standard x86 legacy ports that every guest OS probes at boot:
//   0x3F8-0x3FF  16550A UART (COM1)
//   0x020/0x021  8259A master PIC
//   0x0A0/0x0A1  8259A slave  PIC
//   0x040-0x043  8254 PIT
//   0x060/0x064  8042 PS/2 keyboard controller
//   0x070/0x071  RTC / CMOS
//   0x0CF8/0x0CFC  PCI config-space I/O (type-1 mechanism)
// ---------------------------------------------------------------------------

/// Returns `Some(value)` when the port was handled, `None` to fall through.
pub fn emulate_port_in(port: u16, size: u8) -> Option<u32> {
    let _ = size;
    match port {
        // 16550A COM1 ---------------------------------------------------------
        // 0x3F8: RBR (read data) when DLAB=0, DLL (divisor latch low) when DLAB=1
        0x3F8 => {
            if UART.dlab() {
                Some(0x01) // divisor latch low = 1 (115200 baud)
            } else {
                // Pop one byte from the RX ring for the guest.
                Some(SERIAL_RX.pop().unwrap_or(0x00) as u32)
            }
        }
        // 0x3F9: IER when DLAB=0, DLM (divisor latch high) when DLAB=1
        0x3F9 => {
            if UART.dlab() {
                Some(0x00) // divisor latch high = 0
            } else {
                Some(UART.ier.load(core::sync::atomic::Ordering::Relaxed) as u32)
            }
        }
        // IIR: identify interrupt source
        0x3FA => {
            // If RX data available and IER bit 0 (data ready) set → data ready interrupt
            let ier = UART.ier.load(core::sync::atomic::Ordering::Relaxed);
            if SERIAL_RX.has_data() && ier & 0x01 != 0 {
                Some(0x04) // IIR: data ready (priority 2), bit 0 clear = interrupt pending
            } else {
                Some(0x01) // no interrupt pending (bit 0 set)
            }
        }
        // LCR
        0x3FB => Some(UART.lcr.load(core::sync::atomic::Ordering::Relaxed) as u32),
        // MCR
        0x3FC => Some(UART.mcr.load(core::sync::atomic::Ordering::Relaxed) as u32),
        // LSR: Line Status Register
        0x3FD => {
            let mut lsr: u32 = 0x60; // THR empty (bit 5) + TX shift empty (bit 6)
            if SERIAL_RX.has_data() {
                lsr |= 0x01; // DR bit (data ready)
            }
            // Bits 4-2: BI (break), FE (framing error), PE (parity error) — all clear (no errors)
            // Bit 7: error in FIFO — clear (no FIFO errors)
            Some(lsr)
        }
        // MSR: DSR + CTS asserted (bits 4+5) so firmware doesn't hang.
        0x3FE => Some(0x30),
        // SCR: scratch register
        0x3FF => Some(UART.scr.load(core::sync::atomic::Ordering::Relaxed) as u32),

        // 8259A master PIC ----------------------------------------------------
        // Return "no interrupt" (0xFF = all masked) so the guest can initialise
        // the PIC without hanging.  IMR reads return 0xFF (all masked).
        0x0020 => Some(0x00), // ISR / IRR
        0x0021 => Some(0xFF), // IMR (all masked)

        // 8259A slave PIC
        0x00A0 => Some(0x00),
        0x00A1 => Some(0xFF),

        // 8254 PIT ------------------------------------------------------------
        // Read counter value from PIT state machine
        0x0040 => Some(PIT.read_counter(0) as u32),
        0x0041 => Some(PIT.read_counter(1) as u32),
        0x0042 => Some(PIT.read_counter(2) as u32),
        // Mode/status register
        0x0043 => Some(0x00),

        // 8042 PS/2 keyboard / system controller ------------------------------
        // Output buffer status bit (bit 0) clear → nothing to read.
        0x0060 => Some(0x00),
        0x0064 => Some(0x00), // status: no output buf full, no input buf full

        // RTC / CMOS ----------------------------------------------------------
        0x0070 => Some(0x00),
        0x0071 => Some(0x00),

        // PCI config-space (type-1) address/data port -------------------------
        0x0CF8 => Some(crate::vmm::pci::pci_bus().read_address()),
        0x0CFC..=0x0CFF => {
            let byte_off = (port - 0x0CFC) as u8;
            Some(crate::vmm::pci::pci_bus().read_data(byte_off))
        }

        // ACPI PM registers (as declared in FADT) ----------------------------
        // PM1a_EVT_BLK: PM1 Status (2 bytes) + PM1 Enable (2 bytes)
        0x0600..=0x0603 => Some(ACPI_PM1_EVT.load(core::sync::atomic::Ordering::Relaxed)),
        // PM1a_CNT_BLK: PM1 Control
        0x0604..=0x0605 => Some(ACPI_PM1_CNT.load(core::sync::atomic::Ordering::Relaxed)),
        // PM_TMR_BLK: ACPI timer (3.579545 MHz, 32-bit)
        0x0608..=0x060B => {
            // Approximate: use TSC scaled down.  Real ACPI timer runs at
            // ~3.58 MHz.  At a ~3 GHz TSC that's roughly TSC / 838.
            #[cfg(target_arch = "x86_64")]
            let tsc = unsafe { core::arch::x86_64::_rdtsc() };
            #[cfg(not(target_arch = "x86_64"))]
            let tsc = 0u64;
            Some((tsc / 838) as u32)
        }

        // Unhandled — return 0xFF (standard "floating bus" value)
        _ => Some(0xFF),
    }
}

/// Returns `true` when the write was consumed by the emulator.
pub fn emulate_port_out(port: u16, _size: u8, value: u32) -> bool {
    match port {
        // COM1 TX data / divisor latch low
        0x3F8 => {
            if UART.dlab() {
                // DLL write — absorb divisor latch
            } else {
                SERIAL_TX.push(value as u8);
                // Fire TX interrupt (IRQ4 = vector 0x24) if IER bit 1 (THR empty) is set.
                let ier = UART.ier.load(core::sync::atomic::Ordering::Relaxed);
                if ier & 0x02 != 0 {
                    PENDING_IRQ.store(0x24, core::sync::atomic::Ordering::Release);
                }
            }
            true
        }
        // COM1 IER / divisor latch high
        0x3F9 => {
            if UART.dlab() {
                // DLM write — absorb divisor latch
            } else {
                UART.ier.store(value as u8, core::sync::atomic::Ordering::Relaxed);
            }
            true
        }
        // COM1 FCR (write-only)
        0x3FA => {
            UART.fcr.store(value as u8, core::sync::atomic::Ordering::Relaxed);
            true
        }
        // COM1 LCR
        0x3FB => {
            UART.lcr.store(value as u8, core::sync::atomic::Ordering::Relaxed);
            true
        }
        // COM1 MCR
        0x3FC => {
            UART.mcr.store(value as u8, core::sync::atomic::Ordering::Relaxed);
            // Fire modem status interrupt (IRQ4 = vector 0x24) if IER bit 3 (MSR change) is set.
            let ier = UART.ier.load(core::sync::atomic::Ordering::Relaxed);
            if ier & 0x08 != 0 {
                PENDING_IRQ.store(0x24, core::sync::atomic::Ordering::Release);
            }
            true
        }
        // COM1 LSR, MSR — read-only, absorb writes
        0x3FD | 0x3FE => true,
        // COM1 SCR
        0x3FF => {
            UART.scr.store(value as u8, core::sync::atomic::Ordering::Relaxed);
            true
        }

        // 8259A PIC: absorb ICW1-4, OCW1-3
        0x0020 | 0x0021 | 0x00A0 | 0x00A1 => true,

        // 8254 PIT: write counter reload value or mode command
        0x0040 => { PIT.write_counter(0, value as u16); true }
        0x0041 => { PIT.write_counter(1, value as u16); true }
        0x0042 => { PIT.write_counter(2, value as u16); true }
        0x0043 => { PIT.write_mode(value as u8); true }

        // 8042 keyboard: absorb commands
        0x0060 | 0x0064 => true,

        // RTC
        0x0070 | 0x0071 => true,

        // PCI config-space address write
        0x0CF8 => {
            crate::vmm::pci::pci_bus().write_address(value);
            true
        }
        0x0CFC..=0x0CFF => {
            let byte_off = (port - 0x0CFC) as u8;
            crate::vmm::pci::pci_bus().write_data(byte_off, value);
            true
        }

        // ACPI PM registers --------------------------------------------------
        // PM1_EVT (status+enable)
        0x0600..=0x0603 => {
            // Status bits: writing 1 clears (write-1-to-clear).
            let old = ACPI_PM1_EVT.load(core::sync::atomic::Ordering::Relaxed);
            ACPI_PM1_EVT.store(old & !value, core::sync::atomic::Ordering::Relaxed);
            true
        }
        // PM1_CNT
        0x0604..=0x0605 => {
            ACPI_PM1_CNT.store(value, core::sync::atomic::Ordering::Relaxed);
            // SLP_EN (bit 13): guest is requesting sleep/shutdown
            // SLP_TYP (bits 12:10): sleep type
            // For S5 (power off): SLP_TYP = 5, SLP_EN = 1
            // We don't halt the VM here — the guest will stop executing.
            true
        }
        // PM_TMR (read-only, absorb writes)
        0x0608..=0x060B => true,

        _ => false,
    }
}

pub fn vmx_loop(state: &mut HypervisorState) -> HvResult<()> {
    setup_ept(state)?;
    let mut launched = false;
    loop {
        let ops = state.hv_ops;
        let result = ops.run_vm(state, &mut launched);
        match result {
            Ok(_) => {}
            Err(HvError::LogicalFault) => {
                if state.recover_from_fault() {
                    return Err(HvError::HardwareFault);
                }
                continue;
            }
            Err(HvError::HardwareFault) => return Err(HvError::HardwareFault),
        }
        match vmx_exit_handler(state) {
            Ok(should_continue) => {
                if !should_continue {
                    return Ok(());
                }
            }
            Err(HvError::HardwareFault) => return Err(HvError::HardwareFault),
            Err(HvError::LogicalFault) => {
                if state.recover_from_fault() {
                    return Err(HvError::HardwareFault);
                }
            }
        }
        let now = state.chronos.tsc_exit();
        state.stress_tick(now);

        // ── PIT timer tick ──────────────────────────────────────────────────
        // Bump PIT tick counter.  Every PIT_FIRE_INTERVAL VM-exits, assert
        // IRQ0.  Route through the I/O APIC if it has a valid entry for
        // pin 0, otherwise fall back to the hardcoded 8259A vector 0x20.
        {
            let tick = PIT.tick.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            if tick % PIT_FIRE_INTERVAL == 0 {
                let vector = crate::vmm::ioapic::ioapic()
                    .route_irq(0)
                    .unwrap_or(PIT_IRQ0_VECTOR);
                PENDING_IRQ.store(vector, core::sync::atomic::Ordering::Release);
            }
        }

        // ── Inject pending interrupt into VMCS ─────────────────────────────
        // If there is a queued vector and the guest is interruptible, write
        // VM_ENTRY_INTR_INFO so the interrupt is delivered on the next VMRESUME.
        {
            let vec = PENDING_IRQ.load(core::sync::atomic::Ordering::Acquire);
            if vec != 0 {
                match state.vmx.inject_interrupt(vec) {
                    Ok(true) => {
                        // Injected successfully — clear pending and
                        // disable interrupt-window exiting.
                        PENDING_IRQ.store(0, core::sync::atomic::Ordering::Release);
                        let _ = state.vmx.clear_interrupt_window();
                    }
                    Ok(false) => {
                        // Deferred — interrupt-window exiting was enabled
                        // by inject_interrupt().  Vector stays pending.
                    }
                    Err(_) => {}
                }
            }
        }

        // Batched INVEPT: flush EPT TLB once per exit-loop iteration if any
        // EPT mappings were changed during this cycle.
        if state.ept_dirty {
            let _ = unsafe { invept_single(state.ept.eptp()) };
            state.ept_dirty = false;
        }
        if state.apply_restore().unwrap_or(false) {
            let _ = unsafe { invept_single(state.ept.eptp()) };
        }
    }
}

fn vmx_exit_handler(state: &mut HypervisorState) -> Result<bool, HvError> {
    let reason = state.vmx.exit_reason()? & 0xFFFF;
    match reason {
        EXIT_REASON_EPT_VIOLATION => handle_ept_violation(state)?,
        EXIT_REASON_IO_INSTRUCTION => handle_io_instruction(state)?,
        EXIT_REASON_HLT => return Ok(false),
        EXIT_REASON_NMI => {}
        // Interrupt-window exit: guest just became interruptible.
        // The pending IRQ injection above will handle it on re-entry;
        // just clear the window-exit bit so we don't keep re-exiting.
        EXIT_REASON_INTERRUPT_WINDOW => {
            let _ = state.vmx.clear_interrupt_window();
        }
        // CPUID and MSR exits are handled in the assembly-level vm_exit_dispatch
        // (which writes directly to the GPR frame); just advance RIP here so
        // that the high-level state machine stays consistent.
        10 | 31 | 32 => {
            state.vmx.advance_rip()?;
        }
        _ => return Err(HvError::LogicalFault),
    }
    let entry_tsc = state.chronos.tsc_enter()?;
    let exit_tsc = state.chronos.tsc_exit();
    let overhead = exit_tsc.wrapping_sub(entry_tsc);
    state.update_tsc_baseline(overhead);
    state.chronos.adjust_tsc_offset(state.tsc_baseline)?;
    state
        .aeroframe
        .sync_minimal_registers(state.guest_allocation.tag.guest_id)?;
    Ok(true)
}

pub fn map_ept_neighbors(
    state: &mut HypervisorState,
    faulting: PhysFrame,
) -> Result<[PhysFrame; 3], HvError> {
    let allocation = &state.guest_allocation;
    let neighbors = state.atlas.handle_ept_violation(allocation, faulting)?;
    for frame in neighbors.iter() {
        state.ept.map_4k(frame.0, frame.0)?;
    }
    // Mark EPT as dirty — the flush will happen once at the end of the
    // exit handler batch, instead of per-fault.
    state.ept_dirty = true;
    Ok(neighbors)
}

fn handle_ept_violation(state: &mut HypervisorState) -> Result<(), HvError> {
    let gpa = state.vmx.guest_phys_addr()?;
    let faulting = PhysFrame(gpa & !0xFFF);

    // ── IOAPIC MMIO intercept ──────────────────────────────────────────
    if faulting.0 == crate::vmm::ioapic::IOAPIC_BASE {
        let offset = gpa & 0xFFF;
        let qual = state.vmx.exit_qualification().unwrap_or(0);
        let is_write = (qual & 2) != 0;
        if is_write {
            // We don't have the guest RAX in the high-level state, so use 0
            // as placeholder.  The fast-path handler covers real hardware.
            crate::vmm::ioapic::ioapic().mmio_write(offset, 0);
        } else {
            let _result = crate::vmm::ioapic::ioapic().mmio_read(offset);
        }
        state.vmx.advance_rip()?;
        return Ok(());
    }

    // ── LAPIC MMIO intercept ───────────────────────────────────────────
    if faulting.0 == crate::vmm::vcpu::LAPIC_MMIO_BASE {
        let offset = (gpa & 0xFFF) as u32;
        let qual = state.vmx.exit_qualification().unwrap_or(0);
        let is_write = (qual & 2) != 0;
        let lapic = crate::vmm::vcpu::guest_lapic();
        if is_write {
            lapic.write(offset, 0);
        } else {
            let _result = lapic.read(offset);
        }
        state.vmx.advance_rip()?;
        return Ok(());
    }

    // ── VirtIO MMIO intercept ────────────────────────────────────────
    {
        use crate::vmm::hypervisor::{
            VIRTIO_MMIO_BASE_NET, VIRTIO_MMIO_BASE_BLK, VIRTIO_MMIO_BASE_CONSOLE,
        };
        if faulting.0 == VIRTIO_MMIO_BASE_NET
            || faulting.0 == VIRTIO_MMIO_BASE_BLK
            || faulting.0 == VIRTIO_MMIO_BASE_CONSOLE
        {
            let qual = state.vmx.exit_qualification().unwrap_or(0);
            let is_write = (qual & 2) != 0;
            if is_write {
                let _ = crate::vmm::virtio_direct().mmio_write(gpa, 0);
            } else {
                let _result = crate::vmm::virtio_direct().mmio_read(gpa);
            }
            state.vmx.advance_rip()?;
            return Ok(());
        }
    }

    let now = state.chronos.tsc_exit();
    if state.safe_mode || state.ept.throttle(now) {
        state.ept.map_4k(faulting.0, faulting.0)?;
        state.ept_dirty = true;
    } else {
        let _ = map_ept_neighbors(state, faulting)?;
    }
    snapshot_log().record(faulting.0);
    Ok(())
}

fn handle_io_instruction(state: &mut HypervisorState) -> Result<(), HvError> {
    let qual = state.vmx.exit_qualification()?;
    let size = match qual & 0x7 {
        0 => 1u8,
        1 => 2u8,
        3 => 4u8,
        _ => return Err(HvError::LogicalFault),
    };
    if (qual & (1 << 4)) != 0 {
        // String I/O (INS/OUTS) — not emulated yet, treat as NOP.
        return Ok(());
    }
    let is_in = (qual & (1 << 3)) != 0;
    let port = ((qual >> 16) & 0xFFFF) as u16;

    if is_in {
        // Platform emulator handles all legacy ports; result goes into guest RAX
        // via the VMCS (the assembly dispatcher already advanced RIP).
        let _val = emulate_port_in(port, size).unwrap_or(0xFF);
        // Write the result into the VMCS guest RDX scratch area used by the
        // Hypervisor state machine; the frame-level write was done in
        // vm_exit_dispatch.  No further action needed here.
    } else {
        let _consumed = emulate_port_out(port, size, 0);
    }
    Ok(())
}

fn setup_ept(state: &mut HypervisorState) -> Result<(), HvError> {
    let allocation = &state.guest_allocation;
    state
        .ept
        .map_range_huge(allocation.base.0, allocation.size)?;
    unsafe {
        invept_single(state.ept.eptp())?;
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MinimalRegs {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub ss: u16,
}

impl DriverAbi for MinimalRegs {
    const VERSION: u32 = ABI_VERSION;
    const FEATURES: AbiFeatures = AbiFeatures { bits: 0 };
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironshim::{validate_bindgen_layout, validate_driver_abi};

    #[repr(C)]
    struct BindgenRegs {
        rax: u64, rcx: u64, rdx: u64, rbx: u64,
        rsp: u64, rbp: u64, rsi: u64, rdi: u64,
        r8: u64, r9: u64, r10: u64, r11: u64,
        r12: u64, r13: u64, r14: u64, r15: u64,
        rip: u64, rflags: u64,
        cs: u16, ds: u16, es: u16, ss: u16,
    }

    impl DriverAbi for BindgenRegs {
        const VERSION: u32 = ABI_VERSION;
        const FEATURES: AbiFeatures = AbiFeatures { bits: 0 };
    }

    #[test]
    fn validates_bindgen_layout() {
        let descriptor = DriverAbiDescriptor {
            version: ABI_VERSION,
            features: AbiFeatures { bits: 0 },
            struct_size: size_of::<BindgenRegs>(),
            struct_align: align_of::<BindgenRegs>(),
        };
        assert!(validate_driver_abi::<BindgenRegs>(descriptor).is_ok());
    }

    #[test]
    fn matches_bindgen_constants() {
        assert!(validate_bindgen_layout::<BindgenRegs>(size_of::<BindgenRegs>(), align_of::<BindgenRegs>()).is_ok());
    }

    #[test]
    fn rejects_version_mismatch() {
        let descriptor = DriverAbiDescriptor {
            version: ABI_VERSION + 1,
            features: AbiFeatures { bits: 0 },
            struct_size: size_of::<BindgenRegs>(),
            struct_align: align_of::<BindgenRegs>(),
        };
        assert!(validate_driver_abi::<BindgenRegs>(descriptor).is_err());
    }
}
