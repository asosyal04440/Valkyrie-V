use core::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};
use core::cell::UnsafeCell;

pub const MAX_VCPUS: usize = 64;

pub const VCPU_STATE_INACTIVE: u8 = 0;
pub const VCPU_STATE_INIT: u8 = 1;
pub const VCPU_STATE_RUNNING: u8 = 2;
pub const VCPU_STATE_HALTED: u8 = 3;
pub const VCPU_STATE_WAIT_FOR_SIPI: u8 = 4;
/// AP received SIPI — ready to start executing at the vector address.
pub const VCPU_STATE_SIPI_RECEIVED: u8 = 5;

pub const LAPIC_ID: u32 = 0x0020;
pub const LAPIC_VERSION: u32 = 0x0010;
pub const LAPIC_TPR: u32 = 0x0080;
pub const LAPIC_PPR: u32 = 0x00A0;
pub const LAPIC_EOI: u32 = 0x00B0;
pub const LAPIC_LDR: u32 = 0x00D0;
pub const LAPIC_DFR: u32 = 0x00E0;
pub const LAPIC_SVR: u32 = 0x00F0;
pub const LAPIC_ISR0: u32 = 0x0100;
pub const LAPIC_ISR7: u32 = 0x0170;
pub const LAPIC_TMR0: u32 = 0x0180;
pub const LAPIC_TMR7: u32 = 0x01F0;
pub const LAPIC_IRR0: u32 = 0x0200;
pub const LAPIC_IRR7: u32 = 0x0270;
pub const LAPIC_ERROR_STATUS: u32 = 0x0280;
pub const LAPIC_ICR_LOW: u32 = 0x0300;
pub const LAPIC_ICR_HIGH: u32 = 0x0310;
pub const LAPIC_TIMER_VECTOR: u32 = 0x0320;
pub const LAPIC_THERMAL: u32 = 0x0330;
pub const LAPIC_PERF: u32 = 0x0340;
pub const LAPIC_LINT0: u32 = 0x0350;
pub const LAPIC_LINT1: u32 = 0x0360;
pub const LAPIC_ERROR: u32 = 0x0370;
pub const LAPIC_TICR: u32 = 0x0380;
pub const LAPIC_TCCR: u32 = 0x0390;
pub const LAPIC_TDCR: u32 = 0x03E0;

pub const LAPIC_ENABLE: u32 = 0x100;
pub const LAPIC_FOCUS_DISABLED: u32 = 0x200;
pub const LAPIC_SOFTWARE_ENABLE: u32 = 0x1000;

pub const ICR_DEST_PHYSICAL: u32 = 0x00000000;
pub const ICR_DEST_LOGICAL: u32 = 0x00080000;
pub const ICR_DELIVERY_FIXED: u32 = 0x00000000;
pub const ICR_DELIVERY_LOWPRI: u32 = 0x00010000;
pub const ICR_DELIVERY_SMI: u32 = 0x00020000;
pub const ICR_DELIVERY_NMI: u32 = 0x00040000;
pub const ICR_DELIVERY_INIT: u32 = 0x00050000;
pub const ICR_DELIVERY_STARTUP: u32 = 0x00060000;
pub const ICR_DELIVERY_EXTINT: u32 = 0x00070000;
pub const ICR_LEVEL_ASSERT: u32 = 0x00004000;
pub const ICR_LEVEL_DEASSERT: u32 = 0x00000000;
pub const ICR_TRIGGER_EDGE: u32 = 0x00000000;
pub const ICR_TRIGGER_LEVEL: u32 = 0x00008000;
pub const ICR_DEST_SELF: u32 = 0x00040000;
pub const ICR_DEST_ALL: u32 = 0x00080000;
pub const ICR_DEST_OTHERS: u32 = 0x000C0000;
pub const ICR_STATUS_PENDING: u32 = 0x00001000;
pub const ICR_STATUS_BUSY: u32 = 0x00002000;

pub const IRR_SIZE: usize = 8;
pub const ISR_SIZE: usize = 8;
pub const TMR_SIZE: usize = 8;

pub const LAPIC_MMIO_BASE: u64 = 0xFEE0_0000;

/// Number of 16-byte-aligned register slots in the LAPIC.
/// LAPIC registers are spaced 16 bytes apart (offsets 0x000-0x3F0),
/// giving exactly 64 slots with `offset >> 4` indexing.
const LAPIC_REG_SLOTS: usize = 64;

pub struct LocalApic {
    id: u32,
    regs: [u32; LAPIC_REG_SLOTS],
    /// TSC at which the timer was last armed (TICR write).
    timer_start_tsc: u64,
    /// TSC deadline — the timer fires when rdtsc >= this value.
    timer_deadline_tsc: u64,
    /// Whether the timer is currently counting down.
    timer_armed: bool,
}

impl LocalApic {
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            regs: [0u32; LAPIC_REG_SLOTS],
            timer_start_tsc: 0,
            timer_deadline_tsc: 0,
            timer_armed: false,
        }
    }

    /// Compute the LAPIC timer divider from the Divide Configuration
    /// Register (TDCR, offset 0x3E0).
    ///
    /// Bits [3,1,0] encode the divisor:
    ///   000 → /2, 001 → /4, 010 → /8, 011 → /16,
    ///   100 → /32, 101 → /64, 110 → /128, 111 → /1
    fn timer_divider(&self) -> u64 {
        let dcr = self.regs[(LAPIC_TDCR >> 4) as usize] & 0xB;
        let code = ((dcr >> 1) & 0x4) | (dcr & 0x3); // combine bit3→bit2, bits1:0
        match code {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            0b111 => 1,
            _ => 2,
        }
    }

    /// Arm the LAPIC timer.  Called when the guest writes TICR.
    ///
    /// `current_tsc` is the current TSC value at the time of the write.
    /// The timer deadline = current_tsc + initial_count * divider.
    fn arm_timer(&mut self, initial_count: u32, current_tsc: u64) {
        if initial_count == 0 {
            self.timer_armed = false;
            return;
        }
        let divider = self.timer_divider();
        let total_ticks = (initial_count as u64).wrapping_mul(divider);
        self.timer_start_tsc = current_tsc;
        self.timer_deadline_tsc = current_tsc.wrapping_add(total_ticks);
        self.timer_armed = true;
    }

    /// Check whether the LAPIC timer has fired.
    ///
    /// Returns `Some(vector)` if the timer has expired and should inject an
    /// interrupt.  For periodic timers the deadline is automatically reloaded.
    /// For one-shot timers, the timer is disarmed.
    ///
    /// `current_tsc` is the current TSC value.
    pub fn check_timer(&mut self, current_tsc: u64) -> Option<u8> {
        if !self.timer_armed {
            return None;
        }
        if current_tsc < self.timer_deadline_tsc {
            return None;
        }

        // Timer fired!
        let lvt = self.regs[(LAPIC_TIMER_VECTOR >> 4) as usize];
        let vector = (lvt & 0xFF) as u8;
        let masked = (lvt & (1 << 16)) != 0;
        let mode = (lvt >> 17) & 0x3; // 0=one-shot, 1=periodic, 2=tsc-deadline

        if masked {
            self.timer_armed = false;
            return None;
        }

        match mode {
            1 => {
                // Periodic: reload from TICR
                let initial = self.regs[(LAPIC_TICR >> 4) as usize];
                if initial == 0 {
                    self.timer_armed = false;
                } else {
                    let divider = self.timer_divider();
                    let period = (initial as u64).wrapping_mul(divider);
                    self.timer_start_tsc = self.timer_deadline_tsc;
                    self.timer_deadline_tsc = self.timer_deadline_tsc.wrapping_add(period);
                }
            }
            _ => {
                // One-shot / TSC-deadline: disarm
                self.timer_armed = false;
            }
        }

        Some(vector)
    }

    pub fn read(&self, offset: u32) -> u32 {
        let idx = (offset >> 4) as usize;
        if idx >= LAPIC_REG_SLOTS {
            return 0;
        }
        match offset {
            LAPIC_ID => self.id << 24,
            LAPIC_VERSION => 0x14 | ((8 * 16) << 16),
            LAPIC_EOI => 0,
            LAPIC_LDR => ((self.id & 0xF) << 24) | (1 << ((self.id >> 1) & 0x7)),
            LAPIC_DFR => 0xFFFFFFFF,
            LAPIC_SVR => LAPIC_ENABLE | LAPIC_SOFTWARE_ENABLE,
            LAPIC_ERROR_STATUS => 0,
            LAPIC_ICR_LOW => self.regs[idx] & !ICR_STATUS_PENDING,
            LAPIC_ICR_HIGH => self.regs[idx],
            LAPIC_TCCR => {
                // Current Count = remaining ticks / divider
                if !self.timer_armed {
                    0
                } else {
                    #[cfg(target_arch = "x86_64")]
                    let now = unsafe { core::arch::x86_64::_rdtsc() };
                    #[cfg(not(target_arch = "x86_64"))]
                    let now = 0u64;
                    if now >= self.timer_deadline_tsc {
                        0
                    } else {
                        let remaining = self.timer_deadline_tsc - now;
                        let divider = self.timer_divider();
                        (remaining / divider) as u32
                    }
                }
            }
            _ => self.regs[idx],
        }
    }

    pub fn write(&mut self, offset: u32, value: u32) {
        let idx = (offset >> 4) as usize;
        if idx >= LAPIC_REG_SLOTS {
            return;
        }
        match offset {
            LAPIC_TPR => {
                self.regs[idx] = value & 0xFF;
            }
            LAPIC_SVR => {
                self.regs[idx] = value & 0x3FF;
            }
            LAPIC_EOI => {
                self.regs[idx] = 0;
            }
            LAPIC_ICR_LOW => {
                self.regs[idx] = value;
            }
            LAPIC_ICR_HIGH => {
                self.regs[idx] = value & 0xFF000000;
            }
            LAPIC_TIMER_VECTOR => {
                // LVT Timer: bits [7:0] = vector, [16] = mask,
                //            [18:17] = mode (00=one-shot,01=periodic,10=tsc-deadline)
                self.regs[idx] = value & 0x000710FF;
            }
            LAPIC_TICR => {
                self.regs[idx] = value;
                // Arm (or disarm if value==0) the LAPIC timer.
                #[cfg(target_arch = "x86_64")]
                let now = unsafe { core::arch::x86_64::_rdtsc() };
                #[cfg(not(target_arch = "x86_64"))]
                let now = 0u64;
                self.arm_timer(value, now);
            }
            LAPIC_TDCR => {
                self.regs[idx] = value & 0xB;
            }
            LAPIC_LINT0 => {
                self.regs[idx] = value & 0x10FF;
            }
            LAPIC_LINT1 => {
                self.regs[idx] = value & 0x10FF;
            }
            _ => {
                self.regs[idx] = value;
            }
        }
    }

    pub fn set_id(&mut self, id: u32) {
        self.id = id;
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }
}

pub struct Vcpu {
    pub id: u32,
    pub apic_id: u32,
    pub state: AtomicU8,
    pub running: AtomicU8,
    pub vmcs: u64,
    pub cr3: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
    pub lapic: LocalApic,
    pub tsc_offset: AtomicU64,
    pub cpu_state: u64,
    /// VMCS slot index assigned by Vmx — used to index into the
    /// per-vCPU VMCS_REGIONS / HOST_EXIT_STACKS arrays.
    pub vmcs_slot: u32,
    /// SIPI vector — set when an AP receives a STARTUP IPI.
    /// The AP's entry RIP = sipi_vector << 12.
    pub sipi_vector: u8,
    /// VPID (Virtual Processor ID) for TLB tagging.
    /// 0 = not allocated, 1-4095 = valid VPID.
    pub vpid: AtomicU16,
    /// Scheduler priority (0-255, lower = higher priority).
    pub sched_priority: u8,
    /// Virtual runtime for CFS scheduler.
    pub vruntime: AtomicU64,
    /// Current pCPU this vCPU is running on (0xFFFF = not running).
    pub current_pcpu: AtomicU16,
    /// Affinity type: 0=none, 1=soft, 2=hard.
    pub affinity_type: AtomicU8,
    /// Preferred pCPU for affinity.
    pub affinity_pcpu: AtomicU16,
    /// Timeslice remaining in TSC cycles.
    pub timeslice_remaining: AtomicU64,
}

/// FPU state save area supporting both FXSAVE (512 bytes) and XSAVE (up to 4KB).
///
/// XSAVE supports AVX, AVX-512, and other extended processor states.
/// The XSAVE area layout:
/// - Bytes 0-511: Legacy x87 FPU + SSE state (same as FXSAVE)
/// - Bytes 512-543: XSAVE header
/// - Bytes 544+: Extended state components (AVX, AVX-512, etc.)
#[repr(C, align(64))]
pub struct FpuState {
    /// FXSAVE area (512 bytes) - always present
    pub fxsave: [u8; 512],
    /// XSAVE header (64 bytes)
    pub xsave_header: [u8; 64],
    /// Extended state area (up to 3520 bytes for AVX-512)
    pub extended: [u8; 3520],
    /// Whether this area has been initialized
    pub initialized: bool,
    /// Whether XSAVE is supported and enabled
    pub xsave_enabled: bool,
    /// XSAVE feature mask (XCR0)
    pub xcr0_mask: u64,
}

impl FpuState {
    pub const fn new() -> Self {
        Self {
            fxsave: [0u8; 512],
            xsave_header: [0u8; 64],
            extended: [0u8; 3520],
            initialized: false,
            xsave_enabled: false,
            xcr0_mask: 0,
        }
    }

    /// Check if XSAVE is supported by the CPU
    pub fn check_xsave_support() -> (bool, u64) {
        #[cfg(target_arch = "x86_64")]
        {
            // Check CPUID leaf 0x1, ECX bit 26 (XSAVE)
            let result = unsafe { core::arch::x86_64::__cpuid(1) };
            let xsave_supported = (result.ecx >> 26) & 1 == 1;
            
            if xsave_supported {
                // Read XCR0 to get supported features
                let xcr0: u64;
                unsafe {
                    core::arch::asm!(
                        "xgetbv",
                        in("ecx") 0u32,
                        out("eax") xcr0,
                        out("edx") _,
                        options(nomem, nostack, preserves_flags)
                    );
                }
                (true, xcr0)
            } else {
                (false, 0)
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            (false, 0)
        }
    }

    /// Initialize FPU state with XSAVE detection
    pub fn init(&mut self) {
        let (supported, mask) = Self::check_xsave_support();
        self.xsave_enabled = supported;
        self.xcr0_mask = mask;
        self.initialized = true;
    }

    /// Save the current FPU state into this buffer.
    ///
    /// # Safety
    /// Only valid on x86_64 with FXSAVE/XSAVE support.
    #[cfg(not(test))]
    pub unsafe fn save(&mut self) {
        if self.xsave_enabled {
            // Use XSAVEOPT for better performance (skips unchanged state)
            core::arch::asm!(
                "xsaveopt64 [{}]",
                in(reg) self.fxsave.as_mut_ptr(),
                in("edx") (self.xcr0_mask >> 32) as u32,
                in("eax") self.xcr0_mask as u32,
                options(nostack, preserves_flags)
            );
        } else {
            // Fallback to FXSAVE for older CPUs
            core::arch::asm!(
                "fxsave64 [{}]",
                in(reg) self.fxsave.as_mut_ptr(),
                options(nostack, preserves_flags)
            );
        }
        self.initialized = true;
    }

    /// Restore FPU state from this buffer.
    ///
    /// # Safety
    /// Only valid on x86_64 with FXRSTOR/XRSTOR support.
    #[cfg(not(test))]
    pub unsafe fn restore(&self) {
        if !self.initialized {
            return;
        }
        
        if self.xsave_enabled {
            // Use XRSTOR to restore full state
            core::arch::asm!(
                "xrstor64 [{}]",
                in(reg) self.fxsave.as_ptr(),
                in("edx") (self.xcr0_mask >> 32) as u32,
                in("eax") self.xcr0_mask as u32,
                options(nostack, preserves_flags)
            );
        } else {
            // Fallback to FXRSTOR
            core::arch::asm!(
                "fxrstor64 [{}]",
                in(reg) self.fxsave.as_ptr(),
                options(nostack, preserves_flags)
            );
        }
    }

    /// Test-mode stubs.
    #[cfg(test)]
    pub unsafe fn save(&mut self) {
        self.initialized = true;
    }

    #[cfg(test)]
    pub unsafe fn restore(&self) {}
}

// Static FPU save areas — one per vCPU slot.
struct SyncFpuArray(UnsafeCell<[FpuState; MAX_VCPUS]>);
unsafe impl Sync for SyncFpuArray {}

static FPU_STATES: SyncFpuArray = SyncFpuArray(
    UnsafeCell::new([const { FpuState::new() }; MAX_VCPUS]),
);

/// Get a mutable reference to the FPU save area for the given vCPU.
///
/// # Safety
/// Must only be called from the vCPU's own execution context.
pub fn fpu_state_for(vcpu_id: u32) -> &'static mut FpuState {
    let idx = (vcpu_id as usize) % MAX_VCPUS;
    unsafe { &mut (*FPU_STATES.0.get())[idx] }
}

impl Vcpu {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            apic_id: id,
            state: AtomicU8::new(VCPU_STATE_INIT),
            running: AtomicU8::new(0),
            vmcs: 0,
            cr3: 0,
            rsp: 0,
            rip: 0,
            rflags: 0x2,
            lapic: LocalApic::new(id),
            tsc_offset: AtomicU64::new(0),
            cpu_state: 0,
            vmcs_slot: 0,
            sipi_vector: 0,
            vpid: AtomicU16::new(0),
            sched_priority: 128, // Default priority
            vruntime: AtomicU64::new(0),
            current_pcpu: AtomicU16::new(0xFFFF),
            affinity_type: AtomicU8::new(0),
            affinity_pcpu: AtomicU16::new(0),
            timeslice_remaining: AtomicU64::new(0),
        }
    }

    pub fn set_running(&self, running: bool) {
        self.running
            .store(if running { 1 } else { 0 }, Ordering::Release);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire) != 0
    }

    pub fn set_state(&self, state: u8) {
        self.state.store(state, Ordering::Release);
    }

    pub fn get_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }

    /// Handle INIT IPI: reset the vCPU to its initial state and
    /// transition to WAIT_FOR_SIPI.
    ///
    /// Per Intel SDM Vol 3A §10.4.7.3: after INIT, the processor
    /// waits for a STARTUP IPI before executing.
    pub fn handle_init(&mut self) {
        self.state.store(VCPU_STATE_WAIT_FOR_SIPI, Ordering::Release);
        self.running.store(0, Ordering::Release);
        self.rip = 0;
        self.rsp = 0;
        self.cr3 = 0;
        self.rflags = 0x2; // reserved bit 1
        self.sipi_vector = 0;
        // Reset LAPIC to initial state (keep APIC ID).
        let apic_id = self.lapic.get_id();
        self.lapic = LocalApic::new(apic_id);
    }

    /// Handle STARTUP IPI: transition from WAIT_FOR_SIPI to running.
    ///
    /// The SIPI vector specifies the real-mode entry point:
    ///   CS:IP = (vector << 8) : 0x0000, so linear address = vector << 12.
    ///
    /// Returns `true` if the SIPI was accepted (vCPU was in WAIT_FOR_SIPI).
    pub fn handle_sipi(&mut self, vector: u8) -> bool {
        let current = self.state.load(Ordering::Acquire);
        if current != VCPU_STATE_WAIT_FOR_SIPI {
            return false;
        }
        self.sipi_vector = vector;
        self.rip = (vector as u64) << 12;
        self.state.store(VCPU_STATE_SIPI_RECEIVED, Ordering::Release);
        true
    }

    /// Check if this vCPU is an Application Processor (AP), i.e. not BSP.
    pub fn is_ap(&self) -> bool {
        self.id != 0
    }

    /// Check if this vCPU is the Bootstrap Processor (BSP).
    pub fn is_bsp(&self) -> bool {
        self.id == 0
    }

    /// Check if this vCPU is waiting for SIPI.
    pub fn is_waiting_for_sipi(&self) -> bool {
        self.state.load(Ordering::Acquire) == VCPU_STATE_WAIT_FOR_SIPI
    }

    /// Check if this vCPU received a SIPI and is ready to start.
    pub fn is_sipi_received(&self) -> bool {
        self.state.load(Ordering::Acquire) == VCPU_STATE_SIPI_RECEIVED
    }
    
    /// Allocate a VPID for this vCPU.
    /// Returns true if allocation succeeded.
    pub fn allocate_vpid(&self) -> bool {
        let vpid = crate::vmm::scheduler::allocate_vpid();
        if vpid != 0 {
            self.vpid.store(vpid, Ordering::Release);
            true
        } else {
            false
        }
    }
    
    /// Free the VPID for this vCPU.
    pub fn free_vpid(&self) {
        let vpid = self.vpid.load(Ordering::Acquire);
        if vpid != 0 {
            crate::vmm::scheduler::free_vpid(vpid);
            self.vpid.store(0, Ordering::Release);
        }
    }
    
    /// Get the current VPID.
    pub fn get_vpid(&self) -> u16 {
        self.vpid.load(Ordering::Acquire)
    }
    
    /// Set affinity for this vCPU.
    pub fn set_affinity(&self, pcpu: u16, affinity_type: u8) {
        self.affinity_pcpu.store(pcpu, Ordering::Release);
        self.affinity_type.store(affinity_type, Ordering::Release);
    }
    
    /// Get affinity type.
    pub fn get_affinity_type(&self) -> u8 {
        self.affinity_type.load(Ordering::Acquire)
    }
    
    /// Get preferred pCPU.
    pub fn get_affinity_pcpu(&self) -> u16 {
        self.affinity_pcpu.load(Ordering::Acquire)
    }
    
    /// Update virtual runtime for scheduler.
    pub fn update_vruntime(&self, delta: u64) {
        // vruntime += delta * 1024 / weight
        // Higher priority = higher weight = slower vruntime increment
        let weight = self.sched_weight();
        let vruntime_delta = (delta * 1024) / weight;
        self.vruntime.fetch_add(vruntime_delta, Ordering::Release);
    }
    
    /// Get current virtual runtime.
    pub fn get_vruntime(&self) -> u64 {
        self.vruntime.load(Ordering::Acquire)
    }
    
    /// Calculate weight based on priority (CFS-style).
    /// Higher priority = higher weight.
    pub fn sched_weight(&self) -> u64 {
        let prio_factor = (256 - self.sched_priority as u32) as u64;
        1024 * prio_factor / 128
    }
    
    /// Set scheduler priority.
    pub fn set_priority(&mut self, priority: u8) {
        self.sched_priority = priority;
    }
    
    /// Get scheduler priority.
    pub fn get_priority(&self) -> u8 {
        self.sched_priority
    }
    
    /// Set current pCPU.
    pub fn set_current_pcpu(&self, pcpu: u16) {
        self.current_pcpu.store(pcpu, Ordering::Release);
    }
    
    /// Get current pCPU.
    pub fn get_current_pcpu(&self) -> u16 {
        self.current_pcpu.load(Ordering::Acquire)
    }
    
    /// Check if this vCPU can run on the given pCPU (affinity check).
    pub fn can_run_on(&self, pcpu: u16) -> bool {
        let affinity = self.affinity_type.load(Ordering::Acquire);
        match affinity {
            0 => true, // No affinity
            1 => {
                // Soft affinity - prefer but can run elsewhere
                true
            }
            2 => {
                // Hard affinity - must run on specific pCPU
                self.affinity_pcpu.load(Ordering::Acquire) == pcpu
            }
            _ => true,
        }
    }
}

pub struct VcpuState {
    pub vcpus: [Option<Vcpu>; MAX_VCPUS],
    pub vcpu_count: AtomicU32,
    pub active_count: AtomicU32,
}

impl VcpuState {
    pub const fn new() -> Self {
        const NONE: Option<Vcpu> = None;
        Self {
            vcpus: [NONE; MAX_VCPUS],
            vcpu_count: AtomicU32::new(0),
            active_count: AtomicU32::new(0),
        }
    }

    pub fn create_vcpu(&mut self, id: u32) -> Option<&Vcpu> {
        if id as usize >= MAX_VCPUS {
            return None;
        }
        let vcpu = Vcpu::new(id);
        self.vcpus[id as usize] = Some(vcpu);
        self.vcpu_count.fetch_add(1, Ordering::Release);
        self.vcpus[id as usize].as_ref()
    }

    pub fn get_vcpu(&self, id: u32) -> Option<&Vcpu> {
        if id as usize >= MAX_VCPUS {
            return None;
        }
        self.vcpus[id as usize].as_ref()
    }

    pub fn get_vcpu_mut(&mut self, id: u32) -> Option<&mut Vcpu> {
        if id as usize >= MAX_VCPUS {
            return None;
        }
        self.vcpus[id as usize].as_mut()
    }

    pub fn get_count(&self) -> u32 {
        self.vcpu_count.load(Ordering::Acquire)
    }

    pub fn get_active_count(&self) -> u32 {
        self.active_count.load(Ordering::Acquire)
    }

    pub fn activate_vcpu(&self, id: u32) {
        if id as usize >= MAX_VCPUS {
            return;
        }
        if let Some(vcpu) = &self.vcpus[id as usize] {
            vcpu.set_running(true);
            self.active_count.fetch_add(1, Ordering::Release);
        }
    }

    pub fn deactivate_vcpu(&self, id: u32) {
        if id as usize >= MAX_VCPUS {
            return;
        }
        if let Some(vcpu) = &self.vcpus[id as usize] {
            vcpu.set_running(false);
            self.active_count.fetch_sub(1, Ordering::Release);
        }
    }

    /// Send an INIT IPI to the target vCPU.
    ///
    /// Transitions the AP from any state to WAIT_FOR_SIPI.
    pub fn send_init(&mut self, target_id: u32) -> bool {
        if target_id as usize >= MAX_VCPUS {
            return false;
        }
        if let Some(vcpu) = self.vcpus[target_id as usize].as_mut() {
            vcpu.handle_init();
            true
        } else {
            false
        }
    }

    /// Send a STARTUP IPI to the target vCPU with the given vector.
    ///
    /// Returns `true` if the vCPU was in WAIT_FOR_SIPI and accepted the SIPI.
    pub fn send_sipi(&mut self, target_id: u32, vector: u8) -> bool {
        if target_id as usize >= MAX_VCPUS {
            return false;
        }
        if let Some(vcpu) = self.vcpus[target_id as usize].as_mut() {
            vcpu.handle_sipi(vector)
        } else {
            false
        }
    }

    /// Dispatch an ICR write from the BSP: decode the ICR and send
    /// INIT or SIPI to the appropriate target(s).
    ///
    /// `sender_id`: the vCPU that wrote the ICR.
    /// `icr_low`:   ICR bits [31:0] (delivery mode, vector, shorthand).
    /// `icr_high`:  ICR bits [63:32] (destination field).
    pub fn dispatch_icr(&mut self, sender_id: u32, icr_low: u32, icr_high: u32) {
        let delivery = icr_low & 0x700; // bits 10:8
        let _dest_mode = (icr_low >> 11) & 1; // bit 11: 0=physical, 1=logical
        let shorthand = ((icr_low >> 18) & 3) as u8; // bits 19:18
        let vector = (icr_low & 0xFF) as u8;
        let dest_apic_id = (icr_high >> 24) & 0xFF;

        // Determine target set
        let count = self.vcpu_count.load(Ordering::Acquire);
        match shorthand {
            0 => {
                // No shorthand — use destination field
                if dest_apic_id < count {
                    self.dispatch_icr_to_one(dest_apic_id, delivery, vector);
                }
            }
            1 => {
                // Self
                self.dispatch_icr_to_one(sender_id, delivery, vector);
            }
            2 => {
                // All including self
                for i in 0..count {
                    self.dispatch_icr_to_one(i, delivery, vector);
                }
            }
            3 => {
                // All excluding self
                for i in 0..count {
                    if i != sender_id {
                        self.dispatch_icr_to_one(i, delivery, vector);
                    }
                }
            }
            _ => {}
        }
    }

    fn dispatch_icr_to_one(&mut self, target: u32, delivery: u32, vector: u8) {
        match delivery {
            0x500 => {
                // INIT
                self.send_init(target);
            }
            0x600 => {
                // STARTUP (SIPI)
                self.send_sipi(target, vector);
            }
            _ => {
                // Fixed / lowest-priority / NMI / SMI etc.
                // For fixed delivery, inject the vector into the target's LAPIC.
                if let Some(vcpu) = self.vcpus[target as usize].as_mut() {
                    // Set the IRR bit for the vector
                    let reg_idx = (vector >> 5) as usize;
                    let bit = 1u32 << (vector & 0x1F);
                    let irr_offset = (LAPIC_IRR0 + (reg_idx as u32) * 0x10) >> 4;
                    if (irr_offset as usize) < 64 {
                        vcpu.lapic.regs[irr_offset as usize] |= bit;
                    }
                }
            }
        }
    }

    /// Get the SIPI entry RIP for a vCPU that received a SIPI.
    pub fn get_sipi_entry(&self, vcpu_id: u32) -> Option<u64> {
        if let Some(vcpu) = self.get_vcpu(vcpu_id) {
            if vcpu.is_sipi_received() {
                return Some(vcpu.rip);
            }
        }
        None
    }

    /// Transition a vCPU from SIPI_RECEIVED to RUNNING.
    pub fn start_ap(&mut self, vcpu_id: u32) -> bool {
        if let Some(vcpu) = self.vcpus[vcpu_id as usize].as_mut() {
            if vcpu.is_sipi_received() {
                vcpu.state.store(VCPU_STATE_RUNNING, Ordering::Release);
                vcpu.set_running(true);
                self.active_count.fetch_add(1, Ordering::Release);
                return true;
            }
        }
        false
    }
}

impl Default for VcpuState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global guest LAPIC array ─────────────────────────────────────────────────
//
// One LocalApic per vCPU, wrapped in `UnsafeCell` + manual `Sync` so the
// fast-path exit handler in vmx.rs can access them without any state pointer.
// Safe because each physical CPU only services one vCPU at a time.

struct SyncLapicArray(UnsafeCell<[LocalApic; MAX_VCPUS]>);
unsafe impl Sync for SyncLapicArray {}

const INIT_LAPIC: LocalApic = LocalApic::new(0);

static GUEST_LAPICS: SyncLapicArray = SyncLapicArray(
    UnsafeCell::new([INIT_LAPIC; MAX_VCPUS]),
);

/// Get a mutable reference to the global guest LAPIC for vCPU `id`.
///
/// # Safety
/// Must only be called from the vCPU exit path (single-threaded context per vCPU).
pub fn guest_lapic_for(id: u32) -> &'static mut LocalApic {
    let idx = (id as usize) % MAX_VCPUS;
    unsafe {
        let arr = &mut *GUEST_LAPICS.0.get();
        // Lazily set the APIC ID if it hasn't been set yet.
        if arr[idx].get_id() != id {
            arr[idx].set_id(id);
        }
        &mut arr[idx]
    }
}

/// Convenience: get the BSP (vCPU-0) LAPIC. Backward-compatible alias.
///
/// # Safety
/// Must only be called from the vCPU-0 exit path (single-threaded context).
pub fn guest_lapic() -> &'static mut LocalApic {
    guest_lapic_for(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_init_sipi_state_machine() {
        let mut vcpu = Vcpu::new(1);
        assert_eq!(vcpu.get_state(), VCPU_STATE_INIT);

        // SIPI before INIT should be rejected
        assert!(!vcpu.handle_sipi(0x10));

        // INIT → WAIT_FOR_SIPI
        vcpu.handle_init();
        assert_eq!(vcpu.get_state(), VCPU_STATE_WAIT_FOR_SIPI);
        assert!(!vcpu.is_running());

        // SIPI → SIPI_RECEIVED with correct entry RIP
        assert!(vcpu.handle_sipi(0x10));
        assert_eq!(vcpu.get_state(), VCPU_STATE_SIPI_RECEIVED);
        assert_eq!(vcpu.rip, 0x10000); // 0x10 << 12
        assert_eq!(vcpu.sipi_vector, 0x10);

        // Second SIPI should be rejected (not in WAIT_FOR_SIPI)
        assert!(!vcpu.handle_sipi(0x20));
    }

    #[test]
    fn vcpu_state_dispatch_icr_init_sipi() {
        let mut state = VcpuState::new();
        state.create_vcpu(0); // BSP
        state.create_vcpu(1); // AP

        // BSP sends INIT to AP (vCPU 1)
        // ICR: delivery=INIT(0x500), dest=1, shorthand=0 (no shorthand)
        let icr_low = 0x0000_0500u32; // INIT, no shorthand
        let icr_high = 1u32 << 24;    // dest APIC ID = 1
        state.dispatch_icr(0, icr_low, icr_high);

        // AP should be in WAIT_FOR_SIPI
        let ap = state.get_vcpu(1).unwrap();
        assert_eq!(ap.get_state(), VCPU_STATE_WAIT_FOR_SIPI);

        // BSP sends SIPI to AP with vector 0x08 (entry = 0x8000)
        let icr_low_sipi = 0x0000_0608u32; // STARTUP + vector=0x08
        state.dispatch_icr(0, icr_low_sipi, icr_high);

        let ap = state.get_vcpu(1).unwrap();
        assert_eq!(ap.get_state(), VCPU_STATE_SIPI_RECEIVED);
        assert_eq!(ap.rip, 0x8000);
    }

    #[test]
    fn vcpu_state_broadcast_init_all_excluding_self() {
        let mut state = VcpuState::new();
        for i in 0..4 {
            state.create_vcpu(i);
        }

        // ICR: INIT, shorthand=3 (all-excluding-self)
        let icr_low = 0x000C_0500u32; // INIT + shorthand=3
        state.dispatch_icr(0, icr_low, 0);

        // BSP (0) should NOT get INIT, APs (1,2,3) should
        let bsp = state.get_vcpu(0).unwrap();
        assert_eq!(bsp.get_state(), VCPU_STATE_INIT); // unchanged

        for i in 1..4 {
            let ap = state.get_vcpu(i).unwrap();
            assert_eq!(ap.get_state(), VCPU_STATE_WAIT_FOR_SIPI);
        }
    }

    #[test]
    fn vcpu_start_ap_transitions_to_running() {
        let mut state = VcpuState::new();
        state.create_vcpu(0);
        state.create_vcpu(1);

        state.send_init(1);
        state.send_sipi(1, 0x10);
        assert!(state.start_ap(1));

        let ap = state.get_vcpu(1).unwrap();
        assert_eq!(ap.get_state(), VCPU_STATE_RUNNING);
        assert!(ap.is_running());
    }

    #[test]
    fn fpu_state_save_restore_test_mode() {
        let fpu = fpu_state_for(0);
        assert!(!fpu.initialized);
        unsafe { fpu.save(); }
        assert!(fpu.initialized);
        unsafe { fpu.restore(); } // should not panic
    }

    #[test]
    fn per_vcpu_lapic_isolation() {
        // Each vCPU should have its own LAPIC with the correct ID.
        let lapic0 = guest_lapic_for(0);
        lapic0.write(LAPIC_TPR, 0x42);

        let lapic1 = guest_lapic_for(1);
        lapic1.write(LAPIC_TPR, 0x99);

        // They should be independent
        assert_eq!(guest_lapic_for(0).read(LAPIC_TPR), 0x42);
        assert_eq!(guest_lapic_for(1).read(LAPIC_TPR), 0x99);

        // Clean up
        guest_lapic_for(0).write(LAPIC_TPR, 0);
        guest_lapic_for(1).write(LAPIC_TPR, 0);
    }

    #[test]
    fn vcpu_is_bsp_ap() {
        let bsp = Vcpu::new(0);
        assert!(bsp.is_bsp());
        assert!(!bsp.is_ap());

        let ap = Vcpu::new(1);
        assert!(!ap.is_bsp());
        assert!(ap.is_ap());
    }

    #[test]
    fn icr_fixed_delivery_sets_irr() {
        let mut state = VcpuState::new();
        state.create_vcpu(0);
        state.create_vcpu(1);

        // Send fixed vector 0x30 to vCPU 1
        let icr_low = 0x0000_0030u32; // fixed delivery, vector=0x30
        let icr_high = 1u32 << 24;
        state.dispatch_icr(0, icr_low, icr_high);

        // Check that IRR bit for vector 0x30 is set in AP's LAPIC
        let ap = state.get_vcpu(1).unwrap();
        let irr_reg_idx = (0x30u32 >> 5) as usize; // register 1
        let irr_bit = 1u32 << (0x30 & 0x1F);       // bit 16
        let irr_offset = (LAPIC_IRR0 + (irr_reg_idx as u32) * 0x10) >> 4;
        assert_ne!(ap.lapic.regs[irr_offset as usize] & irr_bit, 0);
    }
}
