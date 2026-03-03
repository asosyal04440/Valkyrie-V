#![allow(clippy::new_without_default)]
#![allow(clippy::declare_interior_mutable_const)]

use crate::vmm::HvError;
use core::ptr::write_volatile;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;

const ICR_LOW: usize = 0x300;
const ICR_HIGH: usize = 0x310;

const DELIVERY_INIT: u32 = 0x5 << 8;
const DELIVERY_STARTUP: u32 = 0x6 << 8;
const LEVEL_ASSERT: u32 = 1 << 14;

const MAX_CPUS: usize = 64;
const MAX_SPINS: u32 = 1_000_000;

pub struct Apic {
    base: *mut u8,
}

impl Apic {
    pub fn new() -> Result<Self, HvError> {
        let base = read_msr(IA32_APIC_BASE);
        if base & APIC_BASE_ENABLE == 0 {
            return Err(HvError::HardwareFault);
        }
        let addr = (base & 0xFFFF_F000) as *mut u8;
        Ok(Self { base: addr })
    }

    pub fn send_init_ipi(&self, apic_id: u32) -> Result<(), HvError> {
        self.send_ipi(apic_id, 0, DELIVERY_INIT | LEVEL_ASSERT)
    }

    pub fn send_startup_ipi(&self, apic_id: u32, vector: u8) -> Result<(), HvError> {
        self.send_ipi(apic_id, vector as u32, DELIVERY_STARTUP)
    }

    pub fn start_aps(&self, apic_ids: &[u32], vector: u8) -> Result<(), HvError> {
        for &apic_id in apic_ids {
            if apic_id == 0 {
                continue;
            }
            self.send_init_ipi(apic_id)?;
            delay();
            self.send_startup_ipi(apic_id, vector)?;
            delay();
            self.send_startup_ipi(apic_id, vector)?;
            delay();
        }
        Ok(())
    }

    fn send_ipi(&self, apic_id: u32, vector: u32, mode: u32) -> Result<(), HvError> {
        unsafe {
            write_volatile(self.base.add(ICR_HIGH) as *mut u32, apic_id << 24);
            write_volatile(self.base.add(ICR_LOW) as *mut u32, mode | vector);
        }
        Ok(())
    }
}

pub struct TscSync {
    ready: [AtomicU32; MAX_CPUS],
    tsc: [AtomicU64; MAX_CPUS],
    offsets: [AtomicU64; MAX_CPUS],
}

impl TscSync {
    pub const fn new() -> Self {
        const ZERO_U32: AtomicU32 = AtomicU32::new(0);
        const ZERO_U64: AtomicU64 = AtomicU64::new(0);
        Self {
            ready: [ZERO_U32; MAX_CPUS],
            tsc: [ZERO_U64; MAX_CPUS],
            offsets: [ZERO_U64; MAX_CPUS],
        }
    }

    pub fn record_local(&self, index: usize, tsc: u64) -> Result<(), HvError> {
        if index >= MAX_CPUS {
            return Err(HvError::LogicalFault);
        }
        self.tsc[index].store(tsc, Ordering::Release);
        self.ready[index].store(1, Ordering::Release);
        Ok(())
    }

    pub fn rendezvous(&self, indices: &[usize]) -> Result<u64, HvError> {
        for &index in indices {
            if index >= MAX_CPUS {
                return Err(HvError::LogicalFault);
            }
            let mut spins = 0u32;
            while self.ready[index].load(Ordering::Acquire) == 0 {
                if spins >= MAX_SPINS {
                    return Err(HvError::LogicalFault);
                }
                core::hint::spin_loop();
                spins += 1;
            }
        }
        let mut sum = 0u128;
        for &index in indices {
            sum += self.tsc[index].load(Ordering::Acquire) as u128;
        }
        let avg = (sum / indices.len() as u128) as u64;
        for &index in indices {
            let local = self.tsc[index].load(Ordering::Acquire);
            let offset = avg.wrapping_sub(local);
            self.offsets[index].store(offset, Ordering::Release);
        }
        Ok(avg)
    }

    pub fn offset(&self, index: usize) -> Result<u64, HvError> {
        if index >= MAX_CPUS {
            return Err(HvError::LogicalFault);
        }
        Ok(self.offsets[index].load(Ordering::Acquire))
    }

    pub fn reset_ready(&self, indices: &[usize]) -> Result<(), HvError> {
        for &index in indices {
            if index >= MAX_CPUS {
                return Err(HvError::LogicalFault);
            }
            self.ready[index].store(0, Ordering::Release);
            self.tsc[index].store(0, Ordering::Release);
            self.offsets[index].store(0, Ordering::Release);
        }
        Ok(())
    }
}

fn delay() {
    for _ in 0..10000 {
        core::hint::spin_loop();
    }
}

fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") low, out("edx") high);
    }
    ((high as u64) << 32) | low as u64
}
