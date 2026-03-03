use crate::vmm::apic::{Apic, TscSync};
use crate::vmm::irq::irq_registry;
use crate::vmm::manifest::{ManifestAuthority, SignatureRecord};
use crate::vmm::{DriverTag, HvError};
use ironshim::{
    Error, InterruptBudget, InterruptHandler, InterruptRegistry, IoPortDesc, MmioDesc,
    ResourceManifest,
};

const MMIO_SLOTS: usize = 1;
const PORT_SLOTS: usize = 0;
const CHRONOS_IRQ: u32 = 32;

pub struct Chronos {
    manifest: ResourceManifest<DriverTag, MMIO_SLOTS, PORT_SLOTS>,
    registry: &'static dyn InterruptRegistry,
    irq: u32,
    authority: ManifestAuthority,
    signature: SignatureRecord,
}

impl Chronos {
    pub fn new() -> Result<Self, HvError> {
        let mmio = [MmioDesc { base: 0, size: 1 }; MMIO_SLOTS];
        let ports: [IoPortDesc; PORT_SLOTS] = [];
        let manifest =
            ResourceManifest::new(mmio, 0, ports, 0).map_err(|_| HvError::LogicalFault)?;
        let registry = irq_registry();
        unsafe {
            registry
                .register_with_budget(
                    CHRONOS_IRQ,
                    &mut *core::ptr::addr_of_mut!(CHRONOS_HANDLER),
                    InterruptBudget {
                        max_ticks: 5000,
                        max_calls: 1000,
                    },
                )
                .map_err(|_| HvError::LogicalFault)?;
        }
        let authority = ManifestAuthority::new();
        let signature = authority.sign(&manifest, 1, current_time(), 0)?;
        Ok(Self {
            manifest,
            registry,
            irq: CHRONOS_IRQ,
            authority,
            signature,
        })
    }

    pub fn tsc_enter(&self) -> Result<u64, HvError> {
        // Uses IronShim's budgeted IRQ isolation to avoid skew in measurements
        self.registry
            .trigger_with_budget(self.irq, 0)
            .map_err(|_| HvError::LogicalFault)?;
        let metrics = self
            .registry
            .metrics(self.irq)
            .map_err(|_| HvError::LogicalFault)?;
        if metrics.budget_violations > 0 {
            return Err(HvError::LogicalFault);
        }
        Ok(unsafe { core::arch::x86_64::_rdtsc() })
    }

    pub fn tsc_exit(&self) -> u64 {
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    pub fn adjust_tsc_offset(&self, cycles: u64) -> Result<(), HvError> {
        self.validate_manifest()?;
        #[cfg(not(test))]
        unsafe {
            // 0x2010 is the VMCS field encoding for TSC_OFFSET (64-bit control field).
            // Must use VMWRITE, not WRMSR — there is no MSR at address 0x2010.
            vmwrite_tsc_offset(cycles);
        }
        #[cfg(test)]
        let _ = cycles;
        Ok(())
    }

    pub fn global_sync(&self, cores: &[u64]) -> Result<u64, HvError> {
        self.validate_manifest()?;
        let mut sum: u64 = 0;
        for _ in cores {
            sum = sum.wrapping_add(unsafe { core::arch::x86_64::_rdtsc() });
        }
        Ok(sum / cores.len() as u64)
    }

    pub fn rendezvous_sync(
        &self,
        apic: &Apic,
        tsc_sync: &TscSync,
        apic_ids: &[u32],
        indices: &[usize],
        vector: u8,
    ) -> Result<u64, HvError> {
        self.validate_manifest()?;
        const MAX_ATTEMPTS: u32 = 3;
        for attempt in 0..MAX_ATTEMPTS {
            apic.start_aps(apic_ids, vector)?;
            match tsc_sync.rendezvous(indices) {
                Ok(avg) => return Ok(avg),
                Err(err) => {
                    if attempt + 1 >= MAX_ATTEMPTS {
                        return Err(err);
                    }
                    tsc_sync.reset_ready(indices)?;
                }
            }
        }
        Err(HvError::LogicalFault)
    }

    fn validate_manifest(&self) -> Result<(), HvError> {
        self.authority
            .validate(&self.manifest, &self.signature, current_time())
    }
}

/// Write a value to a VMCS field using the VMWRITE instruction.
/// VMCS_TSC_OFFSET (0x2010) is a 64-bit control field — it is not an MSR.
#[cfg(not(test))]
unsafe fn vmwrite_tsc_offset(value: u64) {
    const VMCS_TSC_OFFSET: u64 = 0x2010;
    core::arch::asm!(
        "vmwrite {field}, {val}",
        field = in(reg) VMCS_TSC_OFFSET,
        val   = in(reg) value,
    );
}

struct ChronosHandler;

impl InterruptHandler for ChronosHandler {
    fn handle(&mut self, _irq: u32) -> Result<(), Error> {
        Ok(())
    }
}

static mut CHRONOS_HANDLER: ChronosHandler = ChronosHandler;

fn current_time() -> u64 {
    const TSC_HZ: u64 = 3_000_000_000;
    unsafe { core::arch::x86_64::_rdtsc() / TSC_HZ }
}
