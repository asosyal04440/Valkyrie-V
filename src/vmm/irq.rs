#![allow(clippy::new_without_default)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::missing_safety_doc)]
#![allow(static_mut_refs)]

use crate::vmm::{record_telemetry, TELEMETRY_BUDGET_EXCEEDED, TELEMETRY_QUARANTINE};
use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};
use ironshim::{
    Error, InterruptBudget, InterruptHandler, InterruptMetrics, InterruptRegistry, TelemetryEvent,
    TelemetrySink,
};

const MAX_IRQ: usize = 256;

pub struct IrqRegistry {
    handler_data: [AtomicUsize; MAX_IRQ],
    handler_vtable: [AtomicUsize; MAX_IRQ],
    /// Per-slot spinlock: 0 = free, 1 = locked.
    /// Held briefly during the two-word fat-pointer read/write to prevent
    /// a concurrent reader seeing mismatched data+vtable pointers.
    handler_lock: [AtomicU8; MAX_IRQ],
    max_ticks: [AtomicU32; MAX_IRQ],
    max_calls: [AtomicU32; MAX_IRQ],
    latency_ticks: [AtomicU32; MAX_IRQ],
    missed: [AtomicU32; MAX_IRQ],
    budget_violations: [AtomicU32; MAX_IRQ],
    call_count: [AtomicU32; MAX_IRQ],
    quarantined: [AtomicU8; MAX_IRQ],
}

pub struct IrqTelemetry {
    budget_exceeded: [AtomicU32; MAX_IRQ],
    quarantined: [AtomicU32; MAX_IRQ],
}

impl IrqTelemetry {
    pub const fn new() -> Self {
        const ZERO_U32: AtomicU32 = AtomicU32::new(0);
        Self {
            budget_exceeded: [ZERO_U32; MAX_IRQ],
            quarantined: [ZERO_U32; MAX_IRQ],
        }
    }
}

impl TelemetrySink for IrqTelemetry {
    fn record(&self, event: TelemetryEvent) {
        match event {
            TelemetryEvent::BudgetExceeded(irq) => {
                let index = irq as usize;
                if index < MAX_IRQ {
                    self.budget_exceeded[index].fetch_add(1, Ordering::Relaxed);
                }
            }
            TelemetryEvent::Quarantine(irq) => {
                let index = irq as usize;
                if index < MAX_IRQ {
                    self.quarantined[index].fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
}

static TELEMETRY: IrqTelemetry = IrqTelemetry::new();

impl IrqRegistry {
    pub const fn new() -> Self {
        const ZERO_USIZE: AtomicUsize = AtomicUsize::new(0);
        const ZERO_U32: AtomicU32 = AtomicU32::new(0);
        const ZERO_U8: AtomicU8 = AtomicU8::new(0);
        Self {
            handler_data: [ZERO_USIZE; MAX_IRQ],
            handler_vtable: [ZERO_USIZE; MAX_IRQ],
            handler_lock: [ZERO_U8; MAX_IRQ],
            max_ticks: [ZERO_U32; MAX_IRQ],
            max_calls: [ZERO_U32; MAX_IRQ],
            latency_ticks: [ZERO_U32; MAX_IRQ],
            missed: [ZERO_U32; MAX_IRQ],
            budget_violations: [ZERO_U32; MAX_IRQ],
            call_count: [ZERO_U32; MAX_IRQ],
            quarantined: [ZERO_U8; MAX_IRQ],
        }
    }

    /// Acquire the per-slot spinlock by CAS-looping 0 → 1.
    #[inline]
    fn lock_slot(&self, irq: usize) {
        while self.handler_lock[irq]
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
    }

    /// Release the per-slot spinlock.
    #[inline]
    fn unlock_slot(&self, irq: usize) {
        self.handler_lock[irq].store(0, Ordering::Release);
    }

    fn set_handler(
        &self,
        irq: u32,
        handler: &'static mut dyn InterruptHandler,
    ) -> Result<(), Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        let (data, vtable): (*mut (), *mut ()) = unsafe { core::mem::transmute(handler) };
        self.lock_slot(irq);
        self.handler_data[irq].store(data as usize, Ordering::Relaxed);
        self.handler_vtable[irq].store(vtable as usize, Ordering::Relaxed);
        self.unlock_slot(irq);
        Ok(())
    }

    fn handler(&self, irq: u32) -> Result<&'static mut dyn InterruptHandler, Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        self.lock_slot(irq);
        let data = self.handler_data[irq].load(Ordering::Relaxed);
        let vtable = self.handler_vtable[irq].load(Ordering::Relaxed);
        self.unlock_slot(irq);
        if data == 0 || vtable == 0 {
            return Err(Error::InvalidState);
        }
        let handler: *mut dyn InterruptHandler =
            unsafe { core::mem::transmute((data as *mut (), vtable as *mut ())) };
        Ok(unsafe { &mut *handler })
    }

    fn check_budget(&self, irq: u32, elapsed_ticks: u32) -> Result<(), Error> {
        let irq = irq as usize;
        let max_ticks = self.max_ticks[irq].load(Ordering::Relaxed);
        let max_calls = self.max_calls[irq].load(Ordering::Relaxed);
        self.latency_ticks[irq].store(elapsed_ticks, Ordering::Relaxed);
        let calls = self.call_count[irq].fetch_add(1, Ordering::Relaxed) + 1;
        if elapsed_ticks > max_ticks || calls > max_calls {
            self.budget_violations[irq].fetch_add(1, Ordering::Relaxed);
            self.quarantined[irq].store(1, Ordering::Relaxed);
            TELEMETRY.record(TelemetryEvent::BudgetExceeded(irq as u32));
            TELEMETRY.record(TelemetryEvent::Quarantine(irq as u32));
            record_telemetry(TELEMETRY_BUDGET_EXCEEDED, irq as u32);
            record_telemetry(TELEMETRY_QUARANTINE, irq as u32);
            return Err(Error::BudgetExceeded);
        }
        Ok(())
    }

    pub fn force_quarantine(&self, irq: u32) -> Result<(), Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        self.quarantined[irq].store(1, Ordering::Release);
        self.missed[irq].fetch_add(1, Ordering::Relaxed);
        TELEMETRY.record(TelemetryEvent::Quarantine(irq as u32));
        record_telemetry(TELEMETRY_QUARANTINE, irq as u32);
        Ok(())
    }
}

impl InterruptRegistry for IrqRegistry {
    fn register(&self, irq: u32, handler: &'static mut dyn InterruptHandler) -> Result<(), Error> {
        self.set_handler(irq, handler)
    }

    fn register_with_budget(
        &self,
        irq: u32,
        handler: &'static mut dyn InterruptHandler,
        budget: InterruptBudget,
    ) -> Result<(), Error> {
        let irq_index = irq as usize;
        if irq_index >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        self.set_handler(irq, handler)?;
        self.max_ticks[irq_index].store(budget.max_ticks, Ordering::Relaxed);
        self.max_calls[irq_index].store(budget.max_calls, Ordering::Relaxed);
        Ok(())
    }

    fn unregister(&self, irq: u32) -> Result<(), Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        self.handler_data[irq].store(0, Ordering::Release);
        self.handler_vtable[irq].store(0, Ordering::Release);
        Ok(())
    }

    fn trigger(&self, irq: u32) -> Result<(), Error> {
        self.trigger_with_budget(irq, 0)
    }

    fn trigger_with_budget(&self, irq: u32, elapsed_ticks: u32) -> Result<(), Error> {
        let irq_index = irq as usize;
        if irq_index >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        if self.quarantined[irq_index].load(Ordering::Acquire) != 0 {
            self.missed[irq_index].fetch_add(1, Ordering::Relaxed);
            TELEMETRY.record(TelemetryEvent::Quarantine(irq));
            record_telemetry(TELEMETRY_QUARANTINE, irq);
            return Err(Error::Quarantined);
        }
        self.check_budget(irq, elapsed_ticks)?;
        let handler = self.handler(irq)?;
        handler.handle(irq)
    }

    fn unquarantine(&self, irq: u32) -> Result<(), Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        self.quarantined[irq].store(0, Ordering::Release);
        self.call_count[irq].store(0, Ordering::Relaxed);
        Ok(())
    }

    fn metrics(&self, irq: u32) -> Result<InterruptMetrics, Error> {
        let irq = irq as usize;
        if irq >= MAX_IRQ {
            return Err(Error::OutOfBounds);
        }
        Ok(InterruptMetrics {
            latency_ticks: self.latency_ticks[irq].load(Ordering::Relaxed),
            missed: self.missed[irq].load(Ordering::Relaxed),
            budget_violations: self.budget_violations[irq].load(Ordering::Relaxed),
        })
    }
}

static IRQ_REGISTRY: IrqRegistry = IrqRegistry::new();

pub fn irq_registry() -> &'static dyn InterruptRegistry {
    &IRQ_REGISTRY
}

pub fn force_quarantine(irq: u32) -> Result<(), Error> {
    IRQ_REGISTRY.force_quarantine(irq)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler {
        calls: AtomicU32,
    }

    impl InterruptHandler for TestHandler {
        fn handle(&mut self, _irq: u32) -> Result<(), Error> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    static mut TEST_HANDLER: TestHandler = TestHandler {
        calls: AtomicU32::new(0),
    };

    #[test]
    fn irq_budget_quarantine() {
        let irq = 64u32;
        unsafe {
            IRQ_REGISTRY
                .register_with_budget(
                    irq,
                    &mut TEST_HANDLER,
                    InterruptBudget {
                        max_ticks: 0,
                        max_calls: 1,
                    },
                )
                .unwrap();
        }
        assert!(IRQ_REGISTRY.trigger_with_budget(irq, 0).is_ok());
        assert!(matches!(
            IRQ_REGISTRY.trigger_with_budget(irq, 0),
            Err(Error::BudgetExceeded)
        ));
        assert!(matches!(
            IRQ_REGISTRY.trigger_with_budget(irq, 0),
            Err(Error::Quarantined)
        ));
        let metrics = IRQ_REGISTRY.metrics(irq).unwrap();
        assert!(metrics.budget_violations > 0);
        IRQ_REGISTRY.unquarantine(irq).unwrap();
        IRQ_REGISTRY.unregister(irq).unwrap();
    }
}
