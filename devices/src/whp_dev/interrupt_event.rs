use std::sync::Arc;

use crate::Ioapic;
use crate::split_irqchip_common::*;
use sync::Mutex;

use crate::WhpInterruptController;

use sys_util::{Result, EventFd, warn, info};

/// KVM can emulate IO-APIC devices, allowing interrupts to be injected
/// by triggering events.
///
/// "InterruptEvent" emulates this behavior, forwarding requests to an
/// io-apic emulated by us instead.


pub struct InterruptEvent {
    // We may either use a generic controller or conditionally
    // compile some other type.
    ioapic: Arc<Mutex<Ioapic<WhpInterruptController>>>,
    irq: u32,
}

impl InterruptEvent {
    /// Create a new InterruptEvent object.
    // TODO(lpetrut): we may consider assigning those separately so that
    // we keep a similar interface with EventFd.
    pub fn new(
        irq: u32,
        ioapic: Arc<Mutex<Ioapic<WhpInterruptController>>>) ->
            Result<InterruptEvent>
    {
        Ok(InterruptEvent{
            ioapic: ioapic,
            irq: irq,
        })
    }

    fn interrupt(&self) -> Result<()> {
        self.ioapic.lock().service_irq(self.irq as usize, true);
        Ok(())
    }

    /// Trigger an interrupt by signaling this event.
    pub fn write(&self, _v: u64) -> Result<()> {
        self.interrupt()
    }

    /// Clones this InterruptEvent object.
    pub fn try_clone(&self) -> Result<InterruptEvent> {
        Ok(InterruptEvent {
            ioapic: self.ioapic.clone(),
            irq: self.irq,
        })
    }
}
