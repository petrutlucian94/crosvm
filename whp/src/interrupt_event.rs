use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

use libwhp::Partition;
use libwhp::instruction_emulator::*;

use crate::vcpu::*;

use sys_util::{Result, EventFd, warn, info};

/// This is meant to be an EventFd structure replacement, allowing us
/// to emulate KVM APIs.
/// WHP doesn't allow mapping event objects to IRQs, so instead we'll
/// add a dedicated structure that contains a callback which will
/// trigger an iterrupt when the "event" gets signaled.
///
/// For convenience, we'll wrap an EventFd so that this structure can also
/// be used for resample events, triggered by us when receiving an level
/// interrupt EOI.

pub struct InterruptEvent {
    ioapic: Arc<Mutex<Option<Ioapic>>>,
    irq: u32,
    eventfd: EventFd,
}

impl InterruptEvent {
    /// Create a new InterruptEvent object.
    pub fn new() -> Result<InterruptEvent> {
        Ok(InterruptEvent{
            partition: None,
            irq: 0,
            eventfd: EventFd::new()?,
            mode: InterruptMode::Edge
        })
    }

    pub fn map(&mut self, ioapic: Arc<Mutex<Ioapic>>, irq: u32) {
        self.ioapic = Arc::clone(&ioapic);
        self.irq = irq;
    }

    pub fn unmap(&mut self) {
        self.ioapic = None
    }

    fn interrupt(&self) -> Result<()> {
        match &self.ioapic {
            Some(ref ioapic) => {
                ioapic.service_irq(self.irq, 1);
            }
            None => warn!("InterruptEvent: missing io-apic reference, dropping interrupt.");
        }
        Ok(())
    }

    /// Trigger an interrupt by signaling this event.
    ///
    /// "Resample" events will not be mapped. When signaled, we don't want to
    /// send an inerrupt, we just want to let the VMM know that an EOI has been
    /// received.
    pub fn write(&self, v: u64) -> Result<()> {
        self.interrupt()?;
        self.eventfd.write(v)
    }

    /// Blocks until the the eventfd's count is non-zero, then
    /// resets the count to zero.
    pub fn read(&self) -> Result<u64> {
        self.eventfd.read()
    }

    /// Clones this InterruptEvent object.
    pub fn try_clone(&self) -> Result<InterruptEvent> {
        let ioapic = match self.ioapic.lock().unwrap(){
            Some(ref ioapic) => self.ioapic.clone(),
            None => Arc::new(Mutex::new(None))
        };

        Ok(InterruptEvent {
            eventfd: self.eventfd.try_clone()?,
            ioapic: ioapic,
            irq: self.irq,
        })
    }
}

impl AsRawHandle for InterruptEvent {
    fn as_raw_handle(&self) -> RawHandle {
        self.eventfd.as_raw_handle()
    }
}

// TODO(lpetrut): drop this if possible. We're losing
// the irq and ioapic ref.
impl FromRawHandle for InterruptEvent {
    unsafe fn from_raw_handle(fd: RawHandle) -> Self {
        InterruptEvent {
            eventfd: EventFd::from_raw_handle(fd),
            ioapic: Arc::new(Mutex::new(None)),
            irq: 0,
        }
    }
}

impl IntoRawHandle for InterruptEvent {
    fn into_raw_handle(self) -> RawHandle {
        self.eventfd.into_raw_handle()
    }
}
