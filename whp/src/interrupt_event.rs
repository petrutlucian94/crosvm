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
    partition: Option<Partition>,
    irq: u32,
    eventfd: EventFd
}

impl InterruptEvent {
    /// Create a new InterruptEvent object.
    pub fn new() -> Result<InterruptEvent> {
        Ok(InterruptEvent{
            partition: None,
            irq: 0,
            eventfd: EventFd::new()?
        })
    }

    pub fn interrupt(&self) -> Result<()> {
        let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

        interrupt.set_InterruptType(
            WHV_INTERRUPT_TYPE::WHvX64InterruptTypeFixed as UINT64);
        interrupt.set_DestinationMode(
            WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical as UINT64);
        interrupt.set_TriggerMode(
            WHV_INTERRUPT_TRIGGER_MODE::WHvX64InterruptTriggerModeEdge as UINT64);
        interrupt.Destination = 0;

        // Vectors 0x30-0x3f are used for ISA interrupts.
        // TODO(lpetrut): Are we doing the right thing here?
        interrupt.Vector = self.irq + 0x30;

        match &self.partition {
            Some(ref partition) => {
                partition.request_interrupt(&mut interrupt).unwrap()
            }
            None => {
                warn!("InterruptEvent: no mapping found");
            }
        }

        Ok(())
    }

    pub fn map(&mut self, partition: &Partition, irq: u32) {
        self.partition = Some(partition.clone());
        self.irq = irq;
    }

    pub fn unmap(&mut self) {
        self.partition = None;
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
        let partition = match self.partition {
            Some(ref partition) => Some(partition.clone()),
            None => None
        };

        Ok(InterruptEvent {
            eventfd: self.eventfd.try_clone()?,
            partition: partition,
            irq: self.irq
        })
    }
}

impl AsRawHandle for InterruptEvent {
    fn as_raw_handle(&self) -> RawHandle {
        self.eventfd.as_raw_handle()
    }
}

impl FromRawHandle for InterruptEvent {
    unsafe fn from_raw_handle(fd: RawHandle) -> Self {
        InterruptEvent {
            eventfd: EventFd::from_raw_handle(fd),
            partition: None,
            irq: 0
        }
    }
}

impl IntoRawHandle for InterruptEvent {
    fn into_raw_handle(self) -> RawHandle {
        self.eventfd.into_raw_handle()
    }
}
