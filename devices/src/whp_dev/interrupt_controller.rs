use libwhp::platform::*;
use libwhp::common::*;

use sys_util::{Result, warn};

pub use crate::split_irqchip_common::*;

pub struct WhpInterruptController {
    partition: Partition,
}

impl WhpInterruptController {
    pub fn new(partition: Partition) -> Result<WhpInterruptController> {
        Ok(WhpInterruptController {
            partition: partition.clone()
        })
    }
}

// Unfortunately this can't be part of the whp crate,
// otherwise we end up having a circular dependency.
impl InterruptController for WhpInterruptController {
    fn inject_interrupt(&self, vector: u8,
                        trigger_mode: TriggerMode,
                        dest: u8, dest_mode: DestinationMode,
                        delivery_mode: DeliveryMode) {
        let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

        let whp_trigger_mode = match trigger_mode {
            TriggerMode::Level => WHV_INTERRUPT_TRIGGER_MODE::WHvX64InterruptTriggerModeLevel,
            TriggerMode::Edge => WHV_INTERRUPT_TRIGGER_MODE::WHvX64InterruptTriggerModeEdge
        };

        // TODO(lpetrut): decide if we actually need those type
        // conversions. Those should be the same values.
        // LocalInt1 is not covered here. WHP defines it as "9" while
        // the redirection table entries allocate just 3 bits for the
        // delivery mode.
        let whp_interrupt_type = match delivery_mode {
            DeliveryMode::Fixed => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeFixed,
            DeliveryMode::Lowest => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeLowestPriority,
            DeliveryMode::NMI => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeNmi,
            DeliveryMode::Init => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeInit,
            DeliveryMode::Startup => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeSipi,
            DeliveryMode::External => WHV_INTERRUPT_TYPE::WHvX64InterruptTypeFixed,
            _ => {
                warn!("Dropping interrupt. Unsupported delivery mode: {:?}",
                       delivery_mode);
                return;
            }
        };

        let whp_dest_mode = match dest_mode {
            DestinationMode::Logical => WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModeLogical,
            DestinationMode::Physical => WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical
        };

        interrupt.set_TriggerMode(whp_trigger_mode as UINT64);
        interrupt.set_InterruptType(whp_interrupt_type as UINT64);
        interrupt.set_DestinationMode(whp_dest_mode as UINT64);
        interrupt.Destination = dest as UINT32;
        interrupt.Vector = vector as UINT32;

        self.partition.request_interrupt(&mut interrupt).unwrap();
    }
}
