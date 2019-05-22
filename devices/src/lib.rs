// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Emulates virtual and hardware devices.

extern crate chrono;
extern crate vm_memory;

mod bus;
mod cmos;
mod i8042;
mod ioapic;
mod pci;
mod pic;
mod pit;
pub mod pl030;
#[macro_use]
mod register_space;
mod serial;
pub mod split_irqchip_common;
mod utils;
pub mod virtio;

pub use self::bus::Error as BusError;
pub use self::bus::{Bus, BusDevice, BusRange};
pub use self::cmos::Cmos;
pub use self::i8042::I8042Device;
pub use self::ioapic::Ioapic;
pub use self::pci::{
    PciConfigIo, PciConfigMmio, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
};
pub use self::pic::Pic;
pub use self::pit::{Pit, PitError};
pub use self::pl030::Pl030;
pub use self::serial::Serial;
pub use self::virtio::VirtioPciDevice;
