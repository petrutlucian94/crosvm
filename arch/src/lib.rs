// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate sys_util;
extern crate vm_memory;
extern crate whp;

use std::error::Error as StdError;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::Arc;

use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap, GuestMemoryError};

use devices::virtio::VirtioDevice;
use devices::split_irqchip_common::InterruptController;
use devices::{
    Bus, BusError, PciDevice, PciDeviceError, PciInterruptPin, PciRoot,
    Serial, Ioapic, WhpInterruptController
};
use whp::{IoeventAddress, WhpManager, WhpVirtualProcessor, Vm};
use resources::SystemAllocator;
use sync::Mutex;
use sys_util::{EventFd};

#[cfg(unix)]
pub type InterruptEvent = sys_util::EventFd;

#[cfg(windows)]
pub use devices::InterruptEvent;


/// Holds the pieces needed to build a VM. Passed to `build_vm` in the `LinuxArch` trait below to
/// create a `RunnableLinuxVm`.
pub struct VmComponents {
    pub memory_size: u64,
    pub vcpu_count: u32,
    pub vcpu_affinity: Vec<usize>,
    pub kernel_image: File,
    pub initrd_image: Option<File>,
    pub extra_kernel_params: Vec<String>,
}

/// Holds the elements needed to run a Linux VM. Created by `build_vm`.
pub struct RunnableLinuxVm {
    pub vm: Vm,
    pub whp: WhpManager,
    pub resources: SystemAllocator,
    pub stdio_serial: Arc<Mutex<Serial>>,
    pub exit_evt: EventFd,
    pub vcpus: Vec<WhpVirtualProcessor>,
    pub vcpu_affinity: Vec<usize>,
    pub irq_chip: Arc<Mutex<Ioapic<WhpInterruptController>>>,
    pub io_bus: Bus,
    pub mmio_bus: Bus,
}

/// The device and optional jail.
/// TODO(lpetrut): no longer using jails, this wrapper can be dropped.
pub struct VirtioDeviceStub {
    pub dev: Box<dyn VirtioDevice>,
}

/// Trait which is implemented for each Linux Architecture in order to
/// set up the memory, cpus, and system devices and to boot the kernel.
pub trait LinuxArch {
    type Error: StdError;

    /// Takes `VmComponents` and generates a `RunnableLinuxVm`.
    ///
    /// # Arguments
    ///
    /// * `components` - Parts to use to build the VM.
    /// * `split_irqchip` - whether to use a split IRQ chip (i.e. userspace PIT/PIC/IOAPIC)
    /// * `create_devices` - Function to generate a list of devices.
    fn build_vm<F, E>(
        components: VmComponents,
        split_irqchip: bool,
        create_devices: F,
    ) -> Result<RunnableLinuxVm, Self::Error>
    where
        F: FnOnce(&GuestMemoryMmap, &EventFd) -> Result<Vec<(Box<dyn PciDevice>)>, E>,
        E: StdError + 'static;
}

/// Errors for device manager.
#[derive(Debug)]
pub enum DeviceRegistrationError {
    /// Could not allocate IO space for the device.
    AllocateIoAddrs(PciDeviceError),
    /// Could not allocate device address space for the device.
    AllocateDeviceAddrs(PciDeviceError),
    /// Could not allocate an IRQ number.
    AllocateIrq,
    /// Could not create the mmio device to wrap a VirtioDevice.
    CreateMmioDevice(sys_util::Error),
    /// Could not create an event fd.
    EventFdCreate(sys_util::Error),
    /// Could not add a device to the mmio bus.
    MmioInsert(BusError),
    /// Failed to register ioevent with VM.
    RegisterIoevent(sys_util::Error),
    /// Failed to register irq eventfd with VM.
    RegisterIrqfd(sys_util::Error),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// No more MMIO space available.
    AddrsExhausted,
    /// Could not register PCI device capabilities.
    RegisterDeviceCapabilities(PciDeviceError),
}

impl Display for DeviceRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DeviceRegistrationError::*;

        match self {
            AllocateIoAddrs(e) => write!(f, "Allocating IO addresses: {}", e),
            AllocateDeviceAddrs(e) => write!(f, "Allocating device addresses: {}", e),
            AllocateIrq => write!(f, "Allocating IRQ number"),
            CreateMmioDevice(e) => write!(f, "failed to create mmio device: {}", e),
            Cmdline(e) => write!(f, "unable to add device to kernel command line: {}", e),
            EventFdCreate(e) => write!(f, "failed to create eventfd: {}", e),
            MmioInsert(e) => write!(f, "failed to add to mmio bus: {}", e),
            RegisterIoevent(e) => write!(f, "failed to register ioevent to VM: {}", e),
            RegisterIrqfd(e) => write!(f, "failed to register irq eventfd to VM: {}", e),
            IrqsExhausted => write!(f, "no more IRQs are available"),
            AddrsExhausted => write!(f, "no more addresses are available"),
            RegisterDeviceCapabilities(e) => {
                write!(f, "could not register PCI device capabilities: {}", e)
            }
        }
    }
}

/// Creates a root PCI device for use by this Vm.
// TODO(lpetrut): We shouldn't require WhpVirtualProcessor.
// In order to be able to share those crates with rust-vmm,
// we should use vmm-vcpu traits.
pub fn generate_pci_root(
    devices: Vec<(Box<dyn PciDevice>)>,
    mmio_bus: &mut Bus,
    resources: &mut SystemAllocator,
    vm: &mut Vm,
    vcpus: &mut [WhpVirtualProcessor],
    io_apic: Arc<Mutex<Ioapic<WhpInterruptController>>>
) -> Result<(PciRoot, Vec<(u32, PciInterruptPin)>), DeviceRegistrationError>
{
    let mut root = PciRoot::new();
    let mut pci_irqs = Vec::new();
    for (dev_idx, mut device) in devices.into_iter().enumerate() {
        // Only support one bus.
        device.assign_bus_dev(0, dev_idx as u8);

        let irq_resample_fd = EventFd::new().map_err(DeviceRegistrationError::EventFdCreate)?;
        let irq_num = resources
            .allocate_irq()
            .ok_or(DeviceRegistrationError::AllocateIrq)? as u32;
        let pci_irq_pin = match dev_idx % 4 {
            0 => PciInterruptPin::IntA,
            1 => PciInterruptPin::IntB,
            2 => PciInterruptPin::IntC,
            3 => PciInterruptPin::IntD,
            _ => panic!(""), // Obviously not possible, but the compiler is not smart enough.
        };
        // TODO(lpetrut): properly handle the eventfd so that we don't break kvm.
        // WHP only cares about the resample event, so we're passing a stub for
        // the irq fd.
        vm.register_irqfd_resample(
            &mut EventFd::new().unwrap(), &irq_resample_fd, irq_num,
            vcpus)
            .map_err(DeviceRegistrationError::RegisterIrqfd)?;
        let mut irqfd = InterruptEvent::new(irq_num, io_apic.clone()).map_err(DeviceRegistrationError::EventFdCreate)?;
        device.assign_irq(irqfd, irq_resample_fd, irq_num, pci_irq_pin);
        pci_irqs.push((dev_idx as u32, pci_irq_pin));

        let ranges = device
            .allocate_io_bars(resources)
            .map_err(DeviceRegistrationError::AllocateIoAddrs)?;
        let device_ranges = device
            .allocate_device_bars(resources)
            .map_err(DeviceRegistrationError::AllocateDeviceAddrs)?;
        device
            .register_device_capabilities()
            .map_err(DeviceRegistrationError::RegisterDeviceCapabilities)?;
        for (event, addr, datamatch) in device.ioeventfds() {
            let io_addr = IoeventAddress::Mmio(addr);
            vm.register_ioevent(&event, io_addr, datamatch, vcpus)
                .map_err(DeviceRegistrationError::RegisterIoevent)?;
        }

        let arced_dev = Arc::new(Mutex::new(device));
        root.add_device(arced_dev.clone());
        for range in &ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }

        for range in &device_ranges {
            mmio_bus
                .insert(arced_dev.clone(), range.0, range.1, true)
                .map_err(DeviceRegistrationError::MmioInsert)?;
        }
    }
    Ok((root, pci_irqs))
}

/// Errors for image loading.
#[derive(Debug)]
pub enum LoadImageError {
    Seek(io::Error),
    ImageSizeTooLarge(u64),
    ReadToMemory(GuestMemoryError),
}

impl Display for LoadImageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::LoadImageError::*;

        match self {
            Seek(e) => write!(f, "Seek failed: {}", e),
            ImageSizeTooLarge(size) => write!(f, "Image size too large: {}", size),
            ReadToMemory(e) => write!(f, "Reading image into memory failed: {}", e),
        }
    }
}

/// Load an image from a file into guest memory.
///
/// # Arguments
///
/// * `guest_mem` - The memory to be used by the guest.
/// * `guest_addr` - The starting address to load the image in the guest memory.
/// * `max_size` - The amount of space in bytes available in the guest memory for the image.
/// * `image` - The file containing the image to be loaded.
///
/// The size in bytes of the loaded image is returned.
pub fn load_image<F>(
    guest_mem: &GuestMemoryMmap,
    image: &mut F,
    guest_addr: GuestAddress,
    max_size: u64,
) -> Result<usize, LoadImageError>
where
    F: Read + Seek,
{
    let size = image.seek(SeekFrom::End(0)).map_err(LoadImageError::Seek)?;

    if size > usize::max_value() as u64 || size > max_size {
        return Err(LoadImageError::ImageSizeTooLarge(size));
    }

    // This is safe due to the bounds check above.
    let size = size as usize;

    image
        .seek(SeekFrom::Start(0))
        .map_err(LoadImageError::Seek)?;

    guest_mem
        .read_exact_from(guest_addr, image, size)
        .map_err(LoadImageError::ReadToMemory)?;

    Ok(size)
}
