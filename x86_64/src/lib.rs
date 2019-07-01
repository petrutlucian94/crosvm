// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

extern crate vm_memory;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
mod bootparam;
// Bindgen didn't implement copy for boot_params because edid_info contains an array with len > 32.
impl Copy for bootparam::edid_info {}
impl Clone for bootparam::edid_info {
    fn clone(&self) -> Self {
        *self
    }
}
impl Copy for bootparam::boot_params {}
impl Clone for bootparam::boot_params {
    fn clone(&self) -> Self {
        *self
    }
}
// boot_params is just a series of ints, it is safe to initialize it.
unsafe impl vm_memory::ByteValued for bootparam::boot_params {}

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
mod msr_index;

#[allow(dead_code)]
#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(clippy::all)]
mod mpspec;
// These mpspec types are only data, reading them from data is a safe initialization.
unsafe impl vm_memory::ByteValued for mpspec::mpc_bus {}
unsafe impl vm_memory::ByteValued for mpspec::mpc_cpu {}
unsafe impl vm_memory::ByteValued for mpspec::mpc_intsrc {}
unsafe impl vm_memory::ByteValued for mpspec::mpc_ioapic {}
unsafe impl vm_memory::ByteValued for mpspec::mpc_table {}
unsafe impl vm_memory::ByteValued for mpspec::mpc_lintsrc {}
unsafe impl vm_memory::ByteValued for mpspec::mpf_intel {}

mod cpuid;
mod gdt;
mod interrupts;
mod mptable;
mod regs;
mod smbios;

use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, stdout};
use std::mem;
use std::sync::Arc;

use vm_memory::{GuestAddress, GuestMemory, Address, Bytes, GuestMemoryMmap, GuestMemoryError};

use vmm_vcpu::vcpu::Vcpu;

use crate::bootparam::boot_params;
use crate::bootparam::E820_RAM;
use arch::{RunnableLinuxVm, VmComponents};
use devices::{PciConfigIo, PciDevice, PciInterruptPin, InterruptEvent,
              Ioapic, WhpInterruptController};

#[cfg(windows)]
use whp::*;
#[cfg(windows)]
use libwhp::VirtualProcessor;

use remain::sorted;
use resources::SystemAllocator;
use sync::Mutex;
use sys_util::{EventFd, Clock};

#[sorted]
#[derive(Debug)]
pub enum Error {
    CloneEventFd(sys_util::Error),
    Cmdline(kernel_cmdline::Error),
    ConfigureSystem,
    CreateDevices(Box<dyn StdError>),
    CreateEventFd(sys_util::Error),
    CreateIrqChip(sys_util::Error),
    CreateKvm(sys_util::Error),
    CreatePciRoot(arch::DeviceRegistrationError),
    CreatePit(sys_util::Error),
    CreatePitDevice(devices::PitError),
    CreateSocket(io::Error),
    CreateVcpu(sys_util::Error),
    CreateVm(sys_util::Error),
    E820Configuration,
    KernelOffsetPastEnd,
    LoadCmdline(kernel_loader::Error),
    LoadInitrd(arch::LoadImageError),
    LoadKernel(kernel_loader::Error),
    RegisterIrqfd(sys_util::Error),
    RegisterVsock(arch::DeviceRegistrationError),
    SetLint(interrupts::Error),
    SetTssAddr(sys_util::Error),
    SetupCpuid(io::Error),
    SetupFpu(regs::Error),
    SetupGuestMemory(GuestMemoryError),
    SetupMptable(mptable::Error),
    SetupMsrs(regs::Error),
    SetupRegs(regs::Error),
    SetupSmbios(smbios::Error),
    SetupSregs(regs::Error),
    ZeroPagePastRamEnd,
    ZeroPageSetup,
}

impl Display for Error {
    #[remain::check]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Error::*;

        #[sorted]
        match self {
            CloneEventFd(e) => write!(f, "unable to clone an EventFd: {}", e),
            Cmdline(e) => write!(f, "the given kernel command line was invalid: {}", e),
            ConfigureSystem => write!(f, "error configuring the system"),
            CreateDevices(e) => write!(f, "error creating devices: {}", e),
            CreateEventFd(e) => write!(f, "unable to make an EventFd: {}", e),
            CreateIrqChip(e) => write!(f, "failed to create irq chip: {}", e),
            CreateKvm(e) => write!(f, "failed to open /dev/kvm: {}", e),
            CreatePciRoot(e) => write!(f, "failed to create a PCI root hub: {}", e),
            CreatePit(e) => write!(f, "unable to create PIT: {}", e),
            CreatePitDevice(e) => write!(f, "unable to make PIT device: {}", e),
            CreateSocket(e) => write!(f, "failed to create socket: {}", e),
            CreateVcpu(e) => write!(f, "failed to create VCPU: {}", e),
            CreateVm(e) => write!(f, "failed to create VM: {}", e),
            E820Configuration => write!(f, "invalid e820 setup params"),
            KernelOffsetPastEnd => write!(f, "the kernel extends past the end of RAM"),
            LoadCmdline(e) => write!(f, "error loading command line: {}", e),
            LoadInitrd(e) => write!(f, "error loading initrd: {}", e),
            LoadKernel(e) => write!(f, "error loading Kernel: {}", e),
            RegisterIrqfd(e) => write!(f, "error registering an IrqFd: {}", e),
            RegisterVsock(e) => write!(f, "error registering virtual socket device: {}", e),
            SetLint(e) => write!(f, "failed to set interrupts: {}", e),
            SetTssAddr(e) => write!(f, "failed to set tss addr: {}", e),
            SetupCpuid(e) => write!(f, "failed to set up cpuid: {}", e),
            SetupFpu(e) => write!(f, "failed to set up FPU: {}", e),
            SetupGuestMemory(e) => write!(f, "failed to set up guest memory: {}", e),
            SetupMptable(e) => write!(f, "failed to set up mptable: {}", e),
            SetupMsrs(e) => write!(f, "failed to set up MSRs: {}", e),
            SetupRegs(e) => write!(f, "failed to set up registers: {}", e),
            SetupSmbios(e) => write!(f, "failed to set up SMBIOS: {}", e),
            SetupSregs(e) => write!(f, "failed to set up sregs: {}", e),
            ZeroPagePastRamEnd => write!(f, "the zero page extends past the end of guest_mem"),
            ZeroPageSetup => write!(f, "error writing the zero page of guest memory"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::error::Error for Error {}

pub struct X8664arch;

const BOOT_STACK_POINTER: u64 = 0x8000;
const MEM_32BIT_GAP_SIZE: u64 = (768 << 20);
const FIRST_ADDR_PAST_32BITS: u64 = (1 << 32);
const KERNEL_64BIT_ENTRY_OFFSET: u64 = 0x200;
const ZERO_PAGE_OFFSET: u64 = 0x7000;

const KERNEL_START_OFFSET: u64 = 0x200000;
const CMDLINE_OFFSET: u64 = 0x20000;
const CMDLINE_MAX_SIZE: u64 = KERNEL_START_OFFSET - CMDLINE_OFFSET;
const X86_64_IRQ_BASE: u32 = 5;

fn configure_system(
    guest_mem: &GuestMemoryMmap,
    _mem_size: u64,
    kernel_addr: GuestAddress,
    cmdline_addr: GuestAddress,
    cmdline_size: usize,
    num_cpus: u8,
    pci_irqs: Vec<(u32, PciInterruptPin)>,
    initrd: Option<(GuestAddress, usize)>,
) -> Result<()> {
    const EBDA_START: u64 = 0x0009fc00;
    const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
    const KERNEL_HDR_MAGIC: u32 = 0x53726448;
    const KERNEL_LOADER_OTHER: u8 = 0xff;
    const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x1000000; // Must be non-zero.
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);

    // Note that this puts the mptable at 0x0 in guest physical memory.
    mptable::setup_mptable(guest_mem, num_cpus, pci_irqs).map_err(Error::SetupMptable)?;

    smbios::setup_smbios(guest_mem).map_err(Error::SetupSmbios)?;

    let mut params: boot_params = Default::default();

    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;
    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.cmd_line_ptr = cmdline_addr.raw_value() as u32;
    params.hdr.cmdline_size = cmdline_size as u32;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    if let Some((initrd_addr, initrd_size)) = initrd {
        params.hdr.ramdisk_image = initrd_addr.raw_value() as u32;
        params.hdr.ramdisk_size = initrd_size as u32;
    }

    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    let mem_end = guest_mem.end_addr();
    if mem_end < end_32bit_gap_start {
        add_e820_entry(
            &mut params,
            kernel_addr.raw_value() as u64,
            mem_end.checked_offset_from(kernel_addr).unwrap(),
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            kernel_addr.raw_value() as u64,
            end_32bit_gap_start.checked_offset_from(kernel_addr).unwrap(),
            E820_RAM,
        )?;
        if mem_end > first_addr_past_32bits {
            add_e820_entry(
                &mut params,
                first_addr_past_32bits.raw_value() as u64,
                mem_end.checked_offset_from(first_addr_past_32bits).unwrap(),
                E820_RAM,
            )?;
        }
    }

    let zero_page_addr = GuestAddress(ZERO_PAGE_OFFSET);
    guest_mem
        .checked_offset(zero_page_addr, mem::size_of::<boot_params>())
        .ok_or(Error::ZeroPagePastRamEnd)?;
    guest_mem
        .write_obj(params, zero_page_addr)
        .map_err(|_| Error::ZeroPageSetup)?;
    Ok(())
}

/// Add an e820 region to the e820 map.
/// Returns Ok(()) if successful, or an error if there is no space left in the map.
fn add_e820_entry(params: &mut boot_params, addr: u64, size: u64, mem_type: u32) -> Result<()> {
    if params.e820_entries >= params.e820_map.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_map[params.e820_entries as usize].addr = addr;
    params.e820_map[params.e820_entries as usize].size = size;
    params.e820_map[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

/// Returns a Vec of the valid memory addresses.
/// These should be used to configure the GuestMemoryMmap structure for the platfrom.
/// For x86_64 all addresses are valid from the start of the kenel except a
/// carve out at the end of 32bit address space.
fn arch_memory_regions(size: u64) -> Vec<(GuestAddress, usize)> {
    let mem_end = GuestAddress(size);
    let first_addr_past_32bits = GuestAddress(FIRST_ADDR_PAST_32BITS);
    let end_32bit_gap_start = GuestAddress(FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE);

    let mut regions = Vec::new();
    if mem_end < end_32bit_gap_start {
        regions.push((GuestAddress(0), size as usize));
    } else {
        regions.push((GuestAddress(0), end_32bit_gap_start.raw_value() as usize));
        if mem_end > first_addr_past_32bits {
            regions.push((
                first_addr_past_32bits,
                mem_end.checked_offset_from(first_addr_past_32bits).unwrap() as usize,
            ));
        }
    }

    regions
}

impl arch::LinuxArch for X8664arch {
    type Error = Error;

    fn build_vm<F, E>(
        mut components: VmComponents,
        split_irqchip: bool,
        create_devices: F,
    ) -> Result<RunnableLinuxVm>
    where
        F: FnOnce(
            &GuestMemoryMmap,
            &EventFd,
        ) -> std::result::Result<Vec<Box<dyn PciDevice>>, E>,
        E: StdError + 'static,
    {
        let vcpu_count = components.vcpu_count;
        let mut resources =
            Self::get_resource_allocator(components.memory_size);
        let mem = Self::setup_memory(components.memory_size)?;
        let whp = WhpManager::new().map_err(Error::CreateKvm)?;
        let mut vm = Self::create_vm(&whp, vcpu_count as usize,
                                     split_irqchip, mem.clone())?;
        let mut vcpus = Vec::with_capacity(vcpu_count as usize);

        for cpu_id in 0..vcpu_count {
            let vcpu = WhpVirtualProcessor::new(cpu_id, &whp, &vm).map_err(Error::CreateVcpu)?;
            Self::configure_vcpu(
                vm.get_memory(),
                &whp,
                &vm,
                &vcpu,
                cpu_id as u64,
                vcpu_count as u64,
            )?;
            vcpus.push(vcpu);
        }

        let vcpu_affinity = components.vcpu_affinity;

        // let irq_chip = Self::create_irq_chip(&vm)?;
        let mut cmdline = Self::get_base_linux_cmdline();

        let mut mmio_bus = devices::Bus::new();

        let exit_evt = EventFd::new().map_err(Error::CreateEventFd)?;

        let mut io_apic = devices::Ioapic::new();
        let int_ctrl = WhpInterruptController::new(vm.get_partition()).unwrap();
        io_apic.set_interrupt_controller(int_ctrl);

        let io_apic = Arc::new(Mutex::new(io_apic));
        mmio_bus.insert(io_apic.clone(), 0xfec00000, 0x100, false);

        let pci_devices =
            create_devices(&mem, &exit_evt).map_err(|e| Error::CreateDevices(Box::new(e)))?;
        let (pci, pci_irqs) =
            arch::generate_pci_root(
                pci_devices, &mut mmio_bus, &mut resources,
                &mut vm, &mut vcpus, io_apic.clone())
                .map_err(Error::CreatePciRoot)?;
        let pci_bus = Arc::new(Mutex::new(PciConfigIo::new(pci)));

        let (io_bus, stdio_serial) = Self::setup_io_bus(
            &mut vm,
            split_irqchip,
            exit_evt.try_clone().map_err(Error::CloneEventFd)?,
            Some(pci_bus.clone()),
            io_apic.clone(),
        )?;

        for param in components.extra_kernel_params {
            cmdline.insert_str(&param).map_err(Error::Cmdline)?;
        }

        // separate out load_kernel from other setup to get a specific error for
        // kernel loading
        let kernel_end = Self::load_kernel(&mem, &mut components.kernel_image)?;

        let irq_chip = io_apic;

        Self::setup_system_memory(
            &mem,
            components.memory_size,
            vcpu_count,
            &CString::new(cmdline).unwrap(),
            components.initrd_image,
            pci_irqs,
            kernel_end,
        )?;

        Ok(RunnableLinuxVm {
            vm,
            whp,
            resources,
            stdio_serial,
            exit_evt,
            vcpus,
            vcpu_affinity,
            irq_chip,
            io_bus,
            mmio_bus,
        })
    }
}

impl X8664arch {
    /// Loads the kernel from an open file.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `kernel_image` - the File object for the specified kernel.
    fn load_kernel(mem: &GuestMemoryMmap, mut kernel_image: &mut File) -> Result<u64> {
        kernel_loader::load_kernel(mem, GuestAddress(KERNEL_START_OFFSET), &mut kernel_image)
            .map_err(Error::LoadKernel)
    }

    /// Configures the system memory space should be called once per vm before
    /// starting vcpu threads.
    ///
    /// # Arguments
    ///
    /// * `mem` - The memory to be used by the guest.
    /// * `vcpu_count` - Number of virtual CPUs the guest will have.
    /// * `cmdline` - the kernel commandline
    /// * `initrd_file` - an initial ramdisk image
    fn setup_system_memory(
        mem: &GuestMemoryMmap,
        mem_size: u64,
        vcpu_count: u32,
        cmdline: &CStr,
        initrd_file: Option<File>,
        pci_irqs: Vec<(u32, PciInterruptPin)>,
        kernel_end: u64,
    ) -> Result<()> {
        kernel_loader::load_cmdline(mem, GuestAddress(CMDLINE_OFFSET), cmdline)
            .map_err(Error::LoadCmdline)?;

        // Track the first free address after the kernel - this is where extra
        // data like the device tree blob and initrd will be loaded.
        let mut free_addr = kernel_end;

        let initrd = match initrd_file {
            Some(mut initrd_file) => {
                let initrd_start = free_addr;
                let initrd_max_size = mem_size - initrd_start;
                let initrd_size = arch::load_image(
                    mem,
                    &mut initrd_file,
                    GuestAddress(initrd_start),
                    initrd_max_size,
                )
                .map_err(Error::LoadInitrd)?;
                Some((GuestAddress(initrd_start), initrd_size))
            }
            None => None,
        };

        configure_system(
            mem,
            mem_size,
            GuestAddress(KERNEL_START_OFFSET),
            GuestAddress(CMDLINE_OFFSET),
            cmdline.to_bytes().len() + 1,
            vcpu_count as u8,
            pci_irqs,
            initrd,
        )?;
        Ok(())
    }

    /// Creates a new VM object and initializes architecture specific devices
    ///
    /// # Arguments
    ///
    /// * `whp` - The WhpManager object
    /// * `split_irqchip` - Whether to use a split IRQ chip.
    /// * `mem` - The memory to be used by the guest.
    fn create_vm(whp: &WhpManager, vcpu_count: usize,
                 split_irqchip: bool, mem: GuestMemoryMmap) -> Result<Vm> {
        let vm = Vm::new(&whp, mem, vcpu_count, !split_irqchip).map_err(Error::CreateVm)?;
        let tss_addr = GuestAddress(0xfffbd000);
        // vm.set_tss_addr(tss_addr).map_err(Error::SetTssAddr)?;
        // if !split_irqchip {
        //     vm.create_pit().map_err(Error::CreatePit)?;
        //     vm.create_irq_chip().map_err(Error::CreateIrqChip)?;
        // }
        Ok(vm)
    }

    /// This creates a GuestMemoryMmap object for this VM
    ///
    /// * `mem_size` - Desired physical memory size in bytes for this VM
    fn setup_memory(mem_size: u64) -> Result<GuestMemoryMmap> {
        let arch_mem_regions = arch_memory_regions(mem_size);
        let mem = GuestMemoryMmap::new(&arch_mem_regions).unwrap();
        Ok(mem)
    }

    /// The creates the interrupt controller device and optionally returns the fd for it.
    /// Some architectures may not have a separate descriptor for the interrupt
    /// controller, so they would return None even on success.
    ///
    /// # Arguments
    ///
    /// * `vm` - the vm object
    fn create_irq_chip(_vm: &whp::Vm) -> Result<Option<File>> {
        // Unfortunately X86 and ARM have to do this in completely different order
        // X86 needs to create the irq chip before creating cpus and
        // ARM needs to do it afterwards.
        Ok(None)
    }

    /// This returns the first page frame number for use by the balloon driver.
    ///
    /// # Arguments
    ///
    /// * `mem_size` - the size in bytes of physical ram for the guest
    fn get_base_dev_pfn(mem_size: u64) -> u64 {
        // Put device memory at a 2MB boundary after physical memory or 4gb, whichever is greater.
        const MB: u64 = 1024 * 1024;
        const GB: u64 = 1024 * MB;
        let mem_size_round_2mb = (mem_size + 2 * MB - 1) / (2 * MB) * (2 * MB);
        std::cmp::max(mem_size_round_2mb, 4 * GB) / sys_util::pagesize() as u64
    }

    /// This returns a minimal kernel command for this architecture
    fn get_base_linux_cmdline() -> kernel_cmdline::Cmdline {
        let mut cmdline = kernel_cmdline::Cmdline::new(CMDLINE_MAX_SIZE as usize);
        cmdline
            .insert_str("console=ttyS0 noacpi reboot=k panic=-1")
            .unwrap();
        cmdline
    }

    /// Returns a system resource allocator.
    fn get_resource_allocator(mem_size: u64) -> SystemAllocator {
        const MMIO_BASE: u64 = 0xe0000000;
        let device_addr_start = Self::get_base_dev_pfn(mem_size) * sys_util::pagesize() as u64;
        SystemAllocator::builder()
            .add_io_addresses(0xc000, 0x10000)
            .add_mmio_addresses(MMIO_BASE, 0x100000)
            .add_device_addresses(device_addr_start, u64::max_value() - device_addr_start)
            .create_allocator(X86_64_IRQ_BASE)
            .unwrap()
    }

    /// Sets up the IO bus for this platform
    ///
    /// # Arguments
    ///
    /// * - `vm` the vm object
    /// * - `split_irqchip`: whether to use a split IRQ chip (i.e. userspace PIT/PIC/IOAPIC)
    /// * - `exit_evt` - the event fd object which should receive exit events
    fn setup_io_bus(
        vm: &mut Vm,
        split_irqchip: bool,
        exit_evt: EventFd,
        pci: Option<Arc<Mutex<devices::PciConfigIo>>>,
        io_apic: Arc<Mutex<Ioapic<WhpInterruptController>>>,
    ) -> Result<(devices::Bus, Arc<Mutex<devices::Serial>>)> {
        struct NoDevice;
        impl devices::BusDevice for NoDevice {
            fn debug_label(&self) -> String {
                "no device".to_owned()
            }
        }

        let mut io_bus = devices::Bus::new();

        let mut com_evt_1_3 = InterruptEvent::new(4, io_apic.clone()).map_err(Error::CreateEventFd)?;
        let mut com_evt_2_4 = InterruptEvent::new(4, io_apic.clone()).map_err(Error::CreateEventFd)?;

        // TODO(lpetrut): do this for kvm.
        // vm.register_irqfd(&mut com_evt_1_3, 4)
        //     .map_err(Error::RegisterIrqfd)?;
        // vm.register_irqfd(&mut com_evt_2_4, 3)
        //     .map_err(Error::RegisterIrqfd)?;

        let stdio_serial = Arc::new(Mutex::new(devices::Serial::new_out(
            com_evt_1_3.try_clone().map_err(Error::CloneEventFd)?,
            Box::new(stdout()),
        )));
        let nul_device = Arc::new(Mutex::new(NoDevice));
        io_bus
            .insert(stdio_serial.clone(), 0x3f8, 0x8, false)
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(
                    com_evt_2_4.try_clone().map_err(Error::CloneEventFd)?,
                ))),
                0x2f8,
                0x8,
                false,
            )
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(
                    com_evt_1_3.try_clone().map_err(Error::CloneEventFd)?,
                ))),
                0x3e8,
                0x8,
                false,
            )
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::Serial::new_sink(
                    com_evt_2_4.try_clone().map_err(Error::CloneEventFd)?,
                ))),
                0x2e8,
                0x8,
                false,
            )
            .unwrap();
        io_bus
            .insert(Arc::new(Mutex::new(devices::Cmos::new())), 0x70, 0x2, false)
            .unwrap();
        io_bus
            .insert(
                Arc::new(Mutex::new(devices::I8042Device::new(
                    exit_evt.try_clone().map_err(Error::CloneEventFd)?,
                ))),
                0x061,
                0x4,
                false,
            )
            .unwrap();

        // TODO(lpetrut): find out if WHP can emulate a timer for us.
        let mut pit_evt = InterruptEvent::new(0, io_apic.clone()).map_err(Error::CreateEventFd)?;
        // vm.register_irqfd(&mut pit_evt, 0)
        //     .map_err(Error::RegisterIrqfd)?;
        let pit = Arc::new(Mutex::new(
            devices::Pit::new(
                pit_evt.try_clone().map_err(Error::CloneEventFd)?,
                Arc::new(Mutex::new(Clock::new())),
            )
            .map_err(Error::CreatePitDevice)?,
        ));
        // We won't use the speaker port here, avoiding an overlap
        // with i8042.
        io_bus.insert(pit.clone(), 0x040, 0x8, false).unwrap();

        io_bus
            .insert(nul_device.clone(), 0x0ed, 0x1, false)
            .unwrap(); // most likely this one does nothing
        io_bus
            .insert(nul_device.clone(), 0x0f0, 0x2, false)
            .unwrap(); // ignore fpu

        if let Some(pci_root) = pci {
            io_bus.insert(pci_root, 0xcf8, 0x8, false).unwrap();
        } else {
            // ignore pci.
            io_bus
                .insert(nul_device.clone(), 0xcf8, 0x8, false)
                .unwrap();
        }

        Ok((io_bus, stdio_serial))
    }

    /// Configures the vcpu and should be called once per vcpu from the vcpu's thread.
    ///
    /// # Arguments
    ///
    /// * `guest_mem` - The memory to be used by the guest.
    /// * `kernel_load_offset` - Offset in bytes from `guest_mem` at which the
    ///                          kernel starts.
    /// * `whp` - The WhpManager object
    /// * `vm` - The VM object associated with this VCPU.
    /// * `vcpu` - The VCPU object to configure.
    /// * `cpu_id` - The id of the given `vcpu`.
    /// * `num_cpus` - Number of virtual CPUs the guest will have.
    fn configure_vcpu<T: Vcpu>(
        guest_mem: &GuestMemoryMmap,
        whp: &WhpManager,
        _vm: &Vm,
        vcpu: &T,
        cpu_id: u64,
        num_cpus: u64,
    ) -> Result<()> {
        let kernel_load_addr = GuestAddress(KERNEL_START_OFFSET);
        //cpuid::setup_cpuid(whp, vcpu, cpu_id, num_cpus).map_err(Error::SetupCpuid)?;
        // TODO: cpuid setup. atm cpuid calls won't generate exits.
        // cpuid::setup_cpuid(whp, vcpu, cpu_id, num_cpus).map_err(Error::SetupCpuid)?;
        regs::setup_msrs(vcpu).map_err(Error::SetupMsrs)?;
        let kernel_end = guest_mem
            .checked_offset(kernel_load_addr, KERNEL_64BIT_ENTRY_OFFSET as usize)
            .ok_or(Error::KernelOffsetPastEnd)?;
        regs::setup_regs(
            vcpu,
            (kernel_end).raw_value() as u64,
            BOOT_STACK_POINTER as u64,
            ZERO_PAGE_OFFSET as u64,
        )
        .map_err(Error::SetupRegs)?;
        regs::setup_fpu(vcpu).map_err(Error::SetupFpu)?;
        regs::setup_sregs(guest_mem, vcpu).map_err(Error::SetupSregs)?;
        interrupts::set_lint(vcpu).map_err(Error::SetLint)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regions_lt_4gb() {
        let regions = arch_memory_regions(1u64 << 29);
        assert_eq!(1, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(1u64 << 29, regions[0].1);
    }

    #[test]
    fn regions_gt_4gb() {
        let regions = arch_memory_regions((1u64 << 32) + 0x8000);
        assert_eq!(2, regions.len());
        assert_eq!(GuestAddress(0), regions[0].0);
        assert_eq!(GuestAddress(1u64 << 32), regions[1].0);
    }
}
