// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.

extern crate vm_memory;

mod cap;

use std::cmp::{Ordering};
use std::collections::{BinaryHeap, HashMap};
use std::fs::File;
use std::mem::size_of;
use std::os::raw::*;

use vm_memory::{GuestAddress, GuestMemoryMmap, MmapRegion};

use kvm_sys::*;


use sys_util::{
    pagesize, Error, EventFd, Result,
};

pub use crate::cap::*;


// Returns a `Vec<T>` with a size in ytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

// unsafe fn set_user_memory_region<F: AsRawFd>(
//     fd: &F,
//     slot: u32,
//     read_only: bool,
//     log_dirty_pages: bool,
//     guest_addr: u64,
//     memory_size: u64,
//     userspace_addr: u64,
// ) -> Result<()> {
//     panic!("Not Implemented")
// }

/// Helper function to determine the size in bytes of a dirty log bitmap for the given memory region
/// size.
///
/// # Arguments
///
/// * `size` - Number of bytes in the memory region being queried.
pub fn dirty_log_bitmap_size(size: usize) -> usize {
    let page_size = pagesize();
    (((size + page_size - 1) / page_size) + 7) / 8
}

/// A wrapper around opening and using `/dev/kvm`.
///
/// Useful for querying extensions and basic values from the KVM backend. A `Kvm` is required to
/// create a `Vm` object.
pub struct Kvm {
    kvm: File,
}

impl Kvm {
    /// Opens `/dev/kvm/` and returns a Kvm object on success.
    pub fn new() -> Result<Kvm> {
        panic!("Not Implemented")
    }

    /// Checks if a particular `Cap` is available.
    pub fn check_extension(&self, c: Cap) -> bool {
        panic!("Not Implemented")
    }

    /// Gets the size of the mmap required to use vcpu's `kvm_run` structure.
    pub fn get_vcpu_mmap_size(&self) -> Result<usize> {
        panic!("Not Implemented")
    }

    /// Gets the recommended maximum number of VCPUs per VM.
    pub fn get_nr_vcpus(&self) -> u32 {
        panic!("Not Implemented")
    }

    /// X86 specific call to get the system supported CPUID values
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_supported_cpuid(&self) -> Result<CpuId> {
        panic!("Not Implemented")
    }

    /// X86 specific call to get the system emulated CPUID values
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_emulated_cpuid(&self) -> Result<CpuId> {
        panic!("Not Implemented")
    }

    /// X86 specific call to get list of supported MSRS
    ///
    /// See the documentation for KVM_GET_MSR_INDEX_LIST.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msr_index_list(&self) -> Result<Vec<u32>> {
        panic!("Not Implemented")
    }
}

// impl AsRawFd for Kvm {
//     fn as_raw_fd(&self) -> RawFd {
//         self.kvm.as_raw_fd()
//     }
// }

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone, Debug)]
pub enum IoeventAddress {
    Pio(u64),
    Mmio(u64),
}

/// Used in `Vm::register_ioevent` to indicate a size and optionally value to match.
pub enum Datamatch {
    AnyLength,
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
}

/// A source of IRQs in an `IrqRoute`.
pub enum IrqSource {
    Irqchip { chip: u32, pin: u32 },
    Msi { address: u64, data: u32 },
}

/// A single route for an IRQ.
pub struct IrqRoute {
    pub gsi: u32,
    pub source: IrqSource,
}

/// Interrupt controller IDs
pub enum PicId {
    Primary = 0,
    Secondary = 1,
}

/// Number of pins on the IOAPIC.
pub const NUM_IOAPIC_PINS: usize = 24;

// Used to invert the order when stored in a max-heap.
#[derive(Copy, Clone, Eq, PartialEq)]
struct MemSlot(u32);

impl Ord for MemSlot {
    fn cmp(&self, other: &MemSlot) -> Ordering {
        // Notice the order is inverted so the lowest magnitude slot has the highest priority in a
        // max-heap.
        other.0.cmp(&self.0)
    }
}

impl PartialOrd for MemSlot {
    fn partial_cmp(&self, other: &MemSlot) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    vm: File,
    guest_mem: GuestMemoryMmap,
    device_memory: HashMap<u32, MmapRegion>,
    mem_slot_gaps: BinaryHeap<MemSlot>,
}

impl Vm {
    /// Constructs a new `Vm` using the given `Kvm` instance.
    pub fn new(kvm: &Kvm, guest_mem: GuestMemoryMmap) -> Result<Vm> {
        panic!("Not Implemented")
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// This is distinct from the `Kvm` version of this method because the some extensions depend on
    /// the particular `Vm` existence. This method is encouraged by the kernel because it more
    /// accurately reflects the usable capabilities.
    pub fn check_extension(&self, c: Cap) -> bool {
        panic!("Not Implemented")
    }

    /// Inserts the given `MmapRegion` into the VM's address space at `guest_addr`.
    ///
    /// The slot that was assigned the device memory mapping is returned on success. The slot can be
    /// given to `Vm::remove_device_memory` to remove the memory from the VM's address space and
    /// take back ownership of `mem`.
    ///
    /// Note that memory inserted into the VM's address space must not overlap with any other memory
    /// slot's region.
    ///
    /// If `read_only` is true, the guest will be able to read the memory as normal, but attempts to
    /// write will trigger a mmio VM exit, leaving the memory untouched.
    ///
    /// If `log_dirty_pages` is true, the slot number can be used to retrieve the pages written to
    /// by the guest with `get_dirty_log`.
    pub fn add_device_memory(
        &mut self,
        guest_addr: GuestAddress,
        mem: MmapRegion,
        read_only: bool,
        log_dirty_pages: bool,
    ) -> Result<u32> {
        panic!("Not Implemented")
    }

    /// Removes device memory that was previously added at the given slot.
    ///
    /// Ownership of the host memory mapping associated with the given slot is returned on success.
    pub fn remove_device_memory(&mut self, slot: u32) -> Result<MmapRegion> {
        panic!("Not Implemented")
    }

    /// Gets the bitmap of dirty pages since the last call to `get_dirty_log` for the memory at
    /// `slot`.
    ///
    /// The size of `dirty_log` must be at least as many bits as there are pages in the memory
    /// region `slot` represents. For example, if the size of `slot` is 16 pages, `dirty_log` must
    /// be 2 bytes or greater.
    pub fn get_dirty_log(&self, slot: u32, dirty_log: &mut [u8]) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets a reference to the guest memory owned by this VM.
    ///
    /// Note that `GuestMemoryMmap` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemoryMmap {
        &self.guest_mem
    }

    /// Sets the address of the three-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_TSS_ADDR ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_tss_addr(&self, addr: GuestAddress) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Sets the address of a one-page region in the VM's address space.
    ///
    /// See the documentation on the KVM_SET_IDENTITY_MAP_ADDR ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_identity_map_addr(&self, addr: GuestAddress) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Crates an in kernel interrupt controller.
    ///
    /// See the documentation on the KVM_CREATE_IRQCHIP ioctl.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn create_irq_chip(&self) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Retrieves the state of given interrupt controller by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_pic_state(&self, id: PicId) -> Result<kvm_pic_state> {
        panic!("Not Implemented")
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pic_state(&self, id: PicId, state: &kvm_pic_state) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_ioapic_state(&self) -> Result<kvm_ioapic_state> {
        panic!("Not Implemented")
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_ioapic_state(&self, state: &kvm_ioapic_state) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Sets the level on the given irq to 1 if `active` is true, and 0 otherwise.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn set_irq_line(&self, irq: u32, active: bool) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Creates a PIT as per the KVM_CREATE_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn create_pit(&self) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Retrieves the state of PIT by issuing KVM_GET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_pit_state(&self) -> Result<kvm_pit_state2> {
        panic!("Not Implemented")
    }

    /// Sets the state of PIT by issuing KVM_SET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pit_state(&self, pit_state: &kvm_pit_state2) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Registers an event to be signaled whenever a certain address is written to.
    ///
    /// The `datamatch` parameter can be used to limit signaling `evt` to only the cases where the
    /// value being written is equal to `datamatch`. Note that the size of `datamatch` is important
    /// and must match the expected size of the guest's write.
    ///
    /// In all cases where `evt` is signaled, the ordinary vmexit to userspace that would be
    /// triggered is prevented.
    pub fn register_ioevent(
        &self,
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, false)
    }

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    pub fn unregister_ioevent(
        &self,
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> Result<()> {
        self.ioeventfd(evt, addr, datamatch, true)
    }

    fn ioeventfd(
        &self,
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
        deassign: bool,
    ) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Registers an event that will, when signalled, trigger the `gsi` irq.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Registers an event that will, when signalled, trigger the `gsi` irq, and `resample_evt` will
    /// get triggered when the irqchip is resampled.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn register_irqfd_resample(
        &self,
        evt: &EventFd,
        resample_evt: &EventFd,
        gsi: u32,
    ) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Unregisters an event that was previously registered with
    /// `register_irqfd`/`register_irqfd_resample`.
    ///
    /// The `evt` and `gsi` pair must be the same as the ones passed into
    /// `register_irqfd`/`register_irqfd_resample`.
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))]
    pub fn unregister_irqfd(&self, evt: &EventFd, gsi: u32) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Sets the GSI routing table, replacing any table set with previous calls to
    /// `set_gsi_routing`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_gsi_routing(&self, routes: &[IrqRoute]) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Does KVM_CREATE_DEVICE for a generic device.
    pub fn create_device(&self, device: &mut kvm_create_device) -> Result<()> {
        panic!("Not Implemented")
    }

    /// This queries the kernel for the preferred target CPU type.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn arm_preferred_target(&self, kvi: &mut kvm_vcpu_init) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Enable the specified capability.
    /// See documentation for KVM_ENABLE_CAP.
    pub fn kvm_enable_cap(&self, cap: &kvm_enable_cap) -> Result<()> {
        panic!("Not Implemented")
    }

    /// (x86-only): Enable support for split-irqchip.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn enable_split_irqchip(&self) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Request that the kernel inject the specified MSI message.
    /// Returns Ok(true) on delivery, Ok(false) if the guest blocked delivery, or an error.
    /// See kernel documentation for KVM_SIGNAL_MSI.
    pub fn signal_msi(&self, msi: &kvm_msi) -> Result<bool> {
        panic!("Not Implemented")
    }
}

// impl AsRawFd for Vm {
//     fn as_raw_fd(&self) -> RawFd {
//         self.vm.as_raw_fd()
//     }
// }

/// A reason why a VCPU exited. One of these returns every time `Vcpu::run` is called.
#[derive(Debug)]
pub enum VcpuExit {
    /// An out port instruction was run on the given port with the given data.
    IoOut {
        port: u16,
        size: usize,
        data: [u8; 8],
    },
    /// An in port instruction was run on the given port.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    IoIn {
        port: u16,
        size: usize,
    },
    /// A read instruction was run against the given MMIO address.
    ///
    /// The date that the instruction receives should be set with `set_data` before `Vcpu::run` is
    /// called again.
    MmioRead {
        address: u64,
        size: usize,
    },
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite {
        address: u64,
        size: usize,
        data: [u8; 8],
    },
    Unknown,
    Exception,
    Hypercall,
    Debug,
    Hlt,
    IrqWindowOpen,
    Shutdown,
    FailEntry,
    Intr,
    SetTpr,
    TprAccess,
    S390Sieic,
    S390Reset,
    Dcr,
    Nmi,
    InternalError,
    Osi,
    PaprHcall,
    S390Ucontrol,
    Watchdog,
    S390Tsch,
    Epr,
    /// The cpu triggered a system level event which is specified by the type field.
    /// The first field is the event type and the second field is flags.
    /// The possible event types are shutdown, reset, or crash.  So far there
    /// are not any flags defined.
    SystemEvent(u32 /* event_type */, u64 /* flags */),
}

/// A wrapper around creating and using a VCPU.
pub struct Vcpu {
    vcpu: File,
    run_mmap: MmapRegion,
    guest_mem: GuestMemoryMmap,
}

impl Vcpu {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    pub fn new(id: c_ulong, kvm: &Kvm, vm: &Vm) -> Result<Vcpu> {

        // Wrap the vcpu now in case the following ? returns early. This is safe because we verified
        // the value of the fd and we own the fd.
        let vcpu = unsafe { std::mem::zeroed() };
        let run_mmap = unsafe { std::mem::zeroed() };
        let guest_mem = vm.guest_mem.clone();

        Ok(Vcpu {
            vcpu,
            run_mmap,
            guest_mem,
        })
    }

    /// Gets a reference to the guest memory owned by this VM of this VCPU.
    ///
    /// Note that `GuestMemoryMmap` does not include any device memory that may have been added after
    /// this VM was constructed.
    pub fn get_memory(&self) -> &GuestMemoryMmap {
        &self.guest_mem
    }

    /// Sets the data received by an mmio or ioport read/in instruction.
    ///
    /// This function should be called after `Vcpu::run` returns an `VcpuExit::IoIn` or
    /// `Vcpu::MmioRead`.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn set_data(&self, data: &[u8]) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Runs the VCPU until it exits, returning the reason.
    ///
    /// Note that the state of the VCPU and associated VM must be setup first for this to do
    /// anything useful.
    #[allow(clippy::cast_ptr_alignment)]
    // The pointer is page aligned so casting to a different type is well defined, hence the clippy
    // allow attribute.
    pub fn run(&self) -> Result<VcpuExit> {
        // Safe because we know that our file is a VCPU fd and we verify the return result.
        panic!("Not Implemented")
    }

    /// Gets the VCPU registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn get_regs(&self) -> Result<kvm_regs> {
        panic!("Not Implemented")
    }

    /// Sets the VCPU registers.
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn set_regs(&self, regs: &kvm_regs) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the VCPU special registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_sregs(&self) -> Result<kvm_sregs> {
        panic!("Not Implemented")
    }

    /// Sets the VCPU special registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the VCPU FPU registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_fpu(&self) -> Result<kvm_fpu> {
        panic!("Not Implemented")
    }

    /// X86 specific call to setup the FPU
    ///
    /// See the documentation for KVM_SET_FPU.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_fpu(&self, fpu: &kvm_fpu) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the VCPU debug registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_debugregs(&self) -> Result<kvm_debugregs> {
        panic!("Not Implemented")
    }

    /// Sets the VCPU debug registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_debugregs(&self, dregs: &kvm_debugregs) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the VCPU extended control registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_xcrs(&self) -> Result<kvm_xcrs> {
        panic!("Not Implemented")
    }

    /// Sets the VCPU extended control registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_xcrs(&self, xcrs: &kvm_xcrs) -> Result<()> {
        panic!("Not Implemented")
    }

    /// X86 specific call to get the MSRS
    ///
    /// See the documentation for KVM_SET_MSRS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_msrs(&self, msr_entries: &mut Vec<kvm_msr_entry>) -> Result<()> {
        panic!("Not Implemented")
    }

    /// X86 specific call to setup the MSRS
    ///
    /// See the documentation for KVM_SET_MSRS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_msrs(&self, msrs: &kvm_msrs) -> Result<()> {
        panic!("Not Implemented")
    }

    /// X86 specific call to setup the CPUID registers
    ///
    /// See the documentation for KVM_SET_CPUID2.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()> {
        panic!("Not Implemented")
    }

    /// X86 specific call to get the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_GET_LAPIC.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_lapic(&self) -> Result<kvm_lapic_state> {
        panic!("Not Implemented")
    }

    /// X86 specific call to set the state of the "Local Advanced Programmable Interrupt Controller".
    ///
    /// See the documentation for KVM_SET_LAPIC.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_lapic(&self, klapic: &kvm_lapic_state) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_GET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_mp_state(&self) -> Result<kvm_mp_state> {
        panic!("Not Implemented")
    }

    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_SET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_mp_state(&self, state: &kvm_mp_state) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Gets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_GET_VCPU_EVENTS.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_vcpu_events(&self) -> Result<kvm_vcpu_events> {
        panic!("Not Implemented")
    }

    /// Sets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_SET_VCPU_EVENTS.
    ///
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_vcpu_events(&self, events: &kvm_vcpu_events) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Signals to the host kernel that this VCPU is about to be paused.
    ///
    /// See the documentation for KVM_KVMCLOCK_CTRL.
    pub fn kvmclock_ctrl(&self) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Specifies set of signals that are blocked during execution of KVM_RUN.
    /// Signals that are not blocked will will cause KVM_RUN to return
    /// with -EINTR.
    ///
    /// See the documentation for KVM_SET_SIGNAL_MASK
    pub fn set_signal_mask(&self, signals: &[c_int]) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Sets the value of one register on this VCPU.  The id of the register is
    /// encoded as specified in the kernel documentation for KVM_SET_ONE_REG.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()> {
        panic!("Not Implemented")
    }

    /// This initializes an ARM VCPU to the specified type with the specified features
    /// and resets the values of all of its registers to defaults.
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn arm_vcpu_init(&self, kvi: &kvm_vcpu_init) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Use the KVM_INTERRUPT ioctl to inject the specified interrupt vector.
    ///
    /// While this ioctl exits on PPC and MIPS as well as x86, the semantics are different and
    /// ChromeOS doesn't support PPC or MIPS.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn interrupt(&self, irq: u32) -> Result<()> {
        panic!("Not Implemented")
    }
}

// impl AsRawFd for Vcpu {
//     fn as_raw_fd(&self) -> RawFd {
//         self.vcpu.as_raw_fd()
//     }
// }

/// Wrapper for kvm_cpuid2 which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    kvm_cpuid: Vec<kvm_cpuid2>,
    allocated_len: usize, // Number of kvm_cpuid_entry2 structs at the end of kvm_cpuid2.
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<kvm_cpuid2, kvm_cpuid_entry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Get the entries slice so they can be modified before passing to the VCPU.
    pub fn mut_entries_slice(&mut self) -> &mut [kvm_cpuid_entry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_ptr(&self) -> *const kvm_cpuid2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel.  Using this pointer is unsafe.
    pub fn as_mut_ptr(&mut self) -> *mut kvm_cpuid2 {
        &mut self.kvm_cpuid[0]
    }
}
