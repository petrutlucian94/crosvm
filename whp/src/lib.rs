// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! A safe wrapper around the kernel's KVM interface.

// Ideally we'l do something like we did in the vcpu crate where we defined 
// hypervisor-agnostic versions of these, but for now just use kvm_bindings directly
extern crate kvm_bindings;

extern crate vm_memory;

mod cap;

use std::cmp::{Ordering};
use std::io;
//use std::collections::{BinaryHeap, HashMap};
//use std::fs::File;
use std::mem::size_of;
use std::os::raw::*;

use vm_memory::*;

//use kvm_sys::*;

use sys_util::{
    pagesize, EventFd, Result,
};

pub use crate::cap::*;

use libwhp::whp_vcpu::*;
use libwhp::memory::*;
use libwhp::{Partition, GPARangeMapping};
use libwhp::whp_vcpu::WhpVirtualProcessor;
use libwhp::instruction_emulator::*;
use vmm_vcpu::vcpu::{Vcpu, VcpuExit, Result as VcpuResult};
use vmm_vcpu::x86_64::{FpuState, MsrEntries, SpecialRegisters, StandardRegisters,
                       LapicState, CpuId};

use kvm_bindings::*;

//use vm_memory::{GuestAddress, GuestMemoryMmap, MmapRegion};
use kvm_bindings::{
    kvm_debugregs as DebugRegisters,
    kvm_xcrs as ExtendedControlRegisters,
    kvm_mp_state as MpState,
    kvm_vcpu_events as VcpuEvents,
    kvm_clock_data as ClockData,
    kvm_pic_state as PicState,
    kvm_ioapic_state as IoapicState,
    kvm_pit_state2 as PitState2,
    kvm_create_device as CreateDevice,
    kvm_enable_cap as EnableCap,
    kvm_msi as Msi,
    };


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
/// Useful for querying extensions and basic values from the KVM backend. A `WhpManager` is required to
/// create a `Vm` object.
pub struct WhpManager {
}

impl WhpManager {
    /// Opens `/dev/kvm/` and returns a WhpManager object on success.
    pub fn new() -> Result<WhpManager> {
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

// impl AsRawFd for WhpManager {
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
struct MemoryRegionRef<'a> {
    region: &'a GuestRegionMmap,
}

impl<'a> MemoryRegionRef<'a> {
    fn new(region: &'a GuestRegionMmap) -> Self {
        Self { region: region }
    }
}

impl<'a> Memory for MemoryRegionRef<'a> {
    fn as_slice_mut(&mut self) -> &mut [u8] {
        return unsafe { self.region.as_mut_slice().unwrap() };
    }

    fn as_ptr(&self) -> *const std::ffi::c_void {
        return unsafe { self.region.as_slice().unwrap().as_ptr() as *const std::ffi::c_void };
    }

    fn get_size(&self) -> usize {
        return unsafe { self.region.as_slice().unwrap().len() };
    }
}

/// A wrapper around creating and using a VM.
pub struct Vm {
    partition: Partition,
    mappings: Vec<GPARangeMapping>,

    guest_mem: GuestMemoryMmap,
    // device_memory: HashMap<u32, MmapRegion>,
    // mem_slot_gaps: BinaryHeap<MemSlot>,
}

impl Default for Vm {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl Vm {
    /// Constructs a new `Vm` (Partition) using the given `WhpManager` instance.
    /// TODO: Currently working through this/not complete
    pub fn new(whp: &WhpManager, guest_mem: GuestMemoryMmap) -> Result<Vm> {
        let mut partition = Partition::new().unwrap();
        let mut mappings = Vec::new();

        guest_mem.with_regions_mut::<_, ()>(|_index, region| {
            // MemoryRegionRef implements the libwhp::Memory trait
            let region_ref = MemoryRegionRef::new(region);

            // Map the memory to the guest
            let mapping = partition
                .map_gpa_range(
                    &region_ref,
                    region.start_addr().0,
                    region.len() as u64,
                    WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                        | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                        | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagExecute,
                ).unwrap();

           mappings.push(mapping);
           Ok(())
        }).unwrap();

        Ok(Vm{
            partition,
            mappings,
            guest_mem
        })
    }

    /// Checks if a particular `Cap` is available.
    ///
    /// This is distinct from the `WhpManager` version of this method because the some extensions depend on
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

    /// Retrieves the current timestamp of kvmclock as seen by the current guest.
    ///
    /// See the documentation on the KVM_GET_CLOCK ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_clock(&self) -> Result<ClockData> {
        panic!("Not Implemented")
    }

    /// Sets the current timestamp of kvmclock to the specified value.
    ///
    /// See the documentation on the KVM_SET_CLOCK ioctl.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_clock(&self, clock_data: &ClockData) -> Result<()> {
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
    pub fn get_pic_state(&self, id: PicId) -> Result<PicState> {
        panic!("Not Implemented")
    }

    /// Sets the state of given interrupt controller by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pic_state(&self, id: PicId, state: &PicState) -> Result<()> {
        panic!("Not Implemented")
    }

    /// Retrieves the state of IOAPIC by issuing KVM_GET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn get_ioapic_state(&self) -> Result<IoapicState> {
        panic!("Not Implemented")
    }

    /// Sets the state of IOAPIC by issuing KVM_SET_IRQCHIP ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_irq_chip`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_ioapic_state(&self, state: &IoapicState) -> Result<()> {
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
    pub fn get_pit_state(&self) -> Result<PitState2> {
        panic!("Not Implemented")
    }

    /// Sets the state of PIT by issuing KVM_SET_PIT2 ioctl.
    ///
    /// Note that this call can only succeed after a call to `Vm::create_pit`.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub fn set_pit_state(&self, pit_state: &PitState2) -> Result<()> {
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

    /// Enable the specified capability.
    /// See documentation for KVM_ENABLE_CAP.
    pub fn EnableCap(&self, cap: &EnableCap) -> Result<()> {
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
    pub fn signal_msi(&self, msi: &Msi) -> Result<bool> {
        panic!("Not Implemented")
    }
}

pub trait VcpuExtra {
    fn new(id: c_ulong, whp: &WhpManager, vm: &Vm) -> Result<Self> where Self: Sized;
    fn get_memory(&self) -> &GuestMemoryMmap;
    fn set_data(&self, data: &[u8]) -> Result<()>;
    fn get_debugregs(&self) -> Result<DebugRegisters>;
    fn set_debugregs(&self, dregs: &DebugRegisters) -> Result<()>;
    fn get_xcrs(&self) -> Result<ExtendedControlRegisters>;
    fn set_xcrs(&self, xcrs: &ExtendedControlRegisters) -> Result<()>;
    fn get_mp_state(&self) -> Result<MpState>;
    fn set_mp_state(&self, state: &MpState) -> Result<()>;
    fn get_vcpu_events(&self) -> Result<VcpuEvents>;
    fn set_vcpu_events(&self, events: &VcpuEvents) -> Result<()>;
    fn kvmclock_ctrl(&self) -> Result<()>;
    fn set_signal_mask(&self, signals: &[c_int]) -> Result<()>;
}

impl VcpuExtra for WhpVirtualProcessor {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    fn new(id: c_ulong, _whp: &WhpManager, vm: &Vm) -> Result<WhpVirtualProcessor> {
        let vp = vm.partition.create_virtual_processor(id).unwrap();
        let wvp = WhpVirtualProcessor::create_whp_vcpu(vp).unwrap();
        Ok(wvp)
    }

    /// Gets a reference to the guest memory owned by this VM of this VCPU.
    ///
    /// Note that `GuestMemoryMmap` does not include any device memory that may have been added after
    /// this VM was constructed.
    fn get_memory(&self) -> &GuestMemoryMmap {
        unimplemented!();
    }

    /// Sets the data received by an mmio or ioport read/in instruction.
    ///
    /// This function should be called after `Vcpu::run` returns an `VcpuExit::IoIn` or
    /// `Vcpu::MmioRead`.
    #[allow(clippy::cast_ptr_alignment)]
    fn set_data(&self, _data: &[u8]) -> Result<()> {
        unimplemented!();
    }

    /// Gets the VCPU debug registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[allow(unreachable_code)]
    fn get_debugregs(&self) -> Result<DebugRegisters> {
        unimplemented!();
        let mut regs = unsafe { std::mem::zeroed() };
        Ok(regs)
    }

    /// Sets the VCPU debug registers
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_debugregs(&self, _dregs: &DebugRegisters) -> Result<()> {
        unimplemented!();
        Ok(())
    }

    /// Gets the VCPU extended control registers
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_xcrs(&self) -> Result<ExtendedControlRegisters> {
        unimplemented!();
        let mut regs = unsafe { std::mem::zeroed() };
        Ok(regs)
    }

    /// Sets the VCPU extended control registers
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_xcrs(&self, _xcrs: &ExtendedControlRegisters) -> Result<()> {
        unimplemented!();
        Ok(())
    }

    /// Gets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_GET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_mp_state(&self) -> Result<MpState> {
        unimplemented!();
        let mut state: MpState = unsafe { std::mem::zeroed() };
        Ok(state)
    }

    /// Sets the vcpu's current "multiprocessing state".
    ///
    /// See the documentation for KVM_SET_MP_STATE. This call can only succeed after
    /// a call to `Vm::create_irq_chip`.
    ///
    /// Note that KVM defines the call for both x86 and s390 but we do not expect anyone
    /// to run crosvm on s390.
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_mp_state(&self, _state: &MpState) -> Result<()> {
        unimplemented!();
        Ok(())
    }

    /// Gets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_GET_VCPU_EVENTS.
    ///
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_vcpu_events(&self) -> Result<VcpuEvents> {
        unimplemented!();
        let mut events: VcpuEvents = unsafe { std::mem::zeroed() };
        Ok(events)
    }

    /// Sets the vcpu's currently pending exceptions, interrupts, NMIs, etc
    ///
    /// See the documentation for KVM_SET_VCPU_EVENTS.
    ///
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_vcpu_events(&self, _events: &VcpuEvents) -> Result<()> {
        unimplemented!();
        Ok(())
    }

    /// Signals to the host kernel that this VCPU is about to be paused.
    ///
    /// See the documentation for KVM_KVMCLOCK_CTRL.
    #[allow(unreachable_code)]
    fn kvmclock_ctrl(&self) -> Result<()> {
        unimplemented!();
        Ok(())
    }

    /// Specifies set of signals that are blocked during execution of KVM_RUN.
    /// Signals that are not blocked will will cause KVM_RUN to return
    /// with -EINTR.
    ///
    /// See the documentation for KVM_SET_SIGNAL_MASK
    #[allow(unreachable_code)]
    fn set_signal_mask(&self, _signals: &[c_int]) -> Result<()> {
        unimplemented!();
        Ok(())
    }
}

/*
struct WhpVcpuRun<'a> {
    vp: &'a WhpVirtualProcessor,
    exit_context: *const WHV_RUN_VP_EXIT_CONTEXT,
    io_data: [u8; 8],
    io_data_len: usize,
    emulator: Emulator<WhpVcpuRun<'a>>,
}

impl<'a> WhpVcpuRun<'a> {
    fn new(vp: &WhpVirtualProcessor) -> Self {
        return WhpVcpuRun {
            vp: vp,
            // Safe because it has the same lifetime as WhpVirtualProcessor
            exit_context: vp.get_run_context(),
            io_data: Default::default(),
            io_data_len: 0,
            emulator: Emulator::<WhpVcpuRun>::new().unwrap(),
        }
    }

    /* TODO: Continue here
    fn run(&self) -> Result<VcpuExit> {
        let exit_reason = self.vp.run().unwrap();
        self.exit_context = self.vp.get_run_context();

        Ok(())
    }
    */
}

impl<'a> EmulatorCallbacks for WhpVcpuRun<'a> {
    fn io_port(
        &mut self,
        io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {
        let port = io_access.Port;
        let data_size_bytes = io_access.AccessSize;
        let data = unsafe {
            std::slice::from_raw_parts(
                &io_access.Data as *const _ as *const u8,
                io_access.AccessSize as usize,
            )
        };
        S_OK
    }

    fn memory(
        &mut self,
        memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {
        let addr = memory_access.GpaAddress;
        match memory_access.AccessSize {
            8 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u64;
                    unsafe {
                        *data = 0x1000;
                        println!("MMIO read: 0x{:x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u64) };
                    println!("MMIO write: 0x{:x} @0x{:x}", value, addr);
                }
            },
            4 => match memory_access.Direction {
                0 => {
                    let data = &memory_access.Data as *const _ as *mut u32;
                    unsafe {
                        *data = 0x1000;
                        println!("MMIO read: 0x{:x} @0x{:x}", *data, addr);
                    }
                }
                _ => {
                    let value = unsafe { *(&memory_access.Data as *const _ as *const u32) };
                    println!("MMIO write: 0x{:x} @0x{:x}", value, addr);
                }
            },
            _ => println!("Unsupported MMIO access size: {}", memory_access.AccessSize),
        }

        S_OK
    }

    fn get_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vp
            .vp
            .borrow()
            .get_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn set_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &[WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vp
            .vp
            .borrow()
            .set_registers(register_names, register_values)
            .unwrap();
        S_OK
    }

    fn translate_gva_page(
        &mut self,
        gva: WHV_GUEST_VIRTUAL_ADDRESS,
        translate_flags: WHV_TRANSLATE_GVA_FLAGS,
        translation_result: &mut WHV_TRANSLATE_GVA_RESULT_CODE,
        gpa: &mut WHV_GUEST_PHYSICAL_ADDRESS,
    ) -> HRESULT {
        let (translation_result1, gpa1) = self
            .vp
            .vp
            .borrow()
            .translate_gva(gva, translate_flags)
            .unwrap();
        *translation_result = translation_result1.ResultCode;
        *gpa = gpa1;
        S_OK
    }
}
*/