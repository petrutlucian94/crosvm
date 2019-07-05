// Copyright 2018 Cloudbase Solutions Srl
// Copyright 2018-2019 CrowdStrike, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

use std::collections::BTreeMap;
use std::io;
use std::cell::RefCell;
use std::os::raw::*;

use crate::{Vm, WhpManager};
pub use crate::common::*;
use crate::whp_structs::*;

use libwhp::instruction_emulator::*;
pub use libwhp::*;
pub use libwhp::x86_64::XsaveArea;
use libwhp::platform::{VirtualProcessor, Partition};
use libwhp::instruction_emulator::{Emulator, EmulatorCallbacks};
use vmm_vcpu::vcpu::{Vcpu, VcpuExit, Result as VcpuResult};
use vmm_vcpu::x86_64::{FpuState, MsrEntries, SpecialRegisters, StandardRegisters,
                       LapicState, CpuId};
use sys_util::{EventFd, Result as WinResult, debug};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IoCallbackState {
    NoIoOperation = 0,
    IoGetAccessSize = 1,
    IoSetData = 2,
}

pub struct WhpIoAccessData {
    io_data: [u8; 8],
    io_data_len: usize,
    port: u16,
    is_write: u8,
    state: IoCallbackState,
}

impl Default for WhpIoAccessData {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

pub struct WhpMmioAccessData {
    mmio_data: [u8; 8],
    mmio_data_len: usize,
    gpa: u64,
    is_write: u8,
    state: IoCallbackState,
}

impl Default for WhpMmioAccessData {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

pub struct WhpContext<'a> {
    vp: VirtualProcessor<'a>,
    last_exit_context: WHV_RUN_VP_EXIT_CONTEXT,
    io_access_data: WhpIoAccessData,
    mmio_access_data: WhpMmioAccessData,
}

impl<'a> WhpContext<'a> {
    fn get_run_context_ptr(&self) -> *const WHV_RUN_VP_EXIT_CONTEXT {
        &self.last_exit_context as *const WHV_RUN_VP_EXIT_CONTEXT
    }
}

pub struct WhpVirtualProcessor<'a> {
    emulator: Emulator<WhpContext<'a>>,
    whp_context: RefCell<WhpContext<'a>>,
    resample_events: BTreeMap<u32, EventFd>,
    pio_events: BTreeMap<u64, (EventFd, Datamatch)>,
    mmio_events: BTreeMap<u64, (EventFd, Datamatch)>

}

// This isn't a value defined by WHP. We need a "non-success" code
// for our instruction emulation, which contains two steps.
pub const E_PENDING: HRESULT =  0x8000000;

impl<'a> WhpVirtualProcessor<'a> {
    /// Constructs a new VCPU for `vm`.
    ///
    /// The `id` argument is the CPU number between [0, max vcpus).
    fn new(id: c_ulong, _whp: &WhpManager, vm: &'a Vm<'a>) -> WinResult<WhpVirtualProcessor<'a>> {
        let vp = vm.partition.create_virtual_processor(id).unwrap();
        let wvp = WhpVirtualProcessor::create_whp_vcpu(vp).unwrap();
        Ok(wvp)
    }

    pub fn create_whp_vcpu(vp: VirtualProcessor<'a>) -> VcpuResult<Self> {
        return Ok(WhpVirtualProcessor {
            emulator: Emulator::<WhpContext<'a>>::new().unwrap(),
            whp_context: RefCell::new(WhpContext {
                vp: vp,
                last_exit_context: Default::default(),
                io_access_data: Default::default(),
                mmio_access_data: Default::default(),
            }),
            resample_events: BTreeMap::new(),
            pio_events: BTreeMap::new(),
            mmio_events: BTreeMap::new(),
        });
    }

    pub fn create_whp_vcpu_by_partition(p: &'a Partition, index: UINT32) -> VcpuResult<Self> {
        let vp = p.create_virtual_processor(index).unwrap();

        return Ok(WhpVirtualProcessor {
            emulator: Emulator::<WhpContext>::new().unwrap(),
            whp_context: RefCell::new(WhpContext {
                vp: vp,
                last_exit_context: Default::default(),
                io_access_data: Default::default(),
                mmio_access_data: Default::default(),
            }),
            resample_events: BTreeMap::new(),
            pio_events: BTreeMap::new(),
            mmio_events: BTreeMap::new(),
        });
    }

    pub fn handle_io_port_exit(&self, whp_context: &mut WhpContext<'a>) -> Result<(), WHPError> {
        let vp_context = whp_context.last_exit_context.VpContext;
        let io_port_access_ctx =
            unsafe { whp_context.last_exit_context.anon_union.IoPortAccess };

        let status = self
            .emulator
            .try_io_emulation(whp_context, &vp_context, &io_port_access_ctx)?;
        
        // The function returns S_OK in most methods of operation, but
        // return_status will return extended error information. Success is
        // considered either EmulationSuccessful, or a failure of
        // IoPortCallbackFailed. The latter is required because the callback
        // returns a non-success E_PENDING status for the first of the two
        // stages of IO emulation.
        match status.EmulationSuccessful() {
            1 => Ok(()),
            _ => {
                match status.IoPortCallbackFailed() {
                    1 => Ok(()),
                    _ => Err(WHPError::new(status.AsUINT32 as INT32)),
                }
            }
        }
    }

    pub fn handle_mmio_exit(&self, whp_context: &mut WhpContext<'a>) -> Result<(), WHPError> {
        let vp_context = whp_context.last_exit_context.VpContext;
        let mmio_access_ctx =
            unsafe {whp_context.last_exit_context.anon_union.MemoryAccess };

        let status = self
            .emulator
            .try_mmio_emulation(whp_context, &vp_context, &mmio_access_ctx)
            .unwrap();

        // The function returns S_OK in most methods of operation, but
        // return_status will return extended error information. Success is
        // considered either EmulationSuccessful, or a failure of
        // MemoryCallbackFailed. The latter is required because the callback
        // returns a non-success E_PENDING status for the first of the two
        // stages of IO emulation.
        match status.EmulationSuccessful() {
            1 => Ok(()),
            _ => {
                match status.MemoryCallbackFailed() {
                    1 => Ok(()),
                    _ => Err(WHPError::new(status.AsUINT32 as INT32)),
                }
            }
        }
    }

    /// Use request_interrupt to inject the specified interrupt vector.
    pub fn interrupt(&self, irq: UINT32) -> VcpuResult<()> {
        let mut interrupt: WHV_INTERRUPT_CONTROL = Default::default();

        interrupt.set_InterruptType(
            WHV_INTERRUPT_TYPE::WHvX64InterruptTypeFixed as UINT64);
        interrupt.set_DestinationMode(
            WHV_INTERRUPT_DESTINATION_MODE::WHvX64InterruptDestinationModePhysical as UINT64);
        interrupt.set_TriggerMode(
            WHV_INTERRUPT_TRIGGER_MODE::WHvX64InterruptTriggerModeEdge as UINT64);
        interrupt.Destination = 0;
        interrupt.Vector = irq;

        self.whp_context.borrow().vp.request_interrupt(&mut interrupt).unwrap();

        Ok(())
    }

    pub fn get_partition_counters(
        &self,
        partition_counter_set: WHV_PARTITION_COUNTER_SET,
    ) -> Result<(WHV_PARTITION_COUNTERS), WHPError> {

        return self.whp_context.borrow().vp.get_partition_counters(partition_counter_set);
    }

    pub fn get_processor_counters(
        &self,
        processor_counter_set: WHV_PROCESSOR_COUNTER_SET,
    ) -> Result<WHV_PROCESSOR_COUNTERS, WHPError> {

        return self.whp_context.borrow().vp.get_processor_counters(processor_counter_set);
    }

    pub fn get_xsave_state(&self) -> Result<(XsaveArea), WHPError> {
        return self.whp_context.borrow().vp.get_xsave_state();
    }

    pub fn set_xsave_state(&self, xsave_area: XsaveArea) -> Result<(), WHPError> {
        return self.whp_context.borrow().vp.set_xsave_state(xsave_area);
    }

    pub fn set_delivery_notifications(&self) {
        const NUM_REGS: usize = 1;
        let mut reg_values: [WHV_REGISTER_VALUE; NUM_REGS] = Default::default();
        let mut reg_names: [WHV_REGISTER_NAME; NUM_REGS] = Default::default();

        let mut notifications: WHV_X64_DELIVERABILITY_NOTIFICATIONS_REGISTER = Default::default();
        notifications.set_InterruptNotification(1);
        reg_values[0].DeliverabilityNotifications = notifications;
        reg_names[0] = WHV_REGISTER_NAME::WHvX64RegisterDeliverabilityNotifications;
        self.whp_context.borrow().vp.set_registers(&reg_names, &reg_values).unwrap();
    }

    pub fn register_irqfd_resample(
        &mut self,
        _evt: &mut EventFd,
        resample_evt: &EventFd,
        gsi: u32,
    ) -> WinResult<()> {
        println!("Registering resample event {}", gsi);
        self.resample_events.insert(
            gsi, resample_evt.try_clone()?);
        Ok(())
    }

    pub fn unregister_irqfd_resample(
        &mut self,
        gsi: u32,
    ) -> WinResult<()> {
        self.resample_events.remove(&gsi);
        Ok(())
    }

    /// Registers an event to be signaled when the guest writes to
    /// the specified port IO or MMIO address. By using Datamatch,
    /// the written data can be checked.
    ///
    /// Note that for now, we're keeping a single Datamatch object
    /// per address.
    pub fn register_ioevent(
        &mut self,
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> WinResult<()> {
        match addr {
            IoeventAddress::Pio(pio_addr) => {
                let existing = self.pio_events.insert(
                    pio_addr, (evt.try_clone().unwrap(), datamatch));
            }
            IoeventAddress::Mmio(mmio_addr) => {
                let existing = self.mmio_events.insert(
                    mmio_addr, (evt.try_clone().unwrap(), datamatch));
            }
        }
        Ok(())
    }

    /// Unregisters an event previously registered with `register_ioevent`.
    ///
    /// The `evt`, `addr`, and `datamatch` set must be the same as the ones passed into
    /// `register_ioevent`.
    pub fn unregister_ioevent(
        &mut self,
        evt: &EventFd,
        addr: IoeventAddress,
        datamatch: Datamatch,
    ) -> WinResult<()> {
        match addr {
            IoeventAddress::Pio(pio_addr) => {
                self.pio_events.remove(&pio_addr);
            }
            IoeventAddress::Mmio(mmio_addr) => {
                self.mmio_events.remove(&mmio_addr);
            }
        }
        Ok(())
    }

}

impl<'a> Vcpu for WhpVirtualProcessor<'a> {

    type RunContextType = *const WHV_RUN_VP_EXIT_CONTEXT;

    fn get_run_context(&self) -> Self::RunContextType {
        self.whp_context.borrow().get_run_context_ptr()
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn get_regs(&self) -> VcpuResult<StandardRegisters> {
        let mut win_regs: WinStandardRegisters = Default::default();

        self.whp_context
            .borrow()
            .vp
            .get_registers(&win_regs.names, &mut win_regs.values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(StandardRegisters {
                rax: win_regs.values[WinStandardRegIndex::Rax as usize].Reg64,
                rbx: win_regs.values[WinStandardRegIndex::Rbx as usize].Reg64,
                rcx: win_regs.values[WinStandardRegIndex::Rcx as usize].Reg64,
                rdx: win_regs.values[WinStandardRegIndex::Rdx as usize].Reg64,

                rsi: win_regs.values[WinStandardRegIndex::Rsi as usize].Reg64,
                rdi: win_regs.values[WinStandardRegIndex::Rdi as usize].Reg64,
                rsp: win_regs.values[WinStandardRegIndex::Rsp as usize].Reg64,
                rbp: win_regs.values[WinStandardRegIndex::Rbp as usize].Reg64,

                r8: win_regs.values[WinStandardRegIndex::R8 as usize].Reg64,
                r9: win_regs.values[WinStandardRegIndex::R9 as usize].Reg64,
                r10: win_regs.values[WinStandardRegIndex::R10 as usize].Reg64,
                r11: win_regs.values[WinStandardRegIndex::R11 as usize].Reg64,
                r12: win_regs.values[WinStandardRegIndex::R12 as usize].Reg64,
                r13: win_regs.values[WinStandardRegIndex::R13 as usize].Reg64,
                r14: win_regs.values[WinStandardRegIndex::R14 as usize].Reg64,
                r15: win_regs.values[WinStandardRegIndex::R15 as usize].Reg64,

                rip: win_regs.values[WinStandardRegIndex::Rip as usize].Reg64,
                rflags: win_regs.values[WinStandardRegIndex::Rflags as usize].Reg64,
            })
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn set_regs(&self, regs: &StandardRegisters) -> VcpuResult<()> {
        let mut win_regs: WinStandardRegisters = Default::default();

        win_regs.values[WinStandardRegIndex::Rax as usize].Reg64 = regs.rax;
        win_regs.values[WinStandardRegIndex::Rbx as usize].Reg64 = regs.rbx;
        win_regs.values[WinStandardRegIndex::Rcx as usize].Reg64 = regs.rcx;
        win_regs.values[WinStandardRegIndex::Rdx as usize].Reg64 = regs.rdx;

        win_regs.values[WinStandardRegIndex::Rsi as usize].Reg64 = regs.rsi;
        win_regs.values[WinStandardRegIndex::Rdi as usize].Reg64 = regs.rdi;
        win_regs.values[WinStandardRegIndex::Rsp as usize].Reg64 = regs.rsp;
        win_regs.values[WinStandardRegIndex::Rbp as usize].Reg64 = regs.rbp;

        win_regs.values[WinStandardRegIndex::R8 as usize].Reg64 = regs.r8;
        win_regs.values[WinStandardRegIndex::R9 as usize].Reg64 = regs.r9;
        win_regs.values[WinStandardRegIndex::R10 as usize].Reg64 = regs.r10;
        win_regs.values[WinStandardRegIndex::R11 as usize].Reg64 = regs.r11;
        win_regs.values[WinStandardRegIndex::R12 as usize].Reg64 = regs.r12;
        win_regs.values[WinStandardRegIndex::R13 as usize].Reg64 = regs.r13;
        win_regs.values[WinStandardRegIndex::R14 as usize].Reg64 = regs.r14;
        win_regs.values[WinStandardRegIndex::R15 as usize].Reg64 = regs.r15;

        win_regs.values[WinStandardRegIndex::Rip as usize].Reg64 = regs.rip;
        win_regs.values[WinStandardRegIndex::Rflags as usize].Reg64 = regs.rflags;

        self.whp_context
            .borrow()
            .vp
            .set_registers(&win_regs.names, &win_regs.values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn get_sregs(&self) -> VcpuResult<SpecialRegisters> {
        let mut win_sregs: WinSpecialRegisters = Default::default();

        self.whp_context
            .borrow()
            .vp
            .get_registers(&win_sregs.names, &mut win_sregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        unsafe {
            Ok(SpecialRegisters {
                cs: win_sregs.values[WinSpecialRegIndex::Cs as usize].Segment.to_portable(),
                ds: win_sregs.values[WinSpecialRegIndex::Ds as usize].Segment.to_portable(),
                es: win_sregs.values[WinSpecialRegIndex::Es as usize].Segment.to_portable(),
                fs: win_sregs.values[WinSpecialRegIndex::Fs as usize].Segment.to_portable(),
                gs: win_sregs.values[WinSpecialRegIndex::Gs as usize].Segment.to_portable(),
                ss: win_sregs.values[WinSpecialRegIndex::Ss as usize].Segment.to_portable(),
                tr: win_sregs.values[WinSpecialRegIndex::Tr as usize].Segment.to_portable(),

                ldt: win_sregs.values[WinSpecialRegIndex::Ldt as usize].Segment.to_portable(),
                gdt: win_sregs.values[WinSpecialRegIndex::Gdt as usize].Table.to_portable(),
                idt: win_sregs.values[WinSpecialRegIndex::Idt as usize].Table.to_portable(),
                cr0: win_sregs.values[WinSpecialRegIndex::Cr0 as usize].Reg64,
                cr2: win_sregs.values[WinSpecialRegIndex::Cr2 as usize].Reg64,
                cr3: win_sregs.values[WinSpecialRegIndex::Cr3 as usize].Reg64,
                cr4: win_sregs.values[WinSpecialRegIndex::Cr4 as usize].Reg64,
                cr8: win_sregs.values[WinSpecialRegIndex::Cr8 as usize].Reg64,
                efer: win_sregs.values[WinSpecialRegIndex::Efer as usize].Reg64,
                apic_base: win_sregs.values[WinSpecialRegIndex::ApicBase as usize].Reg64,
                interrupt_bitmap: [
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    Default::default(),
                ],
            })
        }
    }

    fn set_sregs(&self, sregs: &SpecialRegisters) -> VcpuResult<()> {
        let mut win_sregs: WinSpecialRegisters = Default::default();
        win_sregs.values[WinSpecialRegIndex::Cs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.cs);

        win_sregs.values[WinSpecialRegIndex::Ds as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ds);

        win_sregs.values[WinSpecialRegIndex::Es as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.es);

        win_sregs.values[WinSpecialRegIndex::Fs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.fs);

        win_sregs.values[WinSpecialRegIndex::Gs as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.gs);

        win_sregs.values[WinSpecialRegIndex::Ss as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ss);

        win_sregs.values[WinSpecialRegIndex::Tr as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.tr);

        win_sregs.values[WinSpecialRegIndex::Ldt as usize].Segment =
            WHV_X64_SEGMENT_REGISTER::from_portable(&sregs.ldt);

        win_sregs.values[WinSpecialRegIndex::Gdt as usize].Table =
            WHV_X64_TABLE_REGISTER::from_portable(&sregs.gdt);

        win_sregs.values[WinSpecialRegIndex::Idt as usize].Table =
            WHV_X64_TABLE_REGISTER::from_portable(&sregs.idt);

        win_sregs.values[WinSpecialRegIndex::Cr0 as usize].Reg64 = sregs.cr0;
        win_sregs.values[WinSpecialRegIndex::Cr2 as usize].Reg64 = sregs.cr2;
        win_sregs.values[WinSpecialRegIndex::Cr3 as usize].Reg64 = sregs.cr3;
        win_sregs.values[WinSpecialRegIndex::Cr4 as usize].Reg64 = sregs.cr4;
        win_sregs.values[WinSpecialRegIndex::Cr8 as usize].Reg64 = sregs.cr8;
        win_sregs.values[WinSpecialRegIndex::Efer as usize].Reg64 = sregs.efer;
        win_sregs.values[WinSpecialRegIndex::ApicBase as usize].Reg64 = sregs.apic_base;

        self.whp_context
            .borrow()
            .vp
            .set_registers(&win_sregs.names, &win_sregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn get_fpu(&self) -> VcpuResult<FpuState>{
        let mut fregs: WinFpuRegisters = Default::default();

        // Get the registers from the vCPU
        self.whp_context
            .borrow()
            .vp
            .get_registers(&fregs.names, &mut fregs.values)
            .map_err(|_| io::Error::last_os_error())?;

        // Perform the conversion from these fields to FpuState fields
        let fpu_state: FpuState = ConvertFpuState::to_portable(&fregs);

        Ok(fpu_state)
    }

    fn set_fpu(&self, fpu: &FpuState) -> VcpuResult<()> {
        let fregs: WinFpuRegisters = ConvertFpuState::from_portable(&fpu);

        self.whp_context
            .borrow()
            .vp
            .set_registers(&fregs.names, &fregs.values)
            .map_err(|_| io::Error::last_os_error()).unwrap();
        Ok(())
    }

    /// x86-specific call to setup the CPUID registers.
    /// 
    /// Unimplemented in WHP because it is not possible to do this from the vCPU
    /// level.
    /// 
    /// CPUID results _can_ be set on a partition level, however, this must be
    /// done via WHvSetPartitionProperty, which itself must be called after
    /// before WHvSetupPartition. Since
    /// a vCPU cannot be created (via WHvCreateVirtualProcessor) until
    /// after WHvSetupPartition finalizes partition properties, it is impossible
    /// to call WHvSetPartitionProperty after a vCPU has been created. In other
    /// words, the mandatory order of operations is:
    /// - WHvCreatePartition
    /// - WHvSetPartitionProperty (which can optionally set the
    ///   WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeCpuidResultList 
    ///   property)
    /// - WHvSetupPartition
    /// - WHvCreateVirtualProcessor
    /// 
    #[allow(unreachable_code)]
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_cpuid2(&self, _cpuid: &CpuId) -> VcpuResult<()> {

        unimplemented!();

        /*
        let mut cpuid_results: Vec<WHV_X64_CPUID_RESULT> = Vec::new();

        for entry in _cpuid.as_entries_slice().iter() {
            let mut cpuid_result: WHV_X64_CPUID_RESULT = Default::default();
            cpuid_result.Function = entry.function;
            cpuid_result.Eax = entry.eax;
            cpuid_result.Ebx = entry.ebx;
            cpuid_result.Ecx = entry.ecx;
            cpuid_result.Edx = entry.edx;

            cpuid_results.push(cpuid_result);
        }

        self.set_cpuid_results_on_partition(&cpuid_results).unwrap();
        */

        return Ok(())
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs(&self, msrs: &mut MsrEntries) -> VcpuResult<i32> {
        let mut msr_names: Vec<WHV_REGISTER_NAME> = Vec::new();
        let mut msr_values: Vec<WHV_REGISTER_VALUE> = Vec::new();

        let num_msrs = msrs.nmsrs as usize;

        // Translate each MSR index into its corresponding MSR NAME
        unsafe {
            for entry in msrs.entries.as_slice(num_msrs).iter() {
                match WHV_REGISTER_NAME::from_portable(entry.index) {
                    Some(reg_name) => {
                        msr_names.push(reg_name);

                        // Push a corresponding blank MSR Value to the value array
                        let reg_value: WHV_REGISTER_VALUE = Default::default();
                        msr_values.push(reg_value);
                    }
                    None => println!("Ignoring unsupported msr: {:#x}",
                                     entry.index)
                }
            }
        }

        // Get the MSR values
        self.whp_context
            .borrow()
            .vp
            .get_registers(&msr_names, &mut msr_values)
            .map_err(|_| io::Error::last_os_error())?;

        // Now re-insert the returned MSR data in the original MsrEntries
        unsafe {
            let mut idx = 0;
            for entry in msrs.entries.as_mut_slice(num_msrs).iter_mut() {
                match WHV_REGISTER_NAME::from_portable(entry.index) {
                    Some(_) => {
                        entry.data = msr_values[idx].Reg64;
                        idx += 1;
                    }
                    None => {}
                }
            }
        }

        Ok(num_msrs as i32)
    }

    fn set_msrs(&self, msrs: &MsrEntries) -> VcpuResult<()> {

        let mut msr_names: Vec<WHV_REGISTER_NAME> = Vec::new();
        let mut msr_values: Vec<WHV_REGISTER_VALUE> = Vec::new();

        unsafe {
            for entry in msrs.entries.as_slice(msrs.nmsrs as usize).iter() {
                match WHV_REGISTER_NAME::from_portable(entry.index) {
                    Some(reg_name) => {
                        msr_names.push(reg_name);

                        let mut reg_value: WHV_REGISTER_VALUE = Default::default();
                        reg_value.Reg64 = entry.data;
                        msr_values.push(reg_value);
                    },
                    None => println!("Ignoring unsupported msr: {:#x}",
                                     entry.index)
                }
            }
        }

        self.whp_context
            .borrow()
            .vp
            .set_registers(&msr_names, &msr_values)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }

    fn run(&self) -> VcpuResult<VcpuExit> {

        let mut whp_context = self.whp_context.borrow_mut();

        // In the case of MMIO and IO Port reads, we do not actually fill in the
        // data within the appropriate callbacks, as would normally be done. We
        // instead capture the necessary information (GPA or Port, respectively),
        // after performing a first round of IO port or MMIO emulation,
        // and pass it back via the whp_context to the VMM that is consuming
        // this VCPU, which will perform the actual read. The VMM will plug that
        // returned read data back into the whp_context, and another invocation
        // of the emulation will fill it in.

        match whp_context.last_exit_context.ExitReason {
            // Here we have that chronologically "second" round of emulation for
            // MMIO and IO port reads only. By this point, the VMM is calling
            // run() again, but the data from the last round of MMIO or IO port
            // read is stored in the whp_context. This code will only be entered
            // for read accesses of MMIO or IO Port operations.
            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                if whp_context.mmio_access_data.is_write == 0 {
                    whp_context.mmio_access_data.state = IoCallbackState::IoSetData;
                    self.handle_mmio_exit(&mut whp_context).unwrap();

                    // Explicitly clear the data
                    whp_context.mmio_access_data = Default::default();
                }
            }

            WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                if whp_context.io_access_data.is_write == 0 {
                    whp_context.io_access_data.state = IoCallbackState::IoSetData;
                    self.handle_io_port_exit(&mut whp_context).unwrap();

                    // Explicitly clear the data 
                    whp_context.io_access_data = Default::default();
                }
            }
            _ => {}
        };

        // In the case of an MMIO or IO Port read, the guest physical address
        // or port (respectively) will be recorded by the MMIO and IO Port
        // emulation callbacks (respectively). This data will be returned to
        // the caller VMM in the VpuExit value, along with pointers to where
        // the data should actually be written after the MMIO or IO port read
        // performed by the VMM. Before calling run() on the VirtualProcessor
        // again, this function will emulate the MMIO or IO Port read again,
        // actually storing the data in the byte array that the hypervisor
        // will return to the guest. Thus, in the read case, there are two calls
        // to IO emulator callbacks: Once after the run() to get the GPA or Port,
        // and once before the next run(), to store the data from the read in
        // the buffer.

        // Chronologically "second" emulation, which closes the loop by supplying
        // the read data requested by the previous run

        whp_context.last_exit_context = whp_context.vp.run().unwrap();
        if whp_context.last_exit_context.ExitReason !=
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess {
        }

        let exit_reason =
            match whp_context.last_exit_context.ExitReason {
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonNone => VcpuExit::Unknown,
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonMemoryAccess => {
                    whp_context.mmio_access_data.state = IoCallbackState::IoGetAccessSize;
                    self.handle_mmio_exit(&mut whp_context).unwrap();

                    let mmio_data_ptr = whp_context.mmio_access_data.mmio_data.as_mut_ptr();
                    let size = whp_context.mmio_access_data.mmio_data_len;
                    let mut mmio_data: &mut [u8];
                    let mmio_addr = whp_context.mmio_access_data.gpa;

                    unsafe {
                        mmio_data = std::slice::from_raw_parts_mut( mmio_data_ptr, size);
                    }

                    if whp_context.mmio_access_data.is_write == 0 {
                        return Ok(VcpuExit::MmioRead(mmio_addr, mmio_data));
                    }
                    else {
                        if let Some((evt, datamatch)) = self.mmio_events.get(&mmio_addr) {
                            if datamatch.matches(mmio_data) {
                                // debug!("Mmio match @ {:x}", mmio_addr);
                                evt.write(1);
                                // forcefully release the borrowed context.
                                // This is a quick hack to avoid multiple borrows.
                                // The alternative would be to propagate an exit (e.g. Unknown or
                                // a new one and let the caller run the vcpu again).
                                { let a = whp_context; }
                                return self.run();
                            }
                        }
                        return Ok(VcpuExit::MmioWrite(
                            whp_context.mmio_access_data.gpa,
                            mmio_data,
                        ));
                    }
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64IoPortAccess => {
                    whp_context.io_access_data.state = IoCallbackState::IoGetAccessSize;
                    self.handle_io_port_exit(&mut whp_context).unwrap();
                    let io_data_ptr = whp_context.io_access_data.io_data.as_mut_ptr();

                    let port = whp_context.io_access_data.port;
                    let size = whp_context.io_access_data.io_data_len;

                    let mut io_data: &mut [u8];

                    unsafe {
                        io_data = std::slice::from_raw_parts_mut(io_data_ptr, size);
                    }

                    if whp_context.io_access_data.is_write == 0 {
                        return Ok(VcpuExit::IoIn(port, io_data));
                    }
                    else {
                        if let Some((evt, datamatch)) = self.pio_events.get(&(port as u64)) {
                            if datamatch.matches(io_data) {
                                println!("pio match");
                                evt.write(1);
                                // forcefully release the borrowed context
                                { let a = whp_context; }
                                return self.run();
                            }
                        }
                        return Ok(VcpuExit::IoOut(
                            whp_context.io_access_data.port,
                            io_data,
                        ));
                    }
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnrecoverableException => {
                    VcpuExit::Exception
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonInvalidVpRegisterValue => {
                    VcpuExit::FailEntry
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonUnsupportedFeature => {
                    VcpuExit::UnsupportedFeature
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64InterruptWindow => {
                    VcpuExit::IrqWindowOpen
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Halt => {
                    VcpuExit::Hlt
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64ApicEoi => {
                    let eoi_ctxt = unsafe {
                        whp_context.last_exit_context.anon_union.ApicEoi
                    };

                    // NOTE(lpetrut): one of the main purposes of resample events
                    // is to avoid generating Eoi exits. We'll still get an exit
                    // but we're not going to propagate it, emulating KVM's
                    // API.
                    // debug!("Resample {}", &eoi_ctxt.InterruptVector);
                    // TODO(lpetrut): check why we're getting some unexpected
                    // resample events.
                    match self.resample_events.get(&eoi_ctxt.InterruptVector) {
                        Some(evt) => {
                            unsafe {
                                // debug!("resample");
                                evt.write(1);
                            }
                            // forcefully release the borrowed context
                            { let a = whp_context; }
                            self.run()?
                        },
                        None => VcpuExit::IoapicEoi
                    }
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64MsrAccess => {
                    VcpuExit::MsrAccess
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonX64Cpuid => {
                    VcpuExit::CpuId
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonException => {
                    VcpuExit::Exception
                }
                WHV_RUN_VP_EXIT_REASON::WHvRunVpExitReasonCanceled => {
                    VcpuExit::Canceled
                }
            };

        Ok(exit_reason)
    }

    fn get_lapic(&self) -> VcpuResult<LapicState> {
        let state: LapicStateRaw = self.whp_context.borrow().vp.get_lapic()
                    .map_err(|_| io::Error::last_os_error())?;

        // TODO(lpetrut): Those two structures are identical,
        // for now. We should probably define this somewhere (vmm-vcpu
        // or libwhp) and avoid this unsafe cast.
        let state = unsafe {
            std::mem::transmute::<LapicStateRaw, LapicState>(state)
        };
        Ok(state)
    }

    fn set_lapic(&self, klapic: &LapicState) -> VcpuResult<()> {
        let klapic = unsafe {
            std::mem::transmute::<&LapicState, &LapicStateRaw>(&klapic)
        };
        self.whp_context.borrow().vp.set_lapic(klapic)
            .map_err(|_| io::Error::last_os_error())?;

        Ok(())
    }
}

impl<'a> EmulatorCallbacks for WhpContext<'a> {
    fn io_port(
        &mut self,
        io_access: &mut WHV_EMULATOR_IO_ACCESS_INFO,
    ) -> HRESULT {

        assert!((io_access.AccessSize == 1) ||
                (io_access.AccessSize == 2) ||
                (io_access.AccessSize == 4));

        let is_write = io_access.Direction;
        let size_bytes = io_access.AccessSize as usize;

        let src: *const u8;
        let dst: *mut u8;

        let ret_val: HRESULT;

        // Copy the port and data to the WhpIoAccessData in the WHP context
        // so that the calling VMM knows what to read/write
        self.io_access_data.port = io_access.Port;
        self.io_access_data.io_data_len = size_bytes;
        self.io_access_data.is_write = is_write;

        if is_write == 1 {
            // Manually copy the data itself.
            src = &io_access.Data as *const _ as *const u8;
            dst = self.io_access_data.io_data.as_mut_ptr();

            // Safe because the API guarantees that the Data stored in the IO access
            // has size AccessSize in bytes and we've already checked that the size
            // is less that the size of our destination buffer
            unsafe {
                std::ptr::copy_nonoverlapping(src, dst, size_bytes);
            }
            
            ret_val = S_OK;
        }
        else {
            match self.io_access_data.state {
                IoCallbackState::IoGetAccessSize => {
                    // We've gotten and stored the access size; return a pending
                    // value so that the hypervisor doesn't complete the emulation
                    // yet
                    ret_val = E_PENDING;
                },
                IoCallbackState::IoSetData => {
                    // The calling VMM has performed the read, supply that data to the 
                    // WHV_EMULATOR_IO_ACCESS_INFO Data to complete the read for the 
                    // guest
                    src = self.io_access_data.io_data.as_ptr();
                    dst = &mut io_access.Data as *mut _ as *mut u8;

                    // Safe because the API guarantees that the Data stored in the IO access
                    // has size AccessSize in bytes and we've already checked that the size
                    // is less that the size of our destination buffer
                    unsafe {
                        std::ptr::copy_nonoverlapping(src, dst, size_bytes);
                    }

                    // We will return S_OK so that the hypervisor will complete
                    // the IO operation
                    ret_val = S_OK;
                },
                _ => {
                    assert!(false, "Invalid IO Emulator state");
                    ret_val = E_FAIL;
                }
            }
        }

        ret_val
    }

    fn memory(
        &mut self,
        memory_access: &mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
    ) -> HRESULT {

        let mut ret_val: HRESULT = S_OK;

        assert!((memory_access.AccessSize > 0) &&
                (memory_access.AccessSize <= 8));

        let is_write = memory_access.Direction;
        let size_bytes = memory_access.AccessSize as usize;
    
        // Copy the guest physical address and data to the WhpMmioAccessData
        // in the WHP context so that the calling VMM knows what to read/write
        self.mmio_access_data.gpa = memory_access.GpaAddress;
        self.mmio_access_data.mmio_data_len = size_bytes;
        self.mmio_access_data.is_write = is_write;

        if is_write == 1 {
            // Write the data to our local storage
            self.mmio_access_data.mmio_data = memory_access.Data;
        }
        else {
            match self.mmio_access_data.state {
                IoCallbackState::IoGetAccessSize => {
                    // We've gotten and stored the access size; return a pending
                    // value so that the hypervisor doesn't complete the emulation
                    // yet
                    ret_val = E_PENDING;
                },
                IoCallbackState::IoSetData => {
                    // The calling VMM has performed the read; supply that data to the
                    // WHV_EMULATOR_MEMORY_ACCESS_INFO Data to complete the read for the
                    // guest
                    memory_access.Data = self.mmio_access_data.mmio_data;

                    // We will return S_OK so that the hypervisor will complete
                    // the IO operation
                    ret_val = S_OK;
                },
                _ => assert!(false, "Invalid IO Emulator state")
            }
        }

        ret_val
    }

    fn get_virtual_processor_registers(
        &mut self,
        register_names: &[WHV_REGISTER_NAME],
        register_values: &mut [WHV_REGISTER_VALUE],
    ) -> HRESULT {
        self.vp
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
            .translate_gva(gva, translate_flags)
            .unwrap();
        *translation_result = translation_result1.ResultCode;
        *gpa = gpa1;
        S_OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub use platform::Partition;
    use vmm_vcpu::x86_64::{CpuIdEntry2, MsrEntry, msr_index};
    use common::*;
    pub use std::*;

    fn setup_vcpu_test(p: &mut Partition) {
        let mut property: WHV_PARTITION_PROPERTY = Default::default();
        property.ProcessorCount = 1;

        p.set_property(
            WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
            &property,
        )
        .unwrap();
        p.setup().unwrap();
    }

    #[test]
    fn test_set_get_vcpu_regs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vcpu = WhpVirtualProcessor::create_whp_vcpu_by_partition(p, vp_index).unwrap();

        let std_regs_in = StandardRegisters {
            rax: 0xabcd0000abcd0000,
            rbx: 0xabcd0000abcd0001,
            rcx: 0xabcd0000abcd0002,
            rdx: 0xabcd0000abcd0003,
            rsi: 0xabcd0000abcd0004,
            rdi: 0xabcd0000abcd0005,
            rsp: 0xabcd0000abcd0006,
            rbp: 0xabcd0000abcd0007,
            r8: 0xabcd0000abcd0008,
            r9: 0xabcd0000abcd0009,
            r10: 0xabcd0000abcd000a,
            r11: 0xabcd0000abcd000b,
            r12: 0xabcd0000abcd000c,
            r13: 0xabcd0000abcd000d,
            r14: 0xabcd0000abcd000e,
            r15: 0xabcd0000abcd000f,
            rip: 0xabcd0000abcd0010,
            rflags: 0xabcd0000abcd0011,
        };

        vcpu.set_regs(&std_regs_in).unwrap();
        let std_regs_out = vcpu.get_regs().unwrap();

        assert_eq!(
            std_regs_in, std_regs_out,
            "StandardRegister values set and gotten do not match"
        );
    }

    #[test]
    fn test_set_get_vcpu_sregs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vp = p.create_virtual_processor(vp_index).unwrap();
        let vcpu = WhpVirtualProcessor::create_whp_vcpu(vp).unwrap();

        // Get the initial set of special registers
        let mut sregs = vcpu.get_sregs().unwrap();

        // Make some modifications to them
        sregs.cs.limit = 0xffff;
        sregs.ds.limit = 0xffff;
        sregs.es.limit = 0xffff;
        sregs.fs.limit = 0xffff;
        sregs.gs.limit = 0xffff;
        sregs.ss.limit = 0xffff;
        sregs.gdt.base = 0xa000;
        sregs.gdt.limit = 0xff;
        sregs.idt.base = 0xb000;
        sregs.idt.limit = 0xff;
        sregs.apic_base = 0xa0000000;

        // Set the modified values
        vcpu.set_sregs(&sregs).unwrap();
        let std_regs_out = vcpu.get_sregs().unwrap();

        assert_eq!(
            sregs, std_regs_out,
            "SpecialRegister values set and gotten do not match"
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_set_and_get_msrs() {
        let mut p: Partition = Partition::new().unwrap();
        setup_vcpu_test(&mut p);

        let vp_index: UINT32 = 0;
        let vcpu = WhpVirtualProcessor::create_whp_vcpu_by_partition(p, vp_index).unwrap();

        let entries = [
            MsrEntry {
                index: 0x174,
                reserved: 0,
                data: 25
            },
            MsrEntry {
                index: msr_index::MSR_IA32_SYSENTER_EIP,
                reserved: 0,
                data: 7890
            },
            MsrEntry {
                // This is supposed to be an unsupported msr.
                index: 0xffff,
                reserved: 0,
                data: 0xff
            }
        ];
        let array_len = entries.len();

        // Create a vector large enough to hold the MSR entry defined above in a
        // MsrEntries structure
        let entries_bytes = array_len * mem::size_of::<MsrEntry>();
        let msrs_vec: Vec<u8> =
            Vec::with_capacity(mem::size_of::<MsrEntries>() + entries_bytes);
        let msrs: &mut MsrEntries = unsafe {
            &mut *(msrs_vec.as_ptr() as *mut MsrEntries)
        };

        // Set the number of entries
        msrs.nmsrs = array_len as u32;

        // Copy the entries into the vector
        unsafe {
            let src = &entries as *const MsrEntry as *const u8;
            let dst = msrs.entries.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(src, dst, entries_bytes);
        }

        unsafe {
            assert_eq!(
                msrs.entries.as_slice(array_len)[0].index,
                0x174,
                "Failure converting/copying MSR entry[0].index");
            assert_eq!(
                msrs.entries.as_slice(array_len)[0].data,
                25,
                "Failure converting/copying MSR entry[0].data");
            assert_eq!(
                msrs.entries.as_slice(array_len)[1].index,
                msr_index::MSR_IA32_SYSENTER_EIP,
                "Failure converting/copying MSR entry[1].index");
            assert_eq!(
                msrs.entries.as_slice(array_len)[1].data,
                7890,
                "Failure converting/copying MSR entry[1].data");
        }

        vcpu.set_msrs(msrs).unwrap();

        // Now test getting the data back
        let out_entries = [
            MsrEntry {
                index: 0x174,
                ..Default::default()
            },
            MsrEntry {
                index: msr_index::MSR_IA32_SYSENTER_EIP,
                ..Default::default()
            },
            MsrEntry {
                index: 0xffff,
                ..Default::default()
            }
        ];

        // Create a vector large enough to hold the MSR entry defined above in a
        // MsrEntries structure
        let out_entries_bytes = out_entries.len() * mem::size_of::<MsrEntry>();
        let out_msrs_vec: Vec<u8> =
            Vec::with_capacity(mem::size_of::<MsrEntries>() + out_entries_bytes);
        let mut out_msrs: &mut MsrEntries = unsafe {
            &mut *(out_msrs_vec.as_ptr() as *mut MsrEntries)
        };

        // Set the number of entries
        out_msrs.nmsrs = out_entries.len() as u32;

        // Copy the entries into the vector
        unsafe {
            let src = &out_entries as *const MsrEntry as *const u8;
            let dst = out_msrs.entries.as_ptr() as *mut u8;
            std::ptr::copy_nonoverlapping(src, dst, out_entries_bytes);
        }

        vcpu.get_msrs(&mut out_msrs).unwrap();

        assert_eq!(msrs.nmsrs, out_msrs.nmsrs, "Mismatch between number of get and set MSRs");

        unsafe {
            let num_msrs = msrs.nmsrs as usize;
            for (idx, entry) in msrs.entries.as_slice(num_msrs).iter().enumerate() {
                let out_entry = out_msrs.entries.as_slice(num_msrs)[idx];
                println!("entry[{}]: {:?}", idx, entry);
                println!("out_entry[{}]: {:?}", idx, out_entry);
                assert_eq!(
                    entry.index, 
                    out_entry.index, 
                    "MSR index gotten from vCPU did not match input"
                );


                match WHV_REGISTER_NAME::from_portable(entry.index) {
                    Some(_) => {
                        assert_eq!(
                            entry.data,
                            out_entry.data,
                            "MSR data gotten from vCPU did not match input"
                        );
                    },
                    None => {
                        assert_eq!(
                            0,
                            out_entry.data,
                            "Unsupported MSR data is supposed to be null."
                        );
                    }
                }
            }
        }
    }
}
