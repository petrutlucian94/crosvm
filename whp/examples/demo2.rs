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

///
/// This demo uses the WhpVirtualProcessor, and its underlying implementation
/// of the Vcpu trait, as the virtual processor of the virtual machine
///


extern crate libc;
extern crate libwhp;
extern crate vmm_vcpu;

use std::fs::File;
use std::io::prelude::*;
use std::io::{self, Write};
use std::path::PathBuf;

use libwhp::memory::*;
use libwhp::*;

use whp::vcpu::*;
use whp::vcpu_structs::*;

use vmm_vcpu::vcpu::{Vcpu, VcpuExit};
use vmm_vcpu::x86_64::{
    StandardRegisters, SpecialRegisters, SegmentRegister,
};

const CPUID_EXT_HYPERVISOR: UINT32 = 1 << 31;

const PDE64_PRESENT: u64 = 1;
const PDE64_RW: u64 = 1 << 1;
const PDE64_USER: u64 = 1 << 2;
const PDE64_PS: u64 = 1 << 7;
const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

const CR0_PE: u64 = 1;
const CR0_MP: u64 = 1 << 1;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_WP: u64 = 1 << 16;
const CR0_AM: u64 = 1 << 18;
const CR0_PG: u64 = 1 << 31;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

const INT_VECTOR: u32 = 0x35;

#[allow(non_snake_case)]
#[derive(Debug, Copy, Clone, Default)]
#[repr(C)]
struct CpuInfo {
    apic_enabled: bool,
}

fn main() {
    println!("\n********** DEMO USING WHP VIRTUAL PROCESSOR **********\n");
    check_hypervisor();

    let mut p = Partition::new().unwrap();

    let apic_present = is_apic_present();

    let mut cpu_info = CpuInfo {
        apic_enabled: false,
    };

    setup_partition(&mut p, &mut cpu_info, apic_present);

    let mem_size = 0x300000;
    let mut payload_mem = VirtualMemory::new(mem_size).unwrap();

    let guest_address: WHV_GUEST_PHYSICAL_ADDRESS = 0;

    let _mapping = p
        .map_gpa_range(
            &payload_mem,
            guest_address,
            payload_mem.get_size() as UINT64,
            WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagRead
                | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagWrite
                | WHV_MAP_GPA_RANGE_FLAGS::WHvMapGpaRangeFlagExecute,
        )
        .unwrap();

    let mut vcpu = WhpVirtualProcessor::create_whp_vcpu_by_partition(p, 0).unwrap();

    setup_long_mode(&mut vcpu, &payload_mem);
    read_payload(&mut payload_mem);

    if cpu_info.apic_enabled {
        // Set the APIC base and send an interrupt to the VCPU
        set_apic_base(&mut vcpu);
        vcpu.interrupt(INT_VECTOR).unwrap();
        set_delivery_notifications(&vcpu);
    }

    loop {
        let exit_reason = vcpu.run();

        match exit_reason {
            Ok(run) => match run {
                VcpuExit::IoIn(port, data) => {
                    handle_io_access_in(port, data);
                }
                VcpuExit::IoOut(port, data) => {
                    handle_io_access_out(port, data);
                }
                VcpuExit::MmioRead(addr, data) => {
                    handle_mmio_read(addr, data);
                }
                VcpuExit::MmioWrite(addr, data) => {
                    handle_mmio_write(addr, data);
                }
                VcpuExit::Canceled => {
                    println!("Canceled");
                }
                VcpuExit::CpuId => {
                    handle_cpuid_exit(&vcpu);
                }
                VcpuExit::MsrAccess => {
                    handle_msr_exit(&vcpu);
                }
                VcpuExit::IoapicEoi => {
                    println!("Apic EOI");
                }
                VcpuExit::IrqWindowOpen => {
                    println!("IRQ Windows open");
                }
                VcpuExit::Exception => {
                    let exit_context = unsafe { *vcpu.get_run_context() };
                    println!("Exit Reason: {:?}", exit_context.ExitReason);
                    println!("Exception. Breaking");
                    break;
                }
                VcpuExit::Hlt => {
                    println!("All done!");
                    break;
                }
                _ => {
                    println!("Unknown/unaccounted for exit");
                }
            },
            // The unwrap on raw_os_error can only fail if we have a logic
            // error in our code in which case it is better to panic.
            Err(ref e) => {
                match e.raw_os_error().unwrap() {
                    _ => {
                        println!("Failure during vcpu run: {}", e);
                        break;
                    }
                }
            }
        }

        // With the APIC enabled, the hlt instruction will not completely halt
        // the processor; it'll just halt it until another interrupt is
        // received, so we don't receive the VMexit that we used to use to end
        // VCPU execution. Since WHV will not let us disable the APIC in the usual
        // means (eg, via the global enable flag of the APIC_BASE register,
        // etc), teriminate the VCPU execution loop when both interrupts we're
        // expecting have been received. Plus we get to exercise the new
        // counter APIs.
        if all_interrupts_received(&vcpu) {
            println!("All interrupts received. All done!");
            break;
        }
    }
}

fn handle_io_access_out(port: u16, data: &[u8]) {
    if port == 42 {
        io::stdout().write(data).unwrap();
    }
    else {
        println!("Unsupported IO port");
    }
}

fn handle_io_access_in(port: u16, data: &mut [u8]) {
    if port == 43 {
        // Simulate doing the read by writing a value to the buffer, which
        // the example will later "read"
        data[0] = 99;
    }
}

fn handle_mmio_read(gpa: u64, data: &mut [u8]) { 
    let ptr = data as *mut _ as *mut u64;

    match data.len() {
        8 => {
            unsafe {
                *ptr = 0x21001;
                println!("MMIO read: 0x{:x} at 0x{:x}", *ptr, gpa);
            }
        },
        1 => {
            unsafe {
                *ptr = 88;
                println!("MMIO read: 0x{:x} at 0x{:x}", *ptr, gpa);
            }
        },
        _ => println!("Unsupported MMIO access size: {}", data.len()),
    }
}

fn handle_mmio_write(gpa: u64, data: &[u8] ) {
    let ptr = data as *const _ as *const u64;

    match data.len() {
        8 => {
            let value = unsafe {*ptr};
            println!("MMIO write: 0x{:x} at 0x{:x}", value, gpa);
        },
        1 => {
            let value = unsafe {*ptr};
            println!("MMIO write: 0x{:x} at 0x{:x}", value, gpa);
        },
        _ => println!("Unsupported MMIO access size: {}", data.len()),
    }
}

/*
 * Terminate VCPU execution when two interrupts have been received by the guest:
 * one from the host, and one from the guest
 */
fn all_interrupts_received(vcpu: &WhpVirtualProcessor) -> bool {
    let counters: WHV_PROCESSOR_COUNTERS = vcpu
        .get_processor_counters(WHV_PROCESSOR_COUNTER_SET::WHvProcessorCounterSetApic)
        .unwrap();
    let apic_counters = unsafe { counters.ApicCounters };

    if apic_counters.EoiAccessCount == 2 {
        true
    } else {
        false
    }
}

fn set_apic_base(vcpu: &mut WhpVirtualProcessor) {
    // Page table translations for this guest only cover the first 1GB of memory,
    // and the default APIC base falls above that. Set the APIC base to
    // something lower, within our range of virtual memory

    // Get the existing state of the standard registers
    let mut sregs: SpecialRegisters = vcpu.get_sregs().unwrap();
    
    // Start with the default APIC base register value
    let mut flags = sregs.apic_base;

    // Mask off the bottom 12 bits, which are used to store flags
    flags = flags & 0xfff;

    // Set the APIC base to something lower within our translatable address
    // space
    let new_apic_base = 0x0fee_0000;
    sregs.apic_base = new_apic_base | flags;
    vcpu.set_sregs(&sregs).unwrap();
}

fn set_delivery_notifications(vcpu: &WhpVirtualProcessor) {
    vcpu.set_delivery_notifications();
}

fn handle_msr_exit(vcpu: &WhpVirtualProcessor) {
    let exit_context = unsafe { *vcpu.get_run_context() };

    let msr_access = unsafe { exit_context.anon_union.MsrAccess };

    let mut regs: StandardRegisters = vcpu.get_regs().unwrap();

    regs.rip = exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;

    match msr_access.MsrNumber {
        1 => {
            if msr_access.AccessInfo.IsWrite() == 1 {
                println!(
                    "MSR write. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, msr_access.Rax, msr_access.Rdx
                );
            }
            else {
                let rax = 0x2000;
                let rdx = 0x2001;

                regs.rax = rax;
                regs.rdx = rdx;

                println!(
                    "MSR read. Number: 0x{:x}, Rax: 0x{:x}, Rdx: 0x{:x}",
                    msr_access.MsrNumber, rax, rdx
                );
            }
        }
        _ => {
            println!("Unknown MSR number: {:#x}", msr_access.MsrNumber);
        }
    }

    vcpu.set_regs(&regs).unwrap();
}

fn handle_cpuid_exit(vcpu: &WhpVirtualProcessor) {
    let exit_context = unsafe { *vcpu.get_run_context() };

    let cpuid_access = unsafe { exit_context.anon_union.CpuidAccess };

    let mut regs: StandardRegisters = vcpu.get_regs().unwrap();
    regs.rip = exit_context.VpContext.Rip + exit_context.VpContext.InstructionLength() as u64;
    regs.rax = cpuid_access.DefaultResultRax;
    regs.rbx = cpuid_access.DefaultResultRbx;
    regs.rcx = cpuid_access.DefaultResultRcx;
    regs.rdx = cpuid_access.DefaultResultRdx;

    match cpuid_access.Rax {
        1 => {
            regs.rcx = CPUID_EXT_HYPERVISOR as UINT64;
        }
        _ => {
            println!("Unknown CPUID leaf: {}", cpuid_access.Rax);
        }
    }

    vcpu.set_regs(&regs).unwrap();
}

fn setup_partition(p: &mut Partition, cpu_info: &mut CpuInfo, apic_present: bool) {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();
    property.ProcessorCount = 1;
    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeProcessorCount,
        &property,
    )
    .unwrap();

    property = Default::default();
    unsafe {
        property.ExtendedVmExits.set_X64CpuidExit(1);
        property.ExtendedVmExits.set_X64MsrExit(1);
        property.ExtendedVmExits.set_ExceptionExit(1);
    }

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeExtendedVmExits,
        &property,
    )
    .unwrap();

    let cpuids: [UINT32; 1] = [1];
    p.set_property_cpuid_exits(&cpuids).unwrap();

    let mut cpuid_results: [WHV_X64_CPUID_RESULT; 1] = Default::default();

    cpuid_results[0].Function = 0x40000000;
    let mut id_reg_values: [UINT32; 3] = [0; 3];
    let id = "libwhp\0";
    unsafe {
        std::ptr::copy_nonoverlapping(id.as_ptr(), id_reg_values.as_mut_ptr() as *mut u8, id.len());
    }
    cpuid_results[0].Ebx = id_reg_values[0];
    cpuid_results[0].Ecx = id_reg_values[1];
    cpuid_results[0].Edx = id_reg_values[2];

    p.set_property_cpuid_results(&cpuid_results).unwrap();

    if apic_present != false {
        enable_apic(p, cpu_info);
    }

    p.setup().unwrap();
}

fn is_apic_present() -> bool {
    let capability: WHV_CAPABILITY =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeFeatures).unwrap();
    let features: WHV_CAPABILITY_FEATURES = unsafe { capability.Features };

    if features.LocalApicEmulation() != 0 {
        true
    } else {
        false
    }
}

fn enable_apic(p: &mut Partition, cpu_info: &mut CpuInfo) {
    let mut property: WHV_PARTITION_PROPERTY = Default::default();
    property.LocalApicEmulationMode =
        WHV_X64_LOCAL_APIC_EMULATION_MODE::WHvX64LocalApicEmulationModeXApic;

    p.set_property(
        WHV_PARTITION_PROPERTY_CODE::WHvPartitionPropertyCodeLocalApicEmulationMode,
        &property,
    )
    .unwrap();

    cpu_info.apic_enabled = true;
}

fn initialize_address_space(payload_mem: &VirtualMemory) -> u64 {
    let mem_addr = payload_mem.as_ptr() as u64;

    let pml4_addr: u64 = 0x9000;
    let pdpt_addr: u64 = 0xa000;
    let pd_addr: u64 = 0xb000;
    let pml4: u64 = mem_addr + pml4_addr;
    let pdpt: u64 = mem_addr + pdpt_addr;
    let pd: u64 = mem_addr + pd_addr;

    unsafe {
        *(pml4 as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
        *(pdpt as *mut u64) = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

        for i in 0..512 {
            *((pd + i * 8) as *mut u64) =
                (i << 21) + (PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS);
        }
    }

    // Return the PML4 guest physical address so the caller can use it to set CR3
    pml4_addr
}

fn setup_long_mode(vcpu: &mut WhpVirtualProcessor, payload_mem: &VirtualMemory) {
    let pml4_addr = initialize_address_space(payload_mem);

    // Get the current state 
    let mut regs: StandardRegisters = vcpu.get_regs().unwrap();
    let mut sregs: SpecialRegisters = vcpu.get_sregs().unwrap();

    // Set the standard registers first by overwriting the ones we care about
    // for setup

    // Start with the Interrupt Flag off; guest will enable it when ready
    regs.rflags = 0x002;

    // Start the Instruction Pointer at 0
    regs.rip = 0;

    // Create stack with stack base at high end of mapped payload
    regs.rsp = payload_mem.get_size() as UINT64;

    vcpu.set_regs(&regs).unwrap();

    // Now overwrite the special registers we care about for setting up long mode
    // cr3, cr4, cr0, Efer, Cs, Ds, Es, Fs, Gs, Ss
    sregs.cr3 = pml4_addr;
    sregs.cr4 = CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
    sregs.cr0 = CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
    sregs.efer = EFER_LME | EFER_LMA;
    
    // Set up a KM code segment that will be used for CS
    let mut code_segment: SegmentRegister = Default::default();
    code_segment.base = 0;
    code_segment.limit = 0xffffffff;
    code_segment.selector = 1 << 3;
    code_segment.type_ = 11;
    code_segment.present = 1;
    code_segment.dpl = 0;
    code_segment.db = 0;
    code_segment.s = 1;
    code_segment.l = 1;
    code_segment.g = 1;
    code_segment.avl = 0;
    code_segment.unusable = 0;
    code_segment.padding = 0;

    // Set up a KM data segment that will be used for DS, ES, FS, GS, and SS
    let mut data_segment: SegmentRegister = Default::default();
    data_segment.base = 0;
    data_segment.limit = 0xffffffff;
    data_segment.selector = 2 << 3;
    data_segment.type_ = 3;
    data_segment.present = 1;
    data_segment.dpl = 0;
    data_segment.db = 0;
    data_segment.s = 1;
    data_segment.l = 1;
    data_segment.g = 1;
    data_segment.avl = 0;
    data_segment.unusable = 0;
    data_segment.padding = 0;

    sregs.cs = code_segment;
    sregs.ds = data_segment;
    sregs.es = data_segment;
    sregs.fs = data_segment;
    sregs.gs = data_segment;
    sregs.ss = data_segment;

    vcpu.set_sregs(&sregs).unwrap();
}

fn read_payload(mem_addr: &mut VirtualMemory) {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("examples");
    p.push("payload");
    p.push("payload.img");

    let mut f = File::open(&p).expect(&format!(
        "Cannot find \"{}\". Run \"make\" in the same folder to build it",
        &p.to_str().unwrap()
    ));
    f.read(mem_addr.as_slice_mut()).unwrap();
}

fn check_hypervisor() {
    let capability =
        get_capability(WHV_CAPABILITY_CODE::WHvCapabilityCodeHypervisorPresent).unwrap();
    if unsafe { capability.HypervisorPresent } == FALSE {
        panic!("Hypervisor not present");
    }
}