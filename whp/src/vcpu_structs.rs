// Copyright 2018-2019 CrowdStrike, Inc.
// Copyright 2018 Cloudbase Solutions Srl
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
#![allow(non_snake_case)]

pub use libwhp::*;

use vmm_vcpu::x86_64::{FpuState, SegmentRegister, DescriptorTable, msr_index};

const NUM_XMM_REGS: usize = 16;
const NUM_FPMMX_REGS: usize = 8;

///
/// Enumerate the index at which each register will be stored within the
/// WinStandardRegisters so that we can get/set both WHV_REGISTER_NAMES and
/// WHV_REGISTER_VALUES with the same enum
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinStandardRegIndex {
    Rax = 0x00,
    Rcx = 0x01,
    Rdx = 0x02,
    Rbx = 0x03,
    Rsp = 0x04,
    Rbp = 0x05,
    Rsi = 0x06,
    Rdi = 0x07,
    R8 = 0x08,
    R9 = 0x09,
    R10 = 0x0A,
    R11 = 0x0B,
    R12 = 0x0C,
    R13 = 0x0D,
    R14 = 0x0E,
    R15 = 0x0F,
    Rip = 0x10,
    Rflags = 0x11,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the StandardRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinStandardRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinStandardRegisters {
    pub names: [WHV_REGISTER_NAME; 18],
    pub values: [WHV_REGISTER_VALUE; 18],
}

impl Default for WinStandardRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinStandardRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinStandardRegIndex::Rax as usize] = WHV_REGISTER_NAME::WHvX64RegisterRax;
        mapping.names[WinStandardRegIndex::Rcx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRcx;
        mapping.names[WinStandardRegIndex::Rdx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRdx;
        mapping.names[WinStandardRegIndex::Rbx as usize] = WHV_REGISTER_NAME::WHvX64RegisterRbx;
        mapping.names[WinStandardRegIndex::Rsp as usize] = WHV_REGISTER_NAME::WHvX64RegisterRsp;
        mapping.names[WinStandardRegIndex::Rbp as usize] = WHV_REGISTER_NAME::WHvX64RegisterRbp;
        mapping.names[WinStandardRegIndex::Rsi as usize] = WHV_REGISTER_NAME::WHvX64RegisterRsi;
        mapping.names[WinStandardRegIndex::Rdi as usize] = WHV_REGISTER_NAME::WHvX64RegisterRdi;
        mapping.names[WinStandardRegIndex::R8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR8;
        mapping.names[WinStandardRegIndex::R9 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR9;
        mapping.names[WinStandardRegIndex::R10 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR10;
        mapping.names[WinStandardRegIndex::R11 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR11;
        mapping.names[WinStandardRegIndex::R12 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR12;
        mapping.names[WinStandardRegIndex::R13 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR13;
        mapping.names[WinStandardRegIndex::R14 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR14;
        mapping.names[WinStandardRegIndex::R15 as usize] = WHV_REGISTER_NAME::WHvX64RegisterR15;
        mapping.names[WinStandardRegIndex::Rip as usize] = WHV_REGISTER_NAME::WHvX64RegisterRip;
        mapping.names[WinStandardRegIndex::Rflags as usize] = WHV_REGISTER_NAME::WHvX64RegisterRflags;

        mapping
    }
}

///
/// Enumerate the index at which each register will be stored within the
/// WinSpecialRegisters
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinSpecialRegIndex {
    Cs,
    Ds,
    Es,
    Fs,
    Gs,
    Ss,
    Tr,
    Ldt,
    Gdt,
    Idt,
    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Cr8,
    Efer,
    ApicBase,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the SpecialRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinSpecialRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinSpecialRegisters {
    pub names: [WHV_REGISTER_NAME; 17],
    pub values: [WHV_REGISTER_VALUE; 17],
}

impl Default for WinSpecialRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinSpecialRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinSpecialRegIndex::Cs as usize] = WHV_REGISTER_NAME::WHvX64RegisterCs;
        mapping.names[WinSpecialRegIndex::Ds as usize] = WHV_REGISTER_NAME::WHvX64RegisterDs;
        mapping.names[WinSpecialRegIndex::Es as usize] = WHV_REGISTER_NAME::WHvX64RegisterEs;
        mapping.names[WinSpecialRegIndex::Fs as usize] = WHV_REGISTER_NAME::WHvX64RegisterFs;
        mapping.names[WinSpecialRegIndex::Gs as usize] = WHV_REGISTER_NAME::WHvX64RegisterGs;
        mapping.names[WinSpecialRegIndex::Ss as usize] = WHV_REGISTER_NAME::WHvX64RegisterSs;

        mapping.names[WinSpecialRegIndex::Tr as usize] = WHV_REGISTER_NAME::WHvX64RegisterTr;
        mapping.names[WinSpecialRegIndex::Ldt as usize] = WHV_REGISTER_NAME::WHvX64RegisterLdtr;
        mapping.names[WinSpecialRegIndex::Gdt as usize] = WHV_REGISTER_NAME::WHvX64RegisterGdtr;
        mapping.names[WinSpecialRegIndex::Idt as usize] = WHV_REGISTER_NAME::WHvX64RegisterIdtr;

        mapping.names[WinSpecialRegIndex::Cr0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr0;
        mapping.names[WinSpecialRegIndex::Cr2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr2;
        mapping.names[WinSpecialRegIndex::Cr3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr3;
        mapping.names[WinSpecialRegIndex::Cr4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr4;
        mapping.names[WinSpecialRegIndex::Cr8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterCr8;

        mapping.names[WinSpecialRegIndex::Efer as usize] = WHV_REGISTER_NAME::WHvX64RegisterEfer;
        mapping.names[WinSpecialRegIndex::ApicBase as usize] = WHV_REGISTER_NAME::WHvX64RegisterApicBase;

        mapping
    }
}

///
/// Enumerate the index at which each register will be stored within the
/// WinFpuRegisters
/// 
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinFpRegIndex {
    Xmm0 = 0,
    Xmm1,
    Xmm2,
    Xmm3,
    Xmm4,
    Xmm5,
    Xmm6,
    Xmm7,
    Xmm8,
    Xmm9,
    Xmm10,
    Xmm11,
    Xmm12,
    Xmm13,
    Xmm14,
    Xmm15,
    FpMmx0 = 16,
    FpMmx1,
    FpMmx2,
    FpMmx3,
    FpMmx4,
    FpMmx5,
    FpMmx6,
    FpMmx7,
    Fcs = 24,
    Xcs = 25,
}

///
/// Create a structure to hold the corresponding arrays of the WHV_REGISTER_NAMEs
/// and WHV_REGISTER_VALUEs that comprise the FpuRegisters, with
/// WHV_REGISTER_NAMEs prepopulated on default initialization, and both arrays
/// accessible via the WinFpuRegIndex enum defined above
///
#[derive(Copy, Clone)]
pub struct WinFpuRegisters {
    pub names: [WHV_REGISTER_NAME; 26],
    pub values: [WHV_REGISTER_VALUE; 26],
}

impl Default for WinFpuRegisters {
    fn default() -> Self {
        //unsafe { ::std::mem::zeroed() }
        let mut mapping = WinFpuRegisters {
            names: Default::default(),
            values: Default::default(),
        };

        mapping.names[WinFpRegIndex::Xmm0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm0;
        mapping.names[WinFpRegIndex::Xmm1 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm1;
        mapping.names[WinFpRegIndex::Xmm2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm2;
        mapping.names[WinFpRegIndex::Xmm3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm3;
        mapping.names[WinFpRegIndex::Xmm4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm4;
        mapping.names[WinFpRegIndex::Xmm5 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm5;
        mapping.names[WinFpRegIndex::Xmm6 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm6;
        mapping.names[WinFpRegIndex::Xmm7 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm7;
        mapping.names[WinFpRegIndex::Xmm8 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm8;
        mapping.names[WinFpRegIndex::Xmm9 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm9;
        mapping.names[WinFpRegIndex::Xmm10 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm10;
        mapping.names[WinFpRegIndex::Xmm11 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm11;
        mapping.names[WinFpRegIndex::Xmm12 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm12;
        mapping.names[WinFpRegIndex::Xmm13 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm13;
        mapping.names[WinFpRegIndex::Xmm14 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm14;
        mapping.names[WinFpRegIndex::Xmm15 as usize] = WHV_REGISTER_NAME::WHvX64RegisterXmm15;

        // Loop over the Floating Point MMX registers
        mapping.names[WinFpRegIndex::FpMmx0 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx0;
        mapping.names[WinFpRegIndex::FpMmx1 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx1;
        mapping.names[WinFpRegIndex::FpMmx2 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx2;
        mapping.names[WinFpRegIndex::FpMmx3 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx3;
        mapping.names[WinFpRegIndex::FpMmx4 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx4;
        mapping.names[WinFpRegIndex::FpMmx5 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx5;
        mapping.names[WinFpRegIndex::FpMmx6 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx6;
        mapping.names[WinFpRegIndex::FpMmx7 as usize] = WHV_REGISTER_NAME::WHvX64RegisterFpMmx7;

        // Fill in the remaining two control registers
        mapping.names[WinFpRegIndex::Fcs as usize] =
            WHV_REGISTER_NAME::WHvX64RegisterFpControlStatus;
        mapping.names[WinFpRegIndex::Xcs as usize] =
            WHV_REGISTER_NAME::WHvX64RegisterXmmControlStatus;

        mapping
    }
}

pub trait ConvertFpuState {
    fn to_portable(from: &Self) -> FpuState;
    fn from_portable(fpu_state: &FpuState) -> Self;
}

impl ConvertFpuState for WinFpuRegisters {
    fn to_portable(from: &Self) -> FpuState {
        // Perform the conversion from these fields to FpuState fields
        let mut fpu_state: FpuState = Default::default();

        unsafe {
            // Add the fields from the FP Control Status Register to the FPU State
            let fcs_reg = from.values[WinFpRegIndex::Fcs as usize].FpControlStatus;

            fpu_state.fcw = fcs_reg.anon_struct.FpControl;
            fpu_state.fsw = fcs_reg.anon_struct.FpStatus;
            fpu_state.ftwx = fcs_reg.anon_struct.FpTag;
            fpu_state.last_opcode = fcs_reg.anon_struct.LastFpOp;
            fpu_state.last_ip = fcs_reg.anon_struct.anon_union.LastFpRip;

            // Add the fields from the XMM Control Status Register to the FPU State
            let xcs_reg = from.values[WinFpRegIndex::Xcs as usize].XmmControlStatus;

            fpu_state.last_dp = xcs_reg.anon_struct.anon_union.LastFpRdp;
            fpu_state.mxcsr = xcs_reg.anon_struct.XmmStatusControl;
        }

        // Add the 16 XMM Regs to the FPU State
        for idx in 0..NUM_XMM_REGS {
            let from_idx = WinFpRegIndex::Xmm0 as usize + idx;
            unsafe {
                fpu_state.xmm[idx] = WHV_UINT128::to_u8_array(&from.values[from_idx].Reg128);
            }
        }

        // Add the 8 FP MMX Regs to the FPU State
        for idx in 0..NUM_FPMMX_REGS {
            let from_idx = WinFpRegIndex::FpMmx0 as usize + idx;
            unsafe {
                fpu_state.fpr[idx] = WHV_UINT128::to_u8_array(&from.values[from_idx].Reg128);
            }
        }

        fpu_state
    }

    fn from_portable(fpu_state: &FpuState) -> Self {
        let mut fregs: WinFpuRegisters = Default::default();

        unsafe {
            // Fill in the fields of the FP Control Status Register from the FpuState

            let mut fcs_reg: WHV_X64_FP_CONTROL_STATUS_REGISTER = Default::default();

            fcs_reg.anon_struct.FpControl = fpu_state.fcw;
            fcs_reg.anon_struct.FpStatus = fpu_state.fsw;
            fcs_reg.anon_struct.FpTag = fpu_state.ftwx;
            fcs_reg.anon_struct.LastFpOp = fpu_state.last_opcode;
            fcs_reg.anon_struct.anon_union.LastFpRip = fpu_state.last_ip;

            fregs.values[WinFpRegIndex::Fcs as usize].FpControlStatus = fcs_reg;

            // Fill in the fields of the XMM Control Status Register from the FpuState
            let mut xcs_reg: WHV_X64_XMM_CONTROL_STATUS_REGISTER = Default::default();

            xcs_reg.anon_struct.anon_union.LastFpRdp = fpu_state.last_dp;
            xcs_reg.anon_struct.XmmStatusControl = fpu_state.mxcsr;
            xcs_reg.anon_struct.XmmStatusControlMask = 0xffff;

            fregs.values[WinFpRegIndex::Xcs as usize].XmmControlStatus = xcs_reg;
        };

        // Add the 16 XMM Regs to the WinFpuRegisters
        for idx in 0..NUM_XMM_REGS {
            let to_idx = WinFpRegIndex::Xmm0 as usize + idx;
            fregs.values[to_idx].Reg128 = WHV_UINT128::from_u8_array(&fpu_state.xmm[idx]);
        }

        // Add the 8 FP MMX Regs to the WinFpuRegisters
        for idx in 0..NUM_FPMMX_REGS {
            let to_idx = WinFpRegIndex::FpMmx0 as usize + idx;
            fregs.values[to_idx].Reg128 = WHV_UINT128::from_u8_array(&fpu_state.fpr[idx]);
        }

        fregs
    }
}

pub trait ConvertMsrIndex {
    fn to_portable(from: &Self) -> Option<u32>;
    fn from_portable(arch_index: u32) -> Option<Self> where Self: Sized;
}

impl ConvertMsrIndex for WHV_REGISTER_NAME {
    fn to_portable(from: &Self) -> Option<u32> {
        match from {
            WHV_REGISTER_NAME::WHvX64RegisterTsc => Some(msr_index::MSR_IA32_TSC),
            WHV_REGISTER_NAME::WHvX64RegisterEfer => Some(msr_index::MSR_EFER),
            WHV_REGISTER_NAME::WHvX64RegisterKernelGsBase => Some(msr_index::MSR_KERNEL_GS_BASE),
            WHV_REGISTER_NAME::WHvX64RegisterApicBase => Some(msr_index::MSR_IA32_APICBASE),
            WHV_REGISTER_NAME::WHvX64RegisterPat => Some(msr_index::MSR_IA32_CR_PAT),
            WHV_REGISTER_NAME::WHvX64RegisterSysenterCs => Some(msr_index::MSR_IA32_SYSENTER_CS),
            WHV_REGISTER_NAME::WHvX64RegisterSysenterEip => Some(msr_index::MSR_IA32_SYSENTER_EIP),
            WHV_REGISTER_NAME::WHvX64RegisterSysenterEsp => Some(msr_index::MSR_IA32_SYSENTER_ESP),
            WHV_REGISTER_NAME::WHvX64RegisterStar => Some(msr_index::MSR_STAR),
            WHV_REGISTER_NAME::WHvX64RegisterLstar => Some(msr_index::MSR_LSTAR),
            WHV_REGISTER_NAME::WHvX64RegisterCstar => Some(msr_index::MSR_CSTAR),
            WHV_REGISTER_NAME::WHvX64RegisterSfmask => Some(msr_index::MSR_SYSCALL_MASK),
            _ => None
        }
    }

    fn from_portable(arch_index: u32) -> Option<Self> {
        match arch_index {
            msr_index::MSR_IA32_TSC => Some(WHV_REGISTER_NAME::WHvX64RegisterTsc),
            msr_index::MSR_EFER => Some(WHV_REGISTER_NAME::WHvX64RegisterEfer),
            msr_index::MSR_KERNEL_GS_BASE => Some(WHV_REGISTER_NAME::WHvX64RegisterKernelGsBase),
            msr_index::MSR_IA32_APICBASE => Some(WHV_REGISTER_NAME::WHvX64RegisterApicBase),
            msr_index::MSR_IA32_CR_PAT => Some(WHV_REGISTER_NAME::WHvX64RegisterPat),
            msr_index::MSR_IA32_SYSENTER_CS => Some(WHV_REGISTER_NAME::WHvX64RegisterSysenterCs),
            msr_index::MSR_IA32_SYSENTER_EIP => Some(WHV_REGISTER_NAME::WHvX64RegisterSysenterEip),
            msr_index::MSR_IA32_SYSENTER_ESP => Some(WHV_REGISTER_NAME::WHvX64RegisterSysenterEsp),
            msr_index::MSR_STAR => Some(WHV_REGISTER_NAME::WHvX64RegisterStar),
            msr_index::MSR_LSTAR => Some(WHV_REGISTER_NAME::WHvX64RegisterLstar),
            msr_index::MSR_CSTAR => Some(WHV_REGISTER_NAME::WHvX64RegisterCstar),
            msr_index::MSR_SYSCALL_MASK => Some(WHV_REGISTER_NAME::WHvX64RegisterSfmask),
            _ => None
        }
    }
}

pub trait ConvertSegmentRegister {
    fn to_portable(&self) -> SegmentRegister;
    fn from_portable(from: &SegmentRegister) -> Self;
}

impl ConvertSegmentRegister for WHV_X64_SEGMENT_REGISTER {
    fn to_portable(&self) -> SegmentRegister {
        SegmentRegister {
            base: self.Base,
            limit: self.Limit,
            selector: self.Selector,
            type_: self.SegmentType() as u8,
            present: self.Present() as u8,
            dpl: self.DescriptorPrivilegeLevel() as u8,
            db: self.Default() as u8,
            s: self.NonSystemSegment() as u8,
            l: self.Long() as u8,
            g: self.Granularity() as u8,
            avl: self.Available() as u8,
            unusable: 0,
            padding: 0,
        }
    }

    fn from_portable(from: &SegmentRegister) -> WHV_X64_SEGMENT_REGISTER {
        let mut segment = WHV_X64_SEGMENT_REGISTER {
            Base: from.base,
            Limit: from.limit,
            Selector: from.selector,
            Attributes: 0,
        };


        segment.set_SegmentType(from.type_ as u16);
        segment.set_Present(from.present as u16);
        segment.set_DescriptorPrivilegeLevel(from.dpl as u16);
        segment.set_Default(from.db as u16);
        segment.set_NonSystemSegment(from.s as u16);
        segment.set_Long(from.l as u16);
        segment.set_Granularity(from.g as u16);
        segment.set_Available(from.avl as u16);

        segment
    }
}

pub trait ConvertDescriptorTable {
    fn to_portable(&self) -> DescriptorTable;
    fn from_portable(from: &DescriptorTable) -> Self;
}

impl ConvertDescriptorTable for WHV_X64_TABLE_REGISTER {
    fn to_portable(&self) -> DescriptorTable {
        DescriptorTable {
            base: self.Base,
            limit: self.Limit,
            padding: self.Pad,
        }
    }

    fn from_portable(from: &DescriptorTable) -> WHV_X64_TABLE_REGISTER {
        WHV_X64_TABLE_REGISTER {
            Base: from.base,
            Limit: from.limit,
            Pad: from.padding,
        }
    }
}

///
/// Trait to convert between a UINT128 and an array of UINT8s
/// 
pub trait ConvertUint128{
    fn to_u8_array(uint128: &Self) -> [u8; 16usize];
    fn from_u8_array(from: &[u8; 16usize]) -> Self;
}

impl ConvertUint128 for WHV_UINT128 {
    fn to_u8_array(uint128: &Self) -> [u8; 16usize] {
        let mut array: [u8; 16usize] = Default::default();
        let src = uint128 as *const WHV_UINT128 as *const u8;
        let dst = array.as_mut_ptr();

        let dst_len = array.len();

        // Safe because we know the two structures are nonoverlapping and the
        // same size (8 * 16 = 128 bytes)
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, dst_len);
        }

        array
    }

    fn from_u8_array(array: &[u8; 16usize]) -> Self {
        let mut uint128: WHV_UINT128 = Default::default();

        let src = array.as_ptr();
        let dst = &mut uint128 as *mut WHV_UINT128 as *mut u8;

        let dst_len = array.len();

        // Safe because we know the two structures are nonoverlapping and the same
        // size (8 * 16 = 128 bytes)
        unsafe {
            std::ptr::copy_nonoverlapping(src, dst, dst_len);
        }

        uint128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_uint128_to_array() {
        let mut uint128_val: WHV_UINT128 = Default::default();
        uint128_val.Low64 = 0xbbbb_aaaa_9999_8888;
        uint128_val.High64 = 0xffff_eeee_dddd_cccc;

        // Convert from UINT128 to array of bytes
        //let array_of_bytes = convert_uint128_to_array(uint128_val).unwrap();
        let array_of_bytes = WHV_UINT128::to_u8_array(&uint128_val);

        // Assert on the MSB being correct
        assert_eq!(
            array_of_bytes[15],
            (uint128_val.High64 >> 56) as u8,
            "Failure to convert UINT128 to array");

        // Assert on the LSB being correct
        assert_eq!(
            array_of_bytes[0],
            (uint128_val.Low64 & 0xff) as u8,
            "Failure to convert UINT128 to array");

        // Convert array of bytes back to UINT128
        //let uint128_out = convert_array_to_uint128(array_of_bytes).unwrap();
        let uint128_out = WHV_UINT128::from_u8_array(&array_of_bytes);
        assert_eq!(
            uint128_val, 
            uint128_out, 
            "Conversion between UINT128 and array of bytes failed");
    }
    
    #[test]
    fn test_win_standard_regs() {
        let regs_in: WinStandardRegisters = Default::default();

        // Test that a few of the names are set correctly
        assert_eq!(
            regs_in.names[WinStandardRegIndex::Rax as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterRax,
            "StandardRegister not initialized correctly");
        assert_eq!(
            regs_in.names[WinStandardRegIndex::Rbx as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterRbx,
            "StandardRegister not initialized correctly");
        assert_eq!(
            regs_in.names[WinStandardRegIndex::R8 as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterR8,
            "StandardRegister not initialized correctly");
        assert_eq!(
            regs_in.names[WinStandardRegIndex::Rflags as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterRflags,
            "StandardRegister not initialized correctly");
    }

    #[test]
    fn test_win_special_regs() {
        let regs_in: WinSpecialRegisters = Default::default();

        // Test that a few of the names are set correctly
        assert_eq!(
            regs_in.names[WinSpecialRegIndex::Cs as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterCs,
            "SpecialRegister not initialized correctly");
        assert_eq!(
            regs_in.names[WinSpecialRegIndex::Ldt as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterLdtr,
            "SpecialRegister not initialized correctly");
        assert_eq!(
            regs_in.names[WinSpecialRegIndex::ApicBase as usize], 
            WHV_REGISTER_NAME::WHvX64RegisterApicBase,
            "SpecialRegister not initialized correctly");
    }

    #[test]
    fn test_convert_fp_state() {
        let mut fpu_state_in: FpuState = Default::default();
        
        // Populate the control pieces
        fpu_state_in.fcw = 0x37f;
        fpu_state_in.fsw = 0xabc;
        fpu_state_in.ftwx = 0xde;
        fpu_state_in.last_opcode = 0xcafe;
        fpu_state_in.last_ip = 0x1111_2222_3333_4444;
        fpu_state_in.last_dp = 0x5555_6666_7777_8888;
        fpu_state_in.mxcsr = 0x9999_aaaa;

        // Populate the XMM and FPMMX registers by writing to the one of the bytes
        for idx in 0..NUM_XMM_REGS {
            fpu_state_in.xmm[idx][0] = idx as u8;
        }

        for idx in 0..NUM_FPMMX_REGS {
            fpu_state_in.fpr[idx][0] = idx as u8;
        }

        // Convert the FpuState into WinFpuRegisters
        let fregs = WinFpuRegisters::from_portable(&fpu_state_in);

        // Populate the WinFpuRegisters with values from FpuState
        unsafe {
            let fcs_reg = fregs.values[WinFpRegIndex::Fcs as usize].FpControlStatus;
            let xcs_reg = fregs.values[WinFpRegIndex::Xcs as usize].XmmControlStatus;

            // Check the FpControlStatus fields
            assert_eq!(fcs_reg.anon_struct.FpControl, 0x37f, "FpControl conversion failed");
            assert_eq!(fcs_reg.anon_struct.FpStatus, 0xabc, "FpStatus conversion failed");
            assert_eq!(fcs_reg.anon_struct.FpTag, 0xde, "FpTag conversion failed");
            assert_eq!(fcs_reg.anon_struct.LastFpOp, 0xcafe, "LastFpOp conversion failed");
            assert_eq!(
                fcs_reg.anon_struct.anon_union.LastFpRip,
                0x1111_2222_3333_4444,
                "LastFpRip conversion failed");

            // Check the XMMControlStatus fields
            assert_eq!(
                xcs_reg.anon_struct.anon_union.LastFpRdp,
                0x5555_6666_7777_8888,
                "LastFpRdp conversion failed");
            assert_eq!(
                xcs_reg.anon_struct.XmmStatusControl,
                0x9999_aaaa,
                "XmlStatusControl conversion failed");
            assert_eq!(
                xcs_reg.anon_struct.XmmStatusControlMask,
                0xffff,
                "XmlStatusControlMask conversion failed");

            // Check the XMM regs
            for idx in 0..NUM_XMM_REGS {
                let from_idx = WinFpRegIndex::Xmm0 as usize + idx;
                assert_eq!(
                    fregs.values[from_idx].Reg128.Low64,
                    idx as u64,
                    "Xmm[{}] reg conversion failed", from_idx);
            }

            // Check the FPMMX regs
            for idx in 0..NUM_FPMMX_REGS {
                let from_idx = WinFpRegIndex::FpMmx0 as usize + idx;
                assert_eq!(
                    fregs.values[from_idx].Reg128.Low64,
                    idx as u64,
                    "FpMmx[{}] reg conversion failed", from_idx);
            }
        }

        let fpu_state_out = WinFpuRegisters::to_portable(&fregs);

        assert_eq!(fpu_state_in, fpu_state_out, "FP conversion failed");
    }

    #[test]
    /// Convert a SegmentRegister to WHP format and back, making sure it
    /// stays consistent.
    fn test_convert_segment_reg() {
        let sreg = SegmentRegister {
            base: 0,
            limit: 1048575,
            selector: 8,
            type_: 11,
            present: 1,
            dpl: 1,
            db: 1,
            s: 1,
            l: 1,
            g: 1,
            avl: 1,
            unusable: 0,
            padding: 0
        };

        let whp_sreg = WHV_X64_SEGMENT_REGISTER::from_portable(&sreg);

        println!("sreg db: {}", sreg.db);
        println!("whp reg db {:?}", whp_sreg.Default());

        println!("sreg s: {}", sreg.s);
        println!("whp reg s {:?}", whp_sreg.NonSystemSegment());
        let converted_sreg = whp_sreg.to_portable();

        assert_eq!(sreg, converted_sreg);
    }
}
