// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles IPC for controlling the main VM process.
//!
//! The VM Control IPC protocol is synchronous, meaning that each `VmRequest` sent over a connection
//! will receive a `VmResponse` for that request next time data is received over that connection.
//!
//! The wire message format is a little-endian C-struct of fixed size, along with a file descriptor
//! if the request type expects one.

use std::fmt::{self, Display};
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{EINVAL, EIO, ENODEV};

use kvm::Vm;
use resources::{SystemAllocator};
use sys_util::{error, Error as SysError, GuestAddress, MemoryMapping, MmapError, Result};

/// A file descriptor either borrowed or owned by this.
#[derive(Debug)]
pub enum MaybeOwnedFd {
    /// Owned by this enum variant, and will be destructed automatically if not moved out.
    Owned(File),
    /// A file descriptor borrwed by this enum.
    Borrowed(RawFd),
}

impl AsRawFd for MaybeOwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            MaybeOwnedFd::Owned(f) => f.as_raw_fd(),
            MaybeOwnedFd::Borrowed(fd) => *fd,
        }
    }
}

// When sent, it could be owned or borrowed. On the receiver end, it always owned.
impl MsgOnSocket for MaybeOwnedFd {
    fn msg_size() -> usize {
        0usize
    }
    fn max_fd_count() -> usize {
        1usize
    }
    unsafe fn read_from_buffer(buffer: &[u8], fds: &[RawFd]) -> MsgResult<(Self, usize)> {
        let (fd, size) = RawFd::read_from_buffer(buffer, fds)?;
        let file = File::from_raw_fd(fd);
        Ok((MaybeOwnedFd::Owned(file), size))
    }
    fn write_to_buffer(&self, buffer: &mut [u8], fds: &mut [RawFd]) -> MsgResult<usize> {
        let fd = self.as_raw_fd();
        fd.write_to_buffer(buffer, fds)
    }
}

/// Mode of execution for the VM.
#[derive(Debug)]
pub enum VmRunMode {
    /// The default run mode indicating the VCPUs are running.
    Running,
    /// Indicates that the VCPUs are suspending execution until the `Running` mode is set.
    Suspending,
    /// Indicates that the VM is exiting all processes.
    Exiting,
}

impl Display for VmRunMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmRunMode::*;

        match self {
            Running => write!(f, "running"),
            Suspending => write!(f, "suspending"),
            Exiting => write!(f, "exiting"),
        }
    }
}

impl Default for VmRunMode {
    fn default() -> Self {
        VmRunMode::Running
    }
}


#[derive(MsgOnSocket, Debug)]
pub enum BalloonControlCommand {
    /// Set the size of the VM's balloon.
    Adjust { num_bytes: u64 },
}

#[derive(MsgOnSocket, Debug)]
pub enum DiskControlCommand {
    /// Resize a disk to `new_size` in bytes.
    Resize { new_size: u64 },
}

impl Display for DiskControlCommand {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::DiskControlCommand::*;

        match self {
            Resize { new_size } => write!(f, "disk_resize {}", new_size),
        }
    }
}

#[derive(MsgOnSocket, Debug)]
pub enum DiskControlResult {
    Ok,
    Err(SysError),
}

pub type BalloonControlRequestSocket = MsgSocket<BalloonControlCommand, ()>;
pub type BalloonControlResponseSocket = MsgSocket<(), BalloonControlCommand>;

pub type DiskControlRequestSocket = MsgSocket<DiskControlCommand, DiskControlResult>;
pub type DiskControlResponseSocket = MsgSocket<DiskControlResult, DiskControlCommand>;

pub type VmControlRequestSocket = MsgSocket<VmRequest, VmResponse>;
pub type VmControlResponseSocket = MsgSocket<VmResponse, VmRequest>;

/// A request to the main process to perform some operation on the VM.
///
/// Unless otherwise noted, each request should expect a `VmResponse::Ok` to be received on success.
#[derive(MsgOnSocket, Debug)]
pub enum VmRequest {
    /// Break the VM's run loop and exit.
    Exit,
    /// Suspend the VM's VCPUs until resume.
    Suspend,
    /// Resume the VM's VCPUs that were previously suspended.
    Resume,
    /// Command for balloon driver.
    BalloonCommand(BalloonControlCommand),
    /// Send a command to a disk chosen by `disk_index`.
    /// `disk_index` is a 0-based count of `--disk`, `--rwdisk`, and `-r` command-line options.
    DiskCommand {
        disk_index: usize,
        command: DiskControlCommand,
    },
}

fn register_memory(
    vm: &mut Vm,
    allocator: &mut SystemAllocator,
    fd: &dyn AsRawFd,
    size: usize,
) -> Result<(u64, u32)> {
    let mmap = match MemoryMapping::from_fd(fd, size) {
        Ok(v) => v,
        Err(MmapError::SystemCallFailed(e)) => return Err(e),
        _ => return Err(SysError::new(EINVAL)),
    };
    let alloc = allocator.get_anon_alloc();
    let addr = match allocator.device_allocator().allocate(
        size as u64,
        alloc,
        "vmcontrol_register_memory".to_string(),
    ) {
        Ok(a) => a,
        Err(_) => return Err(SysError::new(EINVAL)),
    };
    let slot = match vm.add_device_memory(GuestAddress(addr), mmap, false, false) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };

    Ok((addr >> 12, slot))
}

impl VmRequest {
    /// Executes this request on the given Vm and other mutable state.
    ///
    /// This does not return a result, instead encapsulating the success or failure in a
    /// `VmResponse` with the intended purpose of sending the response back over the  socket that
    /// received this `VmRequest`.
    pub fn execute(
        &self,
        run_mode: &mut Option<VmRunMode>,
        balloon_host_socket: &BalloonControlRequestSocket,
        disk_host_sockets: &[DiskControlRequestSocket],
    ) -> VmResponse {
        match *self {
            VmRequest::Exit => {
                *run_mode = Some(VmRunMode::Exiting);
                VmResponse::Ok
            }
            VmRequest::Suspend => {
                *run_mode = Some(VmRunMode::Suspending);
                VmResponse::Ok
            }
            VmRequest::Resume => {
                *run_mode = Some(VmRunMode::Running);
                VmResponse::Ok
            }
            VmRequest::BalloonCommand(ref command) => match balloon_host_socket.send(command) {
                Ok(_) => VmResponse::Ok,
                Err(_) => VmResponse::Err(SysError::last()),
            },
            VmRequest::DiskCommand {
                disk_index,
                ref command,
            } => {
                // Forward the request to the block device process via its control socket.
                if let Some(sock) = disk_host_sockets.get(disk_index) {
                    if let Err(e) = sock.send(command) {
                        error!("disk socket send failed: {}", e);
                        VmResponse::Err(SysError::new(EINVAL))
                    } else {
                        match sock.recv() {
                            Ok(DiskControlResult::Ok) => VmResponse::Ok,
                            Ok(DiskControlResult::Err(e)) => VmResponse::Err(e),
                            Err(e) => {
                                error!("disk socket recv failed: {}", e);
                                VmResponse::Err(SysError::new(EINVAL))
                            }
                        }
                    }
                } else {
                    VmResponse::Err(SysError::new(ENODEV))
                }
            }
        }
    }
}

/// Indication of success or failure of a `VmRequest`.
///
/// Success is usually indicated `VmResponse::Ok` unless there is data associated with the response.
#[derive(MsgOnSocket, Debug)]
pub enum VmResponse {
    /// Indicates the request was executed successfully.
    Ok,
    /// Indicates the request encountered some error during execution.
    Err(SysError),
    /// The request to register memory into guest address space was successfully done at page frame
    /// number `pfn` and memory slot number `slot`.
    RegisterMemory { pfn: u64, slot: u32 },
}

impl Display for VmResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::VmResponse::*;

        match self {
            Ok => write!(f, "ok"),
            Err(e) => write!(f, "error: {}", e),
            RegisterMemory { pfn, slot } => write!(
                f,
                "memory registered to page frame number {:#x} and memory slot {}",
                pfn, slot
            ),
        }
    }
}
