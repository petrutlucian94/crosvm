// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

mod alloc;
#[macro_use]
pub mod handle_eintr;
#[macro_use]
#[cfg(unix)]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod clock;
mod errno;
mod eventfd;
mod file_traits;
mod guest_address;
pub mod guest_memory;
mod mmap;
mod poll;
mod raw_fd;
mod seek_hole;
mod shm;
pub mod signal;
mod signalfd;
mod struct_util;
mod tempdir;
#[cfg(unix)]
mod terminal;
mod timerfd;
mod write_zeroes;

pub use crate::alloc::LayoutAllocation;
pub use crate::clock::{Clock, FakeClock};
use crate::errno::errno_result;
pub use crate::errno::{Error, Result};
pub use crate::eventfd::*;
pub use crate::guest_address::*;
pub use crate::guest_memory::*;
pub use crate::mmap::*;
pub use crate::poll::*;
pub use crate::raw_fd::*;
pub use crate::shm::*;
pub use crate::signal::*;
pub use crate::signalfd::*;
pub use crate::struct_util::*;
pub use crate::tempdir::*;
#[cfg(unix)]
pub use crate::terminal::*;
pub use crate::timerfd::*;
pub use poll_token_derive::*;

pub use crate::file_traits::{FileSetLen, FileSync};
pub use crate::guest_memory::Error as GuestMemoryError;
pub use crate::mmap::Error as MmapError;
pub use crate::seek_hole::SeekHole;
pub use crate::signalfd::Error as SignalFdError;
pub use crate::write_zeroes::{PunchHole, WriteZeroes};

use std::ffi::CStr;
use std::fs::{remove_file, File};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{
    c_long, pid_t, pipe2, syscall, sysconf, O_CLOEXEC, _SC_PAGESIZE,
};

use syscall_defines::linux::LinuxSyscall::SYS_getpid;

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}

/// This bypasses `libc`'s caching `getpid(2)` wrapper which can be invalid if a raw clone was used
/// elsewhere.
#[inline(always)]
pub fn getpid() -> pid_t {
    // Safe because this syscall can never fail and we give it a valid syscall number.
    unsafe { syscall(SYS_getpid as c_long) as pid_t }
}

/// The operation to perform with `fallocate`.
pub enum FallocateMode {
    PunchHole,
    ZeroRange,
}

/// Spawns a pipe pair where the first pipe is the read end and the second pipe is the write end.
///
/// If `close_on_exec` is true, the `O_CLOEXEC` flag will be set during pipe creation.
pub fn pipe(close_on_exec: bool) -> Result<(File, File)> {
    let flags = if close_on_exec { O_CLOEXEC } else { 0 };
    let mut pipe_fds = [-1; 2];
    // Safe because pipe2 will only write 2 element array of i32 to the given pointer, and we check
    // for error.
    let ret = unsafe { pipe2(&mut pipe_fds[0], flags) };
    if ret == -1 {
        errno_result()
    } else {
        // Safe because both fds must be valid for pipe2 to have returned sucessfully and we have
        // exclusive ownership of them.
        Ok(unsafe {
            (
                File::from_raw_fd(pipe_fds[0]),
                File::from_raw_fd(pipe_fds[1]),
            )
        })
    }
}
