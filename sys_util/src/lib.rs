// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Small system utility modules for usage by other modules.

#[cfg(windows)]
extern crate winapi;

mod alloc;
#[macro_use]
pub mod handle_eintr;
#[macro_use]
#[cfg(unix)]
pub mod ioctl;
#[macro_use]
pub mod syslog;
mod clock;

#[cfg(unix)]
mod errno_unix;
#[cfg(windows)]
mod errno_windows;

#[cfg(unix)]
mod eventfd_unix;
#[cfg(windows)]
mod eventfd_windows;
#[cfg(windows)]
mod disk_util_windows;

mod poll;
mod file_traits;
mod raw_fd;
mod seek_hole;
mod struct_util;
mod tempdir;
#[cfg(unix)]
mod terminal;
mod timerfd;
mod write_zeroes;

pub use crate::alloc::LayoutAllocation;
pub use crate::clock::{Clock};

#[cfg(unix)]
use crate::errno_unix as errno;
#[cfg(windows)]
use crate::errno_windows as errno;

#[cfg(unix)]
use crate::eventfd_unix as eventfd;
#[cfg(windows)]
use crate::eventfd_windows as eventfd;
#[cfg(windows)]
use crate::disk_util_windows as disk_util;

pub use errno::errno_result;
pub use crate::errno::{Error, Result};
pub use crate::eventfd::*;
pub use crate::disk_util::*;
pub use poll::{PollContext, PollResult};
pub use crate::raw_fd::*;
pub use crate::struct_util::*;
pub use crate::tempdir::*;
#[cfg(unix)]
pub use crate::terminal::*;
pub use crate::timerfd::*;

pub use crate::seek_hole::SeekHole;
pub use crate::file_traits::{FileSetLen, FileSync};
pub use crate::write_zeroes::{PunchHole, WriteZeroes};

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // Trivially safe
    // unsafe { sysconf(_SC_PAGESIZE) as usize }
    4096
}

/// Uses the system's page size in bytes to round the given value up to the nearest page boundary.
#[inline(always)]
pub fn round_up_to_page_size(v: usize) -> usize {
    let page_mask = pagesize() - 1;
    (v + page_mask) & !page_mask
}


#[inline(always)]
pub fn getpid() -> u32 {
    std::process::id()
}

/// The operation to perform with `fallocate`.
pub enum FallocateMode {
    PunchHole,
    ZeroRange,
}
