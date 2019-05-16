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
mod poll;
mod raw_fd;
mod seek_hole;
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
pub use crate::poll::*;
pub use crate::raw_fd::*;
pub use crate::struct_util::*;
pub use crate::tempdir::*;
#[cfg(unix)]
pub use crate::terminal::*;
pub use crate::timerfd::*;
pub use poll_token_derive::*;

pub use crate::file_traits::{FileSetLen, FileSync};
pub use crate::write_zeroes::{PunchHole, WriteZeroes};

use std::fs::{remove_file, File};
// use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{
    c_long
};

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


#[inline(always)]
pub fn getpid() -> u32 {
    std::process::id()
}

/// The operation to perform with `fallocate`.
pub enum FallocateMode {
    PunchHole,
    ZeroRange,
}
