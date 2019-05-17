// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use winapi::um::synchapi::{CreateEventA, SetEvent, WaitForSingleObject};
use winapi::um::winnt::{HANDLE, DUPLICATE_SAME_ACCESS};
use winapi::um::winbase::{INFINITE, WAIT_FAILED};
use winapi::um::processthreadsapi::{GetCurrentProcess};
use winapi::um::handleapi::{DuplicateHandle};

use crate::{errno_result, Result};

#[derive(Debug)]
pub struct EventFd {
    eventfd: HANDLE,
}

/// We're imitating eventfd behavior using Windows primitives. Note that the
/// posix module is not using "EFD_SEMAPHORE", so we can just use events.
/// crosvm doesn't seem to use the eventfd values (just writing 1, ignoring
/// read values), so we'll do the same.
///
/// One issue is that Linux consumers may set O_NONBLOCK on the file descriptor,
/// which would be transparent to us. Luckily, crosvm doesn't seem to do this.
impl EventFd {
    /// Creates a new blocking EventFd with an initial value of 0.
    pub fn new() -> Result<EventFd> {
        let evt = unsafe {
            CreateEventA(
                std::ptr::null_mut(),
                0,
                0,
                std::ptr::null())
        };
        if evt as usize == 0 {
            return errno_result();
        }

        Ok(EventFd {
            eventfd: evt,
        })
    }

    /// Adds `v` to the eventfd's count, blocking until this won't overflow the count.
    pub fn write(&self, v: u64) -> Result<()> {
        let result = unsafe { SetEvent(self.eventfd) };
        if result == 0 {
            return errno_result();
        }
        Ok(())
    }

    /// Blocks until the the eventfd's count is non-zero, then resets the count to zero.
    pub fn read(&self) -> Result<u64> {
        let result = unsafe {
            WaitForSingleObject(self.eventfd, INFINITE)
        };

        // We're ignoring timeouts (we're using an infinite timeout) as well as
    // WAIT_ABANDONED values.
        match result {
            WAIT_FAILED => {
                return errno_result();
            }
            // Since crosvm doesn't seem to actually use the eventfd
            // values, we'll just return 1 all the time.
            _ => Ok(1)
        }
    }

    /// Clones this EventFd, internally creating a new file descriptor. The new EventFd will share
    /// the same underlying count within the kernel.
    pub fn try_clone(&self) -> Result<EventFd> {
        let mut evt_clone: HANDLE;
        let failed = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.eventfd,
                GetCurrentProcess(),
                &mut evt_clone,
                0,
                0,
                DUPLICATE_SAME_ACCESS)
        };

        if failed != 0 {
            return errno_result();
        }
        Ok(EventFd {
            eventfd: evt_clone
        })
    }
}

// impl AsRawFd for EventFd {
//     fn as_raw_fd(&self) -> RawFd {
//         self.eventfd.as_raw_fd()
//     }
// }

// impl FromRawFd for EventFd {
//     unsafe fn from_raw_fd(fd: RawFd) -> Self {
//         EventFd {
//             eventfd: File::from_raw_fd(fd),
//         }
//     }
// }

// impl IntoRawFd for EventFd {
//     fn into_raw_fd(self) -> RawFd {
//         self.eventfd.into_raw_fd()
//     }
// }
