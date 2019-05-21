// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::time::Duration;


use crate::{Result};

/// A safe wrapper around a Linux timerfd (man 2 timerfd_create).
pub struct TimerFd(File);

// TODO(lpetrut): we should add a timer trait that doesn't rely on timerfd,
// which is Linux specific. ATM, those timers are used by the PIT and virtio
// block devices. We'll just keep it as a stub for now.

impl TimerFd {
    /// Creates a new timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new() -> Result<TimerFd> {
        panic!("Unsupported.")
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        panic!("Unsupported.")
    }

    /// Waits until the timer expires.  The return value represents the number of times the timer
    /// has expired since the last time `wait` was called.  If the timer has not yet expired once
    /// this call will block until it does.
    pub fn wait(&mut self) -> Result<u64> {
        panic!("Unsupported.")
    }

    /// Returns `true` if the timer is currently armed.
    pub fn is_armed(&self) -> Result<bool> {
        panic!("Unsupported.")
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        panic!("Unsupported.")
    }
}

// impl AsRawFd for TimerFd {
//     fn as_raw_fd(&self) -> RawFd {
//         self.0.as_raw_fd()
//     }
// }

// impl FromRawFd for TimerFd {
//     unsafe fn from_raw_fd(fd: RawFd) -> Self {
//         TimerFd(File::from_raw_fd(fd))
//     }
// }

// impl IntoRawFd for TimerFd {
//     fn into_raw_fd(self) -> RawFd {
//         self.0.into_raw_fd()
//     }
// }
