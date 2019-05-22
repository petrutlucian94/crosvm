// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::time::Duration;

use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, RawHandle};

use winapi::um::synchapi::{WaitForSingleObject, SetWaitableTimer, CancelWaitableTimer};
use winapi::um::winbase::{
    INFINITE, WAIT_FAILED,
    CreateWaitableTimerA};
use winapi::um::winnt::{HANDLE, LARGE_INTEGER};

use crate::errno::{errno_result, Result};

/// A timerfd-like interface that uses Windows waitable timers.
#[derive(Debug)]
pub struct TimerFd {
    timer: HANDLE,
    armed: bool
}

unsafe impl Send for TimerFd {}

impl TimerFd {
    /// Creates a new timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    /// TODO(lpetrut): we may want to implement a destructor.
    pub fn new() -> Result<TimerFd> {
        // Manual reset disabled, this timer will be reset when a wait function
        // completes.
        let timer = unsafe {
            CreateWaitableTimerA(
            std::ptr::null_mut(),
            0,
            std::ptr::null())
        };
        if timer as usize == 0 {
            return errno_result();
        }

        Ok(TimerFd {
            timer: timer,
            armed: false
        })
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        let mut duration: LARGE_INTEGER = unsafe {std::mem::zeroed() };
        unsafe { *duration.QuadPart_mut() = dur.as_nanos() as i64 / -100 }
        let mut period = 0;

        if let Some(int) = interval {
            period = int.as_millis();
        }

        let result = unsafe {
            SetWaitableTimer(
                self.timer,
                &duration,
                period as i32,
                None,
                std::ptr::null_mut(),
                0)
        };
        if result == 0 {
            return errno_result();
        }

        self.armed = true;
        Ok(())
    }

    /// Waits until the timer expires.  The return value represents the number of times the timer
    /// has expired since the last time `wait` was called.  If the timer has not yet expired once
    /// this call will block until it does.
    pub fn wait(&mut self) -> Result<u64> {
        let result = unsafe {
            WaitForSingleObject(self.timer, INFINITE)
        };

        // We're ignoring timeouts (we're using an infinite timeout) as well as
        // WAIT_ABANDONED values.
        match result {
            WAIT_FAILED => {
                return errno_result();
            }
            // as opposed to timerfd, we can't tell how many times periodic
            // timers have expired, so we'll just pass "1".
            _ => Ok(1)
        }
    }

    /// Returns `true` if the timer is currently armed.
    pub fn is_armed(&self) -> Result<bool> {
        Ok(self.armed)
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        let result = unsafe { CancelWaitableTimer(self.timer) };
        if result == 0 {
            return errno_result();
        }
        self.armed = false;
        Ok(())
    }
}

impl AsRawHandle for TimerFd {
    fn as_raw_handle(&self) -> RawHandle {
        self.timer
    }
}

impl FromRawHandle for TimerFd {
    unsafe fn from_raw_handle(fd: RawHandle) -> Self {
        TimerFd {
            timer: fd,
            armed: false
        }
    }
}

impl IntoRawHandle for TimerFd {
    fn into_raw_handle(self) -> RawHandle {
        self.timer
    }
}

mod test {
    use crate::TimerFd;
    use std::time::{Duration, SystemTime};

    #[test]
    pub fn test_timer() {
        let mut timer = TimerFd::new().unwrap();

        assert!(!timer.is_armed().unwrap());

        let duration = Duration::from_millis(500);
        timer.reset(duration, Some(duration));
        assert!(timer.is_armed().unwrap());

        let system_timer = SystemTime::now();
        timer.wait();
        timer.wait();
        timer.wait();

        assert!(system_timer.elapsed().unwrap().as_millis() >= 1500);

        timer.clear().unwrap();

        assert!(!timer.is_armed().unwrap());
    }
}
