// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::fs::File;
use std::mem;
use std::ptr;
use std::sync::Arc;
use std::time::Duration;
use sync::Mutex;


use crate::{errno_result, EventFd, FakeClock, Result};

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

/// FakeTimerFd: For use in tests.
pub struct FakeTimerFd {
    clock: Arc<Mutex<FakeClock>>,
    deadline_ns: Option<u64>,
    interval: Option<Duration>,
    fd: EventFd,
}

impl FakeTimerFd {
    /// Creates a new fake timerfd.  The timer is initally disarmed and must be armed by calling
    /// `reset`.
    pub fn new(clock: Arc<Mutex<FakeClock>>) -> Self {
        FakeTimerFd {
            clock,
            deadline_ns: None,
            interval: None,
            fd: EventFd::new().unwrap(),
        }
    }

    fn duration_to_nanos(d: Duration) -> u64 {
        d.as_secs() * 1_000_000_000 + u64::from(d.subsec_nanos())
    }

    /// Sets the timer to expire after `dur`.  If `interval` is not `None` it represents
    /// the period for repeated expirations after the initial expiration.  Otherwise
    /// the timer will expire just once.  Cancels any existing duration and repeating interval.
    pub fn reset(&mut self, dur: Duration, interval: Option<Duration>) -> Result<()> {
        let mut guard = self.clock.lock();
        let deadline = guard.nanos() + FakeTimerFd::duration_to_nanos(dur);
        self.deadline_ns = Some(deadline);
        self.interval = interval;
        guard.add_event_fd(deadline, self.fd.try_clone()?);
        Ok(())
    }

    /// Waits until the timer expires.  The return value represents the number of times the timer
    /// has expired since the last time `wait` was called.  If the timer has not yet expired once
    /// this call will block until it does.
    pub fn wait(&mut self) -> Result<u64> {
        loop {
            self.fd.read()?;
            if let Some(deadline_ns) = &mut self.deadline_ns {
                let mut guard = self.clock.lock();
                let now = guard.nanos();
                if now >= *deadline_ns {
                    let mut expirys = 0;
                    if let Some(interval) = self.interval {
                        let interval_ns = FakeTimerFd::duration_to_nanos(interval);
                        if interval_ns > 0 {
                            expirys += (now - *deadline_ns) / interval_ns;
                            *deadline_ns += (expirys + 1) * interval_ns;
                            guard.add_event_fd(*deadline_ns, self.fd.try_clone()?);
                        }
                    }
                    return Ok(expirys + 1);
                }
            }
        }
    }

    /// Returns `true` if the timer is currently armed.
    pub fn is_armed(&self) -> Result<bool> {
        Ok(self.deadline_ns.is_some())
    }

    /// Disarms the timer.
    pub fn clear(&mut self) -> Result<()> {
        self.deadline_ns = None;
        self.interval = None;
        Ok(())
    }
}

// impl AsRawFd for FakeTimerFd {
//     fn as_raw_fd(&self) -> RawFd {
//         self.fd.as_raw_fd()
//     }
// }

// impl IntoRawFd for FakeTimerFd {
//     fn into_raw_fd(self) -> RawFd {
//         self.fd.into_raw_fd()
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    #[test]
    fn one_shot() {
        let mut tfd = TimerFd::new().expect("failed to create timerfd");
        assert_eq!(tfd.is_armed().unwrap(), false);

        let dur = Duration::from_millis(200);
        let now = Instant::now();
        tfd.reset(dur.clone(), None).expect("failed to arm timer");

        assert_eq!(tfd.is_armed().unwrap(), true);

        let count = tfd.wait().expect("unable to wait for timer");

        assert_eq!(count, 1);
        assert!(now.elapsed() >= dur);
    }

    #[test]
    fn repeating() {
        let mut tfd = TimerFd::new().expect("failed to create timerfd");

        let dur = Duration::from_millis(200);
        let interval = Duration::from_millis(100);
        tfd.reset(dur.clone(), Some(interval))
            .expect("failed to arm timer");

        sleep(dur * 3);

        let count = tfd.wait().expect("unable to wait for timer");
        assert!(count >= 5, "count = {}", count);
    }

    #[test]
    fn fake_one_shot() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimerFd::new(clock.clone());
        assert_eq!(tfd.is_armed().unwrap(), false);

        let dur = Duration::from_nanos(200);
        tfd.reset(dur.clone(), None).expect("failed to arm timer");

        assert_eq!(tfd.is_armed().unwrap(), true);
        clock.lock().add_ns(200);

        let count = tfd.wait().expect("unable to wait for timer");

        assert_eq!(count, 1);
    }

    #[test]
    fn fake_repeating() {
        let clock = Arc::new(Mutex::new(FakeClock::new()));
        let mut tfd = FakeTimerFd::new(clock.clone());

        let dur = Duration::from_nanos(200);
        let interval = Duration::from_nanos(100);
        tfd.reset(dur.clone(), Some(interval))
            .expect("failed to arm timer");

        clock.lock().add_ns(300);

        let mut count = tfd.wait().expect("unable to wait for timer");
        // An expiration from the initial expiry and from 1 repeat.
        assert_eq!(count, 2);

        clock.lock().add_ns(300);
        count = tfd.wait().expect("unable to wait for timer");
        assert_eq!(count, 3);
    }
}
