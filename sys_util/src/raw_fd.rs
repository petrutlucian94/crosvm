// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility file to provide a slightly safer Fd type that cannot be confused with c_int.
// Also useful for situations that require something that is `AsRawFd` but
// where we don't want to store more than the fd.

#[cfg(unix)]
mod unix {
    use std::os::unix::io::{AsRawFd, RawFd};

    pub struct Fd(pub RawFd);
    impl AsRawFd for Fd {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::{AsRawHandle, RawHandle};

    pub struct Fd(pub RawHandle);
    impl AsRawHandle for Fd {
        fn as_raw_handle(&self) -> RawHandle {
            self.0
        }
    }
}

#[cfg(unix)]
pub use unix::Fd;

#[cfg(windows)]
pub use windows::Fd;
