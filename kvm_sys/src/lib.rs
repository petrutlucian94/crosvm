// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86 {
    // generated with bindgen /usr/include/linux/kvm.h --no-unstable-rust --constified-enum '*' --with-derive-default
    #[allow(clippy::all)]
    pub mod bindings;
    pub use crate::bindings::*;
}

// Along with the common ioctls, we reexport the ioctls of the current
// platform.

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use crate::x86::*;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use aarch64::*;
