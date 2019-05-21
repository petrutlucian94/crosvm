// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use kvm_sys::*;

/// A capability the kernel's KVM interface can possibly expose.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum Cap {
    None
}
