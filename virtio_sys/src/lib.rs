// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use sys_util::{ioctl_io_nr, ioctl_ior_nr, ioctl_iow_nr, ioctl_iowr_nr};

// generated with bindgen /usr/include/linux/virtio_net.h --no-unstable-rust --constified-enum '*' --with-derive-default
pub mod virtio_net;
// generated with bindgen /usr/include/linux/virtio_ring.h --no-unstable-rust --constified-enum '*' --with-derive-default
pub mod virtio_ring;
pub use crate::virtio_net::*;
pub use crate::virtio_ring::*;


// TODO(lpetrut): I guess we can drop this module or even crate.
