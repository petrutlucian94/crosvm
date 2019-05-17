// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility file to provide a fake clock object representing current time, and a timerfd driven by
// that time.

use std::time::{Duration, Instant};

#[derive(Debug, Copy, Clone)]
pub struct Clock(Instant);
impl Clock {
    pub fn new() -> Self {
        Clock(Instant::now())
    }

    pub fn now(&self) -> Self {
        Clock(Instant::now())
    }

    pub fn duration_since(&self, earlier: &Self) -> Duration {
        self.0.duration_since(earlier.0)
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}
