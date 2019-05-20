// Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use chrono::{Datelike, Timelike, Utc};

use crate::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

/// A CMOS/RTC device commonly seen on x86 I/O port 0x70/0x71.
pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    /// Constructs a CMOS/RTC device with zero data.
    pub fn new() -> Cmos {
        Cmos {
            index: 0,
            data: [0; DATA_LEN],
        }
    }
}

impl BusDevice for Cmos {
    fn debug_label(&self) -> String {
        "cmos".to_owned()
    }

    fn write(&mut self, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match offset {
            INDEX_OFFSET => self.index = data[0] & INDEX_MASK,
            DATA_OFFSET => self.data[self.index as usize] = data[0],
            o => panic!("bad write offset on CMOS device: {}", o),
        }
    }

    fn read(&mut self, offset: u64, data: &mut [u8]) {
        fn to_bcd(v: u8) -> u8 {
            assert!(v < 100);
            ((v / 10) << 4) | (v % 10)
        }

        if data.len() != 1 {
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => self.index,
            DATA_OFFSET => {
                let now = Utc::now();
                match self.index {
                    0x00 => to_bcd(now.second() as u8),
                    0x02 => to_bcd(now.minute() as u8),
                    0x04 => to_bcd(now.hour() as u8),
                    0x06 => to_bcd(now.weekday() as u8),
                    0x07 => to_bcd(now.day() as u8),
                    0x08 => to_bcd(now.month() as u8),
                    0x09 => to_bcd((now.year() % 100) as u8),
                    0x32 => to_bcd(((now.year() + 1900) / 100) as u8),
                    _ => {
                        // self.index is always guaranteed to be in range via INDEX_MASK.
                        self.data[(self.index & INDEX_MASK) as usize]
                    }
                }
            }
            o => panic!("bad read offset on CMOS device: {}", o),
        }
    }
}
