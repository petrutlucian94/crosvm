use std::io::Cursor;

use byteorder::{NativeEndian, ReadBytesExt};

/// An address either in programmable I/O space or in memory mapped I/O space.
#[derive(Copy, Clone, Debug)]
pub enum IoeventAddress {
    Pio(u64),
    Mmio(u64),
}

/// Used in `Vm::register_ioevent` to indicate a size and optionally value to match.
#[derive(Copy, Clone, Debug)]
pub enum Datamatch {
    AnyLength,
    U8(Option<u8>),
    U16(Option<u16>),
    U32(Option<u32>),
    U64(Option<u64>),
}

impl Datamatch {
    // TODO(lpetrut): this looks overly complicated, should probably clean it
    // up a bit.
    pub fn matches(&self, data: &[u8]) -> bool {
        let mut reader = Cursor::new(data);

        match self {
            Datamatch::AnyLength => {
                true
            },
            Datamatch::U8(val) => {
                if data.len() != 1 {
                    return false;
                }
                match val {
                    Some(num) => *num == data[0],
                    None => true
                }
            },
            Datamatch::U16(val) => {
                if data.len() != 2 {
                    return false;
                }
                match val {
                    Some(num) => *num == reader.read_u16::<NativeEndian>().unwrap(),
                    None => true
                }
            },
            Datamatch::U32(val) => {
                if data.len() != 4 {
                    return false;
                }
                match val {
                    Some(num) => *num == reader.read_u32::<NativeEndian>().unwrap(),
                    None => true
                }
            },
            Datamatch::U64(val) => {
                if data.len() != 8 {
                    return false;
                }
                match val {
                    Some(num) => *num == reader.read_u64::<NativeEndian>().unwrap(),
                    None => true
                }
            }
        }
    }
}

/// A source of IRQs in an `IrqRoute`.
pub enum IrqSource {
    Irqchip { chip: u32, pin: u32 },
    Msi { address: u64, data: u32 },
}

/// A single route for an IRQ.
pub struct IrqRoute {
    pub gsi: u32,
    pub source: IrqSource,
}

/// Interrupt controller IDs
pub enum PicId {
    Primary = 0,
    Secondary = 1,
}
