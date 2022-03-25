use crate::WartsSized;
use deku::bitvec::{BitSlice, BitVec, Msb0};
use deku::ctx::Endian;
use deku::{DekuError, DekuRead, DekuWrite};
use std::fmt::{Debug, Formatter};

// TODO: Automatically generate `fixup()` methods with a derive macro?

/// A variable length flag structure.
///
/// From the [`warts(5)`](https://www.caida.org/catalog/software/scamper/man/warts.5.pdf) man page:
/// > The warts routines in scamper provide the ability to conditionally store arbitrary data in a forwards compatible method.
/// > A set of flags and parameters begins with a sequence of bytes that denote which items are included.
/// > If any flags are set, then after the flags is a 2-byte field that records the length of the parameters that follow.
/// > Finally, the data follows. The following figure illustrates how flags are recorded:
/// > ```text
/// >    Byte zero           Byte one          Byte two
/// >  8 7 6 5 4 3 2 1    8 7 6 5 4 3 2 1   8 7 6 5 4 3 2 1
/// > +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
/// > |1              |  |1              | |0              |
/// > +-+-+-+-+-+-+-+-+  +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
/// > ```
/// > The most significant bit of each byte is the `link' bit; it determines if the next byte in the sequence contains flags.
/// > The low-order 7 bits of each byte signal if the corresponding field is written out in the parameters that follow.
/// > In the figure, the link bit is set to one in the first two bytes, and zero in the final byte,
/// > signifying that three flag-bytes are included.
///
/// > The rest of each byte is used to record flags, whose position in the sequence signifies if a particular parameter is included.
/// > For example, if bit 6 of byte zero is set, then parameter 6 is included, and if bit 5 of byte one is set,
/// > then parameter 12 is included, and if bit 2 of byte two is set, then parameter 16 is included.
#[derive(PartialEq)]
pub struct Flags {
    /// A bitfield where bit `i` is set to 1 if flag `i` is set.
    value: u64,
}

impl Flags {
    /// Initialize flags from a 64-bit bitfield.
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    /// Initialize flags from a byte slice and return the number of bytes read.
    pub fn from_slice(slice: &[u8]) -> (usize, Self) {
        // The following flags parsing logic is from scamper-pywarts:
        // https://github.com/drakkar-lig/scamper-pywarts/blob/master/warts/base.py
        let mut value: u64 = 0;
        let mut read = 0;
        for (i, byte) in slice.iter().enumerate() {
            value |= ((byte & 0x7F) as u64) << (i * 7);
            read += 1;
            if byte & 0x80 == 0 {
                break;
            }
        }
        (read, Flags::new(value))
    }

    /// Returns a byte vector representing the VLQ-encoded flags.
    pub fn to_vec(&self) -> Vec<u8> {
        // Performance?
        let mut buf = [0u8; 8];
        let mut value = self.value;
        let mut index = 0;
        while value > 0x80 {
            buf[index] = (0x80 | value) as u8;
            index += 1;
            value >>= 7;
        }
        buf[index] = (0x7F & value) as u8;
        index += 1;
        Vec::from(&buf[..index])
    }

    /// Returns true if at-least one flag is set to 1.
    pub fn any(&self) -> bool {
        self.value > 0
    }

    /// Returns true if the specified flag is set to 1.
    /// Note that flags indices start at 1.
    pub fn get(&self, index: usize) -> bool {
        assert!(index > 0, "flags are one-indexed");
        let mask = 1 << (index - 1);
        self.value & mask == mask
    }
}

impl From<Vec<i32>> for Flags {
    fn from(indices: Vec<i32>) -> Self {
        let mut flags: u64 = 0;
        for index in indices {
            flags |= 1 << (index - 1);
        }
        Flags::new(flags)
    }
}

impl Debug for Flags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut true_flags = Vec::new();
        for index in 1..=64 {
            if self.get(index) {
                true_flags.push(index);
            }
        }
        write!(f, "{:?}", true_flags)
    }
}

impl DekuRead<'_, Endian> for Flags {
    fn read(
        input: &'_ BitSlice<Msb0, u8>,
        _ctx: Endian,
    ) -> Result<(&'_ BitSlice<Msb0, u8>, Self), DekuError>
    where
        Self: Sized,
    {
        let (read, flags) = Flags::from_slice(input.as_raw_slice());
        Ok((input.get((read * 8)..).unwrap(), flags))
    }
}

impl DekuWrite<Endian> for Flags {
    fn write(&self, output: &mut BitVec<Msb0, u8>, ctx: Endian) -> Result<(), DekuError> {
        self.to_vec().write(output, ctx)
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::new(0)
    }
}

impl WartsSized for Flags {
    fn warts_size(&self) -> usize {
        // TODO: Better implementation...
        self.to_vec().len()
    }
}

#[cfg(test)]
mod tests {
    use crate::Flags;
    use deku::bitvec::{bitvec, Msb0};

    #[test]
    fn single_byte_without_flags() {
        let bitslice = bitvec![Msb0, u8; 0, 0, 0, 0, 0, 0, 0, 0];
        let (read, flags) = Flags::from_slice(bitslice.as_raw_slice());
        assert_eq!(read, 1);
        assert!(!flags.any());
    }

    #[test]
    fn single_byte_with_flags() {
        let bitslice = bitvec![Msb0, u8; 0, 1, 0, 0, 0, 0, 0, 1];
        let (read, flags) = Flags::from_slice(bitslice.as_raw_slice());
        assert_eq!(read, 1);
        assert!(flags.any());
        assert!(flags.get(1));
        assert!(flags.get(7));
        assert!(!flags.get(8));
    }

    #[test]
    fn two_bytes_with_flags() {
        let bitslice = bitvec![Msb0, u8; 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1];
        let (read, flags) = Flags::from_slice(bitslice.as_raw_slice());
        assert_eq!(read, 2);
        assert!(flags.any());
        assert!(flags.get(1));
        assert!(flags.get(7));
        assert!(flags.get(8));
        assert!(flags.get(14));
        assert!(!flags.get(15));
    }

    #[test]
    fn from_int_flags() {
        let flags = Flags::from(vec![1, 7, 8, 14]);
        assert!(flags.any());
        assert!(flags.get(1));
        assert!(flags.get(7));
        assert!(flags.get(8));
        assert!(flags.get(14));
        assert!(!flags.get(15));
    }
}
