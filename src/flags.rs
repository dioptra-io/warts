use deku::bitvec::{BitSlice, BitVec, Msb0};
use deku::ctx::Endian;
use deku::{DekuError, DekuRead, DekuWrite};
use std::fmt::{Debug, Formatter};

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
    bits: u64,
}

impl Flags {
    /// Initialize flags from a 64-bit bitfield,
    /// where the LSB represents flag 1 and the MSB flag 63.
    /// TODO: In practice we can only have 64-4 flags!
    pub fn new(bits: u64) -> Self {
        Self { bits }
    }

    /// Initialize flags from a bitslice and return the remaining slice.
    pub fn from_bitslice(slice: &BitSlice<Msb0, u8>) -> (&BitSlice<Msb0, u8>, Self) {
        // The following flags parsing logic is from scamper-pywarts:
        // https://github.com/drakkar-lig/scamper-pywarts/blob/master/warts/base.py
        let mut flags: u64 = 0;
        let mut offset = 0;
        for (i, byte) in slice.as_raw_slice().iter().enumerate() {
            flags |= (*byte as u64 & 0x7F) << (i * 7);
            offset += 8;
            if byte & 0x80 == 0 {
                break;
            }
        }
        (slice.get(offset..).unwrap(), Flags::new(flags))
    }

    /// Returns true if at-least one flag is set to 1.
    pub fn any(&self) -> bool {
        self.bits > 0
    }

    /// Returns true if the specified flag is set to 1.
    /// Note that flags indices start at 1.
    pub fn get(&self, index: usize) -> bool {
        assert!(index > 0, "flags are one-indexed");
        let mask = 1 << (index - 1);
        self.bits & mask == mask
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
        Ok(Flags::from_bitslice(input))
    }
}

impl DekuWrite<Endian> for Flags {
    fn write(&self, output: &mut BitVec<Msb0, u8>, ctx: Endian) -> Result<(), DekuError> {
        // TODO
        // output.clone_from(&self.bits);
        (self.bits as u8).write(output, ctx)
    }
}

#[cfg(test)]
mod tests {
    use crate::Flags;
    use deku::bitvec::{bitvec, Msb0};

    #[test]
    fn single_byte_without_flags() {
        let (_, flags) = Flags::from_bitslice(&bitvec![Msb0, u8; 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(flags.any(), false);
    }

    #[test]
    fn single_byte_with_flags() {
        let (_, flags) = Flags::from_bitslice(&bitvec![Msb0, u8; 0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(flags.any(), true);
        assert!(flags.get(1));
        assert!(flags.get(7));
    }

    #[test]
    fn two_bytes_with_flags() {
        let (_, flags) = Flags::from_bitslice(
            &bitvec![Msb0, u8; 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1],
        );
        assert_eq!(flags.any(), true);
        assert!(flags.get(1));
        assert!(flags.get(7));
        assert!(flags.get(8));
        assert!(flags.get(14));
    }
}
