use std::ffi::CString;
use std::mem::size_of_val;

/// A trait for defining the size of the binary representation of warts objects.
pub trait WartsSized {
    /// Returns the size of the binary representation of the type in a warts object.
    fn warts_size(&self) -> usize;
}

impl WartsSized for u8 {
    fn warts_size(&self) -> usize {
        size_of_val(self)
    }
}

impl WartsSized for u16 {
    fn warts_size(&self) -> usize {
        size_of_val(self)
    }
}

impl WartsSized for u32 {
    fn warts_size(&self) -> usize {
        size_of_val(self)
    }
}

impl WartsSized for CString {
    fn warts_size(&self) -> usize {
        self.to_bytes_with_nul().len()
    }
}

impl<T: WartsSized> WartsSized for &T {
    fn warts_size(&self) -> usize {
        (*self).warts_size()
    }
}

impl<T: WartsSized> WartsSized for Option<T> {
    fn warts_size(&self) -> usize {
        match self {
            None => 0,
            Some(x) => x.warts_size(),
        }
    }
}
