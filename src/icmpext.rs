use deku::prelude::*;

/// ICMP extension (MPLS-only).
///
// TOOD
// ```
// use warts::{ICMPExtension, MPLSLabel};
// let label = MPLSLabel{
//     label: 1234,
//     experimental: 0,
//     bottom_of_stack: true,
//     ttl: 8
// };
// let ext = ICMPExtension::new(vec![label]);
// ```
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct ICMPExtension {
    /// Length of data that follows.
    #[deku(update = "self.mpls_labels.len() * 4")]
    data_length: u16,
    /// ICMP extension class number.
    #[deku(assert_eq = "1")]
    ext_class: u8,
    /// ICMP extension type number.
    #[deku(assert_eq = "1")]
    ext_type: u8,
    /// ICMP extension data, if any.
    #[deku(count = "data_length / 4")]
    mpls_labels: Vec<MPLSLabel>,
}

impl ICMPExtension {
    pub fn new(mpls_labels: Vec<MPLSLabel>) -> Self {
        ICMPExtension {
            data_length: (mpls_labels.len() * 4) as u16,
            ext_class: 1,
            ext_type: 1,
            mpls_labels,
        }
    }

    pub fn mpls_labels(&self) -> &Vec<MPLSLabel> {
        &self.mpls_labels
    }
}

/// An MPLS label stack entry.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct MPLSLabel {
    // We do not systematically parse MPLS labels as this is relatively slow;
    // instead, we store the raw data and provide getters.
    data: u32,
    // #[deku(bits = 20)]
    // pub label: u32,
    // #[deku(bits = 3)]
    // pub experimental: u8,
    // #[deku(bits = 1)]
    // pub bottom_of_stack: bool,
    // pub ttl: u8
}

impl MPLSLabel {
    // TODO: Getters
    // TODO: Impl From<MPLSLabel> for u32
}
