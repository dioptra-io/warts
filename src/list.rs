use crate::{Flags, WartsSized};
use deku::prelude::*;
use std::ffi::CString;

/// A list of warts objects.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct List {
    pub length: u32,
    /// List ID assigned by warts from a counter.
    pub list_id: u32,
    /// List ID assigned by a person.
    pub list_id_human: u32,
    /// List Name assigned by a person.
    pub name: CString,
    /// Flags.
    pub flags: Flags,
    /// Parameter length (optional, included if any flags are set).
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Description, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub description: Option<CString>,
    /// Monitor name, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub monitor_name: Option<CString>,
}

impl List {
    pub fn fixup(&mut self) -> &mut Self {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.description);
        push_flag!(flags, param_length, 2, self.monitor_name);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self.length = (self.list_id.warts_size()
            + self.list_id_human.warts_size()
            + self.name.warts_size()
            + self.flags.warts_size()
            + self.param_length.warts_size()
            + param_length) as u32;
        self
    }
}
