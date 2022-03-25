use crate::{Flags, WartsSized};
use deku::prelude::*;
use std::ffi::CString;

/// A start record denotes the starting point for a new cycle.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct CycleStart {
    pub length: u32,
    /// Cycle ID, assigned by warts from a counter.
    pub cycle_id: u32,
    /// List ID, referencing the list this cycle is over.
    pub list_id: u32,
    /// Cycle ID, assigned by a human.
    pub cycle_id_human: u32,
    /// Start time of the cycle, seconds since Unix epoch.
    pub start_time: u32,
    /// Flags.
    pub flags: Flags,
    /// Parameter length, included if any flags are set.
    #[deku(cond = "flags.any()")]
    pub param_length: Option<u16>,
    /// Stop time of the cycle in seconds since Unix epoch, included if flag 1 is set.
    #[deku(cond = "flags.get(1)")]
    pub stop_time: Option<u32>,
    /// Hostname at cycle start point, included if flag 2 is set.
    #[deku(cond = "flags.get(2)")]
    pub hostname: Option<CString>,
}

/// A cycle stop record denotes the end point for a cycle.
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct CycleStop {
    pub length: u32,
    /// Cycle ID, assigned by warts from a counter, referencing the cycle structure that is being updated.
    pub cycle_id: u32,
    /// Stop time of the cycle, seconds since Unix epoch.
    pub stop_time: u32,
    /// Flags. Currently set to zero.
    pub flags: Flags,
}

impl CycleStart {
    pub fn fixup(&mut self) {
        let mut flags = Vec::new();
        let mut param_length = 0;
        push_flag!(flags, param_length, 1, self.stop_time);
        push_flag!(flags, param_length, 2, self.hostname);
        self.flags = Flags::from(flags);
        self.param_length = Some(param_length as u16);
        self.length = (self.cycle_id.warts_size()
            + self.list_id.warts_size()
            + self.cycle_id_human.warts_size()
            + self.start_time.warts_size()
            + self.flags.warts_size()
            + self.param_length.warts_size()
            + param_length) as u32
    }
}

impl CycleStop {
    pub fn fixup(&mut self) {
        self.flags = Flags::new(0);
        self.length = (self.cycle_id.warts_size()
            + self.stop_time.warts_size()
            + self.flags.warts_size()) as u32
    }
}
