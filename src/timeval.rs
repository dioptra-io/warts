use crate::WartsSized;
use chrono::NaiveDateTime;
use deku::prelude::*;
use std::mem::size_of_val;

/// A timestamp with a microsecond resolution.
/// ```
/// use chrono::{NaiveDate, NaiveDateTime};
/// use warts::Timeval;
/// // Rust to Warts:
/// let tv = Timeval::from(NaiveDate::from_ymd(2021, 2, 9).and_hms(0, 11, 45));
/// // Warts to Rust:
/// let dt = NaiveDateTime::from(tv);
/// ```
#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: deku::ctx::Endian", endian = "endian")]
pub struct Timeval {
    pub seconds: u32,
    pub microseconds: u32,
}

impl From<Timeval> for NaiveDateTime {
    fn from(x: Timeval) -> Self {
        NaiveDateTime::from_timestamp_opt(x.seconds as i64, x.microseconds * 1000).unwrap()
    }
}

impl From<NaiveDateTime> for Timeval {
    fn from(x: NaiveDateTime) -> Self {
        Timeval {
            seconds: x.timestamp() as u32,
            microseconds: x.timestamp_subsec_micros(),
        }
    }
}

impl WartsSized for Timeval {
    fn warts_size(&self) -> usize {
        size_of_val(self)
    }
}

#[cfg(test)]
mod tests {
    use crate::Timeval;
    use chrono::{NaiveDate, NaiveDateTime};

    #[test]
    fn from_date_time() {
        let dt = NaiveDate::from_ymd_opt(2021, 2, 9)
            .unwrap()
            .and_hms_opt(0, 11, 45)
            .unwrap();
        assert_eq!(NaiveDateTime::from(Timeval::from(dt)), dt);
    }
}
