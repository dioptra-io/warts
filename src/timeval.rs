use chrono::NaiveDateTime;
use deku::prelude::*;

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
        NaiveDateTime::from_timestamp(x.seconds as i64, x.microseconds * 1000)
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

#[cfg(test)]
mod tests {
    use crate::Timeval;
    use chrono::{NaiveDate, NaiveDateTime};

    #[test]
    fn from_date_time() {
        let dt = NaiveDate::from_ymd(2021, 2, 9).and_hms(0, 11, 45);
        assert_eq!(NaiveDateTime::from(Timeval::from(dt)), dt);
    }
}
