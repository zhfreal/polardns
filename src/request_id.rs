use std::cell::Cell;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;

const CHARSET: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

thread_local! {
    static TS_CACHE: Cell<(u64, [u8; 14])> = const { Cell::new((u64::MAX, [0u8; 14])) };
}

/// Zero-allocation 20-character stack-allocated request ID: `YYYYMMDDHHMMSS<6 random chars>`
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId([u8; 20]);

pub(crate) fn secs_to_datetime(secs: u64) -> (u16, u8, u8, u8, u8, u8) {
    let sec = (secs % 60) as u8;
    let mins = secs / 60;
    let min = (mins % 60) as u8;
    let hours = mins / 60;
    let hour = (hours % 24) as u8;
    let days = hours / 24;

    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    (y as u16, m as u8, d as u8, hour, min, sec)
}

impl RequestId {
    /// Generate a new `RequestId` with a 14-char UTC timestamp (`YYYYMMDDHHMMSS`)
    /// and a 6-char random alphanumeric suffix (`[0-9a-zA-Z]`).
    pub fn new() -> Self {
        let mut buf = [0u8; 20];
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1. Thread-local timestamp cache (UTC via pure Rust secs_to_datetime)
        TS_CACHE.with(|cache| {
            let (cached_sec, cached_buf) = cache.get();
            if cached_sec == now_secs {
                buf[..14].copy_from_slice(&cached_buf);
            } else {
                let mut new_buf = [0u8; 14];
                let (year, month, day, hour, min, sec) = secs_to_datetime(now_secs);
                let year = year as usize;
                let month = month as usize;
                let day = day as usize;
                let hour = hour as usize;
                let min = min as usize;
                let sec = sec as usize;

                new_buf[0] = b'0' + (year / 1000 % 10) as u8;
                new_buf[1] = b'0' + (year / 100 % 10) as u8;
                new_buf[2] = b'0' + (year / 10 % 10) as u8;
                new_buf[3] = b'0' + (year % 10) as u8;
                new_buf[4] = b'0' + (month / 10 % 10) as u8;
                new_buf[5] = b'0' + (month % 10) as u8;
                new_buf[6] = b'0' + (day / 10 % 10) as u8;
                new_buf[7] = b'0' + (day % 10) as u8;
                new_buf[8] = b'0' + (hour / 10 % 10) as u8;
                new_buf[9] = b'0' + (hour % 10) as u8;
                new_buf[10] = b'0' + (min / 10 % 10) as u8;
                new_buf[11] = b'0' + (min % 10) as u8;
                new_buf[12] = b'0' + (sec / 10 % 10) as u8;
                new_buf[13] = b'0' + (sec % 10) as u8;

                cache.set((now_secs, new_buf));
                buf[..14].copy_from_slice(&new_buf);
            }
        });

        // 2. Fast 6-char random alphanumeric suffix (Single u64 sampling)
        let mut val: u64 = rand::rng().random();
        for slot in &mut buf[14..20] {
            *slot = CHARSET[(val % 62) as usize];
            val /= 62;
        }

        RequestId(buf)
    }

    /// Create a dummy/zero RequestId (`00000000000000000000`) for system probes.
    pub const fn zero() -> Self {
        Self(*b"00000000000000000000")
    }

    /// Create a RequestId from a 20-character static string slice (primarily for tests).
    pub fn from_static(s: &'static str) -> Self {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 20, "RequestId static string must be exactly 20 bytes");
        let mut buf = [0u8; 20];
        buf.copy_from_slice(bytes);
        Self(buf)
    }

    /// Return the RequestId as a UTF-8 string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: `self.0` is constructed strictly from ASCII alphanumeric characters in `new()` and `from_static()`.
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_hash::FxHashSet;

    #[test]
    fn test_request_id_format() {
        let id = RequestId::new();
        let s = id.as_str();
        assert_eq!(s.len(), 20, "RequestId must be 20 characters long");

        // First 14 characters must be digits (YYYYMMDDHHMMSS)
        for &b in &id.0[..14] {
            assert!(b.is_ascii_digit(), "Timestamp char '{}' must be digit", b as char);
        }

        // Next 6 characters must be alphanumeric ([0-9a-zA-Z])
        for &b in &id.0[14..20] {
            assert!(
                b.is_ascii_alphanumeric(),
                "Random suffix char '{}' must be alphanumeric",
                b as char
            );
        }
    }

    #[test]
    fn test_request_id_zero() {
        let zero_id = RequestId::zero();
        assert_eq!(zero_id.as_str(), "00000000000000000000");
    }

    #[test]
    fn test_request_id_from_static() {
        let id = RequestId::from_static("20260727142048x7K9aZ");
        assert_eq!(id.as_str(), "20260727142048x7K9aZ");
    }

    #[test]
    fn test_request_id_uniqueness() {
        let mut set = FxHashSet::default();
        let count = 5_000;
        for _ in 0..count {
            let id = RequestId::new();
            assert!(set.insert(id), "Duplicate RequestId generated: {}", id);
        }
    }
}
