//! Minimal RFC 3339 <-> unix seconds, so rotation needs no date crate.

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Parses `YYYY-MM-DDTHH:MM:SS[.fff](Z|+HH:MM|-HH:MM)`; returns `None` for anything else or pre-1970 dates.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let (date, rest) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da) = (
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
        d.next()?.parse::<i64>().ok()?,
    );
    let tz_at = rest.rfind(['Z', '+', '-'])?;
    let (clock, tz) = rest.split_at(tz_at);
    let clock = clock.split('.').next()?;
    let mut c = clock.split(':');
    let (h, mi, se) = (
        c.next()?.parse::<i64>().ok()?,
        c.next()?.parse::<i64>().ok()?,
        c.next()?.parse::<i64>().ok()?,
    );
    let offset = match tz {
        "Z" => 0,
        _ => {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            let (oh, om) = tz[1..].split_once(':')?;
            sign * (oh.parse::<i64>().ok()? * 3_600 + om.parse::<i64>().ok()? * 60)
        }
    };
    let secs = days_from_civil(y, mo, da) * 86_400 + h * 3_600 + mi * 60 + se - offset;
    u64::try_from(secs).ok()
}

/// `2026-10-28 10:00:00Z`
pub fn format_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), Some(951_868_800));
        assert_eq!(
            parse_rfc3339("2026-10-28T10:00:00+00:00"),
            Some(1_793_181_600)
        );
    }

    #[test]
    fn offsets_and_fractions_normalise_to_utc() {
        let utc = parse_rfc3339("2026-10-28T10:00:00Z");
        assert_eq!(parse_rfc3339("2026-10-28T15:30:00+05:30"), utc);
        assert_eq!(parse_rfc3339("2026-10-28T05:00:00-05:00"), utc);
        assert_eq!(parse_rfc3339("2026-10-28T10:00:00.123Z"), utc);
    }

    #[test]
    fn garbage_is_none() {
        for bad in [
            "",
            "yesterday",
            "2026-10-28",
            "2026-10-28T10:00:00",
            "1969-12-31T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn format_round_trips_including_leap_day() {
        for t in [0u64, 951_868_800, 1_793_181_600, 1_709_208_000] {
            assert_eq!(parse_rfc3339(&format_utc(t).replace(' ', "T")), Some(t));
        }
        assert_eq!(format_utc(1_709_208_000), "2024-02-29 12:00:00Z");
    }
}
