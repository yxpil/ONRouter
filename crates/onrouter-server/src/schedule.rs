//! The kernel of calendar scheduling: calendar time (cron) -> window open/closed state and the next fire time.
//!
//! Author: yxpil
//!
//! This layer deliberately **touches no action** and reads no configuration either: it is only a collection of
//! pure functions you can hand a clock to (following the `vip.rs` convention -- the production path feeds real
//! time, unit tests feed fake time). That way "is the computation right when the time comes" can be proven with
//! millisecond-level assertions, without making a test actually wait until nine in the morning.
//!
//! ## Why it is needed
//! The gateway originally had only two kinds of time: **interval** polling such as `reload <interval>;`, and
//! request-driven expiry checks (`max_fails/fail_timeout`). **Calendar** semantics like "open daily at 09:00,
//! closed at 23:00" had not a single line -- it has to be carried by something that knows when it should wake
//! up, and that is this module.
//!
//! ## Time zone stance (important, and a deliberate trade-off)
//! Only `UTC` and **fixed offsets** (the `+08:00` kind) are supported. IANA named zones (`Asia/Shanghai`) need a
//! tz database dependency, which was not vendored, so they are not done -- and the "jump with DST" semantics is
//! given up along with it: at a DST switch a fixed offset turns "daily at 09:00" into local 08:00 or 10:00. For
//! mainland China (no DST) this has no effect; EU/US sites must write UTC explicitly or change the offset with
//! the season, rather than pretend we can compute it correctly.

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Timelike, Utc};
use onrouter_config::Config;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
/// Search cap for cron, in years. Past it the expression is treated as never becoming true --
/// prefer a hard error over an unbounded search.
const SEARCH_CAP_YEARS: i32 = 8;

/// Time zone: UTC or a fixed minute offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    Utc,
    /// Minutes; `+08:00` -> 480.
    Fixed(i32),
}

impl Zone {
    pub fn parse(spec: &str) -> Result<Zone, String> {
        let s = spec.trim();
        if s.eq_ignore_ascii_case("utc") {
            return Ok(Zone::Utc);
        }
        let (sign, rest) = match s.as_bytes().first() {
            Some(b'+') | Some(b'-') => (s.as_bytes()[0] as char, &s[1..]),
            _ => return Err(format!("invalid timezone {spec}: only UTC or a fixed +HH:MM / -HH:MM offset is accepted")),
        };
        let (hh, mm) = match rest.split_once(':') {
            Some((h, m)) => (h, m),
            None => return Err(format!("invalid timezone {spec}: write it as +HH:MM (for example +08:00)")),
        };
        let h: i32 = hh
            .parse()
            .map_err(|_| format!("invalid timezone {spec}: the hour is not a number"))?;
        let m: i32 = mm
            .parse()
            .map_err(|_| format!("invalid timezone {spec}: the minute is not a number"))?;
        if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
            return Err(format!("invalid timezone {spec}: offset beyond +/-23:59"));
        }
        let total = h * 60 + m;
        if total == 0 {
            return Ok(Zone::Utc);
        }
        Ok(Zone::Fixed(if sign == '-' { -total } else { total }))
    }

    fn offset_minutes(&self) -> i32 {
        match self {
            Zone::Utc => 0,
            Zone::Fixed(m) => *m,
        }
    }
}

/// One cron field = a bitmap of the accepted value set; `lo`/`hi` are the value range, `names` the usable mnemonic names (lowercase).
#[derive(Clone, Copy)]
struct Spec {
    lo: u32,
    hi: u32,
    names: &'static [(&'static str, u32)],
}

const MINUTE: Spec = Spec { lo: 0, hi: 59, names: &[] };
const HOUR: Spec = Spec { lo: 0, hi: 23, names: &[] };
const DOM: Spec = Spec { lo: 1, hi: 31, names: &[] };
const MONTH: Spec = Spec {
    lo: 1,
    hi: 12,
    names: &[
        ("jan", 1),
        ("feb", 2),
        ("mar", 3),
        ("apr", 4),
        ("may", 5),
        ("jun", 6),
        ("jul", 7),
        ("aug", 8),
        ("sep", 9),
        ("oct", 10),
        ("nov", 11),
        ("dec", 12),
    ],
};
/// dow allows 7 for Sunday and normalizes it to 0 before writing, so the bitmap has 8 slots.
const DOW: Spec = Spec {
    lo: 0,
    hi: 7,
    names: &[
        ("sun", 0),
        ("mon", 1),
        ("tue", 2),
        ("wed", 3),
        ("thu", 4),
        ("fri", 5),
        ("sat", 6),
    ],
};

/// A parsed cron expression. Bit `v` of a bitmap means "value v is accepted".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cron {
    minute: u64,
    hour: u64,
    dom: u64,
    month: u64,
    dow: u64,
    /// Whether `*` was written decides the AND/OR rule for dom/dow (the old Vixie cron convention).
    dom_star: bool,
    dow_star: bool,
}

impl Cron {
    fn accepts_day(&self, day_of_month: u32, day_of_week: u32) -> bool {
        let dom_ok = self.dom & (1u64 << (day_of_month - 1)) != 0;
        let dow_ok = self.dow & (1u64 << (day_of_week % 7)) != 0;
        match (self.dom_star, self.dow_star) {
            (true, true) => true,
            (true, false) => dow_ok,
            (false, true) => dom_ok,
            // Both restricted: either one matching fires. This is cron's established semantics, not an AND.
            (false, false) => dom_ok || dow_ok,
        }
    }
}

fn name_value(spec: Spec, token: &str) -> Option<u32> {
    spec.names
        .iter()
        .find(|(n, _)| token.eq_ignore_ascii_case(n))
        .map(|(_, v)| *v)
}

fn atom(spec: Spec, token: &str) -> Result<u32, String> {
    if let Some(v) = name_value(spec, token) {
        return Ok(v);
    }
    let v: u32 = token
        .parse()
        .map_err(|_| format!("field value {token:?} is neither a number nor a usable mnemonic name"))?;
    if (spec.lo..=spec.hi).contains(&v) {
        Ok(v)
    } else {
        Err(format!(
            "field value {v} out of range {}..{}",
            spec.lo, spec.hi
        ))
    }
}

/// Parse a single field and return (bitmap, whether `*` was written).
fn parse_field(spec: Spec, text: &str) -> Result<(u64, bool), String> {
    let mut mask = 0u64;
    let mut star = false;
    if text.is_empty() {
        return Err("empty field".to_string());
    }
    for item in text.split(',') {
        let (body, step) = match item.split_once('/') {
            Some((b, s)) => {
                let st: u32 = s
                    .parse()
                    .map_err(|_| format!("step {s:?} is not a number"))?;
                if st == 0 {
                    return Err("step cannot be 0".to_string());
                }
                (b, Some(st))
            }
            None => (item, None),
        };
        let (from, to) = if body == "*" {
            star = step.is_none();
            (spec.lo, spec.hi)
        } else if let Some((a, b)) = body.split_once('-') {
            (atom(spec, a)?, atom(spec, b)?)
        } else {
            let a = atom(spec, body)?;
            if step.is_some() {
                // In cron `5/10` means `5-hi/10`, not "5 only".
                (a, spec.hi)
            } else {
                (a, a)
            }
        };
        if from > to {
            return Err(format!(
                "range {item:?} starts after it ends (wrap-around ranges such as 22-2 are not supported)"
            ));
        }
        let step = step.unwrap_or(1);
        // The bitmap is numbered by `value - lo`: dom (lo=1) and month (lo=1) therefore land on chrono's
        // 0-based readings, while minute/hour/dow have lo=0 so the bit number is the value itself. The read
        // side uses 0-based indices everywhere; there is no second convention.
        let mut v = from;
        while v <= to {
            mask |= 1u64 << (v - spec.lo);
            v += step;
        }
    }
    // dow's 7 (Sunday) normalizes to 0, so writing `0,7` is the same as writing `0`.
    if spec.hi == 7 && mask & (1 << 7) != 0 {
        mask |= 1;
        mask &= !(1 << 7);
    }
    Ok((mask, star))
}

/// Aliases such as `@daily`. `@reboot` is deliberately not supported: it means "the run when the process
/// started", which is startup configuration rather than a calendar, and letting it in would blur "scheduled".
const ALIASES: &[(&str, &str)] = &[
    ("@yearly", "0 0 1 1 *"),
    ("@annually", "0 0 1 1 *"),
    ("@monthly", "0 0 1 * *"),
    ("@weekly", "0 0 * * 0"),
    ("@daily", "0 0 * * *"),
    ("@midnight", "0 0 * * *"),
    ("@hourly", "0 * * * *"),
];

pub fn parse_cron(expr: &str) -> Result<Cron, String> {
    let expr = expr.trim();
    if let Some((_, expand)) = ALIASES.iter().find(|(a, _)| expr.eq_ignore_ascii_case(a)) {
        return parse_cron(expand);
    }
    let fields: Vec<&str> = expr.split_whitespace().collect();
    if fields.len() != 5 {
        return Err(format!(
            "cron needs 5 fields (minute hour day-of-month month day-of-week), got {}: {expr:?}",
            fields.len()
        ));
    }
    let (minute, _) = parse_field(MINUTE, fields[0])?;
    let (hour, _) = parse_field(HOUR, fields[1])?;
    let (dom, dom_star) = parse_field(DOM, fields[2])?;
    let (month, _) = parse_field(MONTH, fields[3])?;
    let (dow, dow_star) = parse_field(DOW, fields[4])?;
    Ok(Cron {
        minute,
        hour,
        dom,
        month,
        dow,
        dom_star,
        dow_star,
    })
}

fn floor_minute(dt: NaiveDateTime) -> NaiveDateTime {
    dt.with_second(0).unwrap().with_nanosecond(0).unwrap()
}

fn to_unix_ms(naive: NaiveDateTime, zone: Zone) -> i64 {
    naive
        .checked_sub_signed(chrono::Duration::minutes(zone.offset_minutes() as i64))
        .map(|utc_naive| utc_naive.and_utc().timestamp_millis())
        .unwrap_or(i64::MIN)
}

fn to_naive_in_zone(ms: i64, zone: Zone) -> Option<NaiveDateTime> {
    let utc = DateTime::<Utc>::from_timestamp_millis(ms)?.naive_utc();
    utc.checked_add_signed(chrono::Duration::minutes(zone.offset_minutes() as i64))
}

/// The next fire time of this expression strictly after `from_unix_ms` (in Unix milliseconds).
///
/// The semantics below are exactly the kind an operator will press us on:
/// - **strictly after**: when `from` lands exactly on `09:00` you get tomorrow's `09:00`, never the same minute twice;
/// - seconds are always zeroed, cron's granularity is the minute;
/// - bounded search: an impossible expression (`0 0 31 2 *`) returns `None`; the caller errors at config-check time;
/// - it advances by minute, but an unmatched month/day/hour is **skipped as a whole block**, far below a
///   minute-by-minute yearly scan.
pub fn next_after(cron: &Cron, zone: Zone, from_unix_ms: i64) -> Option<i64> {
    let start = from_unix_ms.checked_add(60_000)?;
    let mut dt = floor_minute(to_naive_in_zone(start, zone)?);
    let cap_year = dt.year() + SEARCH_CAP_YEARS;
    loop {
        if dt.year() > cap_year {
            return None;
        }
        if cron.month & (1u64 << dt.month0()) == 0 {
            // Jump to the 1st of the next month at 00:00.
            dt = dt
                .checked_add_signed(chrono::Duration::days(
                    days_in_month(dt.year(), dt.month()) as i64 - dt.day() as i64 + 1,
                ))?
                .with_day(1)?
                .with_hour(0)?
                .with_minute(0)?;
            continue;
        }
        if !cron.accepts_day(dt.day(), dt.weekday().num_days_from_sunday()) {
            dt = dt
                .checked_add_signed(chrono::Duration::days(1))?
                .with_hour(0)?
                .with_minute(0)?;
            continue;
        }
        if cron.hour & (1u64 << dt.hour()) == 0 {
            dt = dt
                .checked_add_signed(chrono::Duration::hours(1))?
                .with_minute(0)?;
            continue;
        }
        if cron.minute & (1u64 << dt.minute()) == 0 {
            dt = dt.checked_add_signed(chrono::Duration::minutes(1))?;
            continue;
        }
        return Some(to_unix_ms(dt, zone));
    }
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 30,
    }
}

/// Whether these two expressions can ever demand a state change in the **same minute**.
/// With open/close as a pair this is a configuration that must be vetoed: at such a moment "is it open or
/// closed now" has no answer, and the rule's fallback on a tie is "closed" -- that window would then stay
/// closed from the collision all the way to the next independent trigger point, which reads as "the schedule
/// did not take effect".
/// The decision domain is [`CYCLE_DAYS`]: the minute sets and the hour sets must both intersect, and the
/// 400-year cycle must contain a day accepted by both. So "no collision reported" is a proven absence, not
/// "we searched a few years and happened not to collide".
pub fn collides(a: &Cron, b: &Cron) -> bool {
    if a.minute & b.minute == 0 || a.hour & b.hour == 0 {
        return false;
    }
    let base = NaiveDate::from_ymd_opt(CYCLE_EPOCH.0, CYCLE_EPOCH.1, CYCLE_EPOCH.2)
        .expect("the cycle anchor itself must be a valid date");
    for i in 0..CYCLE_DAYS {
        let date = base
            .checked_add_signed(chrono::Duration::days(i))
            .expect("400 years cannot go past the NaiveDate range");
        if a.accepts_date(&date) && b.accepts_date(&date) {
            return true;
        }
    }
    false
}

/// The full cycle of the Gregorian calendar in days: 400 years = 146097 days, also an exact multiple of 7
/// (146097 / 7 = 20871 whole weeks). Using it as the decision domain, every month/day/weekday combination
/// from here on only repeats, so the conclusion holds forever over the representable range -- not "we looked
/// for a few years and saw no collision".
const CYCLE_DAYS: i64 = 146_097;
/// The cycle anchor: a clean century day, so the arithmetic is easy to check by hand.
const CYCLE_EPOCH: (i32, u32, u32) = (2000, 1, 1);

impl Cron {
    /// Only the month/day/weekday layers: whether a given day is accepted by this expression (no time of day, no zone).
    fn accepts_date(&self, date: &NaiveDate) -> bool {
        self.month & (1u64 << date.month0()) != 0
            && self.accepts_day(date.day(), date.weekday().num_days_from_sunday())
    }
}

/// The last time this expression fired at or before **the minute containing** `from_unix_ms`, searched
/// backwards (in Unix milliseconds).
///
/// Why we must compute backwards: when the gateway starts up mid-window or hot-reloads, "is it open or
/// closed right now" cannot be a guess -- it equals "of the last moment open happened and the last moment
/// close happened, which one is later". With only a forward computation that answer is either an assumption
/// or literally waiting until tomorrow.
///
/// Inclusive of equality: with `from` at `09:00:30` and cron `0 9 * * *` this returns today's 09:00.
/// Bounded by the same 8 years as `next_after`, only in the opposite direction.
pub fn prev_before(cron: &Cron, zone: Zone, from_unix_ms: i64) -> Option<i64> {
    let mut dt = floor_minute(to_naive_in_zone(from_unix_ms, zone)?);
    let cap_year = dt.year() - SEARCH_CAP_YEARS;
    loop {
        if dt.year() < cap_year {
            return None;
        }
        if cron.month & (1u64 << dt.month0()) == 0 {
            // Back to 23:59 on the last day of the previous month.
            dt = dt
                .with_day(1)?
                .with_hour(0)?
                .with_minute(0)?
                .checked_sub_signed(chrono::Duration::days(1))?
                .with_hour(23)?
                .with_minute(59)?;
            continue;
        }
        if !cron.accepts_day(dt.day(), dt.weekday().num_days_from_sunday()) {
            dt = dt
                .with_hour(23)?
                .with_minute(59)?
                .checked_sub_signed(chrono::Duration::days(1))?;
            continue;
        }
        if cron.hour & (1u64 << dt.hour()) == 0 {
            dt = dt
                .with_minute(59)?
                .checked_sub_signed(chrono::Duration::hours(1))?;
            continue;
        }
        if cron.minute & (1u64 << dt.minute()) == 0 {
            dt = dt.checked_sub_signed(chrono::Duration::minutes(1))?;
            continue;
        }
        return Some(to_unix_ms(dt, zone));
    }
}

/// A time window = a pair of cron expressions: `open` is the moment we enter, `close` the moment we leave.
///
/// Why a pair instead of an interval like "daily from 9:00 to 18:00": an interval either crosses midnight, a
/// week or a month, and every one of those needs its own syntax; two independent calendar trigger points
/// cover all of them by construction (`open 22 * * *` plus `close 2 * * *` is a maintenance window that
/// crosses midnight), and the semantics stay visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub zone: Zone,
    pub open: Cron,
    pub close: Cron,
}

impl Window {
    /// Whether this moment is inside the window. **The boundary minute belongs to the closing side**: from the
    /// minute `close` matches it is closed, so `open 09:00 / close 18:00` includes 09:00 and excludes 18:00.
    ///
    /// Both sides are searched backwards and compared for which happened later; if the two cron expressions
    /// could both hold in the same minute, `-t` vetoes that configuration first (see [`collides`]), so a
    /// "tie" never exists here.
    pub fn is_open_at(&self, now_ms: i64) -> bool {
        let opened = prev_before(&self.open, self.zone, now_ms);
        let closed = prev_before(&self.close, self.zone, now_ms);
        match (opened, closed) {
            (Some(o), Some(c)) => o > c,
            // Only an open is found and no close => it opened and has never closed; the reverse => it has not opened yet.
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// The earlier of the two trigger points -- note that the name deliberately avoids "change": **coming due
    /// does not necessarily change the state**.
    ///
    /// Counter-example (forced out by a unit test, not invented): `open 0 0 29 2 *` together with
    /// `close 30 0 1 3 *` -- in a non-leap year March 1st comes due every single year while the state never
    /// changed once, because that window is open for one day every four years. So the right move for the
    /// runner is to recompute `is_open_at` when a trigger comes due, never to "just flip it": a blind toggle
    /// turns this configuration into flapping between open and closed at every due point.
    pub fn next_trigger_at(&self, now_ms: i64) -> Option<i64> {
        let a = next_after(&self.open, self.zone, now_ms);
        let b = next_after(&self.close, self.zone, now_ms);
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }
}

/// Render Unix milliseconds as the wall-clock time a human would cross-check, read in `zone` (when the
/// operator asks "what time is that next one you computed, exactly", the log has to show a wall clock in the
/// zone it was computed in, not a bare epoch).
pub fn fmt_wall(ms: i64, zone: Zone) -> String {
    match to_naive_in_zone(ms, zone) {
        Some(n) => n.format("%Y-%m-%d %H:%M").to_string(),
        None => format!("{ms}ms"),
    }
}

// ==================== window table: configuration state + runtime state ====================

/// How many windows one table holds at most. The bound is a given: this table is walked at every minute
/// boundary, and "bounded" is a hard requirement of this codebase for every resident structure.
pub const MAX_WINDOWS: usize = 64;
/// A window name goes into a Prometheus label verbatim, so the character set has to be tightened before
/// anything else is discussed.
const MAX_NAME_LEN: usize = 64;
/// The sentinel for "there is no next trigger" (used once the window has been removed from the configuration).
const NO_NEXT: i64 = i64::MAX;

/// A window's replaceable definition: two cron expressions + the zone they are read in + the raw text for
/// the operator to cross-check.
#[derive(Debug, Clone)]
struct Def {
    tz_spec: String,
    open_expr: String,
    close_expr: String,
    win: Window,
}

/// Runtime state: the request path only touches `open` and `misses`, every other field lives in the lock and
/// only moves at a due point or at a reload.
pub struct Slot {
    pub name: String,
    /// `None` = this configuration no longer has the window (a hot reload removed it). The state is frozen from
    /// that point on and never flips again.
    def: Mutex<Option<Def>>,
    open: AtomicBool,
    next: AtomicI64,
    changes: AtomicU64,
    /// How many requests were rejected with 403 because this window was closed.
    denied: AtomicU64,
}

impl Slot {
    /// The definition lives in the lock, so the summary reads it all in one pass -- including the zone enum
    /// itself; never take `tz_spec` and parse it a second time.
    fn view(&self) -> Option<(String, String, String, Zone)> {
        let g = self.def.lock().unwrap_or_else(|e| e.into_inner());
        g.as_ref().map(|d| {
            (
                d.open_expr.clone(),
                d.close_expr.clone(),
                d.tz_spec.clone(),
                d.win.zone,
            )
        })
    }
}

/// One **real** state change. Note that this is not "a trigger came due": coming due does not imply a change
/// (see [`Window::next_trigger_at`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub open: bool,
    pub at_ms: i64,
}

/// The one-line snapshot read by `/metrics` and by the startup summary.
pub struct Stat {
    pub name: String,
    pub enabled: bool,
    pub open: bool,
    pub next_ms: i64,
    pub changes: u64,
    pub denied: u64,
}

pub struct Scheduler {
    slots: Vec<Arc<Slot>>,
    by_name: HashMap<String, Arc<Slot>>,
    /// A location referenced a window this process does not have -> that path is temporarily **passing**. This
    /// has to stay visible.
    misses: AtomicU64,
}

impl Scheduler {
    pub fn parse_all(config: &Config) -> Result<Self, String> {
        Self::parse_all_at(config, now_ms())
    }

    /// The same construction, but the caller supplies "now". Production passes `now_ms()`, unit tests pass fake
    /// time -- following the `vip.rs` convention: window state is a pure function of the calendar, and without
    /// that there is no way to assert a boundary to the millisecond.
    pub fn parse_all_at(config: &Config, now: i64) -> Result<Self, String> {
        let defs = Self::parse_defs(config)?;
        let mut slots = Vec::with_capacity(defs.len());
        let mut by_name = HashMap::new();
        for (name, def) in defs {
            let open = def.win.is_open_at(now);
            let next = def.win.next_trigger_at(now).unwrap_or(NO_NEXT);
            let slot = Arc::new(Slot {
                name: name.clone(),
                def: Mutex::new(Some(def)),
                open: AtomicBool::new(open),
                next: AtomicI64::new(next),
                changes: AtomicU64::new(0),
                denied: AtomicU64::new(0),
            });
            by_name.insert(name, Arc::clone(&slot));
            slots.push(slot);
        }
        // Sorted by name: metrics rendering and the -t summary must be comparable run to run, not jitter with
        // HashMap order.
        slots.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Scheduler {
            slots,
            by_name,
            misses: AtomicU64::new(0),
        })
    }

    /// Parse the top-level `schedule_window <name> { tz/open/close }` blocks. Returns the ordered table of
    /// (name, definition) pairs.
    fn parse_defs(config: &Config) -> Result<Vec<(String, Def)>, String> {
        let mut out: Vec<(String, Def)> = Vec::new();
        for d in config
            .root
            .block
            .iter()
            .filter(|x| x.name == "schedule_window")
        {
            let name = match d.arg(0) {
                Some(n) if is_valid_name(n) => n.to_string(),
                Some(n) => {
                    return Err(format!(
                        "line {}: schedule_window name {n:?} is invalid: only letters, digits, -, _ and . are \
                         allowed, length 1..{MAX_NAME_LEN} (the name goes into a metric label verbatim, so it \
                         must carry no quotes, spaces or newlines)",
                        d.line
                    ))
                }
                None => {
                    return Err(format!(
                        "line {}: schedule_window has no name: write it as schedule_window <name> {{ ... }}",
                        d.line
                    ))
                }
            };
            if out.iter().any(|(n, _)| *n == name) {
                return Err(format!(
                    "line {}: schedule_window '{name}' is declared twice: same-name windows cannot be told apart \
                     in the metrics",
                    d.line
                ));
            }
            let mut tz_spec: Option<String> = None;
            let mut open_expr: Option<String> = None;
            let mut close_expr: Option<String> = None;
            for c in &d.block {
                // A cron expression is full of spaces, so it is normally written as a quoted string; bare words
                // are rejoined into one expression too -- forgetting two quote characters must not turn this into
                // "the configuration cannot be read".
                let text = c.args.join(" ");
                match c.name.as_str() {
                    "tz" => tz_spec = Some(text),
                    "open" => open_expr = Some(text),
                    "close" => close_expr = Some(text),
                    other => {
                        return Err(format!(
                            "line {}: {other} is not a sub-directive of schedule_window '{name}' (only tz / open / \
                             close exist)",
                            c.line
                        ))
                    }
                }
            }
            // The zone must be written explicitly. Defaulting to UTC would quietly turn "opens daily at 09:00" into
            // "17:00" on a Chinese site, and that is exactly the class of "the configuration reads as if it worked"
            // that this codebase holds must hard-fail.
            let tz_spec = tz_spec.ok_or_else(|| format!(
                "line {}: schedule_window '{name}' has no tz: state explicitly whether it is UTC or a fixed \
                 offset (such as +08:00); there is no default so that \"which clock this opens on\" stays in the \
                 configuration",
                d.line
            ))?;
            let zone = Zone::parse(&tz_spec)?;
            let open_expr = open_expr.ok_or_else(|| format!(
                "line {}: schedule_window '{name}' has no open (open \"0 9 * * 1-5\";)",
                d.line
            ))?;
            let close_expr = close_expr.ok_or_else(|| format!(
                "line {}: schedule_window '{name}' has no close: with only open there is no decidable answer to \
                 \"is it open right now\" (if a route should stay open, do not gate it with a window)",
                d.line
            ))?;
            let open = parse_cron(&open_expr)
                .map_err(|e| format!("line {}: schedule_window '{name}' open: {e}", d.line))?;
            let close = parse_cron(&close_expr)
                .map_err(|e| format!("line {}: schedule_window '{name}' close: {e}", d.line))?;
            // Both expressions must really become true within the search cap, or the window never moves -- that is
            // a configuration error, not an operational fact.
            let probe = now_ms();
            if next_after(&open, zone, probe).is_none() || next_after(&close, zone, probe).is_none() {
                return Err(format!(
                    "line {}: schedule_window '{name}' has an open/close expression that never becomes true within \
                     {} years (such as 0 0 31 2 *): such a window looks configured but will never change state",
                    d.line, SEARCH_CAP_YEARS
                ));
            }
            if collides(&open, &close) {
                return Err(format!(
                    "line {}: schedule_window '{name}' has open and close that both demand a state change in the \
                     same minute, so at that moment nothing decides \"is it open or closed\" \
                     (open={open_expr:?} close={close_expr:?})",
                    d.line
                ));
            }
            out.push((
                name,
                Def {
                    tz_spec,
                    open_expr,
                    close_expr,
                    win: Window { zone, open, close },
                },
            ));
        }
        if out.len() > MAX_WINDOWS {
            return Err(format!(
                "too many schedule_window declarations: {}, the limit is {MAX_WINDOWS}: this table is walked once \
                 at every minute boundary",
                out.len()
            ));
        }
        Ok(out)
    }

    /// The window names declared in the configuration (`-t` uses this to veto misspellings in `schedule_access`).
    /// Names only here: parse errors are hard-failed earlier by [`Scheduler::parse_all`].
    pub fn declared_names(config: &Config) -> Vec<String> {
        config
            .root
            .block
            .iter()
            .filter(|d| d.name == "schedule_window")
            .filter_map(|d| d.arg(0).map(|s| s.to_string()))
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether this route may pass right now. **An unknown name = pass**, and the event is counted in `misses`:
    /// a misspelled name is already vetoed by `-t`, so getting here can only mean "a window added by a hot
    /// reload", and in that case shutting the traffic out is worse than letting it through (see the warning
    /// returned by [`Scheduler::apply`]). The request path does one HashMap lookup plus one AtomicBool load -- no
    /// lock, no timezone math.
    #[inline]
    pub fn is_open(&self, name: &str) -> bool {
        match self.by_name.get(name) {
            Some(s) => s.open.load(Ordering::Relaxed),
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Account for one request "blocked because the window was closed". Called only on the rejecting path; it
    /// never touches the atomics of the passing path.
    pub fn on_denied(&self, name: &str) {
        if let Some(s) = self.by_name.get(name) {
            s.denied.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Recompute at the due point: returns only the windows whose state **really** changed. The runner feeds real
    /// time once a minute. A trigger does not imply a flip -- every wake recomputes `is_open_at`, so a wake that
    /// came late or was skipped is never replayed as a change; state is derived from the calendar, not from "what
    /// I remember flipping" (unmatched gate lookups are counted separately, see [`Scheduler::is_open`]).
    ///
    /// Every recompute also refreshes `next`, otherwise the `next_fire_ms` self-evidence metric would stay frozen
    /// at the value from the moment of startup -- and the whole reason it exists is to let an operator check that
    /// "the next trigger the gateway computed" and "the time on my own watch" come from the same clock.
    pub fn advance(&self, now: i64) -> Vec<Change> {
        let mut out = Vec::new();
        for s in &self.slots {
            let (want, next) = {
                let g = s.def.lock().unwrap_or_else(|e| e.into_inner());
                match g.as_ref() {
                    Some(d) => (
                        d.win.is_open_at(now),
                        d.win.next_trigger_at(now).unwrap_or(NO_NEXT),
                    ),
                    None => continue,
                }
            };
            s.next.store(next, Ordering::Relaxed);
            if want != s.open.load(Ordering::Relaxed) {
                s.open.store(want, Ordering::Relaxed);
                s.changes.fetch_add(1, Ordering::Relaxed);
                out.push(Change { name: s.name.clone(), open: want, at_ms: now });
            }
        }
        out
    }



    /// Render an absolute instant as a wall-clock string in **the zone this window itself is configured with**
    /// (for the logs). If the operator wrote `tz +08:00` but the log prints UTC, "the schedule has not come due"
    /// and "the gateway is eight hours off" cannot be told apart. When the name is not found (the window was
    /// removed) this falls back to UTC -- it affects the readability of this one line only and takes part in no
    /// decision.
    pub fn wall(&self, name: &str, ms: i64) -> String {
        let zone = self
            .by_name
            .get(name)
            .and_then(|s| s.view().map(|v| v.3))
            .unwrap_or(Zone::Utc);
        fmt_wall(ms, zone)
    }

    pub fn snapshot(&self) -> Vec<Stat> {
        self.slots
            .iter()
            .map(|s| Stat {
                name: s.name.clone(),
                enabled: s.def.lock().unwrap_or_else(|e| e.into_inner()).is_some(),
                open: s.open.load(Ordering::Relaxed),
                next_ms: s.next.load(Ordering::Relaxed),
                changes: s.changes.load(Ordering::Relaxed),
                denied: s.denied.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// The summary line shared by startup, hot reload and `-t`. An operator has to be able to read in the log
    /// "what time this window computes from my configuration and what state it is in right now", otherwise "the
    /// schedule did not take effect" and "the schedule was closed to begin with" look exactly alike. `-t` is the
    /// enforcement point -- a bad window definition hard-fails there (see [`Scheduler::parse_defs`]) -- and
    /// describe() exists so that the startup banner and `-t` print the same line.
    pub fn describe(&self, now: i64) -> Vec<String> {
        let mut out = Vec::with_capacity(self.slots.len());
        for s in &self.slots {
            let next = s.next.load(Ordering::Relaxed);
            let open_txt = if s.open.load(Ordering::Relaxed) { "open" } else { "closed" };
            let Some((open_expr, close_expr, tz, zone)) = s.view() else {
                out.push(format!(
                    "schedule window '{}' removed from the configuration, state frozen at {open_txt}",
                    s.name
                ));
                continue;
            };
            let next_txt = if next == NO_NEXT {
                "none (window removed)".to_string()
            } else {
                fmt_wall(next, zone)
            };
            out.push(format!(
                "schedule window '{}' tz={tz} open={open_expr:?} close={close_expr:?} \
                 state={open_txt} next_trigger={next_txt} (now {})",
                s.name,
                fmt_wall(now, zone),
            ));
        }
        out
    }

    /// Hot reload: window names do not change within the process (same reasoning as the `limit_req` zones -- the
    /// references on the request path have to keep resolving), so this only swaps the definitions in place and
    /// recomputes the state; a hot reload must not lose the counters. What comes back is **notes for the log**,
    /// not errors: a window added has no instance in this process and a removed window's state freezes, and
    /// neither of those should fail the reload.
    pub fn apply(&self, config: &Config, now: i64) -> Vec<String> {
        let mut notes = Vec::new();
        let defs = match Self::parse_defs(config) {
            Ok(d) => d,
            // getting here means `-t` already passed once; if it really happens, the two readings have diverged,
            // so report it plainly.
            Err(e) => return vec![format!(
                "schedule: the window definitions in the new configuration do not parse, keeping the old \
                 windows: {e}"
            )],
        };
        for s in &self.slots {
            match defs.iter().find(|(n, _)| n == &s.name) {
                Some((_, d)) => {
                    let before = s.open.load(Ordering::Relaxed);
                    let want = d.win.is_open_at(now);
                    {
                        let mut g = s.def.lock().unwrap_or_else(|e| e.into_inner());
                        *g = Some(d.clone());
                    }
                    s.next.store(d.win.next_trigger_at(now).unwrap_or(NO_NEXT), Ordering::Relaxed);
                    if want != before {
                        s.open.store(want, Ordering::Relaxed);
                        s.changes.fetch_add(1, Ordering::Relaxed);
                        notes.push(format!(
                            "schedule: window '{}' recomputed from the new configuration, state {}->{}",
                            s.name,
                            if before { "open" } else { "closed" },
                            if want { "open" } else { "closed" }
                        ));
                    }
                }
                None => {
                    let mut g = s.def.lock().unwrap_or_else(|e| e.into_inner());
                    let was = g.take().is_some();
                    s.next.store(NO_NEXT, Ordering::Relaxed);
                    if was {
                        notes.push(format!(
                            "schedule: window '{}' removed from the new configuration, it stops flipping and its \
                             state is frozen at {} (the routes referencing it are already gone in the new routing \
                             round, this only keeps it out of the metrics)",
                            s.name,
                            if s.open.load(Ordering::Relaxed) { "open" } else { "closed" }
                        ));
                    }
                }
            }
        }
        for (n, _) in defs.iter().filter(|(n, _)| !self.by_name.contains_key(n)) {
            notes.push(format!(
                "schedule: window '{n}' from the new configuration has no instance in this process (windows are \
                 created at startup, so adding one needs a restart to take effect); until then the routes \
                 referencing it all pass -- this is counted in onrouter_schedule_gate_miss_total"
            ));
        }
        notes
    }
}

/// A window name ends up in a Prometheus label, hence the `[A-Za-z0-9-_.]` character set and the
/// [`MAX_NAME_LEN`] limit.
fn is_valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME_LEN
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The absolute clock (Unix milliseconds). Window state is a pure function of the calendar, so no process origin
/// is needed here, and this does not depend on the "process-relative clock used by rate limiting" from #103.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a UTC wall clock as milliseconds; in the tests it reads clearer than a bare number.
    fn ms(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(y, mo, d).unwrap(),
            chrono::NaiveTime::from_hms_opt(h, mi, 0).unwrap(),
        )
        .and_utc()
        .timestamp_millis()
    }

    fn show(at: i64, zone: Zone) -> String {
        DateTime::<Utc>::from_timestamp_millis(at)
            .unwrap()
            .naive_utc()
            .checked_add_signed(chrono::Duration::minutes(zone.offset_minutes() as i64))
            .unwrap()
            .format("%Y-%m-%dT%H:%M")
            .to_string()
    }

    fn fired(expr: &str, zone: Zone, from: i64) -> String {
        let c = parse_cron(expr).unwrap();
        show(next_after(&c, zone, from).unwrap(), zone)
    }

    #[test]
    fn parses_fields_masks_and_stars() {
        let c = parse_cron("*/15 9-17 1,15 jan-jul mon-fri").unwrap();
        // bit index = value - that field's lower bound, so minute/hour/dow use the value itself while dom/month are 0-based.
        assert_eq!(c.minute, (1 << 0) | (1 << 15) | (1 << 30) | (1 << 45));
        assert_eq!(c.hour, ((1u64 << 9) - 1) << 9, "9..17 is nine slots");
        assert!(c.hour & (1 << 8) == 0 && c.hour & (1 << 18) == 0);
        assert_eq!(c.dom, (1 << 0) | (1 << 14), "day 1 and day 15");
        assert_eq!(c.month, (1u64 << 7) - 1, "jan-jul is the seven slots 0..6");
        assert_eq!(c.dow, ((1u64 << 5) - 1) << 1, "mon-fri is 1..5");
        assert!(!c.dom_star && !c.dow_star);
        // A field of all * must fill the entire value range, not missing a single bit.
        let s = parse_cron("* * * * *").unwrap();
        assert_eq!(s.dom, (1u64 << 31) - 1);
        assert_eq!(s.month, (1u64 << 12) - 1);
        assert_eq!(s.dow, (1u64 << 7) - 1);
        assert!(s.dom_star && s.dow_star);
    }

    #[test]
    fn bare_star_is_not_a_named_range() {
        let c = parse_cron("0 0 * * *").unwrap();
        assert!(c.dom_star && c.dow_star);
        // `*/1` equals `*`, but `1/10` is not "just 1".
        let c2 = parse_cron("1/10 * * * *").unwrap();
        assert_eq!(
            c2.minute,
            (1 << 1) | (1 << 11) | (1 << 21) | (1 << 31) | (1 << 41) | (1 << 51)
        );
    }

    #[test]
    fn dow_seven_is_sunday_and_names_work() {
        let seven = parse_cron("0 0 * * 7").unwrap();
        let sun = parse_cron("0 0 * * sun").unwrap();
        assert_eq!(seven, sun);
        assert!(seven.dow & 1 != 0);
        let m = parse_cron("0 0 1 dec *").unwrap();
        assert!(m.month & (1 << 11) != 0);
    }

    #[test]
    fn aliases_expand() {
        assert_eq!(parse_cron("@daily").unwrap(), parse_cron("0 0 * * *").unwrap());
        assert_eq!(
            parse_cron("@yearly").unwrap(),
            parse_cron("@annually").unwrap()
        );
        assert_eq!(parse_cron("@hourly").unwrap(), parse_cron("0 * * * *").unwrap());
    }

    #[test]
    fn rejects_shapes_a_human_would_want_typed_wrong() {
        assert!(parse_cron("0 0 * *").is_err(), "four fields must be rejected");
        assert!(parse_cron("0 0 * * * *").is_err(), "six fields must be rejected");
        assert!(parse_cron("60 * * * *").is_err(), "minute out of range");
        assert!(parse_cron("* * 32 * *").is_err(), "day out of range");
        assert!(parse_cron("* * * 13 *").is_err(), "month out of range");
        assert!(parse_cron("* * * * 8").is_err(), "weekday out of range");
        assert!(parse_cron("*/0 * * * *").is_err(), "zero step");
        assert!(parse_cron("5-1 * * * *").is_err(), "wrap-around range");
        assert!(parse_cron("abc * * * *").is_err(), "neither a number nor a mnemonic name");
        assert!(parse_cron("@reboot").is_err(), "@reboot is a startup semantic, not a calendar");
    }

    #[test]
    fn hourly_grid_and_strictly_after() {
        // Landing exactly on the top of the hour => the next slot, never re-firing the same minute.
        assert_eq!(fired("*/15 * * * *", Zone::Utc, ms(2026, 10, 20, 4, 30)), "2026-10-20T04:45");
        assert_eq!(fired("30 4 * * *", Zone::Utc, ms(2026, 10, 20, 4, 30)), "2026-10-21T04:30");
        assert_eq!(fired("30 4 * * *", Zone::Utc, ms(2026, 10, 20, 4, 29)), "2026-10-20T04:30");
    }

    #[test]
    fn weekend_skips_to_monday() {
        // 2026-10-24 is a Saturday.
        assert_eq!(fired("0 9 * * 1-5", Zone::Utc, ms(2026, 10, 24, 12, 0)), "2026-10-26T09:00");
        // The "Monday 9:00" seen from Sunday 10:00 belongs to the next week.
        assert_eq!(fired("0 9 * * 1", Zone::Utc, ms(2026, 10, 25, 10, 0)), "2026-10-26T09:00");
    }

    #[test]
    fn leap_day_only_resolves_on_leap_years() {
        assert_eq!(fired("0 0 29 2 *", Zone::Utc, ms(2026, 6, 15, 0, 0)), "2028-02-29T00:00");
        assert_eq!(fired("0 0 29 2 *", Zone::Utc, ms(2028, 3, 1, 0, 0)), "2032-02-29T00:00");
    }

    #[test]
    fn month_rollover_keeps_day_and_time_reset() {
        // June has only 30 days => June must be skipped as a whole block and land on July 31 00:00 (rather than crawling minute by minute after 6/30).
        assert_eq!(fired("0 0 31 * *", Zone::Utc, ms(2026, 6, 15, 8, 0)), "2026-07-31T00:00");
        // February has no 31st: after noon on January 31, the next 31st is March 31.
        assert_eq!(fired("0 0 31 * *", Zone::Utc, ms(2026, 1, 31, 12, 0)), "2026-03-31T00:00");
        // Year-end crossing into the next year.
        assert_eq!(fired("0 0 1 1 *", Zone::Utc, ms(2026, 6, 15, 8, 0)), "2027-01-01T00:00");
        // Jumping from the start to the end of the same month, the day/hour/minute must all reset.
        assert_eq!(fired("30 6 20 * *", Zone::Utc, ms(2026, 3, 1, 0, 0)), "2026-03-20T06:30");
    }

    #[test]
    fn dom_and_dow_or_when_both_restricted() {
        // "day 1 OR Friday": 10/30 is a Friday, 11/1 is the start of a month -- both trigger.
        assert_eq!(fired("0 12 1 * 5", Zone::Utc, ms(2026, 10, 29, 13, 0)), "2026-10-30T12:00");
        assert_eq!(fired("0 12 1 * 5", Zone::Utc, ms(2026, 10, 30, 13, 0)), "2026-11-01T12:00");
        // With only dom restricted (dow is *) it stays an AND and does not let a day through just for its weekday.
        assert_eq!(fired("0 12 15 * *", Zone::Utc, ms(2026, 10, 15, 13, 0)), "2026-11-15T12:00");
    }

    #[test]
    fn fixed_offset_shifts_the_wall_clock() {
        // "daily 09:00 +08:00" == 01:00 UTC; read it back in UTC to confirm the offset really took effect.
        let c = parse_cron("0 9 * * *").unwrap();
        let cn = Zone::parse("+08:00").unwrap();
        let at = next_after(&c, cn, ms(2026, 10, 20, 0, 0)).unwrap();
        assert_eq!(show(at, Zone::Utc), "2026-10-20T01:00");
        assert_eq!(show(at, cn), "2026-10-20T09:00");
    }

    #[test]
    fn impossible_expression_gives_up() {
        // February has no 31st: the search must converge to None, not spin for 8 years.
        let c = parse_cron("0 0 31 2 *").unwrap();
        assert_eq!(next_after(&c, Zone::Utc, ms(2026, 1, 1, 0, 0)), None);
    }

    #[test]
    fn zone_parsing_is_narrow_on_purpose() {
        assert_eq!(Zone::parse("UTC").unwrap(), Zone::Utc);
        assert_eq!(Zone::parse("+00:00").unwrap(), Zone::Utc);
        assert_eq!(Zone::parse("+08:00").unwrap(), Zone::Fixed(480));
        assert_eq!(Zone::parse("-05:30").unwrap(), Zone::Fixed(-330));
        // A named zone needs a tz database; it is explicitly rejected before we carry that dependency, never silently treated as a fixed offset.
        assert!(Zone::parse("Asia/Shanghai").is_err());
        assert!(Zone::parse("+8").is_err());
        assert!(Zone::parse("+24:00").is_err());
    }

    /// The most recent time `expr` held at or before the minute of `from` (as a UTC wall-clock string).
    fn prev_at(expr: &str, from: i64) -> String {
        let c = parse_cron(expr).unwrap();
        show(prev_before(&c, Zone::Utc, from).unwrap(), Zone::Utc)
    }

    fn window(open: &str, close: &str, zone: Zone) -> Window {
        Window {
            zone,
            open: parse_cron(open).unwrap(),
            close: parse_cron(close).unwrap(),
        }
    }

    #[test]
    fn prev_before_is_inclusive_and_walks_backwards() {
        // Inclusive of equality: at 09:00:30 today's 09:00 has already happened.
        assert_eq!(prev_at("0 9 * * *", ms(2026, 10, 20, 9, 0) + 30_000), "2026-10-20T09:00");
        assert_eq!(prev_at("0 9 * * *", ms(2026, 10, 20, 8, 59)), "2026-10-19T09:00");
        assert_eq!(prev_at("*/15 * * * *", ms(2026, 10, 20, 10, 7)), "2026-10-20T10:00");
        // February has no 31st: searching back from March 1, the nearest is January 31.
        assert_eq!(prev_at("0 0 31 * *", ms(2026, 3, 1, 0, 0)), "2026-01-31T00:00");
        // Holds only in leap years.
        assert_eq!(prev_at("0 0 29 2 *", ms(2026, 6, 15, 0, 0)), "2024-02-29T00:00");
        // Monday only: searching back from Monday 08:00 gives last Monday, not "today has not come yet so count yesterday".
        assert_eq!(prev_at("0 9 * * 1", ms(2026, 10, 26, 8, 0)), "2026-10-19T09:00");
        // Under a fixed offset it must also walk back on the same wall clock.
        let cn = Zone::parse("+08:00").unwrap();
        let c = parse_cron("0 9 * * *").unwrap();
        assert_eq!(
            show(prev_before(&c, cn, ms(2026, 10, 20, 0, 30)).unwrap(), cn),
            "2026-10-19T09:00"
        );
    }

    #[test]
    fn forward_and_backward_agree_on_every_fire() {
        // These two identities are the evidence that "compute backwards" and "step forward" share one calendar
        // arithmetic: any fire time found forward, searched back, must land exactly on itself.
        for expr in [
            "*/7 3-5 * * *",
            "0 9 * * 1-5",
            "30 6 20 * *",
            "0 0 29 2 *",
            "17 * * * *",
            "0 0 1 1 *",
        ] {
            let c = parse_cron(expr).unwrap();
            let mut t = ms(2026, 3, 9, 0, 0);
            for _ in 0..30 {
                let n = next_after(&c, Zone::Utc, t).unwrap_or_else(|| panic!("{expr} found no next fire"));
                assert_eq!(prev_before(&c, Zone::Utc, n), Some(n), "{expr} at {}", show(n, Zone::Utc));
                assert_eq!(
                    next_after(&c, Zone::Utc, n - 1),
                    Some(n),
                    "{expr} one slot before {} must come back to itself",
                    show(n, Zone::Utc)
                );
                t = n;
            }
        }
    }

    #[test]
    fn window_state_is_derived_not_assumed() {
        // 2026-10-21 is a Wednesday, 10-24 a Saturday.
        let w = window("0 9 * * 1-5", "0 18 * * 1-5", Zone::Utc);
        assert!(w.is_open_at(ms(2026, 10, 21, 9, 0)), "counted as open from the very moment it opens");
        assert!(w.is_open_at(ms(2026, 10, 21, 17, 59)));
        assert!(!w.is_open_at(ms(2026, 10, 21, 18, 0)), "the boundary belongs to the closing side");
        assert!(!w.is_open_at(ms(2026, 10, 21, 8, 59)));
        assert!(!w.is_open_at(ms(2026, 10, 24, 12, 0)), "the weekend is closed all day");
        // The gateway can start mid-window: whether it is open or closed at this moment must be computable on the spot.
        assert!(w.is_open_at(ms(2026, 10, 21, 14, 20)));
    }

    #[test]
    fn window_next_trigger_picks_the_sooner_one() {
        let w = window("0 9 * * 1-5", "0 18 * * 1-5", Zone::Utc);
        assert_eq!(
            show(w.next_trigger_at(ms(2026, 10, 21, 10, 0)).unwrap(), Zone::Utc),
            "2026-10-21T18:00"
        );
        assert_eq!(
            show(w.next_trigger_at(ms(2026, 10, 21, 19, 0)).unwrap(), Zone::Utc),
            "2026-10-22T09:00"
        );
        // Saturday morning: the next change waits until Monday 9:00 (crossing the whole weekend).
        assert_eq!(
            show(w.next_trigger_at(ms(2026, 10, 24, 10, 0)).unwrap(), Zone::Utc),
            "2026-10-26T09:00"
        );
    }

    #[test]
    fn overnight_window_wraps_midnight() {
        // Opens 22:00, closes 02:00. Crossing midnight it must still be "open through the night", not degrade into "open only 22-24".
        let w = window("0 22 * * *", "0 2 * * *", Zone::Utc);
        assert!(w.is_open_at(ms(2026, 10, 21, 23, 0)));
        assert!(w.is_open_at(ms(2026, 10, 22, 1, 0)));
        assert!(!w.is_open_at(ms(2026, 10, 22, 2, 30)));
        assert!(!w.is_open_at(ms(2026, 10, 22, 21, 0)));
    }

    #[test]
    fn state_is_constant_between_triggers() {
        // This replaces the assumption "a flip is mandatory at every due point": a `0 0 29 2 *` / `30 0 1 3 *`
        // window "opens one day every four years", so March 1 comes due every year while the state never changes.
        // Hence the runner must **recompute at the due point**, never toggle (see the next_trigger_at docs).
        // What is checked here is the invariant that really holds: state is constant between two triggers, and
        // it changes at least once over the whole span (otherwise an is_open_at that always returns false would slip through).
        for (open, close) in [
            ("0 9 * * 1-5", "30 18 * * 1-5"),
            ("0 22 * * *", "0 2 * * *"),
            ("0 0 1 * *", "59 23 15 * *"),
            ("0 0 29 2 *", "30 0 1 3 *"),
        ] {
            let w = window(open, close, Zone::Utc);
            let mut t = ms(2026, 1, 1, 0, 0);
            let mut got = w.is_open_at(t);
            let mut changes = 0;
            for _ in 0..60 {
                let n = w
                    .next_trigger_at(t)
                    .unwrap_or_else(|| panic!("{open} / {close} found no next trigger"));
                // The instant just before a trigger still belongs to the previous segment => state must still be got.
                assert_eq!(
                    w.is_open_at(n - 60_000),
                    got,
                    "{open} / {close} should not have changed state before {}",
                    show(n, Zone::Utc)
                );
                let derived = w.is_open_at(n);
                if derived != got {
                    changes += 1;
                    got = derived;
                }
                t = n;
            }
            assert!(changes > 0, "{open} / {close} went through 60 triggers with no state change, the criterion must be dead");
        }
    }

    #[test]
    fn strictly_alternating_window_flips_at_every_trigger() {
        // Weekday 9:00 open, 18:00 close is the kind of window an operator really writes: the two trigger points
        // strictly alternate, so every due point must change state. This holds only for it, so it is written and
        // proven separately.
        let w = window("0 9 * * 1-5", "30 18 * * 1-5", Zone::Utc);
        let mut t = ms(2026, 1, 5, 0, 0);
        let mut got = w.is_open_at(t);
        for i in 0..80 {
            let n = w.next_trigger_at(t).unwrap();
            let derived = w.is_open_at(n);
            assert_ne!(derived, got, "trigger #{i} at {} did not change state", show(n, Zone::Utc));
            got = derived;
            t = n;
        }
    }

    #[test]
    fn collision_check_is_decidable_not_sampled() {
        let daily9 = parse_cron("0 9 * * *").unwrap();
        assert!(collides(&daily9, &daily9), "the same line obviously collides");
        assert!(collides(&daily9, &parse_cron("0 9 15 * *").unwrap()), "9:00 on the 15th every month must collide with 9:00 daily");
        assert!(!collides(&daily9, &parse_cron("30 18 * * *").unwrap()), "hours apart means no collision, days overlapping every day does not count");
        assert!(!collides(&parse_cron("0 12 * * 1").unwrap(), &parse_cron("0 12 * * 5").unwrap()), "Monday and Friday are never the same day");
        assert!(!collides(&parse_cron("0 0 29 2 *").unwrap(), &parse_cron("0 0 1 8 *").unwrap()), "leap-year 2/29 only versus 8/1 only");
        // The tricky one: dom and dow each never intersect, yet when "the 1st of a month falls on a Friday" both
        // hold at once. A pure bitmap intersection would judge this as no collision -- that is why it must be
        // derived day by day over the full 400-year cycle.
        assert!(collides(&parse_cron("0 12 1 * 1").unwrap(), &parse_cron("0 12 15 * 5").unwrap()));
    }

    // ==================== window table ====================

    fn table(text: &str, now: i64) -> Scheduler {
        let cfg = Config::parse(text).unwrap();
        Scheduler::parse_all_at(&cfg, now).unwrap_or_else(|e| panic!("a legal configuration was rejected: {e}"))
    }

    /// Reads a window's next trigger time (`None` = removed or the name does not exist).
    /// The production path uses `snapshot()`; this is handier in tests -- it also verifies that the snapshot and the schedule agree.
    fn next_ms(t: &Scheduler, name: &str) -> Option<i64> {
        t.snapshot()
            .into_iter()
            .find(|s| s.name == name)
            .filter(|s| s.enabled)
            .map(|s| s.next_ms)
    }

    fn reject(text: &str) -> String {
        let cfg = Config::parse(text).unwrap();
        match Scheduler::parse_all_at(&cfg, ms(2026, 10, 21, 0, 0)) {
            Ok(_) => panic!("this configuration should have been rejected: {text}"),
            Err(e) => e,
        }
    }

    /// Weekday 9:00-18:00 (+08:00). 2026-10-21 is a Wednesday.
    const OFFICE: &str = "schedule_window office { tz +08:00; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }";

    #[test]
    fn table_rejects_every_declared_but_inert_shape() {
        // Each must be a **hard failure**, not "looks configured but never moves".
        // The assertions carry the window name: an operator reading the error must locate which line it is directly.
        let no_tz = "schedule_window office { open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }";
        let e = reject(no_tz);
        assert!(e.contains("has no tz") && e.contains("office"), "{e}");

        let no_close = "schedule_window office { tz UTC; open \"0 9 * * 1-5\"; }";
        let e = reject(no_close);
        assert!(e.contains("has no close") && e.contains("office"), "{e}");

        let dup = format!("{OFFICE}\n{OFFICE}");
        let e = reject(&dup);
        assert!(e.contains("is declared twice"), "{e}");

        // A name with a space: only writing it as a quoted string reaches here, and that is exactly the character a metric label least tolerates.
        let e = reject("schedule_window \"office hours\" { tz UTC; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }");
        assert!(e.contains("is invalid"), "{e}");
        assert!(!is_valid_name("office hours") && !is_valid_name("office/x") && !is_valid_name(""));
        assert!(is_valid_name("office.hours-1_2"));

        let e = reject("schedule_window office { tz UTC; open \"0 0 31 2 *\"; close \"0 18 * * 1-5\"; }");
        assert!(e.contains("never becomes true"), "{e}");

        // open and close in the same minute: at that moment there is no criterion for "open or closed", it must be rejected rather than guessed by order.
        let e = reject("schedule_window office { tz UTC; open \"0 9 * * *\"; close \"0 9 * * *\"; }");
        assert!(e.contains("both demand a state change"), "{e}");

        let e = reject("schedule_window office { tz UTC; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; keep on; }");
        assert!(e.contains("is not a sub-directive"), "{e}");

        let e = reject("schedule_window { tz UTC; open \"0 9 * * *\"; close \"0 18 * * *\"; }");
        assert!(e.contains("has no name"), "{e}");
    }

    #[test]
    fn table_over_capacity_is_refused_not_truncated() {
        let lines: Vec<String> = (0..=MAX_WINDOWS)
            .map(|i| {
                format!(
                    "schedule_window w{i} {{ tz UTC; open \"0 {} * * *\"; close \"30 {} * * *\"; }}",
                    i % 24,
                    i % 24
                )
            })
            .collect();
        let over = lines.join("\n");
        let e = reject(&over);
        assert!(e.contains(&format!("the limit is {MAX_WINDOWS}")), "{e}");
        // Exactly at the limit must still build a table, otherwise this assertion is vacuously true.
        let fits = lines[..MAX_WINDOWS].join("\n");
        assert_eq!(table(&fits, ms(2026, 10, 21, 0, 0)).len(), MAX_WINDOWS);
    }

    #[test]
    fn table_state_and_next_are_derived_from_the_calendar() {
        // Wednesday 02:00 UTC = 10:00 at +08:00 => open; the same instant on Saturday => closed.
        // Construction gives no initial value, all derived from the calendar: after a restart the gate state is
        // correct with no persistence at all.
        let wed = table(OFFICE, ms(2026, 10, 21, 2, 0));
        assert!(wed.is_open("office"));
        assert_eq!(wed.len(), 1);
        assert!(!wed.is_empty());
        // next trigger = 18:00 +08 that day = 10:00 UTC.
        assert_eq!(next_ms(&wed, "office"), Some(ms(2026, 10, 21, 10, 0)));

        let sat = table(OFFICE, ms(2026, 10, 24, 2, 0));
        assert!(!sat.is_open("office"));
        // Saturday's next trigger jumps to Monday: 09:00 opening at +08:00 = 01:00 UTC.
        assert_eq!(next_ms(&sat, "office"), Some(ms(2026, 10, 26, 1, 0)));
    }

    #[test]
    fn unknown_window_name_passes_and_is_counted() {
        // pass + count, not block: see the is_open docs.
        let t = table(OFFICE, ms(2026, 10, 21, 2, 0));
        assert!(t.is_open("nope"));
        assert_eq!(t.misses(), 1);
        assert!(t.is_open("nope"));
        assert_eq!(t.misses(), 2);
        assert_eq!(next_ms(&t, "nope"), None);
    }

    #[test]
    fn advance_reports_only_real_changes_and_keeps_next_fresh() {
        let t = table(OFFICE, ms(2026, 10, 21, 2, 0));
        let before = next_ms(&t, "office").unwrap();
        // Not due yet: no change emitted, and next must not move backwards.
        assert!(t.advance(ms(2026, 10, 21, 9, 59)).is_empty());
        assert_eq!(next_ms(&t, "office"), Some(before));
        // Due: open->closed, and next pushed to the next day.
        let ch = t.advance(ms(2026, 10, 21, 10, 0));
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0], Change { name: "office".into(), open: false, at_ms: ms(2026, 10, 21, 10, 0) });
        assert!(!t.is_open("office"));
        assert!(next_ms(&t, "office").unwrap() > before);
        // The count in the snapshot only tallies real flips.
        let st = &t.snapshot()[0];
        assert_eq!(st.changes, 1);
        assert!(!st.open && st.enabled);
    }

    #[test]
    fn wake_without_a_flip_still_moves_next_forward() {
        // This is the core of how the runner moves: due != state change. A window open one day every four years
        // wakes once every 3/1 00:30, recomputes once, changes nothing, yet next must keep advancing.
        let cfg = "schedule_window leap { tz UTC; open \"0 0 29 2 *\"; close \"30 0 1 3 *\"; }";
        let t = table(cfg, ms(2026, 1, 1, 0, 0));
        assert!(!t.is_open("leap"));
        let mar1 = ms(2026, 3, 1, 0, 30);
        assert!(t.advance(mar1).is_empty(), "3/1 2026 due must not change state");
        // close holds every year, so after waking next advances to **next year's 3/1**, not the leap day --
        // if this computed 2028-02-29, next only looked at the open side.
        assert_eq!(next_ms(&t, "leap"), Some(ms(2027, 3, 1, 0, 30)));
        // Reaching the leap day 00:00 for real: open.
        assert_eq!(t.advance(ms(2028, 2, 29, 0, 0)).len(), 1);
        assert!(t.is_open("leap"));
        // Does the 3/1 trigger within the same day flip? 2028-03-01 00:30 closes.
        assert_eq!(t.advance(ms(2028, 3, 1, 0, 30)).len(), 1);
        assert!(!t.is_open("leap"));
    }

    #[test]
    fn describe_reads_the_windows_own_clock() {
        // This is the exact line an operator cross-checks: if it printed 09:00 (+08:00) as 01:00,
        // "the schedule did not take effect" and "the host clock is 8 hours off" would look identical.
        let t = table(OFFICE, ms(2026, 10, 21, 0, 30));
        let line = t.describe(ms(2026, 10, 21, 0, 30)).remove(0);
        assert!(line.contains("open=\"0 9 * * 1-5\""), "{line}");
        assert!(line.contains("next_trigger=2026-10-21 09:00"), "{line}");
        assert!(line.contains("now 2026-10-21 08:30"), "{line}");
        assert!(line.contains("state=closed"), "{line}");
    }

    #[test]
    fn apply_swaps_defs_freezes_removals_and_announces_new_names() {
        let two = format!("{OFFICE}\nschedule_window night {{ tz UTC; open \"0 22 * * *\"; close \"0 2 * * *\"; }}");
        // Table built at Saturday 02:00 UTC: office (the +08 weekday window) closed, night closing exactly at 02:00.
        let t = table(&two, ms(2026, 10, 24, 2, 0));
        assert_eq!(t.len(), 2);
        assert!(!t.is_open("office") && !t.is_open("night"));
        // The snapshot is sorted by name so metric rendering is comparable.
        let names: Vec<String> = t.snapshot().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["night", "office"]);

        // New configuration: office switched to open all day (recomputed as open right now), night removed, plus a never-instantiated new.
        let next_cfg = "schedule_window office { tz UTC; open \"0 0 * * *\"; close \"59 23 * * *\"; }\n\
                        schedule_window new { tz UTC; open \"0 0 1 1 *\"; close \"0 0 2 1 *\"; }";
        let notes = t.apply(&Config::parse(next_cfg).unwrap(), ms(2026, 10, 24, 12, 0));
        assert!(t.is_open("office"), "recompute under the new definition must take effect immediately");
        assert!(
            notes.iter().any(|n| n.contains("office") && n.contains("closed->open")),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n.contains("night") && n.contains("removed from the new configuration")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("'new'") && n.contains("all pass")), "{notes:?}");
        // A removed window: state frozen, no longer scheduled, but the name stays in the table (metrics must make clear it once existed).
        assert_eq!(next_ms(&t, "night"), None);
        let snap = t.snapshot();
        let frozen = snap.iter().find(|s| s.name == "night").unwrap();
        assert!(!frozen.enabled && !frozen.open);
        // 22:00 UTC is the moment night would originally have opened: after freezing it must not flip even once.
        assert!(t.advance(ms(2026, 10, 25, 22, 0)).is_empty(), "a frozen window is still flipping");
        assert!(!t.snapshot().into_iter().find(|s| s.name == "night").unwrap().open);
        // A new name has no instance => pass + counted in misses.
        assert!(t.is_open("new"));
        assert_eq!(t.misses(), 1);
        // An empty table builds no runner.
        assert!(table("", ms(2026, 10, 21, 0, 0)).is_empty());
    }

    #[test]
    fn declared_names_is_a_name_only_scan_for_the_test_flag() {
        // -t uses it to veto misspellings in schedule_access; here only names are taken, no calendar decision.
        let cfg = Config::parse(&format!("{OFFICE}\nschedule_window night {{ tz UTC; open \"0 22 * * *\"; close \"0 2 * * *\"; }}")).unwrap();
        let mut names = Scheduler::declared_names(&cfg);
        names.sort();
        assert_eq!(names, ["night", "office"]);
        assert!(Scheduler::declared_names(&Config::parse("worker_processes 2;").unwrap()).is_empty());
    }

}
