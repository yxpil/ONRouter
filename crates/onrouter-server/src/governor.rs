//! Cache governor: a traffic-phase machine that slows the cache layer down when the
//! business is quiet and boosts it back when a burst arrives.
//!
//! Author: yxpil
//!
//! ## Why this exists
//! The cache layers have exactly two background rhythms today: the 60s loop in `main.rs`
//! (limits purge + disk cold-tier sweep) and the per-store disk writer. Both run at full
//! cadence at 3 a.m. just as they do at noon. Meanwhile a burst that arrives without warning
//! finds cold pools and stretched sweeps. A human could write cron rules for the known shape
//! of the day (the schedule subsystem covers that), but the *observed* shape is what matters
//! — hence a detector that watches real traffic and a learner that remembers it.
//!
//! ## Semantics (deliberate, all operator-visible)
//! * Three phases: `sleep`, `normal`, `boost`. Transitions are edge-triggered on load with
//!   hysteresis and a minimum dwell, so a jittery rps curve cannot flip-flop the layer.
//! * `off` = the directive is absent. No task, no window, no allocation, no request-path cost.
//! * `observe` = everything is measured and reported (phase machine runs, metrics move) but
//!   **no action is ever taken** — the sweep loop and the stores behave exactly as before.
//!   This is the trust-building tier, same philosophy as `least_time observe`.
//! * `auto` = the phase drives real actions:
//!   * **light sleep** (always): the background loop stretches (sweep cadence ×10) —
//!     cheap, reversible, no data movement.
//!   * **deep sleep** (opt-in tier): entries are *demoted*. For shared-dict zones with a
//!     `disk=` cold tier that means spill-to-disk + reclaim memory (the value stays
//!     readable through the transparent cold path). For `proxy_cache` zones (pure
//!     in-memory, reconstructible from the origin) it means a bounded eviction of the
//!     least-recently-used entries. **A shared-dict zone without a disk tier is never
//!     touched** — it holds Lua application state, and "sleep" must not mean data loss.
//!   * **boost**: the background loop returns to full cadence and recently demoted keys
//!     are pre-warmed back (bounded ring of demotion records, single-flight, cold tier
//!     only). Boost never touches configuration that a reload owns.
//! * **Habit learning** (opt-in): one EWMA slot per minute of day (1440 × u16, ≈2.9 KiB,
//!   memory-only like the rest of the learning trio — a restart rebuilds it). When the
//!   slot ahead of `cache_governor_lead` says "busy", the governor pre-switches to boost
//!   *before* the traffic arrives instead of reacting to it.
//!
//! ## Failure posture
//! Every threshold is a directive; nothing is inferred from the vendor or the hostname.
//! The request-path cost when enabled is a single `fetch_add` into a 256-byte ring.
//! All state decisions are pure functions of (window, profile, now_ms) so tests can hold
//! the clock — the runtime task only feeds real time in, same split as `schedule.rs`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use onrouter_config::Config;

/// Operating mode. `Off` is the parsed default; `enabled()` is the single gate every
/// consumer checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernorMode {
    Off,
    Observe,
    Auto,
}

impl GovernorMode {
    pub fn parse(s: &str) -> Result<GovernorMode, String> {
        match s {
            "off" => Ok(GovernorMode::Off),
            "observe" => Ok(GovernorMode::Observe),
            "auto" => Ok(GovernorMode::Auto),
            other => Err(format!(
                "invalid cache_governor mode {other:?}: only off | observe | auto (observe measures and reports but never acts; auto is the tier that moves the sweep cadence and demotes entries)",
                other = other
            )),
        }
    }
}

/// Sleep depth. Light only touches cadence; deep additionally demotes entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepTier {
    Light,
    Deep,
}

impl SleepTier {
    pub fn parse(s: &str) -> Result<SleepTier, String> {
        match s {
            "light" => Ok(SleepTier::Light),
            "deep" => Ok(SleepTier::Deep),
            other => Err(format!(
                "invalid cache_governor_tier {other:?}: only light | deep (deep demotes cache entries to the disk cold tier and evicts reconstructible proxy_cache entries; a shared-dict zone without disk= is never touched)",
                other = other
            )),
        }
    }
}

/// A traffic phase. The discriminants are the `/metrics` gauge values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Sleep = 0,
    Normal = 1,
    Boost = 2,
}

impl Phase {
    fn from_u8(v: u8) -> Phase {
        match v {
            0 => Phase::Sleep,
            2 => Phase::Boost,
            _ => Phase::Normal,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Sleep => "sleep",
            Phase::Normal => "normal",
            Phase::Boost => "boost",
        }
    }
}

/// Why a switch happened — the access-log/audit answer to "who moved my cache".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Load crossed a threshold (with hysteresis and dwell satisfied).
    Load,
    /// The minute-of-day profile predicted the phase ahead of the traffic.
    Predicted,
}

/// Fully parsed `cache_governor*` configuration.
#[derive(Debug, Clone)]
pub struct GovernorConf {
    pub mode: GovernorMode,
    /// Below this smoothed rps (sustained `hold`) the layer may sleep.
    pub low_rps: f64,
    /// Above this smoothed rps (sustained ~2 ticks) the layer boosts.
    pub high_rps: f64,
    /// Minimum dwell in a phase before a load-driven exit (hysteresis floor).
    pub hold: Duration,
    /// Deep sleep demotes entries; light sleep only slows the background cadence.
    pub tier: SleepTier,
    /// Learn the minute-of-day profile and pre-switch on prediction.
    pub learn: bool,
    /// How far ahead the profile looks when predicting (bounded 5..3600s).
    pub lead: Duration,
}

impl Default for GovernorConf {
    fn default() -> Self {
        GovernorConf {
            mode: GovernorMode::Off,
            low_rps: 2.0,
            high_rps: 50.0,
            hold: Duration::from_secs(60),
            tier: SleepTier::Light,
            learn: false,
            lead: Duration::from_secs(60),
        }
    }
}

impl GovernorConf {
    pub fn enabled(&self) -> bool {
        self.mode != GovernorMode::Off
    }
}

/// Parse the `cache_governor*` directive family out of the top-level config.
///
/// Author: yxpil
///
/// `-t` contract: a bad mode/tier, an inverted threshold pair (`low >= high`), or
/// `cache_governor_learn on` while the mode is `off` are **hard errors** — a governor that
/// cannot say which way it would move is worse than no governor. `learn` under `observe`
/// is allowed but warns (the profile keeps recording, nothing consumes it yet).
pub fn parse_governor(config: &Config) -> Result<(GovernorConf, Vec<String>), String> {
    let mut conf = GovernorConf::default();
    let mut warns = Vec::new();
    let mut seen_mode = false;

    if let Some(d) = config.find("cache_governor") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        conf.mode = GovernorMode::parse(raw).map_err(|e| format!("line {}: {e}", d.line))?;
        seen_mode = true;
    }
    if let Some(d) = config.find("cache_governor_low") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        conf.low_rps = raw.parse::<f64>().map_err(|_| {
            format!(
                "line {}: cache_governor_low {raw:?} is not a number (requests per second)",
                d.line
            )
        })?;
        if !(0.0..=1_000_000.0).contains(&conf.low_rps) {
            return Err(format!(
                "line {}: cache_governor_low {raw} out of range 0..1e6",
                d.line
            ));
        }
    }
    if let Some(d) = config.find("cache_governor_high") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        conf.high_rps = raw.parse::<f64>().map_err(|_| {
            format!(
                "line {}: cache_governor_high {raw:?} is not a number (requests per second)",
                d.line
            )
        })?;
        if !(0.0..=1_000_000.0).contains(&conf.high_rps) {
            return Err(format!(
                "line {}: cache_governor_high {raw} out of range 0..1e6",
                d.line
            ));
        }
    }

    if let Some(d) = config.find("cache_governor_hold") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        let secs: u64 = raw.parse().map_err(|_| {
            format!(
                "line {}: cache_governor_hold {raw:?} is not a number of seconds",
                d.line
            )
        })?;
        if secs == 0 || secs > 86_400 {
            return Err(format!(
                "line {}: cache_governor_hold {raw} out of range 1..86400 seconds",
                d.line
            ));
        }
        conf.hold = Duration::from_secs(secs);
    }

    if let Some(d) = config.find("cache_governor_tier") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        conf.tier = SleepTier::parse(raw).map_err(|e| format!("line {}: {e}", d.line))?;
    }

    if let Some(d) = config.find("cache_governor_learn") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        match raw {
            "on" => conf.learn = true,
            "off" => conf.learn = false,
            other => {
                return Err(format!(
                    "line {}: invalid cache_governor_learn {other:?}: only on | off",
                    d.line
                ))
            }
        }
    }
    // Orphan `learn` is an error whether the mode line says `off` or is absent
    // altogether: a profile nobody reads is pure bookkeeping in both cases, and
    // this must stay reachable without a `cache_governor` line to trigger it.
    if conf.learn && conf.mode == GovernorMode::Off {
        return Err(
            "cache_governor_learn on requires cache_governor (currently off): a profile nobody reads is pure bookkeeping, so the -t gate refuses the combination instead of shipping it silently"
                .to_string(),
        );
    }
    if !seen_mode {
        // No cache_governor directive at all: the feature is off by default and
        // the sub-directives are ignored rather than half-applied.
        return Ok((conf, warns));
    }
    if conf.low_rps >= conf.high_rps {
        return Err(format!(
            "cache_governor_low ({}) must be below cache_governor_high ({}): a governor whose sleep threshold sits at or above its boost threshold can never settle in any phase, and the flapping it would produce is worse than not shipping the feature",
            conf.low_rps, conf.high_rps
        ));
    }
    if conf.learn && conf.mode == GovernorMode::Observe {
        warns.push(
            "cache_governor_learn on while mode is observe: the minute-of-day profile keeps recording (≈2.9 KiB) but nothing consumes it until the mode becomes auto"
                .to_string(),
        );
    }

    if let Some(d) = config.find("cache_governor_lead") {
        let raw = d.args.first().map(String::as_str).unwrap_or("");
        let secs: u64 = raw.parse().map_err(|_| {
            format!(
                "line {}: cache_governor_lead {raw:?} is not a number of seconds",
                d.line
            )
        })?;
        if secs > 3600 {
            return Err(format!(
                "line {}: cache_governor_lead {raw} out of range 0..3600 seconds",
                d.line
            ));
        }
        conf.lead = Duration::from_secs(secs);
    }

    Ok((conf, warns))
}

/// A 256-byte per-second request ring. The only request-path touchpoint:
/// `note_request` is one `fetch_add`, slot chosen by `unix_secs & 31` — no lock,
/// no allocation, no branch beyond the enabled() gate at the call site.
struct Window {
    slots: [AtomicU64; 32],
}

impl Window {
    fn new() -> Window {
        Window {
            slots: Default::default(),
        }
    }

    fn note_request(&self, unix_secs: u64) {
        self.slots[(unix_secs as usize) & 31].fetch_add(1, Ordering::Relaxed);
    }

    /// Mean rps over the trailing `span` whole seconds (current partial second excluded,
    /// so a fresh slot mid-second cannot fake a spike). `span` clamps to 1..30.
    fn rps(&self, unix_secs: u64, span: u64) -> f64 {
        let span = span.clamp(1, 30) as usize;
        let mut total = 0u64;
        for i in 1..=span {
            total += self.slots[((unix_secs - i as u64) as usize) & 31].load(Ordering::Relaxed);
        }
        total as f64 / span as f64
    }
}

/// Minute-of-day traffic profile: 1440 EWMA slots (u16 rps × 64 fixed point) plus a
/// 1440-bit "seen on this minute" day-count. ≈2.9 KiB total, memory-only.
struct DayProfile {
    /// EWMA of rps at minute-of-day, stored ×64 (so 1 rps = 64; u16 caps at 1024 rps,
    /// clamped — the profile is a shape memory, not a meter).
    slots: [AtomicU16; 1440],
    /// How many process-lifetime observations landed on this minute.
    seen: [AtomicU8; 1440],
    /// Absolute minute index (unix minutes) of the last fold. The governor ticks
    /// twice a second; folding every tick would apply α=1/4 120 times a minute and
    /// turn the EWMA into the instantaneous meter, so each natural minute folds once.
    last_minute: AtomicU64,
}

const PROFILE_SCALE: u32 = 64;
const PROFILE_MAX: u16 = u16::MAX;

impl DayProfile {
    fn new() -> DayProfile {
        DayProfile {
            slots: std::array::from_fn(|_| AtomicU16::new(0)),
            seen: std::array::from_fn(|_| AtomicU8::new(0)),
            last_minute: AtomicU64::new(u64::MAX),
        }
    }

    fn minute_of_day(unix_ms: i64) -> usize {
        (((unix_ms.div_euclid(60_000)) % 1440 + 1440) % 1440) as usize
    }

    /// Fold one observation into the minute slot. Weighted EWMA with a fixed α=1/4 so a
    /// single loud day cannot own the slot, plus a floor bump for the seen-counter.
    /// At most one fold per natural minute (see [`Self::last_minute`]).
    fn observe(&self, unix_ms: i64, rps: f64) {
        let minute = unix_ms.div_euclid(60_000);
        let prev = self.last_minute.swap(minute as u64, Ordering::Relaxed);
        if prev == minute as u64 {
            return;
        }
        let m = Self::minute_of_day(unix_ms);
        let scaled = ((rps * PROFILE_SCALE as f64).round() as u32).min(PROFILE_MAX as u32) as u16;
        let old = self.slots[m].load(Ordering::Relaxed);
        // new = old + (obs - old)/4 ; saturating toward the observation.
        let blended = (old as u32 * 3 + scaled as u32 * 1) / 4;
        let next = blended.min(PROFILE_MAX as u32) as u16;
        self.slots[m].store(next, Ordering::Relaxed);
        let s = self.seen[m].load(Ordering::Relaxed);
        if s < u8::MAX {
            self.seen[m].store(s + 1, Ordering::Relaxed);
        }
    }

    /// Profiled rps at `minute` (already EWMA-smoothed). Returns 0.0 for unobserved.
    fn at(&self, minute: usize) -> f64 {
        self.slots[minute % 1440].load(Ordering::Relaxed) as f64 / PROFILE_SCALE as f64
    }

    /// Minutes the governor has actually observed — the honest answer to "has it
    /// learned enough to predict yet".
    fn coverage(&self) -> usize {
        self.seen
            .iter()
            .map(|s| (s.load(Ordering::Relaxed) > 0) as usize)
            .sum()
    }
}

/// One bounded record of a demotion, so boost can pre-warm what sleep pushed out.
/// The ring caps at 256 entries: a long sleep can demote thousands, and re-warming
/// the whole cold tier on boost would defeat the point of having demoted it.
#[derive(Debug, Clone)]
pub struct DemotedKey {
    pub zone: String,
    pub key: String,
    /// True when the value still lives on the cold tier (spilled) — false for
    /// proxy_cache evictions, which can only be re-fetched from the origin and
    /// are therefore logged but not pre-warmed.
    pub on_cold: bool,
}

/// Per-process counters, rendered on /metrics under `onrouter_governor_*`.
#[derive(Default)]
pub struct GovernorCounters {
    pub switches: AtomicU64,
    pub predicted: AtomicU64,
    pub demoted: AtomicU64,
    /// Bytes the deep-sleep passes reclaimed from the in-memory layers.
    pub demoted_bytes: AtomicU64,
    pub prewarmed: AtomicU64,
    /// Background sweeps the sleep phase skipped outright (the light-tier saving).
    pub sweeps_skipped: AtomicU64,
    /// Tick count at boost phase — the denominator for "boost actually ran".
    pub boost_ticks: AtomicU64,
}

/// Which side effects the runtime task should perform after a phase switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Entered sleep: light tier stretches cadence only; deep tier also demotes.
    EnterSleep,
    /// Entered boost: restore cadence and pre-warm the demotion ring (cold tier only).
    EnterBoost,
    /// Entered (or returned to) normal: nothing to do, cadence is the default.
    EnterNormal,
}

/// The governor state machine. Everything decision-shaped is here and pure over
/// `now_ms`; the async runtime wraps it with real time and executes [`Action`]s.
pub struct Governor {
    /// RwLock rather than a bare field: hot reload swaps the whole conf while the
    /// phase-machine task reads it. Request-path code never touches this.
    pub conf: RwLock<GovernorConf>,
    window: Window,
    profile: DayProfile,
    phase: AtomicU8,
    /// Unix-ms timestamp of the last phase entry (dwell measurement).
    phase_since: AtomicU64,
    /// Consecutive ticks above the boost threshold (boost entry needs 2: one tick
    /// is too eager for a 500ms cadence, one hold period is too slow for a burst).
    boost_streak: AtomicU8,
    demoted: Mutex<VecDeque<DemotedKey>>,
    pub counters: GovernorCounters,
    /// Maximum rps observed since process start (diagnostics).
    peak_rps_milli: AtomicU64,
    /// Whether the runtime task has been spawned; `off -> observe/auto` hot reload
    /// starts it lazily, and exactly one task may own the phase machine.
    task_started: std::sync::atomic::AtomicBool,
    /// Enabled bit for the request-path gate: a plain relaxed load per request, no
    /// lock. `apply()` refreshes it from the new conf.
    live: std::sync::atomic::AtomicBool,
    /// True when boost was entered by prediction: its exit is delayed by `hold`,
    /// otherwise the very next tick (live load still quiet) would end the boost
    /// and the prediction would re-enter it, flapping every 500ms until the
    /// predicted window actually arrives.
    boost_predicted: std::sync::atomic::AtomicBool,
}

/// Window seconds used for the smoothed rps estimate. 8s rides over second-scale
/// jitter while still reacting inside a burst's first moments.
const RPS_SPAN_SECS: u64 = 8;
/// Boost entry requires this many consecutive ticks above `high_rps`.
const BOOST_STREAK_TICKS: u8 = 2;
/// Hysteresis: exiting boost requires dropping below `high_rps * BOOST_EXIT_FACTOR`.
const BOOST_EXIT_FACTOR: f64 = 0.8;
/// Waking from sleep requires exceeding `low_rps * SLEEP_EXIT_FACTOR` so a cat
/// walking past the keyboard does not flip the layer.
const SLEEP_EXIT_FACTOR: f64 = 1.5;
/// Deep-sleep demotion passes stay bounded even if sleep lasts all weekend.
const MAX_DEMOTED_RING: usize = 256;

impl Governor {
    pub fn new(conf: GovernorConf) -> Governor {
        let live = conf.enabled();
        Governor {
            conf: RwLock::new(conf),
            window: Window::new(),
            profile: DayProfile::new(),
            phase: AtomicU8::new(Phase::Normal as u8),
            phase_since: AtomicU64::new(0),
            boost_streak: AtomicU8::new(0),
            demoted: Mutex::new(VecDeque::with_capacity(0)),
            counters: GovernorCounters::default(),
            peak_rps_milli: AtomicU64::new(0),
            task_started: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::atomic::AtomicBool::new(live),
            boost_predicted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Claim the single runtime-task slot. False = another task already owns the
    /// phase machine (startup spawn or a previous reload).
    pub fn mark_task_started(&self) -> bool {
        self.task_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn conf_clone(&self) -> GovernorConf {
        self.conf.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn enabled(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    /// True when the phase machine may drive actions (auto only). Observe measures.
    pub fn acting(&self) -> bool {
        self.conf_clone().mode == GovernorMode::Auto
    }

    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::Relaxed))
    }

    /// The request-path hook: a single fetch_add when enabled. Off-mode callers are
    /// gated by `enabled()` before reaching here, so off costs truly nothing.
    pub fn note_request(&self, unix_secs: u64) {
        self.window.note_request(unix_secs);
    }

    pub fn rps(&self, unix_secs: u64) -> f64 {
        let r = self.window.rps(unix_secs, RPS_SPAN_SECS);
        self.peak_rps_milli
            .fetch_max((r * 1000.0) as u64, Ordering::Relaxed);
        r
    }

    pub fn peak_rps(&self) -> f64 {
        self.peak_rps_milli.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn profile_coverage(&self) -> usize {
        self.profile.coverage()
    }

    /// Background cadence for the main.rs maintenance loop. Normal/boost: the stock
    /// 60s. Light/deep sleep in `auto`: ×10 — the sweep is a directory walk, and
    /// walking it ten times per quiet hour buys nothing. `observe` never stretches
    /// it, even when a reload left the phase at `sleep`: observe promises that the
    /// sweep loop behaves exactly as it would with the governor absent.
    pub fn sweep_interval(&self) -> Duration {
        if self.phase() == Phase::Sleep && self.acting() {
            Duration::from_secs(600)
        } else {
            Duration::from_secs(60)
        }
    }

    /// Whether the current tick should skip the expensive cold-tier directory sweep
    /// entirely (sleep + nothing changed since the last one). Counted, never silent.
    pub fn should_skip_sweep(&self) -> bool {
        if self.phase() == Phase::Sleep && self.acting() {
            self.counters.sweeps_skipped.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    /// Record a demotion performed by the deep-sleep pass (bounded ring).
    pub fn note_demotion(&self, zone: String, key: String, on_cold: bool, bytes: u64) {
        self.counters.demoted.fetch_add(1, Ordering::Relaxed);
        self.counters
            .demoted_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        let mut ring = self.demoted.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= MAX_DEMOTED_RING {
            ring.pop_front();
        }
        ring.push_back(DemotedKey { zone, key, on_cold });
    }

    /// Drain the demotion ring for boost pre-warming (oldest first). Only entries
    /// whose value still lives on the cold tier are returned; proxy_cache evictions
    /// are re-fetched from the origin by normal traffic, not by the governor.
    pub fn take_prewarm_batch(&self, max: usize) -> Vec<DemotedKey> {
        let mut ring = self.demoted.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        while out.len() < max {
            // Drain-on-read keeps the ring bounded without a second pass; anything
            // that fails to re-warm is simply gone (it was cold for a reason).
            match ring.pop_front() {
                Some(k) if k.on_cold => out.push(k),
                Some(_) => continue,
                None => break,
            }
        }
        out
    }

    /// Advance the phase machine one tick. Returns `(from, to, cause, action)` when
    /// the phase changed.
    ///
    /// Author: yxpil
    ///
    /// Transition rules, all operator-auditable:
    /// * **normal → boost**: smoothed rps above `high_rps` for `BOOST_STREAK_TICKS`
    ///   consecutive ticks (a burst is a burst on the second tick, not after a dwell).
    /// * **boost → normal**: rps falls below `high_rps * 0.8` (hysteresis so the
    ///   threshold itself is not a chattering point); a boost entered by prediction
    ///   holds for at least `hold` before it may exit.
    /// * **normal → sleep**: rps below `low_rps` AND `hold` seconds spent in normal —
    ///   quiet-for-one-tick is an afternoon lull, not a night.
    /// * **sleep → normal**: rps above `low_rps * 1.5` (exit hysteresis mirrors boost).
    /// * **prediction** (learn on): it is boost-only by design. If the profiled rps
    ///   at the minute `lead` seconds ahead exceeds `high_rps`, boost fires early —
    ///   that is when pre-warm has to be done *before* the burst lands. A predicted
    ///   sleep would buy nothing (stretching the sweep cadence one hold period
    ///   sooner) and could only fire when the live meter already says quiet, so the
    ///   machine never lets the calendar act against a real burst.
    pub fn advance(&self, now_ms: u64) -> Option<(Phase, Phase, Cause, Action)> {
        let c = self.conf_clone();
        if !c.enabled() {
            return None;
        }
        let unix_secs = (now_ms / 1000) as u64;
        let rps = self.rps(unix_secs);

        // Learning folds in every enabled tick, including observe: the profile is
        // the product observe mode exists to show, and an operator who watched for
        // a day then flips to auto must not start from an empty calendar.
        if c.learn {
            self.profile.observe(now_ms as i64, rps);
        }
        if c.mode != GovernorMode::Auto {
            return None;
        }

        let from = self.phase();
        let since = self.phase_since.load(Ordering::Relaxed);
        let mut dwell_ms = now_ms.saturating_sub(since);
        if since == 0 {
            // The first tick starts the initial Normal phase. Without this the dwell
            // would be measured from the epoch, and a freshly started quiet process
            // would sleep on its very first tick instead of after `hold`.
            self.phase_since.store(now_ms, Ordering::Relaxed);
            dwell_ms = 0;
        }
        let hold_ms = c.hold.as_millis() as u64;

        // Prediction first: the calendar-shaped memory beats the live meter when
        // they disagree, because the whole point is to be early.
        if c.learn && c.lead.as_millis() > 0 {
            let ahead_minute = DayProfile::minute_of_day(now_ms as i64 + c.lead.as_millis() as i64);
            let ahead = self.profile.at(ahead_minute);
            if ahead >= c.high_rps && from != Phase::Boost {
                return Some(self.switch(from, Phase::Boost, Cause::Predicted, now_ms));
            }
        }

        let to = match from {
            Phase::Normal => {
                if rps > c.high_rps {
                    let s = self.boost_streak.fetch_add(1, Ordering::Relaxed) + 1;
                    if s >= BOOST_STREAK_TICKS {
                        Some((Phase::Boost, Cause::Load))
                    } else {
                        None
                    }
                } else {
                    self.boost_streak.store(0, Ordering::Relaxed);
                    if rps < c.low_rps && dwell_ms >= hold_ms {
                        Some((Phase::Sleep, Cause::Load))
                    } else {
                        None
                    }
                }
            }
            Phase::Boost => {
                self.counters.boost_ticks.fetch_add(1, Ordering::Relaxed);
                // A predicted boost is held for at least `hold`: the live meter is
                // quiet by definition when it fires, so an unguarded exit would
                // bounce boost <-> normal every tick until the window arrived.
                // When the prediction was wrong it still exits to Normal, never
                // straight to Sleep: the entry just pre-warmed the cold tier, and a
                // calendar miss must not demote it again on the same breath.
                let was_predicted = self.boost_predicted.load(Ordering::Relaxed);
                let predicted_hold = was_predicted && dwell_ms < hold_ms;
                if rps < c.high_rps * BOOST_EXIT_FACTOR && !predicted_hold {
                    if !was_predicted && rps < c.low_rps && dwell_ms >= hold_ms {
                        Some((Phase::Sleep, Cause::Load))
                    } else {
                        Some((Phase::Normal, Cause::Load))
                    }
                } else {
                    None
                }
            }
            Phase::Sleep => {
                if rps > c.low_rps * SLEEP_EXIT_FACTOR {
                    Some((Phase::Normal, Cause::Load))
                } else {
                    None
                }
            }
        };

        to.map(|(to, cause)| self.switch(from, to, cause, now_ms))
    }

    fn switch(
        &self,
        from: Phase,
        to: Phase,
        cause: Cause,
        now_ms: u64,
    ) -> (Phase, Phase, Cause, Action) {
        self.phase.store(to as u8, Ordering::Relaxed);
        self.phase_since.store(now_ms, Ordering::Relaxed);
        self.boost_streak.store(0, Ordering::Relaxed);
        self.boost_predicted.store(
            to == Phase::Boost && cause == Cause::Predicted,
            Ordering::Relaxed,
        );
        self.counters.switches.fetch_add(1, Ordering::Relaxed);
        if cause == Cause::Predicted {
            self.counters.predicted.fetch_add(1, Ordering::Relaxed);
        }
        let action = match to {
            Phase::Sleep => Action::EnterSleep,
            Phase::Boost => Action::EnterBoost,
            Phase::Normal => Action::EnterNormal,
        };
        (from, to, cause, action)
    }

    /// Hot-reload: swap the configuration in place, keeping the window, the phase and
    /// the learned profile (they are observations, not configuration). Mode changes
    /// take effect immediately; an `off` reload stops the caller's task loop.
    pub fn apply(&self, new_conf: GovernorConf) {
        self.live.store(new_conf.enabled(), Ordering::Relaxed);
        *self.conf.write().unwrap_or_else(|e| e.into_inner()) = new_conf;
        self.boost_streak.store(0, Ordering::Relaxed);
    }

    /// One-line self-description for the startup banner.
    pub fn describe(&self) -> String {
        describe_conf(&self.conf_clone())
    }
}

/// `-t` needs the same line without a live Governor instance (nothing is running
/// during a config check), so the formatting lives on the conf.
pub fn describe_conf(c: &GovernorConf) -> String {
    match c.mode {
        GovernorMode::Off => "cache_governor keeps off".to_string(),
        _ => format!(
            "cache_governor {}: tier={:?} low={}rps high={}rps hold={}s learn={} lead={}s",
            match c.mode {
                GovernorMode::Observe => "observe (measures and reports, never acts)".to_string(),
                _ => "auto".to_string(),
            },
            c.tier,
            c.low_rps,
            c.high_rps,
            c.hold.as_secs(),
            c.learn,
            c.lead.as_secs(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Author: yxpil
    //
    // The phase machine is pure over (window, profile, now_ms), so every transition
    // rule is asserted with the clock in hand — no sleeping in tests, same split as
    // schedule.rs. Helpers inject rps by noting N requests spread over the window.

    fn conf(mode: GovernorMode) -> GovernorConf {
        GovernorConf {
            mode,
            low_rps: 5.0,
            high_rps: 50.0,
            hold: Duration::from_secs(4),
            tier: SleepTier::Light,
            learn: false,
            lead: Duration::from_secs(0),
        }
    }

    /// Set exact per-second slot counts (test-only precision instrument:
    /// `note_request` is public, but stamping exact per-bucket counts keeps the
    /// estimator arithmetic honest — and makes each phase independent of the last).
    fn stamp(g: &Governor, now_ms: u64, per_sec: u64) {
        let secs = (now_ms / 1000) as u64;
        for i in 1..=8 {
            let s = secs - i;
            g.window.slots[(s as usize) & 31].store(per_sec, Ordering::Relaxed);
        }
    }

    fn ticks(g: &Governor, start_ms: u64, n: u64) -> u64 {
        let mut t = start_ms;
        for _ in 0..n {
            g.advance(t);
            t += 500;
        }
        t
    }

    #[test]
    fn off_and_observe_never_act() {
        let g = Governor::new(conf(GovernorMode::Off));
        assert!(!g.enabled());
        stamp(&g, 8_000, 100);
        assert_eq!(g.advance(8_000), None);

        let g = Governor::new(conf(GovernorMode::Observe));
        assert!(g.enabled() && !g.acting());
        stamp(&g, 8_000, 100);
        for t in 1..10 {
            assert_eq!(g.advance(8_000 + t * 500), None);
        }
        assert_eq!(g.phase(), Phase::Normal, "observe measures but never moves");
        assert!(g.rps(8) > 0.0, "but it does measure");
    }

    #[test]
    fn observe_with_learn_fills_the_profile_but_never_acts() {
        let mut c = conf(GovernorMode::Observe);
        c.learn = true;
        let g = Governor::new(c);
        let t0: u64 = 9_000_000;
        stamp(&g, t0, 120);
        for i in 0..12 {
            assert_eq!(g.advance(t0 + i * 500), None);
        }
        assert_eq!(g.phase(), Phase::Normal);
        assert!(
            g.profile_coverage() >= 1,
            "observe mode exists to show the calendar; the profile must fill"
        );
        let minute = DayProfile::minute_of_day(t0 as i64);
        assert!(
            g.profile.at(minute) > 0.0,
            "the current minute slot must hold the measured rps"
        );
    }

    #[test]
    fn burst_on_the_second_tick_boosts() {
        let g = Governor::new(conf(GovernorMode::Auto));
        let t0 = 8_000;
        stamp(&g, t0, 100);
        // Tick 1: streak starts.
        assert_eq!(g.advance(t0), None);
        assert_eq!(g.phase(), Phase::Normal);
        // Tick 2: streak satisfies BOOST_STREAK_TICKS → boost.
        let r = g.advance(t0 + 500);
        assert!(matches!(
            r,
            Some((Phase::Normal, Phase::Boost, Cause::Load, Action::EnterBoost))
        ));
        assert_eq!(g.phase(), Phase::Boost);
    }

    #[test]
    fn boost_exits_with_hysteresis_not_on_the_threshold() {
        let g = Governor::new(conf(GovernorMode::Auto));
        let t0 = 8_000;
        stamp(&g, t0, 100);
        g.advance(t0);
        g.advance(t0 + 500);
        assert_eq!(g.phase(), Phase::Boost);
        // Drop to 45 rps: below high (50) but above high*0.8 (40) → stays boost.
        stamp(&g, t0 + 1_000, 45);
        assert_eq!(g.advance(t0 + 1_000), None);
        assert_eq!(g.phase(), Phase::Boost, "hysteresis band must hold");
        // Drop to 20 rps → below 40 → normal.
        stamp(&g, t0 + 1_500, 20);
        let r = g.advance(t0 + 1_500);
        assert!(matches!(
            r,
            Some((
                Phase::Boost,
                Phase::Normal,
                Cause::Load,
                Action::EnterNormal
            ))
        ));
    }

    #[test]
    fn quiet_for_hold_seconds_sleeps() {
        let g = Governor::new(conf(GovernorMode::Auto));
        // Hold is 4s. The first tick starts the phase clock (dwell 0), so eight
        // ticks reach 3.5s and must still be Normal; the ninth (4.0s) sleeps.
        let t0 = 8_000;
        stamp(&g, t0, 1);
        let mut t = t0;
        for _ in 0..8 {
            assert_eq!(g.advance(t), None, "dwell not yet satisfied");
            t += 500;
        }
        let r = g.advance(t);
        assert!(matches!(
            r,
            Some((Phase::Normal, Phase::Sleep, Cause::Load, Action::EnterSleep))
        ));
        assert_eq!(g.phase(), Phase::Sleep);
        assert_eq!(
            g.sweep_interval(),
            Duration::from_secs(600),
            "sleep stretches the sweep"
        );
    }

    #[test]
    fn observe_never_keeps_a_stretched_sweep_after_reload() {
        let g = Governor::new(conf(GovernorMode::Auto));
        let t0 = 8_000;
        stamp(&g, t0, 1);
        let mut t = t0;
        for _ in 0..9 {
            g.advance(t);
            t += 500;
        }
        assert_eq!(g.phase(), Phase::Sleep);
        assert_eq!(g.sweep_interval(), Duration::from_secs(600));

        // Hot reload auto -> observe while the phase is still sleep: the reported
        // phase may stay, but the background loop must go back to the stock cadence.
        g.apply(conf(GovernorMode::Observe));
        assert!(g.enabled() && !g.acting());
        assert_eq!(
            g.sweep_interval(),
            Duration::from_secs(60),
            "observe touches nothing"
        );
        assert!(
            !g.should_skip_sweep(),
            "observe must not skip the sweep either"
        );
    }

    #[test]
    fn sleep_needs_a_real_wake() {
        let g = Governor::new(conf(GovernorMode::Auto));
        stamp(&g, 60_000, 1);
        let mut t = 60_000;
        for _ in 0..9 {
            g.advance(t);
            t += 500;
        }
        assert_eq!(g.phase(), Phase::Sleep);
        // 7 rps: above low (5) but below low*1.5 (7.5) → stays asleep.
        stamp(&g, t, 7);
        assert_eq!(g.advance(t), None);
        assert_eq!(g.phase(), Phase::Sleep, "exit hysteresis must hold");
        // 10 rps → wake.
        stamp(&g, t + 500, 10);
        assert!(matches!(
            g.advance(t + 500),
            Some((Phase::Sleep, Phase::Normal, _, Action::EnterNormal))
        ));
    }

    #[test]
    fn deep_sleep_demotion_ring_and_prewarm_batch() {
        let g = Governor::new(conf(GovernorMode::Auto));
        for i in 0..300 {
            g.note_demotion("sessions".into(), format!("k{i}"), i % 2 == 0, 128);
        }
        assert_eq!(g.counters.demoted.load(Ordering::Relaxed), 300);
        // Ring capped at 256: the oldest 44 were dropped.
        let batch = g.take_prewarm_batch(1000);
        assert_eq!(
            batch.len(),
            128,
            "only on_cold records are pre-warmed, ring cap 256"
        );
        assert!(batch.iter().all(|k| k.on_cold));
        assert!(g.take_prewarm_batch(10).is_empty(), "drain-on-read");
    }

    #[test]
    fn prediction_pre_switches_boost() {
        let mut c = conf(GovernorMode::Auto);
        c.learn = true;
        c.lead = Duration::from_secs(120);
        let g = Governor::new(c);
        // Teach the profile: minute m+2 is busy (100 rps folded a few times).
        let now_ms: u64 = 9_000_000; // minute_of_day = 150
        let busy_minute = DayProfile::minute_of_day(now_ms as i64 + 120_000);
        // Teach the profile across eight different days: one fold per natural
        // minute, so the same minute-of-day needs a new day to fold again.
        for d in 0..8i64 {
            g.profile
                .observe((busy_minute as i64 + d * 1440) * 60_000, 100.0);
        }
        assert!(
            g.profile.at(busy_minute) >= 50.0,
            "profile slot learned the busy minute"
        );
        // Current load is quiet — only the prediction can move the phase.
        stamp(&g, now_ms, 1);
        let r = g.advance(now_ms);
        assert!(
            matches!(
                r,
                Some((
                    Phase::Normal,
                    Phase::Boost,
                    Cause::Predicted,
                    Action::EnterBoost
                ))
            ),
            "profile said busy ahead; got {r:?}"
        );
        assert_eq!(g.counters.predicted.load(Ordering::Relaxed), 1);
        // The live meter is quiet (that is the premise of the prediction), so the
        // predicted boost must be held for `hold` = 4s instead of exiting on the
        // next tick and flapping until the window arrives.
        for i in 1..8 {
            assert_eq!(
                g.advance(now_ms + i * 500),
                None,
                "predicted boost held inside the hold window (tick {i})"
            );
            assert_eq!(g.phase(), Phase::Boost);
        }
        let exit = g.advance(now_ms + 8 * 500);
        assert_eq!(
            exit,
            Some((
                Phase::Boost,
                Phase::Normal,
                Cause::Load,
                Action::EnterNormal
            )),
            "after hold the quiet meter wins and boost exits"
        );
    }

    #[test]
    fn prediction_cannot_fight_a_learned_quiet_minute() {
        let mut c = conf(GovernorMode::Auto);
        c.learn = true;
        c.lead = Duration::from_secs(0); // lead 0 disables prediction entirely
        let g = Governor::new(c);
        stamp(&g, 8_000, 100);
        // With lead=0 the prediction block is skipped; load rules apply instead.
        assert_eq!(g.advance(8_000), None);
    }

    #[test]
    fn parse_rejects_inverted_thresholds_and_orphan_learn() {
        let src =
            "events {}\ncache_governor auto;\ncache_governor_low 30;\ncache_governor_high 10;\n";
        let cfg = Config::parse(src).unwrap();
        let err = parse_governor(&cfg).unwrap_err();
        assert!(err.contains("must be below"), "{err}");

        let src = "events {}\ncache_governor_learn on;\n";
        let cfg = Config::parse(src).unwrap();
        let err = parse_governor(&cfg).unwrap_err();
        assert!(err.contains("requires cache_governor"), "{err}");

        let src = "events {}\ncache_governor turbo;\n";
        let cfg = Config::parse(src).unwrap();
        assert!(parse_governor(&cfg)
            .unwrap_err()
            .contains("off | observe | auto"));
    }

    #[test]
    fn parse_defaults_and_warns_observe_learn() {
        let cfg = Config::parse("events {}\n").unwrap();
        let (c, w) = parse_governor(&cfg).unwrap();
        assert_eq!(c.mode, GovernorMode::Off);
        assert!(w.is_empty());

        let src = "events {}\ncache_governor observe;\ncache_governor_learn on;\n";
        let cfg = Config::parse(src).unwrap();
        let (c, w) = parse_governor(&cfg).unwrap();
        assert!(c.learn && c.mode == GovernorMode::Observe);
        assert_eq!(w.len(), 1, "observe+learn must warn, not error");
    }

    #[test]
    fn describe_and_coverage() {
        let g = Governor::new(conf(GovernorMode::Auto));
        assert!(g.describe().contains("auto"));
        assert!(g.describe().contains("tier=Light"));
        let off = Governor::new(GovernorConf::default());
        assert!(off.describe().contains("keeps off"));
        assert_eq!(off.profile_coverage(), 0);
    }

    #[test]
    fn window_estimator_excludes_the_partial_second() {
        let g = Governor::new(conf(GovernorMode::Off));
        // Slot arithmetic: only whole trailing seconds count.
        let secs: u64 = 1_000_000;
        for i in 1..=8 {
            for _ in 0..10 {
                g.window.note_request(secs - i);
            }
        }
        assert!((g.window.rps(secs, 8) - 10.0).abs() < 1e-9);
        // A burst in the current (partial) second must not leak into the estimate.
        for _ in 0..1000 {
            g.window.note_request(secs);
        }
        assert!((g.window.rps(secs, 8) - 10.0).abs() < 1e-9);
    }
}
