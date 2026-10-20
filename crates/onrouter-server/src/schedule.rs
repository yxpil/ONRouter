//! 定时调度的内核：日历时间（cron）与间隔时间（interval）→ 下一次触发时刻。
//!
//! 这一层刻意**不碰任何动作**，也不读配置：它只是一个能被把时钟捏在手里的纯函数集合
//! （沿用 `vip.rs` 的口径 —— 生产路径喂真实时间，单测喂假时间）。这样"到点算得对不对"可以
//! 用毫秒级断言证完，而不必让测试真的等到早上九点。
//!
//! ## 为什么需要它
//! 网关原本只有两种时间：`reload <interval>;` 这类**间隔**轮询，以及请求驱动的过期判定
//! （`max_fails/fail_timeout`）。"每天 09:00 开放、23:00 关闭"这种**日历**语义一行都没有 ——
//! 它必须由一个知道自己何时该醒的东西来承担，这就是本模块。
//!
//! ## 时区口径（重要，且是刻意的取舍）
//! 只支持 `UTC` 与**固定偏移**（`+08:00` 这种）。IANA 命名时区（`Asia/Shanghai`）需要时区数据库
//! 依赖，没带进来之前不做 —— 而"跟着 DST 跳"的语义也就随之放弃：固定偏移在夏令时切换时刻会让
//! "每天 09:00"实际变成当地 08:00 或 10:00。对中国大陆（无 DST）没有影响，对欧美站点必须显式写
//! 成 UTC 或按季节改偏移，而不是假装我们能算对。

use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, Timelike, Utc};
use onrouter_config::Config;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 一次触发的最小间隔下限。比这更短的"定时"其实是热路径的事，不该由调度任务去轮。
///
/// 这里刻意比 `reload <interval>;` 自己的 200ms 下限更严：reload 只是碰一下配置的
/// mtime，而调度动作可能要跑 Lua、切换限流档位或触发重启，轮得越勤代价越不像"定时"。
pub const MIN_INTERVAL: Duration = Duration::from_secs(1);
/// cron 的搜索上限（年）。超过它就认为这条表达式永远不会成立，宁可报错也不要无限找。
const SEARCH_CAP_YEARS: i32 = 8;

/// 时区：UTC 或固定分钟偏移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Zone {
    Utc,
    /// 分钟数，`+08:00` → 480。
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
            _ => return Err(format!("无效时区 {spec}：只接受 UTC 或 +HH:MM / -HH:MM 固定偏移")),
        };
        let (hh, mm) = match rest.split_once(':') {
            Some((h, m)) => (h, m),
            None => return Err(format!("无效时区 {spec}：写成 +HH:MM（例如 +08:00）")),
        };
        let h: i32 = hh
            .parse()
            .map_err(|_| format!("无效时区 {spec}：小时不是数字"))?;
        let m: i32 = mm
            .parse()
            .map_err(|_| format!("无效时区 {spec}：分钟不是数字"))?;
        if !(0..=23).contains(&h) || !(0..=59).contains(&m) {
            return Err(format!("无效时区 {spec}：偏移超出 ±23:59"));
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

/// 一个 cron 字段 = 值集合位图；`lo`/`hi` 是取值范围，`names` 是可用的助记名（小写）。
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
/// dow 允许 7 表示周日，写入前归一到 0，所以位图有 8 格。
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

/// 解析后的 cron 表达式。位图第 `v` 位表示"值 v 被接受"。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cron {
    minute: u64,
    hour: u64,
    dom: u64,
    month: u64,
    dow: u64,
    /// `*` 与否决定 dom/dow 的 AND/OR 规则（Vixie cron 的老规矩）。
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
            // 两者都被限制：任一成立即触发。这是 cron 的既定语义，不是"且"。
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
        .map_err(|_| format!("字段值 {token:?} 不是数字也不是可用助记名"))?;
    if (spec.lo..=spec.hi).contains(&v) {
        Ok(v)
    } else {
        Err(format!(
            "字段值 {v} 超出范围 {}..{}",
            spec.lo, spec.hi
        ))
    }
}

/// 解析单个字段，返回（位图，是否写了 `*`）。
fn parse_field(spec: Spec, text: &str) -> Result<(u64, bool), String> {
    let mut mask = 0u64;
    let mut star = false;
    if text.is_empty() {
        return Err("字段为空".to_string());
    }
    for item in text.split(',') {
        let (body, step) = match item.split_once('/') {
            Some((b, s)) => {
                let st: u32 = s
                    .parse()
                    .map_err(|_| format!("步进 {s:?} 不是数字"))?;
                if st == 0 {
                    return Err("步进不能是 0".to_string());
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
                // `5/10` 在 cron 里等于 `5-hi/10`，不是"只有 5"。
                (a, spec.hi)
            } else {
                (a, a)
            }
        };
        if from > to {
            return Err(format!(
                "区间 {item:?} 起始大于结束（不支持回绕区间，如 22-2）"
            ));
        }
        let step = step.unwrap_or(1);
        // 位图按 `值 - lo` 编位：dom（lo=1）和 month（lo=1）因此落在 chrono 的 0 基读数上，
        // 而 minute/hour/dow 的 lo=0，编位就是值本身。读侧全部用 0 基下标，不再有第二套口径。
        let mut v = from;
        while v <= to {
            mask |= 1u64 << (v - spec.lo);
            v += step;
        }
    }
    // dow 的 7（周日）归一到 0，所以写 `0,7` 与写 `0` 等价。
    if spec.hi == 7 && mask & (1 << 7) != 0 {
        mask |= 1;
        mask &= !(1 << 7);
    }
    Ok((mask, star))
}

/// `@daily` 之类的别名。`@reboot` 故意不做：它的语义是"进程起来那次"，
/// 那属于启动配置而不是日历，混进来会让"定时"这个词失焦。
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
            "cron 需要 5 个字段（分 时 日 月 周），收到 {} 个：{expr:?}",
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

/// 解析间隔写法。**单位口径完全交给 `settings::parse_duration`** —— `500ms` / `15s` / `1m` /
/// `2h` / `1d`、裸数字按秒、允许小数，与 `reload`、`proxy_read_timeout` 那些写法一致。
/// 这里只加一条下限：定时任务不做亚秒级调度。
pub fn parse_interval(text: &str) -> Result<u64, String> {
    let d = crate::settings::parse_duration(text)
        .ok_or_else(|| format!("间隔 {text:?} 写法无效（参考 reload：500ms / 15s / 1m / 2h / 1d）"))?;
    if d < MIN_INTERVAL {
        return Err(format!(
            "间隔 {text:?} 小于 {}s：定时任务不做亚秒级调度",
            MIN_INTERVAL.as_secs()
        ));
    }
    Ok(d.as_millis() as u64)
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

/// 这条表达式在 `from_unix_ms` 之后的下一次触发时刻（Unix 毫秒）。
///
/// 语义要点，都是会被运维追问的那种：
/// - **严格晚于**：`from` 正好落在 `09:00` 上时，返回的是明天的 `09:00`，不会重复触发同一分钟；
/// - 秒一律归零，cron 的粒度就是分钟；
/// - 搜索有上界，永不成立的表达式（`0 0 31 2 *`）返回 `None`，由调用方在配置校验阶段报错；
/// - 按分钟推进，遇到不匹配的月/日/时直接**整块跳过**，最坏情况远小于"逐年遍历分钟"。
pub fn next_after(cron: &Cron, zone: Zone, from_unix_ms: i64) -> Option<i64> {
    let start = from_unix_ms.checked_add(60_000)?;
    let mut dt = floor_minute(to_naive_in_zone(start, zone)?);
    let cap_year = dt.year() + SEARCH_CAP_YEARS;
    loop {
        if dt.year() > cap_year {
            return None;
        }
        if cron.month & (1u64 << dt.month0()) == 0 {
            // 跳到下月 1 日 00:00。
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

/// 这两条表达式会不会在**同一分钟**都要求改变状态。
/// on/close 成对时这是必须否决的配置：碰上这一刻，
/// "现在算开着还是算关着"没有答案，而判据在平手时的兜底方向是"关" ——
/// 这条窗口会从撞车那一刻起一直关到下一个独立触发点，看起来就是"定时没生效"。
/// 判定域见 [`CYCLE_DAYS`]：分钟集合与小时集合都有交集，且 400 年周期里存在
/// 同一天被两者接受。所以"没报冲突"是证明过的没有冲突，不是"找几年没撞上"。
pub fn collides(a: &Cron, b: &Cron) -> bool {
    if a.minute & b.minute == 0 || a.hour & b.hour == 0 {
        return false;
    }
    let base = NaiveDate::from_ymd_opt(CYCLE_EPOCH.0, CYCLE_EPOCH.1, CYCLE_EPOCH.2)
        .expect("周期锚点本身必须合法");
    for i in 0..CYCLE_DAYS {
        let date = base
            .checked_add_signed(chrono::Duration::days(i))
            .expect("400 年不会超出 NaiveDate 的范围");
        if a.accepts_date(&date) && b.accepts_date(&date) {
            return true;
        }
    }
    false
}

/// 格里历的完整周期天数：400 年 = 146097 天，同时是 7 的整数倍
/// （146097 / 7 = 20871 整周）。用它做判定域，"月-日-星期几"的组合从这里起只会重复，
/// 所以结论对整个可表示时间范围永久有效 —— 不是"找了几年没撞上"。
const CYCLE_DAYS: i64 = 146_097;
/// 周期锚点，取一个整世纪日便于人工核对。
const CYCLE_EPOCH: (i32, u32, u32) = (2000, 1, 1);

impl Cron {
    /// 只看月/日/周三层：某一天是否被这条表达式接受（不涉时刻，也不涉时区）。
    fn accepts_date(&self, date: &NaiveDate) -> bool {
        self.month & (1u64 << date.month0()) != 0
            && self.accepts_day(date.day(), date.weekday().num_days_from_sunday())
    }
}

/// 这条表达式在 `from_unix_ms` **所在分钟或更早**的下一次成立时刻往前找（Unix 毫秒）。
///
/// 为什么需要"往回算"：网关在窗口中途启动或热重载时，"此刻开着还是关着"不能靠猜 ——
/// 它等于"open 与 close 各自最近一次发生的时刻谁更晚"。只有正向算式的话，
/// 这个答案要么靠假设、要么真的等到明天。
///
/// 含等于：`from` 落在 `09:00:30` 而 cron 是 `0 9 * * *` 时返回今天的 09:00。
/// 与 `next_after` 一样有 8 年上界，只是方向相反。
pub fn prev_before(cron: &Cron, zone: Zone, from_unix_ms: i64) -> Option<i64> {
    let mut dt = floor_minute(to_naive_in_zone(from_unix_ms, zone)?);
    let cap_year = dt.year() - SEARCH_CAP_YEARS;
    loop {
        if dt.year() < cap_year {
            return None;
        }
        if cron.month & (1u64 << dt.month0()) == 0 {
            // 回到上月最后一天的 23:59。
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

/// 一个时间窗口 = 一对 cron：`open` 那一刻进入，`close` 那一刻离开。
///
/// 为什么成对而不是"每天 9 点到 18 点"那种区间写法：区间要么跨午夜、要么跨周、要么跨月，
/// 每一种都得再编一套语法；两个独立的日历触发点天然覆盖这几种情况
/// （`open 22 * * *` + `close 2 * * *` 就是跨午夜的维护窗口），而语义仍然看得见。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub zone: Zone,
    pub open: Cron,
    pub close: Cron,
}

impl Window {
    /// 此刻是否在窗口内。**边界归"离开"那一侧**：close 命中的那一分钟起就是关闭，
    /// 所以 `open 09:00 / close 18:00` 含 09:00、不含 18:00。
    ///
    /// 两边都往回找，比较谁更晚发生；两条 cron 若会在同一分钟同时成立，`-t` 先否决
    /// （见 [`collides`]），所以这里不存在"平手"的配置。
    pub fn is_open_at(&self, now_ms: i64) -> bool {
        let opened = prev_before(&self.open, self.zone, now_ms);
        let closed = prev_before(&self.close, self.zone, now_ms);
        match (opened, closed) {
            (Some(o), Some(c)) => o > c,
            // 只找得到开、找不到关 ⇒ 开了就没关过；反过来 ⇒ 还没开过。
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// 两个触发点里更早的那个 —— 注意名字里刻意不叫"改变"：**到点不一定改变状态**。
    ///
    /// 反例（这条是单测逼出来的，不是设想）：`open 0 0 29 2 *` 与 `close 30 0 1 3 *`，
    /// 在非闰年里 3 月 1 日年年到点，而状态一次都没变过 —— 那个窗口四年才开一天。
    /// 所以 runner 的正确走法是"到点重新算 `is_open_at`"，绝不是"翻一下"：
    /// 盲目取反会把这种配置变成"每次到点都在开/关之间乱跳"。
    pub fn next_trigger_at(&self, now_ms: i64) -> Option<i64> {
        let a = next_after(&self.open, self.zone, now_ms);
        let b = next_after(&self.close, self.zone, now_ms);
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }
}

/// 把 Unix 毫秒按 `zone` 写成人类要核对的那种时间（运维追问"你算的下次到底是几点"时，
/// 日志里必须出现带时区口径的墙钟，而不是一个裸 epoch）。
pub fn fmt_wall(ms: i64, zone: Zone) -> String {
    match to_naive_in_zone(ms, zone) {
        Some(n) => n.format("%Y-%m-%d %H:%M").to_string(),
        None => format!("{ms}ms"),
    }
}

// ==================== 窗口表：配置态 + 运行态 ====================

/// 一张表里最多多少个窗口。上限是给定的：这张表会在每个分钟边界被走一遍，
/// 而"有界"是这套代码库对每一个常驻结构的硬要求。
pub const MAX_WINDOWS: usize = 64;
/// 窗口名会原样进 Prometheus 标签，所以字符集必须先收紧再谈别的。
const MAX_NAME_LEN: usize = 64;
/// "没有下一次触发"的哨兵值（窗口已从配置移除时使用）。
const NO_NEXT: i64 = i64::MAX;

/// 一个窗口的可替换定义：两条 cron + 时区口径 + 原文（原文是给运维核对用的）。
#[derive(Debug, Clone)]
struct Def {
    tz_spec: String,
    open_expr: String,
    close_expr: String,
    win: Window,
}

/// 运行态：请求路径只碰 `open` 与 `misses`，其余字段都在锁里、只在到点与重载时动。
pub struct Slot {
    pub name: String,
    /// `None` = 这份配置里已经没有这个窗口了（热重载移除）。状态就此冻结，不再翻转。
    def: Mutex<Option<Def>>,
    open: AtomicBool,
    next: AtomicI64,
    changes: AtomicU64,
}

impl Slot {
    /// 定义在锁里，摘要一次性读全 —— 包括时区枚举本身，不要拿 `tz_spec` 去二次解析。
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

/// 一次**真实的**状态变化。注意不是"到点了"：到点不一定变（见 [`Window::next_trigger_at`]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub open: bool,
    pub at_ms: i64,
}

/// `/metrics` 与启动摘要读的一行快照。
pub struct Stat {
    pub name: String,
    pub enabled: bool,
    pub open: bool,
    pub next_ms: i64,
    pub changes: u64,
}

pub struct Scheduler {
    slots: Vec<Arc<Slot>>,
    by_name: HashMap<String, Arc<Slot>>,
    /// 有 location 引用了本进程没有的窗口 ⇒ 那条路暂时是**放行**的。必须可见。
    misses: AtomicU64,
}

impl Scheduler {
    pub fn parse_all(config: &Config) -> Result<Self, String> {
        Self::parse_all_at(config, now_ms())
    }

    /// 同一个构造，但把"现在"交给调用方。生产传 `now_ms()`，单测传假时间 ——
    /// 沿用 `vip.rs` 的口径：窗口状态是日历的纯函数，没有它就没法在毫秒里断言边界。
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
            });
            by_name.insert(name, Arc::clone(&slot));
            slots.push(slot);
        }
        // 按名字排序：指标渲染与 -t 摘要必须逐次可比对，不能跟着 HashMap 抖。
        slots.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Scheduler {
            slots,
            by_name,
            misses: AtomicU64::new(0),
        })
    }

    /// 解析顶层 `schedule_window <名字> { tz/open/close }`。返回 (名字, 定义) 的有序表。
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
                        "第 {} 行 schedule_window 的名字 {n:?} 无效：只允许字母、数字、-、_、.，\
                         长度 1..{MAX_NAME_LEN}（名字会原样进指标标签，必须不能带引号、空格或换行）",
                        d.line
                    ))
                }
                None => {
                    return Err(format!(
                        "第 {} 行 schedule_window 缺少名字（schedule_window <名字> {{ … }}）",
                        d.line
                    ))
                }
            };
            if out.iter().any(|(n, _)| *n == name) {
                return Err(format!(
                    "第 {} 行 schedule_window '{name}' 重复声明：同名窗口会让指标分不出是哪一个",
                    d.line
                ));
            }
            let mut tz_spec: Option<String> = None;
            let mut open_expr: Option<String> = None;
            let mut close_expr: Option<String> = None;
            for c in &d.block {
                // cron 里全是空格，正常必须写成引号串；写成裸的也能拼回一条表达式，
                // 不该因为少打两个引号就变成"这条配置读不懂"。
                let text = c.args.join(" ");
                match c.name.as_str() {
                    "tz" => tz_spec = Some(text),
                    "open" => open_expr = Some(text),
                    "close" => close_expr = Some(text),
                    other => {
                        return Err(format!(
                            "第 {} 行 schedule_window '{name}' 里 {other} 不是子指令（只有 tz / open / close）",
                            c.line
                        ))
                    }
                }
            }
            // 时区必须显式写。默认 UTC 会让"每天 9 点开门"在中国站点安静地变成"下午 5 点"，
            // 这正是这套代码库认定必须硬失败的那类"配置读起来像生效"。
            let tz_spec = tz_spec.ok_or_else(|| format!(
                "第 {} 行 schedule_window '{name}' 缺少 tz：必须写明 UTC 还是固定偏移（如 +08:00），\
                 不给默认值是为了让\"按哪个钟开\"这件事出现在配置里",
                d.line
            ))?;
            let zone = Zone::parse(&tz_spec)?;
            let open_expr = open_expr.ok_or_else(|| format!(
                "第 {} 行 schedule_window '{name}' 缺少 open（open \"0 9 * * 1-5\";）",
                d.line
            ))?;
            let close_expr = close_expr.ok_or_else(|| format!(
                "第 {} 行 schedule_window '{name}' 缺少 close：只写 open 的话\"现在算开着还是关着\"\
                 没有可判定的答案（要长期开着就别用窗口挡这条路由）",
                d.line
            ))?;
            let open = parse_cron(&open_expr)
                .map_err(|e| format!("第 {} 行 schedule_window '{name}' 的 open：{e}", d.line))?;
            let close = parse_cron(&close_expr)
                .map_err(|e| format!("第 {} 行 schedule_window '{name}' 的 close：{e}", d.line))?;
            // 两条都得在搜索上界内真的会成立，否则窗口永远不会动 —— 这是配置错误，不是运维事实。
            let probe = now_ms();
            if next_after(&open, zone, probe).is_none() || next_after(&close, zone, probe).is_none() {
                return Err(format!(
                    "第 {} 行 schedule_window '{name}' 的 open/close 里有在 {} 年内永不成立的表达式\
                     （如 0 0 31 2 *），这种窗口看起来存在、实际永远不会动",
                    d.line, SEARCH_CAP_YEARS
                ));
            }
            if collides(&open, &close) {
                return Err(format!(
                    "第 {} 行 schedule_window '{name}' 的 open 与 close 会在同一分钟同时要求改变状态，\
                     那一刻没有任何判据能说\"现在算开着还是关着\"（open={open_expr:?} close={close_expr:?}）",
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
                "schedule_window 声明了 {} 个，超过上限 {MAX_WINDOWS}：这张表每个分钟边界都要走一遍",
                out.len()
            ));
        }
        Ok(out)
    }

    /// 配置里声明过的窗口名（`-t` 用它否决 `schedule_access` 的拼写错误）。
    /// 只做名字扫描：解析错误由 [`Scheduler::parse_all`] 在更早的地方硬失败。
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

    /// 这条路由现在能不能过。**未知名字 = 放行**，并把这次计入 `misses`：
    /// 名字写错在 `-t` 就被否决了，走到这里只会是"热重载新加的窗口"，
    /// 而那种情况下把流量挡死比放行更糟（见 [`Scheduler::apply`] 的告警）。
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

    /// 到点重算：返回**真的**变了状态的窗口。runner 每分钟喂一次真实时间。
    ///
    /// 每次重算都会刷新 `next`，否则 `next_fire_ms` 这项自证指标会一直停在启动那一刻的值 ——
    /// 而它存在的意义正是让运维核对"网关算出的下次触发"和"自己表上的时间"是不是同一个钟。
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

    /// 在排期窗口里最早的下一次触发。移除的窗口不算。
    /// runner 用它决定"最远睡多久"，指标用它做自证（运维能核对网关算出的时刻与自己
    /// 系统时钟是否同一个钟 —— 日历类配置最容易出的事故就是主机时钟漂移）。
    pub fn earliest(&self) -> Option<i64> {
        self.slots
            .iter()
            .map(|s| s.next.load(Ordering::Relaxed))
            .filter(|n| *n != NO_NEXT)
            .min()
    }

    /// 有窗口被移除后为 `NO_NEXT`；全部移除时 `earliest` 返回 None，runner 仍在分钟边界上
    /// 空转，直到下一次热重载把定义换回来。
    pub fn next_of(&self, name: &str) -> Option<i64> {
        self.by_name
            .get(name)
            .map(|s| s.next.load(Ordering::Relaxed))
            .filter(|n| *n != NO_NEXT)
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
            })
            .collect()
    }

    /// 启动与热重载共用的摘要行。运维要能在日志里看到"这条窗口按我的配置算出来是几点、
    /// 此刻是什么状态"，否则"定时没生效"和"定时本来就是关着的"这两种情况长得一模一样。
    pub fn describe(&self, now: i64) -> Vec<String> {
        let mut out = Vec::with_capacity(self.slots.len());
        for s in &self.slots {
            let next = s.next.load(Ordering::Relaxed);
            let open_txt = if s.open.load(Ordering::Relaxed) { "开放" } else { "关闭" };
            let Some((open_expr, close_expr, tz, zone)) = s.view() else {
                out.push(format!(
                    "schedule window '{}' 已从配置移除，状态冻结在{open_txt}",
                    s.name
                ));
                continue;
            };
            let next_txt = if next == NO_NEXT {
                "无（窗口已移除）".to_string()
            } else {
                fmt_wall(next, zone)
            };
            out.push(format!(
                "schedule window '{}' tz={tz} open={open_expr:?} close={close_expr:?} \
                 此刻={open_txt} 下次触发={next_txt}（现在 {}）",
                s.name,
                fmt_wall(now, zone),
            ));
        }
        out
    }

    /// 热重载：窗口名在进程内不换（与 limit_req 的区同理 —— 请求路径上的引用要能对上），
    /// 所以这里只原地换定义并重算状态。返回的是**给日志看的说明**，不是错误：
    /// 新增窗口本进程没有实例、被移除窗口状态冻结，都不该让重载失败。
    pub fn apply(&self, config: &Config, now: i64) -> Vec<String> {
        let mut notes = Vec::new();
        let defs = match Self::parse_defs(config) {
            Ok(d) => d,
            // `-t` 已经走通一次才可能到这里；真出现就说明两份读法分叉了，如实说。
            Err(e) => return vec![format!("schedule: 新配置里的窗口定义读不通，保留原窗口：{e}")],
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
                            "schedule: 窗口 '{}' 按新配置重算，状态 {}→{}",
                            s.name,
                            if before { "开放" } else { "关闭" },
                            if want { "开放" } else { "关闭" }
                        ));
                    }
                }
                None => {
                    let mut g = s.def.lock().unwrap_or_else(|e| e.into_inner());
                    let was = g.take().is_some();
                    s.next.store(NO_NEXT, Ordering::Relaxed);
                    if was {
                        notes.push(format!(
                            "schedule: 窗口 '{}' 已从新配置移除，停止翻转，状态冻结在{}（引用它的路由\
                             在新一轮路由里已经不存在，这里只是让指标不再出现它）",
                            s.name,
                            if s.open.load(Ordering::Relaxed) { "开放" } else { "关闭" }
                        ));
                    }
                }
            }
        }
        for (n, _) in defs.iter().filter(|(n, _)| !self.by_name.contains_key(n)) {
            notes.push(format!(
                "schedule: 新配置里的窗口 '{n}' 本进程没有实例（窗口在启动时建立，新增要重启才生效）；\
                 在那之前引用它的路由一律放行 —— 已计入 onrouter_schedule_gate_miss_total"
            ));
        }
        notes
    }
}

fn is_valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= MAX_NAME_LEN
        && n.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// 绝对时钟（Unix 毫秒）。窗口状态是日历的纯函数，所以这里不需要进程原点，
/// 也就不依赖 #103 那条"限流用的进程相对时钟"。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 把 UTC 墙钟写成毫秒，测试里读起来比裸数字清楚。
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
        // 位编号 = 值 - 该字段下界，所以分/时/周是值本身，日/月是 0 基。
        assert_eq!(c.minute, (1 << 0) | (1 << 15) | (1 << 30) | (1 << 45));
        assert_eq!(c.hour, ((1u64 << 9) - 1) << 9, "9..17 共九格");
        assert!(c.hour & (1 << 8) == 0 && c.hour & (1 << 18) == 0);
        assert_eq!(c.dom, (1 << 0) | (1 << 14), "1 日与 15 日");
        assert_eq!(c.month, (1u64 << 7) - 1, "jan-jul 是 0..6 这七格");
        assert_eq!(c.dow, ((1u64 << 5) - 1) << 1, "mon-fri 是 1..5");
        assert!(!c.dom_star && !c.dow_star);
        // 全 * 的字段必须铺满整个取值域，一位都不能差。
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
        // `*/1` 与 `*` 等价，但 `1/10` 不是"只有 1"。
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
        assert!(parse_cron("0 0 * *").is_err(), "四个字段必须拒绝");
        assert!(parse_cron("0 0 * * * *").is_err(), "六个字段必须拒绝");
        assert!(parse_cron("60 * * * *").is_err(), "分越界");
        assert!(parse_cron("* * 32 * *").is_err(), "日越界");
        assert!(parse_cron("* * * 13 *").is_err(), "月越界");
        assert!(parse_cron("* * * * 8").is_err(), "周越界");
        assert!(parse_cron("*/0 * * * *").is_err(), "0 步进");
        assert!(parse_cron("5-1 * * * *").is_err(), "回绕区间");
        assert!(parse_cron("abc * * * *").is_err(), "非数字非助记名");
        assert!(parse_cron("@reboot").is_err(), "@reboot 是启动语义，不是日历");
    }

    #[test]
    fn hourly_grid_and_strictly_after() {
        // 正好压在整点上 ⇒ 下一格，绝不重复触发同一分钟。
        assert_eq!(fired("*/15 * * * *", Zone::Utc, ms(2026, 10, 20, 4, 30)), "2026-10-20T04:45");
        assert_eq!(fired("30 4 * * *", Zone::Utc, ms(2026, 10, 20, 4, 30)), "2026-10-21T04:30");
        assert_eq!(fired("30 4 * * *", Zone::Utc, ms(2026, 10, 20, 4, 29)), "2026-10-20T04:30");
    }

    #[test]
    fn weekend_skips_to_monday() {
        // 2026-10-24 是周六。
        assert_eq!(fired("0 9 * * 1-5", Zone::Utc, ms(2026, 10, 24, 12, 0)), "2026-10-26T09:00");
        // 周日 10:00 的"周一 9 点"是下一周。
        assert_eq!(fired("0 9 * * 1", Zone::Utc, ms(2026, 10, 25, 10, 0)), "2026-10-26T09:00");
    }

    #[test]
    fn leap_day_only_resolves_on_leap_years() {
        assert_eq!(fired("0 0 29 2 *", Zone::Utc, ms(2026, 6, 15, 0, 0)), "2028-02-29T00:00");
        assert_eq!(fired("0 0 29 2 *", Zone::Utc, ms(2028, 3, 1, 0, 0)), "2032-02-29T00:00");
    }

    #[test]
    fn month_rollover_keeps_day_and_time_reset() {
        // 6 月只有 30 天 ⇒ 必须整块跳过 6 月，落在 7 月 31 日 00:00（而不是停在 6/30 之后逐分钟爬）。
        assert_eq!(fired("0 0 31 * *", Zone::Utc, ms(2026, 6, 15, 8, 0)), "2026-07-31T00:00");
        // 2 月没有 31 日：1 月 31 日中午之后，下一个 31 日是 3 月 31 日。
        assert_eq!(fired("0 0 31 * *", Zone::Utc, ms(2026, 1, 31, 12, 0)), "2026-03-31T00:00");
        // 年末跨年。
        assert_eq!(fired("0 0 1 1 *", Zone::Utc, ms(2026, 6, 15, 8, 0)), "2027-01-01T00:00");
        // 同一个月内从月初跳到月末，日/时/分都要复位。
        assert_eq!(fired("30 6 20 * *", Zone::Utc, ms(2026, 3, 1, 0, 0)), "2026-03-20T06:30");
    }

    #[test]
    fn dom_and_dow_or_when_both_restricted() {
        // "1 号 或 周五"：10/30 是周五，11/1 是月初 —— 两个都会触发。
        assert_eq!(fired("0 12 1 * 5", Zone::Utc, ms(2026, 10, 29, 13, 0)), "2026-10-30T12:00");
        assert_eq!(fired("0 12 1 * 5", Zone::Utc, ms(2026, 10, 30, 13, 0)), "2026-11-01T12:00");
        // 只限制 dom 时是"与"（dow 为 *），不会因周几而放行。
        assert_eq!(fired("0 12 15 * *", Zone::Utc, ms(2026, 10, 15, 13, 0)), "2026-11-15T12:00");
    }

    #[test]
    fn fixed_offset_shifts_the_wall_clock() {
        // "每天 09:00 +08:00" == 01:00 UTC；用 UTC 读回来确认偏移真的生效。
        let c = parse_cron("0 9 * * *").unwrap();
        let cn = Zone::parse("+08:00").unwrap();
        let at = next_after(&c, cn, ms(2026, 10, 20, 0, 0)).unwrap();
        assert_eq!(show(at, Zone::Utc), "2026-10-20T01:00");
        assert_eq!(show(at, cn), "2026-10-20T09:00");
    }

    #[test]
    fn impossible_expression_gives_up() {
        // 2 月没有 31 日：搜索必须收敛到 None，而不是转 8 年。
        let c = parse_cron("0 0 31 2 *").unwrap();
        assert_eq!(next_after(&c, Zone::Utc, ms(2026, 1, 1, 0, 0)), None);
    }

    #[test]
    fn zone_parsing_is_narrow_on_purpose() {
        assert_eq!(Zone::parse("UTC").unwrap(), Zone::Utc);
        assert_eq!(Zone::parse("+00:00").unwrap(), Zone::Utc);
        assert_eq!(Zone::parse("+08:00").unwrap(), Zone::Fixed(480));
        assert_eq!(Zone::parse("-05:30").unwrap(), Zone::Fixed(-330));
        // 命名时区需要时区数据库，没带依赖之前明确拒绝，不要悄悄当成固定偏移。
        assert!(Zone::parse("Asia/Shanghai").is_err());
        assert!(Zone::parse("+8").is_err());
        assert!(Zone::parse("+24:00").is_err());
    }

    #[test]
    fn interval_units_and_floor() {
        assert_eq!(parse_interval("1s").unwrap(), 1_000);
        assert_eq!(parse_interval("30m").unwrap(), 1_800_000);
        assert_eq!(parse_interval("2h").unwrap(), 7_200_000);
        assert_eq!(parse_interval("1d").unwrap(), 86_400_000);
        assert_eq!(parse_interval("5").unwrap(), 5_000, "裸数字按秒，与 reload/timeout 一致");
        assert_eq!(parse_interval("1.5m").unwrap(), 90_000, "小数走同一套写法");
        // 亚秒拒绝：那是热路径的事，不该由调度任务轮。
        assert!(parse_interval("500ms").is_err());
        assert!(parse_interval("999ms").is_err());
        assert!(parse_interval("0.5s").is_err());
        assert!(parse_interval("10x").is_err());
        assert!(parse_interval("s").is_err());
        assert!(parse_interval("").is_err());
    }

    /// `expr` 在 `from` 这一分钟或更早的最近一次成立时刻（UTC 墙钟字符串）。
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
        // 含等于：09:00:30 时，今天的 09:00 已经发生了。
        assert_eq!(prev_at("0 9 * * *", ms(2026, 10, 20, 9, 0) + 30_000), "2026-10-20T09:00");
        assert_eq!(prev_at("0 9 * * *", ms(2026, 10, 20, 8, 59)), "2026-10-19T09:00");
        assert_eq!(prev_at("*/15 * * * *", ms(2026, 10, 20, 10, 7)), "2026-10-20T10:00");
        // 2 月没有 31 日：3 月 1 日往前找，最近的是 1 月 31 日。
        assert_eq!(prev_at("0 0 31 * *", ms(2026, 3, 1, 0, 0)), "2026-01-31T00:00");
        // 只在闰年成立。
        assert_eq!(prev_at("0 0 29 2 *", ms(2026, 6, 15, 0, 0)), "2024-02-29T00:00");
        // 只在周一：周一 08:00 往前找的是上周一，不是"今天还没到所以算昨天"。
        assert_eq!(prev_at("0 9 * * 1", ms(2026, 10, 26, 8, 0)), "2026-10-19T09:00");
        // 固定偏移下也必须按同一个墙钟往回走。
        let cn = Zone::parse("+08:00").unwrap();
        let c = parse_cron("0 9 * * *").unwrap();
        assert_eq!(
            show(prev_before(&c, cn, ms(2026, 10, 20, 0, 30)).unwrap(), cn),
            "2026-10-19T09:00"
        );
    }

    #[test]
    fn forward_and_backward_agree_on_every_fire() {
        // 这两条恒等式是"往回算"与"往前走"共用同一套日历算术的证据：
        // 任何一个正向算出的触发时刻，往回找必须正好落在它自己身上。
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
                let n = next_after(&c, Zone::Utc, t).unwrap_or_else(|| panic!("{expr} 找不到下次触发"));
                assert_eq!(prev_before(&c, Zone::Utc, n), Some(n), "{expr} 在 {}", show(n, Zone::Utc));
                assert_eq!(
                    next_after(&c, Zone::Utc, n - 1),
                    Some(n),
                    "{expr} 在 {} 的前一格必须回到它自己",
                    show(n, Zone::Utc)
                );
                t = n;
            }
        }
    }

    #[test]
    fn window_state_is_derived_not_assumed() {
        // 2026-10-21 是周三，10-24 是周六。
        let w = window("0 9 * * 1-5", "0 18 * * 1-5", Zone::Utc);
        assert!(w.is_open_at(ms(2026, 10, 21, 9, 0)), "打开的那一刻起就算开着");
        assert!(w.is_open_at(ms(2026, 10, 21, 17, 59)));
        assert!(!w.is_open_at(ms(2026, 10, 21, 18, 0)), "边界归关闭那一侧");
        assert!(!w.is_open_at(ms(2026, 10, 21, 8, 59)));
        assert!(!w.is_open_at(ms(2026, 10, 24, 12, 0)), "周末整天都关");
        // 网关可以在窗口中间启动：此刻是开着还是关着必须当场算得出来。
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
        // 周六上午：下一次改变要等到下周一 9 点（跨过整个周末）。
        assert_eq!(
            show(w.next_trigger_at(ms(2026, 10, 24, 10, 0)).unwrap(), Zone::Utc),
            "2026-10-26T09:00"
        );
    }

    #[test]
    fn overnight_window_wraps_midnight() {
        // 22:00 开、02:00 关。跨午夜必须还是"夜里开着"，而不是退化成"只有 22-24 点开"。
        let w = window("0 22 * * *", "0 2 * * *", Zone::Utc);
        assert!(w.is_open_at(ms(2026, 10, 21, 23, 0)));
        assert!(w.is_open_at(ms(2026, 10, 22, 1, 0)));
        assert!(!w.is_open_at(ms(2026, 10, 22, 2, 30)));
        assert!(!w.is_open_at(ms(2026, 10, 22, 21, 0)));
    }

    #[test]
    fn state_is_constant_between_triggers() {
        // 这条取代了"每次到点都必须翻转"的想当然：`0 0 29 2 *` / `30 0 1 3 *` 这种
        // "四年才开一天"的窗口，3 月 1 日年年到点而状态一次都不变。
        // runner 因此必须**到点重算**，不能取反（见 next_trigger_at 的文档）。
        // 这里检查的是真正成立的不变式：两次触发之间状态恒定，且整段里至少变过一次
        // （否则一个恒返回 false 的 is_open_at 也能混过去）。
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
                    .unwrap_or_else(|| panic!("{open} / {close} 找不到下次触发"));
                // 触发点前一刻仍属于上一段 ⇒ 状态必须还是 got。
                assert_eq!(
                    w.is_open_at(n - 60_000),
                    got,
                    "{open} / {close} 在 {} 之前不该已经变过状态",
                    show(n, Zone::Utc)
                );
                let derived = w.is_open_at(n);
                if derived != got {
                    changes += 1;
                    got = derived;
                }
                t = n;
            }
            assert!(changes > 0, "{open} / {close} 走了 60 次触发都没变过状态，判据一定是死的");
        }
    }

    #[test]
    fn strictly_alternating_window_flips_at_every_trigger() {
        // 工作日 9:00 开、18:00 关是运维真正会写的那种窗口：两个触发点严格交替，
        // 每一次到点都必须改变状态。这一条只对它会成立，所以单独写、单独证。
        let w = window("0 9 * * 1-5", "30 18 * * 1-5", Zone::Utc);
        let mut t = ms(2026, 1, 5, 0, 0);
        let mut got = w.is_open_at(t);
        for i in 0..80 {
            let n = w.next_trigger_at(t).unwrap();
            let derived = w.is_open_at(n);
            assert_ne!(derived, got, "第 {i} 次到点 {} 状态没变", show(n, Zone::Utc));
            got = derived;
            t = n;
        }
    }

    #[test]
    fn collision_check_is_decidable_not_sampled() {
        let daily9 = parse_cron("0 9 * * *").unwrap();
        assert!(collides(&daily9, &daily9), "同一条当然撞");
        assert!(collides(&daily9, &parse_cron("0 9 15 * *").unwrap()), "每月 15 日 9 点必然撞上每天 9 点");
        assert!(!collides(&daily9, &parse_cron("30 18 * * *").unwrap()), "小时错开就不撞，日子天天重叠也不算");
        assert!(!collides(&parse_cron("0 12 * * 1").unwrap(), &parse_cron("0 12 * * 5").unwrap()), "周一与周五永不同一天");
        assert!(!collides(&parse_cron("0 0 29 2 *").unwrap(), &parse_cron("0 0 1 8 *").unwrap()), "只在闰年 2/29 与只在 8/1");
        // 阴险的一条：dom 与 dow 各自都不相交，但"某月 1 号正好是周五"时两边同时成立。
        // 只看位图相交会判成不撞 —— 这就是必须按完整 400 年周期逐日推的原因。
        assert!(collides(&parse_cron("0 12 1 * 1").unwrap(), &parse_cron("0 12 15 * 5").unwrap()));
    }

    // ==================== 窗口表 ====================

    fn table(text: &str, now: i64) -> Scheduler {
        let cfg = Config::parse(text).unwrap();
        Scheduler::parse_all_at(&cfg, now).unwrap_or_else(|e| panic!("合法配置却被拒：{e}"))
    }

    fn reject(text: &str) -> String {
        let cfg = Config::parse(text).unwrap();
        match Scheduler::parse_all_at(&cfg, ms(2026, 10, 21, 0, 0)) {
            Ok(_) => panic!("这份配置本该被拒：{text}"),
            Err(e) => e,
        }
    }

    /// 工作日 9:00–18:00（+08:00）。2026-10-21 是周三。
    const OFFICE: &str = "schedule_window office { tz +08:00; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }";

    #[test]
    fn table_rejects_every_declared_but_inert_shape() {
        // 每条都必须是**硬失败**而不是"看起来生效、实际永远不动"。
        // 断言里带上窗口名：运维拿到报错要能直接定位是哪一条。
        let no_tz = "schedule_window office { open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }";
        let e = reject(no_tz);
        assert!(e.contains("缺少 tz") && e.contains("office"), "{e}");

        let no_close = "schedule_window office { tz UTC; open \"0 9 * * 1-5\"; }";
        let e = reject(no_close);
        assert!(e.contains("缺少 close") && e.contains("office"), "{e}");

        let dup = format!("{OFFICE}\n{OFFICE}");
        let e = reject(&dup);
        assert!(e.contains("重复声明"), "{e}");

        // 名字带空格：只有把它写成引号串才可能到这里，正是指标标签最不能吃的字符。
        let e = reject("schedule_window \"office hours\" { tz UTC; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; }");
        assert!(e.contains("无效"), "{e}");
        assert!(!is_valid_name("office hours") && !is_valid_name("office/x") && !is_valid_name(""));
        assert!(is_valid_name("office.hours-1_2"));

        let e = reject("schedule_window office { tz UTC; open \"0 0 31 2 *\"; close \"0 18 * * 1-5\"; }");
        assert!(e.contains("永不成立"), "{e}");

        // open 与 close 同一分钟：那一刻"算开着还是关着"没有判据，必须拒绝而不是靠顺序猜。
        let e = reject("schedule_window office { tz UTC; open \"0 9 * * *\"; close \"0 9 * * *\"; }");
        assert!(e.contains("同时要求改变状态"), "{e}");

        let e = reject("schedule_window office { tz UTC; open \"0 9 * * 1-5\"; close \"0 18 * * 1-5\"; keep on; }");
        assert!(e.contains("不是子指令"), "{e}");

        let e = reject("schedule_window { tz UTC; open \"0 9 * * *\"; close \"0 18 * * *\"; }");
        assert!(e.contains("缺少名字"), "{e}");
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
        assert!(e.contains(&format!("超过上限 {MAX_WINDOWS}")), "{e}");
        // 刚好在上限内必须能建表，否则这条断言等于永远为真。
        let fits = lines[..MAX_WINDOWS].join("\n");
        assert_eq!(table(&fits, ms(2026, 10, 21, 0, 0)).len(), MAX_WINDOWS);
    }

    #[test]
    fn table_state_and_next_are_derived_from_the_calendar() {
        // 周三 02:00 UTC = +08:00 的 10:00 ⇒ 开放；周六同一时刻 ⇒ 关闭。
        // 构造时不给初值，全由日历算出：重启后 gate 状态不需要任何持久化就是对的。
        let wed = table(OFFICE, ms(2026, 10, 21, 2, 0));
        assert!(wed.is_open("office"));
        assert_eq!(wed.len(), 1);
        assert!(!wed.is_empty());
        // 下次触发 = 当天 +08 的 18:00 = 10:00 UTC。
        assert_eq!(wed.next_of("office"), Some(ms(2026, 10, 21, 10, 0)));

        let sat = table(OFFICE, ms(2026, 10, 24, 2, 0));
        assert!(!sat.is_open("office"));
        // 周六的下次触发要跳到周一：+08:00 的 09:00 开门 = UTC 01:00。
        assert_eq!(sat.next_of("office"), Some(ms(2026, 10, 26, 1, 0)));
    }

    #[test]
    fn unknown_window_name_passes_and_is_counted() {
        // 放行 + 计数，而不是挡死：见 is_open 的文档。
        let t = table(OFFICE, ms(2026, 10, 21, 2, 0));
        assert!(t.is_open("nope"));
        assert_eq!(t.misses(), 1);
        assert!(t.is_open("nope"));
        assert_eq!(t.misses(), 2);
        assert_eq!(t.next_of("nope"), None);
    }

    #[test]
    fn advance_reports_only_real_changes_and_keeps_next_fresh() {
        let t = table(OFFICE, ms(2026, 10, 21, 2, 0));
        let before = t.next_of("office").unwrap();
        // 还没到点：不产出变化，next 也不该倒退。
        assert!(t.advance(ms(2026, 10, 21, 9, 59)).is_empty());
        assert_eq!(t.next_of("office"), Some(before));
        // 到点：开放→关闭，且 next 推到第二天。
        let ch = t.advance(ms(2026, 10, 21, 10, 0));
        assert_eq!(ch.len(), 1);
        assert_eq!(ch[0], Change { name: "office".into(), open: false, at_ms: ms(2026, 10, 21, 10, 0) });
        assert!(!t.is_open("office"));
        assert!(t.next_of("office").unwrap() > before);
        // 快照里的计数只统计真实翻转。
        let st = &t.snapshot()[0];
        assert_eq!(st.changes, 1);
        assert!(!st.open && st.enabled);
    }

    #[test]
    fn wake_without_a_flip_still_moves_next_forward() {
        // 这条是 runner 走法的核心：到点 ≠ 变状态。四年才开一天的窗口，
        // 每年 3/1 00:30 都要醒一次、算一次、什么都不变，但 next 必须继续往前推。
        let cfg = "schedule_window leap { tz UTC; open \"0 0 29 2 *\"; close \"30 0 1 3 *\"; }";
        let t = table(cfg, ms(2026, 1, 1, 0, 0));
        assert!(!t.is_open("leap"));
        let mar1 = ms(2026, 3, 1, 0, 30);
        assert!(t.advance(mar1).is_empty(), "2026 年 3/1 到点不该变状态");
        // close 年年成立，所以醒完之后 next 推的是**下一年的 3/1**，不是闰日 ——
        // 如果这里算成 2028-02-29，说明 next 只看了 open 一侧。
        assert_eq!(t.next_of("leap"), Some(ms(2027, 3, 1, 0, 30)));
        // 真到了闰日 00:00：开。
        assert_eq!(t.advance(ms(2028, 2, 29, 0, 0)).len(), 1);
        assert!(t.is_open("leap"));
        // 同一天内的 3/1 触发点不翻转吗？2028-03-01 00:30 关。
        assert_eq!(t.advance(ms(2028, 3, 1, 0, 30)).len(), 1);
        assert!(!t.is_open("leap"));
    }

    #[test]
    fn describe_reads_the_windows_own_clock() {
        // 运维核对的就是这一行：如果它把 +08:00 的 09:00 打印成 01:00，
        // "定时没生效"与"主机时钟差 8 小时"看起来一模一样。
        let t = table(OFFICE, ms(2026, 10, 21, 0, 30));
        let line = t.describe(ms(2026, 10, 21, 0, 30)).remove(0);
        assert!(line.contains("open=\"0 9 * * 1-5\""), "{line}");
        assert!(line.contains("下次触发=2026-10-21 09:00"), "{line}");
        assert!(line.contains("现在 2026-10-21 08:30"), "{line}");
        assert!(line.contains("此刻=关闭"), "{line}");
    }

    #[test]
    fn apply_swaps_defs_freezes_removals_and_announces_new_names() {
        let two = format!("{OFFICE}\nschedule_window night {{ tz UTC; open \"0 22 * * *\"; close \"0 2 * * *\"; }}");
        // 周六 02:00 UTC 建表：office（+08 的工作日窗口）关着，night 正好在 02:00 关上。
        let t = table(&two, ms(2026, 10, 24, 2, 0));
        assert_eq!(t.len(), 2);
        assert!(!t.is_open("office") && !t.is_open("night"));
        // 快照按名字排序，指标渲染才可比对。
        let names: Vec<String> = t.snapshot().into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["night", "office"]);

        // 新配置：office 改成全天开（此刻立刻算作开放）、night 移除、多出一个从未实例化的 new。
        let next_cfg = "schedule_window office { tz UTC; open \"0 0 * * *\"; close \"59 23 * * *\"; }\n\
                        schedule_window new { tz UTC; open \"0 0 1 1 *\"; close \"0 0 2 1 *\"; }";
        let notes = t.apply(&Config::parse(next_cfg).unwrap(), ms(2026, 10, 24, 12, 0));
        assert!(t.is_open("office"), "新定义下重算必须立刻生效");
        assert!(
            notes.iter().any(|n| n.contains("office") && n.contains("关闭→开放")),
            "{notes:?}"
        );
        assert!(notes.iter().any(|n| n.contains("night") && n.contains("已从新配置移除")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("'new'") && n.contains("一律放行")), "{notes:?}");
        // 移除的窗口：状态冻结、不再排期、但名字还在表里（指标要说清它曾经存在）。
        assert_eq!(t.next_of("night"), None);
        let snap = t.snapshot();
        let frozen = snap.iter().find(|s| s.name == "night").unwrap();
        assert!(!frozen.enabled && !frozen.open);
        // 22:00 UTC 是 night 原本会开门的时刻：冻结之后它一次都不该翻。
        assert!(t.advance(ms(2026, 10, 25, 22, 0)).is_empty(), "冻结的窗口还在翻转");
        assert!(!t.snapshot().into_iter().find(|s| s.name == "night").unwrap().open);
        // 新名字没有实例 ⇒ 放行 + 计入 misses。
        assert!(t.is_open("new"));
        assert_eq!(t.misses(), 1);
        // 空表不建 runner。
        assert!(table("", ms(2026, 10, 21, 0, 0)).is_empty());
    }

    #[test]
    fn declared_names_is_a_name_only_scan_for_the_test_flag() {
        // -t 要用它否决 schedule_access 的拼写错误；这里只取名字，不做日历判定。
        let cfg = Config::parse(&format!("{OFFICE}\nschedule_window night {{ tz UTC; open \"0 22 * * *\"; close \"0 2 * * *\"; }}")).unwrap();
        let mut names = Scheduler::declared_names(&cfg);
        names.sort();
        assert_eq!(names, ["night", "office"]);
        assert!(Scheduler::declared_names(&Config::parse("worker_processes 2;").unwrap()).is_empty());
    }

    #[test]
    fn interval_still_usable_for_non_calendar_triggers() {
        // 后面几步（定时重载、定时限流档位）走间隔而不是 cron；这里把下限钉住，
        // 免得有人为了"更准时"把它降到毫秒级、让调度任务变成热路径轮询。
        assert_eq!(parse_interval("60s").unwrap(), 60_000);
        assert_eq!(parse_interval("1m").unwrap(), 60_000);
        assert!(parse_interval("999ms").is_err());
        assert_eq!(MIN_INTERVAL, Duration::from_secs(1));
    }
}
