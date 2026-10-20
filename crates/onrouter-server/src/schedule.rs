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
}
