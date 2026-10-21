//! WASM 网关插件宿主（wasmi，纯 Rust 解释执行，无 JIT）。
//!
//! 配置：
//! ```text
//! wasm_plugin <名字> <path.wasm|path.wat> [fuel=10000000] [memory=16m];
//! ```
//! location 里按阶段引用：
//! ```text
//! access_by_wasm <名字>;
//! header_filter_by_wasm <名字>;
//! body_filter_by_wasm <名字>;
//! ```
//!
//! 模块在 `-t` / 启动时加载并编译一次，请求期只做实例化。每个请求一个 `Store`，
//! fuel（指令预算）与 linear memory 上限都由配置给出，插件既不能把工作线程算死，
//! 也不能靠 `memory.grow` 吃掉进程内存。插件 trap / 超预算时：
//! access 阶段按失败关闭（500），响应过滤器同样收成 500——宁可让一个请求失败，
//! 也不能让"本该加安全头/删内部头"的插件静默跳过。
//!
//! 宿主 ABI（导入模块 `env`，所有指针都是 guest linear memory 的字节偏移）：
//!
//! | 导入 | 说明 |
//! |---|---|
//! | `host_log(level, ptr, len)` | 0=info 1=warn 2=error |
//! | `host_read_len(kind, name_ptr, name_len) -> i32` | 数据长度；不存在返回 -1 |
//! | `host_read_into(kind, name_ptr, name_len, dst, cap) -> i32` | 拷入 guest 缓冲；返回实际字节数 |
//! | `host_header_count(kind) -> i32` | kind 4/5 的头数量 |
//! | `host_header_name_len(kind, idx) -> i32` | 第 idx 个头的名字长度 |
//! | `host_header_name_read(kind, idx, dst, cap) -> i32` | 读第 idx 个头的名字 |
//! | `host_status() -> i32` | 当前响应状态码 |
//! | `host_set_status(code)` | 改写响应状态码 |
//! | `host_set_header(kind, name_ptr, name_len, val_ptr, val_len) -> i32` | kind 4=请求头 5=响应头 |
//! | `host_del_header(kind, name_ptr, name_len) -> i32` | 删除同名头（大小写不敏感） |
//! | `host_set_body(ptr, len) -> i32` | 改写（或生成）响应体 |
//!
//! `kind` 取值：0=方法 1=路径 2=query 3=客户端地址 4=请求头 5=响应头 6=请求体 7=响应体。
//!
//! 导出函数与返回值：
//! * `on_access() -> i32`：0=继续；1=就地响应（状态码默认 403，体来自 `host_set_body`）。
//! * `on_header_filter() -> i32`：0=继续；1=丢弃响应体。
//! * `on_body_filter() -> i32`：0=继续；1=丢弃响应体。
//!
//! 响应过滤器看到的是**完整缓冲后的响应**（与 Lua 的 header/body filter 同一取舍），
//! 因此大响应会占用与体积相等的内存；需要流式处理时请用 Lua 的 content 阶段自行分块。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use wasmi::core::TrapCode;
use wasmi::{
    Caller, Engine, Extern, ExternType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
};

use crate::engine::RequestCtx;

pub const DEFAULT_FUEL: u64 = 10_000_000;
pub const DEFAULT_MEMORY: usize = 16 * 1024 * 1024;
/// 单份配置里插件个数上限：指标标签的基数必须有上界。
pub const MAX_PLUGINS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WasmPhase {
    Access,
    HeaderFilter,
    BodyFilter,
}

impl WasmPhase {
    pub fn export(self) -> &'static str {
        match self {
            WasmPhase::Access => "on_access",
            WasmPhase::HeaderFilter => "on_header_filter",
            WasmPhase::BodyFilter => "on_body_filter",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            WasmPhase::Access => "access",
            WasmPhase::HeaderFilter => "header_filter",
            WasmPhase::BodyFilter => "body_filter",
        }
    }

    fn idx(self) -> usize {
        match self {
            WasmPhase::Access => 0,
            WasmPhase::HeaderFilter => 1,
            WasmPhase::BodyFilter => 2,
        }
    }
}

#[derive(Debug)]
pub struct WasmStats {
    invocations: [AtomicU64; 3],
    errors: [AtomicU64; 3],
    fuel_exhausted: [AtomicU64; 3],
    denied: AtomicU64,
}

impl Default for WasmStats {
    fn default() -> Self {
        Self {
            invocations: Default::default(),
            errors: Default::default(),
            fuel_exhausted: Default::default(),
            denied: AtomicU64::new(0),
        }
    }
}

impl WasmStats {
    pub fn invocation(&self, phase: WasmPhase) -> u64 {
        self.invocations[phase.idx()].load(Ordering::Relaxed)
    }
    pub fn error(&self, phase: WasmPhase) -> u64 {
        self.errors[phase.idx()].load(Ordering::Relaxed)
    }
    pub fn fuel_exhausted(&self, phase: WasmPhase) -> u64 {
        self.fuel_exhausted[phase.idx()].load(Ordering::Relaxed)
    }
    pub fn denied(&self) -> u64 {
        self.denied.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmErrorKind {
    Fuel,
    Trap,
    Setup,
}

#[derive(Debug)]
pub struct WasmError {
    pub kind: WasmErrorKind,
    pub message: String,
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmFlow {
    Continue,
    Respond,
    DropBody,
}

#[derive(Debug, Default)]
pub struct WasmOutcome {
    pub flow: Option<WasmFlow>,
    pub status: Option<u16>,
    pub req_headers_set: Vec<(String, String)>,
    pub resp_headers_set: Vec<(String, String)>,
    pub resp_headers_del: Vec<String>,
    pub body: Option<Vec<u8>>,
}

/// 一次调用的输入快照。只在真的配了 wasm 插件的 location 上构造。
struct Exchange {
    method: Vec<u8>,
    path: Vec<u8>,
    query: Vec<u8>,
    remote_addr: Vec<u8>,
    req_headers: Vec<(String, String)>,
    req_body: Vec<u8>,
    status: u16,
    resp_headers: Vec<(String, String)>,
    resp_body: Vec<u8>,
}

impl Exchange {
    fn from_ctx(ctx: &RequestCtx) -> Self {
        Self {
            method: ctx.method.clone().into_bytes(),
            path: ctx.effective_path().as_bytes().to_vec(),
            query: ctx.query.clone().into_bytes(),
            remote_addr: ctx.remote_addr.clone().into_bytes(),
            req_headers: ctx.req_headers.clone(),
            req_body: ctx.req_body.to_vec(),
            status: ctx.status,
            resp_headers: ctx.resp_headers.clone(),
            resp_body: ctx.body.clone().unwrap_or_default(),
        }
    }
}

struct HostState {
    limits: StoreLimits,
    exchange: Exchange,
    status_set: bool,
    out: WasmOutcome,
}

impl HostState {
    fn new(exchange: Exchange, memory_limit: usize) -> Self {
        Self {
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_limit)
                .instances(1)
                .memories(1)
                .tables(4)
                .build(),
            exchange,
            status_set: false,
            out: WasmOutcome::default(),
        }
    }
}

#[derive(Debug)]
pub struct WasmPlugin {
    pub name: String,
    pub path: PathBuf,
    pub fuel: u64,
    pub memory_limit: usize,
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
    exports: Vec<String>,
    stats: Arc<WasmStats>,
}

impl WasmPlugin {
    pub fn load(
        name: &str,
        path: &Path,
        fuel: u64,
        memory_limit: usize,
        stats: Arc<WasmStats>,
    ) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("wasm_plugin {name}: 读取 {} 失败: {e}", path.display()))?;
        let wasm = decode_source(path, &bytes)
            .map_err(|e| format!("wasm_plugin {name}: {} 既不是合法 .wasm 也不是 .wat: {e}", path.display()))?;
        Self::compile(name, path.to_path_buf(), &wasm, fuel, memory_limit, stats)
    }

    pub fn compile(
        name: &str,
        path: PathBuf,
        wasm: &[u8],
        fuel: u64,
        memory_limit: usize,
        stats: Arc<WasmStats>,
    ) -> Result<Self, String> {
        let mut config = wasmi::Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, wasm)
            .map_err(|e| format!("wasm_plugin {name}: 模块编译失败: {e}"))?;
        let exports: Vec<String> = module
            .exports()
            .filter(|e| matches!(e.ty(), ExternType::Func(_)))
            .map(|e| e.name().to_string())
            .collect();
        let has_memory = module
            .exports()
            .any(|e| e.name() == "memory" && matches!(e.ty(), ExternType::Memory(_)));
        if !has_memory {
            return Err(format!(
                "wasm_plugin {name}: 模块没有导出 linear memory 'memory'，宿主无法与它交换数据"
            ));
        }
        let linker = build_linker(&engine)
            .map_err(|e| format!("wasm_plugin {name}: 绑定宿主函数失败: {e}"))?;
        Ok(Self {
            name: name.to_string(),
            path,
            fuel,
            memory_limit,
            engine,
            module,
            linker,
            exports,
            stats,
        })
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.exports.iter().any(|e| e == name)
    }

    fn execute(&self, phase: WasmPhase, exchange: Exchange) -> Result<WasmOutcome, WasmError> {
        self.stats.invocations[phase.idx()].fetch_add(1, Ordering::Relaxed);
        let result = self.execute_inner(phase, exchange);
        if let Err(e) = &result {
            self.stats.errors[phase.idx()].fetch_add(1, Ordering::Relaxed);
            if e.kind == WasmErrorKind::Fuel {
                self.stats.fuel_exhausted[phase.idx()].fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    fn execute_inner(
        &self,
        phase: WasmPhase,
        exchange: Exchange,
    ) -> Result<WasmOutcome, WasmError> {
        let mut store = Store::new(&self.engine, HostState::new(exchange, self.memory_limit));
        store.limiter(|state| &mut state.limits);
        store.add_fuel(self.fuel).map_err(|e| WasmError {
            kind: WasmErrorKind::Setup,
            message: format!("wasm_plugin {}: 无法注入 fuel: {e}", self.name),
        })?;
        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .and_then(|pre| pre.start(&mut store))
            .map_err(|e| WasmError {
                kind: WasmErrorKind::Setup,
                message: format!("wasm_plugin {}: 实例化失败: {e}", self.name),
            })?;
        let func = instance
            .get_typed_func::<(), i32>(&store, phase.export())
            .map_err(|e| WasmError {
                kind: WasmErrorKind::Setup,
                message: format!(
                    "wasm_plugin {}: 找不到导出函数 {}(): {e}",
                    self.name,
                    phase.export()
                ),
            })?;
        let rc = func.call(&mut store, ()).map_err(|e| {
            let fuel = matches!(e.trap_code(), Some(TrapCode::OutOfFuel));
            WasmError {
                kind: if fuel { WasmErrorKind::Fuel } else { WasmErrorKind::Trap },
                message: format!(
                    "wasm_plugin {} 在 {} 阶段{}: {e}",
                    self.name,
                    phase.label(),
                    if fuel {
                        format!("耗尽 {} 条指令预算", self.fuel)
                    } else {
                        "trap".to_string()
                    }
                ),
            }
        })?;
        let flow = match (phase, rc) {
             (_, 0) => WasmFlow::Continue,
             (WasmPhase::Access, 1) => WasmFlow::Respond,
             (WasmPhase::HeaderFilter | WasmPhase::BodyFilter, 1) => WasmFlow::DropBody,
            (_, other) => {
                return Err(WasmError {
                    kind: WasmErrorKind::Trap,
                    message: format!(
                        "wasm_plugin {} 的 {} 返回了未定义的结果 {other}（只允许 0 或 1）",
                        self.name,
                        phase.export()
                    ),
                })
            }
        };
        let state = store.into_data();
        let mut out = state.out;
        out.flow = Some(flow);
        if state.status_set {
            out.status = Some(state.exchange.status);
        }
        Ok(out)
    }
}

fn decode_source<'a>(path: &Path, bytes: &'a [u8]) -> Result<std::borrow::Cow<'a, [u8]>, String> {
    let textual = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("wat"))
        .unwrap_or(false)
        || bytes
            .iter()
            .find(|b| !b.is_ascii_whitespace())
            .map(|b| *b == b'(')
            .unwrap_or(false);
    if textual {
        wat::parse_bytes(bytes).map_err(|e| e.to_string())
    } else {
        Ok(std::borrow::Cow::Borrowed(bytes))
    }
}

fn guest_bytes(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<Vec<u8>> {
    if ptr < 0 || len < 0 {
        return None;
    }
    let Extern::Memory(mem) = caller.get_export("memory")? else {
        return None;
    };
    let mut buf = vec![0u8; len as usize];
    mem.read(&*caller, ptr as usize, &mut buf).ok()?;
    Some(buf)
}

fn guest_store(caller: &mut Caller<'_, HostState>, ptr: i32, cap: i32, data: &[u8]) -> i32 {
    if ptr < 0 || cap < 0 {
        return -1;
    }
    let Some(Extern::Memory(mem)) = caller.get_export("memory") else {
        return -1;
    };
    let n = data.len().min(cap as usize);
    if mem.write(&mut *caller, ptr as usize, &data[..n]).is_err() {
        return -1;
    }
    n as i32
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn data_for<'a>(state: &'a HostState, kind: i32, name: &[u8]) -> Option<&'a [u8]> {
    let name = std::str::from_utf8(name).ok()?;
    match kind {
        0 => Some(&state.exchange.method),
        1 => Some(&state.exchange.path),
        2 => Some(&state.exchange.query),
        3 => Some(&state.exchange.remote_addr),
        4 => header_value(&state.exchange.req_headers, name).map(str::as_bytes),
        5 => header_value(&state.exchange.resp_headers, name).map(str::as_bytes),
        6 => Some(&state.exchange.req_body),
        7 => Some(&state.exchange.resp_body),
        _ => None,
    }
}

fn headers_for(state: &HostState, kind: i32) -> Option<&[(String, String)]> {
    match kind {
        4 => Some(&state.exchange.req_headers),
        5 => Some(&state.exchange.resp_headers),
        _ => None,
    }
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    let mut kept = false;
    headers.retain(|(k, _)| {
        if k.eq_ignore_ascii_case(name) {
            if kept {
                false
            } else {
                kept = true;
                true
            }
        } else {
            true
        }
    });
    if let Some(slot) = headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
        slot.1 = value.to_string();
    } else {
        headers.push((name.to_string(), value.to_string()));
    }
}

fn del_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
}

fn build_linker(engine: &Engine) -> Result<Linker<HostState>, wasmi::Error> {
    let mut linker = Linker::new(engine);

    linker.func_wrap(
        "env",
        "host_log",
        |mut caller: Caller<'_, HostState>, level: i32, ptr: i32, len: i32| {
            if let Some(bytes) = guest_bytes(&mut caller, ptr, len) {
                let msg = String::from_utf8_lossy(&bytes);
                match level {
                    0 => crate::log_info!("[wasm] {msg}"),
                    1 => crate::log_warn!("[wasm] {msg}"),
                    _ => crate::log_error!("[wasm] {msg}"),
                }
            }
        },
    )?;

    linker.func_wrap(
        "env",
        "host_read_len",
        |mut caller: Caller<'_, HostState>, kind: i32, nptr: i32, nlen: i32| -> i32 {
            let name = guest_bytes(&mut caller, nptr, nlen).unwrap_or_default();
            data_for(caller.data(), kind, &name)
                .map(|d| d.len() as i32)
                .unwrap_or(-1)
        },
    )?;

    linker.func_wrap(
        "env",
        "host_read_into",
        |mut caller: Caller<'_, HostState>,
         kind: i32,
         nptr: i32,
         nlen: i32,
         dst: i32,
         cap: i32|
         -> i32 {
            let name = guest_bytes(&mut caller, nptr, nlen).unwrap_or_default();
            let Some(data) = data_for(caller.data(), kind, &name) else {
                return -1;
            };
            let data = data.to_vec();
            guest_store(&mut caller, dst, cap, &data)
        },
    )?;

    linker.func_wrap(
        "env",
        "host_header_count",
        |caller: Caller<'_, HostState>, kind: i32| -> i32 {
            headers_for(caller.data(), kind)
                .map(|h| h.len() as i32)
                .unwrap_or(-1)
        },
    )?;

    linker.func_wrap(
        "env",
        "host_header_name_len",
        |caller: Caller<'_, HostState>, kind: i32, idx: i32| -> i32 {
            headers_for(caller.data(), kind)
                .and_then(|h| h.get(idx.max(0) as usize))
                .map(|(k, _)| k.len() as i32)
                .unwrap_or(-1)
        },
    )?;

    linker.func_wrap(
        "env",
        "host_header_name_read",
        |mut caller: Caller<'_, HostState>, kind: i32, idx: i32, dst: i32, cap: i32| -> i32 {
            let name = headers_for(caller.data(), kind)
                .and_then(|h| h.get(idx.max(0) as usize))
                .map(|(k, _)| k.clone());
            match name {
                Some(n) => guest_store(&mut caller, dst, cap, n.as_bytes()),
                None => -1,
            }
        },
    )?;

    linker.func_wrap(
        "env",
        "host_status",
        |caller: Caller<'_, HostState>| -> i32 { caller.data().exchange.status as i32 },
    )?;

    linker.func_wrap(
        "env",
        "host_set_status",
        |mut caller: Caller<'_, HostState>, code: i32| {
            if (100..=599).contains(&code) {
                caller.data_mut().exchange.status = code as u16;
                caller.data_mut().status_set = true;
            }
        },
    )?;

    linker.func_wrap(
        "env",
        "host_set_header",
        |mut caller: Caller<'_, HostState>,
         kind: i32,
         nptr: i32,
         nlen: i32,
         vptr: i32,
         vlen: i32|
         -> i32 {
            let Some(name) = guest_bytes(&mut caller, nptr, nlen) else {
                return -1;
            };
            let Some(value) = guest_bytes(&mut caller, vptr, vlen) else {
                return -1;
            };
            let Ok(name) = String::from_utf8(name) else {
                return -1;
            };
            let value = String::from_utf8_lossy(&value).to_string();
            let state = caller.data_mut();
            match kind {
                4 => {
                    set_header(&mut state.exchange.req_headers, &name, &value);
                    state.out.req_headers_set.push((name, value));
                }
                5 => {
                    set_header(&mut state.exchange.resp_headers, &name, &value);
                    state.out.resp_headers_set.push((name, value));
                }
                _ => return -1,
            }
            0
        },
    )?;

    linker.func_wrap(
        "env",
        "host_del_header",
        |mut caller: Caller<'_, HostState>, kind: i32, nptr: i32, nlen: i32| -> i32 {
            let Some(name) = guest_bytes(&mut caller, nptr, nlen) else {
                return -1;
            };
            let Ok(name) = String::from_utf8(name) else {
                return -1;
            };
            let state = caller.data_mut();
            match kind {
                4 => del_header(&mut state.exchange.req_headers, &name),
                5 => {
                    del_header(&mut state.exchange.resp_headers, &name);
                    state.out.resp_headers_del.push(name);
                    return 0;
                }
                _ => return -1,
            }
            0
        },
    )?;

    linker.func_wrap(
        "env",
        "host_set_body",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
            let Some(body) = guest_bytes(&mut caller, ptr, len) else {
                return -1;
            };
            let state = caller.data_mut();
            state.exchange.resp_body = body.clone();
            state.out.body = Some(body);
            0
        },
    )?;

    Ok(linker)
}

// ---------- 进程级插件表与统计（-t / 启动横幅 / /metrics 用） ----------

static PLUGINS: OnceLock<RwLock<Vec<Arc<WasmPlugin>>>> = OnceLock::new();
static STATS: OnceLock<RwLock<HashMap<String, Arc<WasmStats>>>> = OnceLock::new();

fn plugin_store() -> &'static RwLock<Vec<Arc<WasmPlugin>>> {
    PLUGINS.get_or_init(|| RwLock::new(Vec::new()))
}

fn stats_store() -> &'static RwLock<HashMap<String, Arc<WasmStats>>> {
    STATS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// 解析配置时取统计账本：同名插件在热重载后复用同一本账，发布窗口里计数器不归零。
pub fn stats_for(name: &str) -> Arc<WasmStats> {
    let mut map = stats_store().write().unwrap();
    Arc::clone(
        map.entry(name.to_string())
            .or_insert_with(|| Arc::new(WasmStats::default())),
    )
}

pub fn install(plugins: Vec<Arc<WasmPlugin>>) {
    let names: HashSet<String> = plugins.iter().map(|p| p.name.clone()).collect();
    stats_store()
        .write()
        .unwrap()
        .retain(|k, _| names.contains(k));
    *plugin_store().write().unwrap() = plugins;
}

pub fn snapshot() -> Vec<Arc<WasmPlugin>> {
    plugin_store().read().unwrap().clone()
}

pub fn stats_snapshot() -> Vec<(String, Arc<WasmStats>)> {
    let mut v: Vec<_> = stats_store()
        .read()
        .unwrap()
        .iter()
        .map(|(k, s)| (k.clone(), Arc::clone(s)))
        .collect();
    v.sort_by(|a, b| a.0.cmp(&b.0));
    v
}

pub fn describe() -> Vec<String> {
    snapshot()
        .iter()
        .map(|p| {
            format!(
                "WASM 插件 {}：{}（fuel={} 条指令，内存上限 {} MiB，导出 {}）",
                p.name,
                p.path.display(),
                p.fuel,
                p.memory_limit / (1024 * 1024),
                p.exports.join(", ")
            )
        })
        .collect()
}

// ---------- 请求期入口 ----------

fn apply_headers(ctx_headers: &mut Vec<(String, String)>, set: &[(String, String)], del: &[String]) {
    for name in del {
        del_header(ctx_headers, name);
    }
    for (k, v) in set {
        set_header(ctx_headers, k, v);
    }
}

/// access 阶段：返回 Ok(true) 表示插件已经就地生成了响应（ctx.done 同时置位）。
pub fn access(plugin: &WasmPlugin, ctx: &mut RequestCtx) -> Result<bool, WasmError> {
    let out = plugin.execute(WasmPhase::Access, Exchange::from_ctx(ctx))?;
    apply_headers(&mut ctx.req_headers, &out.req_headers_set, &[]);
    if out.flow == Some(WasmFlow::Respond) {
        plugin.stats.denied.fetch_add(1, Ordering::Relaxed);
        ctx.status = out.status.unwrap_or(403);
        ctx.body = Some(out.body.unwrap_or_default());
        ctx.done = true;
        return Ok(true);
    }
    Ok(false)
}

/// header_filter / body_filter 阶段：把插件对状态、响应头、响应体的修改写回 ctx。
pub fn filter(
    plugin: &WasmPlugin,
    phase: WasmPhase,
    ctx: &mut RequestCtx,
) -> Result<(), WasmError> {
    debug_assert!(matches!(
        phase,
        WasmPhase::HeaderFilter | WasmPhase::BodyFilter
    ));
    let out = plugin.execute(phase, Exchange::from_ctx(ctx))?;
    if let Some(status) = out.status {
        ctx.status = status;
    }
    apply_headers(&mut ctx.resp_headers, &out.resp_headers_set, &out.resp_headers_del);
    if let Some(body) = out.body {
        ctx.body = Some(body);
    }
    if out.flow == Some(WasmFlow::DropBody) {
        ctx.body = Some(Vec::new());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(name: &str, wat: &str, fuel: u64) -> WasmPlugin {
        let wasm = wat::parse_str(wat).expect("WAT 应能编译");
        WasmPlugin::compile(
            name,
            PathBuf::from(format!("{name}.wat")),
            &wasm,
            fuel,
            DEFAULT_MEMORY,
            stats_for(name),
        )
        .expect("插件应能编译")
    }

    #[test]
    fn access_plugin_can_deny_with_status_and_body() {
        let p = plugin(
            "deny",
            r#"(module
                 (import "env" "host_set_status" (func $status (param i32)))
                 (import "env" "host_set_body" (func $body (param i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "blocked by wasm")
                 (func (export "on_access") (result i32)
                   i32.const 401 call $status
                   i32.const 0 i32.const 15 call $body drop
                   i32.const 1))"#,
            DEFAULT_FUEL,
        );
        let mut ctx = RequestCtx::default();
        ctx.method = "GET".into();
        let denied = access(&p, &mut ctx).expect("插件应成功");
        assert!(denied && ctx.done);
        assert_eq!(ctx.status, 401);
        assert_eq!(ctx.body.as_deref(), Some(&b"blocked by wasm"[..]));
        assert_eq!(p.stats.invocation(WasmPhase::Access), 1);
        assert_eq!(p.stats.denied(), 1);
    }

    #[test]
    fn access_plugin_reads_request_and_sets_forwarded_header() {
        let p = plugin(
            "tag",
            r#"(module
                 (import "env" "host_read_len" (func $len (param i32 i32 i32) (result i32)))
                 (import "env" "host_read_into" (func $read (param i32 i32 i32 i32 i32) (result i32)))
                 (import "env" "host_set_header" (func $set (param i32 i32 i32 i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "cookie")
                 (data (i32.const 16) "session")
                 (data (i32.const 32) "X-Wasm-Session")
                 (data (i32.const 64) "yes")
                 (func (export "on_access") (result i32)
                   ;; 读请求头 Cookie 的值到偏移 128，长度 32
                   i32.const 4 i32.const 0 i32.const 6
                   i32.const 128 i32.const 32 call $read
                   i32.const 0 i32.gt_s
                   if
                     i32.const 4 i32.const 32 i32.const 14 i32.const 64 i32.const 3 call $set drop
                   end
                   i32.const 0))"#,
            DEFAULT_FUEL,
        );
        let mut ctx = RequestCtx::default();
        ctx.method = "GET".into();
        ctx.req_headers
            .push(("Cookie".into(), "session=abc".into()));
        assert!(!access(&p, &mut ctx).expect("插件应成功"));
        assert_eq!(
            header_value(&ctx.req_headers, "x-wasm-session"),
            Some("yes")
        );
        assert!(!ctx.done);
    }

    #[test]
    fn header_filter_adds_header_and_body_filter_replaces_body() {
        let hf = plugin(
            "hf",
            r#"(module
                 (import "env" "host_set_header" (func $set (param i32 i32 i32 i32 i32) (result i32)))
                 (import "env" "host_set_status" (func $status (param i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "X-Wasm")
                 (data (i32.const 16) "on")
                 (func (export "on_header_filter") (result i32)
                   i32.const 5 i32.const 0 i32.const 6 i32.const 16 i32.const 2 call $set drop
                   i32.const 202 call $status
                   i32.const 0))"#,
            DEFAULT_FUEL,
        );
        let bf = plugin(
            "bf",
            r#"(module
                 (import "env" "host_set_body" (func $body (param i32 i32) (result i32)))
                 (memory (export "memory") 1)
                 (data (i32.const 0) "OWNED BY WASM")
                 (func (export "on_body_filter") (result i32)
                   i32.const 0 i32.const 13 call $body drop
                   i32.const 0))"#,
            DEFAULT_FUEL,
        );
        let mut ctx = RequestCtx::default();
        ctx.status = 200;
        ctx.resp_headers.push(("content-type".into(), "text/plain".into()));
        ctx.body = Some(b"original".to_vec());
        filter(&hf, WasmPhase::HeaderFilter, &mut ctx).expect("头过滤应成功");
        filter(&bf, WasmPhase::BodyFilter, &mut ctx).expect("体过滤应成功");
        assert_eq!(ctx.status, 202);
        assert_eq!(header_value(&ctx.resp_headers, "x-wasm"), Some("on"));
        assert_eq!(ctx.body.as_deref(), Some(&b"OWNED BY WASM"[..]));
    }

    #[test]
    fn body_filter_can_drop_the_body() {
        let p = plugin(
            "drop",
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "on_body_filter") (result i32) i32.const 1))"#,
            DEFAULT_FUEL,
        );
        let mut ctx = RequestCtx::default();
        ctx.body = Some(b"secret".to_vec());
        filter(&p, WasmPhase::BodyFilter, &mut ctx).expect("应成功");
        assert_eq!(ctx.body.as_deref(), Some(&b""[..]));
    }

    #[test]
    fn fuel_exhaustion_traps_instead_of_hanging_the_worker() {
        let p = plugin(
            "spin",
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "on_access") (result i32)
                   (loop $forever br $forever)
                   i32.const 0))"#,
            10_000,
        );
        let mut ctx = RequestCtx::default();
        let err = access(&p, &mut ctx).expect_err("死循环必须被 fuel 掐断");
        assert_eq!(err.kind, WasmErrorKind::Fuel, "{err}");
        assert_eq!(p.stats.fuel_exhausted(WasmPhase::Access), 1);
    }

    #[test]
    fn missing_phase_export_is_reported_at_build_time() {
        let p = plugin(
            "only_body",
            r#"(module
                 (memory (export "memory") 1)
                 (func (export "on_body_filter") (result i32) i32.const 0))"#,
            DEFAULT_FUEL,
        );
        assert!(p.has_export("on_body_filter"));
        assert!(!p.has_export("on_access"));
        assert!(p.exports.contains(&"on_body_filter".to_string()));
    }
}
