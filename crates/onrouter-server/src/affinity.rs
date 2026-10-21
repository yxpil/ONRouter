//! Worker 线程的 CPU 亲和性（对照 nginx `worker_cpu_affinity`）。
//!
//! ONRouter 是单进程多线程模型：nginx 的 `worker_processes` 在这里没有对应物，
//! 因此亲和性绑定的对象是 tokio 的 worker 线程，而不是 fork 出来的子进程。
//! 每个 worker 线程在启动时由 `on_thread_start` 钩子绑定到一个（或一组）逻辑核，
//! 让调度器把不同线程的缓存工作集留在各自的核心上，减少跨核迁移与上下文切换。
//!
//! 配置：
//! ```text
//! worker_threads 8;
//! worker_cpu_affinity auto;                       # 第 i 个线程 -> 第 i 个逻辑核
//! worker_cpu_affinity 00000001 00000002 00000004; # 十六进制掩码，逐线程轮换
//! worker_cpu_affinity off;                        # 默认，不绑定
//! ```
//!
//! 边界：掩码是 64 位（与 Windows 的处理器组、Linux 的 `cpu_set_t` 单组一致），
//! 逻辑核超过 64 的机器只使用前 64 个；macOS 没有线程级硬亲和性，`off` 之外
//! 的配置会明确告警而不是假装生效。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::settings::CpuAffinity;

#[derive(Debug, Clone)]
pub struct AffinityPlan {
    masks: Vec<u64>,
    cpus: usize,
    workers: usize,
}

impl AffinityPlan {
    /// 依据配置生成逐线程掩码计划；返回的告警与其它配置告警走同一条 `-t`/日志通道。
    pub fn build(spec: &CpuAffinity, workers: usize) -> (Self, Vec<String>) {
        let cpus = cpu_count();
        let workers = workers.max(1);
        let mut warnings = Vec::new();
        let mut masks: Vec<u64> = match spec {
            CpuAffinity::Auto => {
                if workers > cpus {
                    warnings.push(format!(
                        "worker_cpu_affinity auto：worker_threads={workers} 多于逻辑核 {cpus}，\
                         线程会轮换共享核心（建议 worker_threads <= {cpus}）"
                    ));
                }
                (0..workers)
                    .map(|i| 1u64 << (i % cpus.min(64)))
                    .collect()
            }
            CpuAffinity::Masks(v) => v.clone(),
        };
        if masks.is_empty() {
            masks.push(1);
        }
        // 掩码里不存在的核会被内核直接忽略；这里提前裁掉并告知操作者，
        // 避免"以为是 32 核机器，其实只绑上了 16 核"这种静默偏差。
        let valid = valid_mask(cpus);
        for m in &mut masks {
            let clamped = *m & valid;
            if clamped != *m {
                warnings.push(format!(
                    "worker_cpu_affinity 掩码 {:016x} 含超过逻辑核数 {cpus} 的位，已裁剪为 {:016x}",
                    *m, clamped
                ));
            }
            *m = if clamped == 0 { 1 } else { clamped };
        }
        (AffinityPlan { masks, cpus, workers }, warnings)
    }

    /// 第 `idx` 个 worker 线程使用的掩码（显式列表按声明顺序轮换）。
    fn mask_for(&self, idx: usize) -> u64 {
        self.masks[idx % self.masks.len()]
    }

    /// 线程启动时调用的绑定函数。成功返回使用的核心列表（人类可读）。
    pub fn bind_current(&self, idx: usize) -> Result<String, String> {
        let mask = self.mask_for(idx);
        set_current_thread_affinity(mask)?;
        Ok(mask_list(mask))
    }

    /// 逐线程展开（含掩码用完后的轮换），运维要看到的是每个线程实际会绑到哪。
    pub fn per_thread(&self) -> String {
        (0..self.workers)
            .map(|i| format!("{}={}", i, mask_list(self.mask_for(i))))
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn describe(&self) -> String {
        format!(
            "worker_threads={} / 逻辑核={}；亲和性：{}",
            self.workers,
            self.cpus,
            self.per_thread()
        )
    }

    /// 交给 tokio `on_thread_start` 的闭包工厂。
    pub fn into_thread_start_hook(self) -> impl Fn() + Send + Sync + 'static {
        let plan = Arc::new(self);
        let next = AtomicUsize::new(0);
        move || {
            let idx = next.fetch_add(1, Ordering::Relaxed);
            match plan.bind_current(idx) {
                Ok(cores) => {
                    crate::log_info!("worker 线程 {idx} 绑定 CPU 核心 {cores}");
                }
                Err(e) => {
                    crate::log_warn!("worker 线程 {idx} CPU 亲和性绑定失败: {e}");
                }
            }
        }
    }
}

fn valid_mask(cpus: usize) -> u64 {
    if cpus >= 64 {
        u64::MAX
    } else {
        (1u64 << cpus) - 1
    }
}

fn mask_list(mask: u64) -> String {
    let mut cores = Vec::new();
    for i in 0..64 {
        if mask & (1u64 << i) != 0 {
            cores.push(i.to_string());
        }
    }
    if cores.is_empty() {
        "none".to_string()
    } else {
        format!("[{}]", cores.join(","))
    }
}

pub fn cpu_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(windows)]
fn set_current_thread_affinity(mask: u64) -> Result<(), String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> isize;
        fn SetThreadAffinityMask(thread: isize, mask: usize) -> usize;
    }
    // SetThreadAffinityMask 返回旧掩码，0 表示失败；GetCurrentThread 是伪句柄，无需关闭。
    let prev = unsafe { SetThreadAffinityMask(GetCurrentThread(), mask as usize) };
    if prev == 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn set_current_thread_affinity(mask: u64) -> Result<(), String> {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for i in 0..64 {
            if mask & (1u64 << i) != 0 {
                libc::CPU_SET(i, &mut set);
            }
        }
        let rc = libc::sched_setaffinity(
            0,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        );
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().to_string())
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn set_current_thread_affinity(_mask: u64) -> Result<(), String> {
    Err("当前平台不支持线程级 CPU 亲和性（macOS/BSD）；请使用 worker_cpu_affinity off".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_builds_one_mask_per_worker() {
        let (plan, warnings) = AffinityPlan::build(&CpuAffinity::Auto, 4);
        assert!(warnings.is_empty());
        assert_eq!(plan.masks.len(), 4);
        let mut seen = std::collections::HashSet::new();
        for i in 0..4 {
            assert!(plan.masks[i].is_power_of_two());
            seen.insert(plan.masks[i]);
        }
        assert_eq!(seen.len(), 4, "auto 在核数足够时应绑到不同核心");
    }

    #[test]
    fn explicit_masks_cycle_and_clamp() {
        let (plan, warnings) =
            AffinityPlan::build(&CpuAffinity::Masks(vec![0b11, 0b100, 1 << 40]), 4);
        assert!(!warnings.is_empty(), "超出逻辑核数的位必须告警");
        assert_eq!(plan.mask_for(0), 0b11);
        assert_eq!(plan.mask_for(1), 0b100);
        assert_eq!(plan.mask_for(2), plan.mask_for(2) & valid_mask(plan.cpus));
        assert_eq!(plan.mask_for(3), 0b11, "不足时按声明顺序轮换");
        assert!(plan.describe().contains("3=[0,1]"), "计划必须展开到最后一个线程：{}", plan.describe());
    }

    #[test]
    fn mask_list_renders_cores() {
        assert_eq!(mask_list(0b101), "[0,2]");
        assert_eq!(mask_list(0), "none");
    }
}
