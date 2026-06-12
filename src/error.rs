//! CogniDNS 领域错误类型定义。
//!
//! 使用 `thiserror` 提供结构化、可分类的错误枚举，替代散落在各模块中的
//! `anyhow` + `unwrap()`/`expect()` 组合。

use std::sync::PoisonError;
use thiserror::Error;

/// CogniDNS 核心错误类型。
///
/// 覆盖 DNS 解析、缓存操作、配置加载、策略决策等场景。
/// 可与 `anyhow::Error` 互转（`From<DnsError> for anyhow::Error` 自动派生）。
#[derive(Debug, Error)]
pub enum DnsError {
    /// DNS 报文格式异常。
    #[error("malformed DNS packet: {reason}")]
    MalformedPacket { reason: String },

    /// DNSSEC 验证失败。
    #[error("DNSSEC validation failed for {qname}/{qtype}: {reason}")]
    DnssecValidationFailed {
        qname: String,
        qtype: String,
        reason: String,
    },

    /// 缓存操作失败。
    #[error("cache operation failed: {operation} — {reason}")]
    CacheError {
        operation: &'static str,
        reason: String,
    },

    /// 上游服务器不可用。
    #[error("upstream {address} unavailable: {reason}")]
    UpstreamUnavailable { address: String, reason: String },

    /// 配置无效。
    #[error("invalid configuration: {reason}")]
    InvalidConfig { reason: String },

    /// 互斥锁中毒（Mutex poisoned）。
    ///
    /// 当持有锁的线程 panic 后，其他线程获取同一把锁时会触发此错误。
    /// 生产环境中应优雅降级而非 panic。
    #[error("mutex poisoned on {component}: {reason}")]
    MutexPoisoned {
        component: &'static str,
        reason: String,
    },

    /// 速率限制触发。
    #[error("rate limit exceeded for {client}: {limit}/s")]
    RateLimitExceeded {
        client: String,
        limit: u32,
    },

    /// 通用 I/O 错误。
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl DnsError {
    /// 从 `PoisonError` 构造 `MutexPoisoned` 变体。
    pub fn mutex_poisoned(component: &'static str, err: impl std::fmt::Display) -> Self {
        Self::MutexPoisoned {
            component,
            reason: err.to_string(),
        }
    }
}

/// 将 `PoisonError` 转换为 `DnsError` 的辅助 trait。
///
/// 用法：
/// ```ignore
/// let guard = mutex.lock().map_err(|e| DnsError::from_poison("component_name", e))?;
/// ```
impl<T> From<PoisonError<T>> for DnsError {
    fn from(err: PoisonError<T>) -> Self {
        Self::MutexPoisoned {
            component: "unknown",
            reason: err.to_string(),
        }
    }
}

/// 安全获取 Mutex guard 的扩展 trait。
///
/// 当 Mutex 中毒时，不 panic 而是尝试恢复数据并记录警告。
pub trait MutexRecover<T> {
    /// 尝试获取锁，中毒时恢复数据并记录警告。
    fn recover(self, component: &'static str) -> T;
}

impl<T> MutexRecover<T> for Result<T, PoisonError<T>> {
    fn recover(self, component: &'static str) -> T {
        match self {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::warn!(
                    component = component,
                    "mutex poisoned, recovering data — this indicates a previous panic in a lock-holding thread"
                );
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn dns_error_display_formats_correctly() {
        let err = DnsError::MalformedPacket {
            reason: "truncated header".into(),
        };
        assert_eq!(err.to_string(), "malformed DNS packet: truncated header");
    }

    #[test]
    fn dns_error_mutex_poisoned_recovers_data() {
        let mutex = Arc::new(Mutex::new(42u64));
        let mutex_clone = Arc::clone(&mutex);

        // 模拟另一个线程在持有锁时 panic
        let handle = std::thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            panic!("simulated panic while holding lock");
        });
        let _ = handle.join();

        // 现在锁已中毒，使用 recover 恢复数据
        let guard = mutex.lock().recover("test_mutex");
        assert_eq!(*guard, 42u64);
    }

    #[test]
    fn dns_error_converts_to_anyhow() {
        let dns_err = DnsError::InvalidConfig {
            reason: "missing upstream".into(),
        };
        let anyhow_err: anyhow::Error = dns_err.into();
        assert!(anyhow_err.to_string().contains("missing upstream"));
    }
}
