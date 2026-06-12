//! In-memory response cache for positive and negative DNS answers.
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CacheKey {
    pub qname: SmolStr,
    pub qtype: u16,
    pub dnssec_ok: bool,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub response: Arc<[u8]>,
    pub inserted_at: Instant,
    pub expires_at: Instant,
    pub original_ttl_secs: u64,
    pub rcode: u16,
    pub last_access: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheDump {
    pub exported_at_unix_secs: u64,
    pub entries: Vec<CacheDumpEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheDumpEntry {
    pub qname: String,
    pub qtype: u16,
    pub rcode: u16,
    pub remaining_ttl_secs: u64,
    pub original_ttl_secs: u64,
    pub frozen: bool,
    pub response_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_visualization: Option<CacheResponseVisualization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheResponseVisualization {
    pub id: u16,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    pub rcode: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub answer_ips: Vec<String>,
    pub cname_chain: Vec<CacheCnameRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheCnameRecord {
    pub owner: String,
    pub target: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheImportResult {
    pub imported: usize,
    pub skipped: usize,
}

#[derive(Debug)]
struct CacheShard {
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
}

#[derive(Debug)]
pub struct ResponseCache {
    shards: Vec<CacheShard>,
    capacity: AtomicUsize,
    freeze_all: std::sync::atomic::AtomicBool,
    freeze_domains: RwLock<Vec<String>>,
}

impl Default for ResponseCache {
    /// 默认实现，创建一个容量为0（不限制容量）的缓存。
    fn default() -> Self {
        Self::new(0)
    }
}

impl ResponseCache {
    /// Creates a response cache with optional entry capacity.
    /// capacity=0 means unbounded.
    /// 创建一个响应缓存，可指定最大容量（0为不限制）。
    pub fn new(capacity: usize) -> Self {
        let shard_count = cache_shard_count(capacity);
        let mut shards = Vec::with_capacity(shard_count);
        for _ in 0..shard_count {
            shards.push(CacheShard {
                entries: RwLock::new(HashMap::new()),
            });
        }
        Self {
            shards,
            capacity: AtomicUsize::new(capacity),
            freeze_all: std::sync::atomic::AtomicBool::new(false),
            freeze_domains: RwLock::new(Vec::new()),
        }
    }

    /// 设置是否全局冻结所有缓存条目的 TTL。
    pub fn set_freeze_all(&self, enabled: bool) {
        self.freeze_all.store(enabled, Ordering::Relaxed);
    }

    /// 设置某个域名是否冻结缓存 TTL，返回冻结域名数量。
    pub fn set_freeze_domain(&self, domain: &str, enabled: bool) -> usize {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return self.freeze_domain_count();
        }

        if let Ok(mut domains) = self.freeze_domains.write() {
            if enabled {
                if !domains.iter().any(|d| d == &normalized) {
                    domains.push(normalized.into());
                    domains.sort();
                    domains.dedup();
                }
            } else {
                domains.retain(|d| d != &normalized);
            }
            return domains.len();
        }
        self.freeze_domain_count()
    }

    /// 获取当前被冻结的域名数量。
    pub fn freeze_domain_count(&self) -> usize {
        self.freeze_domains.read().map(|d| d.len()).unwrap_or(0)
    }

    /// 判断某个查询名是否被冻结（TTL 不递减）。
    pub fn is_frozen_for_qname(&self, qname: &str) -> bool {
        if self.freeze_all.load(Ordering::Relaxed) {
            return true;
        }
        let normalized = normalize_domain(qname);
        if normalized.is_empty() {
            return false;
        }
        self.freeze_domains
            .read()
            .map(|domains| {
                domains.iter().any(|domain| {
                    normalized == *domain || normalized.ends_with(&format!(".{domain}"))
                })
            })
            .unwrap_or(false)
    }

    /// 清空所有缓存条目，返回移除的数量。
    pub fn clear_all(&self) -> usize {
        let mut removed = 0usize;
        for shard in &self.shards {
            if let Ok(mut entries) = shard.entries.write() {
                removed += entries.len();
                entries.clear();
            }
        }
        removed
    }

    /// 清空指定域名相关的缓存条目，返回移除的数量。
    pub fn clear_domain(&self, domain: &str) -> usize {
        let normalized = normalize_domain(domain);
        if normalized.is_empty() {
            return 0;
        }

        let mut removed = 0usize;
        for shard in &self.shards {
            if let Ok(mut entries) = shard.entries.write() {
                let before = entries.len();
                entries.retain(|key, _| {
                    let qname = normalize_domain(&key.qname);
                    !(qname == normalized || qname.ends_with(&format!(".{normalized}")))
                });
                removed += before.saturating_sub(entries.len());
            }
        }
        removed
    }

    /// Updates cache capacity and trims each shard independently (non-blocking).
    /// Uses try_write so contended shards are skipped; residual work is handled
    /// lazily by subsequent insertions via `make_room_for_insert_locked`.
    pub fn set_capacity(&self, capacity: usize) {
        self.capacity.store(capacity, Ordering::Relaxed);
        if capacity == 0 {
            return;
        }

        let now = Instant::now();
        for (shard_index, shard) in self.shards.iter().enumerate() {
            // try_write: skip shards that are currently contended.
            if let Ok(mut entries) = shard.entries.try_write() {
                let Some(shard_cap) =
                    bounded_shard_capacity(capacity, shard_index, self.shards.len())
                else {
                    continue;
                };
                entries.retain(|_, v| now < v.expires_at);
                // Trim to per-shard capacity using the same sampling strategy as insert.
                while entries.len() > shard_cap {
                    let oldest = entries
                        .iter()
                        .take(5)
                        .min_by_key(|(_, v)| v.last_access)
                        .map(|(k, _)| k.clone());
                    if let Some(k) = oldest {
                        entries.remove(&k);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    /// Returns the configured cache capacity (0 means unbounded).
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Reads an entry if it exists and has not expired.
    /// 获取缓存条目，支持 TTL 冻结选项。
    pub fn get(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Vec<u8>> {
        let now = Instant::now();
        let shard = self.shard_for_key(key);
        let (response, inserted_at) = {
            let entries = shard.entries.read().ok()?;
            let entry = entries.get(key)?;
            if !freeze_ttl && now >= entry.expires_at {
                drop(entries);
                if let Ok(mut entries) = shard.entries.write() {
                    let should_remove = entries
                        .get(key)
                        .map(|entry| Instant::now() >= entry.expires_at)
                        .unwrap_or(false);
                    if should_remove {
                        entries.remove(key);
                    }
                }
                return None;
            }
            // Arc::clone is an atomic ref-count increment — no heap allocation or memcpy.
            (Arc::clone(&entry.response), entry.inserted_at)
        };

        // Best-effort touch for LRU behavior; skip if cache is currently contended.
        if let Ok(mut entries) = shard.entries.try_write() {
            if let Some(entry) = entries.get_mut(key) {
                entry.last_access = now;
            }
        }

        if freeze_ttl {
            return Some(unwrap_or_clone_vec(response));
        }

        // Return a TTL-adjusted copy so cache hits reflect elapsed residency time.
        let elapsed = now.saturating_duration_since(inserted_at);
        // DNS TTL is second-level granularity; skip parsing/rewriting on sub-second hits.
        if elapsed < Duration::from_secs(1) {
            return Some(unwrap_or_clone_vec(response));
        }
        let mut packet = unwrap_or_clone_vec(response);
        crate::codec::dns::decay_response_ttl_in_place(&mut packet, elapsed);
        Some(packet)
    }

    /// Returns remaining ttl for a key when present and not expired.
    pub fn remaining_ttl(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Duration> {
        let now = Instant::now();
        let shard = self.shard_for_key(key);
        let entries = shard.entries.read().ok()?;
        let entry = entries.get(key)?;
        if freeze_ttl {
            return Some(Duration::from_secs(entry.original_ttl_secs.max(1)));
        }
        if now >= entry.expires_at {
            return None;
        }
        Some(entry.expires_at.saturating_duration_since(now))
    }

    /// Inserts a response with explicit ttl computed by resolver/codec.
    /// 插入一条缓存响应，ttl 由外部指定。
    pub fn insert(&self, key: CacheKey, response: Vec<u8>, ttl: Duration) {
        let rcode = crate::codec::dns::response_code(&response).unwrap_or(2);
        let shard_index = shard_index_for_key(&key, self.shards.len());
        if let Ok(mut entries) = self.shards[shard_index].entries.write() {
            let now = Instant::now();
            let capacity = bounded_shard_capacity(
                self.capacity.load(Ordering::Relaxed),
                shard_index,
                self.shards.len(),
            );
            self.make_room_for_insert_locked(&mut entries, now, capacity);
            entries.insert(
                key,
                CacheEntry {
                    response: Arc::from(response),
                    inserted_at: now,
                    expires_at: now + ttl,
                    original_ttl_secs: ttl.as_secs(),
                    rcode,
                    last_access: now,
                },
            );
        }
    }

    /// 导出缓存快照，可自定义冻结域名判断逻辑。
    pub fn export_dump<F>(&self, is_frozen_domain: F) -> CacheDump
    where
        F: Fn(&str) -> bool,
    {
        let mut entries_out = Vec::new();
        let now = Instant::now();
        for shard in &self.shards {
            if let Ok(entries) = shard.entries.read() {
                for (key, entry) in entries.iter() {
                    let frozen = is_frozen_domain(&key.qname);
                    if !frozen && now >= entry.expires_at {
                        continue;
                    }

                    let remaining_ttl_secs = if frozen {
                        entry.original_ttl_secs
                    } else {
                        entry.expires_at.saturating_duration_since(now).as_secs()
                    };
                    entries_out.push(CacheDumpEntry {
                        qname: key.qname.to_string(),
                        qtype: key.qtype,
                        rcode: entry.rcode,
                        remaining_ttl_secs,
                        original_ttl_secs: entry.original_ttl_secs,
                        frozen,
                        response_hex: encode_hex(&entry.response),
                        response_visualization: build_response_visualization(&entry.response),
                    });
                }
            }
        }

        CacheDump {
            exported_at_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            entries: entries_out,
        }
    }

    /// 导入缓存快照，返回导入和跳过的条数。
    pub fn import_dump(&self, dump: CacheDump) -> CacheImportResult {
        let mut imported = 0usize;
        let mut skipped = 0usize;
        for item in dump.entries {
            if item.remaining_ttl_secs == 0 {
                skipped += 1;
                continue;
            }
            let Some(response) = decode_hex(&item.response_hex) else {
                skipped += 1;
                continue;
            };
            let ttl = Duration::from_secs(item.remaining_ttl_secs);
            self.insert(
                CacheKey {
                    qname: SmolStr::from(item.qname),
                    qtype: item.qtype,
                    dnssec_ok: false,
                },
                response,
                ttl,
            );
            imported += 1;
        }
        CacheImportResult { imported, skipped }
    }

    /// 内部方法：为新插入腾出空间。使用近似 LRU 采样策略，O(1) 采样代替 O(n) 全扫描。
    fn make_room_for_insert_locked(
        &self,
        entries: &mut HashMap<CacheKey, CacheEntry>,
        now: Instant,
        capacity: Option<usize>,
    ) {
        let Some(capacity) = capacity else {
            return;
        };

        if capacity == 0 {
            entries.clear();
            return;
        }

        if entries.len() >= capacity {
            entries.retain(|_, value| now < value.expires_at);
        }

        // Approximate LRU via sampling: pick the oldest from a small random sample
        // rather than scanning all entries (O(n)). 5 samples strikes a balance
        // between eviction quality and speed (Redis default is 5).
        const SAMPLE_SIZE: usize = 5;
        while entries.len() >= capacity {
            let mut oldest_key: Option<CacheKey> = None;
            let mut oldest_access = Instant::now();
            // HashMap iteration order is arbitrary, providing effectively random sampling.
            for (k, v) in entries.iter().take(SAMPLE_SIZE) {
                if oldest_key.is_none() || v.last_access < oldest_access {
                    oldest_access = v.last_access;
                    oldest_key = Some(k.clone());
                }
            }
            if let Some(evict_key) = oldest_key {
                entries.remove(&evict_key);
            } else {
                break;
            }
        }
    }

    /// Opportunistically removes a single key when caller detects expiry.
    /// 移除指定 key 的过期缓存（如果已过期）。
    pub fn prune_expired(&self, key: &CacheKey) {
        if let Ok(mut entries) = self.shard_for_key(key).entries.write() {
            let should_remove = entries
                .get(key)
                .map(|entry| Instant::now() >= entry.expires_at)
                .unwrap_or(false);
            if should_remove {
                entries.remove(key);
            }
        }
    }

    fn shard_for_key(&self, key: &CacheKey) -> &CacheShard {
        &self.shards[shard_index_for_key(key, self.shards.len())]
    }
}

// ---------------------------------------------------------------------------
// DnsCache trait implementation for ResponseCache
// ---------------------------------------------------------------------------

impl crate::traits::DnsCache for ResponseCache {
    fn get(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Vec<u8>> {
        self.get(key, freeze_ttl)
    }

    fn remaining_ttl(&self, key: &CacheKey, freeze_ttl: bool) -> Option<Duration> {
        self.remaining_ttl(key, freeze_ttl)
    }

    fn insert(&self, key: CacheKey, response: Vec<u8>, ttl: Duration) {
        self.insert(key, response, ttl)
    }

    fn clear_all(&self) -> usize {
        self.clear_all()
    }

    fn clear_domain(&self, domain: &str) -> usize {
        self.clear_domain(domain)
    }

    fn set_capacity(&self, capacity: usize) {
        self.set_capacity(capacity)
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn set_freeze_all(&self, enabled: bool) {
        self.set_freeze_all(enabled)
    }

    fn set_freeze_domain(&self, domain: &str, enabled: bool) -> usize {
        self.set_freeze_domain(domain, enabled)
    }

    fn freeze_domain_count(&self) -> usize {
        self.freeze_domain_count()
    }

    fn is_frozen_for_qname(&self, qname: &str) -> bool {
        self.is_frozen_for_qname(qname)
    }

    fn export_dump(&self, is_frozen: &dyn Fn(&str) -> bool) -> CacheDump {
        self.export_dump(is_frozen)
    }

    fn import_dump(&self, dump: CacheDump) -> CacheImportResult {
        self.import_dump(dump)
    }

    fn prune_expired(&self, key: &CacheKey) {
        self.prune_expired(key)
    }
}

fn cache_shard_count(capacity: usize) -> usize {
    let preferred = std::thread::available_parallelism()
        .map(|parallelism| (parallelism.get() * 2).clamp(8, 64))
        .unwrap_or(16);
    if capacity == 0 {
        preferred
    } else {
        preferred.min(capacity.max(1))
    }
}

fn shard_index_for_key(key: &CacheKey, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % shard_count
}

fn bounded_shard_capacity(
    total_capacity: usize,
    shard_index: usize,
    shard_count: usize,
) -> Option<usize> {
    if total_capacity == 0 {
        return None;
    }
    let base = total_capacity / shard_count;
    let remainder = total_capacity % shard_count;
    Some(base + usize::from(shard_index < remainder))
}

/// 将二进制数据编码为十六进制字符串。
fn encode_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// 域名归一化为小写并去除末尾点。
fn normalize_domain(value: &str) -> SmolStr {
    SmolStr::from(value.trim().trim_end_matches('.').to_ascii_lowercase().as_str())
}

/// 构建缓存响应的可视化结构。
fn build_response_visualization(packet: &[u8]) -> Option<CacheResponseVisualization> {
    let header = crate::codec::dns::parse_header(packet).ok()?;
    let question = crate::codec::dns::parse_first_question(packet);
    let answer_ips = crate::codec::dns::extract_answer_ip_endpoints(packet);
    let cname_chain = crate::codec::dns::extract_answer_cname_records(packet)
        .into_iter()
        .map(|(owner, target, ttl)| CacheCnameRecord { owner, target, ttl })
        .collect::<Vec<_>>();

    Some(CacheResponseVisualization {
        id: header.id,
        qname: question.as_ref().map(|q| q.0.clone()),
        qtype: question.as_ref().map(|q| q.1),
        rcode: crate::codec::dns::response_code(packet).unwrap_or(0),
        ancount: header.ancount,
        nscount: header.nscount,
        arcount: header.arcount,
        answer_ips,
        cname_chain,
    })
}

/// 将十六进制字符串解码为二进制数据。
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

/// 单字符十六进制转数值。
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Extract `Vec<u8>` from `Arc<[u8]>`.
///
/// `Arc<[u8]>` eliminates the double-indirection of `Arc<Vec<u8>>`
/// (one pointer hop instead of two, 24 bytes less heap per entry).
/// The trade-off is that we can't use `try_unwrap` on an unsized `[u8]`,
/// so we always copy via `to_vec()` when extracting.  In practice this is
/// acceptable because the cache-hit TTL-decay path always needs a mutable
/// copy anyway, and the storage/access win applies to *every* entry.
#[inline]
fn unwrap_or_clone_vec(arc: Arc<[u8]>) -> Vec<u8> {
    arc.to_vec()
}

#[cfg(test)]
mod tests {
    use super::{CacheDump, CacheDumpEntry, CacheKey, CacheResponseVisualization, ResponseCache};
    use std::time::Duration;

    #[test]
    fn capacity_evicts_oldest_entry() {
        let cache = ResponseCache::new(1);
        cache.insert(
            CacheKey {
                qname: "a.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            vec![0, 1, 2, 3],
            Duration::from_secs(60),
        );
        cache.insert(
            CacheKey {
                qname: "b.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            vec![4, 5, 6, 7],
            Duration::from_secs(60),
        );

        assert!(cache
            .get(
                &CacheKey {
                    qname: "a.example".into(),
                    qtype: 1,
                    dnssec_ok: false,
                },
                false
            )
            .is_none());
        assert!(cache
            .get(
                &CacheKey {
                    qname: "b.example".into(),
                    qtype: 1,
                    dnssec_ok: false,
                },
                false
            )
            .is_some());
    }

    #[test]
    fn lowering_capacity_trims_existing_entries() {
        let cache = ResponseCache::new(3);
        cache.insert(
            CacheKey {
                qname: "a.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            vec![0, 1],
            Duration::from_secs(60),
        );
        cache.insert(
            CacheKey {
                qname: "b.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            vec![2, 3],
            Duration::from_secs(60),
        );
        cache.insert(
            CacheKey {
                qname: "c.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            vec![4, 5],
            Duration::from_secs(60),
        );

        cache.set_capacity(1);

        let mut survivors = 0;
        for name in ["a.example", "b.example", "c.example"] {
            if cache
                .get(
                    &CacheKey {
                        qname: name.into(),
                        qtype: 1,
                        dnssec_ok: false,
                    },
                    false,
                )
                .is_some()
            {
                survivors += 1;
            }
        }
        // With capacity=1 and 3 shards, at most 1 shard gets allocation.
        // Depending on key distribution, 0–1 entries survive.
        assert!(survivors <= 1, "at most 1 entry should survive, got {survivors}");
    }

    #[test]
    fn import_dump_ignores_visualization_field() {
        let cache = ResponseCache::new(8);
        let dump = CacheDump {
            exported_at_unix_secs: 0,
            entries: vec![CacheDumpEntry {
                qname: "v.example".into(),
                qtype: 1,
                rcode: 0,
                remaining_ttl_secs: 60,
                original_ttl_secs: 60,
                frozen: false,
                response_hex: "12345678".into(),
                response_visualization: Some(CacheResponseVisualization {
                    id: 1,
                    qname: Some("v.example".into()),
                    qtype: Some(1),
                    rcode: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                    answer_ips: vec![],
                    cname_chain: vec![],
                }),
            }],
        };

        let result = cache.import_dump(dump);
        assert_eq!(result.imported, 1);
        assert_eq!(result.skipped, 0);
    }

    #[test]
    fn export_dump_includes_response_visualization() {
        let cache = ResponseCache::new(4);
        // Minimal DNS response header: id=0x1234, flags=0x8180, all counts=0.
        let response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        cache.insert(
            CacheKey {
                qname: "x.example".into(),
                qtype: 1,
                dnssec_ok: false,
            },
            response,
            Duration::from_secs(30),
        );

        let dump = cache.export_dump(|_| false);
        assert_eq!(dump.entries.len(), 1);
        let viz = dump.entries[0]
            .response_visualization
            .as_ref()
            .expect("visualization must exist");
        assert_eq!(viz.id, 0x1234);
        assert_eq!(viz.rcode, 0);
    }
}
