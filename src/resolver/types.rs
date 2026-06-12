//! Resolver internal data types: record entries, zone entries, view indices,
//! and query control structures.

use std::collections::{HashMap, HashSet};

use crate::cache::CacheKey;
use crate::config::{ViewQueryMode, ZoneSoa};

// ── Static record entries ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(super) struct StaticRecordEntry {
    pub answer: String,
    pub ttl: u32,
    pub qtype_name: String,
}

#[derive(Debug, Clone)]
pub(super) struct AuthoritativeSourceEntry {
    pub source: String,
    pub ttl: u32,
    pub qtype_name: String,
}

// ── Authoritative zone entries ───────────────────────────────────────────────

/// 权威区多记录条目，支持同名同类型的多条 RR（RFC 1035）。
#[derive(Debug, Clone)]
pub(super) struct MultiRecordEntry {
    /// 所有该类型的 RDATA 文本值列表（如多条 A 地址、多条 NS 主机名）
    pub answers: Vec<String>,
    pub ttl: u32,
    pub qtype_name: String,
}

/// 权威区运行时索引条目，包含 SOA、区内记录索引及名称存在集合。
#[derive(Debug)]
pub(super) struct AuthoritativeZoneEntry {
    /// 规范化区域名称（小写、无末尾点）
    pub zone_name: String,
    /// SOA 记录（可选；无 SOA 则不能生成 NXDOMAIN/NODATA authority section）
    pub soa: Option<ZoneSoa>,
    /// 区内记录索引：CacheKey → MultiRecordEntry（每条 CacheKey 对应同名同类型的所有 RR）
    pub record_index: HashMap<CacheKey, MultiRecordEntry>,
    /// 区内存在的所有规范化 QNAME 集合（用于区分 NXDOMAIN 与 NODATA，RFC 2308）
    pub name_set: HashSet<String>,
}

// ── View types ───────────────────────────────────────────────────────────────

pub(super) type ViewRecordIndex = HashMap<String, HashMap<CacheKey, StaticRecordEntry>>;
pub(super) type ViewZoneIndex = HashMap<String, Vec<AuthoritativeZoneEntry>>;
pub(super) type ViewQueryControlIndex = HashMap<String, ViewQueryControl>;

#[derive(Debug, Clone, Copy)]
pub(super) struct ViewQueryControl {
    pub query_mode: ViewQueryMode,
    pub enable_recursion: bool,
    pub view_static_cname_expand_for_address_queries: Option<bool>,
    pub view_authoritative_cname_expand_for_address_queries: Option<bool>,
}

pub(super) enum ViewLookupResult<'a> {
    Direct(&'a StaticRecordEntry),
    Cname(&'a StaticRecordEntry),
}
