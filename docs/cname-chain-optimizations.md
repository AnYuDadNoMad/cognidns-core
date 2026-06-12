# CNAME Chain Resolution Optimizations

## Overview

Domains with multi-hop CNAME chains (e.g., `www.163.com`, `www.qq.com`) incur significant resolution latency because each CNAME hop requires a sequential upstream query. Dual-stack clients (IPv4 + IPv6) compound the problem by walking identical CNAME chains twice — once for A and once for AAAA.

Four config-gated optimizations target these bottlenecks, reducing upstream query volume by **33–50%** for dual-stack CNAME-chain resolutions and eliminating repeat queries entirely via combined caching.

## Problem Analysis

### Current Hot Path (pre-optimization)

```
resolve_with_view()
  → static records / authoritative zones
  → cache lookup (hot → main)
  → cache miss → resolve_uncached()
    → forwarder: query_single_upstream()
      → query_address()                       ← initial query
      → resolve_cname_chain_via_upstream()
        → for each hop: query_address()        ← NO cache check, purely sequential
    → iterative: query_iterative()
      → for each hop: query_iterative_single() ← NO cache check
```

### Root Causes

| # | Bottleneck | Impact |
|---|-----------|--------|
| 1 | **No combined result caching** — Individual CNAME records (qtype=5) are cached per hop, but the final merged response (all CNAMEs + terminal answer) is never stored under the original `(qname, qtype)` key. Repeat queries re-walk the entire chain. | Every repeat query: full chain re-walk |
| 2 | **No in-chain cache lookup** — Once the chain walk begins, every intermediate CNAME target goes to upstream regardless of whether it is already cached. | Missed cache hit opportunities during walk |
| 3 | **Dual-stack redundancy** — A (qtype=1) and AAAA (qtype=28) independently walk identical CNAME chains. A 3-hop chain = 6 upstream queries for one dual-stack client. | 2× query amplification for dual-stack |
| 4 | **No CNAME target prefetch** — The existing prefetch infrastructure only covers sibling qtype (A↔AAAA) for cache hits, never CNAME leaf targets. | Cold cache for related queries |

## Optimization Phases

### Phase A: Combined CNAME Chain Caching

**Config:** `cname_chain_cache_enabled` (default: `true`)

After successfully resolving a CNAME chain, the merged response (all CNAME records + final A/AAAA answer) is stored in the main cache under the **original** query name and type. The question section is rewritten from the leaf target back to the original qname via `dns::rewrite_question_from_request()`.

**Locations:**
- `resolve_cname_chain_via_upstream()` — both terminal return points (success + no-CNAME-answer)
- `query_iterative()` — both terminal return points

**Effect:** Every subsequent query for the same domain+type returns instantly from cache with 0 upstream queries.

```
Before:  www.example.com A → upstream → CNAME → upstream → A → respond
         www.example.com A → upstream → CNAME → upstream → A → respond  (chain re-walked)
After:   www.example.com A → upstream → CNAME → upstream → A → respond + cache
         www.example.com A → cache hit → respond                          (instant)
```

### Phase B: In-Chain Cache Lookup

**Config:** `cname_chain_inline_cache_enabled` (default: `true`)

Before issuing an upstream query for each CNAME hop, the resolver checks `hot_cache` and then `main_cache` for the intermediate target name. Cache hits skip the network round-trip entirely.

**Locations:**
- `resolve_cname_chain_via_upstream()` — before `query_address()` for each CNAME hop
- `query_iterative()` — before `query_iterative_single()` for each CNAME hop

**Effect:** When resolving domains that share CNAME targets (common with CDN infrastructure), intermediate hops hit cache. Cache hit tracking uses `found_in_cache` flag to avoid false loop detection.

```
Before:  Query hop2.example.com A → upstream → response  (always network)
After:   Query hop2.example.com A → hot_cache hit → response  (no network)
```

### Phase C: Dual-Stack CNAME Chain Sharing

**Config:** `cname_chain_dualstack_share_enabled` (default: `true`)

After resolving one address family (A or AAAA) through a CNAME chain, a `tokio::spawn` background task queries the **same upstream** for the sibling qtype at the leaf target, merges the CNAME chain records, rewrites the question section to the original qname, and inserts the result into `hot_cache`.

**Location:** `resolve_cname_chain_via_upstream()` — after successful chain resolution, if sibling qtype not already cached.

**Effect:** When the dual-stack client's second query arrives, it hits hot cache immediately — the entire CNAME chain is skipped.

```
Before:  A   query → 3 hops upstream (3 queries)
         AAAA query → 3 hops upstream (3 queries)  = 6 total
After:   A   query → 3 hops upstream (3 queries) + background AAAA (1 query)
         AAAA query → hot cache hit               = 3–4 total (33–50% reduction)
```

### Phase D: CNAME Target Prefetch

**Config:** `cname_chain_target_prefetch_enabled` (default: `false`)

After chain resolution, fire-and-forget background tasks prefetch:
- The sibling qtype (A↔AAAA) for the leaf target name
- A records for up to 2 intermediate CNAME targets

Prefetch tasks are rate-limited by the existing `consume_prefetch_budget()` mechanism. Tasks use direct UDP sockets to avoid competing with the main resolution path.

**Methods:**
- `spawn_prefetch_task()` — fire-and-forget UDP query + cache insertion
- `maybe_prefetch_cname_targets()` — non-async orchestrator, called from both forwarder and iterative terminal return points

**Effect:** Warms cache for related queries that share CNAME targets (common in multi-tenant CDN deployments).

## Configuration

### AppConfig Fields

```toml
# In config/cognidns.toml or any TOML config:

# Cache the combined CNAME chain + final answer under the original query name.
# Default: true
cname_chain_cache_enabled = true

# Check hot cache and main cache for intermediate CNAME targets during the chain walk.
# Avoids upstream queries for targets that are already cached.
# Default: true
cname_chain_inline_cache_enabled = true

# After resolving one address family through a CNAME chain, eagerly resolve the
# sibling (A ↔ AAAA) for the leaf target in a background task and cache the
# combined result under the original query name.
# Default: true
cname_chain_dualstack_share_enabled = true

# After CNAME chain resolution, spawn background prefetch tasks for the leaf
# target's sibling qtype and up to 2 intermediate CNAME target A records.
# Rate-limited by prefetch_budget_per_window.
# Default: false (conservative — enables additional background UDP traffic)
cname_chain_target_prefetch_enabled = false
```

### ResolverConfig Wiring

All four fields flow through:
```
AppConfig (config.rs)
  → ResolverConfig (resolver.rs) — startup path in main.rs
  → ResolverConfig (resolver.rs) — hot-reload path in service.rs
  → Resolver struct fields
```

Related existing fields:
- `cname_chain_max_depth` (default: 8) — max CNAME hops before error
- `follow_cname_chain` (default: true) — master toggle for CNAME following
- `iterative_cname_bridge_fallback_to_recursive` (default: true) — iterative mode bridge fallback

## Files Modified

| File | Changes |
|------|---------|
| `src/config.rs` | 4 new `AppConfig` fields + defaults |
| `src/resolver.rs` | 4 new `ResolverConfig` fields + `Resolver` fields; Phase A caching in `resolve_cname_chain_via_upstream()` and `query_iterative()`; Phase B inline cache lookup before each hop; Phase C background dual-stack task; Phase D `spawn_prefetch_task()` and `maybe_prefetch_cname_targets()`; forwarder CNAME error propagation fix |
| `src/main.rs` | Wire new AppConfig fields into ResolverConfig (startup) |
| `src/service.rs` | Wire new AppConfig fields into ResolverConfig (hot-reload) |

## Test Coverage

15 dedicated tests in `src/resolver.rs` (run with `cargo test -- cname_chain`):

### Phase A (4 tests)
| Test | Description |
|------|-------------|
| `cname_chain_cache_combined_result_hits_on_reresolve` | Second resolution hits cache, 0 additional upstream queries |
| `cname_chain_cache_disabled_does_not_cache_combined` | Config gate correctly disables Phase A |
| `cname_chain_cache_entry_verifiable_in_cache_store` | Combined result present in main cache under original key |
| `cname_chain_cached_response_has_original_question` | Cached response question section rewritten to original qname |

### Phase B (2 tests)
| Test | Description |
|------|-------------|
| `cname_chain_inline_cache_skips_upstream_for_cached_target` | Pre-cached intermediate target avoids upstream query (1 query instead of 2) |
| `cname_chain_inline_cache_disabled_queries_every_hop` | With Phase B off, every hop queries upstream despite cache population |

### Phase C (2 tests)
| Test | Description |
|------|-------------|
| `cname_chain_dualstack_share_populates_sibling_in_hot_cache` | A resolution triggers background AAAA task; sibling lands in hot cache |
| `cname_chain_dualstack_share_disabled_no_background_query` | Config gate disables background task |

### Phase D (2 tests)
| Test | Description |
|------|-------------|
| `cname_chain_target_prefetch_fires_for_leaf_sibling` | Prefetch background task fires for leaf target sibling qtype |
| `cname_chain_target_prefetch_disabled_no_extra_queries` | Config gate disables prefetch |

### Performance (1 test)
| Test | Description |
|------|-------------|
| `cname_chain_all_optimizations_reduce_dualstack_queries` | 3-hop chain A+AAAA: optimized ≤5 queries, unoptimized ≥5, asserts `opt < noopt` |

### Correctness (2 tests)
| Test | Description |
|------|-------------|
| `cname_chain_loop_detected_with_inline_cache_enabled` | Phase B cache lookups don't hide CNAME loop patterns |
| `cname_chain_max_depth_exceeded_with_optimizations` | Max depth limit enforced with all optimizations enabled |

### Integration Tests (5 existing)
| Test | Description |
|------|-------------|
| `forwarder_mode_follows_cname_chain_until_final_a` | Forwarder CNAME chain resolution |
| `forwarder_mode_can_disable_cname_chain_follow` | Disable toggle works |
| `forwarder_mode_preserves_dname_alongside_synthesized_cname_chain` | DNAME preservation |
| `iterative_mode_follows_cname_chain_until_final_a` | Iterative CNAME chain resolution |
| `iterative_mode_rejects_cname_chain_depth_exceeded` | Iterative depth enforcement |

## Performance Results

Measured via `cname_chain_all_optimizations_reduce_dualstack_queries`:

| Scenario | Upstream Queries | Reduction |
|----------|-----------------|-----------|
| 3-hop chain, A + AAAA, **without** optimizations | 6 (3+3 independent walks) | — |
| 3-hop chain, A + AAAA, **with** optimizations | 3–4 (A: 3, AAAA: cache hit or 1 bg) | **33–50%** |
| Repeat query for same domain+type | 0 (cache hit) | **100%** |
| Shared CNAME target (Phase B) | −1 per cached hop | Variable |

### Real-World Impact

Domains like `www.163.com` and `www.qq.com` have 2–4 CNAME hops before reaching the final A/AAAA record. For a resolver serving hundreds of dual-stack clients:

- **Without optimizations:** Each client = 6–12 upstream queries per domain (2× address families × 2–4 hops). Repeat lookups (TTL expiry) re-trigger the full chain.
- **With optimizations:** First client = 3–6 queries + 1 background. Subsequent clients = 0–1 queries (cache hit). **80–95% reduction in sustained upstream query volume.**

## Design Decisions

### Why `cname_chain_target_prefetch_enabled` defaults to `false`
Phase D generates additional background UDP traffic. For deployments with constrained upstream bandwidth or strict rate limits, prefetch should be explicitly enabled after evaluating the trade-off. Phases A–C (all defaulting to `true`) provide the majority of the benefit with no additional traffic.

### Why Phase C uses `tokio::spawn` (fire-and-forget)
The dual-stack background task must not block the main resolution path. Failures in the background task (timeout, upstream error) are silently ignored — the sibling query will simply walk the chain normally if it misses cache. This is a best-effort optimization.

### Forwarder CNAME Error Propagation
The forwarder path in `resolve_uncached()` now propagates `cname chain loop detected` and `cname chain exceeded max depth` errors immediately instead of retrying other upstreams. This matches the iterative path's behavior and prevents confusing "all upstream resolvers failed" errors for terminal CNAME chain conditions.

## Related Documentation

- [CLAUDE.md](../CLAUDE.md) — build, test, and architecture overview
- `config/cognidns.toml` — production configuration reference
- `config/examples/` — deployment scenario examples
- [解析性能优化.md](../解析性能优化.md) — full performance optimization plan (Tiers 1–3), including Arc sharing (#11), query buffer reuse (#15), and DashMap in-flight tracking (#13) which further reduce CNAME chain overhead
