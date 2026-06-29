# CogniDNS Core 用户手册

## 1. 产品说明

CogniDNS Core 是一个独立部署的 DNS 解析引擎，提供递归解析、转发、权威应答、Split-Horizon 视图、控制面、管理面和可观测能力。它既可以单独作为 DNS 服务运行，也可以作为 CogniDNS Platform 管理的被控实例。

适合的使用场景包括：企业内网 DNS、分支机构本地递归、按网段返回差异化结果、DNS 安全策略网关、以及自动化运维场景。

## 2. 功能总览

### 2.1 解析能力

支持 UDP、TCP、DoT 和 DoH 入站。解析模式支持 forwarder、iterative，以及 iterative 失败后回退上游的组合方式。静态记录、权威区和视图数据可同时参与应答，命中顺序由配置和视图优先级决定。

当前实现还支持：

- 递归 CNAME 跟随
- 静态 CNAME 地址展开
- 权威区 SOA / NXDOMAIN / NODATA 语义
- DNSSEC 处理与 trust anchor 配置
- DNS64 合成：当递归 AAAA 查询没有 AAAA 但存在 A 记录时，可合成 AAAA 返回
- QNAME minimization：在 iterative 模式下按层次缩短上游查询名，减少泄露的完整路径信息
- SVCB / HTTPS 等现代 RR 类型的透传与回归验证
- DNAME 记录与后续 CNAME 链的组合应答
- referral glue 继续可用时的迭代解析边界验证
- 最小应答与 Additional section 控制

### 2.2 策略与数据能力

- Split-Horizon 视图
- 客户端 CIDR 匹配
- 视图级黑名单
- 视图级递归开关
- 视图级静态 CNAME 展开开关
- 权威区目录化加载
- 静态记录文件化加载
- 允许客户端 ACL
- 域名黑名单
- ANY 查询限制
- 限流

### 2.3 运维与可观测能力

- Agent / Worker 生命周期控制
- 热重载
- 缓存冻结、清空、导入导出
- TopN 查询域名和客户端统计
- health / ready / stats / metrics / views / config 接口
- 日志分级和查询追踪
- 健康检查和 IP 健康优选

## 3. 运行前提

- 操作系统：Windows、Linux、macOS
- Rust：stable
- 建议工具：dig、nslookup、curl、PowerShell
- 源码编译：`cargo check`、`cargo build --release`、`cargo test --all-targets`

## 4. 启动方式

### 4.1 Worker 直启

Worker 直启适合调试和单机测试。

```powershell
cargo run -- worker --config config/cognidns.toml
cargo run -- worker config/cognidns.toml
cargo run -- -vv worker --config config/cognidns.toml
```

说明：第二种写法是兼容形式，旧习惯仍可用。生产环境通常建议由 agent 统一拉起 worker。

### 4.2 Agent 启动

Agent 负责管理 worker 生命周期、接收控制命令和执行停止/重启操作。

```powershell
cargo run -- agent --config config/cognidns.toml
cargo run -- agent start --config config/cognidns.toml
cargo run -- -d agent start --config config/cognidns.toml
```

### 4.3 默认启动

如果不显式指定子命令，程序会按默认 worker 模式运行，默认读取 `config/cognidns.toml`。

## 5. 默认监听

默认值可通过配置修改：

- DNS UDP：`0.0.0.0:5300`
- DNS TCP：`0.0.0.0:5300`
- Admin HTTP：`0.0.0.0:8080`
- Control TCP：`127.0.0.1:19090`

## 6. 控制面命令

控制命令通过 `cognidns ctl ...` 发给运行中的 agent。`ctl` 使用的配置文件默认是 `config/cognidns-ctl.toml`，其中的 `server`、`token` 和超时时间必须与 agent 侧匹配。

### 6.1 基础命令

```powershell
cargo run -- ctl health --config config/cognidns.toml
cargo run -- ctl ready --config config/cognidns.toml
cargo run -- ctl stats --config config/cognidns.toml
cargo run -- ctl version --config config/cognidns.toml
cargo run -- ctl reload --config config/cognidns.toml
cargo run -- ctl start --config config/cognidns.toml
cargo run -- ctl stop --config config/cognidns.toml
cargo run -- ctl stop --all --config config/cognidns.toml
```

### 6.2 TopN 统计

```powershell
cargo run -- ctl top queries --top 10 --window 300 --config config/cognidns.toml
cargo run -- ctl top clients --top 10 --window 300 --config config/cognidns.toml
```

### 6.3 缓存管理

```powershell
cargo run -- ctl cache freeze all on --config config/cognidns.toml
cargo run -- ctl cache freeze all off --config config/cognidns.toml
cargo run -- ctl cache freeze domain example.com on --config config/cognidns.toml
cargo run -- ctl cache clear --config config/cognidns.toml
cargo run -- ctl cache clear domain example.com --config config/cognidns.toml
cargo run -- ctl cache export --config config/cognidns.toml --out cache_dump.json
cargo run -- ctl cache import --config config/cognidns.toml --in cache_dump.json
```

### 6.4 认证注意事项

如果控制面返回 `unauthorized`，通常是 agent 和 ctl 使用了不同的 `control_token`。确保：

- 运行中的 agent 读取的是同一份配置
- `control_token` 一致
- `control_listen` 和 `server` 指向同一个地址

## 7. HTTP 管理接口

Admin HTTP 服务提供运行态查询、配置查看、视图管理和重载入口。

### 7.1 只读接口

- `GET /health`
- `GET /ready`
- `GET /stats`
- `GET /metrics`
- `GET /views`
- `GET /config/raw`
- `GET /config/sections`

### 7.2 写入接口

- `POST /reload`
- `PUT /config/raw`
- `PUT /config/sections`
- `POST /views`
- `DELETE /views/:view`

### 7.3 使用建议

- 生产环境建议将 admin 绑定到本机或内网地址
- 如果要暴露给平台系统，请配合反向代理和访问控制
- `config/raw` 适合整文件覆盖，`config/sections` 适合局部调整

## 8. 配置文件结构

主配置文件是 TOML。推荐从 `config/examples/cognidns.example.recommended.toml` 复制一份作为起点，再按环境修改。

### 8.1 基本结构

```text
config/
├── cognidns.toml
├── cognidns-ctl.toml
├── static_records.toml
├── default/
├── examples/
└── benchmarks/
```

### 8.2 配置块分组

- 基础监听与控制：`udp_listen`、`tcp_listen`、`admin_listen`、`control_listen`、`control_token`
- 解析核心：`resolve_mode`、`root_servers`、`iterative_*`、`cname_chain_*`
- 缓存：`cache_*`、`prefetch_*`、`freeze_cache_*`
- 委托和 NS 解析：`ns_host_cache_*`、`enable_delegation_cache`、`ns_hostname_*`、`prewarm_delegation_zones`
- 策略：`allow_clients`、`blocked_domains`、`blocked_domains_file`、`rate_limit_per_second`、`deny_any_queries`
- 数据：`static_records_file`、`static_records`、`authoritative_sources`
- 视图：`views`
- 协议扩展：`dot`、`doh`、`dnssec`
- 运行时：`logging`、`health_check`

## 9. 配置项详解

### 9.1 监听与控制

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `udp_listen` | UDP DNS 监听地址 | `0.0.0.0:5300` |
| `tcp_listen` | TCP DNS 监听地址 | `0.0.0.0:5300` |
| `admin_listen` | Admin HTTP 监听地址 | `0.0.0.0:8080` |
| `control_listen` | agent 控制面监听地址 | `127.0.0.1:19090` |
| `control_token` | 控制面 token，ctl 必须匹配 | `None` |

### 9.2 解析核心

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `resolve_mode` | `forwarder` 或 `iterative` | `forwarder` |
| `root_servers` | iterative 模式使用的根服务器或 bootstrap 服务器 | 空 |
| `iterative_address_family` | `dual_stack`、`ipv4`、`ipv6` | `dual_stack` |
| `iterative_max_depth` | iterative 最大跳数 | `8` |
| `iterative_timeout_ms` | iterative 总超时 | `3000` |
| `cname_chain_max_depth` | CNAME 链最大深度 | `8` |
| `follow_cname_chain` | 是否跟随 CNAME | `true` |
| `static_cname_expand_for_address_queries` | 静态 CNAME 是否展开成地址答案 | `false` |
| `iterative_fallback_to_forwarder` | iterative 失败时是否回退 forwarder | `false` |
| `iterative_cname_bridge_fallback_to_recursive` | CNAME 桥接失败时是否允许回退到递归补全 | `true` |
| `qname_minimization` | iterative 模式下是否启用 QNAME minimization | `true` |

### 9.3 CNAME 与双栈缓存

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `cname_chain_cache_enabled` | 是否缓存完整 CNAME 链结果 | `true` |
| `cname_chain_inline_cache_enabled` | CNAME 跟随途中是否查缓存 | `true` |
| `cname_chain_dualstack_share_enabled` | A/AAAA 互相预热兄弟类型缓存 | `true` |
| `cname_chain_target_prefetch_enabled` | CNAME 终点是否预取缓存 | `false` |

### 9.4 委托与 NS 主机名解析

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `ns_host_cache_capacity` | NS 主机名缓存容量 | `1024` |
| `ns_host_cache_ttl_secs` | NS 主机名缓存 TTL | `60` |
| `ns_host_cache_cleanup_interval_ms` | 清理间隔 | `1000` |
| `enable_delegation_cache` | 是否启用委托缓存 | `false` |
| `strict_bailiwick` | 是否严格 bailiwick 校验 | `true` |
| `delegation_cache_capacity` | 委托缓存容量 | `2048` |
| `delegation_cache_ttl_cap_secs` | 委托缓存 TTL 上限 | `300` |
| `delegation_cache_cleanup_interval_ms` | 清理间隔 | `1000` |
| `delegation_failure_backoff_ms` | 委托失败退避 | `2000` |
| `ns_hostname_max_concurrent` | 同时解析的 NS 主机名数 | `4` |
| `ns_hostname_enough_endpoints` | 收集到多少端点就提前结束 | `2` |
| `ns_hostname_per_resolve_ms` | 单个 NS 主机名解析超时 | `1500` |
| `ns_hostname_resolve_mode` | `bootstrap_recursive` 或 `pure_iterative` | `bootstrap_recursive` |
| `iterative_per_hop_timeout_ms` | 单跳 NS 解析超时，0 为自动推导 | `0` |
| `prewarm_delegation_zones` | 启动时预热的委托区列表 | 空 |

### 9.5 缓存与预取

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `cache_hot_capacity` | 热缓存容量 | `50000` |
| `response_cache_capacity` | 主响应缓存容量 | `200000` |
| `cache_ttl_secs` | 默认缓存 TTL | `30` |
| `freeze_cache_ttl_decay` | 是否冻结 TTL 衰减 | `false` |
| `freeze_cache_domains` | TTL 冻结域名列表 | 空 |
| `prefetch_budget_per_window` | 每窗口预取预算 | `64` |
| `prefetch_window_secs` | 预取窗口秒数 | `1` |
| `prefetch_ttl_trigger_secs` | TTL 小于等于该值时触发预取 | `5` |
| `prefetch_popularity_threshold` | 热度阈值 | `3` |

### 9.6 统计与自适应缓存

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `stats_window_secs` | 长窗口秒数 | `60` |
| `stats_short_window_secs` | 短窗口秒数 | `10` |
| `topn_stats_enabled` | 是否启用 TopN 统计 | `false` |
| `adaptive_cache_enabled` | 是否启用自适应缓存 | `true` |
| `adaptive_cache_min_capacity` | 最小容量 | `100000` |
| `adaptive_cache_max_capacity` | 最大容量 | `400000` |
| `adaptive_cache_step` | 容量调整步长 | `10000` |
| `adaptive_cache_window_secs` | 调整窗口 | `10` |
| `adaptive_cache_high_miss_ratio` | 高 miss 阈值 | `0.55` |
| `adaptive_cache_low_miss_ratio` | 低 miss 阈值 | `0.15` |

### 9.7 策略与过滤

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `allow_clients` | 允许访问的客户端 CIDR 列表，空表示全放行 | 空 |
| `blocked_domains` | 全局黑名单域名列表 | 空 |
| `blocked_domains_file` | 黑名单外置文件 | `config/default/blocked_domains.toml` |
| `enable_recursion` | 全局递归开关 | `true` |
| `dns64_enabled` | 启用 DNS64 合成 | `false` |
| `dns64_prefix` | DNS64 合成前缀 | `64:ff9b::` |
| `minimal_response` | 是否启用最小应答 | `true` |
| `rate_limit_per_second` | 每秒限流值，0 表示关闭 | `0` |
| `deny_any_queries` | 是否拒绝 ANY 查询 | `false` |

### 9.8 数据源

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `static_records_file` | 静态记录外置文件 | `None` |
| `static_records` | 内联静态记录 | 空 |
| `authoritative_sources` | 外部权威源列表 | 空 |

### 9.9 视图

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `views` | 视图列表，按顺序匹配 client_cidrs | 空 |

视图中的字段说明见下一节。

### 9.10 协议扩展

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `dot.enabled` | 启用 DoT | `false` |
| `dot.listen` | DoT 监听地址 | `0.0.0.0:853` |
| `dot.cert_file` | 证书路径 | `config/dot.crt` |
| `dot.key_file` | 私钥路径 | `config/dot.key` |
| `doh.enabled` | 启用 DoH | `false` |
| `doh.listen` | DoH 监听地址 | `0.0.0.0:8053` |
| `dnssec.enabled` | 启用 DNSSEC | `true` |
| `dnssec.use_builtin_trust_anchors` | 使用内置 trust anchors | `true` |
| `dnssec.trust_anchor_files` | 额外 trust anchor 文件 | 空 |

### 9.11 日志与健康检查

| 字段 | 说明 | 默认值 |
| --- | --- | --- |
| `logging.enabled` | 启用日志 | `true` |
| `logging.console` | 控制台输出 | `true` |
| `logging.directory` | 日志目录 | `logs` |
| `logging.rotation` | 轮转方式 | `day` |
| `logging.format` | `compact` 或 `json` | `compact` |
| `logging.query_level` | 查询日志级别 | `info` |
| `logging.response_level` | 响应日志级别 | `info` |
| `logging.general_level` | 通用日志级别 | `info` |
| `logging.trace_query_domains` | 需要详细追踪的域名后缀 | 空 |
| `health_check.enabled` | 启用健康检查 | `false` |
| `health_check.mode` | `tcp`、`http` 或 `https` | `tcp` |
| `health_check.port` | 健康检查端口 | `80` |
| `health_check.http_path` | 健康检查 HTTP 路径 | `/` |
| `health_check.http_host_header` | 健康检查 Host 头 | `None` |
| `health_check.interval_secs` | 周期 | `30` |
| `health_check.timeout_ms` | 超时 | `1000` |
| `health_check.max_parallel` | 并发探测上限 | `64` |
| `health_check.failure_threshold` | 判定失败阈值 | `2` |
| `health_check.success_threshold` | 判定恢复阈值 | `1` |
| `health_check.all_unhealthy_log_file` | 全部不健康事件日志 | `logs/health-all-unhealthy.log` |
| `health_check.notify_webhook` | 告警回调 URL | `None` |
| `health_check.probe_tls_insecure_skip_verify` | 探测时跳过 TLS 校验 | `false` |
| `health_check.webhook_tls_insecure_skip_verify` | webhook 跳过 TLS 校验 | `false` |
| `health_check.notify_webhook_retries` | webhook 重试次数 | `2` |
| `health_check.notify_webhook_backoff_ms` | webhook 重试退避 | `500` |

## 10. 视图配置说明

视图用于 Split-Horizon。视图会按 `client_cidrs` 顺序匹配，命中后优先使用该视图的数据和策略。

视图支持字段：

| 字段 | 说明 |
| --- | --- |
| `name` | 视图名称，建议唯一 |
| `summary` | 视图说明 |
| `client_cidrs` | 客户端匹配网段列表 |
| `static_records_file` | 视图级静态记录文件 |
| `static_records` | 视图级静态记录 |
| `records` | 兼容旧格式的 `domain_name` / `ip` 记录 |
| `blocked_domains_file` | 视图级黑名单文件 |
| `blocked_domains` | 视图级黑名单 |
| `authoritative_zones_file` | 视图级权威区文件 |
| `authoritative_zones_dir` | 视图级权威区目录 |
| `authoritative_zones` | 视图级权威区内联配置 |
| `query_mode` | `view_only` 或 `global_fallback` |
| `enable_recursion` | 视图级递归开关 |
| `view_static_cname_expand_for_address_queries` | 视图级静态 CNAME 展开开关 |
| `view_authoritative_cname_expand_for_address_queries` | 视图级权威 CNAME 展开开关 |

### 10.1 视图行为

- `view_only`：视图命中后只回答该视图内的数据，不回退到全局。
- `global_fallback`：视图内未命中时，继续使用全局静态记录、权威区和递归逻辑。
- 如果未命中任何视图，但存在名为 `default` 的视图，则会回退到它。

## 11. 解析模式与行为建议

### 11.1 forwarder

forwarder 模式会向上游列表查询。适合依赖上游公共 DNS、内部递归或统一策略网关的场景。

建议：

- 配置 `upstreams`
- 配置合理的 `upstream_timeout_ms`
- 对高并发环境搭配 `cache_hot_capacity` 和 `response_cache_capacity`

### 11.2 iterative

iterative 模式会从 `root_servers` 出发逐跳迭代。

建议：

- 配置 `root_servers`
- 调整 `iterative_timeout_ms`、`iterative_max_depth`
- 开启 `enable_delegation_cache`
- 视情况设置 `prewarm_delegation_zones`

如果启用了 `qname_minimization`，递归查询的每一跳会使用更短的 QNAME 发往上游。比如查询 `www.example.com` 时，首跳通常先问 `com`，再逐层缩回到更具体的名称。这个行为更接近成熟递归解析器，也更适合在对外网络环境中减少信息暴露。

### 11.3 DNS64

DNS64 适合仅具备 IPv4 资源、但客户端需要 IPv6 AAAA 的环境。

配置示例：

```toml
dns64_enabled = true
dns64_prefix = "64:ff9b::"
```

说明：当递归 AAAA 查询没有 AAAA，但存在 A 记录时，服务会使用前缀合成 AAAA 返回。默认前缀是 `64:ff9b::/96`。

## 12. 推荐配置示例

### 12.1 推荐基线

推荐使用 `config/examples/cognidns.example.recommended.toml` 作为生产基线。它默认：

- 监听端口避开 53
- 启用 iterative
- 开启委托缓存和自适应缓存
- 默认关闭危险操作，例如过度开放的管理面

### 12.2 完整示例

`config/examples/cognidns.example.full.toml` 展示了完整字段和注释，适合作为配置字典查看。

### 12.3 Split-Horizon 示例

`config/examples/cognidns.example.split-horizon.toml` 展示了按客户端网段返回不同视图的做法。

## 13. 典型配置片段

### 13.1 Forwarder 示例

```toml
resolve_mode = "forwarder"
upstreams = ["1.1.1.1:53", "8.8.8.8:53"]
enable_recursion = true
```

### 13.2 Iterative 示例

```toml
resolve_mode = "iterative"
root_servers = ["198.41.0.4:53", "199.9.14.201:53"]
enable_delegation_cache = true
iterative_fallback_to_forwarder = false
qname_minimization = true
```

### 13.3 Split-Horizon 示例

```toml
[[views]]
name = "internal"
client_cidrs = ["10.0.0.0/8"]
query_mode = "view_only"
enable_recursion = false
static_records_file = "config/internal/static_records.toml"
```

### 13.4 权威区示例

```toml
[[views]]
name = "default"
client_cidrs = []
query_mode = "global_fallback"
enable_recursion = true
authoritative_zones_dir = "config/examples/authoritative_zones.d/global"
```

### 13.5 DNS64 示例

```toml
resolve_mode = "iterative"
dns64_enabled = true
dns64_prefix = "64:ff9b::"
```

## 14. 查询与验证

### 14.1 使用 dig

```powershell
dig @127.0.0.1 -p 5300 example.com A
dig @127.0.0.1 -p 5300 example.com AAAA
dig @127.0.0.1 -p 5300 example.com NS
dig @127.0.0.1 -p 5300 example.com SOA
```

### 14.2 使用 nslookup

```powershell
nslookup -port=5300 example.com 127.0.0.1
```

### 14.3 验证健康状态

```powershell
cargo run -- ctl health --config config/cognidns.toml
cargo run -- ctl ready --config config/cognidns.toml
cargo run -- ctl stats --config config/cognidns.toml
```

## 15. 与 Platform 的协作

Core 负责：

- DNS 查询处理
- 策略和视图路由
- 控制协议
- 管理 API

Platform 负责：

- 多实例编排
- 可视化
- 审计
- 备份
- 统一配置管理

如果只需要单机 DNS 服务，可以只部署 Core；如果需要多实例管理和审计闭环，建议配合 Platform 使用。

## 16. 故障排查

### 16.1 服务启动后立即退出

1. 检查配置文件语法
2. 检查端口占用
3. 检查 `resolve_mode` 与 `upstreams` / `root_servers` 的组合是否满足约束
4. 检查 `health_check` 和 `dnssec` 相关约束

### 16.2 ctl 返回 unauthorized

1. 确认 agent 和 ctl 使用同一份配置
2. 确认 `control_token` 一致
3. 确认 `control_listen` 和 ctl 的 `server` 一致

### 16.3 查询结果不符合预期

1. 检查视图命中顺序和 `client_cidrs`
2. 检查黑名单和 ACL
3. 检查是否命中权威区或静态记录
4. 检查是否开启 `static_cname_expand_for_address_queries`
5. 检查 DNS64 是否启用，以及 AAAA 请求是否被合成前缀覆盖
6. 如果是 SVCB / HTTPS 或其他现代 RR 类型，确认上游和测试链路都保留了原始 qtype，而不是被错误降级为 A / AAAA
7. 如果是 DNAME / CNAME / glue 组合，应优先检查 referral 是否包含可用 glue，以及权威响应是否保留了 DNAME 与后续 CNAME 链

### 16.4 递归失败

1. iterative 模式检查 `root_servers`
2. forwarder 模式检查 `upstreams`
3. 检查 `iterative_timeout_ms`、`upstream_timeout_ms`
4. 检查 `iterative_fallback_to_forwarder` 是否需要开启

## 17. 常见运行组合

### 17.1 小型生产递归 DNS

- `resolve_mode = "iterative"`
- `enable_delegation_cache = true`
- `topn_stats_enabled = true`
- `logging.enabled = true`
- `health_check.enabled = true`

### 17.3 现代记录与边界回归

建议在以下场景执行更细的验证：

- 修改 modern RR 透传、响应组包或分析逻辑
- 调整 iterative referral、glue 选择或 DNAME 链处理
- 调整 EDNS / DNS Cookies / 兼容性边界

推荐检查项：

- SVCB / HTTPS 查询能否在 forwarder 和 iterative 路径中保持原始 qtype
- DNAME + CNAME 链是否在响应中同时保留
- referral glue 是否能支撑下一跳继续解析

### 17.2 企业内网 Split-Horizon

- 使用多个 `views`
- 视图按网段区分
- 内网视图关闭递归或使用 `view_only`
- 公网视图启用 `global_fallback`

### 17.3 仅转发模式

- `resolve_mode = "forwarder"`
- `upstreams` 配公共或内部递归
- 开启缓存和限流

### 17.4 IPv6 兼容场景

- `dns64_enabled = true`
- `dns64_prefix = "64:ff9b::"`
- 结合 `iterative_address_family = "dual_stack"`

## 18. 相关文件

- [README](../README.md)
- [项目状态](PROJECT_STATUS.md)
- [推荐配置示例](../config/examples/cognidns.example.recommended.toml)
- [全量配置示例](../config/examples/cognidns.example.full.toml)
- [Split-Horizon 示例](../config/examples/cognidns.example.split-horizon.toml)
