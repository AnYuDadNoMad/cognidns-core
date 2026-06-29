# CogniDNS Core 项目状态

## 1. 当前快照（2026-06-29）

- 项目定位：独立 DNS 解析引擎（数据面 + 控制面）
- 版本形态：持续迭代，面向生产可用性强化
- 运行形态：可单独部署，也可被 Platform 托管

## 2. 核心功能完成度

| 模块 | 状态 | 说明 |
| --- | --- | --- |
| 解析数据面 | 已完成 | Forwarder/Iterative/Fallback、UDP/TCP/DoT/DoH |
| 视图与本地数据 | 已完成 | Split-Horizon、静态记录、权威区 |
| 控制面 | 已完成 | Agent/Worker、ctl 命令、热重载 |
| 可观测性 | 已完成 | health/ready/stats/metrics、TopN、日志分流 |
| 安全策略 | 已完成 | ACL、黑名单、速率限制、鉴权链路 |
| 性能优化 | 已完成 | 缓存机制、关键热路径优化、压测矩阵支持 |
| 运维脚本 | 持续完善 | 启停、健康检查、压测与阈值校验脚本 |

## 3. 已验证能力范围

### 3.1 运行与控制

- Agent 启停、Worker 生命周期、ctl 基础命令
- 热重载流程（配置更新后快速生效）
- 缓存管理全链路（冻结/解冻/导入/导出）
- DNS64 递归回填与 IPv6 合成链路
- UDP 响应截断与 TC 标志处理
- serve-stale 过期缓存回退路径
- QNAME minimization 可开关的递归迭代发包链路
- DNS Cookies 与 EDNS 兼容性边界测试
- SVCB / HTTPS 与现代 RR 类型透传回归
- CNAME / DNAME / glue 组合链路回归

### 3.2 数据与策略

- 视图匹配 + 递归策略联动
- 权威区区内命中、NODATA、NXDOMAIN 行为
- 静态记录与权威区共存时的优先级控制
- 过期缓存可回退，但新鲜缓存仍按 TTL 正常衰减
- 现代记录在 forwarder / iterative 路径中的响应类型保真

### 3.3 可观测与排障

- /stats 与 /metrics 提供运维观测指标
- TopN 统计支持热点域名与来源排查
- 日志分流支持查询、响应、通用事件拆分

## 4. 测试与质量

推荐常规验证命令：

```powershell
cargo check
cargo test --all-targets
```

建议在以下场景执行回归：

- 修改 resolver/policy/cache 相关代码
- 增加或调整配置字段
- 调整 DoT/DoH/控制协议链路
- 变更性能相关热路径

## 5. 当前风险与边界

| 风险项 | 影响 | 当前策略 |
| --- | --- | --- |
| 大规模高并发下尾延迟抖动 | 影响体验与上游稳定性 | 持续通过 benchmark matrix + 阈值守门监控 |
| 配置项增长导致使用门槛上升 | 运维误配概率上升 | 通过 examples、手册与平台化编辑降低复杂度 |
| 异构网络环境下联调复杂度 | 平台对接成本上升 | 强化 admin_url/control/token 一致性检查 |

## 6. 与 Platform 的协作状态

- 协作协议：HTTP Admin + 控制通道
- 职责边界清晰：Core 处理 DNS，Platform 处理管理与可视化
- 当前联调重点：实例可达性、鉴权一致性、配置变更回写稳定性

## 7. 下一阶段计划

1. 优先补齐协议兼容性基础，先做 QNAME minimization、DNS Cookies、EDNS0/rcode 语义细化
2. 继续强化缓存正确性，重点覆盖 RRset、bailiwick、negative caching 与 serve-stale 边界
3. 完善上游可靠性策略，统一超时、重试、退避、故障切换与健康检查
4. 持续提升可观测体系，把 qtype / rcode / upstream / 视图维度指标做成常态化
5. 逐步收敛现代记录支持与解析链路边界，重点是 SVCB / HTTPS、CNAME / DNAME / glue
6. 提升文档与脚本的一致性校验自动化程度

### 7.1 对标开发列表

1. 协议兼容性基础
   - 已完成：QNAME minimization 可开关链路、DNS Cookies 与基础 EDNS 回归
   - 继续收敛：EDNS version / DO / UDP payload / truncation / FORMERR fallback 行为
   - 继续收敛：更完整的 DNS Cookies / rcode 语义，以及 EDNS0 / UDP-TCP fallback 边界
2. 缓存核心能力
   - 已完成：serve-stale 过期缓存回退与缓存导入导出基础回归
   - 继续收敛：negative caching、RRset 一致性、bailiwick 相关缓存正确性
   - 继续收敛：扩展 serve-stale 的更细测试矩阵
3. 现代记录与解析链路
   - 已完成：SVCB / HTTPS 透传回归、CNAME / DNAME / glue 组合链路回归
   - 继续收敛：SVCB / HTTPS 的负面响应、SVCB 选项字段
   - 继续收敛：更复杂的 CNAME、DNAME、glue、委派异常边界
4. 上游可靠性
   - 增强 upstream 健康检查、熔断和恢复
   - 统一超时、重试、退避和故障切换策略
5. 可观测与回归测试
   - 增加按 qtype / rcode / upstream / 视图维度的指标
   - 建立 RFC 兼容性和异常报文测试集
   - 增加关键路径查询跟踪能力
6. 配置与热更新安全
   - 加强配置校验
   - 提升热重载一致性与回滚能力

### 7.2 下一步建议

- 第一优先级：继续收敛协议兼容性基础，补齐 EDNS version、DO 标志、UDP payload size、truncation、FORMERR fallback 与无 EDNS 回退的完整矩阵，减少与外部递归/权威服务器的互操作风险。
- 第二优先级：扩展缓存回归集，重点补 negative caching、RRset 一致性与 bailiwick 相关边界。
- 第三优先级：继续收敛现代记录支持与解析链路边界，重点是 SVCB / HTTPS 的负面响应、SVCB 选项字段，以及更复杂的 CNAME / DNAME / glue 委派组合。

## 8. 文档索引

- [README](../README.md)
- [USER_MANUAL](USER_MANUAL.md)
