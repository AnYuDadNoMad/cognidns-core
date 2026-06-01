# CogniDNS Core 用户手册

## 1. 产品定位

CogniDNS Core 是可独立部署的 DNS 解析服务，提供数据面解析、策略决策、控制面运维与可观测能力。

它适用于以下目标：

- 构建企业/园区/边缘节点递归 DNS 服务
- 按网络域（CIDR）返回差异化解析结果
- 以 API/CTL 方式实现自动化运维
- 作为平台侧统一管理的被控 DNS 引擎

## 2. 功能范围

### 2.1 解析能力

- Forwarder / Iterative / Fallback 模式
- UDP/TCP 标准 DNS 入站
- DoT/DoH 加密入站
- DNSSEC 验证（可配置）

### 2.2 数据与策略能力

- Split-Horizon（按客户端网段匹配视图）
- 权威区数据（支持区文件目录化）
- 静态记录（支持批量与文件化）
- 黑名单、ACL、限流、安全策略

### 2.3 运维能力

- Agent/Worker 生命周期控制
- 配置热重载
- 缓存冻结/解冻/清空/导入导出
- TopN 统计（查询域名与来源客户端）
- health/ready/stats/metrics 接口

## 3. 环境要求

- 操作系统：Windows / Linux / macOS
- 编译环境：Rust stable
- 推荐工具：dig、curl、PowerShell

## 4. 目录与配置约定

```text
config/
├── cognidns.toml              # 主配置
├── cognidns-ctl.toml          # 控制客户端默认配置
├── static_records.toml        # 可选：静态记录外置文件
├── examples/                  # 配置示例
└── benchmarks/                # 压测场景配置
```

常用路径：

- 日志目录：logs/
- 测试目录：tests/
- 运行脚本：scripts/

## 5. 快速启动

### 5.1 构建与自检

```powershell
cargo check
cargo build --release
cargo test --all-targets
```

### 5.2 启动 Agent（推荐）

```powershell
# 前台启动
cargo run -- agent --config config/cognidns.toml

# 后台启动
cargo run -- agent start --config config/cognidns.toml

# 调试启动（前台，不后台化）
cargo run -- -d agent start --config config/cognidns.toml
```

### 5.3 Worker 直启（调试）

```powershell
cargo run -- worker config/cognidns.toml
```

说明：Worker 直启不暴露完整控制面，生产环境建议通过 Agent 统一管理。

### 5.4 默认监听（可在配置中修改）

- DNS：0.0.0.0:5300（UDP/TCP）
- Admin HTTP：0.0.0.0:8080
- Control TCP：127.0.0.1:19090

## 6. 控制面命令

### 6.1 基础命令

```powershell
cargo run -- ctl health --config config/cognidns.toml
cargo run -- ctl ready --config config/cognidns.toml
cargo run -- ctl stats --config config/cognidns.toml
cargo run -- ctl version --config config/cognidns.toml
cargo run -- ctl reload --config config/cognidns.toml
cargo run -- ctl stop --all --config config/cognidns.toml
```

### 6.2 TopN 统计

```powershell
cargo run -- ctl top queries --top 10 --window 300 --config config/cognidns.toml
cargo run -- ctl top clients --top 10 --window 300 --config config/cognidns.toml
```

### 6.3 缓存管理

```powershell
cargo run -- ctl cache freeze --config config/cognidns.toml
cargo run -- ctl cache unfreeze --config config/cognidns.toml
cargo run -- ctl cache clear --config config/cognidns.toml
cargo run -- ctl cache export cache_dump.json --config config/cognidns.toml
cargo run -- ctl cache import cache_dump.json --config config/cognidns.toml
```

## 7. HTTP 管理接口

### 7.1 常用只读接口

- GET /health
- GET /ready
- GET /stats
- GET /metrics
- GET /views
- GET /config/raw
- GET /config/sections

### 7.2 常用写接口

- POST /reload
- PUT /config/raw
- PUT /config/sections
- POST /views
- DELETE /views/:view

## 8. 核心配置建议

### 8.1 解析模式约束

- resolve_mode = forwarder 时，upstreams 不能为空
- resolve_mode = iterative 且不回退 forwarder 时，可不配置 upstreams
- resolve_mode = iterative 且开启 fallback 时，必须配置 upstreams

### 8.2 生产建议

- 使用 config/examples 中的推荐配置作为基线
- 权威区优先使用目录化配置，便于分区维护与审计
- 对高并发环境开启缓存与安全限流组合
- 将 /metrics 接入 Prometheus，配合告警规则使用

## 9. 故障排查

### 9.1 服务启动后立即退出

建议顺序：

1. 检查主配置语法与路径引用是否正确
2. 检查监听端口是否被占用
3. 检查上游配置在当前解析模式下是否满足约束
4. 查看 logs/general.log 当日文件

### 9.2 平台显示实例退化

建议顺序：

1. 在 core 主机上验证 /health 与 /ready
2. 验证 admin_url、control_listen、control_token 是否一致
3. 检查是否出现 401（认证信息不匹配）

### 9.3 查询正确率异常

建议顺序：

1. 查看是否命中错误视图（CIDR 匹配顺序）
2. 检查黑名单与 ACL 策略
3. 导出缓存并核查热点域名条目
4. 必要时清空缓存后复测

## 10. 与 Platform 的协作边界

- Core 负责 DNS 查询处理、策略执行与控制接口
- Platform 负责多实例管理、审计、用户、备份与可视化
- 两者通过 HTTP + 控制协议协作，不共享源码依赖

## 11. 相关文档

- [README](../README.md)
- [PROJECT_STATUS](PROJECT_STATUS.md)
