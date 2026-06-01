# CogniDNS Core

CogniDNS Core 是独立的高性能 DNS 解析引擎，提供递归解析、策略控制、可观测能力与控制面接口。

本仓库聚焦 DNS 数据面与控制面，不包含 Web 管理平台前端。

## 1. 核心能力

- 解析模式：Forwarder / Iterative / Fallback 组合
- 接入协议：UDP、TCP、DoT、DoH
- 数据模型：静态记录、权威区、Split-Horizon 视图
- 策略控制：ACL、黑名单、速率限制、查询策略
- 运行控制：Agent/Worker 生命周期、热重载、缓存管理
- 可观测性：health/ready/stats/metrics、TopN 统计、审计日志

## 2. 适用场景

- 企业内网或分支机构的递归 DNS 基础设施
- 作为带策略能力的上游转发器
- 需要按客户端网段返回差异解析结果（Split-Horizon）
- 需要将 DNS 能力嵌入现有自动化或运维系统
- 作为 CogniDNS Platform 的被管实例

## 3. 项目结构

```text
cognidns-core/
├── src/                    # 解析、策略、控制、运维接口实现
├── config/                 # 主配置、ctl 配置、示例与基准配置
├── tests/                  # 集成与端到端测试
├── scripts/                # 启停、健康检查、压测辅助脚本
└── docs/                   # 用户手册与项目状态
```

## 4. 快速开始

### 4.1 构建与测试

```powershell
cargo check
cargo build --release
cargo test --all-targets
```

### 4.2 启动服务

```powershell
# 推荐：由 agent 拉起 worker
cargo run -- agent --config config/cognidns.toml

# 后台启动
cargo run -- agent start --config config/cognidns.toml

# 调试启动（前台）
cargo run -- -d agent start --config config/cognidns.toml
```

### 4.3 验证运行状态

```powershell
cargo run -- ctl health --config config/cognidns.toml
cargo run -- ctl ready --config config/cognidns.toml
cargo run -- ctl stats --config config/cognidns.toml
```

默认端口（可配置）：

- DNS：0.0.0.0:5300
- Admin HTTP：0.0.0.0:8080
- Control TCP：127.0.0.1:19090

## 5. 常用运维命令

```powershell
# 重载配置
cargo run -- ctl reload --config config/cognidns.toml

# 缓存操作
cargo run -- ctl cache clear --config config/cognidns.toml
cargo run -- ctl cache export cache_dump.json --config config/cognidns.toml

# TopN
cargo run -- ctl top queries --top 10 --window 300 --config config/cognidns.toml
cargo run -- ctl top clients --top 10 --window 300 --config config/cognidns.toml

# 关闭 agent + worker
cargo run -- ctl stop --all --config config/cognidns.toml
```

## 6. 文档入口

- [用户手册](docs/USER_MANUAL.md)
- [项目状态](docs/PROJECT_STATUS.md)

## 7. 与平台协作

CogniDNS Platform 通过实例配置中的 `admin_url`、`control_listen`、`control_token` 与 Core 通信。

当你只需要 DNS 解析与自动化控制链路时，可单独部署 Core；当你需要多实例可视化管理与审计闭环时，建议配合 Platform 使用。
