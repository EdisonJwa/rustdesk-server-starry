# 更新日志

[English](CHANGELOG.md) | **简体中文**

本文记录 Starry overlay 的变化。完整产物版本由官方 RustDesk Server 版本与 Starry
patch 版本组合，例如 `1.1.16-patch-v1.3.1`。

## 未发布 — 独立服务端、上游 1.1.17、WebRTC

### 变更

- **Starry 改为独立的服务端源码树。** 退役 overlay 补丁脚本
  （`scripts/apply_overlay.py`，6,700 行）；直接跟踪 `src/`、`tests/`、
  `Cargo.toml`/`Cargo.lock` 与 `libs/hbb_common/`。CI 只构建 `git archive HEAD`。
- `UPSTREAM` 记录最近一次审查的 rustdesk-server 提交（`680b603`，Cargo 版本 1.1.17，
  未打 tag）。上游修复人工移植；CI 只在上游 master 超前时提示。
- `libs/hbb_common` 内置自 rustdesk/hbb_common `bb416bc`（RustDesk 1.5 客户端协议：
  `IceCandidate`、`webrtc_sdp_*`、KeyExchange v2 字段）。Starry 的改动恰好是
  `libs/hbb_common.starry.patch`，CI 会用记录的提交加该补丁复现内置目录。上游把
  `IdPk` 移入 `rendezvous.proto`，线上格式不变。
- WebSocket 使用上游的 `rustdesk-org` tokio-tungstenite 与 tungstenite 0.29 分支。
- 从 `.env`/`-c` 读取的 Starry 配置通过 `common::env_var` 兼容上游参数别名
  （`STARRY_FOO` 与 `STARRY-FOO`）。
- 契约检查现在要求每个契约定义的 protobuf message 原样出现在内置
  `rendezvous.proto` 中。

### 新增

- `starry-client-config`：直接从服务器密钥材料生成客户端配置（ID 服务器、
  中继服务器、公钥、策略组标注），输出 text、JSON 或 base64 导入字符串。只读
  `id_ed25519.pub`；绝不签发 token。
- 策略引擎 v1：版本化的设备组策略文档（`STARRY_STRATEGY_FILE`），按组覆盖
  连接 JWT 的 scope 要求并支持整组拒绝，在 HBBS 内任何信令工作之前强制执行，
  审计事件附带组名。支持运行时经本地控制重载
  （`strategy.status` / `strategy.reload`）。仅服务端强制——客户端设置同步
  仍是 API 层职责。参见[策略引擎 v1](../reference/STRATEGY-v1.zh-CN.md)。
- 连接审计日志：HBBS 将每一次连接认证决策记录为只追加的 JSONL 证据（类型、
  传输、判定、原因、客户端地址、模式），由 `STARRY_AUDIT_DIR` 开启。默认关闭；
  按日轮转、保留期清理与单日大小上限三者约束存储；信令路径绝不因日志阻塞。
  随附的 `starry-audit-export` 工具把日文件转换为 RFC 4180 CSV，支持包含边界
  的 UTC 日期过滤。参见[连接审计日志](../reference/AUDIT-LOG.zh-CN.md)。
- `starry-relay-entrypoint` 与 HBBR 提供可选的、仅回环的运维端点
  （`STARRY_RELAY_OPS_LISTEN`，默认关闭），服务 `/healthz` 与 Prometheus
  `/metrics`，数字与认证遥测报告的一致。
- 可选的 RustDesk 1.5 WebRTC 信令（`--webrtc-signal=Y` 或
  `STARRY_WEBRTC_SIGNAL=Y`，默认关闭）：沿有界的按连接路由转发 SDP offer/answer 与
  trickle ICE，只接受来自 Secure TCP 或 WebSocket 的 offer。见
  [WebRTC 信令](../reference/WEBRTC-SIGNALLING-v1.zh-CN.md)。
- `starry-api`：RustDesk 兼容的 API 服务器（端口 21114），SQLite 账号
  （bcrypt）、官方 1.5 客户端解析的契约（`/api/login-options`、`/api/login`、
  `/api/currentUser`、`/api/logout`），以及被客户端原样当作信令凭据回传的
  Ed25519 连接 token。发布 HBBS 校验所用的 JWKS（`connection_auth.jwks.file`）
  及摘要绑定的新鲜度戳并按心跳续签；`starry-api user add|passwd|enable|disable|list`
  管理账号，密码只接受来自 stdin 或环境变量。见
  [认证服务器 v1](../reference/AUTH-SERVER-v1.zh-CN.md)。

### 在 Starry 重写的路径中保留上游 1.1.17 修复

- HBBR：首个 relay 请求 128 KiB 上限（配对后解除）；30 秒 WebSocket 握手超时与
  64 KiB 缓冲；保留转发 IP 的端口；上游按代际过期等待者（`WaitingPeer`/
  `expire_waiter`）；relay 写入卡住 30 秒超时。
- HBBS：所有 Starry relay 步骤之前先执行 `validate_relay_uuid`/
  `validate_relay_response`；RegisterPeer 与 RegisterPk 的 `MAX_PEER_ID_LEN`
  （Starry 的 `process_register_pk` 曾丢失该检查）；有界的 `record_punch_req` 日志
  （Starry 的 punch-hole 处理仍使用旧的无界写入）；`MAX_MESSAGE_KB` 同时限制
  Secure TCP 和 `/ws/id` 帧；`/ws/id` 升级须在 30 秒内完成并使用 8 KiB 缓冲。

### 修复

- 没有 Starry 配置文件且 `RUST_LOG` 高于 `info` 时，启动时不会初始化 Geo 规则和
  WebSocket Signal：这些调用写在 `log::info!` 参数里，该级别下参数不会被执行。
- 以本地文件发布的 JWKS 原先只在启动时打一次戳，导致 `enforce` 模式的 HBBS 在
  `max_stale_seconds`（默认 1 小时）之后对所有连接报 `key_stale`——即使签发者
  一直健康。现在 HBBS 按刷新周期重读该文件并采纳签发者的戳，且无法解析的
  keyset 绝不会替换正在工作的那一份。
- 中继字段留空（文档推荐配置）的客户端发出的 `RequestRelay` 不带中继地址：
  服务端原先只在 fast_relay 开启时才补地址，于是被控端无处可连，所有需要中继
  的连接都以客户端的 "deadline has elapsed" 失败，而两台 hbbr 的日志里什么都
  没有。现在只要客户端留空就由服务端补齐；fast_relay 接管选路时仍覆盖客户端
  自带的值。
- 中继可达性探测原先只在配置了多于一个中继时才执行，单中继部署的唯一中继可能
  一直不被标记为在线。

### 安全

- lockfile 在 semver 范围内升级 axum 0.5.17、openssl 0.10.82、quick-xml 0.41
  （经 wayland-scanner）、anyhow、bumpalo、rand 0.8.8、crossbeam 与 ahash，并把
  hbb_common 中已停止维护且不健全的 `users` 0.11 换成 API 兼容的 `uzers` 分支
  （RUSTSEC-2023-0040、-2023-0059、-2025-0040）。`cargo audit --deny unsound
  --deny yanked` 通过。

### 移除

- 不再基于上游 checkout 构建，也不再支持上游 1.1.16。

## patch-v1.3.1 — 预览版

完整说明：[`RELEASE-NOTES-patch-v1.3.1.zh-CN.md`](RELEASE-NOTES-patch-v1.3.1.zh-CN.md)

### 新增

- 角色绑定 FastRelayAuthorization 字段 7–12，以及互相独立、默认关闭的 schema v5
  FastCompat/FastMediaV1 策略。
- HBBR AKR1 UDP cookie/bind/forward/rebind 数据面；授权、生命周期、replay、流量、清理
  和认证 telemetry schema 2 均有界。
- Relay Quality decision 和安全普通 GEO/failover 都能得到服务端最终选择的
  FastCompat/FastMedia 授权；客户端永远不能选择签名 Relay。
- Starry Pairing v1、Control Agent pair/adopt/rotate、有界 Relay enrollment 和独立
  `starry-relayctl` 工具。
- 显式容器/原生/DEB 身份持久化布局，以及带 drain 和 90 天证书窗口门禁的无副作用
  schema v5→v4 downgrade 预览/导出。

### 修复

- 仅在完整冻结 Relay Quality 绑定全部匹配时允许 native 初始
  `PunchHoleSent`/`LocalAddr` 的合法 target 来源端口变化；顶层 report/controller route
  仍精确绑定，冲突重复仍拒绝。
- Control Agent 在终止时完成有界 drain，避免诊断容器留下含糊的强制停止状态。
- 生成的 HBBR 测试签名私钥不再进入子进程参数。
- 将锁文件中已撤回的 `chacha20 0.10.1` 替换为未撤回的 `0.10.2`，CI 除 vulnerability
  与 unsound advisory 外也会拒绝 yanked 依赖。

### 兼容性与状态

- Relay Quality v1 protobuf、digest、评分、遥测、迟滞、隐私及 fallback 语义不变。
- 官方客户端、六字段 FastCompat、手工 Agent/Relay 和普通 Native/WSS Relay 保持兼容；
  所有新开关默认关闭。
- 协议级 Akari harness 已针对候选 HBBR 证明双角色转发、可靠回退和同会话自动重入。
  默认关闭新开关的预览版已获批准；真实双客户端 GUI/信令、设备/NAT/故障矩阵及生产
  PKI 门禁通过前仍不得升级为稳定版。

## patch-v1.3.0 — 开发中

完整说明：[`RELEASE-NOTES-patch-v1.3.0.zh-CN.md`](RELEASE-NOTES-patch-v1.3.0.zh-CN.md)

### 新增

- 为 Akari 增加私有且只追加的 protobuf v1 字段，用于 Relay 质量能力协商、候选集、双端
  报告、评分和决定；质量扩展全部使用 100 以上 tag，官方客户端仍以普通
  `relay_server` 为准。
- HBBR 在 TCP/WSS 上响应有界主动探测，回显 nonce，并返回精确 Starry 版本、活动会话、
  容量、当前带宽和 load basis points。
- HBBR 显式协商 `relay_probe_protocol=1` / `relay_load_protocol=1`，HBBS 对 telemetry
  实施新鲜度上限及有界并发 health 探测，legacy fallback 不占用质量候选名额。
- HBBS 综合双端有效 RTT、jitter、loss、可信 Relay load、缺失报告惩罚、对称网段缓存和
  可配置迟滞选出最终 Relay。
- schema v4 `relay_quality` 配置和供 Kessoku 使用的 Control API v1 Relay 质量运行态；
  客户端不会连接 Control Agent。
- allocation 使用独立于清理 TTL 的服务端 report deadline；配置校验证明有序样本可在
  deadline 内完成，并提供稳定 decision reason 与 accepted/late/invalid/binding-mismatch
  聚合计数。
- 默认关闭的 schema v4 `fast_mode` 策略，以及 `RequestRelay`/`RelayResponse` 中只追加的
  tag 64 授权字节。HBBS 仅在鉴权严格允许且最终质量选择完成后签发 `FastCompat`，对授权
  进行来源绑定、有界缓存，并向两端 Akari 发送完全相同的字节。
- Control capability `fast_relay_authorization: 1` 和有界的 `/relays` 签发、复用、送达及
  fail-closed 计数。patch-v1.3.0 始终签发 `allow_fast_media_v1 = false`，不新增 Relay
  UDP 媒体路径。
- 面向 Akari 的 Profile Activation Lease v1：16 字节客户端 activation ID、匹配 Ready
  ACK、32 字节节点本地 route lease，以及 Native UDP/TCP 与 WSS 共用的 route
  generation authority。
- 只允许精确当前 route 的 `DeactivatePeer`、generation-safe 断线清理、45 秒崩溃兜底
  TTL，以及按 peer ID、network identity UUID 和 public key 绑定的每 30 秒最多 12 次
  已验证快速重新注册 burst；HBBR 数据消息保持不变。
- Control capability `profile_activation_lease: 1`、聚合 `/relays` 生命周期/拒绝计数和供
  Kessoku 按实例核对的精确当前 lease `/peers:verify`。

### 兼容性

- schema v1-v3 继续有效；只有 schema v4 显式启用且发起端声明协议 v1 时才进入质量选择。
- 官方客户端继续只接收一个传统 `relay_server`；官方 HBBR 字节转发语义与端口不变。
  官方客户端会忽略未知 tag 64，HBBS 则会清空客户端自行提供的授权字节。
- 官方/legacy HBBR 可列入 `legacy_fallback_relays` 作普通 fallback，但缺少显式能力或新鲜
  load 时绝不进入质量 offer；兼容候选少于两个时不下发 offer，完整保留传统
  Geo/failover。
- Akari 强制 Relay 模式应先执行同一质量能力 PunchHole 预检，再发送 `RequestRelay`；
  未取得 offer 的直接 `RequestRelay` 继续使用传统选择路径。
- 只有 schema v4 同时显式启用极速模式、Relay 质量、连接鉴权和安全信令时才可能签发；
  任一前置条件缺失都不产生授权，并继续标准 Relay 流程。
- 官方注册消息不携带 Profile activation 字段，继续走现有路径。Akari 只有在成功 ACK
  精确回显 activation ID/epoch 且返回合法 lease/generation 后才提交 Profile；因此旧
  服务端会 fail closed 到上一个已提交 Profile。

## patch-v1.2.2 — 2026-08-29

完整说明：[`RELEASE-NOTES-patch-v1.2.2.zh-CN.md`](../archive/releases/RELEASE-NOTES-patch-v1.2.2.zh-CN.md)

### 新增

- 新增私有只读 Control API，按 RustDesk ID 与设备 UUID 精确核对 HBBS 注册表，不返回
  设备资料。
- 为 Kessoku 后台设备发现增加独立、最小权限的服务身份认证。

## patch-v1.2.1 — 2026-08-28

完整说明：[`RELEASE-NOTES-patch-v1.2.1.zh-CN.md`](../archive/releases/RELEASE-NOTES-patch-v1.2.1.zh-CN.md)

### 新增

- Relay 版本上报：从 HBBR WebSocket 握手，经 HBBS 健康探测采集，最终在
  Control API v1 的 Relay 清单中返回。

## patch-v1.2.0 — 2026-08-20

完整说明：[`RELEASE-NOTES-patch-v1.2.0.zh-CN.md`](../archive/releases/RELEASE-NOTES-patch-v1.2.0.zh-CN.md)

### 新增

- schema v3 与严格 Ed25519 连接 JWT 验证；统一覆盖原生 TCP、Secure TCP、WSS 的发起端
  `PunchHoleRequest` 和直接 `RequestRelay`，并提供 `off`、`audit`、`enforce` 模式。
- JWKS 原子 last-known-good 更新、有界 token/introspection 缓存、配置远程 JWKS 或
  introspection 时强制使用排他 CA 的 mTLS，以及 key 过期、依赖故障或 subject 异常时
  fail closed。
- 不可变 Relay runtime snapshot 与返回结构化 decision trace 的无副作用分配模拟。
- 有 frame 上限、仅 loopback 的结构化本地控制协议。
- 可选 Linux `starry-control-agent`：强制 mTLS、URI SAN 白名单、短期细粒度 service
  JWT、固定 Control API v1，并默认采用安全只读 profile。
- 带精确字节 ETag、持久审计、revision history、原子写入、runtime activation ack 与不确定
  状态阻断恢复的乐观并发、幂等 plan/apply/rollback 配置事务。
- 版本化 OpenAPI 3.1、JSON/UI Schema、JWT/协议 fixtures、Control Agent
  Compose/systemd/DEB 制品及安全集成测试。

### 修复

- Relay 探测结果或就绪状态变化时推进 `health_snapshot_id`，使 Relay inventory 与同次
  allocation simulation 能唯一标识实际健康快照，而不是只标识健康配置 generation。
- 将远程 JWKS/introspection mTLS HTTP pool 的 idle lifetime 限制为 15 秒，避免重用已被
  Kessoku 较短 server idle timeout 关闭的 keep-alive 连接，并保留原有 last-known-good/
  fail-closed 行为。

### 依赖与构建完整性

- 审核后的 Cargo 依赖图已锁定；在执行任何 locked metadata、测试或 release build 前，
  workflow 会把同一锁文件复制到 patched upstream tree，并记录 upstream 与 `hbb_common`
  的精确源码提交。
- 使用 bundled SQLite 的 `tokio-rusqlite` 替换旧 SQLx/deadpool 路径，删除未固定的 Git
  `reqwest` 输入，并更新 TLS、WebSocket、JWT、protobuf 与 CLI 依赖路径。
- 固定依赖图的 RustSec 审计为 0 vulnerability、0 unsound、0 yanked；仍披露一个来自
  upstream core 的 `sodiumoxide 0.2.7` unmaintained warning，须在发布风险审核中明确接受。
- 候选 CI 将 Rust、cross、cross image、advisory 数据、扫描器、base image 和全部 Action
  固定到审核后的不可变输入；Debian 包连续构建两次并逐字节比较后才可能批准发布。

### 兼容性与安全性

- schema v1/v2 继续有效；只有 schema v3 显式开启连接认证，或部署层 `--must-login`
  floor 要求时才进入 enforce。
- 无效 reload 保留当前 last-known-good generation，不再清空 Starry runtime state。
- 认证复用既有 RustDesk protobuf 字段，未修改任何 `.proto`。UDP 连接发起继续
  unsupported，且不得触发分配。
- 官方 1.1.16 的原生被控端注册/心跳仍走 UDP；TCP/Secure TCP 覆盖的是控制端连接发起。
  需要禁用 UDP 的被控端必须使用 WSS 注册，不能把 upstream TCP `NOT_SUPPORT` 当成认证
  回归或 TCP-only 注册能力。
- HBBR 和账户/API 职责不变；Control Agent 是独立管理组件，不是账户 API 或 HBBR proxy。
- patch-v1.2.0 的可写 Control Agent 事务只在 Linux 上支持并纳入发布测试；不发布
  Windows Agent 制品。

## patch-v1.1.0

完整说明：[`RELEASE-NOTES-patch-v1.1.0.zh-CN.md`](../archive/releases/RELEASE-NOTES-patch-v1.1.0.zh-CN.md)

### 新增

- 与 RustDesk 客户端身份注册兼容的可选持久 `/ws/id` 信令。
- WSS↔WSS 与 WSS↔原生信令；任一端使用 WebSocket 时明确只走 Relay。
- 针对 `native`、`wss`、`mixed` 会话的传输感知 Relay 选择。
- 验证证书链和域名的 `wss://.../ws/relay` 健康探测。
- schema v2：可信代理 CIDR、精确 Origin 白名单、session/队列/限速与 Relay endpoint 完整覆盖。
- `websocket-status` 管理命令。
- `test-geo <IP_A> <IP_B> [native|wss|mixed]` 可选传输参数。
- 真实进程 WebSocket 与官方 HBBR 混合传输集成测试。

### 兼容性

- schema v1 继续有效，并保持 WebSocket Signal 关闭。
- 客户端关闭 WebSocket 时，默认行为仍是原生信令/P2P。
- 本 patch 不修改 HBBR。
- 回滚到 patch-v1.0.0 时必须恢复 schema v1 配置。

## patch-v1.0.0

### 新增

- 外部 Starry YAML 配置与严格整体验证；无效时安全回退到上游行为。
- 根据连接双方国家、城市、子区域、GeoNames ID、ASN 与 ISP 有序选择 Relay。
- `/`（OR）、`+`（AND）、括号和引号值组成的嵌套 GEO 表达式。
- 对称与方向敏感的双端规则。
- MMDB 定时下载、体积/标记/可读性校验、原子替换与最后可用版本保留。
- 原生 `21116/TCP` 上兼容 RustDesk 的 HBBS Secure TCP 协商与 Secretbox
  传输，包括认证失败关闭和合法明文首帧兼容回退。
- 本机配置重载、Relay 列表、Geo 重载和双 IP 规则测试命令。

### 兼容性

- Starry 配置为空、无法解析或验证失败时，HBBS 使用官方命令行行为。
- 没有规则命中、所需 MMDB 缺失或规则 Relay 不在线时，会继续后续规则并最终进入官方选择逻辑。
- overlay 仅修改 HBBS。

## 版本规则

- `X`：不兼容的配置/行为变更，或新的重大功能族。
- `Y`：向后兼容的功能版本。
- `Z`：当前 patch 线的紧急修复。
- 锁定的官方 RustDesk Server 版本变化时，即使 Starry patch 版本不变，完整版本前缀也会变化。

修改任一部分前请阅读
[`版本升级与回滚`](https://github.com/q1ngyang/rustdesk-server-starry/wiki/ZH-CN-Upgrade-and-Rollback)。
