# ADR：归档 Akari 扩展（FND-03）

状态：盘点完成，尚未开始提取
[English](ADR-AKARI-ARCHIVE.md) | 简体中文

## 待记录的决策

是否、以及按什么顺序，把客户端扩展协议路径（`relay_quality` 主动探测、
`fast_relay` 授权、`fast_media_relay` UDP 数据面、`profile_activation` 租约）
从主线移除，同时保留它们目前与之共用代码的通用服务端机制。

本文是 FND-04 在任何人删模块之前所需的依赖清单。它是针对 `d9ede12` 的只读分析；
没有任何东西被归档或移除。

## 为什么这件事需要一份清单

路线图自己给出了理由：这些扩展模块不是叶子。其中四处耦合是"即使没有任何扩展
客户端也照常工作"的功能的承重墙：

| 耦合 | 位置 | 直接删模块会破坏什么 |
| --- | --- | --- |
| 遥测新鲜度 | `relay_observer.rs:320-325`、`relay_health.rs:986-989`、`relay_health.rs:879` | `max_telemetry_age_seconds` 住在 `RelayQualityConfig` 里。中继健康的过期判定与 `relay_observer::snapshot()` 都读它。删掉 `relay_quality` 会一并删掉通用中继池所用的过期上界。 |
| 遥测 schema | `relay_server.rs:69` | `STARRY_RELAY_TELEMETRY_SCHEMA` 的**定义**是 `fast_media_relay::TELEMETRY_SCHEMA_VERSION`。UDP 数据面一走，HBBR 的认证遥测版本号就没了。 |
| 观测快照 | `relay_observer.rs:127-129, 659-661` | 快照结构体内嵌 `relay_quality`、`fast_relay`、`profile_activation` 三个运行时快照，由 `control_agent` 与 `/healthz` 消费。 |
| 中继选择 | `rendezvous_server.rs:1310` | `server_selects_relay(.., fast_relay::enabled())` 决定是否覆盖客户端自带的中继。留空那半是通用的、必须留下；只有 fast_relay 覆盖那半属扩展。 |

## 官方客户端实际会走到哪

每个扩展都受配置门控，关闭时返回"传统"答案，因此未修改的 RustDesk 客户端
永远不会进入扩展路径：

| 模块 | 行数 | 门控 | 官方客户端行为 |
| --- | --- | --- | --- |
| `relay_quality` | 2630 | `config.relay_quality.enabled`，**默认 false**（`starry_config.rs:349`） | `select_for_request` 返回 `RequestResolution::Legacy` |
| `fast_relay` | 806 | `fast_compat_enabled \|\| fast_media_v1_enabled`，**两者默认 false** | `enabled()` 为假；不签授权、不附带 |
| `fast_media_relay` | 1497 | `Config::from_env` 需要 `STARRY_RELAY_FAST_MEDIA_UDP_PORT` **且**有公网端点 | `spawn()` 立即返回；无 UDP 监听 |
| `profile_activation` | 1343 | 无门控，但官方客户端发送空的 `activation_id`/`activation_epoch` | `begin_registration` 产出未跟踪的 claim，注册照旧 |

`profile_activation` 是唯一无条件运行的，所以它有 29 个调用点。下面清单说明它
是官方注册路径的**严格超集**，而非替代。

## 生产实况

线上部署（`149.104.1.168`，`starry-hbbr` 在 `175.178.125.23`）一个都没开：

- `config.yaml` 里没有 `relay_quality.enabled`（默认 false）
- 没有 `fast_mode` 段（两个开关均默认 false）
- 两个 systemd unit 里都没有 `STARRY_RELAY_FAST_MEDIA_*`
- local-control 的 `relays` 输出报 `fast_relay.disabled = 1`

因此归档不会改变正在运行的服务器的行为。做它的理由是可维护面积，而非用户可见
变化；而急着做的反理由是上面那四处耦合。

## 耦合清单

### `relay_quality` —— 2630 行，`rendezvous_server` 内 23 个调用点

两个截然不同的半边：

- **扩展协议**（归档）：`RelayProbeRequest`/`Response`、
  `RelayQualityOffer`/`Decision`/`Cancel`、阶段报告、`select_for_request` 的分配
  状态、探测调度、`create_offer`、`response_context`。
- **可复用算法**（提取）：评分归一化、滞回、TTL 有界缓存、容量上界，以及作为
  **通用**遥测旋钮的 `max_telemetry_age_seconds`。

提取目标是一个 `telemetry` 模块，持有新鲜度策略，从而让 `relay_observer` 与
`relay_health` 不再伸手进 `RelayQualityConfig`。

### `fast_relay` —— 806 行，6 个调用点

- **扩展协议**（归档）：`authorization_for_request`、`authorization_for_response`、
  `selected_relay_for_response`、授权签名。
- **通用**（保留）：`server_selects_relay` 中"客户端留空即由服务端补"的行为。
  `fast_relay::enabled()` 目前同时被当作"服务端覆盖客户端自带中继"的开关；若模块
  下线，这个开关必须作为独立配置位存活，否则从未启用 fast_relay 的部署的中继选择
  会变。

### `fast_media_relay` —— 1497 行，`relay_server` 内 4 个调用点

- **扩展数据面**（归档）：AKR1 UDP 监听、授权、绑定、重放限制、限速。
- **通用**（保留）：遥测 schema 版本。应把 `TELEMETRY_SCHEMA_VERSION` 迁入遥测
  模块，而不是让 HBBR 的 schema 派生自 UDP 模块。

### `profile_activation` —— 1343 行，29 个调用点

路线图标注 `ARCHIVE + EXTRACT`，调用点印证了原因：它坐在 `RegisterPeer`、
`RegisterPk`、`DeactivatePeer`、WebSocket 路由与 TCP 心跳上——全是标准路径。

- **私有协议**（归档）：`activation_epoch`/`activation_id`/`route_lease` 处理、
  ready-ACK 计数、租约续期、`next_route_generation`。
- **要保留的通用安全语义**：注册突发限流（`BURST_LIMIT`/`BURST_WINDOW`）、
  按 peer 的路由代际、路由变更拒绝、断开时的陈旧路由清理。

这是最大也最危险的一项。移除它意味着在注册路径里重新实现通用子集，并以现有 e2e
（`tests/connection_auth_transport.rs`、`tests/websocket_signal.rs`）作为回归门禁。

### Protobuf 表面

| 消息 | 扩展字段 |
| --- | --- |
| `PunchHoleRequest` | `relay_quality_protocol = 100` |
| `PunchHole` / `PunchHoleSent` | `relay_quality_offer = 100` |
| `RequestRelay` | `relay_quality_report = 100`、`relay_quality_decision = 101`、`relay_quality_allocation_id = 102`、`fast_relay_authorization = 64` |
| `RelayResponse` | `relay_quality_offer = 100`、`relay_quality_peer_report = 101`、`relay_quality_decision = 102` |
| `RendezvousMessage` | `relay_quality_stage_{report,offer,decision}` = 102/103/104、`relay_quality_cancel = 105`、`deactivate_peer{,_response}` = 62/63 |
| `RegisterPeer`（尾部） | `route_generation = 60`、`activation_epoch = 61`、`route_lease = 62`、`activation_id = 63` |
| `RegisterPk`（尾部） | `activation_epoch = 61`、`activation_id = 63` |
| `DeactivatePeer` | `activation_epoch = 3`、`activation_id = 4`、`route_lease = 5`、`route_generation = 6` |

注意 `DeactivatePeer` 的字段是 3–6，是这条上游未定义消息内部的低位编号，而非高位
标签。上游在共享消息里的最高 tag 是 29，故 60+ 与 100+ 是空闲的——但
`DeactivatePeer` 这条消息本身就是扩展，归档它意味着整条消息变为惰性，而不只是
其中若干字段。

按路线图要求：不要重编号，也不要复用已部署客户端可能仍在发送的 tag。归档意味着
服务端不再**据其行事**，而不是这些线号可以重新分配。

## 建议的执行顺序

路线图自己的顺序（FND-03 → FND-04 → FND-05）是对的，但风险集中在
`profile_activation`，因此提取应当分阶段：安全的工作先落地，危险的工作放在回归
门禁之后。

1. **把遥测策略从 `RelayQualityConfig` 提出来**，独立成模块。纯重构、无线上变化；
   `relay_observer` 与 `relay_health` 不再依赖一个将被归档的模块。用现有中继测试
   验证。
2. **把遥测 schema 常量与 `fast_media_relay` 解耦**。
3. **拆开 `server_selects_relay` 的两个理由**：客户端留空（通用）vs fast_relay
   覆盖（扩展）。行为必须完全不变；`tests/relay_selection.rs` 已覆盖通用那半。
4. **归档 `relay_quality` 与 `fast_relay` 的线上协议**，放进默认为关的配置开关后，
   保留算法。
5. **归档 `fast_media_relay`**，待无人再从它派生之后。
6. **`profile_activation` 放最后**，单独一个 PR：把通用子集提取进注册路径，用完整
   传输 e2e 证明，然后移除租约协议。

第 1–3 步是不改变行为的重构，可凭审查通过。第 4–6 步删代码，需要路线图为 FND-05
所要求的 e2e 证据。

## 本文不决定什么

- 是否归档。那是产品决策；本文只记录代价。
- 归档 ref 的命名、是否打 tag。路线图把命名留给维护者。
- 任何生产变更。这里没有任何东西被部署或已排期。

## 给执行者的验证备注

盘点过程中发现两个坑，均已写进测试：

- 单条目的中继池原先从不做健康探测（`7290f29`），因此中继行为必须用真实的
  `tests/relay_selection.rs` 夹具验证，不能靠读代码。
- 审计 writer 是进程级 `OnceLock`；谁先产出事件就固定了输出目录。审计断言不能
  跨同一二进制里的两个测试。
