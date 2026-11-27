# 官方客户端代码分析 —— 未实现功能与优化空间

状态：分析完成（2026-11-28）
分析对象：`github.com/rustdesk/rustdesk` @ `104ef2a`（master）
分析方法：完整 clone（非抽样），枚举全部 `/api/` 路径与 rendezvous 消息类型，逐端点读取请求/响应契约

[English](CLIENT-GAP-ANALYSIS.md) | 简体中文

## 一、方法与边界

**做了什么**：`git clone` 完整客户端仓库，对 `src/`（Rust，含 `hbbs_http` 全部 2002 行）与
`flutter/lib/`（142 个 Dart 文件）做全量枚举；每个端点回到调用点读真实契约，不看文档。

**没做什么**：未分析 Linux/Windows 平台层私有 API（`/api/winuser/...` 那批是 Windows SDK
函数名在文档链接里的误匹配，不是 HTTP 端点）；未分析 Akari 私有分支。

**一个必须先说的结论**：客户端对每个可选端点都用 **404 探测能力**。`/api/ab/personal`
返回 404 → 自动降级到 legacy 地址簿；`/api/ab/settings` 返回 404 → 认为服务器不支持共享
地址簿。这意味着我们现在的"未实现"是**安全的**——客户端不会报错，只是功能不可见。
同样意味着每补一个端点，客户端侧无需任何改动即可点亮对应 UI。

## 二、端点全量对照

图例：✅ 已实现　⬜ 未实现（返回 404，客户端自动降级）　➖ 不适用（Pro 云服务专用）

### 2.1 认证与服务端签发（已完整）

| 端点 | 方法 | 状态 | 备注 |
| --- | --- | --- | --- |
| `/api/login` | POST | ✅ | access_token 即连接凭据 |
| `/api/login-options` | GET | ✅ | 数组；`common-oidc/` 已支持 |
| `/api/currentUser` | GET/POST | ✅ | 大写 U |
| `/api/logout` | POST | ✅ | |
| `/api/oidc/auth` | POST | ✅ | |
| `/api/oidc/auth-query` | GET | ✅ | `{"body":...}` 包裹 |
| `/oidc/callback` | GET | ✅ | 浏览器半程 |
| `/api/connection-token` | POST | ✅ | 客户端实际不调用（自查） |
| `/api/introspect` | POST | ✅ | RFC 7662，hbbs 用 |

### 2.2 地址簿 —— legacy（1 个端点，已实现）

| 端点 | 方法 | 状态 |
| --- | --- | --- |
| `/api/ab` | GET / POST | ✅ 整文档 `{tags,peers,tag_colors}` |

**这是当前唯一被点亮的地址簿形态。**

### 2.3 地址簿 —— 非 legacy（10 个端点，全部未实现）

客户端先 `POST /api/ab/personal`；**404 即整体退回 legacy**。所以这 10 个要么全做，
要么不做。逐端点契约（`flutter/lib/models/ab_model.dart`）：

| 端点 | 方法 | 契约 | 状态 |
| --- | --- | --- | --- |
| `/api/ab/personal` | POST | → `{guid}`。个人地址簿的 guid | ⬜ |
| `/api/ab/settings` | POST | → `{max_peer_one_ab}`。单簿 peer 上限 | ⬜ |
| `/api/ab/shared/profiles` | POST | `?current=&pageSize=` → `{total,data:[AbProfile]}` 分页 | ⬜ |
| `/api/ab/peers` | POST | `?current=&pageSize=&ab=<guid>` → `{total,data:[Peer]}` 分页 | ⬜ |
| `/api/ab/tags/{guid}` | POST | → `[AbTag]` 数组（非信封） | ⬜ |
| `/api/ab/peer/add/{guid}` | POST | `{id,alias,hash,tags,...}` 逐个添加 | ⬜ |
| `/api/ab/peer/update/{guid}` | PUT | `{id,tags}` / `{id,alias}` / `{id,note}` / `{id,hash}` | ⬜ |
| `/api/ab/peer/{guid}` | DELETE | `["id1","id2"]` 裸数组 | ⬜ |
| `/api/ab/tag/add/{guid}` | POST | `{name,color}` 逐个添加 | ⬜ |
| `/api/ab/tag/rename/{guid}` | PUT | `{old,new}` | ⬜ |
| `/api/ab/tag/update/{guid}` | PUT | `{name,color}` | ⬜ |
| `/api/ab/tag/{guid}` | DELETE | `["tag1"]` 裸数组 | ⬜ |

**价值判断**：非 legacy 形态提供**共享地址簿**（多人共用一本）与**分页**。legacy 只有
一账号一本、无共享。做这一组等于补齐 Pro 的 "Address book sharing"。

**风险**：`peer/update` 有四种语义共用同一路径，靠 body 字段区分；`hash` 是客户端生成的
密码哈希，服务端必须原样存储（我们已确立此原则）。

### 2.4 设备组与用户（3 个端点，全部未实现）

| 端点 | 方法 | 契约 | 状态 |
| --- | --- | --- | --- |
| `/api/device-group/accessible` | GET | `?current=&pageSize=` → `{total,data:[{name,...}]}` | ⬜ |
| `/api/users` | GET | `?current=&pageSize=&accessible=&status=1` → `{total,data:[UserPayload]}` | ⬜ |
| `/api/peers` | GET | 同上 → `{total,data:[Peer]}` | ⬜ |

**注意**：`/api/users` 需要 `is_admin` 或返回 `{"error":"Admin required!"}`；客户端把
`ambiguous column name: status` 当作"服务器版本过旧"提示。这两个错误串是契约的一部分。

**价值**：设备组是客户端"分组视图"的数据源。没有它，客户端只显示平铺的设备列表。
同时 `/api/peers` 是 `/api/ab/peers` 的服务端全量版本（跨账号，管理员视角）。

### 2.5 策略下发（3 个端点，全部未实现）—— **本次分析最重要的发现**

客户端每 3 秒轮询 `/api/heartbeat`，响应里可以携带 `strategy`：

| 端点 | 方法 | 契约 | 状态 |
| --- | --- | --- | --- |
| `/api/heartbeat` | POST | `{id,uuid,ver,conns,modified_at}` → `{sysinfo?,disconnect?,strategy?,modified_at?}` | ⬜ |
| `/api/sysinfo` | POST | 设备信息 → 文本 `SYSINFO_UPDATED` / `ID_NOT_FOUND` | ⬜ |
| `/api/sysinfo_ver` | POST | → 版本串（用于跳过无变化的上传） | ⬜ |

`strategy` 的形状（`StrategyOptions`）：

```json
{"strategy":{"config_options":{"key":"value"},"extra":{"k":"v"}}}
```

`config_options` 直接落到客户端 `Config::set_options`，即**服务端可以远程改客户端设置**。
`handle_config_options` 有拒绝路径（部分选项受固定策略保护），客户端会记录
`Strategy update rejected`。

**这条链与我们已有的 `STARRY_STRATEGY_FILE` 完全不是一回事**：我们的策略引擎在 hbbs 侧
决定"这次连接允不允许"；客户端的 strategy 是"客户端自己怎么配置"。两者互补，不重复。

**价值**：这是 Pro 的 "Strategy/安全设置同步" 卖点。补齐后，运维可在服务端统一下发
（如禁用某些传输、固定中继、强制密码策略），无需逐台配置。

**风险（高）**：`config_options` 是**远程改客户端配置**。必须：① 只允许白名单键；
② 与连接认证解耦（未登录不下发）；③ 下发内容签名或依赖已建立的 JWT。否则这是提权面。

### 2.6 审计与记录（3 个端点，全部未实现）

| 端点 | 方法 | 契约 | 状态 |
| --- | --- | --- | --- |
| `/api/audit/{typ}` | POST | 客户端**上传**审计事件到服务器 | ⬜ |
| `/api/audit` | PUT | `{guid,note}` 给一次会话加备注 | ⬜ |
| `/api/record` | POST | `?type=new\|frame&file=` 会话录像分片上传 | ⬜ |

**关键区分**：我们的 `STARRY_AUDIT_DIR` 是**服务端**审计（谁连了谁、策略判定）。
`/api/audit/{typ}` 是**客户端**审计（用户在自己机器上做了什么，比如启动/退出）。
两者是不同数据源，不能互相替代。

**`/api/record` 是隐私敏感项**：会话录像上传，涉及画面内容。必须默认关闭、显式授权、
明确存储位置与保留期。

### 2.7 设备注册与授权（4 个端点，部分相关）

| 端点 | 方法 | 契约 | 状态 |
| --- | --- | --- | --- |
| `/api/devices/deploy` | POST | `Bearer token` + `{id,uuid,pk}` → `{result:"OK"}` | ⬜ |
| `/api/devices/cli` | POST | 同上 + 各种 `*_name` 字段 | ⬜ |
| `/api/switch-grant` | POST | Ed25519 签名的设备切换授权 `{id,switch_code_verifier,timestamp,signature}` | ⬜ |
| `/api/heartbeat`（同上） | POST | 也承载 `disconnect` 指令 | ⬜ |

`/api/devices/deploy` 是**预配置部署**：管理员签发 token，新设备用它注册并绑定 ID。
与我们已有的 `starry-client-config`（生成导入串）是同一目标的两条路——我们生成静态
配置，它做在线注册。补齐后可实现"一次性 token，设备自助上线"。

`/api/switch-grant` 用设备私钥签名，服务端校验。与我们的 JWT 体系并行，属于设备身份层。

## 三、协议层（rendezvous）对照

`libs/hbb_common/protos/rendezvous.proto` 的 19 个 union 成员中：

| 消息 | 服务端 | 说明 |
| --- | --- | --- |
| `register_peer` / `register_pk` / `register_peer_response` | ✅ | |
| `punch_hole_request` / `punch_hole` / `punch_hole_sent` / `punch_hole_response` | ✅ | |
| `request_relay` / `relay_response` | ✅ | |
| `fetch_local_addr` / `local_addr` | ✅ | 经 dispatch 分支 |
| `configure_update` | ✅ | |
| `register_pk` 等 | ✅ | |
| `software_update` | ✅ | |
| `test_nat_request` / `test_nat_response` | ✅ | |
| `online_request` / `online_response` | ✅ | |
| `key_exchange` | ✅ | `secure_tcp.rs` |
| **`http_proxy_request` / `http_proxy_response`** | ⬜ | 见下 |
| **`health_check` (`hc`)** | ⬜ | 见下 |
| **`peer_discovery`** | ⬜ | LAN 发现，见下 |
| `relay_probe_*` / `relay_quality_*` | ✅ | Starry 自有扩展 |

### 3.1 `HttpProxyRequest` —— 内网穿透 API 代理

客户端在 `USE_RAW_TCP_FOR_API=Y` 且非 WS 时，会把 API 请求**经 hbbs 的 TCP 连接代理**发给
API 服务器（`src/common.rs:1469`）。用途：客户端只能连 hbbs 端口（如只开 21116/21117
的受限网络）时，仍能访问 `/api/*`。

**价值**：受限网络下的可用性。**风险**：hbbs 变成任意 HTTP 代理——必须严格白名单
（只允许到配置的 API host、只允许 `/api/` 前缀、限制响应大小、禁止重定向）。

### 3.2 `HealthCheck` —— 会话期保活

`src/client.rs:5296`：连接期间定期发 `hc{token}`。我们未实现 → 客户端该路径会等超时。
影响：长连接的保活从"服务端推"变成"客户端等超时重试"。**应确认是否真的影响体验**。

### 3.3 `PeerDiscovery` —— LAN 直连发现

`src/lan.rs`：同网段设备互发现，用于 LAN 直连（不经中继）。这是纯 P2P 辅助，服务器
不参与也能用（多播）。**优先级最低**，但若要做"同网段优先直连"，这是入口。

## 四、优化空间（已实现部分的改进）

按"用户可感知"排序：

| # | 位置 | 现状 | 改进 | 收益 |
| --- | --- | --- | --- | --- |
| O1 | `/api/ab` legacy | 整文档 4 MiB 上限，后写覆盖 | 文档级 ETag / `If-Match`，冲突时返回 409 而非静默覆盖 | 两台设备交替推送不再互相吞数据 |
| O2 | `/api/ab` legacy | 单行 `document text` | 拆 `ab_peers` 表 + 索引，供未来 `/api/ab/peers` 复用 | 为 2.3 打地基，避免二次迁移 |
| O3 | `/api/login` | 仅密码 + OIDC | `tfa_type`/`secret` 字段已返回但恒空 | 补齐 TOTP 才真正支持两步验证 |
| O4 | 全部 API | 无请求 ID / 结构化日志 | 加 `X-Request-Id` 与耗时日志 | 线上排障从"猜"变"查" |
| O5 | `/api/ab` | 4 MiB 读入内存后校验 JSON | 流式校验或先查 `Content-Length` | 大文档不再双倍占用 |
| O6 | `oidc_links` | 按 `(provider,subject)` 绑定 | 加 `email` 变更审计 | 身份漂移可追溯 |
| O7 | `/api/login-options` | 无缓存头 | 加 `Cache-Control` | 减少客户端每次启动的请求 |
| O8 | hbbs 审计 | 逐行 flush（崩溃一致性） | 批量 + fsync 间隔可配 | 高并发下减少 IOPS（当前刻意不改，需实测） |

**明确不建议做的优化**：给 `/api/ab` 加服务端加密。文档已含客户端生成的密码哈希，
服务端加密只是把密钥管理问题挪个位置，且会破坏"客户端拥有形状"的契约。

## 五、明确不做（记录理由，避免反复讨论）

| 项 | 理由 |
| --- | --- |
| `/api/winuser/*` 等 | 不是 HTTP 端点，是 Windows SDK 函数名 |
| Akari 私有协议（`relay_quality_*` 之外的 AKR1） | 官方客户端不支持，已冻结 |
| 自建 Web 客户端 | 客户端用官方 Flutter，无此需求；竞品做 Web 端是因为它们没有官方客户端 |
| 账号体系重造（OIDC 之外） | 已走 OIDC + 本地密码；LDAP/TOTP 见计划表 |

## 六、结论

**已实现**：认证闭环（密码 + OIDC）、legacy 地址簿、中继选路、策略引擎（hbbs 侧）、
审计、运维端点。这些覆盖了"能连上、连得稳、可观测"。

**最大缺口按价值排序**：
1. **`/api/heartbeat` 策略下发** —— 唯一能"远程改客户端配置"的通道，Pro 核心卖点
2. **非 legacy 地址簿（10 端点）** —— 共享地址簿，Pro 的 Address book sharing
3. **`/api/users` + `/api/peers` + `/api/device-group`** —— 分组视图，管理界面基础
4. **`/api/devices/deploy`** —— 设备自助上线
5. **`/api/record`** —— 会话录像（隐私敏感，需先有治理方案）
6. **`HttpProxyRequest`** —— 受限网络可用性

**最需要警惕的一项**：`/api/heartbeat` 的 `config_options` 是远程配置下发，安全边界
必须先定，代码后写。
