# 客户端 API 端点 —— Starry 现在提供什么

状态：已实现（2026-11-28）
配套文档：[客户端差距分析](CLIENT-GAP-ANALYSIS.zh-CN.md)

[English](CLIENT-API-ENDPOINTS.md) | 简体中文

本文所有端点都是按客户端自身调用点上的契约实现的，且每个端点都有 e2e 测试
（`tests/api_endpoints.rs`）驱动真实 `starry-api` 二进制走 HTTP。

## 地址簿（结构化形态）

客户端先 POST `/api/ab/personal`，只有收到 **404** 才退回 legacy 单文档形态，
因此这一组是全有或全无。

| Endpoint | Method | Body | Answer |
| --- | --- | --- | --- |
| `/api/ab/personal` | POST | empty | `{guid}` |
| `/api/ab/settings` | POST | empty | `{max_peer_one_ab}` |
| `/api/ab/shared/profiles` | POST | empty, `?current=&pageSize=` | `{total, data:[AbProfile]}` |
| `/api/ab/peers` | POST | empty, `?current=&pageSize=&ab=` | `{total, data:[Peer]}` |
| `/api/ab/tags/{guid}` | POST | empty | `[AbTag]` — bare array |
| `/api/ab/peer/add/{guid}` | POST | `Peer` | `null` |
| `/api/ab/peer/update/{guid}` | PUT | `{id, tags\|alias\|note\|hash\|password}` | `null` |
| `/api/ab/peer/{guid}` | DELETE | `["id","id"]` — bare array | `null` |
| `/api/ab/tag/add/{guid}` | POST | `{name, color}` | `null` |
| `/api/ab/tag/rename/{guid}` | PUT | `{old, new}` | `null` |
| `/api/ab/tag/update/{guid}` | PUT | `{name, color}` | `null` |
| `/api/ab/tag/{guid}` | DELETE | `["tag"]` — bare array | `null` |

承重的线上细节：

- 那些「空」body 是带 `Content-Length: 0` 的 POST。服务端把缺失 body 视为合法；
  在此处强制要求 JSON 会打断客户端。
- `Peer` 有 16 个字段，且 `forceAlwaysRelay` 是**字符串**（`"true"`/`"false"`），
  因为客户端 `toJson` 对 bool 调了 `toString()`。
- `total` 是**未分页**的总数。客户端循环条件是 `while current * pageSize < total`，
  报页长会静默截断列表。
- `rename` 在同一个事务里重写每个 peer 的标签数组，否则客户端会显示已不存在的标签。
- `hash` 原样存储。它是客户端生成的密码哈希，服务端绝不解释它。

## 设备目录

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/device-group/accessible` | GET | `{total, data:[{name}]}` |
| `/api/users` | GET | `{total, data:[UserPayload]}` — admin only |
| `/api/peers` | GET | `{total, data:[Peer]}` — admin only |

非 admin 访问 `/api/users` 会得到字面量 `{"error":"Admin required!"}`。客户端靠
比较该字符串来选择提示语。

`/api/peers` 目前返回空页：设备注册表在 rendezvous 数据库里，而该端点读的是 API
数据库。空页是诚实的答案而非 404，客户端因此渲染「无设备」而不是报错。

## 心跳与客户端策略

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/heartbeat` | POST | `{sysinfo?, disconnect?, strategy?, modified_at}` |
| `/api/sysinfo` | POST | text `SYSINFO_UPDATED` / `ID_NOT_FOUND` |
| `/api/sysinfo_ver` | POST | the server version string |

`strategy.config_options` 会进入客户端的 `Config::set_options`。白名单与四条规则见
[客户端策略安全边界](CLIENT-STRATEGY-SECURITY.zh-CN.md)；那份文档是约束性的，本表
只描述传输。

`modified_at` 携带的是**存储的**时间戳，不是客户端的回显。客户端会保存收到的值并
回传；直接回显会让未变化的策略在每次轮询时都显得是新的。

## 设备自助上线

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/devices/deploy` | POST `Bearer <token>` `{id, uuid, pk}` | `{"result": "OK"\|"NOT_ENABLED"\|"INVALID_INPUT"\|"ID_TAKEN"}` |

这就是客户端的整个闭集；其他任何值都会变成用户可见的错误。令牌一次性、有时限，
且只以 SHA-256 指纹存储。对已存在的 id 用不同密钥二次上线会得到 `ID_TAKEN`，
因此令牌无法劫持设备。

把 `STARRY_ENROLMENT_FILE` 指向一个存在的文件即启用。用
`POST /api/admin/enrolment-token` 签发令牌。

## 客户端审计与录像

| Endpoint | Method | Answer |
| --- | --- | --- |
| `/api/audit/{typ}` | POST | `null` |
| `/api/audit` | PUT `{guid, note}` | `null` |
| `/api/record?type=new\|frame&file=` | POST | `null` |

两者**默认关闭**，启用前返回 `501 NotEnabled`
（`STARRY_CLIENT_AUDIT_FILE`、`STARRY_RECORDING_FILE`）。

客户端审计存于独立表，绝不与服务端审计混在一起。客户端可以伪造任何事件，因此客户端
审计仅供参考：可读，永不作判定依据。录像只统计分片字节数，不把画面内容写进元数据
数据库——那不是放兆字节数据的地方。

## 运维接口

客户端不使用。加它是因为否则运维（以及测试）要手写 `client_strategies` 与 `user_totp`
行，等于每个调用方都重新实现一遍密钥编码。

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/api/admin/client-strategy` | GET / PUT | read or replace what would be delivered |
| `/api/admin/totp` | POST `{secret?}` | enrol a second factor, returns `otpauth://` |
| `/api/admin/totp` | DELETE | remove the second factor |
| `/api/admin/enrolment-token` | POST | mint a one-time device token |
| `/api/admin/disconnect/{peer_id}` | POST `{ids}` | queue a session teardown |

全部要求管理员 Bearer 令牌。

## 协议层补充

- **`HealthCheck`（`hc`）** 现在回一个空帧，这正是客户端保活循环期望的。没有它，
  连接会一直等到 `keep_alive * 1.5` 超时后断开。
- **`HttpProxyRequest`** 走白名单且默认关闭（`STARRY_HTTP_PROXY_ALLOW`）：主机精确
  匹配、仅 `/api/` 路径、仅 `GET`/`POST`，且点段、重复斜杠、反斜杠与 `%2e`
  一律拒绝而不做解析。
- **`PeerDiscovery`** 无需服务端代码：它是对端之间的多播。

## 门禁

`tests/api_endpoints.rs`，13 个测试跑在真实二进制上：
结构化地址簿存在且幂等、peer 16 个字段全部往返、标签重命名传导到 peer、未认证调用
返回 401、`/api/users` 返回管理员错误串、未认证心跳不携带策略、已认证心跳通过白名单
且遵守 `modified_at`、审计与录像默认关闭、上线默认 `NOT_ENABLED`、上线一次性且
`ID_TAKEN` 生效、TOTP 两步且句柄不可伪造且验证码一次性。

变异验证三项：去掉白名单会让心跳测试失败并点名泄漏的键；允许复用已用令牌会让上线
测试失败；接受重放的 TOTP 时间步会同时让单测与 e2e 失败。
