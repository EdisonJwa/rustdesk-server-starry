# 开发计划表 — 基于官方客户端代码分析

状态：计划（2026-11-28）
依据：[客户端代码分析](CLIENT-GAP-ANALYSIS.zh-CN.md)（rustdesk @ `104ef2a`）

[English](DEVELOPMENT-PLAN.md) | 简体中文

## 阅读方式

- **优先级**：P0 用户可感知的缺失 / P1 补齐 Pro 核心卖点 / P2 增强 / P3 可选
- **工作量**：S（≤1 天）/ M（2–4 天）/ L（1–2 周）。按"含测试与文档"估。
- **门禁**：每项都必须有 —— ① 单测覆盖契约形状；② e2e 驱动真实二进制；③ 变异验证
  证明测试真的在把关；④ 文档双语。缺一不算完成。
- **依赖**：箭头表示必须先完成。

## 一、总览

| # | 阶段 | 端点 / 范围 | 优先级 | 工作量 | 依赖 |
| --- | --- | --- | --- | --- | --- |
| P0-1 | 心跳与策略下发 | `/api/heartbeat`, `/api/sysinfo`, `/api/sysinfo_ver` | P0 | L | 安全边界先定 |
| P0-2 | 非 legacy 地址簿 | 10 个 `/api/ab/*` 端点 | P0 | L | O2 表结构 |
| P0-3 | 设备组与用户 | `/api/device-group/accessible`, `/api/users`, `/api/peers` | P0 | M | P0-2 的 peer 表 |
| P1-1 | 设备自助上线 | `/api/devices/deploy`, `/api/devices/cli` | P1 | M | 认证（已有） |
| P1-2 | TOTP 两步验证 | `/api/login` 的 `tfa_type`/`secret` | P1 | M | 无 |
| P1-3 | 地址簿冲突语义 | `/api/ab` ETag / 409 | P1 | S | 无 |
| P2-1 | 客户端审计上传 | `/api/audit/{typ}`, `PUT /api/audit` | P2 | M | 治理方案 |
| P2-2 | 受限网络 API 代理 | `HttpProxyRequest` | P2 | M | 白名单设计 |
| P2-3 | 会话录像 | `/api/record` | P2 | L | **治理方案必须先定** |
| P3-1 | 会话保活 | `HealthCheck` | P3 | S | 实测确认有收益 |
| P3-2 | LAN 发现 | `PeerDiscovery` | P3 | S | 无 |
| P3-3 | 设备切换授权 | `/api/switch-grant` | P3 | M | 设备身份层设计 |

## 二、P0-1　心跳与策略下发

**为什么是 P0**：这是唯一能"远程改客户端配置"的通道，Pro 的核心卖点，而我们完全没有。
客户端每 3 秒轮询，没有它就只能逐台手工配置。

**契约**（`src/hbbs_http/sync.rs`）：

```
POST /api/heartbeat
req:  {id, uuid, ver, conns?, modified_at}
resp: {sysinfo?, disconnect?, strategy?, modified_at?}
       strategy = {config_options:{k:v}, extra:{k:v}}
```

**步骤**

1. **先写安全边界文档（不写代码）**：`config_options` 是远程配置变更。必须列出
   ① 允许下发的键白名单；② 拒绝下发的键黑名单（任何影响认证/加密/更新的）；
   ③ 一旦被篡改的影响范围。**这一步不通过评审，后面不许开工。**
2. schema：`device_heartbeats`（设备状态）+ `strategy_documents`（版本化策略）
3. `POST /api/heartbeat`：鉴权（Bearer 或设备签名）、记录在线状态、返回 `strategy`
   与 `modified_at`
4. `disconnect`：下发给指定 `conns` 的断开指令（与 hbbs 联动）
5. `/api/sysinfo` 与 `/api/sysinfo_ver`：设备信息归档 + 版本号跳过优化
6. 与现有 `STARRY_STRATEGY_FILE` 的关系写进文档：**hbbs 策略管"连接允不允许"，
   客户端策略管"客户端怎么配"**，不重复

**门禁**
- 单测：白名单外的键被丢弃且有日志；`modified_at` 未变时不重复下发
- e2e：真 `starry-api` + 模拟客户端轮询，断言收到 strategy 后配置生效
- 变异：把白名单检查去掉 → 黑名单键能下发 → 测试必须失败
- 安全评审：必须有人工评审记录，不接受自动化替代

**风险**：这是全项目**最高安全风险**项。若无法确立可信的下发边界，**宁可做 P1 也不做它**。

## 三、P0-2　非 legacy 地址簿

**为什么是 P0**：Pro 的 "Address book sharing"。当前 legacy 只能一账号一本、无共享、
无分页。10 个端点全做完才生效（`/api/ab/personal` 404 即整体退回）。

**步骤**

1. **先做 O2**：把现有 `address_books.document` 拆成 `ab_books` + `ab_peers` + `ab_tags`
   三张表并做**在线迁移**（legacy 文档解析成行，保留原文档列作为回滚）
2. `/api/ab/personal` → 返回该用户的个人簿 guid
3. `/api/ab/settings` → `{max_peer_one_ab}`（沿用 `licensed_devices` 的高值策略）
4. `/api/ab/shared/profiles` → 分页 `{total,data}`
5. `/api/ab/peers` → 分页 + `ab` 过滤
6. `/api/ab/tags/{guid}` → 裸数组
7. peer 三件套：add(POST) / update(PUT，四种 body 语义) / delete(DELETE 裸数组)
8. tag 四件套：add / rename / update / delete
9. 共享语义：谁可以看/改某本簿（`ShareRule`: read/write）

**门禁**
- 迁移测试：legacy 文档 → 行 → 再次序列化，**逐字节等价**（这是能不能迁移的唯一判据）
- e2e：客户端两套模型都跑通；legacy 用户迁移后仍能用 `/api/ab`
- 变异：把 `peer/update` 的 `hash` 分支去掉 → 密码哈希丢失 → 测试失败
- 分页边界：`pageSize=100`、`total` 为 0、`current` 超界

**风险**：迁移必须可回滚。旧的 `document` 列保留至少一个版本周期。

## 四、P0-3　设备组与用户

**契约**：三个端点都是 `{total,data:[...]}` 分页信封。`/api/users` 需 admin 或
`{"error":"Admin required!"}`；客户端把 `ambiguous column name: status` 当"版本过旧"。

**步骤**

1. `device_groups` 表 + 成员关系
2. `/api/device-group/accessible`（`GET`，只返回当前用户可见的组）
3. `/api/users`（admin 才返回全部；普通用户只返回自己）
4. `/api/peers`（跨账号设备视图，admin）
5. 与我们已有的 strategy 分组对齐：**strategy 的 group 名应能对应到 device group**，
   否则运维要在两处维护同一概念

**门禁**：非 admin 访问 `/api/users` 返回精确错误串；分页；空组不报错。

## 五、P1-1　设备自助上线

`/api/devices/deploy`：管理员签发一次性 token → 新设备 `POST {id,uuid,pk}` → 绑定。
与 `starry-client-config` 并存：那个生成静态串，这个做在线注册。

**门禁**：token 一次性（重放失败）；`pk` 与后续注册的 key 一致；失败时设备不落半状态。

## 六、P1-2　TOTP 两步验证

客户端已支持完整的两步流程：登录返回 `type != access_token` 且 `tfa_type` 为
`tfa_check`/`email_check` 时弹出验证码对话框，用户输入后带 `verificationCode` 再登录一次。
我们返回的 `tfa_type`/`secret` 恒为空，所以这条路从未被点亮。

**步骤**
1. `users` 加 `totp_secret`（加密存储）+ `tfa_type` 状态
2. 首次登录返回 `tfa_type:"tfa_check"` + 一次性 `secret`，不返回 access_token
3. 第二次登录带 `verificationCode`，校验 TOTP 窗口（±1 步）
4. 恢复码 + 管理员重置
5. 与 OIDC 的交互：SSO 用户是否强制 TOTP（建议：由 provider 的 `acr` 决定，默认不叠加）

**门禁**：重放旧验证码失败；窗口外失败；`auth_version` 递增使旧 token 失效。

## 七、P1-3　地址簿冲突语义（小但值得）

当前 `/api/ab` 后写覆盖，两台设备交替推送会互相吞数据。
加 `If-Match`/ETag，冲突返回 409，客户端**已支持**该语义（`pushAb` 会提示失败）。
工作量 S，收益直接。

## 八、P2 / P3

- **P2-1 客户端审计上传**：与我们的服务端审计合并成统一查询面。先定"客户端审计是否
  可信"（客户端可伪造），建议只作参考不作判定。
- **P2-2 `HttpProxyRequest`**：白名单（仅 API host + `/api/` 前缀 + 响应上限 + 禁重定向）。
- **P2-3 `/api/record`**：**治理方案先于代码**——谁授权、存哪里、保留多久、谁能看。
  未定则不做。
- **P3-1 `HealthCheck`**：先实测长连接是否真的有超时问题，再决定。
- **P3-2 `PeerDiscovery`**：服务器非必需，做也是客户端侧为主。
- **P3-3 `/api/switch-grant`**：属设备身份层，与 JWT 平行的第二套信任模型，需先设计。

## 九、横切工作（不单独排期，每项都带着做）

| 项 | 内容 |
| --- | --- |
| O4 请求追踪 | 全 API 加 `X-Request-Id` + 耗时日志。第一个新端点落地时一并做 |
| 文档双语 | 每项都有 `docs/reference/*.md` 与 `.zh-CN.md`，`check_docs.py` 把关 |
| 字典 | 新增端点全部登记到客户端契约文档，避免下次分析重做 |

## 十、建议执行顺序与里程碑

```
M1（1 周）  P1-3 冲突语义  →  O2 表结构拆分  →  P0-2 地址簿（前半）
M2（1 周）  P0-2 完成  →  P0-3 设备组/用户
M3（1 周）  P1-2 TOTP  →  P1-1 设备上线
M4（1–2 周）P0-1 策略下发（安全评审通过后开工）
M5          按需：P2-1 / P2-2 / P2-3（各自治理方案先行）
```

**为什么 P0-1 排在 M4 而不是最先**：它价值最高但风险也最高。先做 M1–M3 能把地址簿、
设备、认证三条腿站住；P0-1 单独一段，便于安全评审不被打断。

## 十一、明确不做

见[分析文档第五节](CLIENT-GAP-ANALYSIS.zh-CN.md)。重复一次最关键的两条：
**不做自建 Web 客户端**（官方客户端已够用）；**不重造账号体系**（OIDC + 本地密码已覆盖）。
