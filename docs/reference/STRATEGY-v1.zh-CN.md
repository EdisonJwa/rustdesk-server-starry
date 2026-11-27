# Strategy v1 —— 设备分组与服务端强制访问策略

状态：已实现（路线 T1）——HBBS 启动时从 `STARRY_STRATEGY_FILE` 加载；未设置即关闭该引擎
[English](STRATEGY-v1.md) | 简体中文

## 问题

RustDesk Server Pro 的收费卖点 *strategy*：由中心决定一条连接可以触达哪些
设备。社区没有任何等价物，且上游协议没有策略通道：唯一类策略的服务端到客户
端消息 `ConfigUpdate` 只携带 `serial` 与 `rendezvous_servers`（vendored
`rendezvous.proto` 的 1、2 号字段）。官方客户端不会应用该消息的任何其他内容，
而 Pro 的客户端设置同步走账号/API 层——Starry 刻意不包含这一层。

## 范围决策

因此 Strategy v1 是**服务端强制策略**——HBBS 自己做出且可举证的决策，而非
客户端设置同步：

- 设备按其注册 ID 分配到**组**（精确或前缀匹配），在请求时依据策略文档无状态
  求值；不引入新持久化，不做 schema 迁移。
- 每个组携带连接 JWT 的 **required scope 覆盖**与可选的 **deny** 判定。
- 拒绝发生在 HBBS 内、任何信令工作之前，进入连接审计日志并附带组名，且在线路
  上与其他授权拒绝完全不可区分（不泄露目标存在性）。

客户端设置同步明确**不在 v1 范围**。为 v2 预留两条扩展路径：`ConfigUpdate`
的 protobuf 增量字段（tags 100+，面向 Starry-aware 客户端），以及经账号/API
层向官方客户端投递。

## 策略文档

独立 YAML 文档，由 `STARRY_STRATEGY_FILE` 定位（未设置则引擎关闭；所有设备
归入隐式 `general` 组且无覆盖）：

```yaml
version: 1
default_group: general
groups:
  - name: general
  - name: contractors
    id_prefixes: ["tmp-"]
    require_scope: "connect:initiate:contractor"
  - name: retired
    ids: ["legacy-box-1"]
    deny: true
```

- `groups[].name` 唯一；`ids` 为精确匹配，`id_prefixes` 为前缀匹配；最具体
  规则胜出（精确优于前缀，长前缀优于短前缀）；未命中的设备落入
  `default_group`。
- `default_group` 是真实分组而非标签：未命中任何规则的设备**属于**它，因此该
  组的 `deny` 与 `require_scope` 对其生效。把默认组设为 deny，就等于拒绝所有
  未被显式放行的设备。
- `require_scope` 在请求**指向该组设备**时替换连接认证的 `required_scope`；
  不具备的 token 以 `missing_group_scope` 拒绝。
- `deny: true` 以 `strategy_group_denied` 拒绝所有指向该组设备的请求，且在
  JWT 求值之前。

文档在启动时加载，按需重读（local-control 方法 `strategy.reload`，与
`runtime.reload` 同型）；内容哈希由 `/healthz` 与 `strategy.status` 上报。

### fail-closed 行为

| 部署形态 | 文档损坏或未配置 | 结果 |
| --- | --- | --- |
| 兼容模式（默认） | 记录加载错误，引擎保持关闭 | HBBS 正常启动 |
| 受管模式：`STARRY_STRATEGY_REQUIRED=1` 或 `MUST_LOGIN` | 拒绝启动 | `hbbs` 以 `Strategy engine startup failed` 退出 |

受管部署绝不能带着加载不了的策略启动——那等于静默地无限制运行。同理，会使
引擎失去策略的运行时 `strategy.reload`（文件被取消配置，或新文档非法）会被
拒绝而不是生效，此前加载的策略继续有效。

## 强制点

1. `PunchHoleRequest` 与 `RequestRelay` 分支先解析
   `strategy::check_target(id)`。deny 判定短路进入标准拒绝路径（审计、计数）。
   否则把组要求的 scope 作为覆盖传给连接认证。
2. `connection_auth::authorize_connection_attempt` 增加 target 检查参数；内部
   scope 校验在存在覆盖时使用之，组 scope 不足时报告 `missing_group_scope`，
   未配置覆盖的全局配置仍报 `missing_scope`。
3. 审计事件增加 `group` 字段（增量式；既有消费方忽略未知字段），CSV 导出器
   携带同一列。策略 `deny` 完全绕过 `connection_auth`，因此单独记录为 verdict
   `deny`、reason `strategy_group_denied`——否则运维特意配置的那一条拒绝反而
   不会出现在证据链里。

## 非目标

- 不做客户端设置同步（见范围决策）。
- 不做按用户策略：用户在账号层。
- 不做组持久化：组隶属由 ID 与当前文档推导，策略编辑经重载即生效，不触碰
  设备状态。

## 门禁

- 单元测试：文档解析与校验、匹配优先级、覆盖传递、deny 短路。
- 集成测试：注册到 `require_scope` 组的设备拒绝无组 scope 的 token
  （`missing_group_scope`）、接受具备的 token；denied 组的目标不暴露存在性。
