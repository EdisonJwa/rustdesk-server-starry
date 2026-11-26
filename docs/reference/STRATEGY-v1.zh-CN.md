# Strategy v1 —— 设备分组与服务端强制访问策略

状态：实施中草案（路线 T1）
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
- `require_scope` 在请求**指向该组设备**时替换连接认证的 `required_scope`；
  不具备的 token 以 `missing_group_scope` 拒绝。
- `deny: true` 以 `strategy_group_denied` 拒绝所有指向该组设备的请求，且在
  JWT 求值之前。

文档在启动时加载，按需重读（local-control 方法 `strategy.reload`，与
`runtime.reload` 同型）；内容哈希由 `/healthz` 与 `strategy.status` 上报。

## 强制点

1. `PunchHoleRequest` 与 `RequestRelay` 分支先解析
   `strategy::check_target(id)`。deny 判定短路进入标准拒绝路径（审计、计数）。
   否则把组要求的 scope 作为覆盖传给连接认证。
2. `connection_auth::authorize_connection_attempt` 增加 target 检查参数；内部
   scope 校验在存在覆盖时使用之，组 scope 不足时报告 `missing_group_scope`，
   未配置覆盖的全局配置仍报 `missing_scope`。
3. 审计事件增加 `group` 字段（增量式；既有消费方忽略未知字段）。CSV 导出器的
   列集合在 v1 保持不变。

## 非目标

- 不做客户端设置同步（见范围决策）。
- 不做按用户策略：用户在账号层。
- 不做组持久化：组隶属由 ID 与当前文档推导，策略编辑经重载即生效，不触碰
  设备状态。

## 门禁

- 单元测试：文档解析与校验、匹配优先级、覆盖传递、deny 短路。
- 集成测试：注册到 `require_scope` 组的设备拒绝无组 scope 的 token
  （`missing_group_scope`）、接受具备的 token；denied 组的目标不暴露存在性。
