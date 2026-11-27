# 中继运维端点 —— `/healthz`、`/readyz`、`/metrics`

状态：已实现
[English](RELAY-OPS-SURFACE.md) | 简体中文

## 是什么

HBBR 提供一个只读 HTTP 监听器用于监控。它**默认关闭**，必须显式指定地址才
开启：

```
STARRY_RELAY_OPS_LISTEN=127.0.0.1:21120
```

三条约束是刻意的：

- **不配置就不开。** 没有监控者的中继不该多开一个端口。
- **默认只回环。** 载荷描述容量与准入压力，因此非回环地址会被拒绝，除非同时
  设置 `STARRY_RELAY_OPS_ALLOW_PUBLIC=1`。
- **只读。** 只接受 `GET`/`HEAD`；其他方法直接拒绝而不是返回错误体，因为这里
  没有需要保护的可变状态。

## 两个探针，两个问题

这个区分正是端点的全部意义所在。把两者混为一谈是常见且代价高昂的错误：

| 端点 | 回答什么 | 200 | 503 |
| --- | --- | --- | --- |
| `/healthz` | 进程还活着、还能服务 HTTP 吗？ | 永远 | 从不 |
| `/readyz` | 现在还会接纳新的中继会话吗？ | 准入开放 | 排水中或已满 |

`/healthz` **永远**返回 200。排水或满载的中继依然活着，重启它要么撤销了运维
的刻意动作，要么掐掉所有在线会话却一个槽位也没多出来。

`/readyz` 在拒绝时返回 503 并带上 `reason`，负载均衡或服务注册表据此停止把
新对端路由过来，而既有会话继续运行。

```json
// GET /readyz —— 准入开放
{"status":"ready","version":"1.1.17-patch-v1.3.1","active_sessions":3,"capacity_sessions":10000}

// GET /readyz —— 排水中
{"status":"not_ready","reason":"draining","version":"...","active_sessions":0,"capacity_sessions":10000}

// GET /readyz —— 槽位用尽
{"status":"not_ready","reason":"at_capacity","version":"...","active_sessions":10000,"capacity_sessions":10000}
```

`/healthz` 把准入状态作为字段报告，但不改变状态码，因此一次抓取回答了两个
问题：

```json
{"status":"ok","version":"...","uptime_seconds":42,"admission_rejections":0,"draining":false,"admission_open":true}
```

## 为什么判定不会与数据面漂移

`/readyz` 与会话准入都调用同一个 `relay_server::admission_decision`。如果探针
自己再推导一遍规则，中继就可能一边报告 "ready"、一边被
`RelayLoadGuard::try_new` 拒绝——负载均衡于是持续送来被丢弃的流量。

`admission_decision(draining, active, capacity)` 的输入是参数而非全局量，这正是
它能在同一个测试二进制里覆盖四种状态、而无需改动进程状态的原因。

两者同时为真时，排水优先于容量：运维主动排空一台繁忙的中继，需要看到的是自己
的动作，而不是一个干等也解决不了的容量症状。

## 排空一台中继

两个等效开关，每次准入判定都会读取：

```
STARRY_RELAY_DRAINING=1              # 环境变量，单元启动时设定
STARRY_RELAY_DRAINING_FILE=/path     # 文件存在即视为排水
```

文件形式适合部署脚本：创建文件，观察 `/readyz` 转为 503，等待
`starry_relay_active_sessions` 归零，再停止进程。既有会话从不被打断——排水
只拒绝新会话。

## 指标

`/metrics` 以 Prometheus 文本格式（0.0.4）渲染中继已有的原子计数：

| 指标 | 类型 | 含义 |
| --- | --- | --- |
| `starry_relay_active_sessions` | gauge | 当前承载流量的会话数 |
| `starry_relay_capacity_sessions` | gauge | 配置的并发会话上限 |
| `starry_relay_active_bandwidth_bps` | gauge | 当前占用带宽 |
| `starry_relay_capacity_bandwidth_bps` | gauge | 配置的总带宽 |
| `starry_relay_load_basis_points` | gauge | 两者利用率的较高值 |
| `starry_relay_pending_pairs` | gauge | 等待第二个对端的配对 ID 数 |
| `starry_relay_uptime_seconds` | gauge | 启动至今秒数 |
| `starry_relay_admission_rejections_total` | counter | 因容量拒绝的准入次数 |
| `starry_relay_probes_*_total` | counter | 中继质量探测的应答 / 限流 / 不支持 / 畸形次数 |
| `starry_relay_telemetry_auth_failures_total` | counter | 握手阶段被拒的认证遥测次数 |

## 门禁

- `src/ops_surface.rs` 单测 —— `/healthz` 在每种准入状态下都保持 200；
  `/readyz` 在正确时给出 200/503 与正确的 `reason`；`admission_decision`
  覆盖开放、最后一个空位、已满、排水、以及排水且已满。
- 变异已验证：让容量永不阻塞会使
  `admission_decision_covers_every_state`、
  `readyz_answers_for_every_admission_state` 与
  `zero_capacity_is_floored_to_one_session` 失败，而
  `healthz_reports_ok_regardless_of_admission` 仍然通过——这正是这个拆分要
  保证的性质。
