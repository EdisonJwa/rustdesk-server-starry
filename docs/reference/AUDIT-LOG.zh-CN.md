# 连接审计日志

[English](AUDIT-LOG.md) | **简体中文**

HBBS 可以把每一次连接认证决策记录为只追加的 JSONL 证据：谁尝试打洞或请求中继、
经哪个传输通道、执行器判了什么、为什么。详细的中继状态仍保留在认证遥测之后；
本模块覆盖的是信令授权一侧。

## 开启

只有在指定目录时审计日志才开启：

```sh
docker run ... -e STARRY_AUDIT_DIR=/var/lib/rustdesk-server-starry/audit \
  -e STARRY_AUDIT_RETENTION_DAYS=90 ... hbbs
```

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `STARRY_AUDIT_DIR` | 未设（关闭） | 存放 `audit-YYYYMMDD.jsonl` 日文件的目录。 |
| `STARRY_AUDIT_RETENTION_DAYS` | `30` | 超过该天数的日文件在轮转时清理。`0` 表示永久保留。 |
| `STARRY_AUDIT_MAX_FILE_MB` | `256` | 单日文件超过该大小后停止接收事件直至次日，防止攻击经由审计路径填满磁盘。`0` 表示不设上限。 |

仅在连接认证处于活动状态（audit 或 enforce）时才记录事件；认证关闭时每个决策
都是无操作，记录它们只会产生噪音。

## 事件格式

每行一个 JSON 对象，字段顺序固定：

```json
{"ts":1735000000,"kind":"punch_hole","transport":"tcp","verdict":"deny","reason":"missing_token","client_ip":"192.0.2.7","mode":"enforce"}
```

- `kind`：`punch_hole` 或 `request_relay`。
- `transport`：`tcp`、`secure_tcp`、`websocket` 或 `unsupported_udp`
  （UDP 发起在分配前即被拒绝，拒绝本身也会被记录）。
- `verdict`：`allow`、`deny` 或 `would_deny`（audit 模式）。
- `reason`：执行器的确切原因，如 `missing_token`、`expired_token`、`allow`。
- `client_ip`：生效的客户端地址；依据监听套接字族，IPv4 客户端可能以
  IPv4 映射的 IPv6 形式出现。
- `mode`：决策时的生效模式。

## 保证

- **绝不阻塞信令。** 事件经由有界通道传递；通道满时丢弃最新事件并计数，而不是
  卡住一条连接。写入由独占日文件的专用线程完成。
- **存储天然有界。** 按日轮转、保留期清理与单日大小上限三者共同约束存储，
  不论流量如何冲击。
- **每个决策一行，包括拒绝。** 拒绝才是证据价值所在；audit 模式记录
  `would_deny` 而不拒绝连接。

## 导出

仓库自带 `starry-audit-export` 独立转换器：读取审计日文件目录，输出 CSV（或
过滤后的 JSONL）：

```sh
starry-audit-export /var/lib/rustdesk-server-starry/audit \
  --out audit-2024Q4.csv --from 20241001 --to 20241231
```

列顺序固定：`timestamp_utc,kind,transport,verdict,reason,client_ip,
mode,group,source_file`；含逗号或引号的字段遵循 RFC 4180。范围过滤为包含边界的
UTC 自然日。`group` 是策略引擎解析出的目标所属组（未加载策略时为 `general`）。

## Kubernetes

把 `STARRY_AUDIT_DIR` 指到 HBBS 状态卷下并在 Helm chart 里加 `extraEnv`；
该卷本身就是持久的，保留策略会把增长约束在有界范围内。
