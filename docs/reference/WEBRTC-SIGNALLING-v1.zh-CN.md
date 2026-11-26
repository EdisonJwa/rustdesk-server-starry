# WebRTC 信令 v1

[English](WEBRTC-SIGNALLING-v1.md) | **简体中文**

RustDesk 1.5 客户端可以在控制端和被控端之间建立 WebRTC 连接。HBBS 不承载媒体，只中转
信令：SDP offer、SDP answer 和 trickle ICE candidate。Starry 把这部分中转实现为可选、
有界的功能。

官方 rustdesk-server 不中转这些消息。功能关闭时（默认），Starry 的行为与官方完全一致：
offer 和 answer 会被去掉，`IceCandidate` 会关闭连接，客户端回退到普通打洞/Relay 路径。

## 启用

| 设置 | 值 |
| --- | --- |
| `hbbs --webrtc-signal=Y` | 为当前进程启用。 |
| `STARRY_WEBRTC_SIGNAL=Y` | 同上，来自环境变量或 `.env`。 |

命令行参数优先。启动日志会输出 `WebRTC signalling: enabled` 或 `disabled`。

该功能尚未进入 Starry 配置 schema（v5），因此 Control API 不能修改它；后续 schema 版本
会加入。

## 消息流程

| 步骤 | 消息 | 路径 |
| --- | --- | --- |
| 1 | `PunchHoleRequest.webrtc_sdp_offer` | 控制端 → HBBS，走其信令连接。 |
| 2 | `PunchHole.webrtc_sdp_offer`（以及 `force_relay`） | HBBS → 被控端，经 UDP 或被控端的 WebSocket 会话。 |
| 3 | `PunchHoleSent.webrtc_sdp_answer` 或 `RelayResponse.webrtc_sdp_answer` | 被控端 → HBBS，走被控端的 TCP/WebSocket 连接。 |
| 4 | `PunchHoleResponse.webrtc_sdp_answer` 或 `RelayResponse.webrtc_sdp_answer` | HBBS → 控制端。 |
| 5 | 带 `id` 的 `IceCandidate` | 控制端 → HBBS，走携带 offer 的那条连接；转发给对应被控端。 |
| 6 | 带 `socket_addr` 的 `IceCandidate` | 被控端 → HBBS，以 `PunchHole.socket_addr` 寻址；转发给对应控制端。 |

转发出去的 candidate 只包含 `session_key` 和 `candidate`。

## 路由

HBBS 在第 2 步转发已准入的 offer 时，会以控制端的信令连接为键打开一条**路由**。路由：

- 在 answer 之后保持该连接，使 candidate 能送达；
- 只允许该连接把 candidate 发给它打洞的那个被控端；
- 只在路由存在期间允许 candidate 发往该控制端；
- 在控制端断开，或最近一次 offer 后 60 秒结束。

对同一被控端的打洞重试会续期路由，但不重置 candidate 配额；对另一被控端的 offer 会替换
原路由。

## 准入与上限

只有同时满足以下条件，offer 才会被转发：

- 功能已启用；
- 经 **Secure TCP 或 WebSocket** 到达。SDP 携带把 WebRTC 通道绑定到对端身份的 DTLS
  指纹，明文 TCP 中间人可以替换它们；
- `ALWAYS_USE_RELAY` 关闭，因为 WebRTC 双方可能直接连接；
- 控制端通过了常规检查（key、连接认证、被控端在线），且 HBBS 发送的是 `PunchHole`
  而不是 `FetchLocalAddr`；
- 还有可用的路由名额。

| 限制 | 值 |
| --- | --- |
| offer 或 answer 大小 | 8 KiB |
| candidate 行 | 2 KiB |
| session key | 256 字节 |
| 路由总数 | 4,096 |
| 每个控制端 IP 的路由数 | 64 |
| 每条路由每个方向的 candidate 数 | 64 |
| 最近一次 offer 后的路由存活时间 | 60 秒 |

每 IP 限制使用控制端的有效 IP（配置了可信 WebSocket 代理时取转发地址），因此同一反向
代理后的客户端不会共享名额。answer 只转发给有活动路由的控制端。路由之外、超出配额或格式
错误的 candidate 会被丢弃；格式错误的 candidate 还会关闭发送它的连接。

## 安全说明

- 被控端或任何得知控制端信令地址的主机，在路由存活期间最多能向其发送 64 个 candidate。
  仅凭 candidate 无法加入会话：已签名 offer 和 answer 中的 DTLS 指纹仍须匹配。
- answer 沿用 `PunchHoleSent` 现有的信任模型：HBBS 无法判断是哪台被控端发送的
  `PunchHoleSent`，只知道它是给哪个控制端的。
- 不会记录任何 SDP、candidate 或密钥。

## 兼容性

旧客户端不会设置这些字段，因此对它们没有任何变化。1.5 客户端收不到 answer 时会回退到普通
连接路径。内置的 `hbb_common`（见 `libs/hbb_common.VENDORED`）包含 1.5 协议字段；
Starry 自己的 protobuf 扩展使用 60+ 和 100+ 号字段，不会冲突。

设计参考了 [bropines/rustdesk-server](https://github.com/bropines/rustdesk-server) 与
[CortenDesk Server](https://github.com/marcpope/cortendesk-server) 的独立实现；代码为
Starry 自行编写。
