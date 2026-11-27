# 部署拓扑 —— 哪个组件跑在哪台机器上

状态：当前
[English](DEPLOYMENT-TOPOLOGY.md) | 简体中文

## 为什么有这一页

中继节点只有一个二进制，中心是三个。把两者混为一谈，轻则多出一个没人能
访问的账号库，重则多出一个会拆分对端注册的 rendezvous。这一页把规则写死，
让节点不再靠猜测部署。

## 规则

| 角色 | 运行 | 不运行 |
| --- | --- | --- |
| 中心 | `hbbs`、`hbbr`、`starry-api`、TLS 终结者 | — |
| 中继节点 | `hbbr` | `hbbs`、`starry-api` |

- **`hbbs` 是唯一的。** 它拥有 rendezvous：对端注册、`PunchHole`、
  `RequestRelay`。两个共享同一密钥的 `hbbs` 会让对端注册在其中之一，
  而控制端的打洞请求落到另一个上。
- **`hbbr` 可复制。** 它只把 `hbbs` 已经互相告知的两个对端配对起来。
  可以跑任意多个，`relay_servers` 里的池子决定它们如何被感知。
- **`starry-api` 只属于客户端指向的那台。** 它提供登录、地址簿与令牌签发。
  客户端经由 import string 里写的主机访问它，因此中继节点上的第二份副本
  只是一个躲在回环监听后面的、与中心分叉的数据库。

## 参考布局

```
                    客户端 import string
        {"host":"rustdesk.edison.network","api":"https://rustdesk.edison.network"}
                                |
                                v
  ┌───────────────── 中心: 149.104.1.168 ──────────────────┐
  │  caddy  :80 :443                                        │
  │    ├── rustdesk.edison.network ──> 127.0.0.1:21114      │
  │    ├── meet / whiteboard       ──> 127.0.0.1:8081       │
  │    └── 为以上每个名字签发 ACME 证书                      │
  │                                                         │
  │  starry-api  127.0.0.1:21114   登录、地址簿、JWKS 签发者 │
  │  starry-hbbs :21115 :21116     rendezvous               │
  │  starry-hbbr :21117 :21119     中继（同时也是池成员）    │
  └─────────────────────────────────────────────────────────┘
                                |
                     relay_servers + GEO 规则
                                |
        ┌───────────────────────┴────────────────────────┐
        v                                                v
  117.78.7.96（CN）                             175.178.125.23（CN）
  starry-hbbr :21117 :21119                     starry-hbbr :21117 :21119
  只有 hbbr                                     只有 hbbr
```

中心的 `starry-hbbr` 与其他节点一样是池成员。CN 客户端优先拿到
`117.78.7.96:21117`，失败则回落到中心。

## 池子如何抵达客户端

`relay_servers` 是配置意图，真正发出去的集合更窄：

1. `hbbs` 每三秒对每个配置的中继做一次 TCP 连接（`check_relay_servers`）。
2. 只有应答成功的才成为 `native` 可用（`relay_observer.rs` —— `eligible_for`
   由探测结果构建）。
3. GEO 规则在**可用**集合内选择，而不是配置集合
   （`select_relay_explained_from` 接收的是 `eligible_relays`）。

因此，一条 GEO 规则里写了、但从中心不可达的中继永远不会被发出去：规则无法
选出可用集合之外的东西，它会落到下一个候选，而不是把客户端丢进黑洞。

这一点当下有实际意义：175.178.125.23 目前从中心没有通路，但从中国大陆访问
仍然正常。把它留在列表里不产生代价，通路恢复当天就自动恢复服务。

## 部署一个中继节点

```
BIN_SRC=/tmp CENTER_PUBKEY="<中心 id_ed25519.pub 内容>" NODE_ADDR=1.2.3.4:21117 \
  bash deploy/systemd/install-relay-node.sh
```

安装脚本只写 `hbbr` 及其 unit；若发现旧版本脚本留下的 `starry-api`，会把它
停用并移到 `/root/starry-retired`，而不是删除。

在有富余核心的机器上编译再拷贝二进制；两端 glibc 大版本必须一致，按集群里
最老的 glibc 编译总是安全的。

## 部署后的检查

```
# 中继能配对两个对端（从任何能访问该节点的地方运行）
python probe-relay.py <node> 21117        # 期望 RELAY_PAIRS_PEERS

# 从中心看该节点作为中继可达
ssh <centre> 'timeout 5 bash -c "cat </dev/null >/dev/tcp/<node>/21117" && echo TCP_OK'

# 节点不提供别的服务
ssh <node> 'ss -ltn'                      # 只有 21117、21119，以及回环上的 21120
```
