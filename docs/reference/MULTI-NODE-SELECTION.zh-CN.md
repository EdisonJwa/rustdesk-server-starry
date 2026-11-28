# 一国多节点时的择优机制 —— 现状分析与改进方案

状态：现状已核实（2026-11-28），改进未实施
适用：`geo_relay` / `relay_observer` / `relay_quality`

English | [简体中文](MULTI-NODE-SELECTION.md)

## 一、先说结论

**当前不存在"择优"。** 同一国别有多个中继时，选路是**配置顺序的稳定交集**：

```
GEO 规则命中
  → 取其 relays 列表
  → 与该时刻 TCP 可达的中继求交集（保持配置顺序）
  → 取第一个
```

影响结果的只有三件事：① 客户端 IP 归到哪条 GEO 规则；② 规则里中继的书写顺序；
③ 该中继此刻 TCP 是否可达。**延迟、负载、带宽、历史成功率都不参与。**

## 二、代码级的完整链路

### 2.1 交集，保持配置顺序

`src/geo_relay/rules.rs:446`：

```rust
fn select_ordered(configured_relays: &[String], online_relays: &[String]) -> Vec<String> {
    configured_relays
        .iter()
        .filter_map(|configured| {
            online_relays
                .iter()
                .find(|online| online.eq_ignore_ascii_case(configured))
                .cloned()
        })
        .collect()
}
```

它遍历**配置**列表，只保留在线者。所以顺序 = 配置顺序，不是探测到的最优顺序。

### 2.2 可达性从哪来

`rendezvous_server.rs` 的 `check_relay_servers` 每三秒对 `relay_servers` 每项做一次
TCP 连接，只有应答的进 `native_online`；`relay_observer.rs:497` 用它决定
`eligible_for` 是否含 `native`。

**这是二值判定（通/不通），没有任何质量维度。** 一台丢包 30% 但 TCP 能握手的中继，
与一台完全健康的中继在选路眼里**完全相同**。

### 2.3 取第一个

`rules.rs:55`：

```rust
let candidates = select_ordered(&rule.relays, online_relays);
if let Some(relay) = candidates.first().cloned() { ... }
```

`candidates` 的**其余部分并不被主选路使用**——只有开启 `relay_quality` 时才交给
自适应探测。

### 2.4 主选路之后还有一层（需要额外条件）

`rendezvous_server.rs:1416`：

```rust
if let Some(server_selected_relay) = fast_relay::selected_relay_for_response(...) {
    rr.relay_server = server_selected_relay;
}
```

`relay_quality`（`src/relay_quality.rs`，约 1000 行）是**真正的"择优"**：
服务端给出候选集，客户端逐台测速上报，服务端按 RTT/抖动/丢包排序后锁定。

**但它有三个前提，当前一条都不满足：**

| 前提 | 现状 |
| --- | --- |
| `relay_quality.enabled: true` | **默认 false**，生产配置里没有这一段 |
| `client_protocol == 1` | 官方客户端**完全不认识**这个协议（全仓 `grep relay_quality` 无命中） |
| `max_candidates >= 2` | 默认 3，但要求 GEO 首选必须是 `quality_candidate` |

第二条是关键：**这是 Starry 私有协议，只有 Akari 系客户端支持。官方 RustDesk 客户端
永远不会进入这条路径。**

## 三、实测证据（生产）

`allocation.simulate`，CN↔CN：

```json
{"candidates": [
  {"configured_order": 1, "eligible": true, "priority": 1, "relay_id": "117.78.7.96:21117"},
  {"configured_order": 2, "eligible": true, "priority": 2, "relay_id": "149.104.1.168:21117"}],
 "matched_rule": {"name": "CN devices use CN relay"},
 "selection": {"kind": "geo_rule", "relay_id": "117.78.7.96:21117"}}
```

`priority` 就是配置下标，`kind` 是 `geo_rule`。**没有 `quality` 排序的痕迹。**

## 四、所以在"一国多节点"下，实际行为是

| 场景 | 结果 |
| --- | --- |
| 两台都健康 | **永远**选配置里靠前那台。第二台只有在第一台 TCP 不可达时才被使用 |
| 第一台健康但很慢 | 继续用它。慢不构成"不可用" |
| 第一台丢包严重 | 继续用它。丢包不构成"不可用" |
| 第一台满载 | 继续用它。负载不参与判定 |
| 第一台宕机 | `check_relay_servers` 三秒内标记不可用，切到第二台 |

**结论：这是"主备"，不是"择优"。** 对一国多节点来说，这浪费了冗余容量——第二台只在
故障时被使用，平时完全空闲。

## 五、改进方案（按可行性排序）

### 方案 A：多规则分流（今天就能做，零代码）

利用"规则按顺序匹配、取第一个命中的"这一语义，把一国拆成多条更细的规则：

```yaml
geo:
  rules:
    - name: CN south goes to Guangzhou
      match: { client_a: CN, client_a_isp: "China Telecom Guangdong" }
      relays: [117.78.7.96:21117]
    - name: CN rest goes to Shanghai
      match: { client_a: CN }
      relays: [new-cn-2:21117, 117.78.7.96:21117]
```

- **能做的**：按 ISP/省份把客户端分到不同节点，实现**地理与运营商层面的分流**。
- **代价**：0 代码，纯配置。
- **局限**：是分流不是择优。同一 ISP 内的客户端仍全落到同一台，且需要准确的 MMDB
  能区分 ISP。

**这是当前唯一能对官方客户端生效的方案。**

### 方案 B：加权轮询（小工作量，服务器侧）

现在多中继里 `ROTATION_RELAY_SERVER` 只在 GEO 未命中时轮转。可以让 GEO 命中时也
按权重轮转：

```rust
// 不止取 first()，而是按 presence/asn 做 hash 后取模
let index = stable_hash(&client_addr) % candidates.len();
```

- **收益**：两台 CN 节点**平时就分摊负载**，而不是一台干活一台闲置。
- **代价**：小（约 50 行 + 测试）。同一客户端稳定落同一台，不影响连接复用。
- **局限**：仍不感知质量。但**消除了最明显的浪费**。

**我建议先做这个。** 风险低、收益直接：一国多节点从"主备"变成"分担"。

### 方案 C：服务端侧被动测速（中工作量）

不开 `relay_quality`（那需要私有客户端），改为**服务端自己**测：

1. hbbs 定期对自己的 `relay_servers` 做质量探测（不只是 TCP 握手）；
2. 得到 RTT/丢包，写进 `relay_observer` 的 `RelayRuntimeView`；
3. GEO 选路时在同规则候选中按分数排序，取最优。

- **收益**：对官方客户端生效，且是真正的质量择优。
- **代价**：中。探测流量必须很小（否则中继侧带宽成本）；排序稳定性需要滞留机制
  （否则客户端在不同节点间抖动）。
- **风险**：**hbbs 到中继的 RTT 不代表客户端到中继的 RTT。** 这是根本局限——
  香港的 hbbs 测广州节点和上海节点，测出的是 hbbs 的位置差异，不是 CN 用户的差异。

  缓解：只用它**排除明显劣化**的节点（如丢包 > 阈值），不做精细排序。

### 方案 D：客户端测速并上报（大工作量，需客户端配合）

即现有的 `relay_quality`，但需要客户端实现。**官方客户端不会实现**，所以除非我们
同时维护一个客户端分支，这条路不通。

## 六、我的建议

| 步骤 | 方案 | 理由 |
| --- | --- | --- |
| 1 | **A（配置分流）** | 零风险、零代码，今天就能让一国多节点开始分担 |
| 2 | **B（权重轮询）** | 50 行，把"主备"变成"分担"，收益最直接 |
| 3 | C 的"排除劣化"子集 | 只做阈值判定（丢包超限即降级），不做精细排序——避开 hbbs 视角的根本局限 |
| 不做 | D | 官方客户端不支持；现有实现保留但保持关闭 |

## 七、需要先回答的问题

这些决定了方案该怎么配，而不是怎么实现：

1. **同一国别的多台节点，是同规格还是不同规格？** 同规格则权重相等，不同则方案 B 需要
   每节点权重。
2. **客户端的出口 IP 是否稳定？** 若 NAT 大量共享出口，按 IP hash 会把整栋楼压到一台。
3. **GB 级带宽的中继成本 vs 用户体验**：方案 C 的探测流量虽小，但中继按流量计费时
   需要确认可接受。

**在 1、2 有答案前，我不建议动方案 B 的哈希策略**——选错会让负载更不均。方案 A 不受
这两点影响，可以先做。
