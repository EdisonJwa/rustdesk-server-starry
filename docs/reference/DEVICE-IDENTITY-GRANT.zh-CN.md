# 设备身份层设计 —— `/api/switch-grant`

状态：设计（2026-11-28）
结论：**可安全实现，但它的价值是审计而非授权。** 不实现门禁，因为没有消费方。

[English](DEVICE-IDENTITY-GRANT.md) | 简体中文

## 一、这个端点在协议里是什么

已对照 rustdesk master 核实（`src/hbbs_http/sync.rs:410-505`、`src/ipc.rs:1184-1194`）。

### 触发时机

用户在已连接的会话里点"切换主控/被控"（switch sides）。被控端做三件事：

```rust
Data::SwitchSidesRequest(id) => {
    let uuid = uuid::Uuid::new_v4();                          // 一次性
    crate::server::insert_switch_sides_uuid(id, uuid.clone()); // 存本地
    crate::hbbs_http::sync::register_switch_grant(uuid.to_string()); // 上报服务器
    stream.send(&Data::SwitchSidesRequest(uuid.to_string()))  // 发给对端
}
```

所以 `switch_uuid` 是**这一次切换动作**的一次性标识。它同时被发给对端，对端用它回头连过来。

### 上报内容

```
POST /api/switch-grant
{"id":"<设备 id>","switch_code_verifier":"<b64>","timestamp":"<unix 秒>","signature":"<b64>"}
```

| 字段 | 怎么算出来的 |
| --- | --- |
| `switch_code` | `base64(sha256(switch_uuid 的字符串))` |
| `switch_code_verifier` | `base64(sha256(b"switch-grant-verifier\0" \|\| switch_code))` |
| 签名原文 | `b"switch-grant\0" \|\| id \|\| 0x00 \|\| verifier \|\| 0x00 \|\| timestamp` |
| `signature` | Ed25519 签名，密钥是**设备自己的** `id_ed25519` 私钥 |

注意 `verifier` 又套了一层前缀哈希。原始 `switch_uuid` 与 `switch_code` **都不出现在请求里**，服务器只拿到不可逆的二次哈希。

### 响应

```json
{"accepted": true}
```

或者，**当设备时钟不在服务器接受的窗口内**：

```json
{"accepted": false, "server_time": 1795820751}
```

客户端收到 `accepted: false` 且有 `server_time` 时，会用服务器时间重签**一次**再发。这是唯一的失败重试路径，说明协议设计者预期的主要失败原因就是时钟偏移。

### 唯一的消费方

**没有。** 我搜遍了客户端：`register_switch_grant` 只被 `ipc.rs` 那一个地方调用，且是 `tokio::spawn` 的 fire-and-forget——

```rust
// Fire-and-forget by design: the switch flow must not block on this POST.
```

服务器从不把 grant 读回给谁。客户端的切换是否成功**完全不依赖**这次上报。

## 二、因此，这个端点能做什么、不能做什么

| 想做的 | 能做吗 | 为什么 |
| --- | --- | --- |
| 记录"某设备在某时刻发起了一次主控切换" | **能** | 签名可验证，事件可审计 |
| 阻止未授权的切换 | **不能** | 切换走的是 P2P/中继通道，不经过 API；服务器拦不住 |
| 给切换发一个令牌/凭证 | **不能** | 客户端不读响应里的凭证，只有 `accepted` 与 `server_time` |
| 把设备密钥当作连接凭据 | **不能** | 连接认证是 JWT（`connection_auth`），这套是并行的另一条链 |

**所以它是审计通道，不是授权通道。** 任何把它包装成"设备门禁"的设计都是错的——那会让人以为切换受控，实际不受控。

## 三、安全边界

这是本项目里**第一个不靠 Bearer 令牌**的端点：认证完全来自设备 Ed25519 签名。因此必须自己把边界写清楚。

### 3.1 设备身份从哪来

签名用设备私钥，验证用**公钥**。公钥不能从请求里取——那样任何人都能自称任何设备。来源只能是：

1. **已有注册**：hbbs 的设备注册表里 `id → pk`（`register_pk` 时写入）。这是权威来源。
2. **首次见到**：如果该 id 未注册，拒绝。不能"先信任再补登"，那是自我认证。

**约束**：签名用的私钥是 `Config::get_key_pair().0`，上报用的公钥是同一对的 `.1`——`src/ui_interface.rs:1149` 的 `/api/devices/deploy` 发送的正是它：

```rust
let pk = crate::encode64(Config::get_key_pair().1);
```

所以两条路径用的是**同一把设备密钥**，而 `enrolled_devices` 表已经存了 `pk`：

```sql
create table if not exists enrolled_devices (
    peer_id text primary key, uuid text not null default '', pk text not null, ...
);
```

**结论：不需要新表，也不需要新的登记流程。** 已有 `enrolled_devices.pk` 就是验证签名所需的全部材料，而且它是管理员用一次性令牌显式登记的（见 `/api/devices/deploy`），边界与本设计一致。

唯一的缺口是：**`enrolled_devices` 只覆盖通过 deploy 流程上线的设备**。第三台、第四台自行输入 ID 的老设备不在这张表里，它们的 grant 会验签失败。这是可接受的：那些设备本来也不在 Starry 的管理范围内。若要覆盖，应扩展 deploy 流程而不是另起一套。

### 3.2 重放

`timestamp` 在签名原文里，所以不能改。但**同一个签名可以重复发送**——服务器若只验签名，同一事件会被记录多次，或被用来推测设备在线状态。

必须做的：

- `(id, switch_code_verifier)` 唯一：同一设备的同一次切换只接受一次。
- `timestamp` 落在 `now ± 300` 秒内。窗口比客户端重试所需的最小值略宽，因为客户端只重试一次。
- 时钟偏移时**先回 `server_time` 让客户端重试**，与客户端契约一致；不要直接拒。

### 3.3 信息泄露

- `switch_code_verifier` 是不可逆的二次哈希，**不含** `switch_uuid`，所以存下它是安全的。
- 但 `(id, 时间)` 的序列会暴露"这台设备何时切换了主控"。这属于行为元数据，与我们的审计日志同级，必须：默认关闭、与 `STARRY_AUDIT_DIR` 相同的留存策略、不出现在任何非管理员接口。

### 3.4 拒绝时的响应

- 签名错、`id` 未登记、重放 → `{"accepted": false}`，**不带** `server_time`。带 `server_time` 会让客户端重试一次无意义的请求。
- 时钟偏移 → `{"accepted": false, "server_time": <now>}`。

## 四、实现计划（评审通过后）

| 步 | 内容 | 门禁 |
| --- | --- | --- |
| 1 | 从 `enrolled_devices.pk` 取公钥验签 | 未登记设备的签名必须被拒（而不是抛错） |
| 2 | `POST /api/switch-grant`：验签、时钟窗口、去重 | 重放被拒；时钟偏移回 `server_time` 且客户端重试成功 |
| 3 | 签名原文构造的**逐字节**测试 | 用客户端自己的测试向量（`test_switch_grant_signed_msg_layout`） |
| 4 | 审计落盘，默认关闭 | 关闭时端点仍然应答但不落盘 |

**没有第 0 步（建表）**，因为 `enrolled_devices` 已经具备条件。这让工作量从 L 降到 M。

**门禁的关键一条**：签名原文的构造必须用客户端仓库里的测试向量对照，而不是我重写一遍。客户端有一个 `test_switch_grant_signed_msg_layout` 测试，它的期望值 `b"switch-grant\0id1\0c1\01700000000"` 是唯一的外部真值。

## 五、与现有体系的关系

```
连接授权     JWT (connection_auth)      → hbbs 决定"能不能连"
设备上线     Bearer deploy_token         → starry-api 决定"这个 id 归谁"
本次         Ed25519 设备签名            → starry-api 记录"谁切换了主控"
```

三条链互不替代。特别地：**设备签名通过不等于该设备可以连接**，也不等于它的 id 被授权。这一点必须在文档里写明，否则读者会以为它是第四种授权。

## 六、建议

**可以实现，但先要一个决定：我们是否需要设备级审计。**

技术前提已经齐了——公钥在 `enrolled_devices`，签名原文可对照客户端测试向量验证，去重与时钟窗口都有明确规则。缺的不是能力，是**需求**：

- 若需要"某设备何时切换过主控"这条审计线 → 实现，工作量 M，门禁清晰。
- 若不需要 → **永久不做**，并把它从计划表移出。理由是唯一消费方根本不在乎结果，硬做出来的是一个只有写入、没有任何读取方的表，纯粹是运维负担。

我的判断：**先不做，等有真实的审计需求再说。** 这个系统当前的盲区不在"少记了一个事件"，而在别处（例如 legacy 与结构化两套地址簿并存）。把精力放在那里收益更高。

如果有人据"Pro 有 switch-grant"来要求实现，正确的回答是：Pro 的实现让客户端能切换主控；我们的客户端本来就能切换——这个端点是可选的遥测，不是功能开关。
