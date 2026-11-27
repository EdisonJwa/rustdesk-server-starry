# 地址簿 v1 —— starry-api 为客户端存什么

状态：已实现
[English](ADDRESS-BOOK-v1.md) | 简体中文

## 是什么

RustDesk 客户端的地址簿页会拉取与推送**一个 JSON 文档**。v1 按账号存储该文档并
原样返回。服务端不对 peer、标签、颜色建模，这是刻意的设计选择而非偷懒：

- 文档形状由客户端拥有。它自己序列化 `{tags, peers, tag_colors}` 并按同一结构
  解析回来，任何服务端改写都会破坏客户端的一次推送。
- 客户端新增字段的版本发布，不应要求服务端做迁移。

## 契约

已对照 rustdesk 1.5.x（`flutter/lib/models/ab_model.dart`）核实。

| 方法 | 路径 | 认证 | 请求 / 响应 |
| --- | --- | --- | --- |
| GET | `/api/ab` | Bearer | `{"data": "<JSON 字符串>", "licensed_devices": N}`，或字面量 `null` |
| POST | `/api/ab` | Bearer | `{"data": "<JSON 字符串>"}` → `null` |

客户端发送的文档：

```json
{
  "tags": ["office"],
  "peers": [
    {"id": "123", "username": "", "hostname": "", "platform": "",
     "alias": "prod-db", "tags": ["office"], "hash": "<密码哈希>"}
  ],
  "tag_colors": "{\"office\":\"#00ff00\"}"
}
```

注意 `tag_colors` 是文档内部的一个 JSON **字符串**。任何改写该载荷的工具都必须
保留这层嵌套。

### 为什么 `null` 与 401 是不同答案

- `null` 表示"该账号还没有地址簿"，是正常情况。
- `401` 会让客户端退出登录。

对未认证请求返回 `null`，会让一个失效的会话看起来像数据丢失，因此未认证的拉取
永远是 401。

`licensed_devices` 是客户端裁剪地址簿的上限。Starry 不做设备授权，因此报一个
高到永不触发的值：这里给一个小数字会静默丢弃用户的 peer。

## 存储

`address_books` 表每账号一行，推送即 upsert（客户端总是发整份文档，没有可合并的
内容）。载荷上限 4 MiB——与每个凭证端点使用的 16 KiB 上限分开，因为几百个 peer
的地址簿会合法地超过后者。

推送在存储前会校验为 JSON。这不是结构校验：它只保证一次损坏的推送不会让之后
每次拉取都无法解析。被拒绝的推送不会动既有文档。

## 刻意不做的事

- **不做共享、不做分组、不做角色。** v1 是一账号一本地址簿。客户端的共享配置与
  设备组端点（`/api/ab/shared/profiles`、`/api/device-group/accessible`、
  `/api/users`、`/api/peers`）未实现，客户端会把它们的缺失理解为"没有共享地址
  簿"，而不是报错。
- **不做冲突解决。** 后写覆盖。同一账号下两台设备推送会互相覆盖，这与官方服务端
  的行为一致。
- **服务端不做加密。** 文档内含客户端生成的密码哈希，按原样存储。数据库应按机密
  对待，与账号密码哈希同等处理。

## 门禁

- `tests/auth_server.rs` —— 先拉后推返回 `null`、推送逐字节往返、损坏的推送被拒
  且不破坏既有文档、未认证拉取为 401。
- `src/auth_server.rs` 单测 —— 文档原样存取，第二次推送是替换而非累积。
- 把拉取改成返回空文档，e2e 会以
  `the document must round-trip unchanged` 失败。
