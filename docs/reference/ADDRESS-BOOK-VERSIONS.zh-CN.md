# 旧版地址簿 —— 版本与丢失更新

状态：已实现（2026-11-28）
[English](ADDRESS-BOOK-VERSIONS.md) | 简体中文

## 解决的是什么

官方客户端的 `pushAb` 推送**整份**地址簿，且从不发前置条件。已对照
`flutter/lib/models/ab_model.dart` 核实：

```dart
final body = jsonEncode({"data": jsonEncode(_serialize())});
http.Response resp = await http.post(Uri.parse(api), headers: authHeaders, body: body);
```

因此两台设备编辑同一账号必然丢一边：后写覆盖，输的一方不留痕迹。这是客户端的
模型，服务端改不了。

服务端**能**做的，是让这次丢失可见、可恢复。本功能就是这些。

## 加了什么

### 每账号一个版本号

`GET /api/ab` 在响应体不变的前提下新增两个头：

| 头 | 含义 |
| --- | --- |
| `ETag` | `"ab-<version>"`，带引号的实体标签 |
| `x-ab-version` | 同一个数字，不带引号，便于脚本读取 |

从未写入过的簿是版本 `0`。响应体与客户端历来解析的逐字节相同，且客户端会忽略
未知头——这正是这个改动对官方客户端安全的原因。

改变文档的写入必然让版本递增。与已存储内容相同的写入**不**递增、也不算作覆盖，
因为客户端每次本地编辑都会重推，不能让它看起来与自己冲突。

### 可选的前置条件

`POST /api/ab` 接受 `If-Match`。发了它，调用方就是主动选择了这项检查；没发
（官方客户端）则行为与从前完全一致。

| 情况 | 答案 |
| --- | --- |
| 无 `If-Match`，或 `*` | 照常写入，后写覆盖 |
| `If-Match` 与存储版本一致 | 照常写入 |
| `If-Match` 不一致 | **412** `{"error":"AddressBookChanged"}`，并带当前 `ETag` |
| `If-Match` 格式非法 | **400** `{"error":"InvalidIfMatch"}` |

用 412 而非 409：RFC 7232 要求 `If-Match` 失败返回 `Precondition Failed`，
而在 409 上重试的客户端会陷入循环。

格式非法一律拒绝而不是忽略。忽略会让调用方以为自己有它并不具备的保护，比失败更糟。

### 被覆盖文档的恢复

`GET /api/ab/previous`：

```json
{"data": "<上一次写入覆盖掉的文档>", "version": 3, "superseded_count": 2}
```

若从未发生过覆盖：

```json
{"data": null, "superseded_count": 0}
```

`superseded_count` 是"丢弃了**不同**文档"的写入次数。非零意味着这本簿正被多处
编辑——问题本来不可见的症状。

每次覆盖写入还会记一条 `warn` 日志，写明账号与新版本号，运维不必轮询即可看到。

## 刻意不做的事

- **不做合并。** 对客户端拥有的 JSON 文档做服务端三方合并，需要深刻理解
  `{tags, peers, tag_colors}`，而那个 schema 按设计归客户端所有。拒绝或上报是
  诚实的；猜一个合并结果不是。
- **不强制客户端处理冲突。** 客户端发不了前置条件，强制要求会打断它所有推送。
- **不保留多代历史。** 为一份含密码哈希的载荷保留完整历史是数据留存负担，而没有
  查询需求来支撑它。一代可恢复，是人真正能处理的数量。

## 门禁

- `src/auth_server.rs` 单测 —— ETag 是带引号的实体标签；缺失或 `*` 前置条件不
  断言任何版本；格式非法的 `If-Match` 被拒绝而非忽略。
- `tests/api_endpoints.rs` —— 簿不存在时读到 `null`；同一文档重推不算冲突；
  过期前置条件得到 412 与当前 `ETag`，而匹配的那一个成功；被覆盖的文档可恢复
  且被计数；未认证调用读不到任何人的上一版；非法前置条件是 400。
- 变异验证两项：丢弃被覆盖文档会让 `a_replaced_document_is_recoverable` 失败并
  点名丢失的笔记本簿；忽略前置条件会让 `a_stale_precondition_is_refused_with_412`
  在应返回 `412` 处返回 `200`。
