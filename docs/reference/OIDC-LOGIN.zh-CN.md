# OIDC 登录 —— 给 RustDesk 客户端的单点登录

状态：已实现
[English](OIDC-LOGIN.md) | 简体中文

## 做什么

`starry-api` 可以把用户交给外部身份提供者认证，然后自己签发 EdDSA 连接令牌。
客户端登录页因此多出提供者按钮；客户端看不到 IdP 的令牌，`hbbs` 也无从得知
这次登录走了单点登录。

这是"人在别处认证，凭据仍由我们签发"的切分。连接能做什么仍由 Starry 决定；
IdP 只回答这个人是谁。

## 线上契约

已对照官方客户端（rustdesk master 的 `src/hbbs_http/account.rs`、
`flutter/lib/models/user_model.dart`）核实。这是一个带轮询半程的设备码流程，
其中四个细节是承重的：

### 1. 声明提供者

`GET /api/login-options` 返回 `List<String>`。存在两种前缀：

- `oidc/<name>` —— 单个提供者，无图标
- `common-oidc/<json 数组>` —— 每项 `{name, icon}`

客户端**先**检查 `common-oidc/`，因此 Starry 用这种形式作答：

```json
["common-oidc/[{\"name\":\"azure\",\"icon\":\"microsoft\"}]"]
```

空数组（`[]`）表示"只有密码登录"，未配置任何提供者时就是这个结果。

### 2. 发起登录

```
POST /api/oidc/auth
{"op":"azure","id":"<设备 id>","uuid":"<设备 uuid>",
 "deviceInfo":{"os":"Linux","type":"client","name":"..."},"apiDomain":"..."}
```

响应：

```json
{"code":"<不透明串>","url":"https://idp.example/authorize?..."}
```

客户端在浏览器里打开 `url`，并以 `code` 每秒轮询一次，最长三分钟。

### 3. 轮询

```
GET /api/oidc/auth-query?code=<code>&id=<设备 id>&uuid=<设备 uuid>
```

响应是**被包裹**的：

```json
{"body": "{\"error\": \"No authed oidc is found\"}"}
```

先解析外层对象，再解析内层字符串。客户端依据内层载荷的形状判断成败，而不是
HTTP 状态码：

- 内层对象带 `error` 键：值中含 `No authed oidc is found` 时继续等待，否则停止
  并显示该错误；
- 内层对象没有 `error`：这就是凭据文档。

正因为这个子串匹配，尚未完成的登录绝不能返回别的文字——任何其他错误文本都会
让客户端直接放弃。

### 4. 凭据

浏览器半程完成后，轮询返回与 `/api/login` 相同的文档：

```json
{"access_token":"<EdDSA JWT>","type":"access_token","tfa_type":"","secret":"",
 "user":{"name":"alice","display_name":"Alice","avatar":"","email":"a@b.test",
         "note":"","status":1,"is_admin":false,"info":{}}}
```

`access_token` **就是**连接凭据：客户端原样把它当作
`PunchHoleRequest.token` / `RequestRelay.token` 发回。它只签发**一次**——同一
`code` 再轮询会得到 `No authed oidc is found`，因为用过的 code 不能再铸出第二个
凭据。

## 浏览器半程

`GET /oidc/callback?code=...&state=...` 是 IdP 重定向落点。Starry 随后：

1. 按 `state` 找到待完成的登录，未知或过期的一律拒绝；
2. 用保存的 PKCE verifier 在提供者的令牌端点兑换 code；
3. 拉取提供者 JWKS 并验证 id_token 签名；
4. 校验声明；
5. 记录已完成的登录，供客户端下一次轮询取走。

## 安全性质

| 性质 | 手段 |
| --- | --- |
| 回调 CSRF | `state` 每次登录随机生成且必须与签发值一致；不匹配无法完成登录 |
| code 拦截 | PKCE `S256`；verifier 从不离开服务端，因此仅观察重定向不足以兑换 code |
| 跨登录重放 | id_token 的 `nonce` 必须等于本次登录签发的那一个 |
| 伪造令牌 | 只接受 RS256/384/512 与 ES256/384；拒绝 `none` 与 HMAC 家族，因为用 HMAC 时任何持有 `client_id` 的人都能造出令牌 |
| issuer / audience 错配 | `iss` 必须等于配置的 issuer，`aud` 必须包含 `client_id` |
| 无界令牌 | `exp` 为必需；缺失的令牌被拒绝而不是被当作长期有效 |
| 时钟偏差 | `exp` 与 `iat` 只容许 60 秒 |
| 发现文档被劫持 | 发现文档与 JWKS 请求不跟随重定向，且文档里的 `issuer` 必须与配置一致 |
| 身份被顶替 | 绑定键是 `(provider, subject)`，绝不使用邮箱；重名会新建带后缀的账号，而不是挂到既有账号上 |
| 待处理状态无界 | 最多 1024 个在途登录；插入时清掉过期项 |

### 刻意不做的事

- **不做组或角色映射。** 声明不分配 scope。授权仍归策略文档，因此 IdP 被攻破
  也无法放大权限。
- **不转发令牌。** IdP 的令牌只用于读取声明，随后丢弃。
- **不刷新。** 与密码登录一样，令牌有效期为
  `STARRY_API_TOKEN_TTL_SECONDS`，之后用户重新登录。
- **SSO 用户没有本地密码。** 首次登录创建的账号带一个从不返回的随机密码，
  因此无法用 `/api/login` 登录它。

## 配置

```json
{
  "request_ttl_seconds": 180,
  "providers": [
    {
      "name": "azure",
      "icon": "microsoft",
      "issuer": "https://login.microsoftonline.com/<tenant>/v2.0",
      "client_id": "...",
      "client_secret": "...",
      "redirect_uri": "https://rustdesk.example.network/oidc/callback",
      "scopes": ["profile"],
      "username_claim": "preferred_username",
      "allowed_email_domains": ["example.test"],
      "require_verified_email": true
    }
  ]
}
```

把 `STARRY_OIDC_CONFIG` 指向该文件。不设置即关闭 OIDC，`/api/login-options`
保持 `[]`。

字段说明：

- `name` 是 slug（`[A-Za-z0-9_-]`）。它会出现在 `common-oidc` 的 JSON 里并以
  `op` 回来，其他字符会让往返产生歧义。
- `issuer` 与 `redirect_uri` 必须是 `https`，唯一例外是回环主机的 `http`，
  以便本地测试提供者可用。主机是被解析后比较的，不是前缀匹配，因此
  `http://127.0.0.1.evil.test` 会被拒绝。
- `client_secret` 可选：公开客户端用 PKCE，不需要它。
- `allowed_email_domains` 为空表示"任意域"。设置后可把部署限制在一个组织内。
- `require_verified_email` 失败即拒绝：缺失 `email_verified` 声明不视为通过。

在 IdP 侧登记的 redirect URI 必须是 `https://<api 主机>/oidc/callback`。

## 门禁

- `src/oidc.rs` 单测 —— issuer/audience/nonce 错配、过期、时钟偏差、缺 `exp`、
  `iat` 在未来、域名白名单、邮箱已验证、用户名回落；对照 RFC 7636 向量验证
  PKCE；只接受非对称算法；待处理登录的一次性完成、state 错配、过期、容量；
  回环 http 通过而形似主机被拒。
- `tests/oidc_login.rs` —— 一个写在 socket 上的手写身份提供者驱动真实
  `starry-api` 二进制走完客户端的确切序列：options → start → 未完成时轮询 →
  authorize → 回调 → 轮询取凭据 → 再次轮询为空。
- 变异已验证：移除 nonce 校验会让
  `oidc_callback_refuses_a_token_with_a_bad_nonce` 失败；让已完成的登录不被消费
  会让 `oidc_login_round_trip_mints_a_usable_access_token` 失败；去掉
  `{"body": ...}` 包裹会让同一测试失败。
