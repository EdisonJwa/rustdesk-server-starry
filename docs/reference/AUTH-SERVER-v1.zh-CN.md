# 认证服务器 v1 —— 账号、登录与连接 token

状态：已实现（路线 P0）
[English](AUTH-SERVER-v1.md) | 简体中文

## 是什么

`starry-api` 是轻量级的 RustDesk 兼容 API 服务器（端口 21114），补全认证闭环：

1. **用户账号**（SQLite + bcrypt）与本地密码登录。
2. **官方客户端登录契约**：1.5 客户端解析的 `POST /api/login` 响应，
   外加 `GET /api/login-options`、`POST /api/currentUser`、`POST /api/logout`。
   配置 API 服务器后，客户端不再产生 ":21114 Connection refused" 噪音或
   响应解析错误，且账号在重启后保持登录。
3. **连接 token**：`/api/login` 返回的 `access_token` **本身**就是 Ed25519
   签名的 JWT（`typ: at+jwt`）——因为官方客户端会把它原样存下来，并在连接时
   作为 `PunchHoleRequest.token` / `RequestRelay.token` 发回。
4. **HBBS 强制模式**：把 Starry 配置的 `connection_auth.jwks.file` 指向本服务
   发布的 JWKS，并设 `connection_auth.mode: enforce`。HBBS 随即拒绝缺失/伪造/
   过期/缺少所需 scope 的连接。Strategy v1 的分组规则在其之上生效。

v1 的边界：这是凭据签发者，不是 OIDC 身份提供者。企业 SSO（OIDC/LDAP）与
TOTP 属 v1.1；用户表已备好所需字段（`status`、`auth_version`、`extra_scopes`）。

## 线契约（已对照 rustdesk 1.5.x 客户端源码核实）

| 方法 | 路径 | 认证 | 请求 → 响应 |
| --- | --- | --- | --- |
| GET | `/api/login-options` | 无 | `[]` —— JSON **数组**（第三方登录提供者）；空数组表示仅密码登录 |
| POST | `/api/login` | 无 | `{username, password, id, uuid, autoLogin, type:"account", deviceInfo}` → `{access_token, type:"access_token", user:{name, display_name, avatar, email, note, status, is_admin, info}}` |
| POST | `/api/currentUser` | Bearer | `{id, uuid}` → 扁平 `UserPayload`；`401` 会让客户端退出登录 |
| POST | `/api/logout` | Bearer | 吊销会话；返回 `null` |
| POST | `/api/connection-token` | Bearer | `{token, expires_in}` —— 供脚本与非官方客户端使用的短期 JWT |
| POST | `/api/introspect` | 无 | `{token}` → `{active, sub, reason}`（RFC 7662 形态，供 HBBS 可选校验器） |
| GET | `/api/ab` | Bearer | `null` —— 客户端约定的"无通讯录"回复，让通讯录页在 P1 之前保持干净 |
| GET | `/healthz` | 无 | `{"status":"live"}` |

错误统一为 `{"error": "<code>"}` 加非 2xx 状态，例如 `UsernameOrPasswordError`
（客户端直接展示该串）、`UserDisabled`、`TooManyAttempts`、`ParamsError`。

每个 token 携带（HBBS 全部会校验）：`iss`、`aud`、`token_use: "access"`、
`scope`、`sub == user_id`、`user_id != 0`、`auth_version != 0`、`jti`（UUID）、
`iat`、`nbf`、`exp`。

## 配置

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `STARRY_API_LISTEN` | `0.0.0.0:21114` | 绑定地址。 |
| `STARRY_API_DB` | `<cwd>/users.db` | SQLite 数据库（用户 + 会话）。 |
| `STARRY_API_KEY_FILE` | `<cwd>/api-signing-key` | Ed25519 私钥，base64(64 字节)，与 `id_ed25519` 同格式；首启自动生成，权限 0600。 |
| `STARRY_API_JWKS_FILE` | `<cwd>/auth/jwks.json` | 发布给 HBBS 的 JWKS；同目录写入摘要绑定的 `<file>.metadata.json` 新鲜度戳。 |
| `STARRY_API_ISSUER` | `https://api.starry.local` | `iss`；**必须是 HTTPS URL**，且与 HBBS 的 `connection_auth.issuer` 完全一致。 |
| `STARRY_API_AUDIENCE` | `rustdesk-connect` | `aud`；与 HBBS 的 `connection_auth.audience` 一致。 |
| `STARRY_API_SCOPE` | `connect:initiate` | 基础 scope；用户级 `--scopes` 会合并进来。 |
| `STARRY_API_TOKEN_TTL_SECONDS` | `604800`（7 天） | 登录 token 有效期，同时就是连接凭据有效期：客户端不会刷新，过期后重新登录。 |
| `STARRY_API_CONNECTION_TOKEN_TTL_SECONDS` | `3600` | `/api/connection-token` 的有效期。 |
| `STARRY_API_JWKS_HEARTBEAT_SECONDS` | `300` | 新鲜度戳续签间隔；必须小于 HBBS 的 `max_stale_seconds`（默认 3600，且 ≥30）。 |
| `STARRY_API_BCRYPT_COST` | `12` | bcrypt 代价（4–15）。 |
| `ADMIN_PASSWORD` | 未设 | 引导创建/更新 `admin` 账号；未设则不动既有账号；值变化会 bump `auth_version`，吊销旧会话。 |
| `STARRY_API_TRUST_PROXY` | `0` | 置于 TLS 终结器之后时，按 `X-Forwarded-For` 做登录限速。 |

## 账号管理

```sh
# 创建账号（密码来自 STDIN 或 STARRY_API_NEW_PASSWORD，绝不走 argv）
printf '%s\n' "$PASSWORD" | starry-api user add alice --display-name "Alice"
starry-api user add contractor --scopes "connect:group:contractors"
starry-api user list
starry-api user passwd alice     # bump auth_version：旧 token 立即失效
starry-api user disable alice    # status 0 + bump auth_version
```

密码至少 8 字符。登录按客户端地址限速（10 次失败 / 5 分钟），且未知用户名
同样执行 bcrypt 比对，避免用响应时间判断账号是否存在。

## 部署

`deploy/systemd/install-starry-api.sh` 负责安装二进制、初始化 admin 账号、落盘
`starry-api.service` 并重启两个单元；单元文件本身
（`deploy/systemd/starry-api.service`）注释了每个环境变量。

与 HBBS 并列运行 `starry-api.service`。首启写出的 JWKS 就是 HBBS 的校验目标：

```yaml
# /var/lib/starry/data/starry/config.yaml
connection_auth:
  mode: audit            # 真实客户端往返验证通过前保持 audit
  issuer: https://api.starry.local
  audience: rustdesk-connect
  token_use: access
  required_scope: connect:initiate
  jwks:
    file: auth/jwks.json # 相对于该配置文件所在目录
```

客户端通过 `http://<host>:21114` 访问 API。密码不应在不可信网络上明文传输，
请在前置 TLS 终结器（此时设 `STARRY_API_TRUST_PROXY=1`，客户端 API Server 填
HTTPS 地址）。

### JWKS 新鲜度规则

HBBS 在 keyset 戳超过 `connection_auth.jwks.max_stale_seconds` 后会 fail closed，
所以运行中的签发者必须持续续签。`starry-api` 每个心跳重写 `jwks.json` 与
`jwks.json.metadata.json`（version、`fetched_at_epoch_seconds`、`jwks_sha256`）；
HBBS 在自己的刷新周期里重新读取文件并采纳签发者的戳。由此：

- `starry-api` 停止超过 `max_stale_seconds` 后，HBBS 开始拒绝新连接——这是
  设计使然（fail closed）。请保持服务运行，或按停机容忍度调大 `max_stale_seconds`。
- 密钥轮换是在线且原子的：替换密钥文件并重启 `starry-api`，HBBS 下一次刷新
  即采纳新 kid。

### 吊销语义

登出与禁用对所有 API 端点立即生效。对**连接**路径而言，已签发的 JWT 在 `exp`
之前仍然密码学有效，除非给 HBBS 配置 `connection_auth.introspection.url` 指向
`/api/introspect`（HBBS 要求 HTTPS + mTLS）。三选一：

- 缩短 `STARRY_API_TOKEN_TTL_SECONDS`（用户更早重新登录）；
- 启用 HBBS introspection（即时吊销，基础设施更重）；
- 紧急全量吊销：轮换签名密钥。

## 验证

`tests/auth_server.rs` 启动真实二进制并断言完整契约：login-options 形态、
错误密码拒绝、登录响应形态、JWT 头部声明、对发布 JWKS 的签名校验、新鲜度
sidecar 摘要、`currentUser`、登出吊销，以及决定性门禁——真实 `hbbs` 在
`enforce` 模式下接受 API 签发的 token，同时拒绝匿名与伪造 token 的打洞请求。
