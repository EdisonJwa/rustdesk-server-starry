# 认证服务器 v1 —— 账号、登录与连接 token 签发

状态：已实现（路线 P0）
[English](AUTH-SERVER-v1.md) | 简体中文

## 是什么

`starry-api` 是轻量级的 RustDesk 兼容 API 服务器（端口 21114），补全认证闭环：

1. **用户账号**（SQLite + bcrypt 密码哈希）与本地登录。
2. **RustDesk 客户端登录契约**：`POST /api/login` 返回官方客户端解析的
   `user_info` + `access_token` 形态；`GET /api/login-options` 报告密码登录可用。
3. **连接 token 签发**：`POST /api/connection-token`（Bearer 会话）返回短期
   Ed25519 签名的 JWT（`scope: connect:initiate`），签名密钥对由服务首次启动
   生成，并以 JWKS 文件发布。
4. **HBBS 强制模式**：把 Starry 配置的 `connection_auth.jwks.file` 指向该
   JWKS 输出并设 `connection_auth.mode: enforce`——HBBS 即拒绝缺失/过期/
   组 scope 不足的连接 token。Strategy v1 的分组规则在其之上生效
   （按组 scope、整组拒绝）。

设计边界：API 服务器签发的是**连接** token，并非 OIDC 身份提供者。企业 SSO
（OIDC/LDAP）与 TOTP 属 v1.1（登录处理器与用户表已预留字段）。

## 配置

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `STARRY_API_LISTEN` | `0.0.0.0:21114` | HTTP API 绑定地址。 |
| `STARRY_API_DB` | `<cwd>/users.db` | SQLite 数据库（用户 + 会话）。 |
| `STARRY_API_KEY_FILE` | `<cwd>/api-signing-key` | Ed25519 私钥（base64，64 字节）；首启缺失则自动生成。 |
| `STARRY_API_JWKS_FILE` | `<cwd>/auth/jwks.json` | 发布给 HBBS `connection_auth.jwks.file` 的 JWKS。启动时写入。 |
| `ADMIN_PASSWORD` | 未设 | 启动时创建/更新 `admin` 用户；未设则不动既有用户。 |

## 端点

| 方法 | 路径 | 认证 | 请求 / 响应 |
| --- | --- | --- | --- |
| GET | `/api/login-options` | 无 | `{"hidden": false}` |
| POST | `/api/login` | 无 | `{username, password}` → `{user_info:{name,id}, access_token}`（bcrypt 校验，7 天会话） |
| GET | `/api/current-user` | Bearer 会话 | `{user_info:{name,id}}` |
| POST | `/api/connection-token` | Bearer 会话 | `{token}` —— EdDSA JWT，`exp` +1 小时，`scope: connect:initiate` |

`/api/login` 的线契约与官方 RustDesk 客户端解析的形态一致
（`user_info` + `access_token`）；v1 已对照 1.5 客户端响应 schema 做过契约
核对，**开启 enforce 模式前必须用真实客户端再做一次验证**。

## 部署

以 `starry-api.service` 与 hbbs 并列运行。其写出的 JWKS 文件就是 HBBS 校验
的目标，首启后：

```sh
# 把 HBBS 指向 API 发布的 JWKS
# （connection_auth.jwks.file: /var/lib/starry/data/auth/jwks.json）
sudo systemctl restart starry-hbbs
```

在真实客户端登录 + 连接 token 往返被观察到之前，保持
`connection_auth.mode: audit`；之后切换 `enforce`。
