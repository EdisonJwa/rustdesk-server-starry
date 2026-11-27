# V3 路线图核实 —— 哪些"已知问题"仍成立

状态：2026-11-27 针对 `27dab9f`（分支 `deploy/standalone-webrtc`，已推 `standalone-dev`）编写
[English](V3-ROADMAP-CHECK.md) | 简体中文

V3 路线图固定在 `2f007ee`，列出九条已知问题外加一个 CI 阻塞。此后有工作落地，因此
该清单已部分过期。本文记录针对当前源码树重新核实的结果：哪些已修、哪些仍成立——
以便路线图重新定基线时不必重新推导。

## CI 阻塞已修复

`Keep Starry's hbb_common changes exactly as recorded` 步骤因
`Only in _vendor_check/hbb_common/tests: data` 失败。

根因：`libs/hbb_common/tests/data/websocket-{cert,key}.pem` 被
`src/websocket/proxy_tests.rs` 与两个集成测试以 `include_bytes!` 引用，却从未纳入
版本跟踪。CI 会重建上游原始 commit、应用 `libs/hbb_common.starry.patch` 再跑
`diff -r`，缺失目录因此表现为差异，并在编译前就让任务失败。

修复（`01abcf6`）：两个文件以上游的精确字节纳入跟踪。`.gitattributes` 标记为
`-text -diff`——CI 比较的是字节，检出时绝不能做换行转换。

本地复现 CI 步骤已验证：only-in 差异归零。该次本地复现中剩下的差异来自 patch 在
CRLF 工作树里打不上，属 Windows 检出产物；CI 在 Linux runner 上应用该 patch。

## 逐条核实

| # | 路线图说法 | `27dab9f` 的实际状态 |
| --- | --- | --- |
| 1 | 策略加载失败会关闭引擎但 HBBS 仍启动 | **已修。** 策略为必需时（`STARRY_STRATEGY_REQUIRED=1` 或 `MUST_LOGIN` 下限）`strategy::startup()` fail-closed；兼容部署仍记录日志后继续。会使受管部署失去策略的运行时重载会被拒绝。 |
| 2 | `default_group` 分支不继承 `deny` / `require_scope` | **已修。** 默认组现在按真实分组解析，未命中规则的设备继承其判定。原先只读组名，把"默认拒绝"的文档变成了全放行。 |
| 3 | 认证关闭时 `require_scope` 不强制，Audit 下仅记录 | **仍成立，且是设计如此。** 兼容模式不强制身份；组 scope 只在连接认证评估 token 时约束。已作为"兼容 / 受管"分工记录，而非"修复"。 |
| 4 | 策略拒绝绕过结构化审计；CSV 缺 `group` | **已修。** `audit_log::record_strategy_denial()` 记录 verdict `deny` 并带上组名，CSV 导出包含文档已描述的 `group` 列。 |
| 5 | HBBR `/healthz` 恒返回 200，无法证明可接受新连接 | **仍成立。** 本次未处理。 |
| 6 | 官方 `RequestRelay` 可能沿用旧地址；不得在一端已连接后重新分配 | **部分处理，症状不同。** `7290f29` 修的是：客户端留空中继时服务端从不填地址（fast_relay 关闭时，文档推荐的空中继配置根本无法连接）。"一端连接后不得重新分配"这条不变量仍待验证。 |
| 7 | Auth Server V1 文档用 `user_info` / `current-user`，与客户端契约不符 | **已修。** 实现与双语文档现使用 `user`、`POST /api/currentUser`、`login-options` 返回 JSON 数组，并把登录返回的 `access_token` 本身当作连接凭据。 |
| 8 | `relay_observer`、控制 API、配置 schema 与遥测对归档扩展存在交叉依赖 | **仍成立。** 直接删模块会如路线图所警告的那样破坏可用的通用功能。 |
| 9 | Control Agent 合并进 HBBS 会收窄进程与文件权限隔离 | **仍成立。** 未尝试合并；路线图自身的 CP-04 备选（保留独立 Agent）仍是默认。 |

## 对规划的含义

在定基线时就有两项已过期（7 在定基线前就修好了；1、2、4 与 CI 阻塞现在已修）。
第 3、5、8、9 条确实仍未解决，第 6 条半解决且失败模式与路线图预判不同。

路线图基线应在下次规划前移到 `27dab9f`，FND-01/FND-02 可连同提交里点名的测试
一起标记为完成。

## 每项修复靠什么守住

| 修复 | 测试 |
| --- | --- |
| 默认组判定 | `src/strategy.rs` 单测经 `check_target` 解析；回退该解析会让两条测试以"判定未生效"的症状失败 |
| 启动 fail-closed | `src/strategy.rs` 针对文档损坏与未配置的单测；另在生产二进制上确认 |
| 拒绝进审计 | `AuditEvent` 形状单测；e2e 断言已注册目标被策略分支拒绝（回退审计调用会让它失败） |
| 留空中继获得地址 | `tests/relay_selection.rs` 配真实 hbbr；回退即以生产症状失败 |
| vendor fixtures | 本地复现 CI 步骤，差异计数为 0 |

审计 writer 是进程级 `OnceLock`，因此同一测试二进制里不能由多个测试断言审计输出：
谁先产出事件就固定了目录。这就是为什么"拒绝被记录"的证据拆成 `AuditEvent` 单测
与 e2e 的可达性断言，而不是单一的端到端文件检查。
