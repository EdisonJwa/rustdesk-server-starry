# V3 roadmap check — which "known issues" still hold

Status: written 2026-11-27 against `27dab9f` (branch `deploy/standalone-webrtc`,
pushed to `standalone-dev`).
English | [简体中文](V3-ROADMAP-CHECK.zh-CN.md)

The V3 roadmap is pinned to `2f007ee` and lists nine known issues plus one CI
blocker. Work landed after that pin, so the list is partly stale. This file
records what was re-checked against the current tree, what was fixed, and what
remains — so the roadmap can be re-pinned without re-deriving it.

## The CI blocker is fixed

`Keep Starry's hbb_common changes exactly as recorded` failed with
`Only in _vendor_check/hbb_common/tests: data`.

Cause: `libs/hbb_common/tests/data/websocket-{cert,key}.pem` are loaded by
`src/websocket/proxy_tests.rs` and two integration tests via `include_bytes!`,
but were never tracked. CI reconstructs the pristine upstream commit, applies
`libs/hbb_common.starry.patch`, and runs `diff -r`, so the missing directory
surfaced as a difference and failed the job before compilation.

Fix (`01abcf6`): both files are tracked with their exact upstream bytes.
`.gitattributes` marks them `-text -diff` — CI compares bytes, so a checkout must
never convert their line endings.

Verified by reproducing the CI steps locally: the only-in difference is gone.
The remaining diff in that local reproduction came from the patch failing to
apply inside a CRLF worktree, which is a Windows-checkout artifact; CI applies it
on a Linux runner.

## Issue-by-issue

| # | Roadmap claim | Status at `27dab9f` |
| --- | --- | --- |
| 1 | Strategy load failure can disable the engine and still start HBBS | **Fixed.** `strategy::startup()` fails closed when the policy is required (`STARRY_STRATEGY_REQUIRED=1` or the `MUST_LOGIN` floor); compatibility deployments still log and continue. Runtime reloads that would leave a managed deployment without a policy are refused. |
| 2 | `default_group` branch does not inherit `deny` / `require_scope` | **Fixed.** The default group is now resolved as a real group, so an unmatched device inherits its verdict. Previously only the name was read, turning a deny-by-default document into allow-all. |
| 3 | `require_scope` is not enforced when auth is Off, and only logged in Audit | **Still true, by design.** Compatibility mode does not force identity; group scopes bind only when connection auth evaluates tokens. Documented as the Compatibility vs Managed split rather than "fixed". |
| 4 | Strategy deny bypasses structured audit; CSV lacks `group` | **Fixed.** `audit_log::record_strategy_denial()` records verdict `deny` with the group, and the CSV export carries the `group` column the docs already described. |
| 5 | HBBR `/healthz` always returns 200 and cannot prove new connections are acceptable | **Fixed, by splitting the probe rather than changing it.** `/healthz` stays 200 on purpose — it answers liveness, and restarting a draining or full relay destroys sessions without adding capacity. The new `/readyz` answers admission, returning 503 with `reason: draining` or `at_capacity`. Both call `relay_server::admission_decision`, so the probe cannot report "ready" while the peer path refuses the connection. See [RELAY-OPS-SURFACE](RELAY-OPS-SURFACE.md). |
| 6 | Official `RequestRelay` may reuse a stale address; must not re-assign one end mid-flow | **Partly addressed, different symptom.** `7290f29` fixed a blank client relay never receiving a server-selected address (with `fast_relay` off, the documented empty-relay setup could not connect at all). The "do not re-assign after one end connected" rule is still an open invariant to verify. |
| 7 | Auth Server V1 docs used `user_info` / `current-user` contrary to the client contract | **Fixed.** The implementation and both language docs now use `user`, `POST /api/currentUser`, a JSON array from `login-options`, and treat the login `access_token` itself as the connection credential. |
| 8 | `relay_observer`, control API, config schema and telemetry cross-depend on the archived extensions | **Still true.** Deleting modules directly would break working generic features, exactly as the roadmap warns. |
| 9 | Merging the Control Agent into HBBS narrows process and file-permission isolation | **Still true.** No merge attempted; the roadmap's own CP-04 escape hatch (keep the separate agent) remains the default. |

## What this means for planning

Two roadmap items were already stale at the pin (7 was fixed before it; 1, 2, 4
and the CI blocker are fixed now, and 5 later). Items 3, 8 and 9 remain genuinely
open, and 6 is half-open with a different failure mode than the roadmap
anticipated.

The baseline in the roadmap should move to `27dab9f` before the next planning
pass, and FND-01/FND-02 can be marked done with the tests named in the commits as
evidence.

## How each fix is held in place

| Fix | Test |
| --- | --- |
| Default group verdict | `src/strategy.rs` unit tests resolve through `check_target`; reverting the resolution fails both with the unenforced-verdict symptom |
| Fail-closed startup | `src/strategy.rs` unit tests for broken and unconfigured required policies; also confirmed on the production binary |
| Deny reaches audit | `AuditEvent` shape unit test; the e2e asserts a registered target is refused by the strategy branch (reverting the audit call fails it) |
| Blank relay gets an address | `tests/relay_selection.rs` with a real hbbr; reverting fails with the production symptom |
| Readiness distinct from liveness | `src/ops_surface.rs` unit tests over a pure `admission_decision`; making capacity never block fails three of them while the liveness test still passes |
| Vendor fixtures | CI step reproduced locally, difference count zero |

The audit writer is a process-wide `OnceLock`, so audit output cannot be asserted
from more than one test in the same binary: whichever emits first fixes the
directory. That is why the deny-recording evidence is split between an
`AuditEvent` unit test and the e2e's reachability assertion rather than a single
end-to-end file check.
