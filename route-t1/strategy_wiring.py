"""Route T1 (Strategy v1) wiring edits for the standalone tree.

Run from the repository root: python3 route-t1/strategy_wiring.py
"""

from pathlib import Path

# ---------- src/lib.rs: declare the module ----------
p = Path("src/lib.rs")
c = p.read_text(encoding="utf-8")
if "mod strategy;" not in c:
    old = "mod secure_tcp;\n"
    assert c.count(old) == 1, "lib anchor"
    c = c.replace(old, "mod secure_tcp;\nmod strategy;\n")
    p.write_text(c, encoding="utf-8")
    print("lib.rs: strategy declared")

# ---------- src/connection_auth.rs: override chain + audit group ----------
p = Path("src/connection_auth.rs")
c = p.read_text(encoding="utf-8")

# wrapper signature: accept the target check and pass override + group
old = (
    "pub(crate) async fn authorize_connection_attempt(\n"
    "    token: &str,\n"
    "    kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    effective_ip: IpAddr,\n"
    ") -> AuthDecision {\n"
    "    let decision =\n"
    "        authorize_connection_attempt_inner(token, kind, transport, effective_ip).await;\n"
    "    crate::audit_log::record_decision(\n"
    "        kind,\n"
    "        transport,\n"
    "        &decision,\n"
    "        &effective_ip.to_string(),\n"
    "    );\n"
    "    decision\n"
    "}"
)
new = (
    "pub(crate) async fn authorize_connection_attempt(\n"
    "    token: &str,\n"
    "    kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    effective_ip: IpAddr,\n"
    "    target: &crate::strategy::TargetCheck,\n"
    ") -> AuthDecision {\n"
    "    let decision = authorize_connection_attempt_inner(\n"
    "        token,\n"
    "        kind,\n"
    "        transport,\n"
    "        effective_ip,\n"
    "        target.required_scope.as_deref(),\n"
    "    )\n"
    "    .await;\n"
    "    crate::audit_log::record_decision(\n"
    "        kind,\n"
    "        transport,\n"
    "        &decision,\n"
    "        &effective_ip.to_string(),\n"
    "        &target.group,\n"
    "    );\n"
    "    decision\n"
    "}"
)
assert c.count(old) == 1, "wrapper anchor"
c = c.replace(old, new)

# inner signature: carry the override
old = (
    "async fn authorize_connection_attempt_inner(\n"
    "    token: &str,\n"
    "    _kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    _effective_ip: IpAddr,\n"
    ") -> AuthDecision {"
)
new = (
    "async fn authorize_connection_attempt_inner(\n"
    "    token: &str,\n"
    "    _kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    _effective_ip: IpAddr,\n"
    "    required_scope_override: Option<&str>,\n"
    ") -> AuthDecision {"
)
assert c.count(old) == 1, "inner signature anchor"
c = c.replace(old, new)

# authorize_at call passes the override down
old = "    let result = runtime.authorize_at(token, now).await;"
new = "    let result = runtime.authorize_at(token, now, required_scope_override).await;"
assert c.count(old) == 1, "authorize_at call anchor"
c = c.replace(old, new)

# authorize_at signature
old = "    async fn authorize_at(&self, token: &str, now: u64) -> Result<(), &'static str> {\n        let local = self.verify_local_at(token, now)?;"
new = (
    "    async fn authorize_at(\n"
    "        &self,\n"
    "        token: &str,\n"
    "        now: u64,\n"
    "        required_scope_override: Option<&str>,\n"
    "    ) -> Result<(), &'static str> {\n"
    "        let local = self.verify_local_at(token, now, required_scope_override)?;"
)
assert c.count(old) == 1, "authorize_at anchor"
c = c.replace(old, new)

# verify_local_at signature
old = "    fn verify_local_at(&self, token: &str, now: u64)"
new = "    fn verify_local_at(&self, token: &str, now: u64, required_scope_override: Option<&str>)"
assert c.count(old) == 1, "verify_local_at anchor"
c = c.replace(old, new)

# scope check honours the override, with a distinct group reason
old = """        if !claims.scope.contains(&self.config.required_scope) {
            return Err("missing_scope");
        }"""
new = """        let required_scope = required_scope_override
            .unwrap_or(self.config.required_scope.as_str());
        if !claims.scope.contains(required_scope) {
            return Err(if required_scope_override.is_some() {
                "missing_group_scope"
            } else {
                "missing_scope"
            });
        }"""
assert c.count(old) == 1, "scope check anchor"
c = c.replace(old, new)

# verify_local_at test call sites inside connection_auth
c = c.replace(
    ".verify_local_at(\"not-a-compact-jwt\", 1_893_456_000)",
    ".verify_local_at(\"not-a-compact-jwt\", 1_893_456_000, None)",
)
c = c.replace(
    ".verify_local_at(&fixture(\"active\"), 1_893_456_000)",
    ".verify_local_at(&fixture(\"active\"), 1_893_456_000, None)",
)
c = c.replace(
    ".verify_local_at(&active, 1_893_456_000)",
    ".verify_local_at(&active, 1_893_456_000, None)",
)
p.write_text(c, encoding="utf-8")
print("connection_auth: override chain wired")

# ---------- src/audit_log.rs: group field (additive) ----------
p = Path("src/audit_log.rs")
c = p.read_text(encoding="utf-8")

old = (
    "    pub(crate) client_ip: String,\n"
    "    pub(crate) mode: &'static str,\n"
)
new = (
    "    pub(crate) client_ip: String,\n"
    "    pub(crate) mode: &'static str,\n"
    "    pub(crate) group: String,\n"
)
assert c.count(old) == 1, "audit fields anchor"
c = c.replace(old, new)

old = (
    "            self.verdict,\n"
    "            json_escape(&self.reason),\n"
    "            json_escape(&self.client_ip),\n"
    "            self.mode,\n"
    "        )"
)
new = (
    "            self.verdict,\n"
    "            json_escape(&self.reason),\n"
    "            json_escape(&self.client_ip),\n"
    "            self.mode,\n"
    "            json_escape(&self.group),\n"
    "        )"
)
assert c.count(old) == 1, "to_jsonl anchor"
c = c.replace(old, new)

old = (
    "        format!(\n"
    "            \"{{\\\"ts\\\":{},\\\"kind\\\":\\\"{}\\\",\\\"transport\\\":\\\"{}\\\",\\\"verdict\\\":\\\"{}\\\",\\"
    "             \\\"reason\\\":\\\"{}\\\",\\\"client_ip\\\":\\\"{}\\\",\\\"mode\\\":\\\"{}\\\"}}\\n\","
)
new = (
    "        format!(\n"
    "            \"{{\\\"ts\\\":{},\\\"kind\\\":\\\"{}\\\",\\\"transport\\\":\\\"{}\\\",\\\"verdict\\\":\\\"{}\\\",\\"
    "             \\\"reason\\\":\\\"{}\\\",\\\"client_ip\\\":\\\"{}\\\",\\\"mode\\\":\\\"{}\\\",\\\"group\\\":\\\"{}\\\"}}\\n\","
)
assert c.count(old) == 1, "format anchor"
c = c.replace(old, new)

# record_decision: take group
old = (
    "pub(crate) fn record_decision(\n"
    "    kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    decision: &AuthDecision,\n"
    "    client_ip: &str,\n"
    ") {"
)
new = (
    "pub(crate) fn record_decision(\n"
    "    kind: ConnectionAttemptKind,\n"
    "    transport: SignalTransport,\n"
    "    decision: &AuthDecision,\n"
    "    client_ip: &str,\n"
    "    group: &str,\n"
    ") {"
)
assert c.count(old) == 1, "record_decision anchor"
c = c.replace(old, new)

old = "        mode: mode_label(&decision.mode),\n    });"
new = "        mode: mode_label(&decision.mode),\n        group: group.to_owned(),\n    });"
assert c.count(old) == 1, "record event anchor"
c = c.replace(old, new)

# parser: group optional (absent on older files)
old = '''    Some(AuditEvent {
        epoch_seconds: field(0).parse().ok()?,
        kind: kind_from_label(&field(1))?,
        transport: transport_from_label(&field(2))?,
        verdict: leak_verdict(&field(3))?,
        reason: json_unescape(&field(4)),
        client_ip: json_unescape(&field(5)),
        mode: mode_label(&mode_from_label(&extract_field(line, "\\"mode\\":\\"")?)?),
    })'''
new = '''    Some(AuditEvent {
        epoch_seconds: field(0).parse().ok()?,
        kind: kind_from_label(&field(1))?,
        transport: transport_from_label(&field(2))?,
        verdict: leak_verdict(&field(3))?,
        reason: json_unescape(&field(4)),
        client_ip: json_unescape(&field(5)),
        mode: mode_label(&mode_from_label(&extract_field(line, "\\"mode\\":\\"")?)?),
        group: extract_field(line, "\\"group\\":\\"").unwrap_or_else(|_| "general".to_owned()),
    })'''
assert c.count(old) == 1, "parser anchor"
c = c.replace(old, new)

p.write_text(c, encoding="utf-8")
print("audit_log: group field added")
