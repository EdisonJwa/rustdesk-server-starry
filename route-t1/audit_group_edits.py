from pathlib import Path

p = Path("src/audit_log.rs")
c = p.read_text(encoding="utf-8")

old = (
    "    pub client_ip: String,\n"
    "    pub mode: &'static str,\n"
    "}"
)
new = (
    "    pub client_ip: String,\n"
    "    pub mode: &'static str,\n"
    "    pub group: String,\n"
    "}"
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
    "             \"reason\":\"{}\",\"client_ip\":\"{}\",\"mode\":\"{}\"}}\\n\","
)
new = (
    "             \"reason\":\"{}\",\"client_ip\":\"{}\",\"mode\":\"{}\",\"group\":\"{}\"}}\\n\","
)
assert c.count(old) == 1, "format anchor"
c = c.replace(old, new)

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

old = '''        mode: mode_label(&mode_from_label(&extract_field(line, "\\"mode\\":\\"")?)?),
    })'''
new = '''        mode: mode_label(&mode_from_label(&extract_field(line, "\\"mode\\":\\"")?)?),
        group: extract_field(line, "\\"group\\":\\"").unwrap_or_else(|_| "general".to_owned()),
    })'''
assert c.count(old) == 1, "parser anchor"
c = c.replace(old, new)

# the round-trip test builds an event; give it a group
old = '''            client_ip: "192.0.2.7".to_owned(),
            mode: "enforce",
        };'''
new = '''            client_ip: "192.0.2.7".to_owned(),
            mode: "enforce",
            group: "contractor".to_owned(),
        };'''
assert c.count(old) == 1, "test event anchor"
c = c.replace(old, new)

p.write_text(c, encoding="utf-8")
print("audit_log: group field added")
