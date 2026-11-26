//! Strategy v1: device groups and server-enforced access policy.
//!
//! See docs/reference/STRATEGY-v1.md for the contract. Summary:
//!
//! - A strategy document (located by `STARRY_STRATEGY_FILE`) assigns devices
//!   to groups by registered ID — exact match or prefix — and gives each
//!   group an optional required-scope override and an optional deny verdict.
//! - `check_target(id)` evaluates the document statelessly at request time;
//!   HBBS refuses denied targets before JWT evaluation and passes the group's
//!   required scope to the connection authority as an override.
//! - Unset `STARRY_STRATEGY_FILE` disables the engine: every device then
//!   belongs to the implicit `general` group with no overrides.
//!
//! The document is immutable once loaded into the runtime slot; reloads swap
//! the whole [`Strategy`] atomically, so enforcement never observes a
//! half-written document.

use std::{
    path::{Path, PathBuf},
    sync::{atomic::{AtomicU64, Ordering}, Arc, OnceLock, RwLock},
};

use serde_derive::Deserialize;

/// The runtime strategy slot. `None` until the engine is enabled.
static RUNTIME: OnceLock<RwLock<Option<Arc<Strategy>>>> = OnceLock::new();
/// Monotonic counter of successful reloads, exposed for supervision.
static RELOADS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Deserialize)]
struct StrategyDocument {
    version: u32,
    default_group: String,
    #[serde(default)]
    groups: Vec<GroupRule>,
}

#[derive(Debug, Deserialize)]
struct GroupRule {
    name: String,
    #[serde(default)]
    ids: Vec<String>,
    #[serde(default)]
    id_prefixes: Vec<String>,
    #[serde(default)]
    require_scope: Option<String>,
    #[serde(default)]
    deny: bool,
}

/// The validated, immutable strategy state.
#[derive(Debug)]
pub(crate) struct Strategy {
    version: u32,
    digest: String,
    default_group: String,
    groups: Vec<GroupRule>,
}

impl Strategy {
    /// The document version.
    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    /// First 16 hex characters of the SHA-256 content digest.
    pub(crate) fn digest(&self) -> &str {
        &self.digest
    }

    fn group_index(&self, device_id: &str) -> Option<usize> {
        let mut best: Option<(u8, u16, usize)> = None;
        for (index, group) in self.groups.iter().enumerate() {
            let exact = group.ids.iter().any(|id| id == device_id);
            let prefix = group
                .id_prefixes
                .iter()
                .any(|prefix| device_id.starts_with(prefix.as_str()));
            let specificity = if exact {
                Some((2u8, u16::MAX))
            } else if prefix {
                // Among prefixes, the longest wins.
                let longest = group
                    .id_prefixes
                    .iter()
                    .filter(|prefix| device_id.starts_with(prefix.as_str()))
                    .map(|prefix| prefix.len())
                    .max()
                    .unwrap_or(0);
                Some((1u8, longest as u16))
            } else {
                None
            };
            if let Some(rank) = specificity {
                if best.is_none_or(|(best_rank, best_len, _)| {
                    rank.0 > best_rank || (rank.0 == best_rank && rank.1 > best_len)
                }) {
                    best = Some((rank.0, rank.1, index));
                }
            }
        }
        best.map(|(_, _, index)| index)
    }
}

/// The policy verdict for one target device.
#[derive(Debug, Clone)]
pub(crate) struct TargetCheck {
    /// Group name the target resolved to; `general` when the engine is off.
    pub(crate) group: String,
    /// Scope the request token must carry; `None` keeps the global floor.
    pub(crate) required_scope: Option<String>,
    /// Set when the group is denied outright; the reason is static so it can
    /// flow into the audit event without allocation.
    pub(crate) deny_reason: Option<&'static str>,
}

/// Evaluates the target device against the loaded strategy.
pub(crate) fn check_target(device_id: &str) -> TargetCheck {
    let strategy = RUNTIME
        .get_or_init(|| RwLock::new(None))
        .read()
        .ok()
        .and_then(|slot| slot.clone());
    let Some(strategy) = strategy else {
        return TargetCheck {
            group: "general".to_owned(),
            required_scope: None,
            deny_reason: None,
        };
    };
    match strategy.group_index(device_id) {
        Some(index) => {
            let group = &strategy.groups[index];
            TargetCheck {
                group: group.name.clone(),
                required_scope: group.require_scope.clone(),
                deny_reason: group.deny.then_some("strategy_group_denied"),
            }
        }
        None => TargetCheck {
            group: strategy.default_group.clone(),
            required_scope: None,
            deny_reason: None,
        },
    }
}

/// Loads or reloads the strategy document from `STARRY_STRATEGY_FILE`.
///
/// Returns the version and digest on success, `None` when the engine is
/// disabled, and an error string when a configured document fails to load or
/// validate. A failed reload keeps the previously loaded strategy active.
pub fn reload() -> Result<Option<(u32, String)>, String> {
    let Some(path) = configured_path() else {
        disable();
        return Ok(None);
    };
    let strategy = load_document(&path)?;
    let version = strategy.version();
    let digest = strategy.digest().to_owned();
    let slot = RUNTIME.get_or_init(|| RwLock::new(None));
    *slot.write().map_err(|_| "strategy_state_poisoned".to_owned())? =
        Some(Arc::new(strategy));
    RELOADS.fetch_add(1, Ordering::Relaxed);
    Ok(Some((version, digest)))
}

fn disable() {
    if let Some(slot) = RUNTIME.get() {
        if let Ok(mut slot) = slot.write() {
            *slot = None;
        }
    }
}

fn configured_path() -> Option<PathBuf> {
    std::env::var("STARRY_STRATEGY_FILE")
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn load_document(path: &Path) -> Result<Strategy, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("cannot read strategy file {}: {err}", path.display()))?;
    let document: StrategyDocument = serde_yml::from_str(&raw)
        .map_err(|err| format!("cannot parse strategy file: {err}"))?;
    validate(document, &raw)
}

fn validate(document: StrategyDocument, raw: &str) -> Result<Strategy, String> {
    if document.version != 1 {
        return Err(format!(
            "unsupported strategy document version {}",
            document.version
        ));
    }
    if document.default_group.trim().is_empty() {
        return Err("default_group must not be empty".to_owned());
    }
    let mut names = std::collections::HashSet::new();
    for group in &document.groups {
        if group.name.trim().is_empty() {
            return Err("group name must not be empty".to_owned());
        }
        if !names.insert(group.name.clone()) {
            return Err(format!("duplicate group name {}", group.name));
        }
        // The default group is the catch-all and may omit matchers; any
        // other group without matchers would silently never apply.
        if group.name != document.default_group
            && group.ids.is_empty()
            && group.id_prefixes.is_empty()
        {
            return Err(format!(
                "group {} matches nothing; give ids or id_prefixes",
                group.name
            ));
        }
        for id in group.ids.iter().chain(group.id_prefixes.iter()) {
            if id.trim().is_empty() {
                return Err(format!("group {} has an empty matcher", group.name));
            }
        }
        if let Some(scope) = &group.require_scope {
            if scope.trim().is_empty() {
                return Err(format!(
                    "group {} has an empty require_scope",
                    group.name
                ));
            }
        }
    }
    if !document
        .groups
        .iter()
        .any(|group| group.name == document.default_group)
    {
        return Err(format!(
            "default_group {} has no matching group entry",
            document.default_group
        ));
    }
    // The digest pins the exact bytes an operator reviewed.
    let digest = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(raw.as_bytes());
        let hex = hash.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        hex[..16].to_owned()
    };
    Ok(Strategy {
        version: document.version,
        digest,
        default_group: document.default_group,
        groups: document.groups,
    })
}

/// Supervision snapshot for `strategy.status` and `/healthz`.
pub(crate) fn status() -> serde_json::Value {
    let strategy = RUNTIME
        .get_or_init(|| RwLock::new(None))
        .read()
        .ok()
        .and_then(|slot| slot.clone());
    match strategy {
        Some(strategy) => serde_json::json!({
            "enabled": true,
            "version": strategy.version(),
            "digest": strategy.digest(),
            "groups": strategy.groups.len(),
            "reloads": RELOADS.load(Ordering::Relaxed),
        }),
        None => serde_json::json!({
            "enabled": false,
            "reloads": RELOADS.load(Ordering::Relaxed),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(yaml: &str) -> Strategy {
        let parsed: StrategyDocument = serde_yml::from_str(yaml).expect("parse");
        validate(parsed, yaml).expect("validate")
    }

    const BASIC: &str = "version: 1\ndefault_group: general\ngroups:\n  - name: general\n";

    #[test]
    fn disabled_engine_gives_general_with_no_overrides() {
        let previous = std::env::var("STARRY_STRATEGY_FILE").ok();
        std::env::remove_var("STARRY_STRATEGY_FILE");
        let check = check_target("anything");
        assert_eq!(check.group, "general");
        assert!(check.required_scope.is_none() && check.deny_reason.is_none());
        if let Some(previous) = previous {
            std::env::set_var("STARRY_STRATEGY_FILE", previous);
        }
    }

    #[test]
    fn exact_match_beats_prefix_and_longer_prefix_beats_shorter() {
        let strategy = document(
            "version: 1\ndefault_group: general\ngroups:\n  - name: general\n  \
             - name: contractor\n    id_prefixes: [\"tmp-\"]\n    require_scope: \"s:contractor\"\n  \
             - name: contractor-long\n    id_prefixes: [\"tmp-special-\"]\n    require_scope: \"s:long\"\n  \
             - name: exact-hit\n    ids: [\"tmp-special-1\"]\n    deny: true\n",
        );
        assert_eq!(
            strategy.group_index("tmp-1").map(|index| strategy.groups[index].name.as_str()),
            Some("contractor")
        );
        assert_eq!(
            strategy.group_index("tmp-special-1")
                .map(|index| strategy.groups[index].name.as_str()),
            Some("exact-hit")
        );
        assert_eq!(
            strategy.group_index("tmp-special-9")
                .map(|index| strategy.groups[index].name.as_str()),
            Some("contractor-long")
        );
        assert_eq!(strategy.group_index("unmatched"), None);
    }

    #[test]
    fn validation_rejects_empty_and_unknown_references() {
        let err = validate(
            serde_yml::from_str::<StrategyDocument>(
                "version: 1\ndefault_group: nowhere\ngroups:\n  - name: general\n    ids: [\"x\"]\n",
            )
            .unwrap(),
            "x",
        )
        .unwrap_err();
        assert!(err.contains("nowhere"));
        // A non-default group without matchers would never apply.
        let err = validate(
            serde_yml::from_str::<StrategyDocument>(
                "version: 1\ndefault_group: general\ngroups:\n  - name: general\n  - name: empty\n",
            )
            .unwrap(),
            "x",
        )
        .unwrap_err();
        assert!(err.contains("empty matches nothing"));
        let err = validate(
            serde_yml::from_str::<StrategyDocument>(
                "version: 2\ndefault_group: general\ngroups:\n  - name: general\n",
            )
            .unwrap(),
            "x",
        )
        .unwrap_err();
        assert!(err.contains("unsupported"));
        let err = validate(
            serde_yml::from_str::<StrategyDocument>(
                "version: 1\ndefault_group: general\ngroups:\n  - name: solo\n",
            )
            .unwrap(),
            "x",
        )
        .unwrap_err();
        assert!(err.contains("matches nothing"));
    }

    #[test]
    fn basic_document_loads_with_digest() {
        let strategy = document(BASIC);
        assert_eq!(strategy.version(), 1);
        assert_eq!(strategy.digest().len(), 16);
    }
}
