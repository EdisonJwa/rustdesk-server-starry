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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock, RwLock,
    },
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
    // The default group is the catch-all: a device matching no rule is *in*
    // that group, so its verdict applies. Reading only the name left
    // `deny`/`require_scope` on the default group unenforced, which turned an
    // operator's deny-by-default document into an allow-all.
    let index = strategy.group_index(device_id).or_else(|| {
        strategy
            .groups
            .iter()
            .position(|group| group.name == strategy.default_group)
    });
    match index {
        Some(index) => {
            let group = &strategy.groups[index];
            TargetCheck {
                group: group.name.clone(),
                required_scope: group.require_scope.clone(),
                deny_reason: group.deny.then_some("strategy_group_denied"),
            }
        }
        // validate() rejects a document whose default_group has no entry, so
        // this is unreachable for a loaded strategy.
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
    *slot
        .write()
        .map_err(|_| "strategy_state_poisoned".to_owned())? = Some(Arc::new(strategy));
    RELOADS.fetch_add(1, Ordering::Relaxed);
    Ok(Some((version, digest)))
}

/// Whether a managed deployment requires the strategy engine to be live.
///
/// `STARRY_STRATEGY_REQUIRED=1` (or the `MUST_LOGIN` floor, which turns the
/// deployment managed) makes a configured-but-unloadable policy a startup
/// failure instead of a silently disabled engine. Operators who deliberately
/// run without a policy leave it unset.
fn policy_is_required() -> bool {
    if crate::connection_auth::must_login_floor() {
        return true;
    }
    let enabled = |value: &str| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "y" | "yes" | "true" | "on"
        )
    };
    crate::common::env_var("STARRY_STRATEGY_REQUIRED")
        .ok()
        .as_deref()
        .is_some_and(enabled)
}

/// Startup gate for the strategy engine.
///
/// A managed deployment (`policy_is_required()`) must end up with a loaded
/// policy: a configured document that fails to load is a hard error, and so is
/// a required-but-unconfigured one. Any other deployment logs and continues, as
/// before.
pub fn startup() -> Result<Option<(u32, String)>, String> {
    let outcome = reload();
    let required = policy_is_required();
    match (&outcome, required) {
        (Err(err), true) => Err(format!(
            "strategy policy is required but failed to load: {err}"
        )),
        (Ok(None), true) => Err(
            "strategy policy is required (STARRY_STRATEGY_REQUIRED / MUST_LOGIN) but \
             STARRY_STRATEGY_FILE is not set"
                .to_owned(),
        ),
        _ => Ok(outcome?),
    }
}

/// Runtime reload with the same managed-mode gate as [`startup`].
///
/// A failed reload keeps the previously loaded policy in force, which is the
/// safe behaviour. What a managed deployment must *not* do is accept a reload
/// that would leave it with no policy at all (someone unset the env var or
/// pointed it at nothing), so that case is refused rather than applied.
pub fn reload_checked() -> Result<Option<(u32, String)>, String> {
    if configured_path().is_none() && policy_is_required() {
        return Err(
            "reload refused: the strategy policy is required but STARRY_STRATEGY_FILE is not set"
                .to_owned(),
        );
    }
    let outcome = reload();
    if let (Err(err), true) = (&outcome, policy_is_required()) {
        return Err(format!(
            "reload refused: the strategy policy is required and the new document is invalid: {err}"
        ));
    }
    outcome
}

/// Whether the engine currently has a loaded policy.
pub(crate) fn is_enabled() -> bool {
    RUNTIME
        .get_or_init(|| RwLock::new(None))
        .read()
        .ok()
        .is_some_and(|slot| slot.is_some())
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
    let document: StrategyDocument =
        serde_yml::from_str(&raw).map_err(|err| format!("cannot parse strategy file: {err}"))?;
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
                return Err(format!("group {} has an empty require_scope", group.name));
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
        let hex = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
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
    use std::sync::Mutex;

    /// These tests drive the engine through `STARRY_STRATEGY_FILE` and
    /// `STARRY_STRATEGY_REQUIRED`, which are process-global; running them in
    /// parallel would let one test observe another's environment.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn document(yaml: &str) -> Strategy {
        let parsed: StrategyDocument = serde_yml::from_str(yaml).expect("parse");
        validate(parsed, yaml).expect("validate")
    }

    const BASIC: &str = "version: 1\ndefault_group: general\ngroups:\n  - name: general\n";

    #[test]
    fn disabled_engine_gives_general_with_no_overrides() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Clear both the env var and the runtime slot: another test may have
        // installed a document, and the slot outlives an env change.
        std::env::remove_var("STARRY_STRATEGY_FILE");
        disable();
        let check = check_target("anything");
        assert_eq!(check.group, "general");
        assert!(check.required_scope.is_none() && check.deny_reason.is_none());
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
            strategy
                .group_index("tmp-1")
                .map(|index| strategy.groups[index].name.as_str()),
            Some("contractor")
        );
        assert_eq!(
            strategy
                .group_index("tmp-special-1")
                .map(|index| strategy.groups[index].name.as_str()),
            Some("exact-hit")
        );
        assert_eq!(
            strategy
                .group_index("tmp-special-9")
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

    /// Install a document through the real reload path so `check_target` is
    /// exercised end to end rather than a copy of its resolution logic.
    fn install(yaml: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("strategy.yaml");
        std::fs::write(&path, yaml).unwrap();
        std::env::set_var("STARRY_STRATEGY_FILE", &path);
        reload()
            .expect("install the strategy")
            .expect("engine enabled");
        directory
    }

    fn uninstall() {
        std::env::remove_var("STARRY_STRATEGY_FILE");
        disable();
    }

    /// The default group is a real group: a device that matches no rule is in
    /// it, so its `deny` must apply. Reading only the name turned an operator's
    /// deny-by-default document into an allow-all.
    #[test]
    fn default_group_deny_applies_to_unmatched_devices() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _directory = install(
            r#"version: 1
default_group: locked
groups:
  - name: locked
    deny: true
  - name: lab
    ids: ["lab-1"]
"#,
        );
        let matched = check_target("lab-1");
        assert_eq!(matched.group, "lab");
        assert!(
            matched.deny_reason.is_none(),
            "an explicitly listed group must not inherit the default deny"
        );

        let unmatched = check_target("not-in-any-rule");
        assert_eq!(unmatched.group, "locked");
        assert_eq!(
            unmatched.deny_reason,
            Some("strategy_group_denied"),
            "an unmatched device must inherit the default group's deny"
        );
        uninstall();
    }

    #[test]
    fn default_group_require_scope_applies_to_unmatched_devices() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _directory = install(
            r#"version: 1
default_group: guarded
groups:
  - name: guarded
    require_scope: "connect:strict"
  - name: lab
    ids: ["lab-1"]
"#,
        );
        assert_eq!(
            check_target("not-in-any-rule").required_scope.as_deref(),
            Some("connect:strict"),
            "an unmatched device must inherit the default group's scope"
        );
        assert!(
            check_target("lab-1").required_scope.is_none(),
            "a matched group keeps its own (absent) override"
        );
        uninstall();
    }

    /// A managed deployment must not start with a policy that failed to load.
    #[test]
    fn required_policy_fails_closed_when_the_document_is_broken() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("strategy.yaml");
        std::fs::write(&path, "version: 1\ndefault_group: general\ngroups:\n").unwrap();
        std::env::set_var("STARRY_STRATEGY_FILE", &path);
        std::env::set_var("STARRY_STRATEGY_REQUIRED", "1");
        let outcome = startup();
        std::env::remove_var("STARRY_STRATEGY_REQUIRED");
        std::env::remove_var("STARRY_STRATEGY_FILE");
        let err = outcome.expect_err("a required policy that cannot load must be fatal");
        assert!(
            err.contains("required but failed to load"),
            "unexpected error: {err}"
        );
    }

    /// A required policy that was never configured is equally fatal.
    #[test]
    fn required_policy_fails_closed_when_unconfigured() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var("STARRY_STRATEGY_FILE");
        std::env::set_var("STARRY_STRATEGY_REQUIRED", "1");
        let outcome = startup();
        std::env::remove_var("STARRY_STRATEGY_REQUIRED");
        let err = outcome.expect_err("a required policy with no file must be fatal");
        assert!(
            err.contains("STARRY_STRATEGY_FILE is not set"),
            "unexpected error: {err}"
        );
    }

    /// Compatibility deployments keep the old behaviour: log and continue.
    #[test]
    fn optional_policy_tolerates_a_broken_document() {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("strategy.yaml");
        std::fs::write(
            &path,
            "version: 9\ndefault_group: general\ngroups:\n  - name: general\n",
        )
        .unwrap();
        std::env::set_var("STARRY_STRATEGY_FILE", &path);
        std::env::remove_var("STARRY_STRATEGY_REQUIRED");
        let outcome = startup();
        std::env::remove_var("STARRY_STRATEGY_FILE");
        assert!(
            outcome.is_err(),
            "the load error must still be reported to the caller"
        );
        uninstall();
        assert!(
            !is_enabled(),
            "a rejected document must not install a policy"
        );
    }
}
