//! Telemetry constants shared by both binaries.
//!
//! Relay health, the relay observer snapshot and the observable readiness of the
//! relay pool all need one answer: how old may a relay's authenticated telemetry
//! be before it is treated as stale. That is a property of *telemetry*, not of
//! adaptive relay-quality probing, even though it has historically been configured
//! as `relay_quality.max_telemetry_age_seconds`.
//!
//! This module holds the parts that carry no configuration graph, so HBBR can
//! compile it directly (HBBR is its own binary and does not link the hbbs
//! library). The freshness *lookup* lives in `starry_config`, which is where
//! configuration belongs and is HBBS-only.
//!
//! See docs/reference/ADR-AKARI-ARCHIVE.md steps 1 and 2.

/// Version of the authenticated HBBR telemetry payload.
///
/// Wire-visible: HBBR stamps it into every report and the observer rejects a
/// schema it does not know. It used to be defined by the FastMedia UDP module,
/// which made a generic relay feature's version number depend on an archived
/// extension. The number itself must not change — bump it only when the payload
/// shape changes, as schema 1 did.
pub(crate) const SCHEMA_VERSION: u32 = 2;

/// Freshness bound used when no Starry config is loaded.
///
/// Matches `RelayQualityConfig::default().max_telemetry_age_seconds` so that
/// moving a deployment from "no config" to "config without the field" changes
/// nothing.
pub(crate) const DEFAULT_MAX_AGE_SECONDS: u64 = 180;

#[cfg(test)]
mod tests {
    use super::*;

    /// Other components assert this number, so changing it is a protocol change,
    /// not a refactor.
    #[test]
    fn the_telemetry_schema_version_is_pinned() {
        assert_eq!(SCHEMA_VERSION, 2);
    }

    #[test]
    fn the_fallback_matches_the_config_default() {
        // If these ever diverge, a deployment that adds a Starry config without
        // the field would silently change its staleness bound.
        assert_eq!(
            DEFAULT_MAX_AGE_SECONDS,
            crate::starry_config::RelayQualityConfig::default().max_telemetry_age_seconds
        );
    }
}
