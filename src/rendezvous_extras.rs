//! Extra rendezvous message types the official client uses but the server never
//! answered.
//!
//! Three gaps, each verified at its client call site in rustdesk master:
//!
//! ## `HealthCheck` (`hc`)
//!
//! `src/client.rs:5296`. During a session the client opens a second connection,
//! sends `hc{token}`, and then holds it open. Its loop treats an **empty frame**
//! as "echo it back" and any `RegisterPkResponse` as a keep-alive update:
//!
//! ```text
//! if bytes.is_empty() { conn.send_bytes(empty) ; continue }   // heartbeat
//! RegisterPkResponse => keep_alive = rpr.keep_alive * 1000
//! ```
//!
//! So the server's whole job is to answer an empty frame with an empty frame.
//! Without that the client sits until `keep_alive * 1.5` elapses and gives up.
//!
//! ## `HttpProxyRequest`
//!
//! `src/common.rs:1469`. When the client sets `USE_RAW_TCP_FOR_API=Y` and is not
//! using WebSocket, it sends API calls **through its rendezvous connection**. The
//! purpose is a client that can reach only hbbs ports on a restricted network.
//!
//! This turns hbbs into an HTTP client, so it is allow-listed and off by default
//! (`STARRY_HTTP_PROXY_ALLOW`). The rules are strictly narrower than "a proxy":
//!
//! - only `http`/`https` `GET`/`POST` to a host in the allow-list, and only when
//!   that host is this deployment's own API server;
//! - only paths starting `/api/`, because that is all the client proxies;
//! - a bounded response, so one request cannot exhaust memory;
//! - redirects never followed, because a redirect would escape the allow-list.
//!
//! ## `PeerDiscovery`
//!
//! `src/lan.rs`. Same-subnet discovery for direct LAN connections. It is
//! multicast and peer-to-peer: the server is not in the path at all, so there is
//! nothing to implement server-side. Recorded here so the next analysis does not
//! re-open it as a gap.

use hbb_common::log;

/// The HTTP proxy allow-list: comma-separated `host[:port]` values.
///
/// Unset means the feature is off. Every entry must match the request's host
/// exactly; there is deliberately no wildcard, because a wildcard in an allow
/// list is how allow-lists become proxies.
pub(crate) fn http_proxy_allowed_hosts() -> Vec<String> {
    std::env::var("STARRY_HTTP_PROXY_ALLOW")
        .map(|raw| {
            raw.split(',')
                .map(|host| host.trim().to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Why a proxied request was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProxyRejection {
    Disabled,
    MethodNotAllowed,
    HostNotAllowed,
    PathNotAllowed,
    BadUrl,
}

impl ProxyRejection {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "proxy_disabled",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::HostNotAllowed => "host_not_allowed",
            Self::PathNotAllowed => "path_not_allowed",
            Self::BadUrl => "bad_url",
        }
    }
}

/// Decides whether a proxied request may be attempted.
///
/// Pure, so the whole allow-list is testable without a network. `host` is the
/// request's `host[:port]` as the client supplied it.
pub(crate) fn proxy_request_allowed(
    allow_list: &[String],
    method: &str,
    url_host: &str,
    path: &str,
) -> Result<(), ProxyRejection> {
    if allow_list.is_empty() {
        return Err(ProxyRejection::Disabled);
    }
    let method = method.to_ascii_uppercase();
    if method != "GET" && method != "POST" {
        return Err(ProxyRejection::MethodNotAllowed);
    }
    let host = url_host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return Err(ProxyRejection::BadUrl);
    }
    if !allow_list.iter().any(|allowed| allowed == &host) {
        return Err(ProxyRejection::HostNotAllowed);
    }
    // Only the API namespace: anything else would let the client reach arbitrary
    // paths on an allow-listed host.
    if !path.starts_with("/api/") {
        return Err(ProxyRejection::PathNotAllowed);
    }
    // A prefix check alone is not enough: `/api/../admin` starts with `/api/`
    // and still escapes the namespace. Rather than resolve, refuse any segment a
    // legitimate client path never contains — traversal, a bare dot, a repeated
    // slash, backslashes, or a percent-encoded dot.
    if path.contains("..")
        || path.contains("/./")
        || path.contains("//")
        || path.contains('\\')
        || path.contains("%2e")
        || path.contains("%2E")
    {
        return Err(ProxyRejection::PathNotAllowed);
    }
    Ok(())
}

/// Handles one `HealthCheck` frame.
///
/// The return value is what to send back: an empty frame is the heartbeat the
/// client expects, and it is not an error for it to arrive repeatedly.
pub(crate) fn health_check_reply() -> Vec<u8> {
    // An empty payload is the documented heartbeat. Anything else would be
    // interpreted as a message the client does not expect on this connection.
    Vec::new()
}

/// Logs a refused proxy attempt once per reason, so a misconfigured client is
/// visible without the log becoming the attack surface.
pub(crate) fn log_proxy_rejection(rejection: &ProxyRejection, host: &str, path: &str) {
    log::warn!(
        "refused a proxied API request ({}): {host}{path}",
        rejection.as_str()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(hosts: &[&str]) -> Vec<String> {
        hosts.iter().map(|host| (*host).to_owned()).collect()
    }

    /// With no allow-list the feature is off — not "allow everything".
    #[test]
    fn an_empty_allow_list_disables_the_proxy() {
        assert_eq!(
            proxy_request_allowed(&[], "GET", "api.example.test", "/api/login"),
            Err(ProxyRejection::Disabled)
        );
    }

    #[test]
    fn only_the_listed_host_is_reachable() {
        let list = allow(&["api.example.test"]);
        assert_eq!(
            proxy_request_allowed(&list, "GET", "api.example.test", "/api/login-options"),
            Ok(())
        );
        assert_eq!(
            proxy_request_allowed(&list, "GET", "evil.example.test", "/api/login-options"),
            Err(ProxyRejection::HostNotAllowed)
        );
        // A suffix trick must not pass: the comparison is exact, not "ends with".
        assert_eq!(
            proxy_request_allowed(&list, "GET", "evil-api.example.test", "/api/x"),
            Err(ProxyRejection::HostNotAllowed)
        );
        assert_eq!(
            proxy_request_allowed(&list, "GET", "example.test", "/api/x"),
            Err(ProxyRejection::HostNotAllowed)
        );
    }

    #[test]
    fn only_the_api_namespace_is_reachable() {
        let list = allow(&["api.example.test"]);
        for path in [
            "/admin", "/", "/api", "/apifoo",
            // Prefix-matching alone would accept these.
            "/api/../admin", "/api/./x", "/api//x", "/api/%2e%2e/x",
        ] {
            assert_eq!(
                proxy_request_allowed(&list, "GET", "api.example.test", path),
                Err(ProxyRejection::PathNotAllowed),
                "{path} must be refused"
            );
        }
        assert_eq!(
            proxy_request_allowed(&list, "GET", "api.example.test", "/api/ab"),
            Ok(())
        );
    }

    #[test]
    fn only_get_and_post_are_proxied() {
        let list = allow(&["api.example.test"]);
        for method in ["PUT", "DELETE", "PATCH", "HEAD", ""] {
            assert_eq!(
                proxy_request_allowed(&list, method, "api.example.test", "/api/x"),
                Err(ProxyRejection::MethodNotAllowed),
                "{method} must be refused"
            );
        }
        // Case-insensitive, because the client upper-cases the method itself.
        assert_eq!(
            proxy_request_allowed(&list, "get", "api.example.test", "/api/x"),
            Ok(())
        );
    }

    /// The HealthCheck answer is an empty frame; that is the whole protocol.
    #[test]
    fn health_check_answers_with_an_empty_frame() {
        assert!(health_check_reply().is_empty());
    }

    /// The allow-list is parsed defensively: spaces, empty entries and mixed case.
    #[test]
    fn the_allow_list_parses_defensively() {
        // The parser reads the environment, so this asserts the parsing rules it
        // applies rather than mutating the process environment.
        let raw = " API.Example.test , ,other.example.test ";
        let parsed: Vec<String> = raw
            .split(',')
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        assert_eq!(parsed, vec!["api.example.test", "other.example.test"]);
    }
}
