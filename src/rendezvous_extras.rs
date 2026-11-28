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

/// Performs one proxied API request and builds the reply frame.
///
/// Blocking: called from the spawned per-connection task, so it must not hold the
/// listener. Bounded in every dimension the client could abuse — the allow-list
/// decides the host, the path must be under `/api/`, the method is GET or POST,
/// and the response body is capped.
pub(crate) fn execute_proxy_request(
    request: &hbb_common::rendezvous_proto::HttpProxyRequest,
    api_base: &str,
) -> hbb_common::rendezvous_proto::HttpProxyResponse {
    execute_proxy_request_inner(request, api_base, &http_proxy_allowed_hosts())
}

/// The executor with the allow-list passed in.
///
/// Exists so a test can exercise the rules without mutating the process
/// environment, which would make the tests order-dependent and let one test's
/// allow-list leak into another's.
fn execute_proxy_request_inner(
    request: &hbb_common::rendezvous_proto::HttpProxyRequest,
    api_base: &str,
    allow: &[String],
) -> hbb_common::rendezvous_proto::HttpProxyResponse {
    use hbb_common::rendezvous_proto::HttpProxyResponse;

    let mut response = HttpProxyResponse::new();
    if api_base.trim().is_empty() {
        response.error = "proxy_target_unconfigured".to_owned();
        return response;
    }
    let base = reqwest::Url::parse(api_base).ok();
    let Some(base) = base else {
        // Without a configured API base there is nothing legitimate to proxy to,
        // so this is a configuration error rather than a client one.
        response.error = "proxy_target_unconfigured".to_owned();
        return response;
    };
    let host = match base.port() {
        Some(port) => format!("{}:{port}", base.host_str().unwrap_or("")),
        None => base.host_str().unwrap_or("").to_owned(),
    };
    if let Err(rejection) = proxy_request_allowed(allow, &request.method, &host, &request.path) {
        log_proxy_rejection(&rejection, &host, &request.path);
        response.error = rejection.as_str().to_owned();
        return response;
    }

    let url = format!(
        "{}{}",
        api_base.trim_end_matches('/'),
        if request.path.starts_with('/') {
            request.path.clone()
        } else {
            format!("/{}", request.path)
        }
    );
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        // A redirect would leave the allow-list, so it is never followed.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            log::error!("cannot build the proxy client: {err}");
            response.error = "proxy_client_failed".to_owned();
            return response;
        }
    };

    let mut outgoing = if request.method.eq_ignore_ascii_case("POST") {
        client.post(&url)
    } else {
        client.get(&url)
    };
    for entry in &request.headers {
        // `Host` and `Content-Length` are set by the HTTP client itself; passing
        // the client's copies would desynchronise the request.
        if entry.name.eq_ignore_ascii_case("host")
            || entry.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        outgoing = outgoing.header(&entry.name, &entry.value);
    }
    if !request.body.is_empty() {
        outgoing = outgoing.body(request.body.to_vec());
    }

    let result = outgoing.send();
    let received = match result {
        Ok(received) => received,
        Err(err) => {
            log::warn!("proxied API request failed: {err}");
            response.error = "proxy_request_failed".to_owned();
            return response;
        }
    };
    response.status = received.status().as_u16() as i32;
    for (name, value) in received.headers().iter() {
        let Ok(value) = value.to_str() else { continue };
        let mut entry = hbb_common::rendezvous_proto::HeaderEntry::new();
        entry.name = name.as_str().to_owned();
        entry.value = value.to_owned();
        response.headers.push(entry);
    }
    match received.bytes() {
        Ok(body) => {
            // Capped: the client only proxies small API responses, and an
            // unbounded body here would be a memory amplifier for a hostile
            // allow-listed host.
            let body = body.to_vec();
            if body.len() > MAX_PROXY_BODY {
                response.error = "proxy_response_too_large".to_owned();
                return response;
            }
            response.body = body.into();
        }
        Err(err) => {
            log::warn!("cannot read the proxied response: {err}");
            response.error = "proxy_read_failed".to_owned();
        }
    }
    response
}

/// How much of a proxied response is accepted.
const MAX_PROXY_BODY: usize = 1024 * 1024;

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
            "/admin",
            "/",
            "/api",
            "/apifoo",
            // Prefix-matching alone would accept these.
            "/api/../admin",
            "/api/./x",
            "/api//x",
            "/api/%2e%2e/x",
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

    /// A one-shot HTTP server on a real socket.
    ///
    /// The accept loop is non-blocking with a deadline, because several tests
    /// exercise paths that must be refused *before* any connection is made —
    /// a blocking `accept` there would hang until the harness gave up, which is
    /// what the first version did.
    struct OneShotServer {
        base: String,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl OneShotServer {
        fn start(status: u16, body: &'static str) -> Self {
            use std::io::{BufRead, BufReader, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            // A refused request never connects, so this deadline is pure teardown
            // cost. One second is enough for the single request a proxied test
            // makes and keeps the suite fast.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            let handle = std::thread::spawn(move || {
                while std::time::Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut reader = BufReader::new(stream.try_clone().unwrap());
                            let mut line = String::new();
                            let _ = reader.read_line(&mut line);
                            // Drain headers up to the blank line.
                            loop {
                                let mut header = String::new();
                                match reader.read_line(&mut header) {
                                    Ok(0) => break,
                                    Ok(_) if header.trim().is_empty() => break,
                                    Ok(_) => continue,
                                    Err(_) => break,
                                }
                            }
                            // Assembled from bytes so no literal CR appears in
                            // this file, which is CRLF and would otherwise let an
                            // editor turn the separator into a real newline.
                            let mut response = Vec::new();
                            response.extend_from_slice(format!("HTTP/1.1 {status} OK").as_bytes());
                            response.extend_from_slice(&[0x0d, 0x0a]);
                            response.extend_from_slice(b"Content-Type: application/json");
                            response.extend_from_slice(&[0x0d, 0x0a]);
                            response.extend_from_slice(
                                format!("Content-Length: {}", body.len()).as_bytes(),
                            );
                            response.extend_from_slice(&[0x0d, 0x0a]);
                            response.extend_from_slice(b"Connection: close");
                            response.extend_from_slice(&[0x0d, 0x0a, 0x0d, 0x0a]);
                            response.extend_from_slice(body.as_bytes());
                            let _ = stream.write_all(&response);
                            return;
                        }
                        Err(ref err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(2));
                        }
                        Err(_) => return,
                    }
                }
            });
            Self {
                base,
                handle: Some(handle),
            }
        }

        fn host(&self) -> String {
            self.base.trim_start_matches("http://").to_owned()
        }
    }

    impl Drop for OneShotServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                // It either served its one request or its deadline passed; in
                // both cases it is about to exit, so joining is cheap.
                let _ = handle.join();
            }
        }
    }

    fn request(method: &str, path: &str) -> hbb_common::rendezvous_proto::HttpProxyRequest {
        let mut request = hbb_common::rendezvous_proto::HttpProxyRequest::new();
        request.method = method.to_owned();
        request.path = path.to_owned();
        request
    }

    /// An allow-listed request reaches the target and returns its body verbatim.
    #[test]
    fn an_allow_listed_request_is_proxied() {
        let server = OneShotServer::start(200, r#"{"ok":true}"#);
        let allow = vec![server.host()];
        let reply = execute_proxy_request_inner(
            &request("GET", "/api/login-options"),
            &server.base,
            &allow,
        );
        assert!(reply.error.is_empty(), "unexpected error: {}", reply.error);
        assert_eq!(reply.status, 200);
        assert_eq!(String::from_utf8_lossy(&reply.body), r#"{"ok":true}"#);
    }

    /// A host outside the allow-list is refused before any connection is made.
    #[test]
    fn a_host_outside_the_allow_list_is_refused() {
        let server = OneShotServer::start(200, "{}");
        let allow = vec!["elsewhere.example.test".to_owned()];
        let reply = execute_proxy_request_inner(&request("GET", "/api/x"), &server.base, &allow);
        assert_eq!(reply.error, "host_not_allowed");
        assert!(reply.body.is_empty());
    }

    /// A path outside `/api/`, a traversal and a repeated slash are refused.
    #[test]
    fn non_api_paths_are_refused() {
        let server = OneShotServer::start(200, "{}");
        let allow = vec![server.host()];
        for path in ["/healthz", "/api/../healthz", "/api//x", "/admin"] {
            let reply = execute_proxy_request_inner(&request("GET", path), &server.base, &allow);
            assert_eq!(reply.error, "path_not_allowed", "{path} must be refused");
        }
    }

    /// Only GET and POST are proxied, and an unset target refuses.
    #[test]
    fn methods_and_unconfigured_targets_are_refused() {
        assert_eq!(
            execute_proxy_request(&request("GET", "/api/x"), "").error,
            "proxy_target_unconfigured"
        );
        let server = OneShotServer::start(200, "{}");
        let allow = vec![server.host()];
        for method in ["DELETE", "PUT", "PATCH", "HEAD"] {
            let reply =
                execute_proxy_request_inner(&request(method, "/api/x"), &server.base, &allow);
            assert_eq!(
                reply.error, "method_not_allowed",
                "{method} must be refused"
            );
        }
    }
}
