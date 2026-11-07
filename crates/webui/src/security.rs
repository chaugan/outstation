//! Same-origin and Host checks (F042, F046, F050). Not authentication.
//!
//! The UI stays unauthenticated and LAN-reachable by design. This layer
//! closes the two browser-borne attacks that the network layer cannot:
//!
//! * **DNS rebinding.** Every request's `Host` must be an IP literal,
//!   `localhost`, one of this machine's host names, or a name listed
//!   with `--allow-host` / `OUTSTATION_ALLOW_HOSTS`.
//! * **CSRF and cross-site WebSocket hijacking.** Every non-GET request
//!   and every WebSocket upgrade must carry an `Origin` whose authority
//!   equals `Host`, or, when no `Origin` is sent, `Sec-Fetch-Site:
//!   same-origin`. Requests with neither header are refused, so
//!   scripted clients must send `Origin: http://<host:port>`.
//! * **Reverse proxies.** A proxy that rewrites `Host` (such as one that
//!   publishes the UI under a path prefix on another site) makes the
//!   browser's `Origin` differ from `Host`. Such origins are accepted
//!   only when listed with `--allow-origin` / `OUTSTATION_ALLOW_ORIGINS`
//!   (exact `scheme://host[:port]` match).

use std::net::{IpAddr, SocketAddr};

use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::state::AppState;

/// Host name (without port) from a `Host` header value.
pub(crate) fn host_without_port(host: &str) -> &str {
    let host = host.trim();
    if let Some(rest) = host.strip_prefix('[') {
        // [v6]:port
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Names this machine answers to: the kernel host name, its
/// `hostname.domainname` form and the canonical name from the resolver.
pub(crate) fn local_host_names() -> Vec<String> {
    let mut out = Vec::new();
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s != "(none)")
    };
    let host = read("/proc/sys/kernel/hostname");
    if let Some(h) = &host {
        out.push(h.clone());
        if let Some(d) = read("/proc/sys/kernel/domainname") {
            out.push(format!("{h}.{d}"));
        }
        if let Some(c) = canonical_name(h) {
            out.push(c);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `getaddrinfo(AI_CANONNAME)` for the FQDN. Best effort.
fn canonical_name(host: &str) -> Option<String> {
    let c_host = std::ffi::CString::new(host).ok()?;
    // SAFETY: plain libc resolver call; the hints struct is zeroed and
    // the result list is freed before returning.
    unsafe {
        let mut hints: libc::addrinfo = std::mem::zeroed();
        hints.ai_flags = libc::AI_CANONNAME;
        hints.ai_family = libc::AF_UNSPEC;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        if libc::getaddrinfo(c_host.as_ptr(), std::ptr::null(), &hints, &mut res) != 0
            || res.is_null()
        {
            return None;
        }
        let name = if (*res).ai_canonname.is_null() {
            None
        } else {
            std::ffi::CStr::from_ptr((*res).ai_canonname)
                .to_str()
                .ok()
                .map(|s| s.to_ascii_lowercase())
        };
        libc::freeaddrinfo(res);
        name
    }
}

pub(crate) fn host_allowed(host_header: &str, local_names: &[String], allow: &[String]) -> bool {
    let h = host_without_port(host_header).to_ascii_lowercase();
    let h = h.trim_end_matches('.');
    if h.is_empty() {
        return false;
    }
    if h.parse::<IpAddr>().is_ok() || h == "localhost" {
        return true;
    }
    local_names.iter().any(|n| n == h)
        || allow
            .iter()
            .any(|a| host_without_port(a).trim_end_matches('.') == h)
}

/// Authority (`host[:port]`) of an `Origin` header value.
fn origin_authority(origin: &str) -> Option<&str> {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    Some(rest.trim_end_matches('/'))
}

fn is_ws_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

/// `Origin` value in the form `--allow-origin` entries are compared in:
/// lower case, no trailing slash.
pub(crate) fn normalize_origin(origin: &str) -> String {
    origin.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Decide whether a request passes. `Err` carries the refusal.
/// `allow_origins` holds extra trusted origins (already normalized),
/// e.g. a reverse proxy's public URL.
pub(crate) fn check_request(
    method: &Method,
    headers: &HeaderMap,
    local_names: &[String],
    allow: &[String],
    allow_origins: &[String],
) -> Result<(), AppError> {
    let forbidden = |code, msg: String| AppError::new(StatusCode::FORBIDDEN, code, msg);
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| forbidden("host_missing", "request has no Host header".into()))?;
    if !host_allowed(host, local_names, allow) {
        return Err(forbidden(
            "host_not_allowed",
            format!(
                "Host {host:?} is not allowed; use an IP address, localhost, this machine's \
                 host name, or start the server with --allow-host {}",
                host_without_port(host)
            ),
        ));
    }
    let safe = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    if safe && !is_ws_upgrade(headers) {
        return Ok(());
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let same = origin_authority(origin).is_some_and(|a| a.eq_ignore_ascii_case(host.trim()));
        let trusted = !same && {
            let o = normalize_origin(origin);
            allow_origins.contains(&o)
        };
        return if same || trusted {
            Ok(())
        } else {
            Err(forbidden(
                "cross_origin",
                format!(
                    "cross-origin request refused (Origin {origin:?}, Host {host:?}); \
                     if this UI is served through a reverse proxy, start the server \
                     with --allow-origin {}",
                    normalize_origin(origin)
                ),
            ))
        };
    }
    match headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        Some("same-origin") => Ok(()),
        Some(other) => Err(forbidden(
            "cross_origin",
            format!("cross-site request refused (Sec-Fetch-Site: {other})"),
        )),
        None => Err(forbidden(
            "origin_required",
            format!(
                "state-changing requests must send an Origin header matching the Host \
                 (e.g. Origin: http://{host})"
            ),
        )),
    }
}

pub(crate) async fn origin_guard(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if let Err(e) = check_request(
        req.method(),
        req.headers(),
        &state.host_names,
        &state.cfg.allow_hosts,
        &state.cfg.allow_origins,
    ) {
        tracing::warn!(method = %req.method(), uri = %req.uri(), code = e.code, "request refused by origin guard");
        return e.into_response();
    }
    next.run(req).await
}

/// Per-connection addresses recorded by `axum::serve`: the peer and the
/// local address the connection arrived on. The local address is what
/// the operator used to reach this host, so runs must never take it
/// over (it goes into `protected_addrs`).
#[derive(Clone, Copy, Debug)]
pub struct ConnAddrs {
    pub peer: SocketAddr,
    pub local: Option<SocketAddr>,
}

impl ConnAddrs {
    #[cfg(test)]
    pub fn new(peer: SocketAddr, local: Option<SocketAddr>) -> Self {
        Self { peer, local }
    }
}

impl<'a> axum::extract::connect_info::Connected<axum::serve::IncomingStream<'a>> for ConnAddrs {
    fn connect_info(s: axum::serve::IncomingStream<'a>) -> Self {
        Self {
            peer: s.remote_addr(),
            local: s.local_addr().ok(),
        }
    }
}

/// Local address the request arrived on (None outside a TCP server).
pub(crate) struct LocalIp(pub Option<IpAddr>);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for LocalIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ip = ConnectInfo::<ConnAddrs>::from_request_parts(parts, state)
            .await
            .ok()
            .and_then(|c| c.0.local)
            .map(|a| a.ip())
            .filter(|ip| !ip.is_unspecified());
        Ok(LocalIp(ip))
    }
}

/// Peer address of the request ("unknown" when not served over TCP,
/// e.g. in tests without `MockConnectInfo`).
pub(crate) struct ClientIp(pub String);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Uses axum's extractor so `MockConnectInfo` works in tests.
        let ip = ConnectInfo::<ConnAddrs>::from_request_parts(parts, state)
            .await
            .map(|c| c.0.peer.ip().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        Ok(ClientIp(ip))
    }
}

/// Optional `X-Client-Id` header, echoed in run events.
pub(crate) fn client_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-client-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_graphic())
                .take(64)
                .collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hm(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn hosts() {
        let names = vec!["lab-vm".to_string(), "lab-vm.example.org".to_string()];
        let allow = vec!["outstation.lan".to_string()];
        for ok in [
            "127.0.0.1:8080",
            "10.1.2.3",
            "[::1]:8080",
            "localhost:8080",
            "LAB-VM:8080",
            "lab-vm.example.org",
            "outstation.lan:8080",
        ] {
            assert!(host_allowed(ok, &names, &allow), "{ok}");
        }
        for bad in [
            "evil.example",
            "lab-vm.evil.example",
            "",
            "localhost.evil.com",
        ] {
            assert!(!host_allowed(bad, &names, &allow), "{bad}");
        }
    }

    fn check(m: &Method, h: &HeaderMap, n: &[String], a: &[String]) -> Result<(), AppError> {
        check_request(m, h, n, a, &[])
    }

    #[test]
    fn origin_rules() {
        let n: Vec<String> = vec![];
        let h = "10.0.0.5:8080";
        // GET without Origin is fine; bad Host is not.
        assert!(check(&Method::GET, &hm(&[("host", h)]), &n, &n).is_ok());
        assert!(check(&Method::GET, &hm(&[("host", "evil.example")]), &n, &n).is_err());
        // POST needs a matching Origin or same-origin fetch metadata.
        assert!(check(&Method::POST, &hm(&[("host", h)]), &n, &n).is_err());
        assert!(check(
            &Method::POST,
            &hm(&[("host", h), ("origin", "http://10.0.0.5:8080")]),
            &n,
            &n
        )
        .is_ok());
        assert!(check(
            &Method::POST,
            &hm(&[("host", h), ("origin", "http://evil.example")]),
            &n,
            &n
        )
        .is_err());
        assert!(check(
            &Method::POST,
            &hm(&[("host", h), ("origin", "null")]),
            &n,
            &n
        )
        .is_err());
        assert!(check(
            &Method::DELETE,
            &hm(&[("host", h), ("sec-fetch-site", "same-origin")]),
            &n,
            &n
        )
        .is_ok());
        assert!(check(
            &Method::POST,
            &hm(&[("host", h), ("sec-fetch-site", "cross-site")]),
            &n,
            &n
        )
        .is_err());
        // WebSocket upgrade is a GET but still needs Origin.
        assert!(check(
            &Method::GET,
            &hm(&[("host", h), ("upgrade", "websocket")]),
            &n,
            &n
        )
        .is_err());
        assert!(check(
            &Method::GET,
            &hm(&[
                ("host", h),
                ("upgrade", "websocket"),
                ("origin", "http://10.0.0.5:8080")
            ]),
            &n,
            &n
        )
        .is_ok());
    }

    #[test]
    fn allowed_origins_pass_behind_a_proxy() {
        let n: Vec<String> = vec![];
        // A proxy rewrote Host to the backend address.
        let h = "localhost:18110";
        let allow = vec![normalize_origin("https://Portal.Example/")];
        for (m, extra) in [
            (Method::POST, None),
            (Method::GET, Some(("upgrade", "websocket"))),
        ] {
            let mut hs = vec![("host", h), ("origin", "https://portal.example")];
            hs.extend(extra);
            assert!(check_request(&m, &hm(&hs), &n, &n, &allow).is_ok());
            // Not listed: refused, and the message names the flag.
            let e = check_request(&m, &hm(&hs), &n, &n, &[]).unwrap_err();
            assert_eq!(e.code, "cross_origin");
            assert!(
                e.message.contains("--allow-origin https://portal.example"),
                "{}",
                e.message
            );
        }
        // Scheme and port must match exactly.
        for bad in [
            "http://portal.example",
            "https://portal.example:8443",
            "https://evil.portal.example",
        ] {
            let hs = [("host", h), ("origin", bad)];
            assert!(
                check_request(&Method::POST, &hm(&hs), &n, &n, &allow).is_err(),
                "{bad}"
            );
        }
    }
}
