//! Per-client rate limiting shared by bff and login: the key extractor (peer address, or the
//! client a trusted proxy reports in `X-Forwarded-For`) and the governor builder.

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request};
use governor::middleware::NoOpMiddleware;
use ipnet::IpNet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Once};
use tower_governor::GovernorError;
use tower_governor::governor::{GovernorConfig, GovernorConfigBuilder};
use tower_governor::key_extractor::KeyExtractor;

pub type Governor = Arc<GovernorConfig<ClientIpKeyExtractor, NoOpMiddleware>>;

/// A bucket per client: a burst of `max_attempts`, then one attempt back every
/// `window_secs / max_attempts` seconds, to the millisecond and no faster than every 1ms (so
/// above `window_secs * 1000` attempts it refills like that).
pub fn build_governor(
    max_attempts: u32,
    window_secs: u64,
    trusted_proxies: &[IpNet],
) -> anyhow::Result<Governor> {
    let replenish_ms = (window_secs * 1000)
        .checked_div(u64::from(max_attempts))
        .ok_or_else(|| anyhow::anyhow!("a rate limit is 0"))?
        .max(1);
    let governor = GovernorConfigBuilder::default()
        .key_extractor(ClientIpKeyExtractor::new(trusted_proxies))
        .burst_size(max_attempts)
        .per_millisecond(replenish_ms)
        .finish()
        .ok_or_else(|| anyhow::anyhow!("invalid governor rate-limit config"))?;
    Ok(Arc::new(governor))
}

/// Rate-limit key: the peer address, or, when the peer is one of the trusted
/// proxies, the client address it reports in `X-Forwarded-For`.
#[derive(Clone)]
pub struct ClientIpKeyExtractor {
    trusted_proxies: Arc<[IpNet]>,
}

impl ClientIpKeyExtractor {
    pub fn new(trusted_proxies: &[IpNet]) -> Self {
        Self {
            trusted_proxies: trusted_proxies.into(),
        }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<IpAddr, GovernorError> {
        request_client_ip(req, &self.trusted_proxies)
            .map(per_network)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// The client's own address: the peer, or what a trusted proxy reports for it
/// in `X-Forwarded-For`. `None` without the peer's `ConnectInfo`.
fn request_client_ip<T>(req: &Request<T>, trusted_proxies: &[IpNet]) -> Option<IpAddr> {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>()?.0.ip();
    Some(client_ip_of(peer, req.headers(), trusted_proxies))
}

/// The client behind `peer`, as [`ClientIpKeyExtractor`] resolves it, without the per-network
/// truncation of the rate-limit key.
pub fn client_ip_of(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> IpAddr {
    let forwarded_for = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|line| line.as_bytes().split(|&byte| byte == b','));
    client_ip(peer, forwarded_for, trusted_proxies)
}

/// Walks the `X-Forwarded-For` entries right to left while the hop it reached
/// is trusted. Each proxy appends the address it got the request from, so only
/// the entries right of the first untrusted one were written by proxies; the
/// rest are whatever the client sent. Entries are bytes, not lines: a proxy
/// may append to the client's own line, whose non-ASCII bytes must not hide
/// the proxy's entry.
fn client_ip<'a>(
    peer: IpAddr,
    forwarded_for: impl DoubleEndedIterator<Item = &'a [u8]>,
    trusted_proxies: &[IpNet],
) -> IpAddr {
    let is_trusted = |ip: &IpAddr| trusted_proxies.iter().any(|net| net.contains(ip));
    let mut client = peer.to_canonical();
    for hop in forwarded_for.rev() {
        if !is_trusted(&client) {
            break;
        }
        let hop = String::from_utf8_lossy(hop);
        match parse_hop(hop.trim()) {
            Some(ip) => client = ip.to_canonical(),
            None => {
                // Swallowed: keying on the proxy beats rejecting the request.
                // Once, as a misbehaving proxy would otherwise log it on every request.
                static WARNED: Once = Once::new();
                WARNED.call_once(|| {
                    tracing::warn!(
                        proxy = %client,
                        entry = hop.trim(),
                        "X-Forwarded-For entry from a trusted proxy is not an IP address; \
                         rate-limiting on the proxy's address (logged once)"
                    );
                });
                break;
            }
        }
    }
    client
}

/// Some load balancers append the client's port: `ip:port` or `[v6]:port`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    hop.parse()
        .ok()
        .or_else(|| hop.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

/// A single host usually holds a whole IPv6 /64, so keying on the full address
/// would hand it 2^64 budgets.
// ponytail: /64 per client, so a routed /48 still gets 65536 budgets; key on the /56 or /48 if that matters.
fn per_network(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !(u128::MAX >> 64))),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trusted() -> Vec<IpNet> {
        vec!["10.0.0.0/8".parse().unwrap()]
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The client address of a request from `peer` carrying these `X-Forwarded-For` lines.
    fn walk(peer: &str, lines: &[&str]) -> IpAddr {
        let lines: Vec<&[u8]> = lines.iter().map(|line| line.as_bytes()).collect();
        walk_bytes(peer, &lines)
    }

    fn walk_bytes(peer: &str, lines: &[&[u8]]) -> IpAddr {
        let mut req = Request::new(());
        for line in lines {
            req.headers_mut().append(
                "x-forwarded-for",
                axum::http::HeaderValue::from_bytes(line).unwrap(),
            );
        }
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip(peer), 4711)));
        request_client_ip(&req, &trusted()).unwrap()
    }

    #[test]
    fn a_bucket_refills_at_the_configured_rate_even_above_one_per_second() {
        // 6000 a minute: one attempt back every 10ms.
        let governor = build_governor(6000, 60, &[]).unwrap();
        let limiter = governor.limiter();
        let client = ip("198.51.100.1");
        while limiter.check_key(&client).is_ok() {}

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(limiter.check_key(&client).is_ok());
    }

    #[test]
    fn an_untrusted_peer_is_the_key_whatever_it_claims() {
        let key = walk("203.0.113.9", &["198.51.100.1"]);
        assert_eq!(key, ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_proxy_is_keyed_on_the_client_it_reports() {
        let key = walk("10.0.0.2", &["198.51.100.1"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn entries_the_client_wrote_itself_are_ignored() {
        let key = walk("10.0.0.2", &["1.1.1.1, 198.51.100.1"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn a_chain_of_trusted_proxies_across_header_lines_is_skipped() {
        let key = walk("10.0.0.2", &["1.1.1.1, 198.51.100.1", "10.0.0.3"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn a_trusted_proxy_that_sends_no_header_is_the_key() {
        let key = walk("10.0.0.2", &[]);
        assert_eq!(key, ip("10.0.0.2"));
    }

    #[test]
    fn an_entry_that_is_not_an_address_stops_the_walk() {
        let key = walk("10.0.0.2", &["198.51.100.1, unknown"]);
        assert_eq!(key, ip("10.0.0.2"));
    }

    #[test]
    fn a_non_ascii_byte_the_client_sent_does_not_hide_the_proxys_entry() {
        let key = walk_bytes("10.0.0.2", &[b"\x80, 198.51.100.1"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn an_entry_with_a_port_is_keyed_on_its_address() {
        let v4 = walk("10.0.0.2", &["198.51.100.1:4711"]);
        let v6 = walk("10.0.0.2", &["[2001:db8::]:443"]);
        assert_eq!((v4, v6), (ip("198.51.100.1"), ip("2001:db8::")));
    }

    #[test]
    fn a_v4_mapped_peer_is_matched_against_v4_proxies() {
        let key = walk("::ffff:10.0.0.2", &["198.51.100.1"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn a_v4_mapped_client_shares_its_v4_budget() {
        let key = walk("10.0.0.2", &["::ffff:198.51.100.1"]);
        assert_eq!(key, ip("198.51.100.1"));
    }

    #[test]
    fn ipv6_clients_are_keyed_on_their_64() {
        let key = |peer| per_network(walk(peer, &[]));
        assert_eq!(key("2001:db8:1:2::5"), ip("2001:db8:1:2::"));
        assert_eq!(key("2001:db8:1:2:ffff::1"), ip("2001:db8:1:2::"));
        assert_eq!(key("2001:db8:1:3::1"), ip("2001:db8:1:3::"));
    }
}
