use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// When true, the built-in IP blacklist is disabled (all IPs are allowed).
static BLACKLIST_DISABLED: AtomicBool = AtomicBool::new(false);

/// Family state for self-learning (Bitmask: 1=IPv4 failed, 2=IPv6 failed)
#[cfg(feature = "ipset")]
const FAMILY_FAIL_V4: u8 = 1 << 0;
#[cfg(feature = "ipset")]
const FAMILY_FAIL_V6: u8 = 1 << 1;

/// Disable the built-in IP blacklist for ipset add operations.
pub fn disable_blacklist() {
    BLACKLIST_DISABLED.store(true, Ordering::Relaxed);
}

/// Check if an IP is a bogon/invalid address that should not be added to ipsets.
fn is_blacklisted(ip: &IpAddr) -> bool {
    if BLACKLIST_DISABLED.load(Ordering::Relaxed) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()         // 127.0.0.0/8
            || v4.is_unspecified()   // 0.0.0.0
            || v4.is_broadcast()     // 255.255.255.255
            || v4.is_link_local()    // 169.254.0.0/16
            || v4.is_private()       // RFC 1918 private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_multicast()     // 224.0.0.0/4
            || *v4 == Ipv4Addr::new(0, 0, 0, 0)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()         // ::1
            || v6.is_unspecified()   // ::
            || v6.is_unique_local() // fc00::/7 unique local address
            || v6.is_unicast_link_local() // fe80::/10 link local
            || v6.is_multicast()     // ff00::/8 multicast
        }
    }
}

/// IP Family for a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    IPv4,
    IPv6,
    Both,
}

/// Type of firewall set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetType {
    Ipset,
    Nftables { family: String, table: String },
}

/// A target set for adding IPs.
#[derive(Debug, Clone)]
pub struct SetTarget {
    pub name: String,
    pub set_type: SetType,
    pub family: IpFamily,
    /// Runtime state to track protocol failures (self-learning)
    pub fail_state: Arc<AtomicU8>,
}

impl SetTarget {
    /// Parse a set string and detect its family.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        if s.starts_with("nft:") {
            // Format: nft:<family>:<table>:<set>
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 4 {
                let family_str = parts[1];
                let family = match family_str {
                    "ip" => IpFamily::IPv4,
                    "ip6" => IpFamily::IPv6,
                    "inet" => IpFamily::Both,
                    _ => IpFamily::Both,
                };
                return Some(SetTarget {
                    name: parts[3].to_string(),
                    set_type: SetType::Nftables {
                        family: family_str.to_string(),
                        table: parts[2].to_string(),
                    },
                    family,
                    fail_state: Arc::new(AtomicU8::new(0)),
                });
            }
        } else if s.starts_with("ipset:") {
            // Format: ipset:<family>:<name>
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() == 3 {
                let family = match parts[1] {
                    "ip" | "v4" | "4" => IpFamily::IPv4,
                    "ip6" | "v6" | "6" => IpFamily::IPv6,
                    "inet" | "both" => IpFamily::Both,
                    _ => IpFamily::Both,
                };
                return Some(SetTarget {
                    name: parts[2].to_string(),
                    set_type: SetType::Ipset,
                    family,
                    fail_state: Arc::new(AtomicU8::new(0)),
                });
            }
        } else if s.contains('@') {
            // Legacy NFT format: family@table@set
            let parts: Vec<&str> = s.split('@').collect();
            if parts.len() == 3 {
                let family_str = parts[0];
                let family = match family_str {
                    "ip" => IpFamily::IPv4,
                    "ip6" => IpFamily::IPv6,
                    "inet" => IpFamily::Both,
                    _ => IpFamily::Both,
                };
                return Some(SetTarget {
                    name: parts[2].to_string(),
                    set_type: SetType::Nftables {
                        family: family_str.to_string(),
                        table: parts[1].to_string(),
                    },
                    family,
                    fail_state: Arc::new(AtomicU8::new(0)),
                });
            }
        }

        // Default to Ipset
        let family = detect_ipset_family(s);
        Some(SetTarget {
            name: s.to_string(),
            set_type: SetType::Ipset,
            family,
            fail_state: Arc::new(AtomicU8::new(0)),
        })
    }
}

/// Detect the IP family of an ipset via name heuristic.
fn detect_ipset_family(name: &str) -> IpFamily {
    let bytes = name.as_bytes();
    let has_v6 = bytes.windows(2).any(|w| w.eq_ignore_ascii_case(b"v6"))
        || bytes.windows(3).any(|w| w.eq_ignore_ascii_case(b"ip6"));
    let has_v4 = bytes.windows(2).any(|w| w.eq_ignore_ascii_case(b"v4"))
        || bytes.windows(3).any(|w| w.eq_ignore_ascii_case(b"ip4"));
    if has_v6 {
        IpFamily::IPv6
    } else if has_v4 {
        IpFamily::IPv4
    } else {
        IpFamily::Both
    }
}

use crate::request_id::RequestId;

/// Context for adding IPs to OS ipsets/nftsets
pub struct IpsetAddCtx {
    pub targets: Arc<[SetTarget]>,
    ips: Vec<IpAddr>,
    req_id: RequestId,
}

pub fn new_addctx_from_targets(targets: Arc<[SetTarget]>, req_id: RequestId) -> Option<IpsetAddCtx> {
    if targets.is_empty() {
        return None;
    }
    Some(IpsetAddCtx {
        targets,
        ips: Vec::new(),
        req_id,
    })
}

pub fn new_addctx(name_list: &str, req_id: RequestId) -> Option<IpsetAddCtx> {
    let targets: Vec<SetTarget> = name_list.split(',').filter_map(SetTarget::parse).collect();

    new_addctx_from_targets(Arc::from(targets), req_id)
}

impl IpsetAddCtx {
    pub fn add(&mut self, ip: IpAddr) {
        if !is_blacklisted(&ip) {
            if !self.ips.contains(&ip) {
                self.ips.push(ip);
            }
        } else {
            tracing::debug!(
                "[{}] Skipping blacklisted IP {} for ipset add",
                self.req_id,
                ip
            );
        }
    }

    pub fn flush(&mut self) {
        #[cfg(feature = "ipset")]
        for target in self.targets.iter() {
            let fail_state = target.fail_state.load(Ordering::Relaxed);
            for ip in &self.ips {
                let matches = match (ip, target.family) {
                    (IpAddr::V4(_), IpFamily::IPv4) | (IpAddr::V4(_), IpFamily::Both) => {
                        (fail_state & FAMILY_FAIL_V4) == 0
                    }
                    (IpAddr::V6(_), IpFamily::IPv6) | (IpAddr::V6(_), IpFamily::Both) => {
                        (fail_state & FAMILY_FAIL_V6) == 0
                    }
                    _ => false,
                };

                if matches {
                    match &target.set_type {
                        SetType::Ipset => {
                            self.native_ipset_add(target, *ip);
                        }
                        SetType::Nftables { family, table } => {
                            self.native_nft_add(target, family, table, &target.name, *ip);
                        }
                    }
                }
            }
        }
        self.ips.clear();
    }

    #[cfg(feature = "ipset")]
    fn native_ipset_add(&self, target: &SetTarget, ip: IpAddr) {
        tracing::debug!("[{}] ripset_add {} {}", self.req_id, target.name, ip);
        if let Err(e) = ripset::ipset_add(&target.name, ip) {
            // Self-learning: if kernel says Address family not supported (4097 / EAFNOSUPPORT)
            if is_afnosupport_err(&e) {
                let bit = if ip.is_ipv4() {
                    FAMILY_FAIL_V4
                } else {
                    FAMILY_FAIL_V6
                };
                target.fail_state.fetch_or(bit, Ordering::Relaxed);
                tracing::warn!(
                    "[{}] Set {} does not support {}, skipping in future",
                    self.req_id,
                    target.name,
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                );
            } else {
                tracing::debug!(
                    "[{}] ripset_add {} {} returned: {}",
                    self.req_id,
                    target.name,
                    ip,
                    e
                );
            }
        }
    }

    #[cfg(feature = "ipset")]
    fn native_nft_add(&self, target: &SetTarget, family: &str, table: &str, set: &str, ip: IpAddr) {
        tracing::debug!(
            "[{}] nftset_add {} {} {} {}",
            self.req_id,
            family,
            table,
            set,
            ip
        );
        if let Err(e) = ripset::nftset_add(family, table, set, ip) {
            if is_afnosupport_err(&e) {
                let bit = if ip.is_ipv4() {
                    FAMILY_FAIL_V4
                } else {
                    FAMILY_FAIL_V6
                };
                target.fail_state.fetch_or(bit, Ordering::Relaxed);
                tracing::warn!(
                    "[{}] Nft set {}:{}:{} does not support {}, skipping in future",
                    self.req_id,
                    family,
                    table,
                    set,
                    if ip.is_ipv4() { "IPv4" } else { "IPv6" }
                );
            } else {
                tracing::debug!(
                    "[{}] nftset_add {} {} {} {} returned: {}",
                    self.req_id,
                    family,
                    table,
                    set,
                    ip,
                    e
                );
            }
        }
    }
}

#[cfg(any(feature = "ipset", test))]
fn is_afnosupport_err<E: std::fmt::Display>(e: &E) -> bool {
    use std::fmt::Write;
    struct StackBuf([u8; 256], usize);
    impl Write for StackBuf {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            let to_write = s.as_bytes();
            let available = self.0.len().saturating_sub(self.1);
            let n = to_write.len().min(available);
            self.0[self.1..self.1 + n].copy_from_slice(&to_write[..n]);
            self.1 += n;
            Ok(())
        }
    }
    let mut buf = StackBuf([0u8; 256], 0);
    let _ = write!(buf, "{}", e);
    if let Ok(s) = std::str::from_utf8(&buf.0[..buf.1]) {
        // 4097: IPSET_ERR_TYPE_MISMATCH for ipset
        // EAFNOSUPPORT (97) / EINVAL (22): nftables kernel / libc error strings & codes
        s.contains("4097")
            || s.contains("Address family not supported")
            || s.contains("EAFNOSUPPORT")
            || s.contains("os error 97")
            || s.contains("errno 97")
            || s.contains("error 97")
            || s.contains("Invalid argument")
            || s.contains("EINVAL")
            || s.contains("os error 22")
            || s.contains("errno 22")
            || s.contains("error 22")
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_set_target() {
        // Test legacy ipset format
        let t = SetTarget::parse("tap11").unwrap();
        assert_eq!(t.name, "tap11");
        assert_eq!(t.family, IpFamily::Both);

        let t = SetTarget::parse("tap11v6").unwrap();
        assert_eq!(t.name, "tap11v6");
        assert_eq!(t.family, IpFamily::IPv6);

        let t = SetTarget::parse("chnroute_v4").unwrap();
        assert_eq!(t.name, "chnroute_v4");
        assert_eq!(t.family, IpFamily::IPv4);

        // Test explicit ipset format
        let t = SetTarget::parse("ipset:v4:my-set").unwrap();
        assert_eq!(t.name, "my-set");
        assert_eq!(t.family, IpFamily::IPv4);

        let t = SetTarget::parse("ipset:v6:my-v6-set").unwrap();
        assert_eq!(t.name, "my-v6-set");
        assert_eq!(t.family, IpFamily::IPv6);

        // Test nft format
        let t = SetTarget::parse("nft:ip:filter:chnroute").unwrap();
        assert_eq!(t.name, "chnroute");
        assert_eq!(t.family, IpFamily::IPv4);
        if let SetType::Nftables { family, table } = t.set_type {
            assert_eq!(family, "ip");
            assert_eq!(table, "filter");
        } else {
            panic!("Wrong set type");
        }

        let t = SetTarget::parse("ip6@filter@chnroute6").unwrap();
        assert_eq!(t.name, "chnroute6");
        assert_eq!(t.family, IpFamily::IPv6);
    }

    #[test]
    fn test_is_afnosupport_err() {
        assert!(is_afnosupport_err(&"ipset error 4097: element mismatch"));
        assert!(is_afnosupport_err(&"Address family not supported by protocol"));
        assert!(is_afnosupport_err(&"error: EAFNOSUPPORT"));
        assert!(is_afnosupport_err(&"failed with os error 97"));
        assert!(is_afnosupport_err(&"Invalid argument"));
        assert!(is_afnosupport_err(&"EINVAL: invalid set element"));
        assert!(!is_afnosupport_err(&"Permission denied (os error 13)"));
        assert!(!is_afnosupport_err(&"connection failed on port 22"));
        assert!(!is_afnosupport_err(&"failed to add 192.168.1.97: set full"));
    }

    #[test]
    fn test_is_blacklisted_extended() {
        // Loopback
        assert!(is_blacklisted(&"127.0.0.1".parse().unwrap()));
        assert!(is_blacklisted(&"::1".parse().unwrap()));
        // Link local
        assert!(is_blacklisted(&"169.254.1.1".parse().unwrap()));
        assert!(is_blacklisted(&"fe80::1".parse().unwrap()));
        // Multicast
        assert!(is_blacklisted(&"224.0.0.1".parse().unwrap()));
        assert!(is_blacklisted(&"ff02::1".parse().unwrap()));
        // Private
        assert!(is_blacklisted(&"192.168.1.1".parse().unwrap()));
        assert!(is_blacklisted(&"10.0.0.1".parse().unwrap()));
        assert!(is_blacklisted(&"fd00::1".parse().unwrap()));
        // Public IPs should not be blacklisted
        assert!(!is_blacklisted(&"1.1.1.1".parse().unwrap()));
        assert!(!is_blacklisted(&"2606:4700:4700::1111".parse().unwrap()));
    }
}
