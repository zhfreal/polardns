use compact_str::CompactString;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

pub struct HostsMap {
    v4: FxHashMap<CompactString, SmallVec<[Ipv4Addr; 1]>>,
    v6: FxHashMap<CompactString, SmallVec<[Ipv6Addr; 1]>>,
}

static HOSTS_MAP: RwLock<Option<HostsMap>> = RwLock::new(None);
static HOSTS_ENABLED: AtomicBool = AtomicBool::new(false);

fn normalize_domain_key(domain: &str) -> CompactString {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        CompactString::new(trimmed.to_ascii_lowercase())
    } else {
        CompactString::new(trimmed)
    }
}

pub fn init(filename: &str) {
    let file = match File::open(filename) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!("failed to open hosts file '{}': {}", filename, e);
            return;
        }
    };

    let reader = BufReader::new(file);
    let mut count = 0;

    let mut map_lock = HOSTS_MAP.write().unwrap();
    let map = map_lock.get_or_insert_with(|| HostsMap {
        v4: FxHashMap::default(),
        v6: FxHashMap::default(),
    });

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Strip comments
        let content = line.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }

        let mut parts = content.split_whitespace();
        let ip_str = match parts.next() {
            Some(ip) => ip,
            None => continue,
        };

        let ip_addr: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        for domain in parts {
            let key = normalize_domain_key(domain);
            match ip_addr {
                IpAddr::V4(ipv4) => {
                    let entry = map.v4.entry(key).or_default();
                    if !entry.contains(&ipv4) {
                        entry.push(ipv4);
                    }
                }
                IpAddr::V6(ipv6) => {
                    let entry = map.v6.entry(key).or_default();
                    if !entry.contains(&ipv6) {
                        entry.push(ipv6);
                    }
                }
            }
            count += 1;
        }
    }

    for v in map.v4.values_mut() {
        v.shrink_to_fit();
    }
    for v in map.v6.values_mut() {
        v.shrink_to_fit();
    }
    map.v4.shrink_to_fit();
    map.v6.shrink_to_fit();

    HOSTS_ENABLED.store(true, Ordering::Release);
    tracing::info!("Loaded {} hosts from '{}'", count, filename);
}

/// Parse `--dns-rr-ip` args in format: `name1,name2=ip1,ip2`
pub fn init_from_args(args: &[String]) {
    let mut map_lock = HOSTS_MAP.write().unwrap();
    let map = map_lock.get_or_insert_with(|| HostsMap {
        v4: FxHashMap::default(),
        v6: FxHashMap::default(),
    });

    let mut count = 0;
    for arg in args {
        let Some((names_part, ips_part)) = arg.split_once('=') else {
            tracing::warn!("Invalid --dns-rr-ip format '{}', expected 'name=ip'", arg);
            continue;
        };

        let names: Vec<&str> = names_part
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        let ips: Vec<&str> = ips_part
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for name in &names {
            let key = normalize_domain_key(name);
            for ip_str in &ips {
                match ip_str.parse::<IpAddr>() {
                    Ok(IpAddr::V4(ipv4)) => {
                        let entry = map.v4.entry(key.clone()).or_default();
                        if !entry.contains(&ipv4) {
                            entry.push(ipv4);
                            count += 1;
                        }
                    }
                    Ok(IpAddr::V6(ipv6)) => {
                        let entry = map.v6.entry(key.clone()).or_default();
                        if !entry.contains(&ipv6) {
                            entry.push(ipv6);
                            count += 1;
                        }
                    }
                    Err(_) => {
                        tracing::warn!("Invalid IP '{}' in --dns-rr-ip", ip_str);
                    }
                }
            }
        }
    }

    if count > 0 {
        HOSTS_ENABLED.store(true, Ordering::Release);
        tracing::info!("Loaded {} dns-rr-ip records from CLI", count);
    }
}

pub fn get_ips(domain: &str, qtype: u16) -> Vec<IpAddr> {
    if !HOSTS_ENABLED.load(Ordering::Relaxed) {
        return Vec::new();
    }
    let map_lock = HOSTS_MAP.read().unwrap();
    let map = match map_lock.as_ref() {
        Some(m) => m,
        None => return Vec::new(),
    };

    let domain_trimmed = domain.trim_end_matches('.');
    let mut lower_buf = [0u8; 255];
    let domain_lower = if domain_trimmed.len() <= lower_buf.len()
        && domain_trimmed.bytes().any(|b| b.is_ascii_uppercase())
    {
        let bytes = domain_trimmed.as_bytes();
        lower_buf[..bytes.len()].copy_from_slice(bytes);
        lower_buf[..bytes.len()].make_ascii_lowercase();
        unsafe { std::str::from_utf8_unchecked(&lower_buf[..bytes.len()]) }
    } else if domain_trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        &domain_trimmed.to_ascii_lowercase()
    } else {
        domain_trimmed
    };

    if qtype == 1 {
        // A record
        if let Some(ips) = map.v4.get(domain_lower) {
            return ips.iter().map(|&ip| IpAddr::V4(ip)).collect();
        }
    } else if qtype == 28 {
        // AAAA record
        if let Some(ips) = map.v6.get(domain_lower) {
            return ips.iter().map(|&ip| IpAddr::V6(ip)).collect();
        }
    }

    Vec::new()
}

pub fn build_response(query: &[u8], domain: &str, qtype: u16) -> Option<Vec<u8>> {
    if !HOSTS_ENABLED.load(Ordering::Relaxed) {
        return None;
    }
    let map_lock = HOSTS_MAP.read().unwrap();
    let map = map_lock.as_ref()?;

    let domain_trimmed = domain.trim_end_matches('.');
    let mut lower_buf = [0u8; 255];
    let domain_lower = if domain_trimmed.len() <= lower_buf.len()
        && domain_trimmed.bytes().any(|b| b.is_ascii_uppercase())
    {
        let bytes = domain_trimmed.as_bytes();
        lower_buf[..bytes.len()].copy_from_slice(bytes);
        lower_buf[..bytes.len()].make_ascii_lowercase();
        unsafe { std::str::from_utf8_unchecked(&lower_buf[..bytes.len()]) }
    } else if domain_trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        &domain_trimmed.to_ascii_lowercase()
    } else {
        domain_trimmed
    };

    if qtype == 1 {
        if let Some(ips) = map.v4.get(domain_lower)
            && !ips.is_empty()
        {
            return Some(crate::dns::build_hosts_response_iter(
                query,
                ips.iter().copied().map(IpAddr::V4),
            ));
        }
    } else if qtype == 28
        && let Some(ips) = map.v6.get(domain_lower)
        && !ips.is_empty()
    {
        return Some(crate::dns::build_hosts_response_iter(
            query,
            ips.iter().copied().map(IpAddr::V6),
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_hosts_init_and_cli_merge() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "1.2.3.4 example.com").unwrap();
        init(f.path().to_str().unwrap());

        init_from_args(&["cli.test=5.6.7.8".to_string()]);

        // Both file-based and CLI-based records should be present
        assert_eq!(get_ips("example.com", 1), vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(get_ips("cli.test", 1), vec![IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))]);
    }
}
