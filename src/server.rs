#[cfg(feature = "server-doh")]
use http_body_util::{BodyExt, Full};
#[cfg(feature = "server-doh")]
use hyper::service::service_fn;
#[cfg(feature = "server-doh")]
use hyper::{Request, Response, body::Bytes, body::Incoming};
#[cfg(feature = "server-doh")]
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(feature = "server-doh")]
use hyper_util::server::conn::auto;
#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
use quinn;
#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
use quinn::crypto::rustls::QuicServerConfig;
use rustc_hash::{FxHashMap, FxHashSet};
#[cfg(feature = "rustls-stack")]
use rustls::ServerConfig;
#[cfg(feature = "rustls-stack")]
use rustls::server::{ClientHello, ResolvesServerCert};
#[cfg(feature = "rustls-stack")]
use rustls::sign::CertifiedKey;
#[cfg(all(feature = "rustls-stack", any(feature = "server-dot", feature = "server-doh")))]
use tokio_rustls::TlsAcceptor;

#[cfg(all(feature = "boring", not(feature = "rustls-stack"), any(feature = "server-dot", feature = "server-doh")))]
pub type TlsAcceptor = Arc<boring::ssl::SslAcceptor>;

#[cfg(feature = "rustls-stack")]
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;
use tracing::{debug, error, info};

use crate::cache::{CacheStatus, DnsCache};
use crate::dnl;
use crate::dns::{DnsMessage, DnsView};
use crate::opt::Opt;
use crate::request_id::RequestId;
use crate::tag::Tag;
use crate::upstream::{TlsConfig, UpstreamProtocol};

const DNS_BUF_SIZE: usize = 4096;
#[cfg(any(feature = "server-doh", all(feature = "server-h3", feature = "original-h3-server")))]
const DOH_GET_DNS_PARAM_MAX: usize = DNS_BUF_SIZE.div_ceil(3) * 4 + 4;
#[cfg(any(feature = "server-doh", all(feature = "server-h3", feature = "original-h3-server")))]
const DOH_BODY_READ_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(feature = "server-doh")]
const DOH_HTTP1_MAX_BUF_SIZE: usize = 32 * 1024;
#[cfg(feature = "server-doh")]
const DOH_HTTP2_MAX_HEADER_LIST_SIZE: u32 = 8 * 1024;
#[cfg(feature = "server-doh")]
const DOH_HTTP2_MAX_SEND_BUF_SIZE: usize = 16 * 1024;
#[cfg(any(feature = "server-doh", all(feature = "server-h3", feature = "original-h3-server")))]
const DOH_MAX_STREAMS_PER_CONN: u32 = 128;
#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
const DOH3_MAX_UNI_STREAMS: u32 = 16;

pub const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_millis(crate::opt::DEFAULT_UPSTREAM_TIMEOUT_MS as u64);
pub const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_millis(crate::opt::DEFAULT_TCP_IDLE_TIMEOUT_MS as u64);
pub const DEFAULT_QUIC_IDLE_TIMEOUT: Duration = Duration::from_millis(crate::opt::DEFAULT_QUIC_IDLE_TIMEOUT_MS as u64);
pub const DEFAULT_QUEUE_TIMEOUT: Duration = Duration::from_millis(crate::opt::DEFAULT_QUEUE_TIMEOUT_MS as u64);
pub const DEFAULT_RTT_PROBE_INTERVAL: Duration = Duration::from_secs(crate::opt::DEFAULT_RTT_PROBE_INTERVAL_SECS);
pub const DEFAULT_RTT_PROBE_TIMEOUT: Duration = Duration::from_millis(crate::opt::DEFAULT_RTT_PROBE_TIMEOUT_MS);
pub const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(10);
pub const SERVER_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(60);
pub const SERVER_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const H2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
pub const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MIN_DOQ_STREAM_TIMEOUT: Duration = Duration::from_secs(3);
pub const JEMALLOC_PURGE_INTERVAL: Duration = Duration::from_secs(60);

fn upstreams_need_default_dot(upstreams: &FxHashMap<Tag, Arc<[UpstreamProtocol]>>) -> bool {
    upstreams.values().any(|list| {
        list.iter().any(|upstream| {
            matches!(
                upstream,
                UpstreamProtocol::Dot { tls, .. } if tls.ca_certs.is_none()
            )
        })
    })
}

fn upstreams_need_default_doh(upstreams: &FxHashMap<Tag, Arc<[UpstreamProtocol]>>) -> bool {
    upstreams.values().any(|list| {
        list.iter().any(|upstream| {
            matches!(
                upstream,
                UpstreamProtocol::Doh { tls, .. } | UpstreamProtocol::DohH3 { tls, .. }
                    if tls.ca_certs.is_none()
            )
        })
    })
}

#[cfg(feature = "rustls-stack")]
fn upstreams_need_default_doh3(upstreams: &FxHashMap<Tag, Arc<[UpstreamProtocol]>>) -> bool {
    upstreams.values().any(|list| {
        list.iter().any(|upstream| {
            matches!(
                upstream,
                UpstreamProtocol::DohH3 { tls, .. } if tls.ca_certs.is_none()
            )
        })
    })
}

fn collect_upstream_ca_paths<F>(
    upstreams: &FxHashMap<Tag, Arc<[UpstreamProtocol]>>,
    mut ca_path_for: F,
) -> Vec<String>
where
    F: FnMut(&UpstreamProtocol) -> Option<&String>,
{
    let mut seen = FxHashSet::default();
    let mut paths = Vec::new();
    for list in upstreams.values() {
        for upstream in list.iter() {
            if let Some(ca_path) = ca_path_for(upstream)
                && seen.insert(ca_path.clone())
            {
                paths.push(ca_path.clone());
            }
        }
    }
    paths
}

#[cfg(feature = "rustls-stack")]
fn load_reqwest_ca_certs(ca_file: &str) -> anyhow::Result<Vec<reqwest::tls::Certificate>> {
    let ca_data = std::fs::read(ca_file)?;
    let mut cursor = std::io::Cursor::new(ca_data);
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert?;
        certs.push(reqwest::tls::Certificate::from_der(&cert)?);
    }
    if certs.is_empty() {
        anyhow::bail!("no valid CA certificates found in '{}'", ca_file);
    }
    Ok(certs)
}

#[cfg(feature = "rustls-stack")]
fn load_reqwest_ca_certs_lenient(ca_file: &str) -> std::io::Result<Vec<reqwest::tls::Certificate>> {
    let ca_data = std::fs::read(ca_file)?;
    let mut cursor = std::io::Cursor::new(ca_data);
    let certs = rustls_pemfile::certs(&mut cursor)
        .flatten()
        .filter_map(|cert| reqwest::tls::Certificate::from_der(&cert).ok())
        .collect();
    Ok(certs)
}

#[cfg(feature = "rustls-stack")]
fn build_reqwest_client_with_ca(
    ca_file: &str,
    timeout_duration: Duration,
    http3: bool,
    user_agent: &str,
) -> anyhow::Result<reqwest::Client> {
    let certs = load_reqwest_ca_certs(ca_file)?;
    let mut builder = reqwest::Client::builder()
        .user_agent(user_agent)
        .timeout(timeout_duration)
        .tls_built_in_root_certs(false);
    if http3 {
        #[cfg(feature = "upstream-h3")]
        {
            builder = builder.http3_prior_knowledge();
        }
        #[cfg(not(feature = "upstream-h3"))]
        {
            anyhow::bail!("h3:// upstreams require build feature 'upstream-h3'");
        }
    }
    for cert in certs {
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder.build()?)
}

#[cfg(feature = "rustls-stack")]
fn build_default_http3_client(
    timeout_duration: Duration,
    user_agent: &str,
) -> anyhow::Result<Option<reqwest::ClientBuilder>> {
    #[cfg(feature = "upstream-h3")]
    {
        Ok(Some(
            reqwest::Client::builder()
                .user_agent(user_agent)
                .timeout(timeout_duration)
                .http3_prior_knowledge(),
        ))
    }

    #[cfg(not(feature = "upstream-h3"))]
    {
        let _ = (timeout_duration, user_agent);
        Ok(None)
    }
}

#[cfg(feature = "rustls-stack")]
fn upstream_clients(state: &ServerState) -> crate::upstream::UpstreamClients<'_> {
    crate::upstream::UpstreamClients {
        default_tls: state.tls_config.clone(),
        tls_by_ca: &state.tls_config_by_ca,
        default_http: state.http_client.as_deref(),
        http_by_ca: &state.http_clients_by_ca,
        default_http3: state.http3_client.as_deref(),
        http3_by_ca: &state.http3_clients_by_ca,
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
fn upstream_clients(state: &ServerState) -> crate::upstream::UpstreamClients<'_> {
    crate::upstream::UpstreamClients {
        default_tls: state.tls_config.clone(),
        tls_by_ca: &state.tls_config_by_ca,
        default_http: state.http_client.as_deref(),
        http_by_ca: &state.http_clients_by_ca,
    }
}

#[cfg(all(
    feature = "rustls-stack",
    any(
        feature = "server-dot",
        feature = "server-doh",
        all(feature = "server-h3", feature = "original-h3-server")
    )
))]
fn build_local_tls_config(
    opt: &Opt,
    cert_resolver: Arc<dyn ResolvesServerCert>,
    alpn_protocols: Vec<Vec<u8>>,
    allow_tls12: bool,
) -> anyhow::Result<ServerConfig> {
    #[cfg(not(feature = "tls12"))]
    let _ = (opt, allow_tls12);

    let mut config = {
        #[cfg(feature = "tls12")]
        {
            if allow_tls12 && opt.enable_tls12 {
                ServerConfig::builder_with_protocol_versions(&[
                    &rustls::version::TLS13,
                    &rustls::version::TLS12,
                ])
            } else {
                ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            }
        }

        #[cfg(not(feature = "tls12"))]
        {
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        }
    }
    .with_no_client_auth()
    .with_cert_resolver(cert_resolver);

    config.alpn_protocols = alpn_protocols;
    Ok(config)
}

pub async fn run_server(opt: Arc<Opt>) -> anyhow::Result<()> {
    // 1. Upstream configuration
    let direct_dns_raw = opt.direct_dns.as_deref().unwrap_or("114.114.114.114");
    let trust_dns_raw = opt.proxy_dns.as_deref().unwrap_or("8.8.8.8");
    let fallback_dns_raw = opt.fallback_dns.as_deref().unwrap_or("114.114.114.114");

    let parse_upstreams = |raw: &str| -> Vec<UpstreamProtocol> {
        let mut ups = Vec::new();
        for s in raw.split(',') {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            if let Some(proto) = UpstreamProtocol::parse(s) {
                ups.push(proto);
            }
        }
        ups
    };

    let parse_fallback_upstreams = |raw: &str| -> Vec<UpstreamProtocol> {
        let mut supported = Vec::new();
        for upstream in parse_upstreams(raw) {
            match upstream {
                UpstreamProtocol::Udp(..)
                | UpstreamProtocol::Tcp(..)
                | UpstreamProtocol::UdpAndTcp(..) => {
                    supported.push(upstream);
                }
                other => {
                    tracing::warn!(
                        "Ignoring unsupported --fallback-dns upstream {:?}. Fallback DNS is a bootstrap resolver and supports only IP literals, udp://IP, or tcp://IP.",
                        other
                    );
                }
            }
        }
        supported
    };

    let mut tag_to_upstreams: FxHashMap<Tag, Vec<UpstreamProtocol>> = FxHashMap::default();
    tag_to_upstreams.insert(Tag::Direct, parse_upstreams(direct_dns_raw));
    tag_to_upstreams.insert(Tag::Proxy, parse_upstreams(trust_dns_raw));
    let fallback_upstreams = parse_fallback_upstreams(fallback_dns_raw);
    if opt.fallback_dns.is_some() && fallback_upstreams.is_empty() {
        anyhow::bail!(
            "--fallback-dns supports only IP literals, udp://IP, or tcp://IP bootstrap resolvers"
        );
    }

    for up_arg in &opt.group_upstream {
        if let Some((tag_name, ups_raw)) = up_arg.split_once(':')
            && let Some(t) = Tag::from_name(tag_name)
        {
            tag_to_upstreams
                .entry(t)
                .or_default()
                .extend(parse_upstreams(ups_raw));
        }
    }

    #[cfg(feature = "ipset")]
    let tag_to_sets: FxHashMap<Tag, Arc<[crate::ipset::SetTarget]>> = {
        let mut tag_to_sets: FxHashMap<Tag, Vec<crate::ipset::SetTarget>> = FxHashMap::default();

        // Merge Tag::Direct sets
        let mut direct_set_strs = opt.direct_sets.clone();
        if let Some(ref legacy) = opt.add_tagchn_ip {
            direct_set_strs.extend(legacy.split(',').map(|s| s.to_string()));
        }
        for s in direct_set_strs {
            if let Some(target) = crate::ipset::SetTarget::parse(&s) {
                tag_to_sets.entry(Tag::Direct).or_default().push(target);
            }
        }

        // Merge Tag::Proxy sets
        let mut gfw_set_strs = opt.proxy_sets.clone();
        if let Some(ref legacy) = opt.add_taggfw_ip {
            gfw_set_strs.extend(legacy.split(',').map(|s| s.to_string()));
        }
        for s in gfw_set_strs {
            if let Some(target) = crate::ipset::SetTarget::parse(&s) {
                tag_to_sets.entry(Tag::Proxy).or_default().push(target);
            }
        }

        // Merge group sets
        let mut group_set_entries = opt.group_sets.clone();
        group_set_entries.extend(opt.group_ipset.clone());
        for entry in group_set_entries {
            if let Some((tag_name, sets_raw)) = entry.split_once(':')
                && let Some(t) = Tag::from_name(tag_name)
            {
                for s in sets_raw.split(',') {
                    if let Some(target) = crate::ipset::SetTarget::parse(s) {
                        tag_to_sets.entry(t).or_default().push(target);
                    }
                }
            }
        }

        info!("Set configuration summary: {:?}", tag_to_sets);
        tag_to_sets
            .into_iter()
            .map(|(tag, targets)| (tag, Arc::from(targets)))
            .collect()
    };
    let tag_to_upstreams: FxHashMap<Tag, Arc<[UpstreamProtocol]>> = tag_to_upstreams
        .into_iter()
        .map(|(tag, upstreams)| (tag, Arc::from(upstreams)))
        .collect();
    let fallback_upstreams: Arc<[UpstreamProtocol]> = Arc::from(fallback_upstreams);
    let timeout_duration = if opt.timeout_ms != crate::opt::DEFAULT_UPSTREAM_TIMEOUT_MS {
        Duration::from_millis(opt.timeout_ms as u64)
    } else if let Some(sec) = opt.timeout_sec {
        Duration::from_secs(sec as u64)
    } else {
        DEFAULT_DNS_TIMEOUT
    };

    info!("Active upstream timeout: {:?}", timeout_duration);

    // 2. Global Resources
    let cache = Arc::new(DnsCache::new(
        opt.cache_size,
        opt.cache_stale,
        opt.cache_refresh,
    ));
    if let Some(ref db_path) = opt.cache_db {
        cache.load_from_db(db_path);
    }

    let need_dot = upstreams_need_default_dot(&tag_to_upstreams);
    let need_doh = upstreams_need_default_doh(&tag_to_upstreams);
    #[cfg(feature = "rustls-stack")]
    let need_doh3 = upstreams_need_default_doh3(&tag_to_upstreams);
    let dot_ca_paths = collect_upstream_ca_paths(&tag_to_upstreams, |upstream| match upstream {
        UpstreamProtocol::Dot { tls, .. } => tls.ca_certs.as_ref(),
        _ => None,
    });
    let doh_ca_paths = collect_upstream_ca_paths(&tag_to_upstreams, |upstream| match upstream {
        UpstreamProtocol::Doh { tls, .. } | UpstreamProtocol::DohH3 { tls, .. } => {
            tls.ca_certs.as_ref()
        }
        _ => None,
    });
    #[cfg(feature = "rustls-stack")]
    let doh3_ca_paths = collect_upstream_ca_paths(&tag_to_upstreams, |upstream| match upstream {
        UpstreamProtocol::DohH3 { tls, .. } => tls.ca_certs.as_ref(),
        _ => None,
    });

    let tls_config = if need_dot {
        Some(Arc::new(TlsConfig::new(
            opt.cert_verify,
            opt.ca_certs.as_deref(),
        )))
    } else {
        None
    };
    let mut tls_config_by_ca = FxHashMap::default();
    for ca_path in dot_ca_paths {
        tls_config_by_ca.insert(ca_path.clone(), Arc::new(TlsConfig::new_ca_only(&ca_path)?));
    }

    #[cfg(feature = "rustls-stack")]
    let mut http_client = None;
    #[cfg(feature = "rustls-stack")]
    let mut http3_client = None;
    #[cfg(feature = "rustls-stack")]
    if need_doh {
        let mut http_builder = reqwest::Client::builder()
            .user_agent(&opt.user_agent)
            .timeout(timeout_duration);
        let mut http3_builder = if need_doh3 {
            build_default_http3_client(timeout_duration, &opt.user_agent)?
        } else {
            None
        };

        if opt.cert_verify {
            if let Some(ca_file) = &opt.ca_certs {
                match load_reqwest_ca_certs_lenient(ca_file) {
                    Ok(certs) => {
                        for reqwest_cert in certs {
                            http_builder = http_builder.add_root_certificate(reqwest_cert.clone());
                            if let Some(builder) = http3_builder.take() {
                                http3_builder = Some(builder.add_root_certificate(reqwest_cert));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to load CA certs '{}' for DoH upstreams: {}, falling back to built-in roots",
                            ca_file,
                            e
                        );
                    }
                }
            }
        } else {
            http_builder = http_builder.danger_accept_invalid_certs(true);
            if let Some(builder) = http3_builder.take() {
                http3_builder = Some(builder.danger_accept_invalid_certs(true));
            }
        }

        http_client = Some(Arc::new(http_builder.build()?));
        if let Some(builder) = http3_builder {
            http3_client = Some(Arc::new(builder.build()?));
        }
    }
    #[cfg(feature = "rustls-stack")]
    let mut http_clients_by_ca = FxHashMap::default();
    #[cfg(feature = "rustls-stack")]
    for ca_path in doh_ca_paths {
        http_clients_by_ca.insert(
            ca_path.clone(),
            Arc::new(build_reqwest_client_with_ca(
                &ca_path,
                timeout_duration,
                false,
                &opt.user_agent,
            )?),
        );
    }
    #[cfg(feature = "rustls-stack")]
    let mut http3_clients_by_ca = FxHashMap::default();
    #[cfg(feature = "rustls-stack")]
    for ca_path in doh3_ca_paths {
        http3_clients_by_ca.insert(
            ca_path.clone(),
            Arc::new(build_reqwest_client_with_ca(
                &ca_path,
                timeout_duration,
                true,
                &opt.user_agent,
            )?),
        );
    }

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    let mut http_client = None;
    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    if need_doh {
        let client = crate::http_client::HttpClient::new(
            timeout_duration,
            opt.cert_verify,
            opt.ca_certs.as_deref(),
            opt.user_agent.clone(),
        )?;
        http_client = Some(Arc::new(client));
    }

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    let mut http_clients_by_ca = FxHashMap::default();
    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    for ca_path in doh_ca_paths {
        let client = crate::http_client::HttpClient::new(
            timeout_duration,
            opt.cert_verify,
            Some(&ca_path),
            opt.user_agent.clone(),
        )?;
        http_clients_by_ca.insert(ca_path.clone(), Arc::new(client));
    }



    let shared_state = Arc::new(ServerState {
        opt: opt.clone(),
        default_tag: Tag::from_name(&opt.default_tag)
            .ok_or_else(|| anyhow::anyhow!("Invalid default_tag '{}'", opt.default_tag))?,
        tag_to_upstreams,
        #[cfg(feature = "ipset")]
        tag_to_sets,
        fallback_upstreams,
        cache: cache.clone(),
        tls_config,
        tls_config_by_ca,
        http_client,
        http_clients_by_ca,
        #[cfg(feature = "rustls-stack")]
        http3_client,
        #[cfg(feature = "rustls-stack")]
        http3_clients_by_ca,
        conn_pool: Arc::new(crate::upstream::ConnectionPool::new(
            opt.max_upstream_conns,
            opt.clone(),
        )),
        timeout_duration,
        query_count: std::sync::atomic::AtomicU64::new(0),
        refresh_inflight: std::sync::Mutex::new(rustc_hash::FxHashSet::default()),
        global_query_queue: Arc::new(tokio::sync::Semaphore::new(opt.max_concurrent_queries)),
        client_conn_queue: Arc::new(tokio::sync::Semaphore::new(opt.max_client_connections)),
        background_refresh_queue: Arc::new(tokio::sync::Semaphore::new(
            opt.max_background_refreshes,
        )),
        rtt_tracker: Arc::new(crate::upstream::RttTracker::new()),
    });

    // 3. Spawning Listeners
    let mut uds_listeners: Vec<String> = Vec::new();
    let mut configured_socket_keys = Vec::new();

    let has_tls_specific = !opt.tls_interface.is_empty()
        || !opt.tls_bind_addr.is_empty()
        || opt.tls_bind_interfaces
        || opt.tls_bind_dynamic;
    let tls_interface_list = if has_tls_specific {
        &opt.tls_interface
    } else {
        &opt.interface
    };
    let tls_bind_addr_list = if has_tls_specific {
        &opt.tls_bind_addr
    } else {
        &opt.bind_addr
    };
    let tls_bind_interfaces = if has_tls_specific {
        opt.tls_bind_interfaces
    } else {
        opt.bind_interfaces
    };
    let tls_bind_dynamic = if has_tls_specific {
        opt.tls_bind_dynamic
    } else {
        opt.bind_dynamic
    };

    let tls_no_ipv6_link_local = opt.no_ipv6_link_local || opt.no_tls_ipv6_link_local;

    let all_ifaces = crate::utils::get_all_interfaces();
    let resolve_ip_to_iface = |ip: IpAddr| -> Option<String> {
        all_ifaces
            .iter()
            .find(|(_, iface_ip, _)| *iface_ip == ip)
            .map(|(name, _, _)| name.clone())
    };
    let should_expand = !opt.interface.is_empty() || opt.bind_interfaces || opt.bind_dynamic;
    let tls_should_expand =
        !tls_interface_list.is_empty() || tls_bind_interfaces || tls_bind_dynamic;

    // Loopback auto-inclusion: automatically include "lo" interface if "interface" is set and "lo" is not excluded
    let mut watched_ifaces = opt.interface.clone();
    if !watched_ifaces.is_empty()
        && !watched_ifaces.iter().any(|i| i == "lo")
        && !crate::utils::is_interface_excluded("lo", &opt.except_interface)
    {
        watched_ifaces.push("lo".to_string());
    }
    let mut tls_watched_ifaces = tls_interface_list.clone();
    if !tls_watched_ifaces.is_empty() && !tls_watched_ifaces.iter().any(|i| i == "lo") {
        let tls_except = if opt.tls_except_interface.is_empty() {
            &opt.except_interface
        } else {
            &opt.tls_except_interface
        };
        if !crate::utils::is_interface_excluded("lo", tls_except) {
            tls_watched_ifaces.push("lo".to_string());
        }
    }

    let parse_addr_with_scope =
        |addr_str: &str, default_port: u16| -> Option<(SocketAddr, Option<u32>, Option<String>)> {
            let mut s = addr_str.trim();
            let mut port = default_port;

            if s.starts_with('[') {
                if let Some(close_bracket_idx) = s.find(']') {
                    let ip_part = &s[1..close_bracket_idx];
                    let port_part = &s[close_bracket_idx + 1..];
                    if port_part.starts_with(':')
                        && let Ok(p) = port_part[1..].parse::<u16>()
                    {
                        port = p;
                    }
                    s = ip_part;
                }
            } else if !s.contains(':') {
                // Bare IPv4 address
            } else {
                // Check if it's IPv4:port
                if s.matches(':').count() == 1
                    && let Some((ip, p_str)) = s.split_once(':')
                    && let Ok(p) = p_str.parse::<u16>()
                {
                    port = p;
                    s = ip;
                }
            }

            let (ip_str, scope_str) = if let Some((ip, scope)) = s.split_once('%') {
                (ip, Some(scope))
            } else {
                (s, None)
            };

            let ip: IpAddr = ip_str.parse().ok()?;
            let mut sa = SocketAddr::new(ip, port);

            let mut scope_id = None;
            let mut scope_name = None;

            if let Some(scope) = scope_str {
                if let Ok(num) = scope.parse::<u32>() {
                    scope_id = Some(num);
                } else {
                    scope_name = Some(scope.to_string());
                    scope_id = crate::utils::resolve_scope_id(scope);
                }
            }

            if let Some(sid) = scope_id
                && let SocketAddr::V6(ref mut v6) = sa
            {
                v6.set_scope_id(sid);
            }

            Some((sa, scope_id, scope_name))
        };

    let push_plain = |configured_socket_keys: &mut Vec<crate::listener_manager::SocketKey>,
                      sa: SocketAddr,
                      scope_id: Option<u32>,
                      scope_name: Option<String>,
                      iface: Option<String>| {
        let mut key_udp = crate::listener_manager::SocketKey::new(
            sa,
            crate::listener_manager::ProtocolKind::PlainUdp,
            iface.clone(),
        );
        key_udp.scope_id = scope_id;
        key_udp.scope_name = scope_name.clone();
        configured_socket_keys.push(key_udp);

        let mut key_tcp = crate::listener_manager::SocketKey::new(
            sa,
            crate::listener_manager::ProtocolKind::PlainTcp,
            iface,
        );
        key_tcp.scope_id = scope_id;
        key_tcp.scope_name = scope_name;
        configured_socket_keys.push(key_tcp);
    };

    let push_tls = |configured_socket_keys: &mut Vec<crate::listener_manager::SocketKey>,
                    sa: SocketAddr,
                    scope_id: Option<u32>,
                    scope_name: Option<String>,
                    iface: Option<String>| {
        if opt.enable_dot {
            for &port in &opt.dot_port {
                let mut sa_dot = sa;
                sa_dot.set_port(port);
                if let Some(sid) = scope_id
                    && let SocketAddr::V6(ref mut v6) = sa_dot
                {
                    v6.set_scope_id(sid);
                }
                let mut key = crate::listener_manager::SocketKey::new(
                    sa_dot,
                    crate::listener_manager::ProtocolKind::DoT,
                    iface.clone(),
                );
                key.scope_id = scope_id;
                key.scope_name = scope_name.clone();
                configured_socket_keys.push(key);
            }
        }
        if opt.enable_doh {
            for &port in &opt.doh_port {
                let mut sa_doh = sa;
                sa_doh.set_port(port);
                if let Some(sid) = scope_id
                    && let SocketAddr::V6(ref mut v6) = sa_doh
                {
                    v6.set_scope_id(sid);
                }
                let mut key_doh = crate::listener_manager::SocketKey::new(
                    sa_doh,
                    crate::listener_manager::ProtocolKind::DoH,
                    iface.clone(),
                );
                key_doh.scope_id = scope_id;
                key_doh.scope_name = scope_name.clone();
                configured_socket_keys.push(key_doh);
            }
        }
        if opt.enable_doh3 {
            for &port in &opt.doh3_port {
                let mut sa_h3 = sa;
                sa_h3.set_port(port);
                if let Some(sid) = scope_id
                    && let SocketAddr::V6(ref mut v6) = sa_h3
                {
                    v6.set_scope_id(sid);
                }
                let mut key_h3 = crate::listener_manager::SocketKey::new(
                    sa_h3,
                    crate::listener_manager::ProtocolKind::DoH3,
                    iface.clone(),
                );
                key_h3.scope_id = scope_id;
                key_h3.scope_name = scope_name.clone();
                configured_socket_keys.push(key_h3);
            }
        }
        if opt.enable_doq {
            for &port in &opt.doq_port {
                let mut sa_doq = sa;
                sa_doq.set_port(port);
                if let Some(sid) = scope_id
                    && let SocketAddr::V6(ref mut v6) = sa_doq
                {
                    v6.set_scope_id(sid);
                }
                let mut key = crate::listener_manager::SocketKey::new(
                    sa_doq,
                    crate::listener_manager::ProtocolKind::DoQ,
                    iface.clone(),
                );
                key.scope_id = scope_id;
                key.scope_name = scope_name.clone();
                configured_socket_keys.push(key);
            }
        }
    };

    // 1. Explicit bindings
    for addr in &opt.bind_addr {
        if addr.starts_with("unix:") || addr.starts_with("unixgram:") {
            uds_listeners.push(addr.clone());
            continue;
        }
        for &port in &opt.bind_port {
            if let Some((sa, scope_id, scope_name)) = parse_addr_with_scope(addr, port) {
                let ifname_opt = resolve_ip_to_iface(sa.ip());
                let is_excluded = ifname_opt
                    .as_ref()
                    .map(|ifn| crate::utils::is_interface_excluded(ifn, &opt.except_interface))
                    .unwrap_or(false);
                if is_excluded {
                    continue;
                }

                // For explicit wildcard (0.0.0.0 / ::), dnsmasq style means we push it directly
                // and rely on IP_PKTINFO for interface filtering, rather than expanding.
                if should_expand && !sa.ip().is_unspecified() {
                    if let Some(ifname) = ifname_opt {
                        push_plain(
                            &mut configured_socket_keys,
                            sa,
                            scope_id,
                            Some(ifname.clone()),
                            Some(ifname),
                        );
                    } else {
                        push_plain(
                            &mut configured_socket_keys,
                            sa,
                            scope_id,
                            scope_name.clone(),
                            None,
                        );
                    }
                } else {
                    push_plain(
                        &mut configured_socket_keys,
                        sa,
                        scope_id,
                        scope_name.clone(),
                        None,
                    );
                }
            }
        }
    }
    for addr in tls_bind_addr_list {
        if let Some((sa, scope_id, scope_name)) = parse_addr_with_scope(addr, 0) {
            if let SocketAddr::V6(v6) = sa
                && v6.ip().is_unicast_link_local()
                && tls_no_ipv6_link_local
            {
                continue;
            }
            let ifname_opt = resolve_ip_to_iface(sa.ip());
            let is_excluded = ifname_opt
                .as_ref()
                .map(|ifn| crate::utils::is_interface_excluded(ifn, &opt.tls_except_interface))
                .unwrap_or(false);
            if is_excluded {
                continue;
            }

            if tls_should_expand && !sa.ip().is_unspecified() {
                if let Some(ifname) = ifname_opt {
                    push_tls(
                        &mut configured_socket_keys,
                        sa,
                        scope_id,
                        Some(ifname.clone()),
                        Some(ifname),
                    );
                } else {
                    push_tls(
                        &mut configured_socket_keys,
                        sa,
                        scope_id,
                        scope_name.clone(),
                        None,
                    );
                }
            } else {
                push_tls(
                    &mut configured_socket_keys,
                    sa,
                    scope_id,
                    scope_name.clone(),
                    None,
                );
            }
        }
    }

    // 1.5. Interface dynamic per-IP bindings (if explicit wildcard wasn't used)
    let explicit_wildcard_plain = opt
        .bind_addr
        .iter()
        .filter_map(|a| parse_addr_with_scope(a, 0))
        .any(|(sa, _, _)| sa.ip().is_unspecified());
    if should_expand && !explicit_wildcard_plain {
        for (ifname, iface_ip, iface_scope) in &all_ifaces {
            if crate::utils::is_interface_excluded(ifname, &opt.except_interface) {
                continue;
            }
            if !opt.interface.is_empty()
                && !crate::utils::is_interface_allowed(ifname, &opt.interface)
            {
                continue;
            }
            for &port in &opt.bind_port {
                let mut sa_if = SocketAddr::new(*iface_ip, port);
                if let SocketAddr::V6(ref mut v6) = sa_if {
                    if v6.ip().is_unicast_link_local() && opt.no_ipv6_link_local {
                        continue;
                    }
                    if let Some(sid) = iface_scope {
                        v6.set_scope_id(*sid);
                    }
                }
                push_plain(
                    &mut configured_socket_keys,
                    sa_if,
                    *iface_scope,
                    Some(ifname.clone()),
                    Some(ifname.clone()),
                );
            }
        }
    }

    let explicit_wildcard_tls = opt
        .tls_bind_addr
        .iter()
        .filter_map(|a| parse_addr_with_scope(a, 0))
        .any(|(sa, _, _)| sa.ip().is_unspecified());
    if tls_should_expand && !explicit_wildcard_tls {
        for (ifname, iface_ip, iface_scope) in &all_ifaces {
            if crate::utils::is_interface_excluded(ifname, &opt.tls_except_interface) {
                continue;
            }
            if !tls_interface_list.is_empty()
                && !crate::utils::is_interface_allowed(ifname, tls_interface_list)
            {
                continue;
            }
            let mut sa_if = SocketAddr::new(*iface_ip, 0);
            if let SocketAddr::V6(ref mut v6) = sa_if {
                if v6.ip().is_unicast_link_local() && tls_no_ipv6_link_local {
                    continue;
                }
                if let Some(sid) = iface_scope {
                    v6.set_scope_id(*sid);
                }
            }
            push_tls(
                &mut configured_socket_keys,
                sa_if,
                *iface_scope,
                Some(ifname.clone()),
                Some(ifname.clone()),
            );
        }
    }

    // 2. Listen specs
    for spec in &opt.listen {
        if spec.starts_with("unix:") || spec.starts_with("unixgram:") {
            uds_listeners.push(spec.clone());
            continue;
        }
        if let Some((sa, scope_id, scope_name)) = parse_addr_with_scope(spec, 0) {
            let ifname_opt = resolve_ip_to_iface(sa.ip());
            let is_excluded = ifname_opt
                .as_ref()
                .map(|ifn| crate::utils::is_interface_excluded(ifn, &opt.except_interface))
                .unwrap_or(false);
            if is_excluded {
                continue;
            }

            if should_expand {
                if sa.ip().is_unspecified() {
                    for (ifname, iface_ip, iface_scope) in &all_ifaces {
                        if crate::utils::is_interface_excluded(ifname, &opt.except_interface) {
                            continue;
                        }
                        if !opt.interface.is_empty()
                            && !crate::utils::is_interface_allowed(ifname, &watched_ifaces)
                        {
                            continue;
                        }
                        if iface_ip.is_ipv4() == sa.ip().is_ipv4() {
                            let mut sa_if = sa;
                            sa_if.set_ip(*iface_ip);
                            push_plain(
                                &mut configured_socket_keys,
                                sa_if,
                                scope_id.or(*iface_scope),
                                Some(ifname.clone()),
                                Some(ifname.clone()),
                            );
                        }
                    }
                } else if let Some(ifname) = ifname_opt {
                    push_plain(
                        &mut configured_socket_keys,
                        sa,
                        scope_id,
                        Some(ifname.clone()),
                        Some(ifname),
                    );
                } else {
                    push_plain(
                        &mut configured_socket_keys,
                        sa,
                        scope_id,
                        scope_name.clone(),
                        None,
                    );
                }
            } else {
                push_plain(
                    &mut configured_socket_keys,
                    sa,
                    scope_id,
                    scope_name.clone(),
                    None,
                );
            }
        }
    }

    // 4. Key Deduplication (Interface-bound keys take precedence over static ones)
    let mut deduped_keys: Vec<crate::listener_manager::SocketKey> =
        Vec::with_capacity(configured_socket_keys.len());
    let mut iface_bound_set = FxHashSet::default();

    for key in &configured_socket_keys {
        if key.iface.is_some() && iface_bound_set.insert((key.addr, key.protocol)) {
            deduped_keys.push(key.clone());
        }
    }

    for key in configured_socket_keys {
        if key.iface.is_none() && iface_bound_set.insert((key.addr, key.protocol)) {
            deduped_keys.push(key);
        }
    }
    configured_socket_keys = deduped_keys;

    let has_plain = configured_socket_keys.iter().any(|k| {
        k.protocol == crate::listener_manager::ProtocolKind::PlainUdp
            || k.protocol == crate::listener_manager::ProtocolKind::PlainTcp
    });
    let has_listeners = has_plain
        || !uds_listeners.is_empty()
        || opt.enable_dot
        || opt.enable_doh
        || opt.enable_doq;
    if !has_listeners {
        anyhow::bail!(
            "No listeners configured. You must specify at least one listener: bind-addr, listen, enable-dot, or enable-doh"
        );
    }

    let mut listeners = JoinSet::new();

    let mut watched_ifaces = opt.interface.clone();
    watched_ifaces.extend(opt.tls_interface.clone());
    for addr_str in opt.bind_addr.iter().chain(opt.tls_bind_addr.iter()) {
        if let Some((_, scope)) = addr_str.split_once('%')
            && scope.parse::<u32>().is_err()
        {
            watched_ifaces.push(scope.to_string());
        }
    }
    watched_ifaces.sort();
    watched_ifaces.dedup();

    tracing::info!(
        "Initializing IfaceWatcher with watched_ifaces: {:?}",
        watched_ifaces
    );
    let watcher = crate::iface_watcher::IfaceWatcher::new(watched_ifaces).ok();

    // Spawn UDS listeners
    for addr in &uds_listeners {
        #[cfg(unix)]
        {
            let is_stream = addr.starts_with("unix:");
            let path = if is_stream {
                addr.strip_prefix("unix:").unwrap()
            } else {
                addr.strip_prefix("unixgram:").unwrap()
            };

            let _ = std::fs::remove_file(path);

            if is_stream {
                let std_listener = match std::os::unix::net::UnixListener::bind(path) {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind Unix stream socket {}: {}", path, e);
                        continue;
                    }
                };
                let _ = std_listener.set_nonblocking(true);
                let listener = tokio::net::UnixListener::from_std(std_listener)?;

                let state = shared_state.clone();
                let path_str = path.to_string();
                listeners.spawn(async move {
                    if let Err(e) = handle_unix_listener(listener, state).await {
                        error!("Unix stream listener error on {}: {}", path_str, e);
                    }
                });
                info!("DNS proxy listening on unix:{} (Stream)", path);
            } else {
                let std_sock = match std::os::unix::net::UnixDatagram::bind(path) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to bind Unix datagram socket {}: {}", path, e);
                        continue;
                    }
                };
                let _ = std_sock.set_nonblocking(true);
                let sock = Arc::new(tokio::net::UnixDatagram::from_std(std_sock)?);

                let state = shared_state.clone();
                let mux = Arc::new(
                    crate::upstream::UdpMultiplexer::new(
                        false,
                        opt.socket_buffer_size,
                        opt.out_mark,
                    )
                    .await?,
                );

                let num_workers = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
                    .min(8);
                for worker_id in 0..num_workers {
                    let sock = sock.clone();
                    let state = state.clone();
                    let mux = mux.clone();
                    let path_str = path.to_string();
                    listeners.spawn(async move {
                        if let Err(e) = handle_unixgram_listener(sock, state, mux, worker_id).await
                        {
                            error!(
                                "Unix datagram worker {} error on unixgram:{}: {}",
                                worker_id, path_str, e
                            );
                        }
                    });
                }
                info!("DNS proxy listening on unixgram:{} (Datagram)", path);
            }
        }
        #[cfg(not(unix))]
        {
            error!(
                "Unix Domain Sockets are not supported on this platform: {}",
                addr
            );
        }
    }

    // Plain TCP/UDP listener loops are dynamically managed by ListenerManager below

    // Initialize TLS context for DoT/DoH servers
    #[cfg(all(feature = "rustls-stack", any(feature = "server-dot", feature = "server-doh")))]
    let mut server_tls_config = None;
    #[cfg(all(feature = "boring", not(feature = "rustls-stack"), feature = "server-dot"))]
    let mut server_dot_acceptor = None;
    #[cfg(all(feature = "boring", not(feature = "rustls-stack"), feature = "server-doh"))]
    let mut server_doh_acceptor = None;
    #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
    let mut server_quinn_config = None;
    #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
    let mut server_quinn_doq_config = None;

    if opt.enable_doh3 && !opt.enable_doh {
        anyhow::bail!("--enable-doh3 requires --enable-doh");
    }

    #[cfg(all(
        feature = "rustls-stack",
        any(
            feature = "server-dot",
            feature = "server-doh",
            all(feature = "server-h3", feature = "original-h3-server")
        )
    ))]
    if opt.enable_dot || opt.enable_doh || opt.enable_doq {
        let cert_resolver = build_server_cert_resolver(&opt)?;
        #[cfg(any(feature = "server-dot", feature = "server-doh"))]
        {
            server_tls_config = Some(Arc::new(build_local_tls_config(
                &opt,
                cert_resolver.clone(),
                vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()],
                true,
            )?));
        }

        #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
        if opt.enable_doh3 {
            let quic_crypto =
                build_local_tls_config(&opt, cert_resolver.clone(), vec![b"h3".to_vec()], false)?;
            let mut q_config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(quic_crypto)?,
            ));
            let mut transport = quinn::TransportConfig::default();
            let doh3_stream_limit = opt
                .max_concurrent_queries
                .max(1)
                .min(DOH_MAX_STREAMS_PER_CONN as usize) as u32;
            transport.max_concurrent_bidi_streams(doh3_stream_limit.into());
            transport.max_concurrent_uni_streams(DOH3_MAX_UNI_STREAMS.into());
            let quic_idle_timeout = quinn::IdleTimeout::try_from(Duration::from_millis(
                opt.tcp_idle_timeout_ms as u64,
            ))?;
            transport.max_idle_timeout(Some(quic_idle_timeout));
            q_config.transport_config(Arc::new(transport));
            server_quinn_config = Some(q_config);
        }

        #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
        if opt.enable_doq {
            let quic_crypto =
                build_local_tls_config(&opt, cert_resolver.clone(), vec![b"doq".to_vec()], false)?;
            let mut q_config = quinn::ServerConfig::with_crypto(Arc::new(
                QuicServerConfig::try_from(quic_crypto)?,
            ));
            let mut transport = quinn::TransportConfig::default();
            let doq_stream_limit = opt
                .max_concurrent_queries
                .max(1)
                .min(DOH_MAX_STREAMS_PER_CONN as usize) as u32;
            transport.max_concurrent_bidi_streams(doq_stream_limit.into());
            transport.max_concurrent_uni_streams(DOH3_MAX_UNI_STREAMS.into());
            let quic_idle_timeout = quinn::IdleTimeout::try_from(Duration::from_millis(
                opt.quic_idle_timeout_ms as u64,
            ))?;
            transport.max_idle_timeout(Some(quic_idle_timeout));
            q_config.transport_config(Arc::new(transport));
            server_quinn_doq_config = Some(q_config);
        }
    }

    #[cfg(all(feature = "boring", not(feature = "rustls-stack"), any(feature = "server-dot", feature = "server-doh")))]
    if opt.enable_dot || opt.enable_doh {
        let cert_resolver = build_boring_cert_resolver(&opt)?;
        #[cfg(feature = "tls12")]
        let enable_tls12 = opt.enable_tls12;
        #[cfg(not(feature = "tls12"))]
        let enable_tls12 = false;

        #[cfg(feature = "server-dot")]
        if opt.enable_dot {
            server_dot_acceptor = Some(Arc::new(build_boring_ssl_context(
                cert_resolver.clone(),
                enable_tls12,
                "dot",
            )?));
        }
        #[cfg(feature = "server-doh")]
        if opt.enable_doh {
            server_doh_acceptor = Some(Arc::new(build_boring_ssl_context(
                cert_resolver.clone(),
                enable_tls12,
                "doh",
            )?));
        }
    }

    // Build ServerDependencies and run ListenerManager to handle Dot, Doh, Plain, QUIC listeners
    #[cfg(feature = "server-dot")]
    let dot_acceptor = {
        #[cfg(feature = "rustls-stack")]
        {
            server_tls_config
                .as_ref()
                .map(|cfg| tokio_rustls::TlsAcceptor::from(cfg.clone()))
        }
        #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
        {
            server_dot_acceptor
        }
        #[cfg(not(any(feature = "rustls-stack", feature = "boring")))]
        {
            None
        }
    };

    #[cfg(feature = "server-doh")]
    let doh_acceptor = {
        #[cfg(feature = "rustls-stack")]
        {
            server_tls_config
                .as_ref()
                .map(|cfg| tokio_rustls::TlsAcceptor::from(cfg.clone()))
        }
        #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
        {
            server_doh_acceptor
        }
        #[cfg(not(any(feature = "rustls-stack", feature = "boring")))]
        {
            None
        }
    };

    let deps = crate::listener_manager::ServerDependencies {
        state: Some(shared_state.clone()),
        #[cfg(feature = "server-dot")]
        dot_acceptor,
        #[cfg(feature = "server-doh")]
        doh_acceptor,
        #[cfg(any(feature = "server-doh", feature = "server-h3"))]
        doh_path: Some(Arc::from(opt.doh_path.as_str())),

        #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
        quinn_doh3_config: server_quinn_config,
        #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
        quinn_doq_config: server_quinn_doq_config,
    };

    // Resilient listener manager execution fallback
    let mut watcher = watcher;
    let (tx, rx) = if let Some(w) = watcher.as_mut() {
        (w.tx.clone(), Some(w.rx.take().unwrap()))
    } else {
        tracing::warn!(
            "Interface watcher failed to start or is unavailable. ListenerManager running in static fallback mode."
        );
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        (tx, Some(rx))
    };

    let mut manager =
        crate::listener_manager::ListenerManager::new(configured_socket_keys, tx, deps);
    listeners.spawn(async move {
        let _keep_watcher = watcher;
        if let Some(rx) = rx {
            manager.run(rx).await;
        }
    });

    // 4. Maintenance Task
    let cache_for_maint = cache.clone();
    let opt_for_maint = opt.clone();
    let pool_for_maint = shared_state.conn_pool.clone();
    tokio::spawn(async move {
        // If cleanup interval is 0, we still want to run persistence (if enabled) occasionally.
        // We'll default to a 60s loop in that case.
        let interval_secs = if opt_for_maint.cache_cleanup_interval > 0 {
            opt_for_maint.cache_cleanup_interval as u64
        } else {
            JEMALLOC_PURGE_INTERVAL.as_secs() // Fallback interval if cleanup is disabled
        };

        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await; // Skip first immediate tick

        loop {
            interval.tick().await;

            if opt_for_maint.cache_cleanup_interval > 0 {
                let stats = cache_for_maint.cleanup();
                if stats.total_removed > 0 {
                    debug!(
                        "Background cache cleanup: removed {} expired entries. Active entries remaining: {}. Duration: {}µs.",
                        stats.total_removed, stats.total_active, stats.duration_us
                    );
                }
            }

            pool_for_maint.prune_idle();

            if let Some(ref db_path) = opt_for_maint.cache_db {
                let cache = cache_for_maint.clone();
                let path = db_path.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    cache.save_to_db(&path);
                })
                .await;
            }

            #[cfg(feature = "jemalloc")]
            {
                if let Ok(epoch) = tikv_jemalloc_ctl::epoch::mib() {
                    let _ = epoch.advance();
                }
                unsafe {
                    let _ = tikv_jemalloc_ctl::raw::update(b"arena.4096.purge\0", 0);
                }
            }
        }
    });

    // 5. Active RTT Probing Task (only when multiple upstreams exist in a group)
    let state_for_rtt = shared_state.clone();
    let has_multiple_upstreams = state_for_rtt.tag_to_upstreams.values().any(|ups| ups.len() > 1)
        || state_for_rtt.fallback_upstreams.len() > 1;

    if has_multiple_upstreams {
        tokio::spawn(async move {
            // Collect all unique upstreams
            let mut unique_upstreams = rustc_hash::FxHashSet::default();
            for ups in state_for_rtt.tag_to_upstreams.values() {
                for up in ups.iter() {
                    unique_upstreams.insert(up.clone());
                }
            }
            for up in state_for_rtt.fallback_upstreams.iter() {
                unique_upstreams.insert(up.clone());
            }
            let upstreams: Vec<crate::upstream::UpstreamProtocol> =
                unique_upstreams.into_iter().collect();

            if upstreams.is_empty() {
                return;
            }

            let probe_interval_secs = state_for_rtt.opt.rtt_probe_interval;
            if probe_interval_secs == 0 {
                return;
            }
            let mut interval = tokio::time::interval(Duration::from_secs(probe_interval_secs));

            loop {
                interval.tick().await;

                let mut join_set = JoinSet::new();
                for upstream in &upstreams {
                    let upstream = upstream.clone();
                    let state = state_for_rtt.clone();
                    join_set.spawn(async move {
                        let query = crate::dns::build_probe_query();
                        let start = std::time::Instant::now();

                        let probe_timeout = if state.opt.rtt_probe_timeout_ms > 0 {
                            Duration::from_millis(state.opt.rtt_probe_timeout_ms)
                        } else {
                            DEFAULT_RTT_PROBE_TIMEOUT
                        };

                        let res = crate::upstream::resolve_upstream(
                            &query,
                            &upstream,
                            true, // is_udp: true is default for probing
                            probe_timeout,
                        upstream_clients(&state),
                        &state.fallback_upstreams,
                        state.opt.fallback_dns_all,
                        &state.cache,
                        None, // no global multiplexer for background probes
                        state.conn_pool.clone(),
                        RequestId::zero(), // req_id = RequestId::zero() for probes
                        state.opt.out_mark,
                    )
                    .await;

                    let elapsed = start.elapsed().as_millis() as u32;
                    (upstream, res.is_some(), elapsed)
                });
            }

            while let Some(res) = join_set.join_next().await {
                if let Ok((upstream, success, elapsed)) = res {
                    if success {
                        state_for_rtt.rtt_tracker.record_success(&upstream, elapsed);
                    } else {
                        state_for_rtt.rtt_tracker.record_failure(&upstream);
                    }
                }
            }
        }
    });
    }

    // Spawn background task for SIGHUP log rotation reopen
    #[cfg(unix)]
    {
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut sighup) = signal(SignalKind::hangup()) {
                loop {
                    sighup.recv().await;
                    info!("Received SIGHUP, reopening match log file...");
                    crate::dnl::reopen_match_log();
                    reopen_result_log();
                }
            }
        });
    }

    // Wait for shutdown signal or listener failure
    tokio::select! {
        res = async {
            while let Some(res) = listeners.join_next().await {
                if let Err(e) = res {
                    error!("Listener task panicked: {}", e);
                }
            }
            Ok::<(), anyhow::Error>(())
        } => {
            if let Err(e) = res {
                error!("A listener task failed: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl-C (SIGINT), shutting down gracefully...");
        }
        _ = async {
            #[cfg(unix)]
            {
                let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Failed to register SIGTERM handler: {}", e);
                        std::future::pending().await
                    }
                };
                sigterm.recv().await;
                info!("Received SIGTERM, shutting down gracefully...");
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {}
    }

    // Graceful cleanup and persistence
    if let Some(ref db_path) = opt.cache_db {
        info!("Saving cache database to {}...", db_path);
        cache.save_to_db(db_path);
    }

    info!("polardns shutdown complete.");
    Ok(())
}

pub(crate) struct ServerState {
    pub(crate) opt: Arc<Opt>,
    pub(crate) default_tag: Tag,
    pub(crate) tag_to_upstreams: FxHashMap<Tag, Arc<[UpstreamProtocol]>>,
    #[cfg(feature = "ipset")]
    pub(crate) tag_to_sets: FxHashMap<Tag, Arc<[crate::ipset::SetTarget]>>,
    pub(crate) fallback_upstreams: Arc<[UpstreamProtocol]>,
    pub(crate) cache: Arc<DnsCache>,
    pub(crate) tls_config: Option<Arc<TlsConfig>>,
    pub(crate) tls_config_by_ca: FxHashMap<String, Arc<TlsConfig>>,
    #[cfg(feature = "rustls-stack")]
    pub(crate) http_client: Option<Arc<reqwest::Client>>,
    #[cfg(feature = "rustls-stack")]
    pub(crate) http_clients_by_ca: FxHashMap<String, Arc<reqwest::Client>>,
    #[cfg(feature = "rustls-stack")]
    pub(crate) http3_client: Option<Arc<reqwest::Client>>,
    #[cfg(feature = "rustls-stack")]
    pub(crate) http3_clients_by_ca: FxHashMap<String, Arc<reqwest::Client>>,

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    pub(crate) http_client: Option<Arc<crate::http_client::HttpClient>>,
    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    pub(crate) http_clients_by_ca: FxHashMap<String, Arc<crate::http_client::HttpClient>>,
    pub(crate) conn_pool: Arc<crate::upstream::ConnectionPool>,
    pub(crate) timeout_duration: Duration,
    pub(crate) query_count: std::sync::atomic::AtomicU64,
    pub(crate) refresh_inflight:
        std::sync::Mutex<rustc_hash::FxHashSet<compact_str::CompactString>>,
    pub(crate) global_query_queue: Arc<tokio::sync::Semaphore>,
    pub(crate) client_conn_queue: Arc<tokio::sync::Semaphore>,
    pub(crate) background_refresh_queue: Arc<tokio::sync::Semaphore>,
    pub(crate) rtt_tracker: Arc<crate::upstream::RttTracker>,
}

#[cfg(feature = "server-doh")]
fn doh_stream_limit(state: &ServerState) -> u32 {
    state
        .opt
        .max_concurrent_queries
        .max(1)
        .min(DOH_MAX_STREAMS_PER_CONN as usize) as u32
}

pub(crate) fn try_acquire_client_conn(
    state: &Arc<ServerState>,
    protocol: &str,
    client_addr: SocketAddr,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    match state.client_conn_queue.clone().try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            tracing::warn!(
                "Dropped {} client connection from {} because --max-client-connections={} is exhausted",
                protocol,
                client_addr,
                state.opt.max_client_connections
            );
            None
        }
    }
}

#[cfg(feature = "rustls-stack")]
pub(crate) fn load_certs(
    path: &str,
) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_data = std::fs::read(path)?;
    let mut cursor = std::io::Cursor::new(cert_data);
    let certs = rustls_pemfile::certs(&mut cursor).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

#[cfg(feature = "rustls-stack")]
pub(crate) fn load_keys(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let key_data = std::fs::read(path)?;
    let mut cursor = std::io::Cursor::new(&key_data);
    if let Some(key) = rustls_pemfile::private_key(&mut cursor)? {
        return Ok(key);
    }

    anyhow::bail!("No suitable private key found")
}

#[cfg(feature = "rustls-stack")]
struct LoadedServerCert {
    key: Arc<CertifiedKey>,
    names: Vec<String>,
    source: String,
}

#[cfg(feature = "rustls-stack")]
struct SniCertResolver {
    exact: FxHashMap<String, Arc<CertifiedKey>>,
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
    fallback: Arc<CertifiedKey>,
    strict_sni: bool,
}

#[cfg(feature = "rustls-stack")]
impl fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_names: Vec<&str> = self.exact.keys().map(String::as_str).collect();
        let wildcard_names: Vec<String> = self
            .wildcards
            .iter()
            .map(|(suffix, _)| format!("*{}", suffix))
            .collect();
        f.debug_struct("SniCertResolver")
            .field("exact", &exact_names)
            .field("wildcards", &wildcard_names)
            .field("strict_sni", &self.strict_sni)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "rustls-stack")]
impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        select_sni_match(
            &self.exact,
            &self.wildcards,
            Some(&self.fallback),
            self.strict_sni,
            client_hello.server_name(),
        )
        .cloned()
    }
}

#[cfg(feature = "rustls-stack")]
fn select_sni_match<'a, T>(
    exact: &'a FxHashMap<String, T>,
    wildcards: &'a [(String, T)],
    fallback: Option<&'a T>,
    strict_sni: bool,
    server_name: Option<&str>,
) -> Option<&'a T> {
    let Some(server_name) = server_name.and_then(normalize_sni_name) else {
        return if strict_sni { None } else { fallback };
    };

    if let Some(cert) = exact.get(&server_name) {
        return Some(cert);
    }

    for (suffix, cert) in wildcards {
        if wildcard_matches(suffix, &server_name) {
            return Some(cert);
        }
    }

    if strict_sni { None } else { fallback }
}

fn parse_cert_pair(raw: &str) -> anyhow::Result<(String, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        anyhow::bail!("empty --cert-pair entry");
    }
    if let Some((cert, key)) = raw.split_once(',') {
        let cert = cert.trim();
        let key = key.trim();
        if cert.is_empty() || key.is_empty() {
            anyhow::bail!("invalid --cert-pair '{}': expected cert,key", raw);
        }
        Ok((cert.to_string(), key.to_string()))
    } else {
        Ok((raw.to_string(), raw.to_string()))
    }
}

#[cfg(feature = "rustls-stack")]
fn load_server_cert_pair(cert_path: &str, key_path: &str) -> anyhow::Result<LoadedServerCert> {
    let certs = load_certs(cert_path)?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in '{}'", cert_path);
    }
    let names = extract_cert_names(&certs)?;
    let key = load_keys(key_path)?;
    let provider = rustls::crypto::ring::default_provider();
    let certified_key = CertifiedKey::from_der(certs, key, &provider)?;
    Ok(LoadedServerCert {
        key: Arc::new(certified_key),
        names,
        source: if cert_path == key_path {
            cert_path.to_string()
        } else {
            format!("{},{}", cert_path, key_path)
        },
    })
}

#[cfg(feature = "rustls-stack")]
fn build_server_cert_resolver(opt: &Opt) -> anyhow::Result<Arc<dyn ResolvesServerCert>> {
    let mut loaded = Vec::new();

    match (&opt.cert_file, &opt.key_file) {
        (Some(cert_path), Some(key_path)) => {
            loaded.push(load_server_cert_pair(cert_path, key_path).map_err(|e| {
                anyhow::anyhow!("failed to load --cert-file/--key-file pair: {}", e)
            })?);
        }
        (None, None) => {}
        _ => {
            anyhow::bail!("--cert-file and --key-file must be provided together");
        }
    }

    for raw in &opt.cert_pair {
        for entry in raw
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (cert_path, key_path) = parse_cert_pair(entry)?;
            loaded.push(
                load_server_cert_pair(&cert_path, &key_path).map_err(|e| {
                    anyhow::anyhow!("failed to load --cert-pair '{}': {}", entry, e)
                })?,
            );
        }
    }

    if loaded.is_empty() {
        anyhow::bail!(
            "--cert-file/--key-file or --cert-pair is required when --enable-dot or --enable-doh is set"
        );
    }

    let fallback = loaded[0].key.clone();
    let mut exact = FxHashMap::default();
    let mut wildcards = Vec::new();

    for cert in loaded {
        if cert.names.is_empty() {
            tracing::warn!(
                "TLS certificate '{}' has no DNS SAN or CN names; it can only be used as the fallback certificate",
                cert.source
            );
        }
        for name in cert.names {
            if let Some(suffix) = name.strip_prefix('*') {
                wildcards.push((suffix.to_string(), cert.key.clone()));
            } else {
                exact.insert(name, cert.key.clone());
            }
        }
    }
    wildcards.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));

    Ok(Arc::new(SniCertResolver {
        exact,
        wildcards,
        fallback,
        strict_sni: opt.strict_sni,
    }))
}

#[cfg(feature = "rustls-stack")]
pub(crate) fn extract_cert_names(
    certs: &[rustls::pki_types::CertificateDer<'static>],
) -> anyhow::Result<Vec<String>> {
    use anyhow::Context;

    let Some(cert_der) = certs.first() else {
        return Ok(Vec::new());
    };

    let cert = webpki::EndEntityCert::try_from(cert_der).context("failed to parse certificate")?;
    let mut seen = FxHashSet::default();
    let mut names = Vec::with_capacity(4);

    // Extract DNS names from the SAN extension via webpki.
    // CN fallback is intentionally omitted — all modern CAs include SANs.
    for dns_name in cert.valid_dns_names() {
        if let Some(name) = normalize_cert_name(dns_name)
            && seen.insert(name.clone())
        {
            names.push(name);
        }
    }

    // Extract IP address SANs for parity with the boring stack.
    // webpki does not expose valid_ip_names(), so we parse them from raw DER.
    // NOTE: Standard TLS clients connecting via IP omit the SNI extension entirely.
    // Therefore, while these IP SANs are registered in exact matches, they are rarely reachable.
    for ip in extract_ip_sans(cert_der.as_ref()) {
        let ip_str = ip.to_string();
        if seen.insert(ip_str.clone()) {
            names.push(ip_str);
        }
    }

    Ok(names)
}

/// Extract IP address SANs from raw DER certificate bytes.
///
/// Iterates all occurrences of the SubjectAltName extension OID (2.5.29.17),
/// then parses the GeneralName entries looking for iPAddress [7] entries (4 bytes for IPv4,
/// 16 bytes for IPv6).
#[cfg(feature = "rustls-stack")]
#[must_use]
fn extract_ip_sans(der: &[u8]) -> Vec<std::net::IpAddr> {
    // OID 2.5.29.17 (id-ce-subjectAltName) encoded as: 06 03 55 1D 11
    let san_oid = [0x06, 0x03, 0x55, 0x1D, 0x11];
    let mut ips = Vec::with_capacity(2);
    let mut search_pos = 0;

    while let Some(relative_pos) = der[search_pos..].windows(5).position(|w| w == san_oid) {
        let oid_pos = search_pos + relative_pos;
        search_pos = oid_pos + 5; // advance search position for next candidate

        let mut pos = oid_pos + 5;

        // Skip optional critical BOOLEAN: tag=0x01, len=0x01, value
        if pos + 3 <= der.len() && der[pos] == 0x01 && der[pos + 1] == 0x01 {
            pos += 3; // skip tag + length + value
        }

        // Expect OCTET STRING wrapper (tag=0x04)
        if pos >= der.len() || der[pos] != 0x04 {
            continue;
        }
        pos += 1;
        let Some((octet_len, octet_hdr)) = read_der_length(&der[pos..]) else {
            continue;
        };
        pos += octet_hdr;

        let octet_end = pos.saturating_add(octet_len).min(der.len());

        // Inside the OCTET STRING: expect SEQUENCE (tag=0x30)
        if pos >= octet_end || der[pos] != 0x30 {
            continue;
        }
        pos += 1;
        let Some((seq_len, seq_hdr)) = read_der_length(&der[pos..octet_end]) else {
            continue;
        };
        pos += seq_hdr;

        let seq_end = pos.saturating_add(seq_len).min(octet_end);

        // Iterate GeneralName entries inside the SEQUENCE
        while pos + 2 <= seq_end {
            let tag = der[pos];
            pos += 1;
            let Some((entry_len, entry_hdr)) = read_der_length(&der[pos..seq_end]) else {
                break;
            };
            pos += entry_hdr;

            let entry_end = pos.saturating_add(entry_len).min(seq_end);

            // iPAddress is context-specific tag [7] = 0x87
            if tag == 0x87 {
                if entry_len == 4
                    && pos + 4 <= seq_end
                    && let Some(bytes) = der.get(pos..pos + 4)
                {
                    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ));
                    ips.push(ip);
                } else if entry_len == 16
                    && pos + 16 <= seq_end
                    && let Some(bytes) = der.get(pos..pos + 16)
                {
                    let mut array = [0u8; 16];
                    array.copy_from_slice(bytes);
                    let ip = std::net::IpAddr::V6(std::net::Ipv6Addr::from(array));
                    ips.push(ip);
                }
            }

            pos = entry_end;
        }

        if !ips.is_empty() {
            break; // Successfully parsed the SAN extension, stop candidate search
        }
    }
    ips
}

/// Read a DER length field. Returns (length_value, header_bytes_consumed).
#[cfg(feature = "rustls-stack")]
#[inline]
#[must_use]
fn read_der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first < 0x80 {
        // Short form: length is the byte itself
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite form — not valid in DER
        None
    } else {
        // Long form: lower 7 bits = number of subsequent length bytes
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || num_bytes + 1 > data.len() {
            return None; // unreasonably large or truncated
        }
        let mut len: usize = 0;
        for &b in &data[1..1 + num_bytes] {
            len = len.checked_mul(256)?.checked_add(b as usize)?;
        }
        Some((len, 1 + num_bytes))
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
struct LoadedServerCertBoring {
    cert_key: Arc<crate::quiche_server::BoringCertKey>,
    names: rustc_hash::FxHashSet<String>,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
fn load_server_cert_pair_boring(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<LoadedServerCertBoring> {
    let cert_key = Arc::new(crate::quiche_server::BoringCertKey::load(
        cert_path, key_path,
    )?);
    let names = extract_cert_names_boring(cert_path)?;
    Ok(LoadedServerCertBoring { cert_key, names })
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub struct BoringCertResolverInner {
    exact: std::collections::HashMap<String, Arc<crate::quiche_server::BoringCertKey>>,
    wildcards: Vec<(String, Arc<crate::quiche_server::BoringCertKey>)>,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
#[derive(Clone)]
pub struct BoringCertResolver {
    inner: Arc<arc_swap::ArcSwap<BoringCertResolverInner>>,
    fallback: Arc<crate::quiche_server::BoringCertKey>,
    strict_sni: bool,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl BoringCertResolver {
    pub fn new(
        exact: std::collections::HashMap<String, Arc<crate::quiche_server::BoringCertKey>>,
        mut wildcards: Vec<(String, Arc<crate::quiche_server::BoringCertKey>)>,
        fallback: Arc<crate::quiche_server::BoringCertKey>,
        strict_sni: bool,
    ) -> Self {
        wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        Self {
            inner: Arc::new(arc_swap::ArcSwap::new(Arc::new(BoringCertResolverInner {
                exact,
                wildcards,
            }))),
            fallback,
            strict_sni,
        }
    }

    pub fn reload(
        &self,
        exact: std::collections::HashMap<String, Arc<crate::quiche_server::BoringCertKey>>,
        mut wildcards: Vec<(String, Arc<crate::quiche_server::BoringCertKey>)>,
    ) {
        wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        self.inner
            .store(Arc::new(BoringCertResolverInner { exact, wildcards }));
    }

    pub fn resolve(
        &self,
        server_name: Option<&str>,
    ) -> Result<Arc<crate::quiche_server::BoringCertKey>, boring::ssl::SniError> {
        let name = match server_name {
            Some(n) => n.to_ascii_lowercase(),
            None => {
                if self.strict_sni {
                    return Err(boring::ssl::SniError::ALERT_FATAL);
                } else {
                    return Ok(self.fallback.clone());
                }
            }
        };

        let inner = self.inner.load();
        if let Some(ctx) = inner.exact.get(&name) {
            return Ok(ctx.clone());
        }

        for (suffix, ctx) in &inner.wildcards {
            if name.ends_with(suffix) {
                let prefix = &name[..name.len() - suffix.len()];
                if !prefix.is_empty() && !prefix.contains('.') {
                    return Ok(ctx.clone());
                }
            }
        }

        if self.strict_sni {
            Err(boring::ssl::SniError::ALERT_FATAL)
        } else {
            Ok(self.fallback.clone())
        }
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub fn build_boring_cert_resolver(opt: &Opt) -> anyhow::Result<Arc<BoringCertResolver>> {
    let mut loaded = Vec::new();
    if let (Some(cert_path), Some(key_path)) = (&opt.cert_file, &opt.key_file) {
        loaded.push(load_server_cert_pair_boring(cert_path, key_path)?);
    }
    for raw in &opt.cert_pair {
        for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
            let (cert_path, key_path) = parse_cert_pair(entry)?;
            loaded.push(load_server_cert_pair_boring(&cert_path, &key_path)?);
        }
    }
    if loaded.is_empty() {
        anyhow::bail!("--cert-file/--key-file or --cert-pair is required");
    }

    let fallback = loaded[0].cert_key.clone();
    let mut exact = std::collections::HashMap::new();
    let mut wildcards = Vec::new();

    for cert in loaded {
        for name in cert.names {
            if let Some(suffix) = name.strip_prefix('*') {
                wildcards.push((suffix.to_string(), cert.cert_key.clone()));
            } else {
                exact.insert(name, cert.cert_key.clone());
            }
        }
    }

    Ok(Arc::new(BoringCertResolver::new(
        exact,
        wildcards,
        fallback,
        opt.strict_sni,
    )))
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub fn build_boring_ssl_context(
    cert_resolver: Arc<BoringCertResolver>,
    enable_tls12: bool,
    alpn_mode: &str,
) -> anyhow::Result<boring::ssl::SslAcceptor> {
    use foreign_types::ForeignTypeRef;

    let mut builder = if enable_tls12 {
        boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls_server())?
    } else {
        boring::ssl::SslAcceptor::mozilla_modern(boring::ssl::SslMethod::tls_server())?
    };

    builder.clear_options(boring::ssl::SslOptions::NO_TLSV1_3);
    if !enable_tls12 {
        builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    }

    if alpn_mode == "doh" {
        builder.set_alpn_select_callback(|_ssl, client_protocols| {
            static SERVER_PROTOS: &[u8] = b"\x02h2\x08http/1.1";
            match boring::ssl::select_next_proto(SERVER_PROTOS, client_protocols) {
                Some(proto) => Ok(proto),
                None => Err(boring::ssl::AlpnError::NOACK),
            }
        });
    } else if alpn_mode == "dot" {
        builder.set_alpn_select_callback(|_ssl, client_protocols| {
            static SERVER_PROTOS: &[u8] = b"\x03dot";
            match boring::ssl::select_next_proto(SERVER_PROTOS, client_protocols) {
                Some(proto) => Ok(proto),
                None => Err(boring::ssl::AlpnError::NOACK),
            }
        });
    }

    let resolver = cert_resolver.clone();
    builder.set_servername_callback(move |ssl, _alert| {
        let name = ssl.servername(boring::ssl::NameType::HOST_NAME);
        match resolver.resolve(name) {
            Ok(cert_key) => {
                if ssl.set_certificate(&cert_key.leaf).is_err()
                    || ssl.set_private_key(&cert_key.key).is_err()
                {
                    return Err(boring::ssl::SniError::ALERT_FATAL);
                }
                unsafe {
                    boring_sys::SSL_clear_chain_certs(ssl.as_ptr());
                }
                for cert in &cert_key.chain {
                    let _ = ssl.add_chain_cert(cert);
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    });

    Ok(builder.build())
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub fn extract_cert_names_boring(cert_path: &str) -> anyhow::Result<rustc_hash::FxHashSet<String>> {
    let cert_pem = std::fs::read(cert_path)?;
    let certs = boring::x509::X509::stack_from_pem(&cert_pem)?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("No certificates found"))?;

    let mut names = rustc_hash::FxHashSet::default();

    if let Some(subject) = leaf
        .subject_name()
        .entries_by_nid(boring::nid::Nid::COMMONNAME)
        .next()
    {
        if let Ok(cn) = subject.data().as_utf8() {
            if let Some(name) = normalize_cert_name(&cn.to_string()) {
                names.insert(name);
            }
        }
    }

    if let Some(sans) = leaf.subject_alt_names() {
        names.reserve(sans.len());
        for san in sans {
            if let Some(dns) = san.dnsname() {
                if let Some(name) = normalize_cert_name(dns) {
                    names.insert(name);
                }
            } else if let Some(ip) = san.ipaddress() {
                if ip.len() == 4 {
                    let ip_str =
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))
                            .to_string();
                    names.insert(ip_str);
                } else if ip.len() == 16 {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(ip);
                    let ip_str = std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)).to_string();
                    names.insert(ip_str);
                }
            }
        }
    }
    Ok(names)
}

pub(crate) fn normalize_cert_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_prefix("*.") {
        if is_valid_dns_name(rest) {
            return Some(format!("*.{}", rest));
        }
        return None;
    }
    if name.contains('*') || !is_valid_dns_name(&name) {
        return None;
    }
    Some(name)
}

#[cfg(feature = "rustls-stack")]
fn normalize_sni_name(name: &str) -> Option<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.contains('*') || !is_valid_dns_name(&name) {
        return None;
    }
    Some(name)
}

fn is_valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(feature = "rustls-stack")]
fn wildcard_matches(suffix: &str, name: &str) -> bool {
    if !name.ends_with(suffix) {
        return false;
    }
    let prefix = &name[..name.len() - suffix.len()];
    !prefix.is_empty() && !prefix.contains('.')
}

#[cfg(feature = "server-dot")]
pub(crate) async fn handle_dot_listener(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    state: Arc<crate::server::ServerState>,
) -> anyhow::Result<()> {
    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("DoT TCP accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let state = state.clone();
        let Some(conn_permit) = try_acquire_client_conn(&state, "DoT", client_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            let sock_ref = socket2::SockRef::from(&stream);
            let ka = socket2::TcpKeepalive::new()
                .with_time(SERVER_TCP_KEEPALIVE_TIME)
                .with_interval(SERVER_TCP_KEEPALIVE_INTERVAL);
            let _ = sock_ref.set_tcp_keepalive(&ka);
            let _ = sock_ref.set_nodelay(true);
            let _ = sock_ref.set_nodelay(true);

            let idle_timeout = Duration::from_millis(state.opt.tcp_idle_timeout_ms as u64);
            #[cfg(feature = "rustls-stack")]
            let accept_fut = tls_acceptor.accept(stream);
            #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
            let accept_fut = tokio_boring::accept(&tls_acceptor, stream);

            let mut tls_stream = match tokio::time::timeout(idle_timeout, accept_fut).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!("DoT TLS handshake failed with {}: {}", client_addr, e);
                    return;
                }
                Err(_) => {
                    debug!("DoT TLS handshake timed out with {}", client_addr);
                    return;
                }
            };

            let mut len_buf = [0u8; 2];
            let mut query_data = Vec::with_capacity(DNS_BUF_SIZE);
            loop {
                match tokio::time::timeout(idle_timeout, tls_stream.read_exact(&mut len_buf)).await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => break, // EOF or timeout
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                if !(12..=DNS_BUF_SIZE).contains(&len) {
                    break;
                }
                query_data.resize(len, 0);
                match tokio::time::timeout(idle_timeout, tls_stream.read_exact(&mut query_data))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => break,
                }

                state
                    .query_count
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let req_id = RequestId::new();

                let queue_timeout = if state.opt.queue_timeout_ms > 0 {
                    Duration::from_millis(state.opt.queue_timeout_ms as u64)
                } else {
                    DEFAULT_QUEUE_TIMEOUT
                };
                let permit_res = tokio::time::timeout(
                    queue_timeout,
                    state.global_query_queue.acquire(),
                )
                .await;

                if let Ok(Ok(_permit)) = permit_res {
                    if let Some(resp) =
                        process_query(&query_data, &state, client_addr, false, None, req_id).await
                    {
                        let mut out = Vec::with_capacity(2 + resp.len());
                        out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                        out.extend_from_slice(&resp);
                        let write_fut = async {
                            tls_stream.write_all(&out).await.map_err(|_| ())
                        };

                        if tokio::time::timeout(idle_timeout, write_fut)
                            .await
                            .unwrap_or(Err(()))
                            .is_err()
                        {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    tracing::warn!(
                        "[REQ #{}] Dropped DoT query from {} due to global queue timeout",
                        req_id,
                        client_addr
                    );
                    break;
                }
            }
        });
    }
}

#[cfg(feature = "server-doh")]
pub(crate) async fn handle_doh_listener(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    state: Arc<crate::server::ServerState>,
    doh_path: Arc<str>,
) -> anyhow::Result<()> {
    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("DoH TCP accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        let tls_acceptor = tls_acceptor.clone();
        let state = state.clone();
        let doh_path = doh_path.clone();
        let Some(conn_permit) = try_acquire_client_conn(&state, "DoH", client_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            let sock_ref = socket2::SockRef::from(&stream);
            let ka = socket2::TcpKeepalive::new()
                .with_time(SERVER_TCP_KEEPALIVE_TIME)
                .with_interval(SERVER_TCP_KEEPALIVE_INTERVAL);
            let _ = sock_ref.set_tcp_keepalive(&ka);
            let _ = sock_ref.set_nodelay(true);

            let handshake_timeout = Duration::from_millis(state.opt.tcp_idle_timeout_ms as u64);
            #[cfg(feature = "rustls-stack")]
            let accept_fut = tls_acceptor.accept(stream);
            #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
            let accept_fut = tokio_boring::accept(&tls_acceptor, stream);

            let tls_stream = match tokio::time::timeout(handshake_timeout, accept_fut).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    debug!("DoH TLS handshake failed with {}: {}", client_addr, e);
                    return;
                }
                Err(_) => {
                    debug!("DoH TLS handshake timed out with {}", client_addr);
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);

            let idle_timeout = Duration::from_millis(state.opt.tcp_idle_timeout_ms as u64);
            let max_concurrent_streams = doh_stream_limit(&state);
            let service_state = state.clone();
            let service = service_fn(move |req| {
                let state = service_state.clone();
                let doh_path = doh_path.clone();
                async move { handle_doh_request(req, state, client_addr, doh_path).await }
            });

            let mut builder = auto::Builder::new(TokioExecutor::new());
            builder
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Some(idle_timeout))
                .max_buf_size(DOH_HTTP1_MAX_BUF_SIZE)
                .max_headers(32)
                .keep_alive(true);
            builder
                .http2()
                .timer(hyper_util::rt::TokioTimer::new())
                .max_concurrent_streams(Some(max_concurrent_streams))
                .max_pending_accept_reset_streams(Some(32))
                .max_header_list_size(DOH_HTTP2_MAX_HEADER_LIST_SIZE)
                .max_send_buf_size(DOH_HTTP2_MAX_SEND_BUF_SIZE)
                .keep_alive_interval(Some(H2_KEEPALIVE_INTERVAL))
                .keep_alive_timeout(H2_KEEPALIVE_TIMEOUT);

            if let Err(err) = builder.serve_connection(io, service).await {
                debug!("Error serving DoH HTTP connection: {:?}", err);
            }
        });
    }
}

#[cfg(feature = "server-doh")]
async fn handle_doh_request(
    req: Request<Incoming>,
    state: Arc<crate::server::ServerState>,
    client_addr: SocketAddr,
    doh_path: Arc<str>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let not_found = || {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Not Found")));
        *res.status_mut() = hyper::StatusCode::NOT_FOUND;
        res
    };
    let bad_request = || {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Bad Request")));
        *res.status_mut() = hyper::StatusCode::BAD_REQUEST;
        res
    };
    let unsupported_media_type = || {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Unsupported Media Type")));
        *res.status_mut() = hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE;
        res
    };
    let request_timeout = || {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Request Timeout")));
        *res.status_mut() = hyper::StatusCode::REQUEST_TIMEOUT;
        res
    };
    let unavailable = || {
        let mut res = Response::new(Full::new(Bytes::from_static(b"Service Unavailable")));
        *res.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
        res
    };

    if req.uri().path() != doh_path.as_ref() {
        return Ok(not_found());
    }

    if req.method() != hyper::Method::GET && req.method() != hyper::Method::POST {
        return Ok(bad_request());
    }

    let query_data = if req.method() == hyper::Method::GET {
        let mut query_data = Vec::new();
        if let Some(query) = req.uri().query() {
            for param in query.split('&') {
                if let Some(dns_val) = param.strip_prefix("dns=") {
                    if dns_val.len() > DOH_GET_DNS_PARAM_MAX {
                        return Ok(bad_request());
                    }
                    use base64::Engine;
                    if let Ok(decoded) =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_val)
                    {
                        query_data = decoded;
                    } else if let Ok(decoded) =
                        base64::engine::general_purpose::URL_SAFE.decode(dns_val)
                    {
                        query_data = decoded;
                    }
                    break;
                }
            }
        }
        query_data
    } else {
        if !has_dns_message_content_type(req.headers()) {
            return Ok(unsupported_media_type());
        }
        let initial_capacity = match content_length(req.headers()) {
            Some(len) if len > DNS_BUF_SIZE => return Ok(bad_request()),
            Some(len) => len,
            None => 0,
        };
        match tokio::time::timeout(
            DOH_BODY_READ_TIMEOUT,
            collect_limited_body(req.into_body(), DNS_BUF_SIZE, initial_capacity),
        )
        .await
        {
            Ok(Some(body)) => body,
            Ok(None) => return Ok(bad_request()),
            Err(_) => return Ok(request_timeout()),
        }
    };

    if query_data.is_empty() || query_data.len() > DNS_BUF_SIZE {
        return Ok(bad_request());
    }

    state
        .query_count
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let req_id = RequestId::new();
    let queue_timeout = if state.opt.queue_timeout_ms > 0 {
        Duration::from_millis(state.opt.queue_timeout_ms as u64)
    } else {
        DEFAULT_QUEUE_TIMEOUT
    };
    let _permit = match tokio::time::timeout(
        queue_timeout,
        state.global_query_queue.acquire(),
    )
    .await
    {
        Ok(Ok(permit)) => permit,
        _ => {
            tracing::warn!(
                "[REQ #{}] Dropped DoH query from {} due to global queue timeout",
                req_id,
                client_addr
            );
            return Ok(unavailable());
        }
    };

    if let Some(resp) = process_query(&query_data, &state, client_addr, false, None, req_id).await {
        let res = Response::builder()
            .status(hyper::StatusCode::OK)
            .header("Content-Type", "application/dns-message")
            .body(Full::new(Bytes::from(resp)))
            .unwrap();
        return Ok(res);
    }

    let mut res = Response::new(Full::new(Bytes::from_static(b"Server Error")));
    *res.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
    Ok(res)
}

#[cfg(any(feature = "server-doh", all(feature = "server-h3", feature = "original-h3-server")))]
fn has_dns_message_content_type(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|mime| mime.trim().eq_ignore_ascii_case("application/dns-message"))
        .unwrap_or(false)
}

#[cfg(any(feature = "server-doh", all(feature = "server-h3", feature = "original-h3-server")))]
fn content_length(headers: &http::HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

#[cfg(feature = "server-doh")]
async fn collect_limited_body(
    mut body: Incoming,
    max_len: usize,
    initial_capacity: usize,
) -> Option<Vec<u8>> {
    let mut query_data = Vec::with_capacity(initial_capacity.min(max_len));
    while let Some(frame) = body.frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            if query_data.len().saturating_add(data.len()) > max_len {
                return None;
            }
            query_data.extend_from_slice(&data);
        }
    }
    Some(query_data)
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
fn doh3_bad_request_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::BAD_REQUEST)
        .body(())
        .unwrap()
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
fn doh3_unsupported_media_type_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE)
        .body(())
        .unwrap()
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
fn doh3_unavailable_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::SERVICE_UNAVAILABLE)
        .body(())
        .unwrap()
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
fn doh3_request_timeout_response() -> http::Response<()> {
    http::Response::builder()
        .status(http::StatusCode::REQUEST_TIMEOUT)
        .body(())
        .unwrap()
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
async fn recv_h3_body_limited(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<bytes::Bytes>, bytes::Bytes>,
    max_len: usize,
    initial_capacity: usize,
) -> Option<Vec<u8>> {
    let mut query_data = Vec::with_capacity(initial_capacity.min(max_len));
    loop {
        match stream.recv_data().await {
            Ok(Some(mut bytes)) => {
                use bytes::Buf;
                let len = bytes.remaining();
                if query_data.len().saturating_add(len) > max_len {
                    return None;
                }
                let start = query_data.len();
                query_data.resize(start + len, 0);
                bytes.copy_to_slice(&mut query_data[start..]);
            }
            Ok(None) => return Some(query_data),
            Err(_) => return None,
        }
    }
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
pub(crate) async fn handle_doh3_listener(
    endpoint: quinn::Endpoint,
    state: Arc<crate::server::ServerState>,
    doh_path: Arc<str>,
) -> anyhow::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let client_addr = incoming.remote_address();
        let state = state.clone();
        let doh_path = doh_path.clone();
        let Some(conn_permit) = try_acquire_client_conn(&state, "DoH3", client_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            match incoming.await {
                Ok(connection) => {
                    let h3_conn = h3_quinn::Connection::new(connection);
                    if let Ok(mut server) = h3::server::Connection::new(h3_conn).await {
                        while let Ok(Some(req_resolver)) = server.accept().await {
                            let state = state.clone();
                            let doh_path = doh_path.clone();
                            tokio::spawn(async move {
                                let (req, mut stream) = match req_resolver.resolve_request().await {
                                    Ok(r) => r,
                                    Err(_) => return,
                                };

                                if req.uri().path() != doh_path.as_ref() {
                                    let res = http::Response::builder()
                                        .status(http::StatusCode::NOT_FOUND)
                                        .body(())
                                        .unwrap();
                                    let _ = stream.send_response(res).await;
                                    let _ = stream.finish().await;
                                    return;
                                }

                                if req.method() != http::Method::GET
                                    && req.method() != http::Method::POST
                                {
                                    let _ = stream.send_response(doh3_bad_request_response()).await;
                                    let _ = stream.finish().await;
                                    return;
                                }

                                let query_data = if req.method() == http::Method::GET {
                                    let mut query_data = Vec::new();
                                    if let Some(query) = req.uri().query() {
                                        for param in query.split('&') {
                                            if let Some(dns_val) = param.strip_prefix("dns=") {
                                                if dns_val.len() > DOH_GET_DNS_PARAM_MAX {
                                                    let _ = stream
                                                        .send_response(doh3_bad_request_response())
                                                        .await;
                                                    let _ = stream.finish().await;
                                                    return;
                                                }
                                                use base64::Engine;
                                                if let Ok(decoded) =
                                                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                                                        .decode(dns_val)
                                                {
                                                    query_data = decoded;
                                                } else if let Ok(decoded) =
                                                    base64::engine::general_purpose::URL_SAFE
                                                        .decode(dns_val)
                                                {
                                                    query_data = decoded;
                                                }
                                                break;
                                            }
                                        }
                                    }
                                    query_data
                                } else {
                                    if !has_dns_message_content_type(req.headers()) {
                                        let _ = stream
                                            .send_response(doh3_unsupported_media_type_response())
                                            .await;
                                        let _ = stream.finish().await;
                                        return;
                                    }
                                    let initial_capacity = match content_length(req.headers()) {
                                        Some(len) if len > DNS_BUF_SIZE => {
                                            let _ = stream
                                                .send_response(doh3_bad_request_response())
                                                .await;
                                            let _ = stream.finish().await;
                                            return;
                                        }
                                        Some(len) => len,
                                        None => 0,
                                    };
                                    match tokio::time::timeout(
                                        DOH_BODY_READ_TIMEOUT,
                                        recv_h3_body_limited(
                                            &mut stream,
                                            DNS_BUF_SIZE,
                                            initial_capacity,
                                        ),
                                    )
                                    .await
                                    {
                                        Ok(Some(body)) => body,
                                        Ok(None) => {
                                            let _ = stream
                                                .send_response(doh3_bad_request_response())
                                                .await;
                                            let _ = stream.finish().await;
                                            return;
                                        }
                                        Err(_) => {
                                            let _ = stream
                                                .send_response(doh3_request_timeout_response())
                                                .await;
                                            let _ = stream.finish().await;
                                            return;
                                        }
                                    }
                                };

                                if query_data.is_empty() || query_data.len() > DNS_BUF_SIZE {
                                    let _ = stream.send_response(doh3_bad_request_response()).await;
                                    let _ = stream.finish().await;
                                    return;
                                }

                                state
                                    .query_count
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let req_id = RequestId::new();
                                let queue_timeout = if state.opt.queue_timeout_ms > 0 {
                                    Duration::from_millis(state.opt.queue_timeout_ms as u64)
                                } else {
                                    DEFAULT_QUEUE_TIMEOUT
                                };
                                let _permit = match tokio::time::timeout(
                                    queue_timeout,
                                    state.global_query_queue.clone().acquire_owned(),
                                )
                                .await
                                {
                                    Ok(Ok(permit)) => permit,
                                    _ => {
                                        tracing::warn!(
                                            "[REQ #{}] Dropped DoH3 query from {} due to global queue timeout",
                                            req_id,
                                            client_addr
                                        );
                                        let _ =
                                            stream.send_response(doh3_unavailable_response()).await;
                                        let _ = stream.finish().await;
                                        return;
                                    }
                                };

                                if let Some(resp) = process_query(
                                    &query_data,
                                    &state,
                                    client_addr,
                                    false,
                                    None,
                                    req_id,
                                )
                                .await
                                {
                                    let res = http::Response::builder()
                                        .status(http::StatusCode::OK)
                                        .header("content-type", "application/dns-message")
                                        .body(())
                                        .unwrap();
                                    if stream.send_response(res).await.is_ok() {
                                        let _ = stream.send_data(bytes::Bytes::from(resp)).await;
                                    }
                                    let _ = stream.finish().await;
                                    return;
                                }

                                let res = http::Response::builder()
                                    .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(())
                                    .unwrap();
                                let _ = stream.send_response(res).await;
                                let _ = stream.finish().await;
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("DoH3 QUIC connection failed: {}", e);
                }
            }
        });
    }
    Ok(())
}

pub(crate) async fn handle_udp_listener(
    socket: Arc<UdpSocket>,
    state: Arc<ServerState>,
    mux: Arc<crate::upstream::UdpMultiplexer>,
    _worker_id: usize,
) -> anyhow::Result<()> {
    let mut buf = [0u8; DNS_BUF_SIZE];
    loop {
        let (len, client_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                error!("UDP recv_from error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let state = state.clone();
        let socket = socket.clone();
        let mux = mux.clone();
        state
            .query_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req_id = RequestId::new();
        if len < 12 {
            continue;
        }
        let permit = match state.global_query_queue.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    "[REQ #{}] Dropped UDP query from {} due to global queue saturation",
                    req_id,
                    client_addr
                );
                continue;
            }
        };
        let query_data = buf[..len].to_vec();

        tokio::spawn(async move {
            let _permit = permit;
            if let Some(resp) =
                process_query(&query_data, &state, client_addr, true, Some(mux), req_id).await
                && socket.send_to(&resp, client_addr).await.is_ok()
            {
                debug!("[REQ #{}] Sent response to {}", req_id, client_addr);
            }
        });
    }
}

pub(crate) async fn handle_tcp_listener(
    listener: TcpListener,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    loop {
        let (mut stream, client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("TCP accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let state = state.clone();
        let Some(conn_permit) = try_acquire_client_conn(&state, "TCP", client_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            let sock_ref = socket2::SockRef::from(&stream);
            let ka = socket2::TcpKeepalive::new()
                .with_time(SERVER_TCP_KEEPALIVE_TIME)
                .with_interval(SERVER_TCP_KEEPALIVE_INTERVAL);
            let _ = sock_ref.set_tcp_keepalive(&ka);
            let _ = sock_ref.set_nodelay(true);
            if let Err(e) = handle_tcp_client(&mut stream, state, client_addr).await {
                debug!("TCP client {} error: {}", client_addr, e);
            }
        });
    }
}

async fn handle_tcp_client(
    stream: &mut TcpStream,
    state: Arc<ServerState>,
    client_addr: SocketAddr,
) -> anyhow::Result<()> {
    let idle_timeout = Duration::from_millis(state.opt.tcp_idle_timeout_ms as u64);

    let mut len_buf = [0u8; 2];
    let mut query_data = Vec::with_capacity(DNS_BUF_SIZE);
    loop {
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if !(12..=DNS_BUF_SIZE).contains(&len) {
            break;
        }

        query_data.resize(len, 0);
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut query_data)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        state
            .query_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req_id = RequestId::new();
        let queue_timeout = if state.opt.queue_timeout_ms > 0 {
            Duration::from_millis(state.opt.queue_timeout_ms as u64)
        } else {
            DEFAULT_QUEUE_TIMEOUT
        };
        let permit_res =
            tokio::time::timeout(queue_timeout, state.global_query_queue.acquire()).await;

        if let Ok(Ok(_permit)) = permit_res {
            if let Some(resp) =
                process_query(&query_data, &state, client_addr, false, None, req_id).await
            {
                let len_bytes = (resp.len() as u16).to_be_bytes();
                let write_fut = async {
                    if stream.write_all(&len_bytes).await.is_err()
                        || stream.write_all(&resp).await.is_err()
                    {
                        Err(())
                    } else {
                        Ok(())
                    }
                };

                if tokio::time::timeout(idle_timeout, write_fut)
                    .await
                    .unwrap_or(Err(()))
                    .is_err()
                {
                    break;
                }
                debug!("[REQ #{}] Sent response to {}", req_id, client_addr);
            } else {
                break;
            }
        } else {
            tracing::warn!(
                "[REQ #{}] Dropped TCP query from {} due to global queue timeout",
                req_id,
                client_addr
            );
            break;
        }
    }
    Ok(())
}

pub(crate) async fn process_query(
    query_data: &[u8],
    state: &Arc<ServerState>,
    client_addr: SocketAddr,
    is_udp: bool,
    mux: Option<Arc<crate::upstream::UdpMultiplexer>>,
    req_id: RequestId,
) -> Option<Vec<u8>> {
    let query_msg = DnsView::parse(query_data)?;
    let dns_id = query_msg.get_id();
    let (qname, qtype) = query_msg.get_qname_and_type()?;
    let max_payload = if is_udp {
        query_msg.get_edns_max_payload() as usize
    } else {
        65535
    };

    debug!(
        "[REQ #{}] Query: {} (type {}) from {} (ID: {}, max_payload: {})",
        req_id, qname, qtype, client_addr, dns_id, max_payload
    );

    // Filter QType check
    if state.opt.filter_qtype.contains(&qtype) {
        debug!(
            "[REQ #{}] Filtered qtype {} for {}. Returning empty NOERROR.",
            req_id, qtype, qname
        );
        return Some(crate::dns::build_empty_reply(query_data));
    }

    // 0. Hosts file lookup
    if let Some(resp) = crate::hosts::build_response(query_msg.bytes, &qname, qtype) {
        debug!("[REQ #{}] Hosts match for {}", req_id, qname);
        return Some(resp);
    }

    // 0.5. Adblock immediate check
    if let Some(rule) = dnl::check_adblock(&qname) {
        debug!(
            "[REQ #{}] Adblock match for {} (rule: {}). Returning NXDOMAIN.",
            req_id, qname, rule
        );
        return Some(crate::dns::build_nxdomain(query_msg.bytes));
    }

    let tag = dnl::get_tag(&qname, state.default_tag);

    if let Some(filtered_qtypes) = state.opt.tag_to_filter_qtype.get(&tag)
        && filtered_qtypes.contains(&qtype)
    {
        debug!(
            "[REQ #{}] Filtered qtype {} for {} under group tag {:?}. Returning empty NOERROR.",
            req_id, qtype, qname, tag
        );
        return Some(crate::dns::build_empty_reply(query_data));
    }

    // Per-Group IPv6 Check (AAAA = 28)
    if qtype == 28 && state.opt.tag_to_no_ipv6.get(&tag).copied().unwrap_or(false) {
        debug!(
            "[REQ #{}] Filtered IPv6 query for {} under group tag {:?}. Returning empty NOERROR.",
            req_id, qname, tag
        );
        return Some(crate::dns::build_empty_reply(query_data));
    }

    // 1. Adblock immediate check
    if tag == Tag::Adblock {
        debug!(
            "[REQ #{}] Adblock match for {}. Returning NXDOMAIN.",
            req_id, qname
        );
        return Some(crate::dns::build_nxdomain(query_msg.bytes));
    }

    // 2. Check Cache
    let mut cache_key = compact_str::CompactString::new(&qname);
    cache_key.push(':');
    let mut itoa_buf = itoa::Buffer::new();
    cache_key.push_str(itoa_buf.format(qtype));

    let final_resp = match state.cache.get(&cache_key) {
        CacheStatus::Hit { data, elapsed } => {
            let mut resp = data.to_vec();
            if elapsed > 0 {
                crate::dns::decrement_ttl_in_place(&mut resp, elapsed);
            }
            if tracing::enabled!(tracing::Level::DEBUG)
                && let Some(resp_msg) = DnsView::parse(&resp)
            {
                debug!(
                    "[REQ #{}] Cache hit: {} (ID: {}, TTL: {})",
                    req_id,
                    qname,
                    dns_id,
                    resp_msg.get_min_ttl()
                );
            }
            Some(resp)
        }
        CacheStatus::Refresh { data, elapsed } => {
            let mut resp = data.to_vec();
            if elapsed > 0 {
                crate::dns::decrement_ttl_in_place(&mut resp, elapsed);
            }
            if tracing::enabled!(tracing::Level::DEBUG)
                && let Some(resp_msg) = DnsView::parse(&resp)
            {
                debug!(
                    "[REQ #{}] Cache hit (refreshing): {} (ID: {}, TTL: {})",
                    req_id,
                    qname,
                    dns_id,
                    resp_msg.get_min_ttl()
                );
            }
            spawn_background_refresh(
                state.clone(),
                query_msg.bytes.to_vec(),
                qname.clone(),
                cache_key.clone(),
                tag,
                mux.clone(),
                is_udp,
                req_id,
                "refresh",
            );
            Some(resp)
        }
        CacheStatus::Stale { data, .. } => {
            let mut resp = data.to_vec();
            crate::dns::set_ttl_to_one(&mut resp);
            if tracing::enabled!(tracing::Level::DEBUG)
                && let Some(resp_msg) = DnsView::parse(&resp)
            {
                debug!(
                    "[REQ #{}] Cache hit (stale): {} (ID: {}, TTL: {})",
                    req_id,
                    qname,
                    dns_id,
                    resp_msg.get_min_ttl()
                );
            }
            spawn_background_refresh(
                state.clone(),
                query_msg.bytes.to_vec(),
                qname.clone(),
                cache_key.clone(),
                tag,
                mux.clone(),
                is_udp,
                req_id,
                "stale",
            );
            Some(resp)
        }
        CacheStatus::Miss => {
            debug!("[REQ #{}] Cache miss: {}", req_id, qname);
            // 2. Resolve
            resolve_and_cache(
                query_msg.bytes,
                &qname,
                &cache_key,
                state.clone(),
                tag,
                mux,
                is_udp,
                req_id,
            )
            .await
        }
    };

    if let Some(mut resp) = final_resp {
        // Restore client's original DNS ID
        crate::dns::set_id_in_place(&mut resp, [query_msg.bytes[0], query_msg.bytes[1]]);

        if is_udp && resp.len() > max_payload {
            let mut resp_msg = DnsMessage::from_vec(resp)?;
            resp_msg.truncate_to_size(max_payload);
            return Some(resp_msg.into_bytes());
        }
        return Some(resp);
    }

    debug!(
        "[REQ #{}] Resolution failed for {}. Returning SERVFAIL.",
        req_id, qname
    );
    Some(crate::dns::build_servfail(query_msg.bytes))
}

fn sync_ipset(
    resp_data: Arc<[u8]>,
    tag: Tag,
    state: &Arc<ServerState>,
    _reason: &'static str,
    req_id: RequestId,
) {
    #[cfg(feature = "ipset")]
    if let Some(targets) = state.tag_to_sets.get(&tag)
        && !targets.is_empty()
    {
        // Run synchronously to ensure IP is in ipset before DNS response is returned to the client.
        // This avoids race conditions where client packets arrive before ipset is populated.
        tokio::task::block_in_place(|| {
            if let Some(resp_view) = DnsView::parse(&resp_data)
                && resp_view.is_good()
                && let Some(mut ctx) =
                    crate::ipset::new_addctx_from_targets(targets.clone(), req_id)
            {
                resp_view.add_ips(&mut ctx);
                ctx.flush();
            }
        });
    }
    #[cfg(not(feature = "ipset"))]
    {
        let _ = (resp_data, tag, state, _reason, req_id);
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_background_refresh(
    state: Arc<ServerState>,
    query_data: Vec<u8>,
    qname: compact_str::CompactString,
    cache_key: compact_str::CompactString,
    tag: Tag,
    mux: Option<Arc<crate::upstream::UdpMultiplexer>>,
    is_udp: bool,
    req_id: RequestId,
    reason: &'static str,
) {
    let should_refresh = {
        let mut inflight = state
            .refresh_inflight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        inflight.insert(cache_key.clone())
    };

    if should_refresh {
        let refresh_permit = match state.background_refresh_queue.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                let mut inflight = state
                    .refresh_inflight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                inflight.remove(&cache_key);
                debug!(
                    "[REQ #{}] Skipped background {} refresh for {} because --max-background-refreshes={} is exhausted",
                    req_id, reason, qname, state.opt.max_background_refreshes
                );
                return;
            }
        };

        struct InflightGuard {
            state: Arc<ServerState>,
            key: compact_str::CompactString,
        }
        impl Drop for InflightGuard {
            fn drop(&mut self) {
                let mut inflight = self
                    .state
                    .refresh_inflight
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                inflight.remove(&self.key);
            }
        }

        tokio::spawn(async move {
            let _refresh_permit = refresh_permit;
            let _guard = InflightGuard {
                state: state.clone(),
                key: cache_key.clone(),
            };
            debug!(
                "[REQ #{}] Background refreshing {} cache for {}",
                req_id, reason, qname
            );
            let res = resolve_and_cache(
                &query_data,
                &qname,
                &cache_key,
                state.clone(),
                tag,
                mux,
                is_udp,
                req_id,
            )
            .await;
            if res.is_some() {
                debug!(
                    "[REQ #{}] Background refresh complete ({}) for {}",
                    req_id, reason, qname
                );
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_and_cache(
    query_data: &[u8],
    qname: &str,
    cache_key: &str,
    state: Arc<ServerState>,
    tag: Tag,
    mux: Option<Arc<crate::upstream::UdpMultiplexer>>,
    is_udp: bool,
    req_id: RequestId,
) -> Option<Vec<u8>> {
    debug!("[REQ #{}] Tag for {}: {:?}", req_id, qname, tag);

    let upstreams = state.tag_to_upstreams.get(&tag)?;
    if upstreams.is_empty() {
        tracing::warn!(
            "[REQ #{}] No upstreams configured for tag {:?}",
            req_id,
            tag
        );
        return None;
    }

    let all_mode = match tag {
        Tag::Direct => state.opt.direct_dns_all,
        Tag::Proxy => state.opt.proxy_dns_all,
        _ => state
            .opt
            .tag_to_all
            .get(&tag)
            .copied()
            .unwrap_or(state.opt.group_upstream_all),
    };

    let mut final_resp = None;

    if all_mode {
        let targets = upstreams.clone();
        debug!(
            "[REQ #{}] Resolving {} via {:?} (all_mode: true)",
            req_id, qname, targets
        );
        let query: Arc<[u8]> = Arc::from(query_data);
        let mut join_set = JoinSet::new();
        for idx in 0..targets.len() {
            let query = query.clone();
            let targets_for_task = targets.clone();
            let state = state.clone();
            let mux = mux.clone();
            join_set.spawn(async move {
                let start = std::time::Instant::now();
                let res = crate::upstream::resolve_upstream(
                    query.as_ref(),
                    &targets_for_task[idx],
                    is_udp,
                    state.timeout_duration,
                    upstream_clients(&state),
                    &state.fallback_upstreams,
                    state.opt.fallback_dns_all,
                    &state.cache,
                    mux,
                    state.conn_pool.clone(),
                    req_id,
                    state.opt.out_mark,
                )
                .await;
                let elapsed = start.elapsed().as_millis() as u32;
                (idx, res, elapsed)
            });
        }

        let mut fallback_resp = None;
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok((idx, Some(resp), elapsed)) => {
                    let is_good = DnsView::parse(&resp).map(|v| v.is_good()).unwrap_or(false);
                    if is_good {
                        state.rtt_tracker.record_success(&targets[idx], elapsed);
                        final_resp = Some(resp);
                        // Remaining tasks in join_set are aborted when it's dropped
                        // at end of scope (Tokio JoinSet drop behavior).
                        break;
                    } else {
                        state.rtt_tracker.record_failure(&targets[idx]);
                        if fallback_resp.is_none() {
                            fallback_resp = Some(resp);
                        }
                    }
                }
                Ok((idx, None, _)) => {
                    state.rtt_tracker.record_failure(&targets[idx]);
                }
                Err(_) => {}
            }
        }
        if final_resp.is_none() {
            final_resp = fallback_resp;
        }
    } else {
        let mut targets: smallvec::SmallVec<[&UpstreamProtocol; 8]> = upstreams.iter().collect();
        if targets.len() > 1 {
            use rand::seq::SliceRandom;
            targets.shuffle(&mut rand::rng());
            targets.sort_by_cached_key(|up| state.rtt_tracker.get_rtt(up));
        }
        debug!(
            "[REQ #{}] Resolving {} sequentially (RTT-sorted targets: {:?})",
            req_id, qname, targets
        );

        for upstream in targets {
            let mux = mux.clone();
            let start = std::time::Instant::now();
            let res = crate::upstream::resolve_upstream(
                query_data,
                upstream,
                is_udp,
                state.timeout_duration,
                upstream_clients(&state),
                &state.fallback_upstreams,
                state.opt.fallback_dns_all,
                &state.cache,
                mux,
                state.conn_pool.clone(),
                req_id,
                state.opt.out_mark,
            )
            .await;

            if let Some(resp) = res {
                let is_good = DnsView::parse(&resp).map(|v| v.is_good()).unwrap_or(false);
                if is_good {
                    let elapsed = start.elapsed().as_millis() as u32;
                    state.rtt_tracker.record_success(upstream, elapsed);
                    final_resp = Some(resp);
                    break;
                } else {
                    state.rtt_tracker.record_failure(upstream);
                    debug!(
                        "[REQ #{}] Sequential resolve via {:?} returned non-good rcode, trying next...",
                        req_id, upstream
                    );
                    if final_resp.is_none() {
                        final_resp = Some(resp);
                    }
                }
            } else {
                state.rtt_tracker.record_failure(upstream);
                debug!(
                    "[REQ #{}] Sequential resolve via {:?} failed, trying next...",
                    req_id, upstream
                );
            }
        }
    }

    if let Some(mut resp_data) = final_resp {
        let (is_cacheable, mut ttl, resp_id, rcode) = {
            let resp_msg = DnsView::parse(&resp_data)?;
            (
                resp_msg.is_cacheable(),
                resp_msg.get_min_ttl(),
                resp_msg.get_id(),
                resp_msg.get_rcode(),
            )
        };

        debug!(
            "[REQ #{}] Resolved {} (ID: {}, RCODE: {}, TTL: {})",
            req_id, qname, resp_id, rcode, ttl
        );

        if !is_cacheable {
            return Some(resp_data);
        }

        // Use nodata-ttl if the response has no TTL-bearing records.
        if ttl == 0 {
            ttl = state.opt.cache_nodata_ttl;
        }

        let ttl = if let Some(min) = state.opt.cache_min_ttl {
            ttl.max(min)
        } else {
            ttl
        };
        let ttl = if let Some(max) = state.opt.cache_max_ttl {
            ttl.min(max)
        } else {
            ttl
        };

        // Normalize internal RRs TTLs!
        let min_ttl_override = state.opt.cache_min_ttl.unwrap_or(0);
        let max_ttl_override = state.opt.cache_max_ttl.unwrap_or(u32::MAX);
        crate::dns::normalize_ttl_in_place(&mut resp_data, min_ttl_override, max_ttl_override);

        let resp_arc: Arc<[u8]> = Arc::from(resp_data.into_boxed_slice());
        state.cache.insert(cache_key, resp_arc.clone(), ttl);

        // Add to IPSet (only for good responses)
        sync_ipset(resp_arc.clone(), tag, &state, "resolve success", req_id);

        return Some(resp_arc.to_vec());
    }

    None
}

#[cfg(unix)]
async fn handle_unix_listener(
    listener: tokio::net::UnixListener,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    loop {
        let (mut stream, _client_addr) = match listener.accept().await {
            Ok(res) => res,
            Err(e) => {
                error!("Unix accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let state = state.clone();
        let dummy_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
        let Some(conn_permit) = try_acquire_client_conn(&state, "Unix", dummy_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            if let Err(e) = handle_unix_client(&mut stream, state).await {
                debug!("Unix client error: {}", e);
            }
        });
    }
}

#[cfg(unix)]
async fn handle_unix_client(
    stream: &mut tokio::net::UnixStream,
    state: Arc<ServerState>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let idle_timeout = Duration::from_millis(state.opt.tcp_idle_timeout_ms as u64);
    let dummy_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    let mut query_data = Vec::with_capacity(DNS_BUF_SIZE);

    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if !(12..=DNS_BUF_SIZE).contains(&len) {
            break;
        }

        query_data.resize(len, 0);
        match tokio::time::timeout(idle_timeout, stream.read_exact(&mut query_data)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        state
            .query_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req_id = RequestId::new();
        let queue_timeout = if state.opt.queue_timeout_ms > 0 {
            Duration::from_millis(state.opt.queue_timeout_ms as u64)
        } else {
            DEFAULT_QUEUE_TIMEOUT
        };
        let permit_res =
            tokio::time::timeout(queue_timeout, state.global_query_queue.acquire()).await;

        if let Ok(Ok(_permit)) = permit_res {
            if let Some(resp) =
                process_query(&query_data, &state, dummy_addr, false, None, req_id).await
            {
                let len_bytes = (resp.len() as u16).to_be_bytes();
                let write_fut = async {
                    if stream.write_all(&len_bytes).await.is_err()
                        || stream.write_all(&resp).await.is_err()
                    {
                        Err(())
                    } else {
                        Ok(())
                    }
                };

                if tokio::time::timeout(idle_timeout, write_fut)
                    .await
                    .unwrap_or(Err(()))
                    .is_err()
                {
                    break;
                }
                debug!("[REQ #{}] Sent response to Unix client", req_id);
            } else {
                break;
            }
        } else {
            tracing::warn!(
                "[REQ #{}] Dropped Unix query due to global queue timeout",
                req_id
            );
            break;
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn handle_unixgram_listener(
    socket: Arc<tokio::net::UnixDatagram>,
    state: Arc<ServerState>,
    mux: Arc<crate::upstream::UdpMultiplexer>,
    _worker_id: usize,
) -> anyhow::Result<()> {
    let mut buf = [0u8; DNS_BUF_SIZE];
    let dummy_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();
    loop {
        let (len, peer_addr) = match socket.recv_from(&mut buf).await {
            Ok(res) => res,
            Err(e) => {
                error!("UnixGram recv_from error: {}", e);
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let state = state.clone();
        let socket = socket.clone();
        let mux = mux.clone();
        state
            .query_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let req_id = RequestId::new();
        if len < 12 {
            continue;
        }
        let permit = match state.global_query_queue.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    "[REQ #{}] Dropped UnixGram query due to global queue saturation",
                    req_id
                );
                continue;
            }
        };
        let query_data = buf[..len].to_vec();

        tokio::spawn(async move {
            let _permit = permit;
            if let Some(resp) =
                process_query(&query_data, &state, dummy_addr, true, Some(mux), req_id).await
            {
                if let Some(path) = peer_addr.as_pathname() {
                    if socket.send_to(&resp, path).await.is_ok() {
                        debug!("[REQ #{}] Sent response to UnixGram client", req_id);
                    }
                } else {
                    debug!(
                        "[REQ #{}] Cannot send response to unnamed UnixGram client",
                        req_id
                    );
                }
            }
        });
    }
}

#[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
pub(crate) async fn handle_doq_listener(
    endpoint: quinn::Endpoint,
    state: Arc<crate::server::ServerState>,
) -> anyhow::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let client_addr = incoming.remote_address();
        let state = state.clone();
        let Some(conn_permit) = try_acquire_client_conn(&state, "DoQ", client_addr) else {
            continue;
        };

        tokio::spawn(async move {
            let _conn_permit = conn_permit;
            match incoming.await {
                Ok(connection) => {
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        let state = state.clone();
                        tokio::spawn(async move {
                            let stream_timeout = Duration::from_millis(state.opt.timeout_ms as u64).max(MIN_DOQ_STREAM_TIMEOUT);
                            // RFC 9250: Read query with 2-byte BE length prefix
                            let mut len_buf = [0u8; 2];
                            if tokio::time::timeout(stream_timeout, recv.read_exact(&mut len_buf)).await.map_or(true, |r| r.is_err()) {
                                return;
                            }
                            let msg_len = u16::from_be_bytes(len_buf) as usize;
                            if !(12..=DNS_BUF_SIZE).contains(&msg_len) {
                                return;
                            }
                            let mut query_buf = vec![0u8; msg_len];
                            if tokio::time::timeout(stream_timeout, recv.read_exact(&mut query_buf)).await.map_or(true, |r| r.is_err()) {
                                return;
                            }

                            state.query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let req_id = crate::request_id::RequestId::new();
                            let queue_timeout = if state.opt.queue_timeout_ms > 0 {
                                Duration::from_millis(state.opt.queue_timeout_ms as u64)
                            } else {
                                DEFAULT_QUEUE_TIMEOUT
                            };
                            let _permit = match tokio::time::timeout(
                                queue_timeout,
                                state.global_query_queue.clone().acquire_owned(),
                            ).await {
                                Ok(Ok(p)) => p,
                                _ => {
                                    tracing::warn!(
                                        "[REQ #{}] Dropped DoQ query from {} due to global queue saturation",
                                        req_id,
                                        client_addr
                                    );
                                    return;
                                }
                            };

                            // Process query
                            if let Some(resp) = process_query(
                                &query_buf,
                                &state,
                                client_addr,
                                false,
                                None,
                                req_id,
                            )
                            .await
                            {
                                // RFC 9250: Write back response with 2-byte BE length prefix, then finish stream
                                let mut payload = Vec::with_capacity(2 + resp.len());
                                payload.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                                payload.extend_from_slice(&resp);
                                let write_res = tokio::time::timeout(stream_timeout, send.write_all(&payload)).await;
                                if matches!(write_res, Ok(Ok(()))) {
                                    let _ = send.finish();
                                }
                            }
                        });
                    }
                }
                Err(e) => {
                    tracing::error!("DoQ incoming connection failed from {}: {}", client_addr, e);
                }
            }
        });
    }
    Ok(())
}

#[cfg(test)]
impl ServerState {
    pub(crate) fn mock() -> Self {
        let opt = std::sync::Arc::new(crate::opt::Opt::default());
        Self {
            opt: opt.clone(),
            default_tag: Tag::Direct,
            tag_to_upstreams: rustc_hash::FxHashMap::default(),
            #[cfg(feature = "ipset")]
            tag_to_sets: rustc_hash::FxHashMap::default(),
            fallback_upstreams: std::sync::Arc::from(Vec::new()),
            cache: std::sync::Arc::new(crate::cache::DnsCache::new(0, 0, None)),
            tls_config: None,
            tls_config_by_ca: rustc_hash::FxHashMap::default(),
            http_client: None,
            http_clients_by_ca: rustc_hash::FxHashMap::default(),
            #[cfg(feature = "rustls-stack")]
            http3_client: None,
            #[cfg(feature = "rustls-stack")]
            http3_clients_by_ca: rustc_hash::FxHashMap::default(),
            conn_pool: std::sync::Arc::new(crate::upstream::ConnectionPool::new(16, opt.clone())),
            timeout_duration: DEFAULT_DNS_TIMEOUT,
            query_count: std::sync::atomic::AtomicU64::new(0),
            refresh_inflight: std::sync::Mutex::new(rustc_hash::FxHashSet::default()),
            global_query_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1000)),
            client_conn_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1024)),
            background_refresh_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            rtt_tracker: std::sync::Arc::new(crate::upstream::RttTracker::new()),
        }
    }
}

pub(crate) fn init_result_logging(_path: &str) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn reopen_result_log() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cert_pair() {
        assert_eq!(
            parse_cert_pair("/etc/dns.crt,/etc/dns.key").unwrap(),
            ("/etc/dns.crt".to_string(), "/etc/dns.key".to_string())
        );
        assert_eq!(
            parse_cert_pair("/etc/combined.pem").unwrap(),
            (
                "/etc/combined.pem".to_string(),
                "/etc/combined.pem".to_string()
            )
        );
        assert!(parse_cert_pair("").is_err());
        assert!(parse_cert_pair("/etc/dns.crt,").is_err());
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_load_sec1_ec_private_key() {
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        writeln!(
            key_file,
            "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMaA7bFrjDDBSik057bIKo7UQXJZNwLK9AjYZQ7yIWFloAoGCCqGSM49
AwEHoUQDQgAExu0Z/w8nQJZAXeOXOnZun9HiZscY9H/KwYcXpeZHu+f9P9mOUEkH
5Z0av+JKtzhFspjngNLVgWcjlA1L5AJLdA==
-----END EC PRIVATE KEY-----"
        )
        .unwrap();

        let key = load_keys(key_file.path().to_str().unwrap()).unwrap();
        assert!(matches!(key, rustls::pki_types::PrivateKeyDer::Sec1(_)));
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_normalize_cert_name() {
        assert_eq!(
            normalize_cert_name("DNS.Example.COM."),
            Some("dns.example.com".to_string())
        );
        assert_eq!(
            normalize_cert_name("*.Example.COM"),
            Some("*.example.com".to_string())
        );
        assert!(normalize_cert_name("*a.example.com").is_none());
        assert!(normalize_cert_name("-bad.example.com").is_none());
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_wildcard_matches_single_label_only() {
        assert!(wildcard_matches(".example.com", "dns.example.com"));
        assert!(!wildcard_matches(".example.com", "a.b.example.com"));
        assert!(!wildcard_matches(".example.com", "example.com"));
        assert!(!wildcard_matches(".example.com", "badexample.com"));
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_sni_selection_default_uses_fallback() {
        let mut exact = FxHashMap::default();
        exact.insert("dns.example.com".to_string(), 1);
        let wildcards = vec![(".example.net".to_string(), 2)];
        let fallback = 9;

        assert_eq!(
            select_sni_match(&exact, &wildcards, Some(&fallback), false, None),
            Some(&fallback)
        );
        assert_eq!(
            select_sni_match(
                &exact,
                &wildcards,
                Some(&fallback),
                false,
                Some("unknown.example.com")
            ),
            Some(&fallback)
        );
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_sni_selection_strict_rejects_no_or_unmatched_sni() {
        let mut exact = FxHashMap::default();
        exact.insert("dns.example.com".to_string(), 1);
        let wildcards = vec![(".example.net".to_string(), 2)];
        let fallback = 9;

        assert_eq!(
            select_sni_match(&exact, &wildcards, Some(&fallback), true, None),
            None
        );
        assert_eq!(
            select_sni_match(
                &exact,
                &wildcards,
                Some(&fallback),
                true,
                Some("unknown.example.com")
            ),
            None
        );
    }

    #[test]
    #[cfg(feature = "rustls-stack")]
    fn test_sni_selection_strict_accepts_exact_and_wildcard() {
        let mut exact = FxHashMap::default();
        exact.insert("dns.example.com".to_string(), 1);
        let wildcards = vec![(".example.net".to_string(), 2)];
        let fallback = 9;

        assert_eq!(
            select_sni_match(
                &exact,
                &wildcards,
                Some(&fallback),
                true,
                Some("DNS.Example.COM.")
            ),
            Some(&1)
        );
        assert_eq!(
            select_sni_match(
                &exact,
                &wildcards,
                Some(&fallback),
                true,
                Some("anycast.example.net")
            ),
            Some(&2)
        );
        assert_eq!(
            select_sni_match(
                &exact,
                &wildcards,
                Some(&fallback),
                true,
                Some("a.b.example.net")
            ),
            None
        );
    }

    #[test]
    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    fn test_boring_cert_resolver_selection() {
        boring::init();
        let create_key = || {
            let rsa = boring::rsa::Rsa::generate(2048).unwrap();
            let key = boring::pkey::PKey::from_rsa(rsa).unwrap();
            let mut x509_name = boring::x509::X509Name::builder().unwrap();
            x509_name.append_entry_by_text("CN", "test").unwrap();
            let x509_name = x509_name.build();
            let mut x509_builder = boring::x509::X509::builder().unwrap();
            x509_builder.set_subject_name(&x509_name).unwrap();
            x509_builder.set_pubkey(&key).unwrap();
            let bn = boring::bn::BigNum::from_u32(1).unwrap();
            let serial = boring::asn1::Asn1Integer::from_bn(&bn).unwrap();
            x509_builder.set_serial_number(&serial).unwrap();
            let not_before = boring::asn1::Asn1Time::days_from_now(0).unwrap();
            x509_builder.set_not_before(&not_before).unwrap();
            let not_after = boring::asn1::Asn1Time::days_from_now(365).unwrap();
            x509_builder.set_not_after(&not_after).unwrap();
            x509_builder
                .sign(&key, boring::hash::MessageDigest::sha256())
                .unwrap();
            let leaf = x509_builder.build();
            Arc::new(crate::quiche_server::BoringCertKey {
                leaf,
                key,
                chain: vec![],
            })
        };

        let ctx_exact = create_key();
        let ctx_wildcard = create_key();
        let ctx_fallback = create_key();

        let mut exact = std::collections::HashMap::new();
        exact.insert("dns.example.com".to_string(), ctx_exact.clone());
        let wildcards = vec![(".example.net".to_string(), ctx_wildcard.clone())];

        let resolver = BoringCertResolver::new(exact, wildcards, ctx_fallback.clone(), false);

        // Exact match
        let res_exact = resolver.resolve(Some("dns.example.com")).unwrap();
        assert!(Arc::ptr_eq(&res_exact, &ctx_exact));

        // Wildcard match
        let res_wildcard = resolver.resolve(Some("sub.example.net")).unwrap();
        assert!(Arc::ptr_eq(&res_wildcard, &ctx_wildcard));

        // RFC 6125 Single-level wildcard scope check (multi-level should fail wildcard match and return fallback)
        let res_multilevel = resolver.resolve(Some("a.b.example.net")).unwrap();
        assert!(Arc::ptr_eq(&res_multilevel, &ctx_fallback));

        // Fallback when no SNI provided and strict_sni = false
        let res_none = resolver.resolve(None).unwrap();
        assert!(Arc::ptr_eq(&res_none, &ctx_fallback));

        // Strict SNI test: returns SniError::ALERT_FATAL on missing or unmatched SNI
        let strict_resolver = BoringCertResolver::new(
            std::collections::HashMap::new(),
            vec![],
            ctx_fallback.clone(),
            true,
        );
        assert!(strict_resolver.resolve(None).is_err());
        assert!(strict_resolver.resolve(Some("unknown.com")).is_err());
    }

    // --- IP SAN extraction tests ---

    /// Helper: build a minimal SAN extension DER fragment containing the given
    /// GeneralName entries (each entry is a raw tag+length+value).
    #[cfg(feature = "rustls-stack")]
    fn build_san_extension(entries: &[&[u8]]) -> Vec<u8> {
        // Build inner SEQUENCE of GeneralName entries
        let mut seq_content = Vec::new();
        for entry in entries {
            seq_content.extend_from_slice(entry);
        }
        let mut seq = vec![0x30]; // SEQUENCE tag
        push_der_length(&mut seq, seq_content.len());
        seq.extend(seq_content);

        // Wrap in OCTET STRING
        let mut octet = vec![0x04]; // OCTET STRING tag
        push_der_length(&mut octet, seq.len());
        octet.extend(seq);

        // Prepend the SAN OID: 06 03 55 1D 11
        let mut ext = vec![0x06, 0x03, 0x55, 0x1D, 0x11];
        ext.extend(octet);

        ext
    }

    #[cfg(feature = "rustls-stack")]
    fn push_der_length(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }

    /// Build an iPAddress GeneralName entry (tag 0x87)
    #[cfg(feature = "rustls-stack")]
    fn ip4_entry(a: u8, b: u8, c: u8, d: u8) -> Vec<u8> {
        vec![0x87, 0x04, a, b, c, d]
    }

    #[cfg(feature = "rustls-stack")]
    fn ip6_entry(bytes: [u8; 16]) -> Vec<u8> {
        let mut v = vec![0x87, 0x10]; // tag=0x87, len=16
        v.extend_from_slice(&bytes);
        v
    }

    /// Build a dNSName GeneralName entry (tag 0x82) — used as filler
    #[cfg(feature = "rustls-stack")]
    fn dns_entry(name: &str) -> Vec<u8> {
        let mut v = vec![0x82, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_ipv4() {
        let ip4 = ip4_entry(10, 20, 30, 1);
        let der = build_san_extension(&[&ip4]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 20, 30, 1))]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_ipv6() {
        let bytes: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ip6 = ip6_entry(bytes);
        let der = build_san_extension(&[&ip6]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1
            ))]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_mixed_with_dns() {
        let dns = dns_entry("example.com");
        let ip4 = ip4_entry(192, 168, 1, 100);
        let der = build_san_extension(&[&dns, &ip4]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, 1, 100
            ))]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_multiple_ips() {
        let ip1 = ip4_entry(10, 0, 0, 1);
        let ip2 = ip4_entry(10, 0, 0, 2);
        let der = build_san_extension(&[&ip1, &ip2]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
            ]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_no_san_extension() {
        let der = [0x30, 0x03, 0x01, 0x02, 0x03];
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_empty_san() {
        let der = build_san_extension(&[]);
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_ignores_bad_length() {
        // iPAddress with length 5 (not valid IPv4 or IPv6)
        let bad = vec![0x87, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        let der = build_san_extension(&[&bad]);
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_short_form() {
        assert_eq!(read_der_length(&[0x00]), Some((0, 1)));
        assert_eq!(read_der_length(&[0x7F]), Some((127, 1)));
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_long_form() {
        assert_eq!(read_der_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(read_der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_indefinite_rejected() {
        assert_eq!(read_der_length(&[0x80]), None);
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_empty_rejected() {
        assert_eq!(read_der_length(&[]), None);
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_with_critical_flag() {
        let ip4 = ip4_entry(10, 0, 0, 1);
        let inner = build_san_extension(&[&ip4]);
        let mut der = inner[..5].to_vec();
        der.extend_from_slice(&[0x01, 0x01, 0xFF]);
        der.extend_from_slice(&inner[5..]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_truncated_entry() {
        let mut der = vec![0x06, 0x03, 0x55, 0x1D, 0x11];
        der.extend_from_slice(&[0x04, 0x06]);
        der.extend_from_slice(&[0x30, 0x04]);
        der.extend_from_slice(&[0x87, 0x04, 0x0A, 0x00]);
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_ipv4_mapped_ipv6() {
        let bytes: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1];
        let ip6 = ip6_entry(bytes);
        let der = build_san_extension(&[&ip6]);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xFFFF, 0xC0A8, 0x0101
            ))]
        );
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_zero_length_ip() {
        let bad = vec![0x87, 0x00];
        let der = build_san_extension(&[&bad]);
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_non_minimal_accepted() {
        assert_eq!(read_der_length(&[0x81, 0x01]), Some((1, 2)));
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_multibyte() {
        assert_eq!(read_der_length(&[0x83, 0x01, 0x00, 0x00]), Some((65536, 4)));
        assert_eq!(
            read_der_length(&[0x84, 0x01, 0x00, 0x00, 0x00]),
            Some((16777216, 5))
        );
        assert_eq!(read_der_length(&[0x85, 0x01, 0x00, 0x00, 0x00, 0x00]), None);
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_ignores_subnet_mask_ip() {
        let mask_ip = vec![0x87, 0x08, 10, 0, 0, 0, 255, 255, 255, 0];
        let der = build_san_extension(&[&mask_ip]);
        assert!(extract_ip_sans(&der).is_empty());
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_read_der_length_truncated_header() {
        assert_eq!(read_der_length(&[0x82, 0x01]), None);
    }

    #[cfg(feature = "rustls-stack")]
    #[test]
    fn test_extract_ip_sans_false_oid_in_issuer_dn() {
        let fake = vec![0x06, 0x03, 0x55, 0x1D, 0x11, 0x04, 0x02, 0x01, 0x02];
        let ip4 = ip4_entry(10, 0, 0, 5);
        let real_san = build_san_extension(&[&ip4]);
        let mut der = fake;
        der.extend_from_slice(&real_san);
        let result = extract_ip_sans(&der);
        assert_eq!(
            result,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))]
        );
    }
}
