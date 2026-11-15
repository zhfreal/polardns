use rustc_hash::FxHashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use crate::request_id::RequestId;

#[cfg(feature = "rustls-stack")]
use rustls::ClientConfig;
#[cfg(feature = "rustls-stack")]
use rustls::pki_types::ServerName;
#[cfg(feature = "rustls-stack")]
use tokio_rustls::TlsConnector;

#[cfg(feature = "rustls-stack")]
pub type HttpClientType = reqwest::Client;

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub type HttpClientType = crate::http_client::HttpClient;

#[cfg(feature = "rustls-stack")]
pub type UpstreamTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub type UpstreamTlsStream = tokio_boring::SslStream<tokio::net::TcpStream>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TlsOptions {
    pub ca_certs: Option<String>,
    pub mark: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamProtocol {
    Udp(SocketAddr, TlsOptions),
    Tcp(SocketAddr, TlsOptions),
    UdpAndTcp(SocketAddr, TlsOptions),
    Dot {
        addr: Option<SocketAddr>,
        hostname: String,
        port: u16,
        tls: TlsOptions,
    },
    Doh {
        url: String,
        tls: TlsOptions,
    },
    DohH3 {
        url: String,
        tls: TlsOptions,
    },
    Doq {
        addr: Option<SocketAddr>,
        hostname: String,
        port: u16,
        tls: TlsOptions,
    },
}

impl UpstreamProtocol {
    pub fn options(&self) -> &TlsOptions {
        match self {
            UpstreamProtocol::Udp(_, opts) => opts,
            UpstreamProtocol::Tcp(_, opts) => opts,
            UpstreamProtocol::UdpAndTcp(_, opts) => opts,
            UpstreamProtocol::Dot { tls, .. } => tls,
            UpstreamProtocol::Doh { tls, .. } => tls,
            UpstreamProtocol::DohH3 { tls, .. } => tls,
            UpstreamProtocol::Doq { tls, .. } => tls,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let (s, tls) = parse_upstream_tls_options(s)?;
        if let Some(host_port) = s.strip_prefix("tls://") {
            let (host, port) = parse_tls_host_port(host_port, 853);

            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                Some(UpstreamProtocol::Dot {
                    addr: Some(SocketAddr::new(ip, port)),
                    hostname: host,
                    port,
                    tls,
                })
            } else {
                Some(UpstreamProtocol::Dot {
                    addr: None,
                    hostname: host,
                    port,
                    tls,
                })
            }
        } else if s.starts_with("https://") {
            Some(UpstreamProtocol::Doh {
                url: s.to_string(),
                tls,
            })
        } else if s.starts_with("h3://") {
            #[cfg(any(feature = "upstream-h3", feature = "quiche"))]
            {
                Some(UpstreamProtocol::DohH3 {
                    url: s.replacen("h3://", "https://", 1),
                    tls,
                })
            }
            #[cfg(not(any(feature = "upstream-h3", feature = "quiche")))]
            {
                tracing::warn!("h3:// upstream requested but HTTP/3 client features are disabled");
                None
            }
        } else if let Some(_host_port) = s.strip_prefix("quic://").or_else(|| s.strip_prefix("doq://")) {
            #[cfg(any(feature = "original-h3-server", feature = "quiche"))]
            {
                let (host, port) = parse_tls_host_port(_host_port, 853);
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    Some(UpstreamProtocol::Doq {
                        addr: Some(SocketAddr::new(ip, port)),
                        hostname: host,
                        port,
                        tls,
                    })
                } else {
                    Some(UpstreamProtocol::Doq {
                        addr: None,
                        hostname: host,
                        port,
                        tls,
                    })
                }
            }
            #[cfg(not(any(feature = "original-h3-server", feature = "quiche")))]
            {
                tracing::warn!("quic:// / doq:// upstream requested but DoQ client features are disabled");
                None
            }
        } else if let Some(host_port) = s.strip_prefix("tcp://") {
            if tls.ca_certs.is_some() {
                return None;
            }
            let addr = parse_ip_port(host_port, 53)?;
            Some(UpstreamProtocol::Tcp(addr, tls))
        } else if let Some(host_port) = s.strip_prefix("udp://") {
            if tls.ca_certs.is_some() {
                return None;
            }
            let addr = parse_ip_port(host_port, 53)?;
            Some(UpstreamProtocol::Udp(addr, tls))
        } else {
            if tls.ca_certs.is_some() {
                return None;
            }
            let addr = parse_ip_port(s, 53)?;
            Some(UpstreamProtocol::UdpAndTcp(addr, tls))
        }
    }
}

impl std::fmt::Display for UpstreamProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamProtocol::Udp(addr, _) => write!(f, "udp://{}", addr),
            UpstreamProtocol::Tcp(addr, _) => write!(f, "tcp://{}", addr),
            UpstreamProtocol::UdpAndTcp(addr, _) => write!(f, "udp+tcp://{}", addr),
            UpstreamProtocol::Dot { hostname, port, .. } => write!(f, "tls://{}:{}", hostname, port),
            UpstreamProtocol::Doh { url, .. } => write!(f, "{}", url),
            UpstreamProtocol::DohH3 { url, .. } => write!(f, "h3://{}", url.strip_prefix("https://").unwrap_or(url)),
            UpstreamProtocol::Doq { hostname, port, .. } => write!(f, "quic://{}:{}", hostname, port),
        }
    }
}

fn parse_upstream_tls_options(s: &str) -> Option<(&str, TlsOptions)> {
    let Some((base, raw_attrs)) = s.split_once('|') else {
        return Some((s, TlsOptions::default()));
    };
    if base.trim().is_empty() {
        return None;
    }

    let mut opts = TlsOptions::default();
    for raw_attr in raw_attrs.split('|') {
        let raw_attr = raw_attr.trim();
        if raw_attr.is_empty() {
            continue;
        }
        let (key, value) = raw_attr.split_once('=')?;
        match key.trim() {
            "ca" => {
                let value = value.trim();
                if value.is_empty() {
                    return None;
                }
                opts.ca_certs = Some(value.to_string());
            }
            "mark" => {
                let value = value.trim();
                let mark = value.parse::<u32>().ok()?;
                opts.mark = Some(mark);
            }
            _ => return None,
        }
    }

    Some((base.trim(), opts))
}

fn parse_tls_host_port(s: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }

    if s.parse::<std::net::IpAddr>().is_ok() {
        return (s.to_string(), default_port);
    }

    if let Some((host, port)) = s.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_string(), port);
    }

    (s.to_string(), default_port)
}

fn parse_ip_port(s: &str, default_port: u16) -> Option<SocketAddr> {
    let s = s.replace('#', ":");
    if let Ok(addr) = s.parse::<SocketAddr>() {
        Some(addr)
    } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        Some(SocketAddr::new(ip, default_port))
    } else {
        None
    }
}

pub const DEFAULT_UNMEASURED_RTT_MS: u32 = 10;
pub const RTT_EMA_WEIGHT_PREV: f32 = 0.8;
pub const RTT_EMA_WEIGHT_CURR: f32 = 0.2;
pub const DEFAULT_RTT_FAILURE_PENALTY_MS: u32 = 1000;
pub const MAX_RTT_PENALTY_MS: u32 = 5000;
pub const DEFAULT_UPSTREAM_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_BOOTSTRAP_RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);
pub const UDP_MUX_ERROR_BACKOFF: Duration = Duration::from_millis(10);
pub const UPSTREAM_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(60);
pub const UPSTREAM_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

pub struct RttTracker {
    rtts: std::sync::RwLock<rustc_hash::FxHashMap<UpstreamProtocol, Arc<std::sync::atomic::AtomicU32>>>,
}

impl Default for RttTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RttTracker {
    pub fn new() -> Self {
        Self {
            rtts: std::sync::RwLock::new(rustc_hash::FxHashMap::default()),
        }
    }

    pub fn get_rtt(&self, upstream: &UpstreamProtocol) -> u32 {
        let rtts = self.rtts.read().unwrap_or_else(|e| e.into_inner());
        rtts.get(upstream)
            .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(DEFAULT_UNMEASURED_RTT_MS)
    }

    pub fn get_rtts(&self, upstreams: &[UpstreamProtocol]) -> Vec<u32> {
        let rtts = self.rtts.read().unwrap_or_else(|e| e.into_inner());
        upstreams
            .iter()
            .map(|up| {
                rtts.get(up)
                    .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(DEFAULT_UNMEASURED_RTT_MS)
            })
            .collect()
    }

    pub fn get_rtts_refs(&self, upstreams: &[&UpstreamProtocol]) -> Vec<u32> {
        let rtts = self.rtts.read().unwrap_or_else(|e| e.into_inner());
        upstreams
            .iter()
            .map(|up| {
                rtts.get(*up)
                    .map(|a| a.load(std::sync::atomic::Ordering::Relaxed))
                    .unwrap_or(DEFAULT_UNMEASURED_RTT_MS)
            })
            .collect()
    }

    pub fn record_success(&self, upstream: &UpstreamProtocol, rtt_ms: u32) {
        let atom = {
            let rtts = self.rtts.read().unwrap_or_else(|e| e.into_inner());
            rtts.get(upstream).cloned()
        };

        let atom = match atom {
            Some(a) => a,
            None => {
                let mut rtts = self.rtts.write().unwrap_or_else(|e| e.into_inner());
                match rtts.entry(upstream.clone()) {
                    std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        let val = (((DEFAULT_UNMEASURED_RTT_MS as f32) * RTT_EMA_WEIGHT_PREV)
                            + (rtt_ms as f32 * RTT_EMA_WEIGHT_CURR)) as u32;
                        tracing::debug!(
                            "[RTT] Upstream {:?} RTT: {}ms -> {}ms (measured: {}ms)",
                            upstream,
                            DEFAULT_UNMEASURED_RTT_MS,
                            val,
                            rtt_ms
                        );
                        let a = Arc::new(std::sync::atomic::AtomicU32::new(val));
                        e.insert(a);
                        return;
                    }
                }
            }
        };

        let mut old = atom.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let new = ((old as f32) * RTT_EMA_WEIGHT_PREV + (rtt_ms as f32) * RTT_EMA_WEIGHT_CURR) as u32;
            match atom.compare_exchange_weak(
                old,
                new,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    tracing::debug!(
                        "[RTT] Upstream {:?} RTT: {}ms -> {}ms (measured: {}ms)",
                        upstream,
                        old,
                        new,
                        rtt_ms
                    );
                    break;
                }
                Err(actual) => old = actual,
            }
        }
    }

    pub fn record_failure(&self, upstream: &UpstreamProtocol) {
        let atom = {
            let rtts = self.rtts.read().unwrap_or_else(|e| e.into_inner());
            rtts.get(upstream).cloned()
        };

        let atom = match atom {
            Some(a) => a,
            None => {
                let mut rtts = self.rtts.write().unwrap_or_else(|e| e.into_inner());
                match rtts.entry(upstream.clone()) {
                    std::collections::hash_map::Entry::Occupied(e) => e.get().clone(),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        let initial = DEFAULT_UNMEASURED_RTT_MS + DEFAULT_RTT_FAILURE_PENALTY_MS;
                        tracing::debug!(
                            "[RTT] Upstream {:?} failure penalty: {}ms -> {}ms",
                            upstream,
                            DEFAULT_UNMEASURED_RTT_MS,
                            initial
                        );
                        let a = Arc::new(std::sync::atomic::AtomicU32::new(initial));
                        e.insert(a);
                        return;
                    }
                }
            }
        };

        let mut old = atom.load(std::sync::atomic::Ordering::Relaxed);
        loop {
            let new = old.saturating_add(DEFAULT_RTT_FAILURE_PENALTY_MS).min(MAX_RTT_PENALTY_MS);
            match atom.compare_exchange_weak(
                old,
                new,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => {
                    tracing::debug!(
                        "[RTT] Upstream {:?} failure penalty: {}ms -> {}ms",
                        upstream,
                        old,
                        new
                    );
                    break;
                }
                Err(actual) => old = actual,
            }
        }
    }
}

#[cfg(feature = "rustls-stack")]
pub struct TlsConfig {
    pub client_config: Arc<ClientConfig>,
}

#[cfg(feature = "rustls-stack")]
impl TlsConfig {
    pub fn new(cert_verify: bool, ca_certs: Option<&str>) -> Self {
        let client_config = if cert_verify {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(ca_path) = ca_certs {
                match std::fs::File::open(ca_path) {
                    Ok(mut file) => {
                        let mut pem_data = Vec::new();
                        use std::io::Read;
                        if file.read_to_end(&mut pem_data).is_ok() {
                            let mut reader = &pem_data[..];
                            let certs = rustls_pemfile::certs(&mut reader);
                            let mut loaded = 0;
                            for cert in certs {
                                if let Ok(cert) = cert
                                    && root_store.add(cert).is_ok()
                                {
                                    loaded += 1;
                                }
                            }
                            tracing::info!("Loaded {} CA certificates from '{}'", loaded, ca_path);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to open CA certs '{}': {}, falling back to built-in roots",
                            ca_path,
                            e
                        );
                        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                    }
                }
            } else {
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            }

            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        } else {
            let verifier = Arc::new(NoVerifier);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth()
        };
        let mut client_config = client_config;
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        Self {
            client_config: Arc::new(client_config),
        }
    }

    pub fn new_ca_only(ca_path: &str) -> anyhow::Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        let mut file = std::fs::File::open(ca_path)?;
        let mut pem_data = Vec::new();
        use std::io::Read;
        file.read_to_end(&mut pem_data)?;
        let mut reader = &pem_data[..];
        let mut loaded = 0;
        for cert in rustls_pemfile::certs(&mut reader) {
            if let Ok(cert) = cert
                && root_store.add(cert).is_ok()
            {
                loaded += 1;
            }
        }
        if loaded == 0 {
            anyhow::bail!("no valid CA certificates found in '{}'", ca_path);
        }
        tracing::info!("Loaded {} CA certificates from '{}'", loaded, ca_path);

        let mut client_config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"dot".to_vec()];

        Ok(Self {
            client_config: Arc::new(client_config),
        })
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
#[derive(Clone)]
pub struct TlsConfig {
    pub connector: boring::ssl::SslConnector,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub fn configure_ca_store_with_fallbacks(builder: &mut boring::ssl::SslConnectorBuilder) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        let candidates = [
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/ca-bundle.pem",
        ];
        let mut loaded = false;
        for path in &candidates {
            let path_ref = std::path::Path::new(path);
            if path_ref.exists() {
                if let Err(e) = std::fs::File::open(path_ref) {
                    tracing::warn!("CA certificate file '{}' exists but is not readable: {}", path, e);
                    continue;
                }
                if builder.set_ca_file(path).is_ok() {
                    tracing::info!("Loaded CA certificates from fallback path: '{}'", path);
                    loaded = true;
                    break;
                }
            }
        }
        if !loaded {
            builder.set_default_verify_paths()?;
        }
    }
    #[cfg(not(unix))]
    {
        builder.set_default_verify_paths()?;
    }
    Ok(())
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl TlsConfig {
    pub fn new(cert_verify: bool, ca_certs: Option<&str>) -> Self {
        let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls()).unwrap();
        let _ = builder.set_alpn_protos(b"\x03dot");
        builder.set_session_cache_size(256);
        if !cert_verify {
            builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        } else if let Some(ca_path) = ca_certs {
            if std::fs::metadata(ca_path).is_ok() {
                if let Err(e) = builder.set_ca_file(ca_path) {
                    tracing::warn!("Failed to load CA file '{}' for DoT upstream: {}", ca_path, e);
                    let _ = configure_ca_store_with_fallbacks(&mut builder);
                }
            } else {
                tracing::warn!("CA certificate file '{}' does not exist, using fallbacks", ca_path);
                let _ = configure_ca_store_with_fallbacks(&mut builder);
            }
        } else {
            let _ = configure_ca_store_with_fallbacks(&mut builder);
        }
        Self {
            connector: builder.build(),
        }
    }

    pub fn new_ca_only(ca_path: &str) -> anyhow::Result<Self> {
        let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
        let _ = builder.set_alpn_protos(b"\x03dot");
        builder.set_session_cache_size(256);
        
        if !std::path::Path::new(ca_path).exists() {
            anyhow::bail!("no valid CA certificates found in '{}'", ca_path);
        }
        let metadata = std::fs::metadata(ca_path)?;
        if metadata.len() == 0 {
            anyhow::bail!("no valid CA certificates found in '{}'", ca_path);
        }
        
        builder.set_ca_file(ca_path)?;
        Ok(Self {
            connector: builder.build(),
        })
    }
}

#[cfg(feature = "rustls-stack")]
#[derive(Debug)]
struct NoVerifier;

#[cfg(feature = "rustls-stack")]
impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn resolve_upstream(
    query: &[u8],
    protocol: &UpstreamProtocol,
    is_udp: bool,
    timeout_dur: Duration,
    clients: UpstreamClients<'_>,
    fallback_upstreams: &[UpstreamProtocol],
    fallback_dns_all: bool,
    cache: &Arc<crate::cache::DnsCache>,
    mux: Option<Arc<UdpMultiplexer>>,
    pool: Arc<ConnectionPool>,
    req_id: RequestId,
    global_mark: Option<u32>,
) -> Option<Vec<u8>> {
    match timeout(
        timeout_dur,
        resolve_upstream_internal(
            query,
            protocol,
            is_udp,
            clients,
            fallback_upstreams,
            fallback_dns_all,
            cache,
            mux,
            pool,
            req_id,
            global_mark,
        ),
    )
    .await
    {
        Ok(res) => {
            if let Some(resp) = &res {
                let query_msg = crate::dns::DnsView::parse(query)?;
                let resp_msg = match crate::dns::DnsView::parse(resp) {
                    Some(msg) => msg,
                    None => {
                        tracing::warn!(
                            "[{}] Invalid upstream response from {:?}",
                            req_id,
                            protocol
                        );
                        return None;
                    }
                };
                let (q_name, q_type) = query_msg.get_qname_and_type()?;
                let (r_name, r_type) = match resp_msg.get_qname_and_type() {
                    Some(q) => q,
                    None => {
                        tracing::warn!(
                            "[{}] Upstream response missing question section from {:?}",
                            req_id,
                            protocol
                        );
                        return None;
                    }
                };
                if q_type != r_type || !q_name.eq_ignore_ascii_case(&r_name) {
                    tracing::warn!(
                        "[{}] Mismatch in upstream response! Query: {} (type {}), got: {} (type {}) from {:?}",
                        req_id,
                        q_name,
                        crate::dns::qtype_to_str(q_type),
                        r_name,
                        crate::dns::qtype_to_str(r_type),
                        protocol
                    );
                    return None;
                }
                if !resp_msg.is_acceptable_upstream_response() {
                    tracing::debug!(
                        "[{}] Rejecting upstream response from {:?}: rcode={}, truncated={}",
                        req_id,
                        protocol,
                        resp_msg.get_rcode(),
                        resp_msg.is_truncated()
                    );
                    return None;
                }
            }
            res
        }
        Err(_) => {
            tracing::debug!(
                "[{}] Upstream query timed out after {:?}",
                req_id,
                timeout_dur
            );
            None
        }
    }
}

pub struct UpstreamClients<'a> {
    pub default_tls: Option<Arc<TlsConfig>>,
    pub tls_by_ca: &'a FxHashMap<String, Arc<TlsConfig>>,
    pub default_http: Option<&'a HttpClientType>,
    pub http_by_ca: &'a FxHashMap<String, Arc<HttpClientType>>,
    #[cfg(feature = "rustls-stack")]
    pub default_http3: Option<&'a reqwest::Client>,
    #[cfg(feature = "rustls-stack")]
    pub http3_by_ca: &'a FxHashMap<String, Arc<reqwest::Client>>,
}

impl UpstreamClients<'_> {
    pub fn empty() -> UpstreamClients<'static> {
        static TLS_BY_CA: std::sync::OnceLock<FxHashMap<String, Arc<TlsConfig>>> =
            std::sync::OnceLock::new();
        static HTTP_BY_CA: std::sync::OnceLock<FxHashMap<String, Arc<HttpClientType>>> =
            std::sync::OnceLock::new();
        #[cfg(feature = "rustls-stack")]
        static HTTP3_BY_CA: std::sync::OnceLock<FxHashMap<String, Arc<reqwest::Client>>> =
            std::sync::OnceLock::new();

        UpstreamClients {
            default_tls: None,
            tls_by_ca: TLS_BY_CA.get_or_init(FxHashMap::default),
            default_http: None,
            http_by_ca: HTTP_BY_CA.get_or_init(FxHashMap::default),
            #[cfg(feature = "rustls-stack")]
            default_http3: None,
            #[cfg(feature = "rustls-stack")]
            http3_by_ca: HTTP3_BY_CA.get_or_init(FxHashMap::default),
        }
    }

    fn tls_config(&self, opts: &TlsOptions) -> Option<Arc<TlsConfig>> {
        if let Some(ca_path) = &opts.ca_certs {
            self.tls_by_ca.get(ca_path).cloned()
        } else {
            self.default_tls.clone()
        }
    }

    fn http_client(&self, opts: &TlsOptions) -> Option<&HttpClientType> {
        if let Some(ca_path) = &opts.ca_certs {
            self.http_by_ca.get(ca_path).map(Arc::as_ref)
        } else {
            self.default_http
        }
    }

    #[cfg(all(feature = "rustls-stack", feature = "upstream-h3"))]
    fn http3_client(&self, opts: &TlsOptions) -> Option<&reqwest::Client> {
        if let Some(ca_path) = &opts.ca_certs {
            self.http3_by_ca.get(ca_path).map(Arc::as_ref)
        } else {
            self.default_http3
        }
    }
}

async fn resolve_via_udp(
    query: &[u8],
    addr: &SocketAddr,
    mux: Option<&Arc<UdpMultiplexer>>,
    mark: Option<u32>,
    timeout_dur: Duration,
) -> Option<Vec<u8>> {
    if let Some(mux) = mux {
        mux.send_query(addr, query, timeout_dur).await
    } else {
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = socket2::Socket::new(
            if addr.is_ipv6() {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ).ok()?;
        #[cfg(unix)]
        if let Some(m) = mark {
            let _ = sock.set_mark(m);
        }
        sock.bind(&bind_addr.parse::<SocketAddr>().unwrap().into()).ok()?;
        sock.set_nonblocking(true).ok()?;
        let socket = UdpSocket::from_std(sock.into()).ok()?;
        socket.connect(addr).await.ok()?;
        socket.send(query).await.ok()?;
        let mut buf = [0u8; 4096];
        let len = timeout(timeout_dur, socket.recv(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf[..len].to_vec())
    }
}

fn is_truncated_response(resp: &[u8]) -> bool {
    crate::dns::DnsView::parse(resp)
        .map(|msg| msg.is_truncated())
        .unwrap_or(false)
}

#[cfg(feature = "rustls-stack")]
async fn resolve_via_doh_client(
    agent: &reqwest::Client,
    url: &str,
    query: &[u8],
) -> Option<Vec<u8>> {
    let mut res = agent
        .post(url)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(query.to_vec())
        .send()
        .await
        .ok()?;

    if !res.status().is_success() {
        return None;
    }

    if let Some(ct) = res.headers().get("content-type")
        && !ct.to_str().unwrap_or("").starts_with("application/dns-message") {
            return None;
    }

    if let Some(cl) = res.content_length()
        && cl > crate::http_client::MAX_DOH_RESPONSE_SIZE {
            return None;
    }

    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.ok()? {
        if body.len() + chunk.len() > crate::http_client::MAX_DOH_RESPONSE_SIZE as usize {
            return None;
        }
        body.extend_from_slice(&chunk);
    }

    if body.len() < 12 {
        return None;
    }

    Some(body)
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
async fn resolve_via_doh_client(
    agent: &crate::http_client::HttpClient,
    url: &str,
    query: &[u8],
) -> Option<Vec<u8>> {
    use bytes::Bytes;
    match agent.post_dns_wire(url, Bytes::copy_from_slice(query)).await {
        Ok(bytes) => Some(bytes.to_vec()),
        Err(e) => {
            tracing::warn!("DoH query failed: {}", e);
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn resolve_upstream_internal(
    query: &[u8],
    protocol: &UpstreamProtocol,
    is_udp: bool,
    clients: UpstreamClients<'_>,
    fallback_upstreams: &[UpstreamProtocol],
    fallback_dns_all: bool,
    cache: &Arc<crate::cache::DnsCache>,
    mux: Option<Arc<UdpMultiplexer>>,
    pool: Arc<ConnectionPool>,
    _req_id: RequestId,
    global_mark: Option<u32>,
) -> Option<Vec<u8>> {
    let opts = protocol.options();
    let upstream_mark = opts.mark.or(global_mark);
    
    // Warn if a custom mark is configured on a DoH/DoH3 upstream
    match protocol {
        UpstreamProtocol::Doh { .. } | UpstreamProtocol::DohH3 { .. } if opts.mark.is_some() => {
            tracing::warn!("Warning: per-upstream socket mark is not supported for DoH/DoH3 upstreams due to Client library limitations.");
        }
        UpstreamProtocol::Doh { .. } | UpstreamProtocol::DohH3 { .. } => {}
        _ => {}
    }

    match protocol {
        UpstreamProtocol::Udp(addr, _opts) => {
            let actual_mux = if opts.mark.is_some() { None } else { mux.as_ref() };
            let timeout_dur = Duration::from_millis(pool.opt.timeout_ms as u64);
            resolve_via_udp(query, addr, actual_mux, upstream_mark, timeout_dur).await
        }
        UpstreamProtocol::Tcp(addr, _opts) => resolve_via_tcp(query, addr, upstream_mark, pool.clone()).await,
        UpstreamProtocol::Dot {
            addr,
            hostname,
            port,
            tls,
        } => {
            let addr = if let Some(a) = addr {
                Some(*a)
            } else {
                resolve_hostname(
                    hostname,
                    *port,
                    fallback_upstreams,
                    fallback_dns_all,
                    cache,
                    mux.clone(),
                    pool.clone(),
                )
                .await
            };

            if let Some(addr) = addr {
                let tls_config = clients.tls_config(tls)?;
                resolve_via_dot(
                    query,
                    &addr,
                    hostname,
                    tls.ca_certs.as_deref(),
                    tls_config,
                    upstream_mark,
                    pool.clone(),
                )
                .await
            } else {
                None
            }
        }
        UpstreamProtocol::Doh { url, tls } => {
            resolve_via_doh_client(clients.http_client(tls)?, url, query).await
        }
        #[cfg(feature = "quiche")]
        UpstreamProtocol::DohH3 { url, tls: _ } => {
            let parsed_url = match url::Url::parse(url) {
                Ok(u) => u,
                Err(e) => {
                    tracing::error!("Failed to parse upstream DoH3 URL '{}': {}", url, e);
                    return None;
                }
            };
            let host = match parsed_url.host_str() {
                Some(h) => h,
                None => return None,
            };
            let port = parsed_url.port().unwrap_or(443);
            
            let peer_addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                std::net::SocketAddr::new(ip, port)
            } else {
                resolve_hostname(
                    host,
                    port,
                    fallback_upstreams,
                    fallback_dns_all,
                    cache,
                    mux.clone(),
                    pool.clone(),
                ).await?
            };
            
            let bind_addr = if peer_addr.is_ipv6() {
                std::net::SocketAddr::from(([0; 16], 0))
            } else {
                std::net::SocketAddr::from(([0; 4], 0))
            };
            
            let tx = match pool.quiche_pool.get_or_create(peer_addr, bind_addr, Some(host), upstream_mark).await {
                Ok(sender) => sender,
                Err(e) => {
                    tracing::error!("Failed to get or create client for upstream DoH3 {}: {}", peer_addr, e);
                    return None;
                }
            };
            
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            let path_and_query = if let Some(q) = parsed_url.query() {
                format!("{}?{}", parsed_url.path(), q)
            } else {
                parsed_url.path().to_string()
            };
            let req = crate::quiche_client::QuicheRequest {
                host: host.to_string(),
                path: path_and_query,
                body: bytes::Bytes::copy_from_slice(query),
                timeout: Duration::from_millis(pool.opt.timeout_ms as u64),
                resp_tx,
                created_at: std::time::Instant::now(),
            };
            
            if tx.send(req).await.is_err() {
                tracing::error!("Failed to send query to DoH3 upstream worker for {}", peer_addr);
                return None;
            }
            
            match resp_rx.await {
                Ok(Ok(body)) => Some(body),
                Ok(Err(e)) => {
                    tracing::debug!("DoH3 resolution error from upstream {}: {}", peer_addr, e);
                    None
                }
                Err(_) => {
                    tracing::debug!("DoH3 worker dropped oneshot sender for {}", peer_addr);
                    None
                }
            }
        }
        #[cfg(not(feature = "quiche"))]
        UpstreamProtocol::DohH3 { url, tls } => {
            #[cfg(all(feature = "rustls-stack", feature = "upstream-h3"))]
            {
                if let Some(agent_h3) = clients.http3_client(tls)
                    && let Some(resp) = resolve_via_doh_client(agent_h3, url, query).await
                {
                    return Some(resp);
                }
            }
            #[cfg(not(all(feature = "rustls-stack", feature = "upstream-h3")))]
            {
                let _ = url;
                let _ = tls;
            }
            resolve_via_doh_client(clients.http_client(tls)?, url, query).await
        }
        UpstreamProtocol::Doq {
            addr,
            hostname,
            port,
            tls,
        } => {
            let addr = if let Some(a) = addr {
                Some(*a)
            } else {
                resolve_hostname(
                    hostname,
                    *port,
                    fallback_upstreams,
                    fallback_dns_all,
                    cache,
                    mux.clone(),
                    pool.clone(),
                )
                .await
            };

            if let Some(addr) = addr {
                resolve_via_doq(query, &addr, hostname, *port, tls, upstream_mark, pool.clone()).await
            } else {
                None
            }
        }
        UpstreamProtocol::UdpAndTcp(addr, _opts) => {
            if is_udp {
                let actual_mux = if opts.mark.is_some() { None } else { mux.as_ref() };
                let timeout_dur = Duration::from_millis(pool.opt.timeout_ms as u64);
                let udp_resp =
                    resolve_via_udp(query, addr, actual_mux, upstream_mark, timeout_dur).await;
                if let Some(resp) = udp_resp {
                    if is_truncated_response(&resp) {
                        tracing::debug!(
                            "UDP response from {} was truncated; retrying over TCP",
                            addr
                        );
                        resolve_via_tcp(query, addr, upstream_mark, pool.clone()).await
                    } else {
                        Some(resp)
                    }
                } else {
                    None
                }
            } else {
                resolve_via_tcp(query, addr, upstream_mark, pool.clone()).await
            }
        }
    }
}

async fn resolve_hostname(
    hostname: &str,
    port: u16,
    fallback_upstreams: &[UpstreamProtocol],
    fallback_dns_all: bool,
    cache: &crate::cache::DnsCache,
    mux: Option<Arc<UdpMultiplexer>>,
    pool: Arc<ConnectionPool>,
) -> Option<SocketAddr> {
    let mut cache_key_a = compact_str::CompactString::default();
    let mut cache_key_aaaa = compact_str::CompactString::default();
    use std::fmt::Write;
    let _ = write!(cache_key_a, "{}:1", hostname);
    let _ = write!(cache_key_aaaa, "{}:28", hostname);

    // 1. Try Cache hit for A
    if let crate::cache::CacheStatus::Hit { data, .. } = cache.get(&cache_key_a)
        && let Some(msg) = crate::dns::DnsView::parse(&data)
    {
        let mut found_ip = None;
        msg.for_each_ip(|ip| {
            found_ip = Some(ip);
            true
        });
        if let Some(ip) = found_ip {
            return Some(SocketAddr::new(ip, port));
        }
    }

    // 2. Try Cache hit for AAAA
    if let crate::cache::CacheStatus::Hit { data, .. } = cache.get(&cache_key_aaaa)
        && let Some(msg) = crate::dns::DnsView::parse(&data)
    {
        let mut found_ip = None;
        msg.for_each_ip(|ip| {
            found_ip = Some(ip);
            true
        });
        if let Some(ip) = found_ip {
            return Some(SocketAddr::new(ip, port));
        }
    }

    if fallback_upstreams.is_empty() {
        return None;
    }

    let mut chosen_targets: Vec<&UpstreamProtocol> = fallback_upstreams.iter().collect();
    if !fallback_dns_all && chosen_targets.len() > 1 {
        use rand::seq::SliceRandom;
        chosen_targets.shuffle(&mut rand::rng());
    }

    // Resolve A first, then fallback to AAAA
    for qtype in &[1, 28] {
        let query = crate::dns::build_query(hostname, *qtype);
        let timeout_dur = Duration::from_millis(pool.opt.timeout_ms as u64).max(DEFAULT_BOOTSTRAP_RESOLVE_TIMEOUT);

        for &upstream in &chosen_targets {
            let response = match upstream {
                UpstreamProtocol::Udp(addr, opts) => {
                    let actual_mux = if opts.mark.is_some() { None } else { mux.as_ref() };
                    resolve_via_udp(&query, addr, actual_mux, opts.mark, timeout_dur).await
                }
                UpstreamProtocol::Tcp(addr, opts) => {
                    match timeout(timeout_dur, resolve_via_tcp(&query, addr, opts.mark, pool.clone())).await {
                        Ok(Some(resp)) => Some(resp),
                        _ => None,
                    }
                }
                UpstreamProtocol::UdpAndTcp(addr, opts) => {
                    let actual_mux = if opts.mark.is_some() { None } else { mux.as_ref() };
                    if let Some(resp) =
                        resolve_via_udp(&query, addr, actual_mux, opts.mark, timeout_dur).await
                    {
                        if is_truncated_response(&resp) {
                            match timeout(timeout_dur, resolve_via_tcp(&query, addr, opts.mark, pool.clone()))
                                .await
                            {
                                Ok(Some(resp)) => Some(resp),
                                _ => None,
                            }
                        } else {
                            Some(resp)
                        }
                    } else {
                        match timeout(timeout_dur, resolve_via_tcp(&query, addr, opts.mark, pool.clone()))
                            .await
                        {
                            Ok(Some(resp)) => Some(resp),
                            _ => None,
                        }
                    }
                }
                _ => None,
            };

            if let Some(resp_data) = response
                && let Some(msg) = crate::dns::DnsView::parse(&resp_data)
                && msg.is_good()
            {
                let mut found_ip = None;
                msg.for_each_ip(|ip| {
                    found_ip = Some(ip);
                    true
                });

                if let Some(ip) = found_ip {
                    let ttl = msg.get_min_ttl().max(60);
                    let cache_key = if *qtype == 1 {
                        &cache_key_a
                    } else {
                        &cache_key_aaaa
                    };
                    cache.insert(cache_key, Arc::from(resp_data.as_slice()), ttl);
                    return Some(SocketAddr::new(ip, port));
                }
            }
        }
    }

    None
}

const MUX_SHARD_COUNT: usize = 32;
const MUX_SHARD_MASK: u16 = (MUX_SHARD_COUNT - 1) as u16;

type ShardMap = rustc_hash::FxHashMap<(SocketAddr, u16), tokio::sync::oneshot::Sender<Vec<u8>>>;
type ShardRef = Arc<std::sync::Mutex<ShardMap>>;

fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                addr
            }
        }
        SocketAddr::V4(_) => addr,
    }
}

fn map_to_ipv6(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            SocketAddr::new(std::net::IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port())
        }
        SocketAddr::V6(_) => addr,
    }
}

/// A high-performance UDP multiplexer that reuses a single socket for all upstream queries.
/// The pending queries map is sharded into 32 independent buckets to reduce lock contention.
pub struct UdpMultiplexer {
    socket: Arc<UdpSocket>,
    shards: Vec<ShardRef>,
    next_id: std::sync::atomic::AtomicU16,
    cancel_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for UdpMultiplexer {
    fn drop(&mut self) {
        if let Some(tx) = self.cancel_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl UdpMultiplexer {
    pub async fn new(is_ipv6: bool, socket_buffer_size: usize, mark: Option<u32>) -> anyhow::Result<Self> {
        let bind_addr: SocketAddr = if is_ipv6 {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let sock = socket2::Socket::new(
            if is_ipv6 {
                socket2::Domain::IPV6
            } else {
                socket2::Domain::IPV4
            },
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        #[cfg(unix)]
        if let Some(m) = mark {
            let _ = sock.set_mark(m);
        }
        if socket_buffer_size > 0 {
            let _ = sock.set_recv_buffer_size(socket_buffer_size);
            let _ = sock.set_send_buffer_size(socket_buffer_size);
        }
        sock.bind(&bind_addr.into())?;
        sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(sock.into())?;
        let socket = Arc::new(socket);

        let shards: Vec<ShardRef> = (0..MUX_SHARD_COUNT)
            .map(|_| Arc::new(std::sync::Mutex::new(rustc_hash::FxHashMap::default())))
            .collect();

        let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();

        // Background receiver task
        let socket_clone = socket.clone();
        let shards_clone = shards.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    res = socket_clone.recv_from(&mut buf) => {
                        match res {
                            Ok((len, addr)) => {
                                if len >= 2 {
                                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                                    let shard_idx = (id & MUX_SHARD_MASK) as usize;
                                    let normalized_addr = normalize_addr(addr);
                                    let sender = {
                                        let mut shard = shards_clone[shard_idx].lock().unwrap();
                                        shard.remove(&(normalized_addr, id))
                                    };
                                    if let Some(s) = sender {
                                        let _ = s.send(buf[..len].to_vec());
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("UdpMultiplexer recv_from error: {}", e);
                                tokio::time::sleep(UDP_MUX_ERROR_BACKOFF).await;
                            }
                        }
                    }
                    _ = &mut cancel_rx => {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            socket,
            shards,
            next_id: std::sync::atomic::AtomicU16::new(rand::random()),
            cancel_tx: Some(cancel_tx),
        })
    }

    pub async fn send_query(
        &self,
        addr: &SocketAddr,
        query: &[u8],
        timeout_dur: Duration,
    ) -> Option<Vec<u8>> {
        if query.len() < 2 {
            return None;
        }

        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut tx = Some(tx);
        let mut selected = None;

        let normalized_addr = normalize_addr(*addr);

        for _ in 0..(usize::from(u16::MAX) + 1) {
            let internal_id = self
                .next_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let key = (normalized_addr, internal_id);
            let shard_idx = (internal_id & MUX_SHARD_MASK) as usize;
            let shard = self.shards[shard_idx].clone();

            let mut s = shard.lock().unwrap();
            if let std::collections::hash_map::Entry::Vacant(entry) = s.entry(key) {
                entry.insert(tx.take().unwrap());
                selected = Some((internal_id, key, shard.clone()));
                break;
            }
        }

        let (internal_id, key, shard) = selected?;
        let mut stack_buf = [0u8; 4096];
        let mut heap_buf;
        let upstream_query: &[u8] = if query.len() <= stack_buf.len() {
            stack_buf[..query.len()].copy_from_slice(query);
            stack_buf[0] = (internal_id >> 8) as u8;
            stack_buf[1] = (internal_id & 0xFF) as u8;
            &stack_buf[..query.len()]
        } else {
            heap_buf = query.to_vec();
            heap_buf[0] = (internal_id >> 8) as u8;
            heap_buf[1] = (internal_id & 0xFF) as u8;
            &heap_buf
        };

        struct PendingGuard {
            shard: ShardRef,
            key: (SocketAddr, u16),
            active: bool,
        }

        impl PendingGuard {
            #[inline]
            fn disarm(&mut self) {
                self.active = false;
            }
        }

        impl Drop for PendingGuard {
            fn drop(&mut self) {
                if self.active && let Ok(mut s) = self.shard.lock() {
                    s.remove(&self.key);
                }
            }
        }

        let mut _guard = PendingGuard {
            shard: shard.clone(),
            key,
            active: true,
        };

        let is_ipv6_sock = self.socket.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
        let send_addr = if is_ipv6_sock {
            map_to_ipv6(*addr)
        } else {
            *addr
        };

        if self.socket.send_to(upstream_query, send_addr).await.is_err() {
            return None;
        }

        match timeout(timeout_dur, rx).await {
            Ok(Ok(resp)) => {
                _guard.disarm();
                Some(resp)
            }
            _ => None,
        }
    }
}

pub trait CheckDead {
    fn is_dead(&self) -> bool;
}

impl CheckDead for TcpStream {
    fn is_dead(&self) -> bool {
        let mut buf = [0u8; 1];
        match self.try_read(&mut buf) {
            Ok(0) => true,
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    }
}

#[cfg(feature = "rustls-stack")]
impl CheckDead for tokio_rustls::client::TlsStream<TcpStream> {
    fn is_dead(&self) -> bool {
        let stream = self.get_ref().0;
        let mut buf = [0u8; 1];
        match stream.try_read(&mut buf) {
            Ok(0) => true,
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl CheckDead for tokio_boring::SslStream<TcpStream> {
    fn is_dead(&self) -> bool {
        let stream = self.get_ref();
        let mut buf = [0u8; 1];
        match stream.try_read(&mut buf) {
            Ok(0) => true,
            Ok(_) => true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(_) => true,
        }
    }
}

pub struct PoolSlot<T> {
    pub conn: Arc<tokio::sync::Mutex<Option<T>>>,
    pub last_used: std::time::Instant,
}
type PoolSlots<T> = Arc<std::sync::Mutex<Vec<PoolSlot<T>>>>;
type PoolLease<T> = (
    tokio::sync::OwnedSemaphorePermit,
    tokio::sync::OwnedMutexGuard<Option<T>>,
);

pub struct SingleUpstreamPool<T> {
    pub semaphore: Arc<tokio::sync::Semaphore>,
    pub conns: PoolSlots<T>,
}

impl<T: CheckDead + Send + Sync + 'static> SingleUpstreamPool<T> {
    pub fn new(max_conns: usize) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_conns)),
            conns: Arc::new(std::sync::Mutex::new(Vec::with_capacity(max_conns))),
        }
    }

    fn clear_if_dead(conn: &mut Option<T>) {
        if conn.as_ref().is_some_and(CheckDead::is_dead) {
            *conn = None;
        }
    }

    fn try_lease(&self) -> Option<PoolLease<T>> {
        let permit = self.semaphore.clone().try_acquire_owned().ok()?;

        let conn = {
            let mut conns = self.conns.lock().unwrap();
            let mut empty_slot = None;
            let mut i = 0;
            while i < conns.len() {
                if let Ok(mut guard) = conns[i].conn.clone().try_lock_owned() {
                    Self::clear_if_dead(&mut guard);
                    if guard.is_some() {
                        conns[i].last_used = std::time::Instant::now();
                        return Some((permit, guard));
                    } else if empty_slot.is_none() {
                        empty_slot = Some((i, guard));
                    }
                }
                i += 1;
            }
            if let Some((idx, guard)) = empty_slot {
                conns[idx].last_used = std::time::Instant::now();
                guard
            } else {
                let conn = Arc::new(tokio::sync::Mutex::new(None));
                conns.push(PoolSlot {
                    conn: conn.clone(),
                    last_used: std::time::Instant::now(),
                });
                conn.try_lock_owned().unwrap()
            }
        };

        Some((permit, conn))
    }
}

/// A lightweight TCP/TLS connection pool.
pub struct ConnectionPool {
    max_conns: usize,
    tcp_conns:
        std::sync::Mutex<rustc_hash::FxHashMap<SocketAddr, Arc<SingleUpstreamPool<TcpStream>>>>,
    dot_conns: std::sync::Mutex<
        rustc_hash::FxHashMap<
            String,
            Arc<SingleUpstreamPool<UpstreamTlsStream>>,
        >,
    >,
    #[cfg(feature = "quiche")]
    pub quiche_pool: Arc<crate::quiche_client::QuichePool>,
    #[cfg(feature = "quiche")]
    pub quiche_doq_pool: Arc<crate::quiche_client::QuicheDoqPool>,
    #[cfg(feature = "original-h3-server")]
    pub quinn_doq_pool: Arc<QuinnDoqPool>,
    pub opt: Arc<crate::opt::Opt>,
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new(16, Arc::new(crate::opt::Opt::default()))
    }
}

impl ConnectionPool {
    pub fn new(max_conns: usize, opt: Arc<crate::opt::Opt>) -> Self {
        #[cfg(feature = "quiche")]
        let quiche_pool = {
            let mut quiche_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
            crate::quiche_server::configure_quiche_limits(&mut quiche_config, &limits, &opt).unwrap();
            quiche_config.verify_peer(opt.cert_verify);
            Arc::new(crate::quiche_client::QuichePool::new(quiche_config, opt.clone()))
        };

        #[cfg(feature = "quiche")]
        let quiche_doq_pool = {
            let mut quiche_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
            let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
            crate::quiche_server::configure_quiche_limits(&mut quiche_config, &limits, &opt).unwrap();
            quiche_config.verify_peer(opt.cert_verify);
            quiche_config.set_application_protos(&[b"doq"]).unwrap();
            Arc::new(crate::quiche_client::QuicheDoqPool::new(quiche_config, opt.clone()))
        };

        #[cfg(feature = "original-h3-server")]
        let quinn_doq_pool = Arc::new(QuinnDoqPool::new(opt.clone()));

        Self {
            max_conns,
            tcp_conns: std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
            dot_conns: std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
            #[cfg(feature = "quiche")]
            quiche_pool,
            #[cfg(feature = "quiche")]
            quiche_doq_pool,
            #[cfg(feature = "original-h3-server")]
            quinn_doq_pool,
            opt,
        }
    }

    pub async fn lease_tcp(&self, addr: &SocketAddr) -> Option<PoolLease<TcpStream>> {
        let pool = {
            let mut pools = self.tcp_conns.lock().unwrap();
            pools
                .entry(*addr)
                .or_insert_with(|| Arc::new(SingleUpstreamPool::new(self.max_conns)))
                .clone()
        };

        pool.try_lease()
    }

    pub async fn lease_dot(
        &self,
        hostname: &str,
        port: u16,
        ca_path: Option<&str>,
    ) -> Option<PoolLease<UpstreamTlsStream>> {
        let key = if let Some(ca_path) = ca_path {
            format!("{}:{}|ca={}", hostname, port, ca_path)
        } else {
            format!("{}:{}", hostname, port)
        };
        let pool = {
            let mut pools = self.dot_conns.lock().unwrap();
            pools
                .entry(key)
                .or_insert_with(|| Arc::new(SingleUpstreamPool::new(self.max_conns)))
                .clone()
        };

        pool.try_lease()
    }

    pub fn prune_idle(&self) {
        let idle_timeout = Duration::from_millis(self.opt.tcp_idle_timeout_ms as u64);
        let mut tcp_map = self.tcp_conns.lock().unwrap();
        tcp_map.retain(|_, pool| {
            let available = pool.semaphore.available_permits();
            let mut conns_guard = pool.conns.lock().unwrap();
            conns_guard.retain(|slot| {
                if let Ok(mut g) = slot.conn.try_lock() {
                    SingleUpstreamPool::clear_if_dead(&mut g);
                    if g.is_some() {
                        if slot.last_used.elapsed() >= idle_timeout {
                            *g = None;
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    true
                }
            });
            let is_idle = available == self.max_conns && conns_guard.is_empty();
            let is_in_use = std::sync::Arc::strong_count(pool) > 1;
            !(is_idle && !is_in_use)
        });

        let mut dot_map = self.dot_conns.lock().unwrap();
        dot_map.retain(|_, pool| {
            let available = pool.semaphore.available_permits();
            let mut conns_guard = pool.conns.lock().unwrap();
            conns_guard.retain(|slot| {
                if let Ok(mut g) = slot.conn.try_lock() {
                    SingleUpstreamPool::clear_if_dead(&mut g);
                    if g.is_some() {
                        if slot.last_used.elapsed() >= idle_timeout {
                            *g = None;
                            false
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    true
                }
            });
            let is_idle = available == self.max_conns && conns_guard.is_empty();
            let is_in_use = std::sync::Arc::strong_count(pool) > 1;
            !(is_idle && !is_in_use)
        });

        #[cfg(feature = "original-h3-server")]
        self.quinn_doq_pool.prune_idle();
    }
}

struct TcpConnGuard<'a> {
    conn: &'a mut Option<TcpStream>,
    success: bool,
}

impl<'a> Drop for TcpConnGuard<'a> {
    fn drop(&mut self) {
        if !self.success {
            *self.conn = None;
        }
    }
}

async fn resolve_via_tcp(
    query: &[u8],
    addr: &SocketAddr,
    mark: Option<u32>,
    pool: Arc<ConnectionPool>,
) -> Option<Vec<u8>> {
    let lease = pool.lease_tcp(addr).await;
    if lease.is_none() {
        tracing::debug!("TCP upstream connection limit reached for {}", addr);
        return None;
    }
    let (_permit, mut conn_guard) = lease.unwrap();

    // Attempt to reuse or establish connection
    for _attempt in 0..2 {
        if conn_guard.is_none() {
            let socket_fut = async {
                let sock = socket2::Socket::new(
                    if addr.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    },
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                #[cfg(unix)]
                if let Some(m) = mark {
                    let _ = sock.set_mark(m);
                }
                sock.set_nonblocking(true)?;
                match sock.connect(&(*addr).into()) {
                    Ok(_) => {},
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::EINPROGRESS)
                        || (cfg!(windows) && e.raw_os_error() == Some(10035)) => {},
                    Err(e) => return Err(e),
                }
                let std_stream = std::net::TcpStream::from(sock);
                let stream = TcpStream::from_std(std_stream)?;
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(e);
                }
                Ok::<_, std::io::Error>(stream)
            };
            if let Ok(stream) = socket_fut.await {
                let _ = stream.set_nodelay(true);
                let sock_ref = socket2::SockRef::from(&stream);
                let ka = socket2::TcpKeepalive::new()
                    .with_time(UPSTREAM_TCP_KEEPALIVE_TIME)
                    .with_interval(UPSTREAM_TCP_KEEPALIVE_INTERVAL);
                let _ = sock_ref.set_tcp_keepalive(&ka);
                *conn_guard = Some(stream);
            } else {
                return None;
            }
        }

        let mut guard = TcpConnGuard {
            conn: &mut conn_guard,
            success: false,
        };

        let stream = guard.conn.as_mut().unwrap();
        let frame_len = 2 + query.len();
        if frame_len <= 4098 {
            let mut frame_buf = [0u8; 4098];
            frame_buf[0..2].copy_from_slice(&(query.len() as u16).to_be_bytes());
            frame_buf[2..frame_len].copy_from_slice(query);
            if stream.write_all(&frame_buf[..frame_len]).await.is_err() {
                continue;
            }
        } else {
            let mut frame_buf = Vec::with_capacity(frame_len);
            frame_buf.extend_from_slice(&(query.len() as u16).to_be_bytes());
            frame_buf.extend_from_slice(query);
            if stream.write_all(&frame_buf).await.is_err() {
                continue;
            }
        }

        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            continue;
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        if stream.read_exact(&mut resp_buf).await.is_err() {
            continue;
        }

        guard.success = true;
        return Some(resp_buf);
    }
    None
}

struct DotConnGuard<'a> {
    conn: &'a mut Option<UpstreamTlsStream>,
    success: bool,
}

impl<'a> Drop for DotConnGuard<'a> {
    fn drop(&mut self) {
        if !self.success {
            *self.conn = None;
        }
    }
}

async fn resolve_via_dot(
    query: &[u8],
    addr: &SocketAddr,
    hostname: &str,
    ca_path: Option<&str>,
    tls: Arc<TlsConfig>,
    mark: Option<u32>,
    pool: Arc<ConnectionPool>,
) -> Option<Vec<u8>> {
    let lease = pool.lease_dot(hostname, addr.port(), ca_path).await;
    if lease.is_none() {
        tracing::debug!(
            "DoT upstream connection limit reached for {}:{}",
            hostname,
            addr.port()
        );
        return None;
    }
    let (_permit, mut conn_guard) = lease.unwrap();

    for _attempt in 0..2 {
        if conn_guard.is_none() {
            let socket_fut = async {
                let sock = socket2::Socket::new(
                    if addr.is_ipv4() {
                        socket2::Domain::IPV4
                    } else {
                        socket2::Domain::IPV6
                    },
                    socket2::Type::STREAM,
                    Some(socket2::Protocol::TCP),
                )?;
                #[cfg(unix)]
                if let Some(m) = mark {
                    let _ = sock.set_mark(m);
                }
                sock.set_nonblocking(true)?;
                match sock.connect(&(*addr).into()) {
                    Ok(_) => {},
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::EINPROGRESS)
                        || (cfg!(windows) && e.raw_os_error() == Some(10035)) => {},
                    Err(e) => return Err(e),
                }
                let std_stream = std::net::TcpStream::from(sock);
                let stream = TcpStream::from_std(std_stream)?;
                stream.writable().await?;
                if let Some(e) = stream.take_error()? {
                    return Err(e);
                }
                let _ = stream.set_nodelay(true);
                Ok::<_, std::io::Error>(stream)
            };
            if let Ok(stream) = socket_fut.await {
                let sock_ref = socket2::SockRef::from(&stream);
                let ka = socket2::TcpKeepalive::new()
                    .with_time(UPSTREAM_TCP_KEEPALIVE_TIME)
                    .with_interval(UPSTREAM_TCP_KEEPALIVE_INTERVAL);
                let _ = sock_ref.set_tcp_keepalive(&ka);

                #[cfg(feature = "rustls-stack")]
                {
                    let connector = TlsConnector::from(tls.client_config.clone());
                    let clean_host = hostname.trim_end_matches('.');
                    let dns_name = match ServerName::try_from(clean_host) {
                        Ok(name) => name.to_owned(),
                        Err(e) => {
                            tracing::error!(
                                "Failed to parse hostname '{}' for TLS ServerName: {}",
                                hostname,
                                e
                            );
                            return None;
                        }
                    };
                    if let Ok(tls_stream) = connector.connect(dns_name, stream).await {
                        *conn_guard = Some(tls_stream);
                    } else {
                        return None;
                    }
                }
                #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
                {
                    let mut ssl_config = match tls.connector.configure() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::error!("Failed to configure SslConnector: {}", e);
                            return None;
                        }
                    };
                    
                    let clean_host = hostname.trim_matches('[').trim_matches(']');
                    let tls_stream_res = if let Ok(ip) = clean_host.parse::<std::net::IpAddr>() {
                        if let Err(e) = ssl_config.param_mut().set_ip(ip) {
                            tracing::error!("Failed to set IP parameter: {}", e);
                            return None;
                        }
                        ssl_config.set_use_server_name_indication(false);
                        tokio_boring::connect(ssl_config, "", stream).await
                    } else {
                        let domain_host = hostname.trim_end_matches('.');
                        let ascii_host = idna::domain_to_ascii(domain_host).unwrap_or_else(|_| domain_host.to_string());
                        if let Err(e) = ssl_config.set_hostname(&ascii_host) {
                            tracing::error!("Failed to set SNI hostname: {}", e);
                            return None;
                        }
                        tokio_boring::connect(ssl_config, &ascii_host, stream).await
                    };

                    match tls_stream_res {
                        Ok(tls_stream) => {
                            *conn_guard = Some(tls_stream);
                        }
                        Err(e) => {
                            tracing::error!("BoringSSL handshake failed: {}", e);
                            return None;
                        }
                    }
                }
            } else {
                return None;
            }
        }

        let mut guard = DotConnGuard {
            conn: &mut conn_guard,
            success: false,
        };

        let stream = guard.conn.as_mut().unwrap();
        let frame_len = 2 + query.len();
        if frame_len <= 4098 {
            let mut frame_buf = [0u8; 4098];
            frame_buf[0..2].copy_from_slice(&(query.len() as u16).to_be_bytes());
            frame_buf[2..frame_len].copy_from_slice(query);
            if stream.write_all(&frame_buf[..frame_len]).await.is_err() {
                continue;
            }
        } else {
            let mut frame_buf = Vec::with_capacity(frame_len);
            frame_buf.extend_from_slice(&(query.len() as u16).to_be_bytes());
            frame_buf.extend_from_slice(query);
            if stream.write_all(&frame_buf).await.is_err() {
                continue;
            }
        }

        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            continue;
        }

        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        if stream.read_exact(&mut resp_buf).await.is_err() {
            continue;
        }

        guard.success = true;
        return Some(resp_buf);
    }
    None
}

async fn resolve_via_doq(
    query: &[u8],
    addr: &SocketAddr,
    hostname: &str,
    port: u16,
    tls: &TlsOptions,
    upstream_mark: Option<u32>,
    pool: Arc<ConnectionPool>,
) -> Option<Vec<u8>> {
    #[cfg(feature = "quiche")]
    {
        let _ = (port, tls);
        let bind_addr = if addr.is_ipv6() {
            SocketAddr::from(([0; 16], 0))
        } else {
            SocketAddr::from(([0; 4], 0))
        };
        let tx = match pool.quiche_doq_pool.get_or_create(*addr, bind_addr, Some(hostname), upstream_mark).await {
            Ok(sender) => sender,
            Err(e) => {
                tracing::error!("Failed to get or create client for upstream DoQ {}: {}", addr, e);
                return None;
            }
        };

        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
        let req = crate::quiche_client::QuicheDoqRequest {
            body: bytes::Bytes::copy_from_slice(query),
            timeout: Duration::from_millis(pool.opt.timeout_ms as u64),
            resp_tx,
            created_at: std::time::Instant::now(),
        };

        if tx.send(req).await.is_err() {
            tracing::error!("Failed to send query to DoQ upstream worker for {}", addr);
            return None;
        }

        match resp_rx.await {
            Ok(Ok(body)) => Some(body),
            Ok(Err(e)) => {
                tracing::debug!("DoQ resolution error from upstream {}: {}", addr, e);
                None
            }
            Err(_) => {
                tracing::debug!("DoQ worker dropped oneshot sender for {}", addr);
                None
            }
        }
    }

    #[cfg(all(not(feature = "quiche"), feature = "original-h3-server"))]
    {
        let _ = (port, upstream_mark);
        pool.quinn_doq_pool.resolve(*addr, hostname, tls, query).await
    }

    #[cfg(all(not(feature = "quiche"), not(feature = "original-h3-server")))]
    {
        let _ = (query, addr, hostname, port, tls, upstream_mark, pool);
        tracing::warn!("DoQ upstream is not supported in this build profile.");
        None
    }
}

#[cfg(feature = "original-h3-server")]
#[cfg(feature = "original-h3-server")]
pub struct QuinnDoqPool {
    opt: Arc<crate::opt::Opt>,
    endpoint_v4: tokio::sync::OnceCell<quinn::Endpoint>,
    endpoint_v6: tokio::sync::OnceCell<quinn::Endpoint>,
    connections: std::sync::Mutex<rustc_hash::FxHashMap<String, (quinn::Connection, std::time::Instant)>>,
}

#[cfg(feature = "original-h3-server")]
impl QuinnDoqPool {
    pub fn new(opt: Arc<crate::opt::Opt>) -> Self {
        Self {
            opt,
            endpoint_v4: tokio::sync::OnceCell::new(),
            endpoint_v6: tokio::sync::OnceCell::new(),
            connections: std::sync::Mutex::new(rustc_hash::FxHashMap::default()),
        }
    }

    pub fn prune_idle(&self) {
        let mut conns = self.connections.lock().unwrap();
        let quic_idle_timeout = Duration::from_millis(self.opt.quic_idle_timeout_ms as u64);
        conns.retain(|_key, (c, last_used)| {
            if c.close_reason().is_some() {
                false
            } else if last_used.elapsed() >= quic_idle_timeout {
                c.close(0u32.into(), b"idle timeout");
                false
            } else {
                true
            }
        });
    }

    async fn get_endpoint(&self, is_ipv6: bool) -> anyhow::Result<&quinn::Endpoint> {
        let cell = if is_ipv6 { &self.endpoint_v6 } else { &self.endpoint_v4 };
        cell.get_or_try_init(|| async {
            let mut crypto_config = if self.opt.cert_verify {
                let mut root_store = rustls::RootCertStore::empty();
                if let Some(ca_path) = self.opt.ca_certs.as_deref()
                    && let Ok(mut file) = std::fs::File::open(ca_path) {
                        let mut pem_data = Vec::new();
                        use std::io::Read;
                        if file.read_to_end(&mut pem_data).is_ok() {
                            let mut reader = &pem_data[..];
                            for cert in rustls_pemfile::certs(&mut reader).flatten() {
                                let _ = root_store.add(cert);
                            }
                        }
                }
                if root_store.is_empty() {
                    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                }
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            } else {
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoVerifier))
                    .with_no_client_auth()
            };
            crypto_config.alpn_protocols = vec![b"doq".to_vec()];

            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(quinn::IdleTimeout::try_from(Duration::from_millis(self.opt.quic_idle_timeout_ms as u64)).ok());

            let client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config).map_err(|e| anyhow::anyhow!("QuicClientConfig error: {}", e))?
            ));

            let bind_addr = if is_ipv6 {
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let mut endpoint = quinn::Endpoint::client(bind_addr)?;
            endpoint.set_default_client_config(client_config);
            Ok(endpoint)
        }).await
    }

    pub async fn resolve(&self, addr: SocketAddr, hostname: &str, tls: &TlsOptions, query: &[u8]) -> Option<Vec<u8>> {
        let endpoint = match self.get_endpoint(addr.is_ipv6()).await {
            Ok(ep) => ep,
            Err(e) => {
                tracing::error!("Failed to initialize Quinn DoQ endpoint: {}", e);
                return None;
            }
        };

        let key = if let Some(ca) = &tls.ca_certs {
            format!("{}:{}|ca={}", hostname, addr.port(), ca)
        } else {
            format!("{}:{}", hostname, addr.port())
        };

        let conn = {
            let mut conns = self.connections.lock().unwrap();
            if let Some((c, last_used)) = conns.get_mut(&key) {
                if c.close_reason().is_none() {
                    *last_used = std::time::Instant::now();
                    Some(c.clone())
                } else {
                    conns.remove(&key);
                    None
                }
            } else {
                None
            }
        };

        let conn = match conn {
            Some(c) => c,
            None => {
                let connecting = match endpoint.connect(addr, hostname) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!("Quinn DoQ connect error to {}: {}", addr, e);
                        return None;
                    }
                };
                let c = match tokio::time::timeout(Duration::from_millis(self.opt.timeout_ms as u64), connecting).await {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        tracing::error!("Quinn DoQ handshake failed for {}: {}", addr, e);
                        return None;
                    }
                    Err(_) => {
                        tracing::error!("Quinn DoQ handshake timed out for {}", addr);
                        return None;
                    }
                };
                let mut conns = self.connections.lock().unwrap();
                conns.insert(key.clone(), (c.clone(), std::time::Instant::now()));
                c
            }
        };

        let timeout_dur = Duration::from_millis(self.opt.timeout_ms as u64);
        let fut = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!("open_bi error: {}", e))?;
            let len_prefix = (query.len() as u16).to_be_bytes();
            send.write_all(&len_prefix).await.map_err(|e| anyhow::anyhow!("send len prefix error: {}", e))?;
            send.write_all(query).await.map_err(|e| anyhow::anyhow!("send payload error: {}", e))?;
            send.finish().map_err(|e| anyhow::anyhow!("send finish error: {}", e))?;

            let resp_buf = recv.read_to_end(65535).await.map_err(|e| anyhow::anyhow!("read payload error: {}", e))?;
            if resp_buf.len() < 14 {
                anyhow::bail!("DoQ response too short: {} bytes", resp_buf.len());
            }
            let msg_len = u16::from_be_bytes([resp_buf[0], resp_buf[1]]) as usize;
            let wire = if resp_buf.len() >= 2 + msg_len {
                resp_buf[2..2 + msg_len].to_vec()
            } else {
                resp_buf[2..].to_vec()
            };
            Ok::<Vec<u8>, anyhow::Error>(wire)
        };

        match tokio::time::timeout(timeout_dur, fut).await {
            Ok(Ok(res)) => Some(res),
            Ok(Err(e)) => {
                tracing::debug!("Quinn DoQ query error to {}: {}", addr, e);
                let mut conns = self.connections.lock().unwrap();
                conns.remove(&key);
                None
            }
            Err(_) => {
                tracing::debug!("Quinn DoQ query timed out to {}", addr);
                let mut conns = self.connections.lock().unwrap();
                conns.remove(&key);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_dot_parse_ipv6_and_ports() {
        assert_eq!(
            UpstreamProtocol::parse("tls://[2606:4700:4700::1111]:8853"),
            Some(UpstreamProtocol::Dot {
                addr: Some("[2606:4700:4700::1111]:8853".parse().unwrap()),
                hostname: "2606:4700:4700::1111".to_string(),
                port: 8853,
                tls: TlsOptions::default(),
            })
        );

        assert_eq!(
            UpstreamProtocol::parse("tls://2606:4700:4700::1111"),
            Some(UpstreamProtocol::Dot {
                addr: Some("[2606:4700:4700::1111]:853".parse().unwrap()),
                hostname: "2606:4700:4700::1111".to_string(),
                port: 853,
                tls: TlsOptions::default(),
            })
        );

        assert_eq!(
            UpstreamProtocol::parse("tls://dns.google:8853"),
            Some(UpstreamProtocol::Dot {
                addr: None,
                hostname: "dns.google".to_string(),
                port: 8853,
                tls: TlsOptions::default(),
            })
        );
    }

    #[test]
    fn test_encrypted_upstream_parse_inline_ca() {
        let tls = TlsOptions {
            ca_certs: Some("/etc/polardns/dns1-ca.pem".to_string()),
            mark: None,
        };

        assert_eq!(
            UpstreamProtocol::parse("tls://dns1.example.com:853|ca=/etc/polardns/dns1-ca.pem"),
            Some(UpstreamProtocol::Dot {
                addr: None,
                hostname: "dns1.example.com".to_string(),
                port: 853,
                tls: tls.clone(),
            })
        );

        assert_eq!(
            UpstreamProtocol::parse(
                "https://dns1.example.com/dns-query|ca=/etc/polardns/dns1-ca.pem"
            ),
            Some(UpstreamProtocol::Doh {
                url: "https://dns1.example.com/dns-query".to_string(),
                tls: tls.clone(),
            })
        );

        #[cfg(any(feature = "upstream-h3", feature = "quiche"))]
        assert_eq!(
            UpstreamProtocol::parse(
                "h3://dns1.example.com/dns-query|ca=/etc/polardns/dns1-ca.pem"
            ),
            Some(UpstreamProtocol::DohH3 {
                url: "https://dns1.example.com/dns-query".to_string(),
                tls,
            })
        );

        #[cfg(not(any(feature = "upstream-h3", feature = "quiche")))]
        {
            let _ = tls;
            assert!(
                UpstreamProtocol::parse(
                    "h3://dns1.example.com/dns-query|ca=/etc/polardns/dns1-ca.pem"
                )
                .is_none()
            );
        }
    }

    #[test]
    fn test_inline_ca_rejected_for_plain_upstreams() {
        assert!(UpstreamProtocol::parse("udp://1.1.1.1|ca=/tmp/ca.pem").is_none());
        assert!(UpstreamProtocol::parse("tcp://1.1.1.1|ca=/tmp/ca.pem").is_none());
        assert!(UpstreamProtocol::parse("1.1.1.1|ca=/tmp/ca.pem").is_none());
        assert!(UpstreamProtocol::parse("tls://dns.example|foo=/tmp/ca.pem").is_none());
    }

    #[tokio::test]
    async fn test_udp_multiplexer_cancellation() {
        let mux = UdpMultiplexer::new(false, 1_048_576, None).await.unwrap();
        let addr = "127.0.0.1:9999".parse().unwrap();
        let query = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x05baidu\x03com\x00\x00\x01\x00\x01".to_vec();

        // Spawn send_query in a background task
        let mux_clone = std::sync::Arc::new(mux);
        let mux_ref = mux_clone.clone();
        let handle = tokio::spawn(async move {
            mux_ref
                .send_query(&addr, &query, Duration::from_secs(5))
                .await
        });

        // Yield execution to allow the task to start and insert into pending map
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify that the pending map has 1 entry
        {
            let len: usize = mux_clone
                .shards
                .iter()
                .map(|s| s.lock().unwrap().len())
                .sum();
            assert_eq!(len, 1);
        }

        // Abort the task (simulate cancellation)
        handle.abort();

        // Wait a bit for the drop/cleanup to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Verify that the pending map is now empty!
        {
            let len: usize = mux_clone
                .shards
                .iter()
                .map(|s| s.lock().unwrap().len())
                .sum();
            assert_eq!(len, 0);
        }
    }

    static INIT: std::sync::Once = std::sync::Once::new();
    fn init_rustls() {
        INIT.call_once(|| {
            #[cfg(feature = "rustls-stack")]
            let _ = rustls::crypto::ring::default_provider().install_default();
            #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
            boring::init();
        });
    }

    #[tokio::test]
    async fn test_resolve_upstream_mismatch_discard() {
        init_rustls();
        // Bind a mock DNS server
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_server.local_addr().unwrap();

        // Spawn mock server task that replies with a mismatched query name
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_len, client_addr)) = mock_server.recv_from(&mut buf).await {
                // Parse query to get ID
                let id = u16::from_be_bytes([buf[0], buf[1]]);

                // Build a response for "safebrowsing.google.com" instead of the queried domain
                let mut resp_msg = crate::dns::build_query("safebrowsing.google.com", 65); // HTTPS
                // Set QR bit (response) and set ID
                resp_msg[2] |= 0x80;
                resp_msg[0] = (id >> 8) as u8;
                resp_msg[1] = (id & 0xFF) as u8;

                let _ = mock_server.send_to(&resp_msg, client_addr).await;
            }
        });

        // Set up client arguments
        let query = crate::dns::build_query("github.githubassets.com", 28); // AAAA
        let protocol = UpstreamProtocol::Udp(mock_addr, Default::default());
        let timeout_dur = Duration::from_secs(3);
        let fallback_upstreams = vec![];
        let cache = Arc::new(crate::cache::DnsCache::new(10, 0, Some(0)));
        let mux = Arc::new(UdpMultiplexer::new(false, 1_048_576, None).await.unwrap());
        let pool = Arc::new(ConnectionPool::new(16, Arc::new(crate::opt::Opt::default())));

        // Resolve upstream. It should filter out the mismatched response and return None!
        let result = resolve_upstream(
            &query,
            &protocol,
            true,
            timeout_dur,
            UpstreamClients::empty(),
            &fallback_upstreams,
            false,
            &cache,
            Some(mux),
            pool,
            crate::request_id::RequestId::new(),
            None,
        )
        .await;

        assert!(
            result.is_none(),
            "Mismatched response should have been discarded!"
        );
    }

    #[tokio::test]
    async fn test_resolve_upstream_matching_accept() {
        init_rustls();
        // Bind a mock DNS server
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_server.local_addr().unwrap();

        // Spawn mock server task that replies with a matching query name
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_len, client_addr)) = mock_server.recv_from(&mut buf).await {
                // Parse query to get ID
                let id = u16::from_be_bytes([buf[0], buf[1]]);

                // Build a response for "github.githubassets.com"
                let mut resp_msg = crate::dns::build_query("github.githubassets.com", 28); // AAAA
                // Set QR bit (response) and set ID
                resp_msg[2] |= 0x80;
                resp_msg[0] = (id >> 8) as u8;
                resp_msg[1] = (id & 0xFF) as u8;

                let _ = mock_server.send_to(&resp_msg, client_addr).await;
            }
        });

        // Set up client arguments
        let query = crate::dns::build_query("github.githubassets.com", 28); // AAAA
        let protocol = UpstreamProtocol::Udp(mock_addr, Default::default());
        let timeout_dur = Duration::from_secs(3);
        let fallback_upstreams = vec![];
        let cache = Arc::new(crate::cache::DnsCache::new(10, 0, Some(0)));
        let mux = Arc::new(UdpMultiplexer::new(false, 1_048_576, None).await.unwrap());
        let pool = Arc::new(ConnectionPool::new(16, Arc::new(crate::opt::Opt::default())));

        // Resolve upstream. It should accept the matching response!
        let result = resolve_upstream(
            &query,
            &protocol,
            true,
            timeout_dur,
            UpstreamClients::empty(),
            &fallback_upstreams,
            false,
            &cache,
            Some(mux),
            pool,
            crate::request_id::RequestId::new(),
            None,
        )
        .await;

        assert!(
            result.is_some(),
            "Matching response should have been accepted!"
        );
    }

    #[tokio::test]
    async fn test_resolve_upstream_servfail_rejected() {
        init_rustls();
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, client_addr)) = mock_server.recv_from(&mut buf).await {
                let mut resp = buf[..len].to_vec();
                resp[2] |= 0x80; // QR
                resp[3] = (resp[3] & 0xF0) | 0x02; // SERVFAIL
                let _ = mock_server.send_to(&resp, client_addr).await;
            }
        });

        let query = crate::dns::build_query("servfail.example", 1);
        let protocol = UpstreamProtocol::Udp(mock_addr, Default::default());
        let cache = Arc::new(crate::cache::DnsCache::new(10, 0, Some(0)));
        let pool = Arc::new(ConnectionPool::new(16, Arc::new(crate::opt::Opt::default())));

        let result = resolve_upstream(
            &query,
            &protocol,
            true,
            Duration::from_secs(1),
            UpstreamClients::empty(),
            &[],
            false,
            &cache,
            None,
            pool,
            crate::request_id::RequestId::new(),
            None,
        )
        .await;

        assert!(
            result.is_none(),
            "SERVFAIL should be rejected so fallback can continue"
        );
    }

    #[tokio::test]
    async fn test_resolve_upstream_explicit_udp_accepts_truncated_response() {
        init_rustls();
        let mock_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, client_addr)) = mock_server.recv_from(&mut buf).await {
                let mut resp = buf[..len].to_vec();
                resp[2] |= 0x82; // QR + TC
                resp[3] = (resp[3] & 0xF0) | 0x80; // RA, NOERROR
                let _ = mock_server.send_to(&resp, client_addr).await;
            }
        });

        let query = crate::dns::build_query("truncated-udp.example", 1);
        let protocol = UpstreamProtocol::Udp(mock_addr, Default::default());
        let cache = Arc::new(crate::cache::DnsCache::new(10, 0, Some(0)));
        let pool = Arc::new(ConnectionPool::new(16, Arc::new(crate::opt::Opt::default())));

        let result = resolve_upstream(
            &query,
            &protocol,
            true,
            Duration::from_secs(1),
            UpstreamClients::empty(),
            &[],
            false,
            &cache,
            None,
            pool,
            crate::request_id::RequestId::new(),
            None,
        )
        .await;

        let resp = result.expect("explicit UDP TC response should be accepted for forwarding");
        let msg = crate::dns::DnsMessage::parse(&resp).unwrap();
        assert!(msg.is_truncated());
        assert!(!msg.is_cacheable());
        assert!(msg.is_acceptable_upstream_response());
    }

    #[tokio::test]
    async fn test_udp_and_tcp_retries_tcp_on_truncated_udp() {
        init_rustls();
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = tcp_listener.local_addr().unwrap();
        let udp_server = UdpSocket::bind(upstream_addr).await.unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((len, client_addr)) = udp_server.recv_from(&mut buf).await {
                let mut resp = buf[..len].to_vec();
                resp[2] |= 0x82; // QR + TC
                let _ = udp_server.send_to(&resp, client_addr).await;
            }
        });

        tokio::spawn(async move {
            let (mut stream, _) = tcp_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut query = vec![0u8; len];
            stream.read_exact(&mut query).await.unwrap();

            query[2] |= 0x80; // QR
            query[3] = (query[3] & 0xF0) | 0x80; // RA, NOERROR
            let mut out = Vec::with_capacity(2 + query.len());
            out.extend_from_slice(&(query.len() as u16).to_be_bytes());
            out.extend_from_slice(&query);
            stream.write_all(&out).await.unwrap();
        });

        let query = crate::dns::build_query("truncated.example", 1);
        let protocol = UpstreamProtocol::UdpAndTcp(upstream_addr, Default::default());
        let cache = Arc::new(crate::cache::DnsCache::new(10, 0, Some(0)));
        let pool = Arc::new(ConnectionPool::new(16, Arc::new(crate::opt::Opt::default())));

        let result = resolve_upstream(
            &query,
            &protocol,
            true,
            Duration::from_secs(2),
            UpstreamClients::empty(),
            &[],
            false,
            &cache,
            None,
            pool,
            crate::request_id::RequestId::new(),
            None,
        )
        .await;

        let resp = result.expect("truncated UDP response should retry over TCP");
        let msg = crate::dns::DnsMessage::parse(&resp).unwrap();
        assert!(!msg.is_truncated());
        assert_eq!(msg.get_rcode(), 0);
    }

    #[tokio::test]
    async fn test_connection_pool_limit() {
        let pool = Arc::new(ConnectionPool::new(2, Arc::new(crate::opt::Opt::default())));
        let addr = "127.0.0.1:53".parse::<SocketAddr>().unwrap();

        // Lease first connection slot
        let guard1 = pool.lease_tcp(&addr).await;
        assert!(guard1.is_some());

        // Lease second connection slot concurrently
        let guard2 = pool.lease_tcp(&addr).await;
        assert!(guard2.is_some());

        // Attempt to lease third connection slot concurrently (should fail-fast)
        let guard3 = pool.lease_tcp(&addr).await;
        assert!(guard3.is_none());

        // Verify that the pool created 2 connection slots
        let tcp_conns = pool.tcp_conns.lock().unwrap();
        let conns = tcp_conns.get(&addr).unwrap();
        assert_eq!(conns.conns.lock().unwrap().len(), 2);
    }

    #[test]
    fn test_rtt_tracker_ema() {
        let tracker = RttTracker::new();
        let up = UpstreamProtocol::Udp("8.8.8.8:53".parse().unwrap(), Default::default());

        // Default RTT should be 10ms
        assert_eq!(tracker.get_rtt(&up), 10);

        // Record a success of 100ms
        // Formula: 10 * 0.8 + 100 * 0.2 = 8 + 20 = 28
        tracker.record_success(&up, 100);
        assert_eq!(tracker.get_rtt(&up), 28);

        // Record another success of 50ms
        // Formula: 28 * 0.8 + 50 * 0.2 = 22.4 + 10 = 32.4 -> 32
        tracker.record_success(&up, 50);
        assert_eq!(tracker.get_rtt(&up), 32);
    }

    #[test]
    fn test_rtt_tracker_failure_penalty() {
        let tracker = RttTracker::new();
        let up = UpstreamProtocol::Udp("8.8.8.8:53".parse().unwrap(), Default::default());

        // Default RTT is 10
        assert_eq!(tracker.get_rtt(&up), 10);

        // Record a failure: 10 + 1000 = 1010
        tracker.record_failure(&up);
        assert_eq!(tracker.get_rtt(&up), 1010);

        // Apply multiple failures to test saturation/cap at 5000ms
        for _ in 0..5 {
            tracker.record_failure(&up);
        }
        assert_eq!(tracker.get_rtt(&up), 5000);
    }

    #[test]
    fn test_rtt_sorting() {
        let tracker = RttTracker::new();
        let up1 = UpstreamProtocol::Udp("8.8.8.8:53".parse().unwrap(), Default::default());
        let up2 = UpstreamProtocol::Udp("1.1.1.1:53".parse().unwrap(), Default::default());
        let up3 = UpstreamProtocol::Udp("114.114.114.114:53".parse().unwrap(), Default::default());

        // Default is 10ms. Record success to set custom RTTs:
        // up1 RTT sample 20ms -> EMA: 10 * 0.8 + 20 * 0.2 = 12ms
        tracker.record_success(&up1, 20);
        // up2 RTT sample 5ms -> EMA: 10 * 0.8 + 5 * 0.2 = 9ms
        tracker.record_success(&up2, 5);
        // up3 RTT sample 100ms -> EMA: 10 * 0.8 + 100 * 0.2 = 28ms
        tracker.record_success(&up3, 100);

        let mut targets = [up1.clone(), up2.clone(), up3.clone()];
        targets.sort_by_key(|up| tracker.get_rtt(up));

        assert_eq!(targets[0], up2); // 9ms
        assert_eq!(targets[1], up1); // 12ms
        assert_eq!(targets[2], up3); // 28ms
    }

    #[test]
    fn test_doq_parse() {
        #[cfg(any(feature = "original-h3-server", feature = "quiche"))]
        {
            assert_eq!(
                UpstreamProtocol::parse("quic://1.1.1.1"),
                Some(UpstreamProtocol::Doq {
                    addr: Some("1.1.1.1:853".parse().unwrap()),
                    hostname: "1.1.1.1".to_string(),
                    port: 853,
                    tls: TlsOptions::default(),
                })
            );

            assert_eq!(
                UpstreamProtocol::parse("doq://dns.adguard-dns.com:8853|ca=/path/to/ca.pem"),
                Some(UpstreamProtocol::Doq {
                    addr: None,
                    hostname: "dns.adguard-dns.com".to_string(),
                    port: 8853,
                    tls: TlsOptions {
                        ca_certs: Some("/path/to/ca.pem".to_string()),
                        mark: None,
                    },
                })
            );
        }

        #[cfg(not(any(feature = "original-h3-server", feature = "quiche")))]
        {
            assert_eq!(UpstreamProtocol::parse("quic://1.1.1.1"), None);
            assert_eq!(UpstreamProtocol::parse("doq://dns.adguard-dns.com"), None);
        }
    }

    #[cfg(any(feature = "quiche", feature = "original-h3-server"))]
    fn ensure_test_certs() -> (String, String) {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("test_temp.crt");
        let key_path = dir.path().join("test_temp.key");
        let _ = std::process::Command::new("openssl")
            .args(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key_path.to_str().unwrap()])
            .output();
        let _ = std::process::Command::new("openssl")
            .args(["req", "-new", "-key", key_path.to_str().unwrap(), "-x509", "-days", "1", "-out", cert_path.to_str().unwrap(), "-subj", "/CN=localhost", "-addext", "subjectAltName = DNS:localhost, IP:127.0.0.1"])
            .output();
        let cert_str = cert_path.to_str().unwrap().to_string();
        let key_str = key_path.to_str().unwrap().to_string();
        std::mem::forget(dir);
        (cert_str, key_str)
    }

    #[cfg(feature = "original-h3-server")]
    #[tokio::test]
    async fn test_doq_server_and_client_quinn() {
        let _ = tracing_subscriber::fmt::try_init();

        let _ = rustls::crypto::ring::default_provider().install_default();
        let (cert_path, key_path) = ensure_test_certs();

        let server_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let server_addr = format!("127.0.0.1:{}", server_port).parse::<SocketAddr>().unwrap();

        let cert = std::fs::read(&cert_path).unwrap();
        let key = std::fs::read(&key_path).unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut &cert[..]).map(|c| c.unwrap()).collect();
        let cert = certs[0].clone();
        let mut keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut &key[..]).map(|k| k.unwrap()).collect();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(keys.remove(0));
        
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        server_crypto.alpn_protocols = vec![b"doq".to_vec()];

        let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto).unwrap()
        ));
        let endpoint = quinn::Endpoint::server(server_config, server_addr).unwrap();

        let server_endpoint = endpoint.clone();
        tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await
                && let Ok(c) = conn.await
                && let Ok((mut send, mut recv)) = c.accept_bi().await
            {
                if let Ok(buf) = recv.read_to_end(65535).await {
                    let _ = send.write_all(&buf).await;
                    let _ = send.finish();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        });

        let opt = crate::opt::Opt {
            timeout_ms: 5000,
            quic_idle_timeout_ms: 5000,
            ..Default::default()
        };
        let opt = std::sync::Arc::new(opt);

        let pool = std::sync::Arc::new(ConnectionPool::new(
            10,
            opt.clone(),
        ));

        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01";
        let tls = TlsOptions { ca_certs: Some("test_temp.crt".to_string()), mark: None };
        let resp = resolve_via_doq(query, &server_addr, "localhost", server_port, &tls, None, pool).await;

        assert!(resp.is_some());
        let resp_bytes = resp.unwrap();
        assert_eq!(resp_bytes[0], 0x12);
        assert_eq!(resp_bytes[1], 0x34);

        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);
    }

    #[cfg(feature = "quiche")]
    #[tokio::test]
    async fn test_doq_server_and_client_quiche() {
        let _ = tracing_subscriber::fmt::try_init();
        let (cert_path, key_path) = ensure_test_certs();

        let server_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let server_addr = format!("127.0.0.1:{}", server_port).parse::<SocketAddr>().unwrap();

        let mut ssl_ctx_builder = boring::ssl::SslContext::builder(boring::ssl::SslMethod::tls_server()).unwrap();
        ssl_ctx_builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::OFF);
        
        let cert_key = crate::quiche_server::BoringCertKey::load(&cert_path, &key_path).unwrap();
        ssl_ctx_builder.set_certificate(&cert_key.leaf).unwrap();
        ssl_ctx_builder.set_private_key(&cert_key.key).unwrap();

        let mut quiche_config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl_ctx_builder).unwrap();
        let mut opt = crate::opt::Opt::default();
        opt.timeout_ms = 5000;
        opt.quic_idle_timeout_ms = 5000;
        let opt = std::sync::Arc::new(opt);
        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
        crate::quiche_server::configure_quiche_limits(&mut quiche_config, &limits, &opt).unwrap();

        let socket = std::net::UdpSocket::bind(server_addr).unwrap();
        socket.set_nonblocking(true).unwrap();
        let socket = std::sync::Arc::new(tokio::net::UdpSocket::from_std(socket).unwrap());
        let server_socket = socket.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut out_buf = vec![0u8; 65535];
            let mut conn: Option<quiche::Connection> = None;
            let mut stream_buf = Vec::new();

            loop {
                let timer = tokio::time::sleep(Duration::from_millis(50));
                tokio::pin!(timer);

                let timeout = conn.as_ref().map(|c| c.timeout().unwrap_or(Duration::from_millis(5000))).unwrap_or(Duration::from_millis(5000));
                timer.as_mut().reset(tokio::time::Instant::now() + timeout);

                tokio::select! {
                    Ok((len, src)) = server_socket.recv_from(&mut buf) => {
                        eprintln!("[SERVER] recv_from {} bytes from {}", len, src);
                        let info = quiche::RecvInfo { from: src, to: server_addr };
                        if conn.is_none() {
                            let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
                            boring::rand::rand_bytes(&mut scid).unwrap();
                            let scid = quiche::ConnectionId::from_ref(&scid);
                            conn = Some(quiche::accept(&scid, None, server_addr, src, &mut quiche_config).unwrap());
                            eprintln!("[SERVER] accepted new connection");
                        }

                        let c = conn.as_mut().unwrap();
                        match c.recv(&mut buf[..len], info) {
                            Ok(n) => eprintln!("[SERVER] conn.recv OK: {} bytes processed, is_established={}, is_closed={}", n, c.is_established(), c.is_closed()),
                            Err(e) => eprintln!("[SERVER] conn.recv ERROR: {:?}, is_closed={}", e, c.is_closed()),
                        }
                        if c.is_established() {
                            for stream_id in c.readable() {
                                let mut b = vec![0u8; 1024];
                                if let Ok((read_bytes, fin)) = c.stream_recv(stream_id, &mut b) {
                                    eprintln!("[SERVER] stream_recv: stream_id={}, read_bytes={}, fin={}", stream_id, read_bytes, fin);
                                    stream_buf.extend_from_slice(&b[..read_bytes]);
                                    if stream_buf.len() >= 2 {
                                        let expected = u16::from_be_bytes([stream_buf[0], stream_buf[1]]) as usize;
                                        if stream_buf.len() >= 2 + expected || fin {
                                            let payload = if stream_buf.len() >= 2 + expected {
                                                stream_buf[..2+expected].to_vec()
                                            } else {
                                                stream_buf.to_vec()
                                            };
                                            eprintln!("[SERVER] sending response: stream_id={}, payload_len={}", stream_id, payload.len());
                                            let _ = c.stream_send(stream_id, &payload, true);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ = &mut timer => {
                        if let Some(c) = conn.as_mut() {
                            c.on_timeout();
                        }
                    }
                }

                if let Some(c) = conn.as_mut() {
                    let mut sent_count = 0;
                    while let Ok((write_len, send_info)) = c.send(&mut out_buf) {
                        eprintln!("[SERVER] sending {} bytes to {}", write_len, send_info.to);
                        let _ = server_socket.send_to(&out_buf[..write_len], send_info.to).await;
                        sent_count += 1;
                    }
                    if sent_count > 0 {
                        eprintln!("[SERVER] sent {} packets total, is_established={}, is_in_early_data={}", sent_count, c.is_established(), c.is_in_early_data());
                    }
                    if c.is_closed() {
                        eprintln!("[SERVER] connection closed, peer_error={:?}", c.peer_error());
                        break;
                    }
                }
            }
        });

        let pool = std::sync::Arc::new(ConnectionPool::new(10, opt.clone()));

        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01";
        let tls = TlsOptions { ca_certs: Some("test_temp.crt".to_string()), mark: None };
        let resp = resolve_via_doq(query, &server_addr, "localhost", server_port, &tls, None, pool).await;

        assert!(resp.is_some());
        let resp_bytes = resp.unwrap();
        assert_eq!(resp_bytes[0], 0x12);
        assert_eq!(resp_bytes[1], 0x34);

        let _ = std::fs::remove_file("test_temp.crt");
        let _ = std::fs::remove_file("test_temp.key");
    }

    #[cfg(feature = "quiche")]
    #[test]
    fn test_quiche_handshake_only() {
        let (cert_path, key_path) = ensure_test_certs();

        // Server config
        let mut ssl_ctx_builder = boring::ssl::SslContext::builder(boring::ssl::SslMethod::tls_server()).unwrap();
        ssl_ctx_builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::OFF);
        let cert_key = crate::quiche_server::BoringCertKey::load(&cert_path, &key_path).unwrap();
        ssl_ctx_builder.set_certificate(&cert_key.leaf).unwrap();
        ssl_ctx_builder.set_private_key(&cert_key.key).unwrap();

        let mut server_config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl_ctx_builder).unwrap();
        let opt = crate::opt::Opt::default();
        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
        crate::quiche_server::configure_quiche_limits(&mut server_config, &limits, &opt).unwrap();

        // Client config
        let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        crate::quiche_server::configure_quiche_limits(&mut client_config, &limits, &opt).unwrap();
        client_config.verify_peer(false);
        client_config.set_application_protos(&[b"doq"]).unwrap();

        let client_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();

        let mut client_scid = [0u8; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut client_scid).unwrap();
        let client_scid = quiche::ConnectionId::from_ref(&client_scid);

        let mut client = quiche::connect(Some("localhost"), &client_scid, client_addr, server_addr, &mut client_config).unwrap();

        let mut server_scid = [0u8; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut server_scid).unwrap();
        let server_scid = quiche::ConnectionId::from_ref(&server_scid);

        let mut buf = vec![0u8; 65535];
        let mut pipe_buf = Vec::new();
        let mut server: Option<quiche::Connection> = None;

        for round in 0..20 {
            // Client sends
            pipe_buf.clear();
            while let Ok((len, _)) = client.send(&mut buf) {
                pipe_buf.extend_from_slice(&buf[..len]);
            }

            if !pipe_buf.is_empty() {
                eprintln!("[ROUND {}] Client -> Server: {} bytes", round, pipe_buf.len());

                if server.is_none() {
                    server = Some(quiche::accept(&server_scid, None, server_addr, client_addr, &mut server_config).unwrap());
                }
                let s = server.as_mut().unwrap();
                let info = quiche::RecvInfo { from: client_addr, to: server_addr };
                match s.recv(&mut pipe_buf, info) {
                    Ok(n) => eprintln!("[ROUND {}] Server recv: {} bytes, established={}", round, n, s.is_established()),
                    Err(e) => eprintln!("[ROUND {}] Server recv error: {:?}", round, e),
                }
            }

            // Server sends
            if let Some(s) = server.as_mut() {
                pipe_buf.clear();
                while let Ok((len, _)) = s.send(&mut buf) {
                    pipe_buf.extend_from_slice(&buf[..len]);
                }

                if !pipe_buf.is_empty() {
                    eprintln!("[ROUND {}] Server -> Client: {} bytes", round, pipe_buf.len());
                    let info = quiche::RecvInfo { from: server_addr, to: client_addr };
                    match client.recv(&mut pipe_buf, info) {
                        Ok(n) => eprintln!("[ROUND {}] Client recv: {} bytes, established={}", round, n, client.is_established()),
                        Err(e) => eprintln!("[ROUND {}] Client recv error: {:?}", round, e),
                    }
                }
            }

            let c_est = client.is_established();
            let s_est = server.as_ref().map(|s| s.is_established()).unwrap_or(false);
            let s_alpn = server.as_ref().map(|s| String::from_utf8_lossy(s.application_proto()).to_string()).unwrap_or_default();
            eprintln!("[ROUND {}] client.established={}, server.established={}, server.alpn={:?}", round, c_est, s_est, s_alpn);

            if c_est && s_est {
                eprintln!("[HANDSHAKE COMPLETE] Took {} rounds", round + 1);
                break;
            }
        }

        let c_est = client.is_established();
        let s_est = server.as_ref().map(|s| s.is_established()).unwrap_or(false);
        eprintln!("[FINAL] client.established={}, server.established={}", c_est, s_est);
        assert!(c_est, "Client handshake failed");
        assert!(s_est, "Server handshake failed");

        let _ = std::fs::remove_file("test_temp.crt");
        let _ = std::fs::remove_file("test_temp.key");
    }

    #[tokio::test]
    async fn test_connection_pool_prune_idle() {
        let pool = ConnectionPool::new(2, Arc::new(crate::opt::Opt::default()));
        let addr: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let lease = pool.lease_tcp(&addr).await;
        assert!(lease.is_some());
        {
            let pools = pool.tcp_conns.lock().unwrap();
            assert!(pools.contains_key(&addr));
        }
        drop(lease);
        pool.prune_idle();
        {
            let pools = pool.tcp_conns.lock().unwrap();
            assert!(!pools.contains_key(&addr));
        }
    }

    #[tokio::test]
    async fn test_connection_pool_clears_dead_connections() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let pool = ConnectionPool::new(2, Arc::new(crate::opt::Opt::default()));
        {
            let lease = pool.lease_tcp(&addr).await.unwrap();
            let (_permit, mut guard) = lease;
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (server_stream, _) = listener.accept().await.unwrap();
            *guard = Some(stream);
            drop(server_stream); // Close connection from server end (peer FIN)
        }

        // Allow socket time to settle into CLOSE-WAIT
        tokio::time::sleep(Duration::from_millis(50)).await;

        // prune_idle should detect dead socket, clear it and drop the pool
        pool.prune_idle();
        {
            let pools = pool.tcp_conns.lock().unwrap();
            assert!(!pools.contains_key(&addr));
        }
    }

    #[tokio::test]
    async fn test_connection_pool_prunes_idle_timeout() {
        let mut opt = crate::opt::Opt::default();
        opt.tcp_idle_timeout_ms = 50; // 50ms timeout for test
        let pool = ConnectionPool::new(2, Arc::new(opt));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();

        let _server_task = tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        {
            let lease = pool.lease_tcp(&target_addr).await.unwrap();
            let (_permit, mut guard) = lease;
            let stream = tokio::net::TcpStream::connect(target_addr).await.unwrap();
            *guard = Some(stream);
        }

        // Before timeout, prune_idle keeps the connection alive
        pool.prune_idle();
        {
            let pools = pool.tcp_conns.lock().unwrap();
            assert!(pools.contains_key(&target_addr));
        }

        // Wait past 50ms idle timeout
        tokio::time::sleep(Duration::from_millis(70)).await;

        // prune_idle should now expire the idle connection and drop the pool
        pool.prune_idle();
        {
            let pools = pool.tcp_conns.lock().unwrap();
            assert!(!pools.contains_key(&target_addr));
        }
    }
}
