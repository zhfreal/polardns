use std::time::Duration;
#[cfg(feature = "server-h3")]
use dashmap::DashMap;
#[cfg(feature = "server-h3")]
use std::collections::HashMap;
#[cfg(feature = "server-h3")]
use std::net::SocketAddr;
#[cfg(feature = "server-h3")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "server-h3")]
use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "server-h3")]
use tokio::net::UdpSocket;
#[cfg(feature = "server-h3")]
use tokio::sync::mpsc;
#[cfg(feature = "server-h3")]
use quiche::h3::NameValue;

#[cfg(feature = "server-h3")]
const LOCAL_CONN_ID_LEN: usize = 16;
pub const QUICHE_TIMER_INIT_DURATION: Duration = Duration::from_millis(50);
pub const STREAM_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

pub struct H3ResourceLimits {
    pub max_conn_data: u64,
    pub max_stream_data: u64,
    pub client_max_pending: usize,
    pub session_cache_limit: usize,
    pub server_packet_pool_size: usize,
    pub client_packet_pool_size: usize,
    pub conn_channel_capacity: usize,
    pub max_header_list_size: u64,
    pub retry_token_ttl: u64,
    pub max_response_size: usize,
    pub max_udp_payload_size: usize,
    pub stream_timeout_ms: u64,
    pub body_buffer_size: usize,
    pub server_resp_channel_capacity: usize,
    pub max_active_cids: usize,
    pub max_ack_delay: u64,
}

impl H3ResourceLimits {
    pub fn from_opt(opt: &crate::opt::Opt) -> Self {
        let profile = opt.h3_profile.as_deref().unwrap_or(if opt.h3_low_memory { "low" } else { "balanced" });
        
        match profile {
            "low" => Self {
                max_conn_data: 262_144,              // 256 KB
                max_stream_data: 16_384,             // 16 KB
                client_max_pending: 64,
                session_cache_limit: 64,
                server_packet_pool_size: 32,
                client_packet_pool_size: 16,
                conn_channel_capacity: 16,
                max_header_list_size: 4096,          // 4 KB
                retry_token_ttl: 15,
                max_response_size: 65535,            // RFC max DNS message
                max_udp_payload_size: 1350,          // Standard safe MTU
                stream_timeout_ms: 5000,
                body_buffer_size: 1024,              // 1 KB
                server_resp_channel_capacity: 32,
                max_active_cids: 2,
                max_ack_delay: 25,
            },
            "high" => Self {
                max_conn_data: 8_388_608,            // 8 MB
                max_stream_data: 262_144,            // 256 KB
                client_max_pending: 8192,
                session_cache_limit: 8192,
                server_packet_pool_size: 512,
                client_packet_pool_size: 256,
                conn_channel_capacity: 256,
                max_header_list_size: 16384,         // 16 KB
                retry_token_ttl: 30,
                max_response_size: 65535,
                max_udp_payload_size: 1350,
                stream_timeout_ms: 10000,
                body_buffer_size: 8192,              // 8 KB
                server_resp_channel_capacity: 512,
                max_active_cids: 4,
                max_ack_delay: 10,
            },
            _ => Self { // "balanced" default
                max_conn_data: 1_048_576,            // 1 MB
                max_stream_data: 65_536,             // 64 KB
                client_max_pending: 1024,
                session_cache_limit: 1024,
                server_packet_pool_size: 128,
                client_packet_pool_size: 64,
                conn_channel_capacity: 64,
                max_header_list_size: 8192,          // 8 KB
                retry_token_ttl: 15,
                max_response_size: 65535,
                max_udp_payload_size: 1350,
                stream_timeout_ms: 5000,
                body_buffer_size: 4096,              // 4 KB
                server_resp_channel_capacity: 128,
                max_active_cids: 2,
                max_ack_delay: 25,
            },
        }
    }
}

pub fn create_tuned_udp_socket(
    bind_addr: std::net::SocketAddr,
    mark: Option<u32>,
    opt: &crate::opt::Opt,
) -> anyhow::Result<tokio::net::UdpSocket> {
    let domain = if bind_addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    
    if bind_addr.is_ipv6() {
        let _ = sock.set_only_v6(false);
    }

    let buf_size = if opt.socket_buffer_size > 0 {
        opt.socket_buffer_size
    } else if opt.h3_low_memory || opt.h3_profile.as_deref() == Some("low") {
        256 * 1024
    } else {
        512 * 1024
    };
    let _ = sock.set_recv_buffer_size(buf_size);
    let _ = sock.set_send_buffer_size(buf_size);
    let _ = sock.set_reuse_address(true);

    #[cfg(target_os = "linux")]
    {
        if opt.reuse_port {
            let _ = sock.set_reuse_port(true);
        }
    }

    #[cfg(unix)]
    if let Some(m) = mark {
        let _ = sock.set_mark(m);
    }

    sock.bind(&bind_addr.into())?;
    sock.set_nonblocking(true)?;
    
    let tokio_socket = tokio::net::UdpSocket::from_std(sock.into())?;
    Ok(tokio_socket)
}

pub fn configure_quiche_limits(config: &mut quiche::Config, limits: &H3ResourceLimits, opt: &crate::opt::Opt) -> anyhow::Result<()> {
    config.set_initial_max_data(limits.max_conn_data);
    config.set_initial_max_stream_data_bidi_local(limits.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(limits.max_stream_data);
    config.set_initial_max_stream_data_uni(limits.max_stream_data);
    
    config.set_max_send_udp_payload_size(limits.max_udp_payload_size);
    config.set_max_recv_udp_payload_size(limits.max_udp_payload_size);

    let bidi_limit = opt.max_concurrent_queries.max(1).min(1024) as u64;
    config.set_initial_max_streams_bidi(bidi_limit);
    config.set_initial_max_streams_uni(100);
    config.set_max_idle_timeout(opt.quic_idle_timeout_ms as u64);
    config.set_disable_active_migration(true);

    config.set_active_connection_id_limit(limits.max_active_cids as u64);
    config.set_max_ack_delay(limits.max_ack_delay);

    config.enable_early_data();
    config.discover_pmtu(true);

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.log_keys();
    }
    
    config.set_application_protos(&[b"h3", b"h3-29", b"h3-30", b"h3-31", b"h3-32", b"doq"])
        .map_err(|e| anyhow::anyhow!("failed to set ALPN: {:?}", e))?;
    
    Ok(())
}

pub fn create_h3_config(limits: &H3ResourceLimits) -> anyhow::Result<quiche::h3::Config> {
    let mut h3_config = quiche::h3::Config::new()?;
    h3_config.set_max_field_section_size(limits.max_header_list_size);
    h3_config.set_qpack_max_table_capacity(0);
    h3_config.set_qpack_blocked_streams(0);
    Ok(h3_config)
}

#[cfg(feature = "boring")]
#[derive(Clone)]
pub struct BoringCertKey {
    pub leaf: boring::x509::X509,
    pub key: boring::pkey::PKey<boring::pkey::Private>,
    pub chain: Vec<boring::x509::X509>,
}

#[cfg(feature = "boring")]
impl BoringCertKey {
    pub fn load(cert_path: &str, key_path: &str) -> anyhow::Result<Self> {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        
        let mut certs = boring::x509::X509::stack_from_pem(&cert_pem)?;
        if certs.is_empty() {
            anyhow::bail!("No certificates found in {}", cert_path);
        }
        let leaf = certs.remove(0);
        let key = boring::pkey::PKey::private_key_from_pem(&key_pem)?;
        
        Ok(Self { leaf, key, chain: certs })
    }
}

#[cfg(all(feature = "boring", feature = "server-h3"))]
pub struct BoringSniCertResolver {
    exact: rustc_hash::FxHashMap<String, Arc<BoringCertKey>>,
    wildcards: Vec<(String, Arc<BoringCertKey>)>,
    pub fallback: Arc<BoringCertKey>,
    pub strict_sni: bool,
}

#[cfg(all(feature = "boring", feature = "server-h3"))]
impl BoringSniCertResolver {
    pub fn resolve(&self, server_name: Option<&str>) -> Option<Arc<BoringCertKey>> {
        if let Some(name) = server_name {
            let name_lower = name.to_ascii_lowercase();

            if let Some(ctx) = self.exact.get(&name_lower) {
                return Some(ctx.clone());
            }

            for (suffix, ctx) in &self.wildcards {
                if name_lower.ends_with(suffix) {
                    return Some(ctx.clone());
                }
            }
        }

        if self.strict_sni {
            None
        } else {
            Some(self.fallback.clone())
        }
    }
}

#[cfg(all(feature = "boring", feature = "server-h3"))]
pub fn build_boring_cert_resolver(
    opt: &crate::opt::Opt,
) -> anyhow::Result<Arc<BoringSniCertResolver>> {
    let mut cert_pairs = Vec::new();
    if let (Some(cert_path), Some(key_path)) = (&opt.cert_file, &opt.key_file) {
        cert_pairs.push((cert_path.clone(), key_path.clone()));
    }
    for raw in &opt.cert_pair {
        for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
            if let Some((cert, key)) = entry.split_once(',') {
                cert_pairs.push((cert.trim().to_string(), key.trim().to_string()));
            } else {
                cert_pairs.push((entry.to_string(), entry.to_string()));
            }
        }
    }

    if cert_pairs.is_empty() {
        anyhow::bail!("--cert-file/--key-file or --cert-pair is required for DoH3 listener");
    }

    let mut exact = rustc_hash::FxHashMap::default();
    let mut wildcards = Vec::new();
    let mut fallback_ctx = None;

    for (cert_path, key_path) in cert_pairs {
        let cert_key = Arc::new(BoringCertKey::load(&cert_path, &key_path)?);
        
        if fallback_ctx.is_none() {
            fallback_ctx = Some(cert_key.clone());
        }

        #[cfg(feature = "rustls-stack")]
        let domains = {
            let certs = crate::server::load_certs(&cert_path)?;
            crate::server::extract_cert_names(&certs)?
        };
        #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
        let domains = crate::server::extract_cert_names_boring(&cert_path)?;

        for domain in domains {
            tracing::info!("BoringSniCertResolver: registered domain: {}", domain);
            let d_lower = domain.to_ascii_lowercase();
            if let Some(suffix) = d_lower.strip_prefix("*.") {
                wildcards.push((format!(".{}", suffix), cert_key.clone()));
            } else {
                exact.insert(d_lower, cert_key.clone());
            }
        }
    }

    let fallback = fallback_ctx.ok_or_else(|| anyhow::anyhow!("Failed to build fallback BoringCertKey"))?;
    wildcards.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    Ok(Arc::new(BoringSniCertResolver {
        exact,
        wildcards,
        fallback,
        strict_sni: opt.strict_sni,
    }))
}

#[cfg(feature = "server-h3")]
fn hmac_sha256_boring(secret_key: &[u8], payload: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut out_len: std::os::raw::c_uint = 0;
    // SAFETY: `EVP_sha256()` returns a valid digest algorithm pointer; `secret_key`, `payload`, and `out` pointers and lengths passed to HMAC are valid and non-null.
    unsafe {
        let md = boring_sys::EVP_sha256();
        let ptr = boring_sys::HMAC(
            md,
            secret_key.as_ptr() as *const std::os::raw::c_void,
            secret_key.len(),
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            &mut out_len,
        );
        if ptr.is_null() || out_len != 32 {
            return None;
        }
    }
    Some(out)
}

#[cfg(feature = "server-h3")]
pub fn generate_stateless_retry_token(
    src: &SocketAddr,
    dcid: &[u8],
    secret_key: &[u8],
) -> ([u8; 128], usize) {
    mint_stateless_retry_token(dcid, src, secret_key)
}

#[cfg(feature = "server-h3")]
pub fn mint_stateless_retry_token(
    dcid: &[u8],
    src: &SocketAddr,
    secret_key: &[u8],
) -> ([u8; 128], usize) {
    let mut payload = [0u8; 128];
    let mut offset = 0;
    
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    payload[offset..offset+8].copy_from_slice(&now.to_be_bytes());
    offset += 8;

    match src.ip() {
        std::net::IpAddr::V4(ip) => {
            payload[offset] = 4;
            offset += 1;
            let ip_bytes = ip.octets();
            payload[offset..offset+ip_bytes.len()].copy_from_slice(&ip_bytes);
            offset += ip_bytes.len();
        }
        std::net::IpAddr::V6(ip) => {
            payload[offset] = 6;
            offset += 1;
            let ip_bytes = ip.octets();
            payload[offset..offset+ip_bytes.len()].copy_from_slice(&ip_bytes);
            offset += ip_bytes.len();
        }
    }
    
    let dcid_len = std::cmp::min(dcid.len(), payload.len() - offset);
    payload[offset..offset+dcid_len].copy_from_slice(&dcid[..dcid_len]);
    offset += dcid_len;

    let payload_slice = &payload[..offset];
    let hmac_bytes = hmac_sha256_boring(secret_key, payload_slice).unwrap_or([0u8; 32]);

    let mut out_token = [0u8; 128];
    let token_len = hmac_bytes.len() + payload_slice.len();
    out_token[..hmac_bytes.len()].copy_from_slice(&hmac_bytes);
    out_token[hmac_bytes.len()..token_len].copy_from_slice(payload_slice);
    (out_token, token_len)
}

#[cfg(feature = "server-h3")]
pub fn validate_stateless_retry_token(
    src: &SocketAddr,
    token: &[u8],
    secret_key: &[u8],
    ttl_seconds: u64,
) -> Option<([u8; quiche::MAX_CONN_ID_LEN], usize)> {
    if token.len() < 32 + 8 + 1 {
        return None;
    }
    
    let (signature, payload) = token.split_at(32);
    let calculated_hmac = hmac_sha256_boring(secret_key, payload)?;
    if !boring::memcmp::eq(&calculated_hmac, signature) {
        return None;
    }

    let timestamp = u64::from_be_bytes(payload[0..8].try_into().ok()?);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    
    if now < timestamp || now - timestamp > ttl_seconds {
        return None;
    }

    let family = payload[8];
    let (ip_match, odcid_offset) = match (family, src.ip()) {
        (4, std::net::IpAddr::V4(ip)) => {
            if payload[9..13] != ip.octets() { return None; }
            (true, 13)
        }
        (6, std::net::IpAddr::V6(ip)) => {
            if payload[9..25] != ip.octets() { return None; }
            (true, 25)
        }
        _ => return None,
    };

    if !ip_match {
        return None;
    }

    let odcid_bytes = &payload[odcid_offset..];
    let mut arr = [0u8; quiche::MAX_CONN_ID_LEN];
    let len = std::cmp::min(odcid_bytes.len(), quiche::MAX_CONN_ID_LEN);
    arr[..len].copy_from_slice(&odcid_bytes[..len]);
    Some((arr, len))
}

#[cfg(feature = "server-h3")]
pub struct QuichePacket {
    pub data: Vec<u8>,
    pub len: usize,
    pub peer: SocketAddr,
    pub recycle_tx: mpsc::Sender<Vec<u8>>,
}

#[cfg(feature = "server-h3")]
pub type CidKey = (u8, [u8; quiche::MAX_CONN_ID_LEN]);

#[cfg(feature = "server-h3")]
pub fn cid_to_key(cid: &[u8]) -> CidKey {
    let mut key = [0u8; quiche::MAX_CONN_ID_LEN];
    let len = std::cmp::min(cid.len(), quiche::MAX_CONN_ID_LEN);
    key[..len].copy_from_slice(&cid[..len]);
    (len as u8, key)
}

#[cfg(feature = "server-h3")]
struct ConnectionGuard {
    active_connections: Arc<DashMap<CidKey, mpsc::Sender<QuichePacket>>>,
    tracked_cids: Arc<Mutex<Vec<CidKey>>>,
}

#[cfg(feature = "server-h3")]
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Ok(cids) = self.tracked_cids.lock() {
            for cid_key in cids.iter() {
                self.active_connections.remove(cid_key);
            }
        }
    }
}

#[cfg(feature = "server-h3")]
pub(crate) async fn handle_doh3_listener(
    socket: Arc<UdpSocket>,
    state: Arc<crate::server::ServerState>,
    doh_path: Arc<str>,
    mut config: quiche::Config,
    _server_secret_key: Vec<u8>,
    worker_abort_handles: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
) -> anyhow::Result<()> {
    let opt = &state.opt;
    let limits = H3ResourceLimits::from_opt(opt);
    let active_connections = Arc::new(DashMap::<CidKey, mpsc::Sender<QuichePacket>>::with_capacity(opt.max_client_connections));
    
    let pool_size = limits.server_packet_pool_size;
    let (free_tx, mut free_rx) = mpsc::channel::<Vec<u8>>(pool_size);
    for _ in 0..pool_size {
        let _ = free_tx.try_send(vec![0u8; limits.max_udp_payload_size]);
    }

    loop {
        let mut buf = match free_rx.try_recv() {
            Ok(b) => b,
            Err(_) => vec![0u8; limits.max_udp_payload_size],
        };

        let (len, src) = socket.recv_from(&mut buf).await?;

        let dcid_key = {
            let header = match quiche::Header::from_slice(&mut buf[..len], LOCAL_CONN_ID_LEN) {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!("quiche::Header::from_slice failed for packet of len {} from {}: {:?}", len, src, e);
                    let _ = free_tx.try_send(buf);
                    continue;
                }
            };
            cid_to_key(&header.dcid)
        };

        let odcid_buf = [0u8; quiche::MAX_CONN_ID_LEN];
        let odcid_len = 0;
        let has_odcid = false;

        // Stateless retry bypassed for debugging/verification

        let packet = QuichePacket {
            data: buf,
            len,
            peer: src,
            recycle_tx: free_tx.clone(),
        };

        if let Some(tx) = active_connections.get(&dcid_key) {
            if let Err(e) = tx.try_send(packet) {
                let data = match e {
                    mpsc::error::TrySendError::Closed(p) => {
                        drop(tx);
                        active_connections.remove(&dcid_key);
                        p.data
                    }
                    mpsc::error::TrySendError::Full(p) => p.data,
                };
                let _ = free_tx.try_send(data);
            }
        } else {
            let Some(conn_permit) = crate::server::try_acquire_client_conn(&state, "DoH3", src) else {
                tracing::warn!("Max client connections reached, rejecting new DoH3 connection from {}", src);
                let _ = free_tx.try_send(packet.data);
                continue;
            };

            let (tx, rx) = mpsc::channel(limits.conn_channel_capacity);
            let mut scid_bytes = [0u8; LOCAL_CONN_ID_LEN];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut scid_bytes);
            
            let local_addr = socket.local_addr()?;
            let quiche_scid = quiche::ConnectionId::from_ref(&scid_bytes);
            let quiche_odcid = if has_odcid {
                Some(quiche::ConnectionId::from_ref(&odcid_buf[..odcid_len]))
            } else {
                None
            };
            
            let conn = match quiche::accept(&quiche_scid, quiche_odcid.as_ref(), local_addr, src, &mut config) {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!("Failed to accept connection: {:?}", e);
                    let _ = free_tx.try_send(packet.data);
                    continue;
                }
            };

            let tracked_cids = if has_odcid {
                Arc::new(Mutex::new(vec![dcid_key]))
            } else {
                Arc::new(Mutex::new(vec![dcid_key, cid_to_key(&scid_bytes)]))
            };
            
            active_connections.insert(dcid_key, tx.clone());
            if !has_odcid {
                active_connections.insert(cid_to_key(&scid_bytes), tx.clone());
            }
            
            let socket_clone = socket.clone();
            let state_clone = state.clone();
            let path_clone = doh_path.clone();
            let active_connections_clone = active_connections.clone();
            let tracked_cids_clone = tracked_cids.clone();
            
            let worker_tx = tx.clone();
            let worker_task = tokio::spawn(async move {
                let _conn_permit = conn_permit;
                if let Err(e) = run_server_worker(
                    socket_clone,
                    rx,
                    conn,
                    worker_tx,
                    src,
                    state_clone,
                    path_clone,
                    active_connections_clone,
                    tracked_cids_clone,
                ).await {
                    tracing::error!("DoH3 connection server worker error: {:?}", e);
                }
            });
            if let Ok(mut lock) = worker_abort_handles.lock() {
                if lock.len() > 256 {
                    lock.retain(|h| !h.is_finished());
                }
                lock.push(worker_task.abort_handle());
            }
            
            if let Err(e) = tx.try_send(packet) {
                let data = match e {
                    mpsc::error::TrySendError::Closed(p) => p.data,
                    mpsc::error::TrySendError::Full(p) => p.data,
                };
                let _ = free_tx.try_send(data);
            }
        }
    }
}

#[cfg(feature = "server-h3")]
struct ServerRequestContext {
    method: String,
    query: Option<String>,
    body: Vec<u8>,
    created_at: Instant,
}

#[cfg(feature = "server-h3")]
async fn run_server_worker(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<QuichePacket>,
    mut conn: quiche::Connection,
    worker_tx: mpsc::Sender<QuichePacket>,
    mut peer_addr: SocketAddr,
    state: Arc<crate::server::ServerState>,
    doh_path: Arc<str>,
    active_connections: Arc<DashMap<CidKey, mpsc::Sender<QuichePacket>>>,
    tracked_cids: Arc<Mutex<Vec<CidKey>>>,
) -> anyhow::Result<()> {
    let _guard = ConnectionGuard {
        active_connections: active_connections.clone(),
        tracked_cids: tracked_cids.clone(),
    };

    let opt = state.opt.clone();
    let limits = H3ResourceLimits::from_opt(&opt);
    let local_addr = socket.local_addr()?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let mut pending_requests = HashMap::<u64, ServerRequestContext>::with_capacity(opt.max_concurrent_queries);
    
    let mut out_buf = vec![0u8; 65535];
    let mut body_buf = vec![0u8; limits.body_buffer_size];
    let mut doq_stream_bufs = HashMap::<u64, (Instant, Vec<u8>)>::new();
    
    let (resp_tx, mut resp_rx) = mpsc::channel::<(u64, Vec<u8>)>(limits.server_resp_channel_capacity);

    let timer = tokio::time::sleep(QUICHE_TIMER_INIT_DURATION);
    tokio::pin!(timer);

    let mut last_cleanup = Instant::now();

    loop {
        let now = Instant::now();
        if now.duration_since(last_cleanup) > STREAM_CLEANUP_INTERVAL {
            last_cleanup = now;
            let timeout_dur = Duration::from_millis(limits.stream_timeout_ms);
            let expired_streams: Vec<u64> = pending_requests
                .iter()
                .filter(|(_, ctx)| now.duration_since(ctx.created_at) > timeout_dur)
                .map(|(&s_id, _)| s_id)
                .collect();

            for stream_id in expired_streams {
                pending_requests.remove(&stream_id);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
            }

            let expired_doq_streams: Vec<u64> = doq_stream_bufs
                .iter()
                .filter(|(_, (created_at, _))| now.duration_since(*created_at) > timeout_dur)
                .map(|(&s_id, _)| s_id)
                .collect();

            for stream_id in expired_doq_streams {
                doq_stream_bufs.remove(&stream_id);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
            }
        }

        let key = cid_to_key(conn.source_id().as_ref());
        if let Ok(mut cids) = tracked_cids.lock() {
            if !cids.contains(&key) {
                active_connections.insert(key, worker_tx.clone());
                cids.push(key);
            }
        }

        let timeout = conn.timeout().unwrap_or(Duration::from_millis(opt.quic_idle_timeout_ms as u64));
        timer.as_mut().reset(tokio::time::Instant::now() + timeout);

        tokio::select! {
            Some(packet) = rx.recv() => {
                let info = quiche::RecvInfo { from: packet.peer, to: local_addr };
                let mut pkt_buf = packet.data;
                
                if packet.peer != peer_addr {
                    peer_addr = packet.peer;
                }

                match conn.recv(&mut pkt_buf[..packet.len], info) {
                    Ok(_) => {
                        if conn.is_established() && h3_conn.is_none() && conn.application_proto() != b"doq" {
                            tracing::info!("QUIC established! Negotiated ALPN: {:?}", String::from_utf8_lossy(conn.application_proto()));
                            let h3_config = create_h3_config(&limits)?;
                            h3_conn = Some(quiche::h3::Connection::with_transport(&mut conn, &h3_config)?);
                        }
                    }
                    Err(e) => {
                        tracing::error!("conn.recv failed: {:?}", e);
                    }
                }

                if conn.is_established() && conn.application_proto() == b"doq" {
                    for stream_id in conn.readable() {
                        while let Ok((read_bytes, fin)) = conn.stream_recv(stream_id, &mut body_buf) {
                            let entry = doq_stream_bufs.entry(stream_id).or_insert_with(|| (Instant::now(), Vec::new()));
                            entry.1.extend_from_slice(&body_buf[..read_bytes]);
                            if entry.1.len() > limits.max_response_size {
                                doq_stream_bufs.remove(&stream_id);
                                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
                                break;
                            }
                            if entry.1.len() >= 2 {
                                let msg_len = u16::from_be_bytes([entry.1[0], entry.1[1]]) as usize;
                                if entry.1.len() >= 2 + msg_len || fin {
                                    let query_data = if entry.1.len() >= 2 + msg_len {
                                        entry.1[2..2 + msg_len].to_vec()
                                    } else {
                                        entry.1[2..].to_vec()
                                    };
                                    doq_stream_bufs.remove(&stream_id);

                                    let permit = match state.global_query_queue.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            tracing::warn!("Dropped DoQ query from {} due to global queue saturation", peer_addr);
                                            continue;
                                        }
                                    };

                                    let state_clone = state.clone();
                                    let resp_tx = resp_tx.clone();
                                    let peer_addr_clone = peer_addr;
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        state_clone.query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                        let req_id = crate::request_id::RequestId::new();

                                        let resp = crate::server::process_query(
                                            &query_data,
                                            &state_clone,
                                            peer_addr_clone,
                                            false,
                                            None,
                                            req_id,
                                        ).await.unwrap_or_else(|| crate::dns::build_servfail(&query_data));
                                        let _ = resp_tx.send((stream_id, resp)).await;
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some(h3) = h3_conn.as_mut() {
                        while let Ok((stream_id, event)) = h3.poll(&mut conn) {
                            match event {
                                quiche::h3::Event::Headers { list, .. } => {
                                    let mut method = None;
                                    let mut path = None;
                                    let mut query = None;
                                    let mut content_type_valid = true;
                                    
                                    for header in list {
                                        let name = header.name();
                                        let value = header.value();
                                        if name == b":method" {
                                            method = Some(String::from_utf8_lossy(value).into_owned());
                                        } else if name == b":path" {
                                            let path_str = String::from_utf8_lossy(value).into_owned();
                                            if let Some((p, q)) = path_str.split_once('?') {
                                                path = Some(p.to_string());
                                                query = Some(q.to_string());
                                            } else {
                                                path = Some(path_str);
                                            }
                                        } else if name == b"content-type" {
                                            if value != b"application/dns-message" {
                                                content_type_valid = false;
                                            }
                                        }
                                    }
                                    
                                    if let (Some(m), Some(p)) = (method, path) {
                                        if p != doh_path.as_ref() {
                                            let res = [
                                                quiche::h3::Header::new(b":status", b"404"),
                                                quiche::h3::Header::new(b"content-length", b"0"),
                                            ];
                                            let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                            continue;
                                        }
                                        if m != "GET" && m != "POST" {
                                            let res = [
                                                quiche::h3::Header::new(b":status", b"400"),
                                                quiche::h3::Header::new(b"content-length", b"0"),
                                            ];
                                            let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                            continue;
                                        }
                                        if m == "POST" && !content_type_valid {
                                            let res = [
                                                quiche::h3::Header::new(b":status", b"415"),
                                                quiche::h3::Header::new(b"content-length", b"0"),
                                            ];
                                            let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                            continue;
                                        }

                                        if pending_requests.len() >= opt.max_concurrent_queries {
                                            let res = [
                                                quiche::h3::Header::new(b":status", b"503"),
                                                quiche::h3::Header::new(b"content-length", b"0"),
                                            ];
                                            let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                            continue;
                                        }

                                        pending_requests.insert(stream_id, ServerRequestContext {
                                            method: m,
                                            query,
                                            body: Vec::new(),
                                            created_at: Instant::now(),
                                        });
                                    }
                                }
                                quiche::h3::Event::Data => {
                                    if let Ok(body_len) = h3.recv_body(&mut conn, stream_id, &mut body_buf) {
                                        if let Some(ctx) = pending_requests.get_mut(&stream_id) {
                                            if ctx.body.len() + body_len > limits.max_response_size {
                                                let res = [
                                                    quiche::h3::Header::new(b":status", b"400"),
                                                    quiche::h3::Header::new(b"content-length", b"0"),
                                                ];
                                                let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                                pending_requests.remove(&stream_id);
                                            } else {
                                                ctx.body.extend_from_slice(&body_buf[..body_len]);
                                            }
                                        }
                                    }
                                }
                                quiche::h3::Event::Finished => {
                                    if let Some(ctx) = pending_requests.remove(&stream_id) {
                                        let query_data = if ctx.method == "GET" {
                                            let mut dns_bytes = Vec::new();
                                            if let Some(q) = ctx.query {
                                                for param in q.split('&') {
                                                    if let Some(dns_val) = param.strip_prefix("dns=") {
                                                        use base64::Engine;
                                                        if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(dns_val) {
                                                            dns_bytes = decoded;
                                                        } else if let Ok(decoded) = base64::engine::general_purpose::URL_SAFE.decode(dns_val) {
                                                            dns_bytes = decoded;
                                                        }
                                                        break;
                                                    }
                                                }
                                            }
                                            dns_bytes
                                        } else {
                                            ctx.body
                                        };
                                        
                                        if query_data.is_empty() {
                                            let res = [
                                                quiche::h3::Header::new(b":status", b"400"),
                                                quiche::h3::Header::new(b"content-length", b"0"),
                                            ];
                                            let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                            continue;
                                        }

                                        let permit = match state.global_query_queue.clone().try_acquire_owned() {
                                            Ok(p) => p,
                                            Err(_) => {
                                                tracing::warn!("Dropped DoH3 query from {} due to global queue saturation", peer_addr);
                                                let res = [
                                                    quiche::h3::Header::new(b":status", b"503"),
                                                    quiche::h3::Header::new(b"content-length", b"0"),
                                                ];
                                                let _ = h3.send_response(&mut conn, stream_id, &res, true);
                                                continue;
                                            }
                                        };
                                        
                                        let state_clone = state.clone();
                                        let resp_tx = resp_tx.clone();
                                        
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            state_clone.query_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                            let req_id = crate::request_id::RequestId::new();
                                            
                                            let resp = crate::server::process_query(
                                                &query_data,
                                                &state_clone,
                                                peer_addr,
                                                false,
                                                None,
                                                req_id,
                                            ).await.unwrap_or_else(|| crate::dns::build_servfail(&query_data));
                                            let _ = resp_tx.send((stream_id, resp)).await;
                                        });
                                    }
                                }
                                quiche::h3::Event::Reset(_) => {
                                    pending_requests.remove(&stream_id);
                                }
                                _ => {}
                            }
                        }
                    }
                let _ = packet.recycle_tx.try_send(pkt_buf);
            }
            Some((stream_id, response_data)) = resp_rx.recv() => {
                if conn.application_proto() == b"doq" {
                    let mut payload = vec![0u8; 2 + response_data.len()];
                    payload[0..2].copy_from_slice(&(response_data.len() as u16).to_be_bytes());
                    payload[2..].copy_from_slice(&response_data);
                    let _ = conn.stream_send(stream_id, &payload, true);
                } else if let Some(h3) = h3_conn.as_mut() {
                    let mut len_buf = itoa::Buffer::new();
                    let content_len_bytes = len_buf.format(response_data.len()).as_bytes();
                    let headers = [
                        quiche::h3::Header::new(b":status", b"200"),
                        quiche::h3::Header::new(b"content-type", b"application/dns-message"),
                        quiche::h3::Header::new(b"content-length", content_len_bytes),
                        quiche::h3::Header::new(b"cache-control", b"max-age=0"),
                        quiche::h3::Header::new(b"access-control-allow-origin", b"*"),
                    ];
                    match h3.send_response(&mut conn, stream_id, &headers, false) {
                        Ok(_) => {
                            tracing::debug!("h3.send_response succeeded for stream {}", stream_id);
                            match h3.send_body(&mut conn, stream_id, &response_data, true) {
                                Ok(sent_bytes) => {
                                    tracing::debug!("h3.send_body succeeded for stream {}, wrote {} bytes", stream_id, sent_bytes);
                                }
                                Err(e) => {
                                    tracing::error!("h3.send_body failed for stream {}: {:?}", stream_id, e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("h3.send_response failed for stream {}: {:?}", stream_id, e);
                        }
                    }
                } else {
                    tracing::error!("h3_conn is None when trying to send response for stream {}", stream_id);
                }

                let stats = conn.stats();
                let mut cwnd = 0;
                let mut rtt = Duration::ZERO;
                if let Some(path) = conn.path_stats().next() {
                    cwnd = path.cwnd;
                    rtt = path.rtt;
                }
                tracing::debug!(
                    "QUIC Connection stats: established={}, closed={}, sent={}, recv={}, lost={}, retrans={}, cwnd={}, rtt={:?}",
                    conn.is_established(),
                    conn.is_closed(),
                    stats.sent,
                    stats.recv,
                    stats.lost,
                    stats.retrans,
                    cwnd,
                    rtt
                );
            }
            _ = &mut timer => {
                conn.on_timeout();
            }
        }

        loop {
            match conn.send(&mut out_buf) {
                Ok((write_len, send_info)) => {
                    if let Err(e) = socket.send_to(&out_buf[..write_len], send_info.to).await {
                        tracing::error!("socket.send_to failed to {}: {:?}", send_info.to, e);
                    } else {
                        tracing::debug!("socket.send_to sent {} bytes to {}", write_len, send_info.to);
                    }
                }
                Err(quiche::Error::Done) => {
                    break;
                }
                Err(e) => {
                    tracing::error!("conn.send failed: {:?}", e);
                    break;
                }
            }
        }

        if conn.is_closed() {
            break;
        }
    }
    
    let _ = conn.close(true, 0x00, b"graceful shutdown");
    while let Ok((write_len, send_info)) = conn.send(&mut out_buf) {
        let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
    }
    Ok(())
}
