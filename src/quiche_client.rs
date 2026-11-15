use lru::LruCache;
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};


pub const QUICHE_CLIENT_TIMER_INIT_DURATION: Duration = Duration::from_millis(50);

pub struct QuicheRequest {
    pub host: String,
    pub path: String,
    pub body: bytes::Bytes,
    pub timeout: Duration,
    pub resp_tx: oneshot::Sender<Result<Vec<u8>, String>>,
    pub created_at: Instant,
}

pub struct QuichePool {
    config: Arc<Mutex<quiche::Config>>,
    opt: Arc<crate::opt::Opt>,
    session_tickets: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    active_workers: DashMap<SocketAddr, mpsc::Sender<QuicheRequest>>,
}

use dashmap::DashMap;

impl QuichePool {
    pub fn new(config: quiche::Config, opt: Arc<crate::opt::Opt>) -> Self {
        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
        let cap = NonZeroUsize::new(limits.session_cache_limit).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            config: Arc::new(Mutex::new(config)),
            opt,
            session_tickets: Arc::new(Mutex::new(LruCache::new(cap))),
            active_workers: DashMap::new(),
        }
    }

    pub async fn get_or_create(
        &self,
        peer_addr: SocketAddr,
        bind_addr: SocketAddr,
        server_name: Option<&str>,
        mark: Option<u32>,
    ) -> Result<mpsc::Sender<QuicheRequest>, String> {
        if let Some(worker) = self.active_workers.get(&peer_addr) {
            if !worker.is_closed() {
                return Ok(worker.clone());
            } else {
                drop(worker);
                self.active_workers.remove(&peer_addr);
            }
        }

        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&self.opt);
        let (tx, rx) = mpsc::channel::<QuicheRequest>(limits.client_max_pending);

        let socket = crate::quiche_server::create_tuned_udp_socket(bind_addr, mark, &self.opt)
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
        let socket = Arc::new(socket);

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut scid);
        let scid = quiche::ConnectionId::from_ref(&scid);

        let clean_server_name = server_name.filter(|&name| {
            name.parse::<std::net::IpAddr>().is_err()
        });

        let mut conn = {
            let mut locked_config = self.config.lock().unwrap_or_else(|e| e.into_inner());
            locked_config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
                .map_err(|e| format!("Config error: {}", e))?;
            quiche::connect(clean_server_name, &scid, bind_addr, peer_addr, &mut locked_config)
                .map_err(|e| format!("Quiche connect error: {}", e))?
        };

        if let Some(sni) = clean_server_name {
            if let Ok(mut tickets) = self.session_tickets.lock() {
                if let Some(ticket) = tickets.get(sni) {
                    let _ = conn.set_session(ticket);
                }
            }
        }

        let opt_clone = self.opt.clone();
        let session_tickets_clone = self.session_tickets.clone();
        let server_name_owned = clean_server_name.map(|s| s.to_string());
        let active_workers_clone = self.active_workers.clone();

        active_workers_clone.insert(peer_addr, tx.clone());

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let _guard = ClientGuard {
                active_workers: active_workers_clone,
                peer_addr,
                tx: tx_clone,
            };
            let _ = run_client_worker(
                socket,
                rx,
                conn,
                peer_addr,
                server_name_owned,
                session_tickets_clone,
                opt_clone,
            )
            .await;
        });

        Ok(tx)
    }
}

struct ClientGuard {
    active_workers: DashMap<SocketAddr, mpsc::Sender<QuicheRequest>>,
    peer_addr: SocketAddr,
    tx: mpsc::Sender<QuicheRequest>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.active_workers.remove_if(&self.peer_addr, |_, sender| sender.same_channel(&self.tx));
    }
}

struct RequestContext {
    resp_tx: oneshot::Sender<Result<Vec<u8>, String>>,
    created_at: Instant,
    timeout: Duration,
}

async fn run_client_worker(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<QuicheRequest>,
    mut conn: quiche::Connection,
    _peer_addr: SocketAddr,
    server_name: Option<String>,
    session_tickets: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    opt: Arc<crate::opt::Opt>,
) -> Result<(), String> {
    let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
    let mut h3_conn: Option<quiche::h3::Connection> = None;
    let mut pending_requests = HashMap::<u64, RequestContext>::new();

    let mut out_buf = vec![0u8; limits.max_udp_payload_size];
    let mut recv_pkt_buf = vec![0u8; limits.max_udp_payload_size];
    let mut body_buf = vec![0u8; limits.body_buffer_size];
    let mut resp_bodies = HashMap::<u64, Vec<u8>>::new();

    let timer = tokio::time::sleep(QUICHE_CLIENT_TIMER_INIT_DURATION);
    tokio::pin!(timer);

    let mut uninitialized_requests: Vec<QuicheRequest> = Vec::new();

    while let Ok((write_len, send_info)) = conn.send(&mut out_buf) {
        let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
    }

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(opt.tcp_idle_timeout_ms as u64));
        timer.as_mut().reset(tokio::time::Instant::now() + timeout);

        tokio::select! {
            Some(req) = rx.recv() => {
                if conn.is_established() && h3_conn.is_none() {
                    if let Ok(h3_config) = crate::quiche_server::create_h3_config(&limits) {
                        h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config).ok();
                    }
                }

                if let Some(h3) = h3_conn.as_mut() {
                    let mut len_buf = itoa::Buffer::new();
                    let content_len_bytes = len_buf.format(req.body.len()).as_bytes();
                    let headers = vec![
                        quiche::h3::Header::new(b":method", b"POST"),
                        quiche::h3::Header::new(b":scheme", b"https"),
                        quiche::h3::Header::new(b":authority", req.host.as_bytes()),
                        quiche::h3::Header::new(b":path", req.path.as_bytes()),
                        quiche::h3::Header::new(b"content-type", b"application/dns-message"),
                        quiche::h3::Header::new(b"content-length", content_len_bytes),
                        quiche::h3::Header::new(b"accept", b"application/dns-message"),
                        quiche::h3::Header::new(b"user-agent", opt.user_agent.as_bytes()),
                    ];

                    match h3.send_request(&mut conn, &headers, false) {
                        Ok(stream_id) => {
                            let _ = h3.send_body(&mut conn, stream_id, &req.body, true);
                            pending_requests.insert(stream_id, RequestContext {
                                resp_tx: req.resp_tx,
                                created_at: req.created_at,
                                timeout: req.timeout,
                            });
                        }
                        Err(e) => {
                            let _ = req.resp_tx.send(Err(format!("H3 send_request error: {:?}", e)));
                        }
                    }
                } else {
                    uninitialized_requests.push(req);
                }
            }

            result = socket.recv_from(&mut recv_pkt_buf) => {
                match result {
                    Ok((len, from)) => {
                        let info = quiche::RecvInfo { from, to: local_addr };
                        if let Ok(_) = conn.recv(&mut recv_pkt_buf[..len], info) {
                            if conn.is_established() && h3_conn.is_none() {
                                if let Ok(h3_config) = crate::quiche_server::create_h3_config(&limits) {
                                    h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config).ok();
                                }
                            }

                            if let Some(h3) = h3_conn.as_mut() {
                                if !uninitialized_requests.is_empty() {
                                    let pending_uninit = std::mem::take(&mut uninitialized_requests);
                                    for req in pending_uninit {
                                        let mut len_buf = itoa::Buffer::new();
                                        let content_len_bytes = len_buf.format(req.body.len()).as_bytes();
                                        let headers = vec![
                                            quiche::h3::Header::new(b":method", b"POST"),
                                            quiche::h3::Header::new(b":scheme", b"https"),
                                            quiche::h3::Header::new(b":authority", req.host.as_bytes()),
                                            quiche::h3::Header::new(b":path", req.path.as_bytes()),
                                            quiche::h3::Header::new(b"content-type", b"application/dns-message"),
                                            quiche::h3::Header::new(b"content-length", content_len_bytes),
                                            quiche::h3::Header::new(b"accept", b"application/dns-message"),
                                            quiche::h3::Header::new(b"user-agent", opt.user_agent.as_bytes()),
                                        ];

                                        match h3.send_request(&mut conn, &headers, false) {
                                            Ok(stream_id) => {
                                                let _ = h3.send_body(&mut conn, stream_id, &req.body, true);
                                                pending_requests.insert(stream_id, RequestContext {
                                                    resp_tx: req.resp_tx,
                                                    created_at: req.created_at,
                                                    timeout: req.timeout,
                                                });
                                            }
                                            Err(e) => {
                                                let _ = req.resp_tx.send(Err(format!("H3 send_request error: {:?}", e)));
                                            }
                                        }
                                    }
                                }

                                while let Ok((stream_id, event)) = h3.poll(&mut conn) {
                                    match event {
                                        quiche::h3::Event::Headers { list, .. } => {
                                            if !pending_requests.contains_key(&stream_id) {
                                                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                                continue;
                                            }
                                            let mut status = None;
                                            let mut content_type_valid = true;
                                            for header in list {
                                                let name = header.name();
                                                let value = header.value();
                                                if name == b":status" {
                                                    status = std::str::from_utf8(value).ok().and_then(|s| s.parse::<u16>().ok());
                                                } else if name == b"content-type" {
                                                    if !value.starts_with(b"application/dns-message") {
                                                        content_type_valid = false;
                                                    }
                                                }
                                            }
                                            if let Some(s) = status {
                                                if s != 200 {
                                                    resp_bodies.remove(&stream_id);
                                                    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                                    if let Some(ctx) = pending_requests.remove(&stream_id) {
                                                        let _ = ctx.resp_tx.send(Err(format!("DoH3 response status: HTTP {}", s)));
                                                    }
                                                } else if !content_type_valid {
                                                    resp_bodies.remove(&stream_id);
                                                    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                                    if let Some(ctx) = pending_requests.remove(&stream_id) {
                                                        let _ = ctx.resp_tx.send(Err("DoH3 invalid content-type".to_string()));
                                                    }
                                                }
                                            }
                                        }
                                        quiche::h3::Event::Data => {
                                            if !pending_requests.contains_key(&stream_id) {
                                                let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                                resp_bodies.remove(&stream_id);
                                                continue;
                                            }
                                            if let Ok(read_bytes) = h3.recv_body(&mut conn, stream_id, &mut body_buf) {
                                                let entry = resp_bodies.entry(stream_id).or_insert_with(Vec::new);
                                                if entry.len() + read_bytes <= limits.max_response_size {
                                                    entry.extend_from_slice(&body_buf[..read_bytes]);
                                                }
                                            }
                                        }
                                        quiche::h3::Event::Finished => {
                                            let body = resp_bodies.remove(&stream_id).unwrap_or_default();
                                            if let Some(ctx) = pending_requests.remove(&stream_id) {
                                                let _ = ctx.resp_tx.send(Ok(body));
                                            }
                                        }
                                        quiche::h3::Event::Reset(err) => {
                                            resp_bodies.remove(&stream_id);
                                            if let Some(ctx) = pending_requests.remove(&stream_id) {
                                                let _ = ctx.resp_tx.send(Err(format!("Stream reset with error code {}", err)));
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Client socket receive error: {}", e);
                    }
                }
            }

            _ = &mut timer => {
                conn.on_timeout();

                let now = Instant::now();
                let expired_streams: Vec<(u64, Duration)> = pending_requests
                    .iter()
                    .filter(|(_, ctx)| now.duration_since(ctx.created_at) > ctx.timeout)
                    .map(|(&s_id, ctx)| (s_id, ctx.timeout))
                    .collect();

                for (stream_id, timeout_dur) in expired_streams {
                    if let Some(ctx) = pending_requests.remove(&stream_id) {
                        resp_bodies.remove(&stream_id);
                        let _ = ctx.resp_tx.send(Err(format!("Request timed out after {:?}", timeout_dur)));
                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
                    }
                }

                let mut remaining_uninit = Vec::with_capacity(uninitialized_requests.len());
                for req in uninitialized_requests.drain(..) {
                    if now.duration_since(req.created_at) > req.timeout {
                        let _ = req.resp_tx.send(Err(format!(
                            "DoH3 request timed out after {:?} waiting for connection establishment",
                            req.timeout
                        )));
                    } else {
                        remaining_uninit.push(req);
                    }
                }
                uninitialized_requests = remaining_uninit;
            }
        }

        while let Ok((write_len, send_info)) = conn.send(&mut out_buf) {
            let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
        }

        if conn.is_closed() {
            if let Some(ticket) = conn.session() {
                if let Some(sni) = &server_name {
                    if let Ok(mut tickets) = session_tickets.lock() {
                        tickets.put(sni.clone(), ticket.to_vec());
                    }
                }
            }
            break;
        }
    }

    for req in uninitialized_requests {
        let _ = req.resp_tx.send(Err("DoH3 connection closed before establishment".to_string()));
    }
    for (_, ctx) in pending_requests {
        let _ = ctx.resp_tx.send(Err("DoH3 connection closed before response received".to_string()));
    }
    while let Ok(req) = rx.try_recv() {
        let _ = req.resp_tx.send(Err("DoH3 client worker terminated".to_string()));
    }

    Ok(())
}

pub struct QuicheDoqRequest {
    pub body: bytes::Bytes,
    pub timeout: Duration,
    pub resp_tx: oneshot::Sender<Result<Vec<u8>, String>>,
    pub created_at: Instant,
}

pub struct QuicheDoqPool {
    config: Arc<Mutex<quiche::Config>>,
    opt: Arc<crate::opt::Opt>,
    session_tickets: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    active_workers: DashMap<SocketAddr, mpsc::Sender<QuicheDoqRequest>>,
}

impl QuicheDoqPool {
    pub fn new(config: quiche::Config, opt: Arc<crate::opt::Opt>) -> Self {
        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
        let cap = NonZeroUsize::new(limits.session_cache_limit).unwrap_or(NonZeroUsize::new(1024).unwrap());
        Self {
            config: Arc::new(Mutex::new(config)),
            opt,
            session_tickets: Arc::new(Mutex::new(LruCache::new(cap))),
            active_workers: DashMap::new(),
        }
    }

    pub async fn get_or_create(
        &self,
        peer_addr: SocketAddr,
        bind_addr: SocketAddr,
        server_name: Option<&str>,
        mark: Option<u32>,
    ) -> Result<mpsc::Sender<QuicheDoqRequest>, String> {
        if let Some(worker) = self.active_workers.get(&peer_addr) {
            if !worker.is_closed() {
                return Ok(worker.clone());
            } else {
                drop(worker);
                self.active_workers.remove(&peer_addr);
            }
        }

        let limits = crate::quiche_server::H3ResourceLimits::from_opt(&self.opt);
        let (tx, rx) = mpsc::channel::<QuicheDoqRequest>(limits.client_max_pending);

        let socket = crate::quiche_server::create_tuned_udp_socket(bind_addr, mark, &self.opt)
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
        let local_addr = socket.local_addr().map_err(|e| format!("Local addr error: {}", e))?;
        let socket = Arc::new(socket);

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut scid);
        let scid = quiche::ConnectionId::from_ref(&scid);

        let clean_server_name = server_name.filter(|&name| {
            name.parse::<std::net::IpAddr>().is_err()
        });

        let mut conn = {
            let mut locked_config = self.config.lock().unwrap_or_else(|e| e.into_inner());
            locked_config.set_application_protos(&[b"doq"])
                .map_err(|e| format!("Config error: {}", e))?;
            quiche::connect(clean_server_name, &scid, local_addr, peer_addr, &mut locked_config)
                .map_err(|e| format!("Quiche connect error: {}", e))?
        };

        if let Some(sni) = clean_server_name {
            if let Ok(mut tickets) = self.session_tickets.lock() {
                if let Some(ticket) = tickets.get(sni) {
                    let _ = conn.set_session(ticket);
                }
            }
        }

        let opt_clone = self.opt.clone();
        let session_tickets_clone = self.session_tickets.clone();
        let server_name_owned = clean_server_name.map(|s| s.to_string());
        let active_workers_clone = self.active_workers.clone();

        active_workers_clone.insert(peer_addr, tx.clone());

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            struct DoqClientGuard {
                active_workers: DashMap<SocketAddr, mpsc::Sender<QuicheDoqRequest>>,
                peer_addr: SocketAddr,
                tx: mpsc::Sender<QuicheDoqRequest>,
            }
            impl Drop for DoqClientGuard {
                fn drop(&mut self) {
                    self.active_workers.remove_if(&self.peer_addr, |_, sender| sender.same_channel(&self.tx));
                }
            }
            let _guard = DoqClientGuard {
                active_workers: active_workers_clone,
                peer_addr,
                tx: tx_clone,
            };
            let _ = run_doq_client_worker(
                socket,
                rx,
                conn,
                peer_addr,
                server_name_owned,
                session_tickets_clone,
                opt_clone,
            )
            .await;
        });

        Ok(tx)
    }
}

async fn run_doq_client_worker(
    socket: Arc<UdpSocket>,
    mut rx: mpsc::Receiver<QuicheDoqRequest>,
    mut conn: quiche::Connection,
    _peer_addr: SocketAddr,
    server_name: Option<String>,
    session_tickets: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    opt: Arc<crate::opt::Opt>,
) -> Result<(), String> {
    let limits = crate::quiche_server::H3ResourceLimits::from_opt(&opt);
    let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
    let mut pending_requests = HashMap::<u64, RequestContext>::new();
    let mut next_stream_id: u64 = 0;

    let mut out_buf = vec![0u8; limits.max_udp_payload_size];
    let mut recv_pkt_buf = vec![0u8; limits.max_udp_payload_size];
    let mut stream_read_buf = vec![0u8; limits.max_response_size];
    let mut resp_bodies = HashMap::<u64, Vec<u8>>::new();

    let timer = tokio::time::sleep(QUICHE_CLIENT_TIMER_INIT_DURATION);
    tokio::pin!(timer);

    let mut queued_requests = std::collections::VecDeque::<(u64, QuicheDoqRequest)>::new();

    while let Ok((write_len, send_info)) = conn.send(&mut out_buf) {
        let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
    }

    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(opt.quic_idle_timeout_ms as u64));
        timer.as_mut().reset(tokio::time::Instant::now() + timeout);

        tokio::select! {
            Some(req) = rx.recv() => {
                tracing::debug!("DoQ worker: received request, conn.is_established={}, conn.is_closed={}", conn.is_established(), conn.is_closed());
                let stream_id = next_stream_id;
                next_stream_id += 4;

                if !conn.is_established() {
                    tracing::debug!("DoQ worker: connection not yet established, queuing request stream_id={}", stream_id);
                    queued_requests.push_back((stream_id, req));
                } else {
                    let mut payload = Vec::with_capacity(2 + req.body.len());
                    payload.extend_from_slice(&(req.body.len() as u16).to_be_bytes());
                    payload.extend_from_slice(&req.body);
                    match conn.stream_send(stream_id, &payload, true) {
                        Ok(_) => {
                            tracing::debug!("DoQ worker: stream_send OK for stream_id={}", stream_id);
                            pending_requests.insert(stream_id, RequestContext {
                                resp_tx: req.resp_tx,
                                created_at: req.created_at,
                                timeout: req.timeout,
                            });
                        }
                        Err(quiche::Error::StreamLimit) | Err(quiche::Error::Done) => {
                            tracing::debug!("DoQ worker: stream_send StreamLimit/Done for stream_id={}, queuing", stream_id);
                            queued_requests.push_back((stream_id, req));
                        }
                        Err(e) => {
                            tracing::debug!("DoQ worker: stream_send error for stream_id={}: {:?}", stream_id, e);
                            let _ = req.resp_tx.send(Err(format!("Failed to send stream on DoQ connection: {:?}", e)));
                        }
                    }
                }
            }

            result = socket.recv_from(&mut recv_pkt_buf) => {
                match result {
                    Ok((len, from)) => {
                        let info = quiche::RecvInfo { from, to: local_addr };
                        match conn.recv(&mut recv_pkt_buf[..len], info) {
                            Ok(_) => {
                                tracing::debug!("DoQ worker: recv OK, is_established={}, is_closed={}, queued={}", conn.is_established(), conn.is_closed(), queued_requests.len());
                            }
                            Err(e) => {
                                tracing::debug!("DoQ worker: recv error: {:?}, is_closed={}", e, conn.is_closed());
                            }
                        }

                        if conn.is_established() {
                            while let Some((stream_id, req)) = queued_requests.pop_front() {
                                let mut payload = Vec::with_capacity(2 + req.body.len());
                                payload.extend_from_slice(&(req.body.len() as u16).to_be_bytes());
                                payload.extend_from_slice(&req.body);
                                match conn.stream_send(stream_id, &payload, true) {
                                    Ok(_) => {
                                        tracing::debug!("DoQ worker: dequeued and sent stream_id={}", stream_id);
                                        pending_requests.insert(stream_id, RequestContext {
                                            resp_tx: req.resp_tx,
                                            created_at: req.created_at,
                                            timeout: req.timeout,
                                        });
                                    }
                                    Err(quiche::Error::StreamLimit) | Err(quiche::Error::Done) => {
                                        queued_requests.push_front((stream_id, req));
                                        break;
                                    }
                                    Err(e) => {
                                        let _ = req.resp_tx.send(Err(format!("Failed to send stream on DoQ connection: {:?}", e)));
                                    }
                                }
                            }

                            for stream_id in conn.readable() {
                                tracing::debug!("DoQ worker: readable stream_id={}", stream_id);
                                if !pending_requests.contains_key(&stream_id) {
                                    while let Ok((_, _)) = conn.stream_recv(stream_id, &mut stream_read_buf) {}
                                    let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                    resp_bodies.remove(&stream_id);
                                    continue;
                                }
                                while let Ok((read_bytes, fin)) = conn.stream_recv(stream_id, &mut stream_read_buf) {
                                    let entry = resp_bodies.entry(stream_id).or_insert_with(Vec::new);
                                    if entry.len() + read_bytes > limits.max_response_size {
                                        resp_bodies.remove(&stream_id);
                                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
                                        if let Some(ctx) = pending_requests.remove(&stream_id) {
                                            let _ = ctx.resp_tx.send(Err(format!(
                                                "DoQ response exceeded max response size limit ({} bytes)",
                                                limits.max_response_size
                                            )));
                                        }
                                        break;
                                    }
                                    entry.extend_from_slice(&stream_read_buf[..read_bytes]);
                                    tracing::debug!("DoQ worker: stream_recv stream_id={}, read_bytes={}, fin={}, total={}", stream_id, read_bytes, fin, entry.len());

                                    if fin {
                                        let body = resp_bodies.remove(&stream_id).unwrap_or_default();
                                        if let Some(ctx) = pending_requests.remove(&stream_id) {
                                            let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x00);
                                            if body.len() < 14 {
                                                let _ = ctx.resp_tx.send(Err(format!(
                                                    "DoQ response truncated on FIN: received {} bytes, expected at least 14 (2-octet length + DNS header)",
                                                    body.len()
                                                )));
                                            } else {
                                                let msg_len = u16::from_be_bytes([body[0], body[1]]) as usize;
                                                let response_data = if body.len() >= 2 + msg_len {
                                                    body[2..2 + msg_len].to_vec()
                                                } else {
                                                    body[2..].to_vec()
                                                };
                                                tracing::debug!("DoQ worker: sending response for stream_id={}, body_len={}", stream_id, response_data.len());
                                                let _ = ctx.resp_tx.send(Ok(response_data));
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("DoQ client socket receive error: {}", e);
                    }
                }
            }

            _ = &mut timer => {
                conn.on_timeout();

                let now = Instant::now();
                let expired_streams: Vec<(u64, Duration)> = pending_requests
                    .iter()
                    .filter(|(_, ctx)| now.duration_since(ctx.created_at) > ctx.timeout)
                    .map(|(&s_id, ctx)| (s_id, ctx.timeout))
                    .collect();

                for (stream_id, timeout_dur) in expired_streams {
                    if let Some(ctx) = pending_requests.remove(&stream_id) {
                        resp_bodies.remove(&stream_id);
                        let _ = ctx.resp_tx.send(Err(format!("Request timed out after {:?}", timeout_dur)));
                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0x01);
                        let _ = conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0x01);
                    }
                }

                let mut remaining_queued = std::collections::VecDeque::new();
                while let Some((stream_id, req)) = queued_requests.pop_front() {
                    if now.duration_since(req.created_at) > req.timeout {
                        let _ = req.resp_tx.send(Err(format!(
                            "DoQ request timed out after {:?} waiting for connection establishment / stream quota",
                            req.timeout
                        )));
                    } else {
                        remaining_queued.push_back((stream_id, req));
                    }
                }
                queued_requests = remaining_queued;
            }
        }

        let mut client_sent = 0;
        while let Ok((write_len, send_info)) = conn.send(&mut out_buf) {
            let _ = socket.send_to(&out_buf[..write_len], send_info.to).await;
            client_sent += 1;
        }
        if client_sent > 0 {
            tracing::debug!("DoQ worker: sent {} packets, is_established={}, is_closed={}", client_sent, conn.is_established(), conn.is_closed());
        }

        if conn.is_closed() {
            tracing::debug!("DoQ worker: connection closed, pending={}, queued={}", pending_requests.len(), queued_requests.len());
            if let Some(ticket) = conn.session() {
                if let Some(sni) = &server_name {
                    if let Ok(mut tickets) = session_tickets.lock() {
                        tickets.put(sni.clone(), ticket.to_vec());
                    }
                }
            }
            break;
        }
    }

    for (_, req) in queued_requests {
        let _ = req.resp_tx.send(Err("DoQ connection closed before establishment".to_string()));
    }
    for (_, ctx) in pending_requests {
        let _ = ctx.resp_tx.send(Err("DoQ connection closed before response received".to_string()));
    }
    while let Ok(req) = rx.try_recv() {
        let _ = req.resp_tx.send(Err("DoQ client worker terminated".to_string()));
    }

    Ok(())
}
