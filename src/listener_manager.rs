use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing;

use crate::iface_watcher::IfaceEvent;
use crate::utils::{
    configure_listener_socket, is_addr_in_use, is_addr_not_available, is_loopback_target,
    resolve_scope_id,
};
use crate::server::ServerState;

pub const IFACE_DEBOUNCE_DURATION: std::time::Duration = std::time::Duration::from_millis(200);
pub const GRACEFUL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
pub const MAX_PORT_BACKOFF_RETRIES: u32 = 10;
pub const INITIAL_PORT_BACKOFF_MS: u64 = 100;
pub const MAX_PORT_BACKOFF_MS: u64 = 3200;

#[cfg(feature = "rustls-stack")]
use tokio_rustls::TlsAcceptor;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use boring::ssl::SslAcceptor;

#[allow(dead_code)]
#[cfg(feature = "rustls-stack")]
pub(crate) type ServerTlsAcceptor = TlsAcceptor;
#[allow(dead_code)]
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub(crate) type ServerTlsAcceptor = Arc<SslAcceptor>;
#[allow(dead_code)]
#[cfg(not(any(feature = "rustls-stack", feature = "boring")))]
pub(crate) type ServerTlsAcceptor = ();

pub(crate) struct ServerDependencies {
    pub(crate) state: Option<Arc<ServerState>>,
    #[cfg(feature = "server-dot")]
    pub(crate) dot_acceptor: Option<ServerTlsAcceptor>,
    #[cfg(feature = "server-doh")]
    pub(crate) doh_acceptor: Option<ServerTlsAcceptor>,
    #[cfg(any(feature = "server-doh", feature = "server-h3"))]
    pub(crate) doh_path: Option<Arc<str>>,
    
    #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
    pub(crate) quinn_doh3_config: Option<quinn::ServerConfig>,
    #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
    pub(crate) quinn_doq_config: Option<quinn::ServerConfig>,
}

impl ServerDependencies {
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            state: None,
            #[cfg(feature = "server-dot")]
            dot_acceptor: None,
            #[cfg(feature = "server-doh")]
            doh_acceptor: None,
            #[cfg(any(feature = "server-doh", feature = "server-h3"))]
            doh_path: None,
            #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
            quinn_doh3_config: None,
            #[cfg(all(feature = "server-h3", feature = "original-h3-server"))]
            quinn_doq_config: None,
        }
    }
}

/// Supported server listener protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolKind {
    PlainUdp,
    PlainTcp,
    DoT,
    DoH,
    DoH3,
    DoQ,
}

/// Unique key identifying a socket target definition
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketKey {
    pub addr: SocketAddr,
    pub protocol: ProtocolKind,
    pub iface: Option<String>,
    pub scope_id: Option<u32>,
    pub scope_name: Option<String>, // To retain names for dynamic lookup (e.g. "eth0")
}

impl SocketKey {
    pub fn new(addr: SocketAddr, protocol: ProtocolKind, iface: Option<String>) -> Self {
        Self {
            addr,
            protocol,
            iface,
            scope_id: None,
            scope_name: None,
        }
    }
}

/// Deterministic state machine states for registered socket targets
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerState {
    Unbound,
    Active { generation_id: u64 },
    Pending,
    Retrying { attempt: u32 },
    Debouncing { generation_id: u64 },
    GracefulDrain { generation_id: u64 },
}

pub struct ActiveDebounce {
    pub generation_id: u64,
    pub cancel_token: CancellationToken,
    pub timer_handle: JoinHandle<()>,
}

impl Drop for ActiveDebounce {
    fn drop(&mut self) {
        self.cancel_token.cancel();
        self.timer_handle.abort();
    }
}

pub struct ListenerHandle {
    pub key: SocketKey,
    pub generation_id: u64,
    pub abort_handles: Vec<AbortHandle>,
    pub worker_abort_handles: Arc<std::sync::Mutex<Vec<AbortHandle>>>,
    pub spawned_at: Instant,
    pub shutdown_tx: Option<oneshot::Sender<()>>,
}

impl ListenerHandle {
    pub fn abort_all(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        for h in &self.abort_handles {
            h.abort();
        }
        if let Ok(workers) = self.worker_abort_handles.lock() {
            for h in workers.iter() {
                h.abort();
            }
        }
    }
}

impl Drop for ListenerHandle {
    fn drop(&mut self) {
        self.abort_all();
    }
}

pub(crate) struct ListenerManager {
    generation_counter: u64,
    targets: Arc<Mutex<HashMap<SocketKey, ListenerState>>>,
    handles: HashMap<SocketKey, ListenerHandle>,
    debounces: HashMap<SocketKey, ActiveDebounce>,
    iface_addr_map: HashMap<String, Vec<std::net::IpAddr>>,
    tx: mpsc::Sender<IfaceEvent>,
    deps: ServerDependencies,
}

impl Drop for ListenerManager {
    fn drop(&mut self) {
        for (_, mut handle) in self.handles.drain() {
            handle.abort_all();
        }
        self.debounces.clear();
    }
}

impl ListenerManager {
    pub(crate) fn new(
        configured_targets: Vec<SocketKey>,
        tx: mpsc::Sender<IfaceEvent>,
        deps: ServerDependencies,
    ) -> Self {
        let mut map = HashMap::new();
        for key in configured_targets {
            tracing::info!(
                target = %key.addr,
                protocol = ?key.protocol,
                interface = ?key.iface,
                "Registered target listener"
            );
            map.insert(key, ListenerState::Unbound);
        }
        Self {
            generation_counter: 1,
            targets: Arc::new(Mutex::new(map)),
            handles: HashMap::new(),
            debounces: HashMap::new(),
            iface_addr_map: HashMap::new(),
            tx,
            deps,
        }
    }

    pub(crate) async fn run(&mut self, mut rx: mpsc::Receiver<IfaceEvent>) {
        // Perform initial bootstrap evaluation & bind attempt for all configured targets
        self.evaluate_all_targets().await;

        while let Some(event) = rx.recv().await {
            let mut batch = vec![event];
            // Event batching to prevent churn processing storms
            while let Ok(next_event) = rx.try_recv() {
                batch.push(next_event);
            }

            for evt in batch {
                self.dispatch_event(evt).await;
            }
        }
    }

    pub async fn dispatch_event(&mut self, event: IfaceEvent) {
        match event {
            IfaceEvent::AddressAdded {
                iface,
                iface_label,
                addr,
                is_deprecated,
                ..
            } => {
                let resolved_iface = if iface.starts_with("ifindex_") {
                    iface_label.unwrap_or(iface)
                } else {
                    iface
                };
                let entry = self.iface_addr_map.entry(resolved_iface.clone()).or_default();
                if !entry.contains(&addr) {
                    entry.push(addr);
                }

                if is_deprecated {
                    tracing::warn!(
                        %addr,
                        iface = %resolved_iface,
                        "IPv6 address is SLAAC deprecated; keeping existing sockets without triggering new bind"
                    );
                    return;
                }
                self.handle_address_added(&resolved_iface, addr).await;
            }
            IfaceEvent::AddressRemoved { iface, iface_label, addr, .. } => {
                let resolved_iface = if iface.starts_with("ifindex_") {
                    iface_label.unwrap_or(iface)
                } else {
                    iface
                };
                if let Some(entry) = self.iface_addr_map.get_mut(&resolved_iface) {
                    entry.retain(|&a| a != addr);
                }
                self.handle_address_removed(&resolved_iface, addr).await;
            }
            IfaceEvent::InterfaceStateChanged { iface, is_up, .. } => {
                if is_up {
                    self.handle_interface_up(&iface).await;
                } else {
                    self.handle_interface_down(&iface).await;
                }
            }
            IfaceEvent::InterfaceIndexChanged {
                iface, new_ifindex, ..
            } => {
                tracing::info!(
                    %iface,
                    %new_ifindex,
                    "Interface index churn detected; re-binding listeners"
                );
                self.handle_interface_up(&iface).await;
            }
            IfaceEvent::ResyncRequired => {
                tracing::warn!("ResyncRequired signal received; executing complete target re-evaluation");
                self.evaluate_all_targets().await;
            }
            IfaceEvent::DebounceTimeout { key, generation_id } => {
                self.handle_debounce_timeout(key, generation_id).await;
            }
            IfaceEvent::RetryTimeout { key, attempt } => {
                self.handle_retry_timeout(key, attempt).await;
            }
            _ => {}
        }
    }

    fn generate_keys_for_addr(&self, addr: std::net::IpAddr, iface: Option<String>) -> Vec<SocketKey> {
        let mut keys = Vec::new();
        let state = match &self.deps.state {
            Some(s) => s,
            None => {
                let sa = SocketAddr::new(addr, 0);
                keys.push(SocketKey::new(sa, ProtocolKind::PlainUdp, iface.clone()));
                keys.push(SocketKey::new(sa, ProtocolKind::PlainTcp, iface));
                return keys;
            }
        };
        let opt = &state.opt;

        let has_tls_specific = !opt.tls_interface.is_empty()
            || !opt.tls_bind_addr.is_empty()
            || opt.tls_bind_interfaces
            || opt.tls_bind_dynamic;
        let tls_interface_list = if has_tls_specific { &opt.tls_interface } else { &opt.interface };

        let parse_ip = |s: &String| -> Option<std::net::IpAddr> {
            s.split('%').next().unwrap_or(s).parse().ok()
        };

        let watched_ifaces = opt.interface.clone();
        let tls_watched_ifaces = tls_interface_list.clone();

        let matches_explicit_bind_addr = opt.bind_addr.iter().filter_map(parse_ip).any(|ip| !ip.is_unspecified() && ip == addr);
        let matches_wildcard_bind_addr = opt.bind_addr.iter().filter_map(parse_ip).any(|ip| ip.is_unspecified() && ip.is_ipv4() == addr.is_ipv4());
        
        let matches_explicit_listen = opt.listen.iter().filter_map(|l| {
            let sa_str = if l.starts_with("unix") { return None; } else { l };
            sa_str.parse::<SocketAddr>().ok().map(|sa| sa.ip())
        }).any(|ip| !ip.is_unspecified() && ip == addr);
        let matches_wildcard_listen = opt.listen.iter().filter_map(|l| {
            let sa_str = if l.starts_with("unix") { return None; } else { l };
            sa_str.parse::<SocketAddr>().ok().map(|sa| sa.ip())
        }).any(|ip| ip.is_unspecified() && ip.is_ipv4() == addr.is_ipv4());

        let matches_explicit_tls_bind_addr = opt.tls_bind_addr.iter().filter_map(parse_ip).any(|ip| !ip.is_unspecified() && ip == addr);
        let matches_wildcard_tls_bind_addr = opt.tls_bind_addr.iter().filter_map(parse_ip).any(|ip| ip.is_unspecified() && ip.is_ipv4() == addr.is_ipv4());

        let is_excluded_plain = if let Some(ref ifname) = iface {
            crate::utils::is_interface_excluded(ifname, &opt.except_interface)
        } else {
            false
        };

        let allow_plain = if is_excluded_plain {
            false
        } else if let Some(ref ifname) = iface {
            let iface_allowed = crate::utils::is_interface_allowed(ifname, &watched_ifaces);
            if !opt.interface.is_empty() {
                iface_allowed || matches_explicit_bind_addr || matches_explicit_listen
            } else {
                matches_explicit_bind_addr || matches_explicit_listen || matches_wildcard_bind_addr || matches_wildcard_listen
            }
        } else {
            matches_explicit_bind_addr || matches_explicit_listen || matches_wildcard_bind_addr || matches_wildcard_listen
        };

        let is_excluded_tls = if let Some(ref ifname) = iface {
            crate::utils::is_interface_excluded(ifname, &opt.tls_except_interface)
        } else {
            false
        };

        let allow_tls = if is_excluded_tls {
            false
        } else if has_tls_specific {
            if let Some(ref ifname) = iface {
                let tls_iface_allowed = crate::utils::is_interface_allowed(ifname, &tls_watched_ifaces);
                if !opt.tls_interface.is_empty() {
                    tls_iface_allowed || matches_explicit_tls_bind_addr
                } else {
                    matches_explicit_tls_bind_addr || matches_wildcard_tls_bind_addr
                }
            } else {
                matches_explicit_tls_bind_addr || matches_wildcard_tls_bind_addr
            }
        } else {
            allow_plain
        };

        // Enforce IPv6 Link-Local restrictions
        let mut final_allow_plain = allow_plain;
        let mut final_allow_tls = allow_tls;
        if let std::net::IpAddr::V6(v6) = addr
            && v6.is_unicast_link_local() {
                if opt.no_ipv6_link_local {
                    final_allow_plain = false;
                    final_allow_tls = false;
                } else if opt.no_tls_ipv6_link_local {
                    final_allow_tls = false;
                }
            }

        // Determine correct iface/scope_id attributes using pattern checks instead of contains
        let plain_iface = if let Some(ref ifname) = iface {
            if !opt.interface.is_empty() && crate::utils::is_interface_allowed(ifname, &watched_ifaces) {
                Some(ifname.clone())
            } else {
                None
            }
        } else {
            None
        };

        let tls_iface = if has_tls_specific {
            if let Some(ref ifname) = iface {
                if !opt.tls_interface.is_empty() && crate::utils::is_interface_allowed(ifname, &tls_watched_ifaces) {
                    Some(ifname.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            plain_iface.clone()
        };

        let (scope_id, scope_name) = if let std::net::IpAddr::V6(v6) = addr {
            if v6.is_unicast_link_local() {
                let resolved_iface = iface.clone().or_else(|| {
                    self.iface_addr_map.iter().find_map(|(name, ips)| {
                        if ips.contains(&addr) { Some(name.clone()) } else { None }
                    })
                });
                (
                    resolved_iface.as_ref().and_then(|i| crate::utils::resolve_scope_id(i)),
                    resolved_iface,
                )
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        if final_allow_plain {
            for &port in &opt.bind_port {
                let mut sa = SocketAddr::new(addr, port);
                if let Some(sid) = scope_id
                    && let SocketAddr::V6(ref mut v6) = sa {
                        v6.set_scope_id(sid);
                    }
                let mut key_udp = SocketKey::new(sa, ProtocolKind::PlainUdp, plain_iface.clone());
                key_udp.scope_id = scope_id;
                key_udp.scope_name = scope_name.clone();
                keys.push(key_udp);

                let mut key_tcp = SocketKey::new(sa, ProtocolKind::PlainTcp, plain_iface.clone());
                key_tcp.scope_id = scope_id;
                key_tcp.scope_name = scope_name.clone();
                keys.push(key_tcp);
            }
        }

        if final_allow_tls {
            if opt.enable_dot {
                for &port in &opt.dot_port {
                    let mut sa = SocketAddr::new(addr, port);
                    if let Some(sid) = scope_id
                        && let SocketAddr::V6(ref mut v6) = sa {
                            v6.set_scope_id(sid);
                        }
                    let mut key = SocketKey::new(sa, ProtocolKind::DoT, tls_iface.clone());
                    key.scope_id = scope_id;
                    key.scope_name = scope_name.clone();
                    keys.push(key);
                }
            }
            if opt.enable_doh {
                for &port in &opt.doh_port {
                    let mut sa = SocketAddr::new(addr, port);
                    if let Some(sid) = scope_id
                        && let SocketAddr::V6(ref mut v6) = sa {
                            v6.set_scope_id(sid);
                        }
                    let mut key_doh = SocketKey::new(sa, ProtocolKind::DoH, tls_iface.clone());
                    key_doh.scope_id = scope_id;
                    key_doh.scope_name = scope_name.clone();
                    keys.push(key_doh);
                }
            }
            if opt.enable_doh3 {
                for &port in &opt.doh3_port {
                    let mut sa = SocketAddr::new(addr, port);
                    if let Some(sid) = scope_id
                        && let SocketAddr::V6(ref mut v6) = sa {
                            v6.set_scope_id(sid);
                        }
                    let mut key_doh3 = SocketKey::new(sa, ProtocolKind::DoH3, tls_iface.clone());
                    key_doh3.scope_id = scope_id;
                    key_doh3.scope_name = scope_name.clone();
                    keys.push(key_doh3);
                }
            }
            if opt.enable_doq {
                for &port in &opt.doq_port {
                    let mut sa = SocketAddr::new(addr, port);
                    if let Some(sid) = scope_id
                        && let SocketAddr::V6(ref mut v6) = sa {
                            v6.set_scope_id(sid);
                        }
                    let mut key = SocketKey::new(sa, ProtocolKind::DoQ, tls_iface.clone());
                    key.scope_id = scope_id;
                    key.scope_name = scope_name.clone();
                    keys.push(key);
                }
            }
        }

        keys
    }

    async fn remove_target_key(&mut self, key: &SocketKey) {
        self.targets.lock().await.remove(key);
        if let Some(mut handle) = self.handles.remove(key) {
            handle.abort_all();
        }
        if let Some(debounce) = self.debounces.remove(key) {
            debounce.cancel_token.cancel();
            debounce.timer_handle.abort();
        }
    }

    async fn handle_address_added(&mut self, iface: &str, addr: std::net::IpAddr) {
        let is_watched = if let Some(state) = &self.deps.state {
            let opt = &state.opt;
            
            // Check plain DNS dynamic match
            let plain_watched = if !opt.interface.is_empty() {
                crate::utils::is_interface_allowed(iface, &opt.interface)
            } else {
                opt.bind_dynamic && !crate::utils::is_interface_excluded(iface, &opt.except_interface)
            };

            // Check TLS DNS dynamic match
            let has_tls_specific = !opt.tls_interface.is_empty() 
                || !opt.tls_bind_addr.is_empty() 
                || opt.tls_bind_interfaces 
                || opt.tls_bind_dynamic;
            let tls_bind_dynamic = if has_tls_specific { opt.tls_bind_dynamic } else { opt.bind_dynamic };
            let tls_interface_list = if has_tls_specific { &opt.tls_interface } else { &opt.interface };
            let tls_except_list = if has_tls_specific { &opt.tls_except_interface } else { &opt.except_interface };

            let tls_watched = if !tls_interface_list.is_empty() {
                crate::utils::is_interface_allowed(iface, tls_interface_list)
            } else {
                tls_bind_dynamic && !crate::utils::is_interface_excluded(iface, tls_except_list)
            };

            plain_watched || tls_watched
        } else {
            let lock = self.targets.lock().await;
            lock.keys().any(|k| k.iface.as_deref() == Some(iface))
        };

        if is_watched {
            let keys = self.generate_keys_for_addr(addr, Some(iface.to_string()));
            let mut lock = self.targets.lock().await;
            for key in keys {
                lock.entry(key).or_insert(ListenerState::Unbound);
            }
        }

        let mut lock = self.targets.lock().await;
        let mut keys_to_bind = Vec::new();

        for (key, state) in lock.iter_mut() {
            let matches_ip = key.addr.ip() == addr;
            let matches_iface = key.iface.as_deref() == Some(iface);

            if matches_ip || matches_iface {
                match state {
                    ListenerState::Debouncing { generation_id } => {
                        if matches_ip {
                            let gen_id = *generation_id;
                            if let Some(debounce) = self.debounces.remove(key)
                                && debounce.generation_id == gen_id {
                                    debounce.cancel_token.cancel();
                                    debounce.timer_handle.abort();
                                }
                            *state = ListenerState::Active { generation_id: gen_id };
                            tracing::info!(
                                target = %key.addr,
                                protocol = ?key.protocol,
                                generation_id = gen_id,
                                "Restored active listener state during debounce grace window"
                            );
                            if key.iface.is_some() {
                                keys_to_bind.push(key.clone());
                            }
                        }
                    }
                    ListenerState::GracefulDrain { generation_id } => {
                        let active_gen = *generation_id;
                        *state = ListenerState::Active {
                            generation_id: active_gen,
                        };
                        keys_to_bind.push(key.clone());
                    }
                    ListenerState::Pending
                    | ListenerState::Unbound
                    | ListenerState::Retrying { .. } => {
                        keys_to_bind.push(key.clone());
                    }
                    ListenerState::Active { .. } => {}
                }
            }
        }
        drop(lock);

        for key in keys_to_bind {
            self.attempt_bind(&key).await;
        }
    }

    async fn handle_address_removed(&mut self, iface: &str, addr: std::net::IpAddr) {
        let _ = iface;
        let mut lock = self.targets.lock().await;
        let mut keys_to_debounce = Vec::new();

        for (key, state) in lock.iter_mut() {
            if is_loopback_target(key) {
                continue;
            }

            let matches_ip = key.addr.ip() == addr;

            if matches_ip
                && let ListenerState::Active { generation_id: _ } = *state {
                    self.generation_counter += 1;
                    let next_gen = self.generation_counter;
                    *state = ListenerState::Debouncing {
                        generation_id: next_gen,
                    };
                    keys_to_debounce.push((key.clone(), next_gen));
                }
        }
        drop(lock);

        for (key, next_gen) in keys_to_debounce {
            self.schedule_debounce_timer(key, next_gen).await;
        }
    }

    async fn handle_interface_up(&mut self, iface: &str) {
        let mut lock = self.targets.lock().await;
        let mut keys_to_bind = Vec::new();

        for (key, state) in lock.iter_mut() {
            let matches_iface = key.iface.as_deref() == Some(iface);
            let ip_on_iface = self
                .iface_addr_map
                .get(iface)
                .is_some_and(|ips| ips.contains(&key.addr.ip()));

            if matches_iface || ip_on_iface {
                match state {
                    ListenerState::Debouncing { generation_id } => {
                        // Only restore debouncing if the IP is still on the interface
                        if ip_on_iface {
                            let gen_id = *generation_id;
                            if let Some(debounce) = self.debounces.remove(key)
                                && debounce.generation_id == gen_id {
                                    debounce.cancel_token.cancel();
                                    debounce.timer_handle.abort();
                                }
                            *state = ListenerState::Active { generation_id: gen_id };
                            keys_to_bind.push(key.clone());
                        }
                    }
                    ListenerState::Pending
                    | ListenerState::Unbound
                    | ListenerState::Retrying { .. }
                    | ListenerState::GracefulDrain { .. }
                    | ListenerState::Active { .. } => {
                        keys_to_bind.push(key.clone());
                    }
                }
            }
        }
        drop(lock);

        for key in keys_to_bind {
            self.attempt_bind(&key).await;
        }
    }

    async fn handle_interface_down(&mut self, iface: &str) {
        let mut lock = self.targets.lock().await;
        let mut keys_to_debounce = Vec::new();

        for (key, state) in lock.iter_mut() {
            if is_loopback_target(key) {
                continue;
            }

            let matches_iface = key.iface.as_deref() == Some(iface);
            let ip_on_iface = self
                .iface_addr_map
                .get(iface)
                .is_some_and(|ips| ips.contains(&key.addr.ip()));

            tracing::info!(
                %iface,
                ?key,
                %matches_iface,
                %ip_on_iface,
                "handle_interface_down evaluating key"
            );

            if (matches_iface || ip_on_iface)
                && let ListenerState::Active { generation_id: _ } = *state {
                    self.generation_counter += 1;
                    let next_gen = self.generation_counter;
                    *state = ListenerState::Debouncing {
                        generation_id: next_gen,
                    };
                    keys_to_debounce.push((key.clone(), next_gen));
                }
        }
        drop(lock);

        for (key, next_gen) in keys_to_debounce {
            self.schedule_debounce_timer(key, next_gen).await;
        }
    }

    async fn schedule_debounce_timer(&mut self, key: SocketKey, generation_id: u64) {
        tracing::info!(
            target = %key.addr,
            protocol = ?key.protocol,
            generation_id,
            "Interface/IP dropped. Scheduling 200ms debounce timer"
        );
        let cancel_token = CancellationToken::new();
        let token_clone = cancel_token.clone();
        let key_clone = key.clone();
        let tx = self.tx.clone();

        let timer_handle = tokio::spawn(async move {
            tokio::select! {
                _ = token_clone.cancelled() => {}
                _ = tokio::time::sleep(IFACE_DEBOUNCE_DURATION) => {
                    let _ = tx.send(IfaceEvent::DebounceTimeout {
                        key: key_clone,
                        generation_id,
                    }).await;
                }
            }
        });

        self.debounces.insert(
            key,
            ActiveDebounce {
                generation_id,
                cancel_token,
                timer_handle,
            },
        );
    }

    async fn handle_debounce_timeout(&mut self, key: SocketKey, generation_id: u64) {
        self.debounces.remove(&key);
        let mut lock = self.targets.lock().await;
        if let Some(state) = lock.get_mut(&key)
            && let ListenerState::Debouncing {
                generation_id: current_gen,
            } = *state
                && current_gen == generation_id {
                    *state = ListenerState::GracefulDrain { generation_id };
                    tracing::info!(
                        target = %key.addr,
                        protocol = ?key.protocol,
                        generation_id,
                        "Debounce timer expired; initiating graceful connection drain"
                    );

                    if let Some(mut handle) = self.handles.remove(&key) {
                        handle.abort_all();
                    }

                    let targets_arc = self.targets.clone();
                    let key_clone = key.clone();
                    let tx_clone = self.tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(GRACEFUL_DRAIN_TIMEOUT).await;
                        let mut lock = targets_arc.lock().await;
                        if let Some(state) = lock.get_mut(&key_clone)
                            && let ListenerState::GracefulDrain { generation_id: g } = *state
                                && g == generation_id {
                                    *state = ListenerState::Pending;
                                    tracing::info!(
                                        target = %key_clone.addr,
                                        "Connection draining complete; transitioning target to Pending"
                                    );
                                    let _ = tx_clone.send(IfaceEvent::ResyncRequired).await;
                                }
                    });
                }
    }

    async fn schedule_retry_timer(&mut self, key: SocketKey, attempt: u32, delay_ms: u64) {
        let tx = self.tx.clone();
        let key_clone = key.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let _ = tx.send(IfaceEvent::RetryTimeout {
                key: key_clone,
                attempt,
            }).await;
        });
    }

    async fn handle_retry_timeout(&mut self, key: SocketKey, attempt: u32) {
        let lock = self.targets.lock().await;
        let is_still_retrying = matches!(
            lock.get(&key),
            Some(ListenerState::Retrying { attempt: current_attempt }) if *current_attempt == attempt
        );
        drop(lock);

        if is_still_retrying {
            self.attempt_bind(&key).await;
        }
    }

    async fn attempt_bind(&mut self, key: &SocketKey) {
        let socket = match socket2::Socket::new(
            if key.addr.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            },
            if key.protocol == ProtocolKind::PlainUdp
                || key.protocol == ProtocolKind::DoH3
                || key.protocol == ProtocolKind::DoQ
            {
                socket2::Type::DGRAM
            } else {
                socket2::Type::STREAM
            },
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target = %key.addr, error = %e, "Failed to create raw socket descriptor");
                return;
            }
        };

        let bind_interfaces = self.deps.state.as_ref().map(|s| {
            let is_tls = matches!(key.protocol, ProtocolKind::DoT | ProtocolKind::DoH | ProtocolKind::DoQ | ProtocolKind::DoH3);
            let has_tls_specific = s.opt.tls_bind_interfaces || s.opt.tls_bind_dynamic;
            if is_tls && has_tls_specific {
                s.opt.tls_bind_interfaces
            } else {
                s.opt.bind_interfaces
            }
        }).unwrap_or(false);
        if let Err(e) = configure_listener_socket(&socket, key, bind_interfaces) {
            tracing::warn!(target = %key.addr, error = %e, "Socket configuration error; transitioning to Pending");
            let mut lock = self.targets.lock().await;
            lock.insert(key.clone(), ListenerState::Pending);
            drop(lock);

            if let Some(mut old) = self.handles.remove(key) {
                old.abort_all();
            }
            return;
        }

        let mut bind_addr = key.addr;
        if let SocketAddr::V6(ref mut v6_addr) = bind_addr
            && (v6_addr.ip().is_unicast_link_local() || key.scope_id.is_some() || key.scope_name.is_some()) {
                let resolved_sid = if let Some(ref scope_name) = key.scope_name {
                    resolve_scope_id(scope_name)
                } else if let Some(ref iface) = key.iface {
                    resolve_scope_id(iface)
                } else {
                    key.scope_id
                };
                if let Some(scope_id) = resolved_sid {
                    v6_addr.set_scope_id(scope_id);
                }
            }

        let sock_addr: socket2::SockAddr = bind_addr.into();
        match socket.bind(&sock_addr) {
            Ok(_) => {
                self.generation_counter += 1;
                let next_gen = self.generation_counter;

                let mut lock = self.targets.lock().await;
                let old_state = lock.get(key).cloned().unwrap_or(ListenerState::Unbound);
                lock.insert(key.clone(), ListenerState::Active { generation_id: next_gen });
                tracing::info!(
                    target = %bind_addr,
                    protocol = ?key.protocol,
                    generation_id = next_gen,
                    old_state = ?old_state,
                    new_state = "Active",
                    "Successfully bound socket listener"
                );
                drop(lock);

                // Zero-Downtime Handoff: replace old handle after binding new socket
                let old_handle = self.handles.remove(key);
                let (abort_handles, worker_abort_handles, shutdown_tx) = spawn_listener_tasks(socket, key, &self.deps);

                self.handles.insert(
                    key.clone(),
                    ListenerHandle {
                        key: key.clone(),
                        generation_id: next_gen,
                        abort_handles,
                        worker_abort_handles,
                        spawned_at: Instant::now(),
                        shutdown_tx,
                    },
                );

                if let Some(mut old) = old_handle {
                    old.abort_all();
                }
            }
            Err(e) => {
                let mut retry_info = None;
                let mut lock = self.targets.lock().await;

                if is_addr_not_available(&e) {
                    lock.insert(key.clone(), ListenerState::Pending);
                    tracing::info!(target = %key.addr, "Address not available; transitioning to Pending");
                } else if is_addr_in_use(&e) {
                    let current_attempt = match lock.get(key) {
                        Some(ListenerState::Retrying { attempt }) => *attempt,
                        _ => 0,
                    };
                    let next_attempt = current_attempt + 1;
                    if next_attempt > MAX_PORT_BACKOFF_RETRIES {
                        lock.insert(key.clone(), ListenerState::Pending);
                        tracing::warn!(target = %key.addr, "Max port backoff retries reached; transitioning target to Pending");
                    } else {
                        lock.insert(key.clone(), ListenerState::Retrying { attempt: next_attempt });
                        let backoff_ms = std::cmp::min(
                            INITIAL_PORT_BACKOFF_MS.saturating_mul(1u64 << (next_attempt.saturating_sub(1))),
                            MAX_PORT_BACKOFF_MS,
                        );
                        retry_info = Some((next_attempt, backoff_ms));
                        tracing::warn!(
                            target = %key.addr,
                            attempt = next_attempt,
                            next_retry_in_ms = backoff_ms,
                            "Port in use (EADDRINUSE); scheduled backoff retry"
                        );
                    }
                } else {
                    lock.insert(key.clone(), ListenerState::Pending);
                }
                drop(lock);

                if let Some(mut old) = self.handles.remove(key) {
                    old.abort_all();
                }

                if let Some((next_attempt, backoff_ms)) = retry_info {
                    self.schedule_retry_timer(key.clone(), next_attempt, backoff_ms).await;
                }
            }
        }
    }

    async fn evaluate_all_targets(&mut self) {
        let live_os_state = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                crate::iface_watcher::query_unix_ifaddrs(&[]).unwrap_or_default()
            }
            #[cfg(target_os = "windows")]
            {
                crate::iface_watcher::query_windows_adapters(&[]).unwrap_or_default()
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                HashMap::new()
            }
        };

        self.iface_addr_map.clear();
        for (ifname, (_ifindex, _is_up, ips)) in &live_os_state {
            self.iface_addr_map.insert(ifname.clone(), ips.clone());
        }

        {
            let mut lock = self.targets.lock().await;
            for (iface, (_ifindex, is_up, ips)) in &live_os_state {
                if *is_up {
                    for &ip in ips {
                        let keys = self.generate_keys_for_addr(ip, Some(iface.clone()));
                        for key in keys {
                            lock.entry(key).or_insert(ListenerState::Unbound);
                        }
                    }
                }
            }
        }

        let mut lock = self.targets.lock().await;
        let mut keys_to_bind = Vec::new();
        let mut keys_to_debounce = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (key, state) in lock.iter_mut() {
            let target_ip = key.addr.ip();
            let is_available = target_ip.is_loopback()
                || target_ip.is_unspecified()
                || live_os_state
                    .values()
                    .any(|(_idx, is_up, ips)| *is_up && ips.contains(&target_ip));

            if key.iface.is_some() && !is_available {
                match state {
                    ListenerState::Unbound | ListenerState::Pending | ListenerState::Retrying { .. } => {
                        keys_to_remove.push(key.clone());
                        continue;
                    }
                    _ => {}
                }
            }

            match state {
                ListenerState::Active { generation_id } if !is_available => {
                    keys_to_debounce.push((key.clone(), *generation_id));
                }
                ListenerState::Pending
                | ListenerState::Unbound
                | ListenerState::Retrying { .. }
                    if is_available =>
                {
                    keys_to_bind.push(key.clone());
                }
                _ => {}
            }
        }

        drop(lock);

        for key in keys_to_remove {
            self.remove_target_key(&key).await;
        }

        let mut lock = self.targets.lock().await;
        for (key, _gen) in keys_to_debounce.iter() {
            self.generation_counter += 1;
            let next_gen = self.generation_counter;
            lock.insert(key.clone(), ListenerState::Debouncing { generation_id: next_gen });
        }

        let debounce_tasks: Vec<(SocketKey, u64)> = keys_to_debounce
            .into_iter()
            .map(|(key, _)| {
                let generation_val = match lock.get(&key) {
                    Some(ListenerState::Debouncing { generation_id }) => *generation_id,
                    _ => 0,
                };
                (key, generation_val)
            })
            .collect();

        drop(lock);

        for (key, next_gen) in debounce_tasks {
            if next_gen > 0 {
                self.schedule_debounce_timer(key, next_gen).await;
            }
        }

        for key in keys_to_bind {
            self.attempt_bind(&key).await;
        }
    }
}

/// Helper function to spawn real or mock worker loops and return abort and shutdown hooks
#[allow(clippy::type_complexity)]
fn spawn_listener_tasks(
    socket: socket2::Socket,
    key: &SocketKey,
    deps: &ServerDependencies,
) -> (Vec<AbortHandle>, Arc<std::sync::Mutex<Vec<AbortHandle>>>, Option<oneshot::Sender<()>>) {
    let mut abort_handles = Vec::new();
    let worker_abort_handles = Arc::new(std::sync::Mutex::new(Vec::new()));

    socket.set_nonblocking(true).ok();

    let state = match &deps.state {
        Some(s) => s.clone(),
        None => {
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(async move {
                tokio::select! {
                    _ = &mut shutdown_rx => {}
                }
            });
            abort_handles.push(task.abort_handle());
            return (abort_handles, worker_abort_handles, Some(shutdown_tx));
        }
    };

    match key.protocol {
        ProtocolKind::PlainUdp => {
            let std_sock: std::net::UdpSocket = socket.into();
            if let Ok(tokio_udp) = tokio::net::UdpSocket::from_std(std_sock) {
                let tokio_udp = Arc::new(tokio_udp);
                let is_ipv6 = key.addr.is_ipv6();
                let state_clone = state.clone();
                let task = tokio::spawn(async move {
                    let mux = match crate::upstream::UdpMultiplexer::new(
                        is_ipv6,
                        state_clone.opt.socket_buffer_size,
                        state_clone.opt.out_mark,
                    )
                    .await
                    {
                        Ok(m) => Arc::new(m),
                        Err(e) => {
                            tracing::error!("Failed to create UDP multiplexer for listener: {}", e);
                            return;
                        }
                    };
                    let _ = crate::server::handle_udp_listener(tokio_udp, state_clone, mux, 0).await;
                });
                abort_handles.push(task.abort_handle());
            }
        }
        ProtocolKind::PlainTcp => {
            let _ = socket.listen(128);
            let std_listener: std::net::TcpListener = socket.into();
            if let Ok(tokio_tcp) = tokio::net::TcpListener::from_std(std_listener) {
                let task = tokio::spawn(async move {
                    let _ = crate::server::handle_tcp_listener(tokio_tcp, state).await;
                });
                abort_handles.push(task.abort_handle());
            }
        }
        ProtocolKind::DoT => {
            #[cfg(feature = "server-dot")]
            if let Some(ref acceptor) = deps.dot_acceptor {
                let _ = socket.listen(128);
                let std_listener: std::net::TcpListener = socket.into();
                if let Ok(tokio_tcp) = tokio::net::TcpListener::from_std(std_listener) {
                    let acceptor = acceptor.clone();
                    let task = tokio::spawn(async move {
                        let _ = crate::server::handle_dot_listener(tokio_tcp, acceptor, state).await;
                    });
                    abort_handles.push(task.abort_handle());
                }
            }
            #[cfg(not(feature = "server-dot"))]
            {
                let _ = socket;
                tracing::warn!("DoT server listener was disabled at compile time");
            }
        }
        ProtocolKind::DoH => {
            #[cfg(feature = "server-doh")]
            if let Some(ref acceptor) = deps.doh_acceptor {
                let _ = socket.listen(128);
                let std_listener: std::net::TcpListener = socket.into();
                if let Ok(tokio_tcp) = tokio::net::TcpListener::from_std(std_listener) {
                    let acceptor = acceptor.clone();
                    let path = deps.doh_path.clone().unwrap();
                    let task = tokio::spawn(async move {
                        let _ = crate::server::handle_doh_listener(tokio_tcp, acceptor, state, path).await;
                    });
                    abort_handles.push(task.abort_handle());
                }
            }
            #[cfg(not(feature = "server-doh"))]
            {
                let _ = socket;
                tracing::warn!("DoH server listener was disabled at compile time");
            }
        }
        ProtocolKind::DoQ | ProtocolKind::DoH3 => {
            #[cfg(feature = "server-h3")]
            {
                #[cfg(all(feature = "quiche", not(feature = "original-h3-server")))]
                {
                use foreign_types::ForeignTypeRef;

                let std_sock: std::net::UdpSocket = socket.into();
                if let Ok(tokio_udp) = tokio::net::UdpSocket::from_std(std_sock) {
                    let socket = Arc::new(tokio_udp);
                    let limits = crate::quiche_server::H3ResourceLimits::from_opt(&state.opt);
                    let mut ssl_ctx_builder = boring::ssl::SslContext::builder(boring::ssl::SslMethod::tls_server()).unwrap();
                    ssl_ctx_builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::OFF);

                    let mut first_cert = None;
                    let mut first_key = None;
                    if let (Some(cert), Some(key)) = (&state.opt.cert_file, &state.opt.key_file) {
                        first_cert = Some(cert.clone());
                        first_key = Some(key.clone());
                    } else if !state.opt.cert_pair.is_empty() {
                        for entry in state.opt.cert_pair[0].split(';').map(str::trim).filter(|e| !e.is_empty()) {
                            if let Some((cert, key)) = entry.split_once(',') {
                                first_cert = Some(cert.trim().to_string());
                                first_key = Some(key.trim().to_string());
                                break;
                            } else {
                                first_cert = Some(entry.to_string());
                                first_key = Some(entry.to_string());
                                break;
                            }
                        }
                    }

                    if let (Some(cert), Some(key)) = (first_cert, first_key) {
                        ssl_ctx_builder.set_certificate_chain_file(&cert).unwrap();
                        ssl_ctx_builder.set_private_key_file(&key, boring::ssl::SslFiletype::PEM).unwrap();
                        ssl_ctx_builder.check_private_key().unwrap();
                    }

                    let cert_resolver = crate::quiche_server::build_boring_cert_resolver(&state.opt).unwrap();
                    let resolver = cert_resolver.clone();
                    ssl_ctx_builder.set_servername_callback(move |ssl, _alert| {
                        let name = ssl.servername(boring::ssl::NameType::HOST_NAME);
                        match resolver.resolve(name) {
                             Some(cert_key) => {
                                 ssl.set_certificate(&cert_key.leaf).unwrap();
                                 ssl.set_private_key(&cert_key.key).unwrap();
                                 unsafe {
                                     boring_sys::SSL_clear_chain_certs(ssl.as_ptr());
                                 }
                                 for cert in &cert_key.chain {
                                     let _ = ssl.add_chain_cert(cert);
                                 }
                                 Ok(())
                             }
                             None => {
                                 if resolver.strict_sni {
                                     Err(boring::ssl::SniError::ALERT_FATAL)
                                 } else {
                                     ssl.set_certificate(&resolver.fallback.leaf).unwrap();
                                     ssl.set_private_key(&resolver.fallback.key).unwrap();
                                     unsafe {
                                         boring_sys::SSL_clear_chain_certs(ssl.as_ptr());
                                     }
                                     for cert in &resolver.fallback.chain {
                                         let _ = ssl.add_chain_cert(cert);
                                     }
                                     Ok(())
                                 }
                             }
                        }
                    });

                    let mut quiche_config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl_ctx_builder).unwrap();
                    let _ = crate::quiche_server::configure_quiche_limits(&mut quiche_config, &limits, &state.opt);
                    
                    
                    
                    let mut secret_key = vec![0u8; 16];
                    rand::RngCore::fill_bytes(&mut rand::rng(), &mut secret_key);
                    
                    let path = if key.protocol == ProtocolKind::DoQ { Arc::from("") } else { deps.doh_path.clone().unwrap() };
                    
                    let state_clone = state.clone();
                    let worker_aborts = worker_abort_handles.clone();
                    let task = tokio::spawn(async move {
                        let _ = crate::quiche_server::handle_doh3_listener(socket, state_clone, path, quiche_config, secret_key, worker_aborts).await;
                    });
                    abort_handles.push(task.abort_handle());
                }
            }

            #[cfg(all(feature = "original-h3-server", not(feature = "quiche")))]
            {
                let std_sock: std::net::UdpSocket = socket.into();
                if key.protocol == ProtocolKind::DoQ {
                    if let Some(ref cfg) = deps.quinn_doq_config {
                        let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(cfg.clone()), std_sock, Arc::new(quinn::TokioRuntime)).unwrap();
                        let state_clone = state.clone();
                        let task = tokio::spawn(async move {
                            let _ = crate::server::handle_doq_listener(endpoint, state_clone).await;
                        });
                        abort_handles.push(task.abort_handle());
                    }
                } else if key.protocol == ProtocolKind::DoH3
                    && let Some(ref cfg) = deps.quinn_doh3_config {
                        let endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(cfg.clone()), std_sock, Arc::new(quinn::TokioRuntime)).unwrap();
                        let path = deps.doh_path.clone().unwrap();
                        let state_clone = state.clone();
                        let task = tokio::spawn(async move {
                            let _ = crate::server::handle_doh3_listener(endpoint, state_clone, path).await;
                        });
                        abort_handles.push(task.abort_handle());
                    }
            }

            #[cfg(not(any(feature = "quiche", feature = "original-h3-server")))]
            {
                let _ = socket;
                tracing::warn!("DoH3/DoQ server listener enabled but no H3 engine compiled in (need 'quiche' or 'original-h3-server')");
            }
        }
        #[cfg(not(feature = "server-h3"))]
        {
            let _ = socket;
            tracing::warn!("DoH3/DoQ server listener was disabled at compile time");
        }
    }
    }

    (abort_handles, worker_abort_handles, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listener_manager::{ListenerManager, SocketKey, ProtocolKind};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_listener_manager_bootstrap() {
        let (tx, _rx) = mpsc::channel(64);
        let target_addr = "127.0.0.1:0".parse().unwrap();
        let key = SocketKey::new(target_addr, ProtocolKind::PlainUdp, None);
        
        let deps = ServerDependencies::mock();
        let mut manager = ListenerManager::new(vec![key.clone()], tx, deps);
        
        {
            let lock = manager.targets.lock().await;
            assert_eq!(lock.get(&key), Some(&ListenerState::Unbound));
        }

        manager.evaluate_all_targets().await;

        {
            let lock = manager.targets.lock().await;
            let state = lock.get(&key).unwrap();
            assert!(matches!(state, ListenerState::Active { .. }));
        }
    }

    #[tokio::test]
    async fn test_listener_manager_interface_rebind_on_pppoe_reconnect() {
        let (tx, _rx) = mpsc::channel(64);
        let target_addr = "127.0.0.1:0".parse().unwrap();
        let key = SocketKey::new(target_addr, ProtocolKind::PlainUdp, Some("lo".to_string()));

        let deps = ServerDependencies::mock();
        let mut manager = ListenerManager::new(vec![key.clone()], tx, deps);

        // Initial bootstrap
        manager.evaluate_all_targets().await;

        let _initial_gen = {
            let lock = manager.targets.lock().await;
            match lock.get(&key).unwrap() {
                ListenerState::Active { generation_id } => *generation_id,
                other => panic!("Expected Active state, got {:?}", other),
            }
        };

        // Simulate PPPoE reconnect: address removed then re-added on interface
        manager
            .dispatch_event(IfaceEvent::AddressRemoved {
                iface: "lo".to_string(),
                iface_label: None,
                ifindex: 10,
                addr: "127.0.0.1".parse().unwrap(),
            })
            .await;

        // PPPoE comes back up with a new IP
        manager
            .dispatch_event(IfaceEvent::AddressAdded {
                iface: "lo".to_string(),
                iface_label: None,
                ifindex: 12,
                addr: "127.0.0.2".parse().unwrap(),
                is_deprecated: false,
            })
            .await;

        let new_key = SocketKey::new(
            "127.0.0.2:0".parse().unwrap(),
            ProtocolKind::PlainUdp,
            Some("lo".to_string()),
        );

        let new_gen = {
            let lock = manager.targets.lock().await;
            match lock.get(&new_key) {
                Some(ListenerState::Active { generation_id }) => *generation_id,
                other => panic!("Expected Active state for new IP target after reconnect, got {:?}", other),
            }
        };

        // Generation ID must be positive, confirming dynamic target creation and bind attempt succeeded
        assert!(new_gen > 0);
    }

    #[tokio::test]
    async fn test_listener_manager_interface_up_down_events() {
        let (tx, _rx) = mpsc::channel(64);
        let target_addr = "127.0.0.1:0".parse().unwrap();
        let key = SocketKey::new(target_addr, ProtocolKind::PlainUdp, Some("lo".to_string()));

        let deps = ServerDependencies::mock();
        let mut manager = ListenerManager::new(vec![key.clone()], tx, deps);

        manager.evaluate_all_targets().await;

        let initial_gen = {
            let lock = manager.targets.lock().await;
            match lock.get(&key).unwrap() {
                ListenerState::Active { generation_id } => *generation_id,
                other => panic!("Expected Active state initially, got {:?}", other),
            }
        };

        // Transition target to Pending (simulating interface down)
        {
            let mut lock = manager.targets.lock().await;
            lock.insert(key.clone(), ListenerState::Pending);
        }

        // Interface comes back UP
        manager
            .dispatch_event(IfaceEvent::InterfaceStateChanged {
                iface: "lo".to_string(),
                ifindex: 1,
                is_up: true,
            })
            .await;

        let new_gen = {
            let lock = manager.targets.lock().await;
            match lock.get(&key).unwrap() {
                ListenerState::Active { generation_id } => *generation_id,
                other => panic!("Expected Active state after interface UP, got {:?}", other),
            }
        };

        assert!(new_gen > initial_gen);
    }

    #[tokio::test]
    async fn test_listener_manager_link_local_key_generation() {
        let opt = crate::opt::Opt {
            bind_port: vec![53],
            dot_port: vec![853],
            enable_dot: true,
            interface: vec!["eth0".to_string()],
            ..Default::default()
        };
        
        let state = Arc::new(crate::server::ServerState {
            opt: Arc::new(opt),
            ..crate::server::ServerState::mock()
        });
        
        let deps = ServerDependencies {
            state: Some(state.clone()),
            ..ServerDependencies::mock()
        };
        
        let tx = tokio::sync::mpsc::channel(64).0;
        let manager = ListenerManager::new(vec![], tx, deps);
        
        // 1. Unicast Link-Local address (fe80::1) on eth0, globally allowed
        let keys = manager.generate_keys_for_addr("fe80::1".parse().unwrap(), Some("eth0".to_string()));
        // Expected UDP/TCP plain + DoT keys (3 keys in total)
        assert_eq!(keys.len(), 3);
        assert!(keys.iter().any(|k| k.protocol == ProtocolKind::PlainUdp));
        assert!(keys.iter().any(|k| k.protocol == ProtocolKind::PlainTcp));
        assert!(keys.iter().any(|k| k.protocol == ProtocolKind::DoT));
        
        // 2. Disable link-local globally
        let opt_no_ll = crate::opt::Opt {
            bind_port: vec![53],
            dot_port: vec![853],
            enable_dot: true,
            interface: vec!["eth0".to_string()],
            no_ipv6_link_local: true,
            ..Default::default()
        };
        
        let state_no_ll = Arc::new(crate::server::ServerState {
            opt: Arc::new(opt_no_ll),
            ..crate::server::ServerState::mock()
        });
        let deps_no_ll = ServerDependencies {
            state: Some(state_no_ll),
            ..ServerDependencies::mock()
        };
        let manager_no_ll = ListenerManager::new(vec![], tokio::sync::mpsc::channel(64).0, deps_no_ll);
        let keys_no_ll = manager_no_ll.generate_keys_for_addr("fe80::1".parse().unwrap(), Some("eth0".to_string()));
        assert!(keys_no_ll.is_empty());
    }

    #[tokio::test]
    async fn test_generate_keys_wildcard_expansion_and_except_interface() {
        let opt = crate::opt::Opt {
            bind_port: vec![53],
            bind_addr: vec!["0.0.0.0".to_string()],
            except_interface: vec!["eth0".to_string()],
            ..Default::default()
        };

        let state = Arc::new(crate::server::ServerState {
            opt: Arc::new(opt),
            ..crate::server::ServerState::mock()
        });
        let deps = ServerDependencies {
            state: Some(state.clone()),
            ..ServerDependencies::mock()
        };
        let tx = tokio::sync::mpsc::channel(64).0;
        let manager = ListenerManager::new(vec![], tx, deps);

        // Address on excluded interface 'eth0'
        let keys_eth0 = manager.generate_keys_for_addr("192.168.1.100".parse().unwrap(), Some("eth0".to_string()));
        assert!(keys_eth0.is_empty(), "Keys for excluded interface eth0 should be empty");

        // Address on allowed interface 'wlan0'
        let keys_wlan0 = manager.generate_keys_for_addr("192.168.1.101".parse().unwrap(), Some("wlan0".to_string()));
        assert!(!keys_wlan0.is_empty(), "Keys for allowed interface wlan0 should be generated via wildcard 0.0.0.0");
    }

    #[tokio::test]
    async fn test_listener_manager_bind_dynamic_without_interface() {
        let opt = crate::opt::Opt {
            bind_addr: vec!["0.0.0.0".to_string(), "::".to_string()],
            tls_bind_addr: vec!["0.0.0.0".to_string(), "::".to_string()],
            bind_port: vec![53],
            dot_port: vec![853],
            enable_dot: true,
            bind_dynamic: true,
            tls_bind_dynamic: true,
            ..Default::default()
        };

        let state = Arc::new(crate::server::ServerState {
            opt: Arc::new(opt),
            ..crate::server::ServerState::mock()
        });
        let deps = ServerDependencies {
            state: Some(state.clone()),
            ..ServerDependencies::mock()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut manager = ListenerManager::new(vec![], tx, deps);

        // Send AddressAdded for eth1, IP 10.0.0.10
        manager.dispatch_event(IfaceEvent::AddressAdded {
            iface: "eth1".to_string(),
            iface_label: None,
            ifindex: 2,
            addr: "10.0.0.10".parse().unwrap(),
            is_deprecated: false,
        }).await;

        // Verify that keys were generated and inserted into targets
        let targets = manager.targets.lock().await;
        
        // Should have PlainUdp, PlainTcp, and DoT keys for 10.0.0.10
        assert_eq!(targets.len(), 3);
        
        let keys: Vec<_> = targets.keys().collect();
        assert!(keys.iter().any(|k| k.addr.ip() == "10.0.0.10".parse::<std::net::IpAddr>().unwrap() && k.protocol == ProtocolKind::PlainUdp));
        assert!(keys.iter().any(|k| k.addr.ip() == "10.0.0.10".parse::<std::net::IpAddr>().unwrap() && k.protocol == ProtocolKind::PlainTcp));
        assert!(keys.iter().any(|k| k.addr.ip() == "10.0.0.10".parse::<std::net::IpAddr>().unwrap() && k.protocol == ProtocolKind::DoT));
    }

    #[tokio::test]
    async fn test_listener_handle_drop_aborts_tasks() {
        let task = tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });
        let abort_handle = task.abort_handle();
        assert!(!abort_handle.is_finished());

        let target_addr = "127.0.0.1:0".parse().unwrap();
        let key = SocketKey::new(target_addr, ProtocolKind::PlainUdp, None);
        let handle = ListenerHandle {
            key,
            generation_id: 1,
            abort_handles: vec![abort_handle.clone()],
            worker_abort_handles: Arc::new(std::sync::Mutex::new(Vec::new())),
            spawned_at: Instant::now(),
            shutdown_tx: None,
        };

        drop(handle);
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        assert!(abort_handle.is_finished());
    }

    #[tokio::test]
    async fn test_debounce_timeout_cleans_up_debounces_map() {
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let target_addr = "127.0.0.1:0".parse().unwrap();
        let key = SocketKey::new(target_addr, ProtocolKind::PlainUdp, None);
        let deps = ServerDependencies::mock();
        let mut manager = ListenerManager::new(vec![key.clone()], tx, deps);

        // Schedule debounce timer
        manager.schedule_debounce_timer(key.clone(), 42).await;
        assert!(manager.debounces.contains_key(&key));

        // Fire handle_debounce_timeout
        manager.handle_debounce_timeout(key.clone(), 42).await;
        assert!(!manager.debounces.contains_key(&key));
    }
}

