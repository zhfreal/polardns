use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing;

use crate::listener_manager::SocketKey;

pub const WINDOWS_IFACE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3);
pub const UNIX_IFACE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Normalized network interface events
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfaceEvent {
    /// An IP address was added to an interface
    AddressAdded {
        iface: String,
        iface_label: Option<String>,
        ifindex: u32,
        addr: IpAddr,
        is_deprecated: bool,
    },
    /// An IP address was removed from an interface
    AddressRemoved {
        iface: String,
        iface_label: Option<String>,
        ifindex: u32,
        addr: IpAddr,
    },
    /// Interface link state changed (e.g. UP/DOWN)
    InterfaceStateChanged {
        iface: String,
        ifindex: u32,
        is_up: bool,
    },
    /// Interface index changed due to adapter reset
    InterfaceIndexChanged {
        iface: String,
        old_ifindex: u32,
        new_ifindex: u32,
    },
    /// Interface was renamed dynamically
    InterfaceRenamed {
        ifindex: u32,
        old_name: String,
        new_name: String,
    },
    /// Default route/gateway changed
    DefaultRouteChanged {
        ifindex: u32,
        preferred_src: Option<IpAddr>,
    },
    /// Trigger full resynchronization of network addresses
    ResyncRequired,
    /// Internal: Retry timer expired for a socket target
    RetryTimeout {
        key: SocketKey,
        attempt: u32,
    },
    /// Internal: Debounce timer expired for a socket target
    DebounceTimeout {
        key: SocketKey,
        generation_id: u64,
    },
}

/// Helper function to check if an address is an APIPA IPv4 address (169.254.0.0/16)
pub fn is_apipa(addr: &IpAddr) -> bool {
    if let IpAddr::V4(v4) = addr {
        let octets = v4.octets();
        octets[0] == 169 && octets[1] == 254
    } else {
        false
    }
}

pub struct IfaceWatcher {
    pub rx: Option<mpsc::Receiver<IfaceEvent>>,
    pub tx: mpsc::Sender<IfaceEvent>,
    _task_handle: tokio::task::JoinHandle<()>,
}

impl IfaceWatcher {
    pub fn new(filters: Vec<String>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::channel(64);
        let filters_arc = Arc::new(filters);

        #[cfg(target_os = "linux")]
        let _task_handle = start_linux_watcher(tx.clone(), filters_arc)?;

        #[cfg(target_os = "macos")]
        let _task_handle = start_macos_watcher(tx.clone(), filters_arc)?;

        #[cfg(target_os = "windows")]
        let _task_handle = start_windows_watcher(tx.clone(), filters_arc)?;

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _task_handle = start_fallback_polling_thread(tx.clone(), filters_arc)?;

        Ok(Self {
            rx: Some(rx),
            tx,
            _task_handle,
        })
    }
}

impl Drop for IfaceWatcher {
    fn drop(&mut self) {
        self._task_handle.abort();
    }
}

// ============================================================================
// Linux Netlink Driver (`NETLINK_ROUTE`)
// ============================================================================

#[cfg(target_os = "linux")]
pub fn start_linux_watcher(
    tx: mpsc::Sender<IfaceEvent>,
    filters: Arc<Vec<String>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EACCES) || err.raw_os_error() == Some(libc::EPERM) {
            tracing::warn!(
                "Netlink socket creation failed with EACCES/EPERM. Fallback to periodic getifaddrs polling."
            );
            return start_fallback_polling_thread(tx, filters);
        }
        return Err(err);
    }

    let socket = unsafe { socket2::Socket::from_raw_fd(fd) };

    let groups_mask = (1u32 << (libc::RTNLGRP_IPV4_IFADDR - 1))
        | (1u32 << (libc::RTNLGRP_IPV6_IFADDR - 1))
        | (1u32 << (libc::RTNLGRP_LINK - 1));

    let mut nl_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    nl_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    nl_addr.nl_pid = 0;
    nl_addr.nl_groups = groups_mask;

    unsafe {
        let ret = libc::bind(
            socket.as_raw_fd(),
            &nl_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }

    // Tune receive buffer to 8MB to prevent ENOBUFS
    let buffer_size: libc::c_int = 8 * 1024 * 1024;
    unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buffer_size as *const _ as *const libc::c_void,
            std::mem::size_of_val(&buffer_size) as libc::socklen_t,
        );
    }

    // Safety: The socket was created with SOCK_NONBLOCK, and we explicitly ensure non-blocking mode.
    socket.set_nonblocking(true)?;
    let async_fd = unsafe { tokio::io::unix::AsyncFd::register(socket) }?;
    tracing::info!("rtnetlink watcher started (groups: RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR)");

    Ok(tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        let mut ifindex_cache = rustc_hash::FxHashMap::<u32, String>::default();
        unsafe {
            let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs_ptr) == 0 {
                let mut next = ifaddrs_ptr;
                while !next.is_null() {
                    let ifaddr = &*next;
                    if !ifaddr.ifa_name.is_null() {
                        let name = std::ffi::CStr::from_ptr(ifaddr.ifa_name)
                            .to_string_lossy()
                            .into_owned();
                        let idx = libc::if_nametoindex(ifaddr.ifa_name);
                        if idx != 0 {
                            ifindex_cache.insert(idx, name);
                        }
                    }
                    next = ifaddr.ifa_next;
                }
                libc::freeifaddrs(ifaddrs_ptr);
            }
        }
        loop {
            if tx.is_closed() {
                tracing::debug!("iface_watcher: tx is closed, breaking loop");
                break;
            }
            let mut guard = match async_fd.readable().await {
                Ok(g) => {
                    tracing::debug!("iface_watcher: async_fd is readable");
                    g
                },
                Err(e) => {
                    tracing::error!("iface_watcher: readable() error: {}", e);
                    break;
                }
            };

            loop {
                let len = unsafe {
                    libc::recv(
                        async_fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                    )
                };
                tracing::debug!("iface_watcher: recv returned {}", len);
                if len < 0 {
                    let err = std::io::Error::last_os_error();
                    tracing::debug!("iface_watcher: recv error: {:?}", err);
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        tracing::debug!("iface_watcher: clear_ready");
                        guard.clear_ready();
                        break;
                    }
                    if err.raw_os_error() == Some(libc::ENOBUFS) {
                        tracing::warn!("Netlink socket receive error: ENOBUFS. Emitting ResyncRequired signal.");
                        let _ = tx.try_send(IfaceEvent::ResyncRequired);
                    }
                    break;
                } else if len == 0 {
                    tracing::debug!("iface_watcher: socket closed");
                    break;
                } else {
                    tracing::debug!("iface_watcher: parsing buffer of length {}", len);
                    parse_netlink_buffer(&buf[..len as usize], &tx, &filters, &mut ifindex_cache);
                }
            }
        }
    }))
}

#[cfg(target_os = "linux")]
fn parse_netlink_buffer(
    buffer: &[u8],
    tx: &mpsc::Sender<IfaceEvent>,
    filters: &Arc<Vec<String>>,
    ifindex_cache: &mut rustc_hash::FxHashMap<u32, String>,
) {
    let mut offset = 0;
    while offset + std::mem::size_of::<libc::nlmsghdr>() <= buffer.len() {
        // SAFETY: `buffer` bounds are checked to contain at least `size_of::<nlmsghdr>()`.
        let nlh = unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr() as *const libc::nlmsghdr) };
        let msg_len = nlh.nlmsg_len as usize;
        if msg_len < std::mem::size_of::<libc::nlmsghdr>() || offset + msg_len > buffer.len() {
            break;
        }

        let msg_type = nlh.nlmsg_type as u32;
        let rtm_newaddr = libc::RTM_NEWADDR as u32;
        let rtm_deladdr = libc::RTM_DELADDR as u32;
        let rtm_newlink = libc::RTM_NEWLINK as u32;
        let rtm_dellink = libc::RTM_DELLINK as u32;

        if msg_type == rtm_newaddr || msg_type == rtm_deladdr {
            let ifa_offset = offset + std::mem::size_of::<libc::nlmsghdr>();
            if ifa_offset + std::mem::size_of::<libc::ifaddrmsg>() <= offset + msg_len {
                // SAFETY: `buffer` bounds are checked to contain at least `size_of::<ifaddrmsg>()`.
                let ifa = unsafe {
                    std::ptr::read_unaligned(buffer[ifa_offset..].as_ptr() as *const libc::ifaddrmsg)
                };

                let attr_start = ifa_offset + std::mem::size_of::<libc::ifaddrmsg>();
                let attr_len = msg_len.saturating_sub(
                    std::mem::size_of::<libc::nlmsghdr>() + std::mem::size_of::<libc::ifaddrmsg>(),
                );

                if attr_start + attr_len <= buffer.len()
                    && let Some((addr, label, ext_flags)) =
                        parse_ifaddr_rtattrs(&buffer[attr_start..attr_start + attr_len], ifa.ifa_family)
                    {
                        if is_apipa(&addr) {
                            tracing::debug!(%addr, "APIPA address event filtered; ignoring event");
                            offset += (msg_len + 3) & !3;
                            continue;
                        }

                        let combined_flags = (ifa.ifa_flags as u32) | ext_flags;

                        let is_tentative = (combined_flags & libc::IFA_F_TENTATIVE) != 0;
                        if is_tentative && msg_type == rtm_newaddr {
                            tracing::info!(%addr, "IPv6 address is tentative (DAD in progress); deferring bind");
                            offset += (msg_len + 3) & !3;
                            continue;
                        }

                        let is_deprecated = (combined_flags & libc::IFA_F_DEPRECATED) != 0;
                        let ifindex = ifa.ifa_index as u32;

                        let mut name_buf = [0u8; libc::IF_NAMESIZE];
                        let iface_name = unsafe {
                            if !libc::if_indextoname(ifindex, name_buf.as_mut_ptr() as *mut libc::c_char)
                                .is_null()
                            {
                                let name = std::ffi::CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char)
                                    .to_string_lossy()
                                    .into_owned();
                                ifindex_cache.insert(ifindex, name.clone());
                                name
                            } else if let Some(cached_name) = ifindex_cache.get(&ifindex) {
                                cached_name.clone()
                            } else {
                                format!("ifindex_{}", ifindex)
                            }
                        };

                        let should_include = filters.is_empty()
                            || filters.iter().any(|f| &iface_name == f || label.as_deref() == Some(f.as_str()));

                        if should_include {
                            let event = if msg_type == rtm_newaddr {
                                IfaceEvent::AddressAdded {
                                    iface: iface_name,
                                    iface_label: label,
                                    ifindex,
                                    addr,
                                    is_deprecated,
                                }
                            } else {
                                IfaceEvent::AddressRemoved {
                                    iface: iface_name,
                                    iface_label: label,
                                    ifindex,
                                    addr,
                                }
                            };
                            let _ = tx.try_send(event);
                        }
                    }
            }
        } else if msg_type == rtm_newlink || msg_type == rtm_dellink {
            let ifi_offset = offset + std::mem::size_of::<libc::nlmsghdr>();
            if ifi_offset + std::mem::size_of::<libc::ifinfomsg>() <= offset + msg_len {
                let ifi = unsafe {
                    std::ptr::read_unaligned(buffer[ifi_offset..].as_ptr() as *const libc::ifinfomsg)
                };
                let is_up = if msg_type == rtm_dellink {
                    false
                } else {
                    (ifi.ifi_flags & libc::IFF_UP as libc::c_uint) != 0
                };
                let ifindex = ifi.ifi_index as u32;
                let mut parsed_name = None;
                let mut rtattr_offset = ifi_offset + std::mem::size_of::<libc::ifinfomsg>();
                while rtattr_offset + std::mem::size_of::<libc::rtattr>() <= offset + msg_len {
                    let rta = unsafe { std::ptr::read_unaligned(buffer[rtattr_offset..].as_ptr() as *const libc::rtattr) };
                    let rta_len = rta.rta_len as usize;
                    if rta_len < std::mem::size_of::<libc::rtattr>() || rtattr_offset + rta_len > offset + msg_len { break; }
                    if rta.rta_type == libc::IFLA_IFNAME {
                        let payload = &buffer[rtattr_offset + std::mem::size_of::<libc::rtattr>()..rtattr_offset + rta_len];
                        if let Ok(cstr) = std::ffi::CStr::from_bytes_with_nul(payload) {
                            parsed_name = Some(cstr.to_string_lossy().into_owned());
                        } else if !payload.is_empty() {
                            parsed_name = Some(String::from_utf8_lossy(payload).trim_matches('\0').to_string());
                        }
                    }
                    rtattr_offset += (rta_len + 3) & !3;
                }

                let mut name_buf = [0u8; libc::IF_NAMESIZE];
                let iface_name = unsafe {
                    if let Some(ref n) = parsed_name {
                        ifindex_cache.insert(ifindex, n.clone());
                        n.clone()
                    } else if !libc::if_indextoname(ifindex, name_buf.as_mut_ptr() as *mut libc::c_char).is_null() {
                        let name = std::ffi::CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char)
                            .to_string_lossy()
                            .into_owned();
                        ifindex_cache.insert(ifindex, name.clone());
                        name
                    } else if let Some(cached_name) = ifindex_cache.get(&ifindex) {
                        cached_name.clone()
                    } else {
                        format!("ifindex_{}", ifindex)
                    }
                };
                let should_include = filters.is_empty()
                    || filters.iter().any(|f| &iface_name == f);

                if msg_type == rtm_dellink {
                    tracing::debug!("RTM_DELLINK for ifindex {} name {:?} iface_name {:?} should_include {}", ifindex, parsed_name, iface_name, should_include);
                } else if msg_type == rtm_newlink {
                    tracing::debug!("RTM_NEWLINK for ifindex {} name {:?} iface_name {:?} is_up {} should_include {}", ifindex, parsed_name, iface_name, is_up, should_include);
                }

                if should_include {
                    tracing::info!(
                        %iface_name,
                        %ifindex,
                        %is_up,
                        "Interface state changed event emitted"
                    );
                    let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                        iface: iface_name.clone(),
                        ifindex,
                        is_up,
                    });
                }

                if msg_type == rtm_dellink {
                    ifindex_cache.remove(&ifindex);
                }
            }
        } else {
            tracing::debug!("Received netlink msg_type {}", msg_type);
        }
        offset += (msg_len + 3) & !3;
    }
}

#[cfg(target_os = "linux")]
fn parse_ifaddr_rtattrs(
    rtattr_buf: &[u8],
    family: libc::c_uchar,
) -> Option<(IpAddr, Option<String>, u32)> {
    let mut ip_addr = None;
    let mut local_ip = None;
    let mut label = None;
    let mut flags_attr = 0u32;

    let ifa_address = libc::IFA_ADDRESS as u32;
    let ifa_local = libc::IFA_LOCAL as u32;
    let ifa_label = libc::IFA_LABEL as u32;

    let mut offset = 0;
    while offset + std::mem::size_of::<libc::rtattr>() <= rtattr_buf.len() {
        let rta = unsafe { std::ptr::read_unaligned(rtattr_buf[offset..].as_ptr() as *const libc::rtattr) };
        let rta_len = rta.rta_len as usize;
        if rta_len < std::mem::size_of::<libc::rtattr>() || offset + rta_len > rtattr_buf.len() {
            break;
        }

        let payload_offset = offset + std::mem::size_of::<libc::rtattr>();
        let payload_len = rta_len - std::mem::size_of::<libc::rtattr>();
        if payload_offset + payload_len > rtattr_buf.len() {
            break;
        }
        let payload = &rtattr_buf[payload_offset..payload_offset + payload_len];
        let rta_type = rta.rta_type as u32;

        if rta_type == ifa_address {
            if family as libc::c_int == libc::AF_INET && payload.len() >= 4 {
                let bytes: [u8; 4] = payload[..4].try_into().ok()?;
                ip_addr = Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)));
            } else if family as libc::c_int == libc::AF_INET6 && payload.len() >= 16 {
                let bytes: [u8; 16] = payload[..16].try_into().ok()?;
                ip_addr = Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
            }
        } else if rta_type == ifa_local {
            if family as libc::c_int == libc::AF_INET && payload.len() >= 4 {
                let bytes: [u8; 4] = payload[..4].try_into().ok()?;
                local_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)));
            } else if family as libc::c_int == libc::AF_INET6 && payload.len() >= 16 {
                let bytes: [u8; 16] = payload[..16].try_into().ok()?;
                local_ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
            }
        } else if rta_type == ifa_label {
            if let Ok(cstr) = std::ffi::CStr::from_bytes_with_nul(payload) {
                label = Some(cstr.to_string_lossy().into_owned());
            } else if !payload.is_empty() {
                label = Some(String::from_utf8_lossy(payload).trim_matches('\0').to_string());
            }
        } else if rta_type == 8 {
            // IFA_FLAGS (32-bit extended flags)
            if payload.len() >= 4 {
                flags_attr = u32::from_ne_bytes(payload[..4].try_into().ok()?);
            }
        }

        offset += (rta_len + 3) & !3;
    }

    let final_ip = local_ip.or(ip_addr)?;
    Some((final_ip, label, flags_attr))
}

// ============================================================================
// macOS Driver Implementation (`PF_ROUTE` + `getifaddrs` Diff)
// ============================================================================

#[cfg(target_os = "macos")]
pub fn start_macos_watcher(
    tx: mpsc::Sender<IfaceEvent>,
    filters: Arc<Vec<String>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let route_socket = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
    if route_socket < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EACCES) {
            tracing::warn!("macOS PF_ROUTE socket creation failed (EACCES). Falling back to periodic getifaddrs polling.");
            return start_fallback_polling_thread(tx, filters);
        }
        return Err(err);
    }

    let socket = unsafe { socket2::Socket::from_raw_fd(route_socket) };
    socket.set_nonblocking(true)?;

    // SAFETY: `socket` is an owned `socket2::Socket` with a valid open file descriptor
    // that is non-blocking and will remain valid and unchanged for the lifetime of `AsyncFd`.
    let async_fd = unsafe { tokio::io::unix::AsyncFd::register(socket) }?;
    tracing::info!("macOS PF_ROUTE watcher socket opened successfully");

    Ok(tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        let mut ifindex_cache = std::collections::HashMap::<u32, String>::new();
        unsafe {
            let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifaddrs_ptr) == 0 {
                let mut next = ifaddrs_ptr;
                while !next.is_null() {
                    let ifaddr = &*next;
                    if !ifaddr.ifa_name.is_null() {
                        let name = std::ffi::CStr::from_ptr(ifaddr.ifa_name)
                            .to_string_lossy()
                            .into_owned();
                        let idx = libc::if_nametoindex(ifaddr.ifa_name);
                        if idx != 0 {
                            ifindex_cache.insert(idx, name);
                        }
                    }
                    next = ifaddr.ifa_next;
                }
                libc::freeifaddrs(ifaddrs_ptr);
            }
        }
        loop {
            if tx.is_closed() {
                break;
            }
            let mut guard = match async_fd.readable().await {
                Ok(g) => g,
                Err(_) => break,
            };

            match guard.try_io(|inner| {
                let len = unsafe {
                    libc::read(
                        inner.get_ref().as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if len < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(len as usize)
                }
            }) {
                Ok(Ok(bytes_read)) => {
                    parse_macos_route_msg(&buf[..bytes_read], &tx, &filters, &mut ifindex_cache);
                }
                _ => {}
            }
        }
    }))
}

#[cfg(target_os = "macos")]
fn parse_macos_route_msg(
    buffer: &[u8],
    tx: &mpsc::Sender<IfaceEvent>,
    filters: &Arc<Vec<String>>,
    ifindex_cache: &mut std::collections::HashMap<u32, String>,
) {
    let mut offset = 0;
    while offset < buffer.len() {
        if offset + 4 > buffer.len() {
            break;
        }
        let msg_len = u16::from_ne_bytes([buffer[offset], buffer[offset + 1]]) as usize;
        let msg_version = buffer[offset + 2];
        let msg_type = buffer[offset + 3];

        if msg_len < std::mem::size_of::<libc::ifa_msghdr>() || offset + msg_len > buffer.len() {
            break;
        }

        if msg_version as libc::c_int == libc::RTM_VERSION {
            match msg_type as libc::c_int {
                libc::RTM_NEWADDR | libc::RTM_DELADDR => {
                    if offset + std::mem::size_of::<libc::ifa_msghdr>() <= buffer.len() {
                        let ifam = unsafe {
                            std::ptr::read_unaligned(
                                buffer[offset..].as_ptr() as *const libc::ifa_msghdr
                            )
                        };
                        let ifindex = ifam.ifam_index as u32;

                        let mut name_buf = [0u8; libc::IF_NAMESIZE];
                        let iface_name = unsafe {
                            if !libc::if_indextoname(ifindex, name_buf.as_mut_ptr() as *mut libc::c_char)
                                .is_null()
                            {
                                let name = std::ffi::CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char)
                                    .to_string_lossy()
                                    .into_owned();
                                ifindex_cache.insert(ifindex, name.clone());
                                name
                            } else if let Some(cached_name) = ifindex_cache.get(&ifindex) {
                                cached_name.clone()
                            } else {
                                format!("ifindex_{}", ifindex)
                            }
                        };

                        let should_include = filters.is_empty() || filters.iter().any(|f| &iface_name == f);
                        if should_include {
                            let sa_start = offset + std::mem::size_of::<libc::ifa_msghdr>();
                            if sa_start < offset + msg_len {
                                if let Some(ip) = parse_macos_ifam_addrs(
                                    &buffer[sa_start..offset + msg_len],
                                    ifam.ifam_addrs as u32,
                                ) {
                                    if is_apipa(&ip) {
                                        offset += msg_len;
                                        continue;
                                    }

                                    let event = if msg_type as libc::c_int == libc::RTM_NEWADDR {
                                        IfaceEvent::AddressAdded {
                                            iface: iface_name,
                                            iface_label: None,
                                            ifindex,
                                            addr: ip,
                                            is_deprecated: false,
                                        }
                                    } else {
                                        IfaceEvent::AddressRemoved {
                                            iface: iface_name,
                                            iface_label: None,
                                            ifindex,
                                            addr: ip,
                                        }
                                    };
                                    let _ = tx.try_send(event);
                                }
                            }
                        }
                    }
                }
                libc::RTM_IFINFO => {
                    if offset + std::mem::size_of::<libc::if_msghdr>() <= buffer.len() {
                        let ifm = unsafe {
                            std::ptr::read_unaligned(
                                buffer[offset..].as_ptr() as *const libc::if_msghdr
                            )
                        };
                        let is_up = (ifm.ifm_flags & libc::IFF_UP as i32) != 0;
                        let ifindex = ifm.ifm_index as u32;
                        let mut name_buf = [0u8; libc::IF_NAMESIZE];
                        let iface_name = unsafe {
                            if !libc::if_indextoname(ifindex, name_buf.as_mut_ptr() as *mut libc::c_char)
                                .is_null()
                            {
                                let name = std::ffi::CStr::from_ptr(name_buf.as_ptr() as *const libc::c_char)
                                    .to_string_lossy()
                                    .into_owned();
                                ifindex_cache.insert(ifindex, name.clone());
                                name
                            } else if let Some(cached_name) = ifindex_cache.get(&ifindex) {
                                cached_name.clone()
                            } else {
                                format!("ifindex_{}", ifindex)
                            }
                        };
                        let should_include = filters.is_empty() || filters.iter().any(|f| &iface_name == f);
                        if should_include {
                            let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                                iface: iface_name,
                                ifindex,
                                is_up,
                            });
                        }
                    }
                }
                _ => {}
            }
        }
        offset += msg_len;
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_ifam_addrs(sa_buf: &[u8], addrs_mask: u32) -> Option<IpAddr> {
    let mut sa_offset = 0;
    let mut target_ip = None;

    for bit in 0..8 {
        let mask = 1u32 << bit;
        if (addrs_mask & mask) != 0 {
            if sa_offset >= sa_buf.len() {
                break;
            }
            let sa_len = sa_buf[sa_offset] as usize;
            let aligned_len = if sa_len == 0 { 4 } else { (sa_len + 3) & !3 };

            if mask == libc::RTA_IFA as u32 {
                if sa_offset + 2 <= sa_buf.len() {
                    let family = sa_buf[sa_offset + 1] as libc::c_int;
                    if family == libc::AF_INET
                        && sa_offset + std::mem::size_of::<libc::sockaddr_in>() <= sa_buf.len()
                    {
                        let sin = unsafe {
                            std::ptr::read_unaligned(
                                sa_buf[sa_offset..].as_ptr() as *const libc::sockaddr_in
                            )
                        };
                        let bytes = sin.sin_addr.s_addr.to_ne_bytes();
                        target_ip = Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)));
                    } else if family == libc::AF_INET6
                        && sa_offset + std::mem::size_of::<libc::sockaddr_in6>() <= sa_buf.len()
                    {
                        let sin6 = unsafe {
                            std::ptr::read_unaligned(
                                sa_buf[sa_offset..].as_ptr() as *const libc::sockaddr_in6
                            )
                        };
                        let bytes = sin6.sin6_addr.s6_addr;
                        target_ip = Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)));
                    }
                }
            }
            sa_offset += aligned_len;
        }
    }
    target_ip
}

// ============================================================================
// Windows Driver Implementation
// ============================================================================

#[cfg(target_os = "windows")]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, GetAdaptersAddresses, IpDadStateDeprecated, IpDadStateTentative,
    MibAddInstance, MibDeleteInstance, MibParameterNotification, IP_ADAPTER_ADDRESSES_LH,
    MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange,
    NotifyUnicastIpAddressChange, GAA_FLAG_INCLUDE_PREFIX,
};

#[cfg(target_os = "windows")]
pub struct WindowsWatcherContext {
    pub tx: mpsc::Sender<IfaceEvent>,
    pub filters: Arc<Vec<String>>,
    pub luid_alias_map: std::sync::Mutex<std::collections::HashMap<u64, String>>,
}

#[cfg(target_os = "windows")]
struct RegistrationGuard {
    addr_handle: isize,
    if_handle: isize,
    raw_ctx: usize,
}

/// SAFETY: `RegistrationGuard` holds raw Windows notification handles (`addr_handle`, `if_handle`)
/// and atomic context pointers (`raw_ctx`) which are safe to cancel and drop across threads.
#[cfg(target_os = "windows")]
unsafe impl Send for RegistrationGuard {}
#[cfg(target_os = "windows")]
unsafe impl Sync for RegistrationGuard {}

#[cfg(target_os = "windows")]
impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        let addr_handle = self.addr_handle;
        let if_handle = self.if_handle;
        let raw_ctx = self.raw_ctx;

        // CancelMibChangeNotify2 blocks until all in-flight OS threadpool callbacks finish.
        // Offload to a blocking threadpool thread to avoid blocking Tokio worker threads.
        let cleanup = move || unsafe {
            if addr_handle != 0 {
                CancelMibChangeNotify2(addr_handle);
            }
            if if_handle != 0 {
                CancelMibChangeNotify2(if_handle);
            }
            if raw_ctx != 0 {
                let _ = Arc::from_raw(raw_ctx as *const WindowsWatcherContext);
            }
        };

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn_blocking(cleanup);
        } else {
            std::thread::spawn(cleanup);
        }
    }
}

#[cfg(target_os = "windows")]
pub fn start_windows_watcher(
    tx: mpsc::Sender<IfaceEvent>,
    filters: Arc<Vec<String>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let ctx = Arc::new(WindowsWatcherContext {
        tx: tx.clone(),
        filters: filters.clone(),
        luid_alias_map: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    let raw_ctx_ptr = Arc::into_raw(ctx) as *const std::ffi::c_void;
    let raw_ctx_val = raw_ctx_ptr as usize;

    let mut addr_handle = 0isize;
    let mut if_handle = 0isize;

    let ret1 = unsafe {
        NotifyUnicastIpAddressChange(
            AF_UNSPEC as u16,
            Some(windows_unicast_ip_callback),
            raw_ctx_ptr,
            1,
            &mut addr_handle,
        )
    };

    if ret1 != NO_ERROR {
        let _ = unsafe { Arc::from_raw(raw_ctx_ptr as *const WindowsWatcherContext) };
        return Err(std::io::Error::from_raw_os_error(ret1 as i32));
    }

    let ret2 = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC as u16,
            Some(windows_interface_callback),
            raw_ctx_ptr,
            1,
            &mut if_handle,
        )
    };

    if ret2 != NO_ERROR {
        unsafe {
            CancelMibChangeNotify2(addr_handle);
            let _ = Arc::from_raw(raw_ctx_ptr as *const WindowsWatcherContext);
        }
        return Err(std::io::Error::from_raw_os_error(ret2 as i32));
    }

    let guard = RegistrationGuard {
        addr_handle,
        if_handle,
        raw_ctx: raw_ctx_val,
    };

    tracing::info!("Windows IP Helper unicast address and interface change notification handles registered");

    Ok(tokio::spawn(async move {
        let _guard = guard;
        let mut interval = tokio::time::interval(WINDOWS_IFACE_POLL_INTERVAL);
        let mut last_state = std::collections::HashMap::new();

        loop {
            interval.tick().await;
            if tx.is_closed() {
                break;
            }
            if let Ok(current_state) = query_windows_adapters(&filters) {
                diff_and_emit_windows_events(&last_state, &current_state, &tx);
                last_state = current_state;
            }
        }
    }))
}

#[cfg(target_os = "windows")]
pub unsafe extern "system" fn windows_unicast_ip_callback(
    caller_context: *const std::ffi::c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    if row.is_null() || caller_context.is_null() {
        return;
    }

    let ctx = unsafe { &*(caller_context as *const WindowsWatcherContext) };
    let row_ref = unsafe { &*row };

    let ifindex = row_ref.InterfaceIndex;
    let luid_val = unsafe { row_ref.InterfaceLuid.Value };

    let iface_name = {
        let mut alias_map = ctx.luid_alias_map.lock().unwrap();
        if let Some(name) = alias_map.get(&luid_val).cloned() {
            name
        } else {
            use windows_sys::Win32::Foundation::NO_ERROR;
            use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToAlias;
            let mut alias_buf = [0u16; 256];
            if unsafe {
                ConvertInterfaceLuidToAlias(
                    &row_ref.InterfaceLuid,
                    alias_buf.as_mut_ptr(),
                    alias_buf.len(),
                )
            } == NO_ERROR
            {
                let end = alias_buf.iter().position(|&c| c == 0).unwrap_or(alias_buf.len());
                let friendly_name = String::from_utf16_lossy(&alias_buf[..end]);
                alias_map.insert(luid_val, friendly_name.clone());
                friendly_name
            } else {
                format!("ifindex_{}", ifindex)
            }
        }
    };

    let should_include = ctx.filters.is_empty() || ctx.filters.iter().any(|f| &iface_name == f);
    if !should_include {
        return;
    }

    if row_ref.DadState == IpDadStateTentative {
        return;
    }
    let is_deprecated = row_ref.DadState == IpDadStateDeprecated;

    if let Some(ip_addr) = parse_winsock_address(&row_ref.Address) {
        if is_apipa(&ip_addr) {
            return;
        }

        let event = match notification_type {
            MibAddInstance | MibParameterNotification => IfaceEvent::AddressAdded {
                iface: iface_name,
                iface_label: None,
                ifindex,
                addr: ip_addr,
                is_deprecated,
            },
            MibDeleteInstance => IfaceEvent::AddressRemoved {
                iface: iface_name,
                iface_label: None,
                ifindex,
                addr: ip_addr,
            },
            _ => return,
        };

        let _ = ctx.tx.try_send(event);
    }
}

#[cfg(target_os = "windows")]
fn parse_winsock_address(
    addr: &windows_sys::Win32::Networking::WinSock::SOCKADDR_INET,
) -> Option<IpAddr> {
    unsafe {
        match addr.si_family {
            windows_sys::Win32::Networking::WinSock::AF_INET => {
                let ipv4 = addr.Ipv4;
                let bytes = ipv4.sin_addr.S_un.S_un_b;
                Some(IpAddr::V4(std::net::Ipv4Addr::new(
                    bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                )))
            }
            windows_sys::Win32::Networking::WinSock::AF_INET6 => {
                let ipv6 = addr.Ipv6;
                let bytes = ipv6.sin6_addr.u.Byte;
                Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
            }
            _ => None,
        }
    }
}

#[cfg(target_os = "windows")]
pub unsafe extern "system" fn windows_interface_callback(
    caller_context: *const std::ffi::c_void,
    row: *const windows_sys::Win32::NetworkManagement::IpHelper::MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    if row.is_null() || caller_context.is_null() {
        return;
    }
    let ctx = unsafe { &*(caller_context as *const WindowsWatcherContext) };
    let row_ref = unsafe { &*row };

    if notification_type != MibAddInstance
        && notification_type != MibDeleteInstance
        && notification_type != MibParameterNotification
    {
        return;
    }

    let ifindex = row_ref.InterfaceIndex;
    let luid_val = unsafe { row_ref.InterfaceLuid.Value };

    let iface_name = {
        let mut alias_map = ctx.luid_alias_map.lock().unwrap();
        if notification_type == MibAddInstance
            || notification_type == MibParameterNotification
            || !alias_map.contains_key(&luid_val)
        {
            use windows_sys::Win32::Foundation::NO_ERROR;
            use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToAlias;
            let mut alias_buf = [0u16; 256];
            if unsafe {
                ConvertInterfaceLuidToAlias(
                    &row_ref.InterfaceLuid,
                    alias_buf.as_mut_ptr(),
                    alias_buf.len(),
                )
            } == NO_ERROR
            {
                let end = alias_buf.iter().position(|&c| c == 0).unwrap_or(alias_buf.len());
                let friendly_name = String::from_utf16_lossy(&alias_buf[..end]);
                alias_map.insert(luid_val, friendly_name.clone());
                friendly_name
            } else {
                alias_map
                    .get(&luid_val)
                    .cloned()
                    .unwrap_or_else(|| format!("ifindex_{}", ifindex))
            }
        } else {
            alias_map
                .get(&luid_val)
                .cloned()
                .unwrap_or_else(|| format!("ifindex_{}", ifindex))
        }
    };

    let should_include = ctx.filters.is_empty() || ctx.filters.iter().any(|f| &iface_name == f);
    if !should_include {
        return;
    }

    let is_up = if notification_type == MibDeleteInstance {
        false
    } else {
        row_ref.Connected != 0
    };

    let event = IfaceEvent::InterfaceStateChanged {
        iface: iface_name,
        ifindex,
        is_up,
    };
    let _ = ctx.tx.try_send(event);
}

#[cfg(target_os = "windows")]
pub fn query_windows_adapters(
    filters: &[String],
) -> std::io::Result<std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>> {
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::Foundation::NO_ERROR;
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    let mut state = std::collections::HashMap::new();
    let mut buf_len = 15360u32;
    let mut buf = vec![0u8; buf_len as usize];

    let mut ret = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            GAA_FLAG_INCLUDE_PREFIX,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut buf_len,
        )
    };

    if ret == ERROR_BUFFER_OVERFLOW {
        buf.resize(buf_len as usize, 0);
        ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_PREFIX,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut buf_len,
            )
        };
    }

    if ret != NO_ERROR {
        return Err(std::io::Error::from_raw_os_error(ret as i32));
    }

    let mut curr = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !curr.is_null() {
        let adapter = unsafe { &*curr };
        if !adapter.FriendlyName.is_null() {
            let len = (0..)
                .take_while(|&i| unsafe { *adapter.FriendlyName.offset(i) } != 0)
                .count();
            let slice = unsafe { std::slice::from_raw_parts(adapter.FriendlyName, len) };
            let name = String::from_utf16_lossy(slice);

            let should_include = filters.is_empty() || filters.iter().any(|f| &name == f);
            if should_include {
                let ifindex = adapter.IfIndex;
                let is_up = adapter.OperStatus == 1;

                let entry = state
                    .entry(name)
                    .or_insert_with(|| (ifindex, is_up, Vec::new()));
                entry.1 = is_up;

                let mut unicast = adapter.FirstUnicastAddress;
                while !unicast.is_null() {
                    let uaddr = unsafe { &*unicast };
                    if !uaddr.Address.lpSockaddr.is_null() {
                        let sockaddr = unsafe { &*uaddr.Address.lpSockaddr };
                        if sockaddr.sa_family == windows_sys::Win32::Networking::WinSock::AF_INET as u16 {
                            let sin = unsafe {
                                &*(uaddr.Address.lpSockaddr
                                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN)
                            };
                            let bytes = sin.sin_addr.S_un.S_un_b;
                            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                                bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                            ));
                            if !is_apipa(&ip) {
                                entry.2.push(ip);
                            }
                        } else if sockaddr.sa_family
                            == windows_sys::Win32::Networking::WinSock::AF_INET6 as u16
                        {
                            let sin6 = unsafe {
                                &*(uaddr.Address.lpSockaddr
                                    as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN6)
                            };
                            let bytes = sin6.sin6_addr.u.Byte;
                            let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
                            if !is_apipa(&ip) {
                                entry.2.push(ip);
                            }
                        }
                    }
                    unicast = uaddr.Next;
                }
            }
        }
        curr = adapter.Next;
    }

    Ok(state)
}

#[cfg(target_os = "windows")]
fn diff_and_emit_windows_events(
    old_state: &std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>,
    new_state: &std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>,
    tx: &mpsc::Sender<IfaceEvent>,
) {
    for (name, (new_ifindex, new_is_up, new_ips)) in new_state {
        if let Some((old_ifindex, old_is_up, old_ips)) = old_state.get(name) {
            if new_ifindex != old_ifindex {
                let _ = tx.try_send(IfaceEvent::InterfaceIndexChanged {
                    iface: name.clone(),
                    old_ifindex: *old_ifindex,
                    new_ifindex: *new_ifindex,
                });
            }
            if new_is_up != old_is_up {
                let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                    iface: name.clone(),
                    ifindex: *new_ifindex,
                    is_up: *new_is_up,
                });
            }
            for ip in new_ips {
                if !old_ips.contains(ip) {
                    let _ = tx.try_send(IfaceEvent::AddressAdded {
                        iface: name.clone(),
                        iface_label: None,
                        ifindex: *new_ifindex,
                        addr: *ip,
                        is_deprecated: false,
                    });
                }
            }
            for ip in old_ips {
                if !new_ips.contains(ip) {
                    let _ = tx.try_send(IfaceEvent::AddressRemoved {
                        iface: name.clone(),
                        iface_label: None,
                        ifindex: *old_ifindex,
                        addr: *ip,
                    });
                }
            }
        } else {
            let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                iface: name.clone(),
                ifindex: *new_ifindex,
                is_up: *new_is_up,
            });
            for ip in new_ips {
                let _ = tx.try_send(IfaceEvent::AddressAdded {
                    iface: name.clone(),
                    iface_label: None,
                    ifindex: *new_ifindex,
                    addr: *ip,
                    is_deprecated: false,
                });
            }
        }
    }

    for (name, (old_ifindex, old_is_up, old_ips)) in old_state {
        if !new_state.contains_key(name) {
            if *old_is_up {
                let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                    iface: name.clone(),
                    ifindex: *old_ifindex,
                    is_up: false,
                });
            }
            for ip in old_ips {
                let _ = tx.try_send(IfaceEvent::AddressRemoved {
                    iface: name.clone(),
                    iface_label: None,
                    ifindex: *old_ifindex,
                    addr: *ip,
                });
            }
        }
    }
}

// ============================================================================
// Unix Fallback Polling Driver Implementation (`getifaddrs` Polling)
// ============================================================================

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn start_fallback_polling_thread(
    tx: mpsc::Sender<IfaceEvent>,
    filters: Arc<Vec<String>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    Ok(tokio::spawn(async move {
        let mut interval = tokio::time::interval(UNIX_IFACE_POLL_INTERVAL);
        let mut last_state = std::collections::HashMap::new();

        loop {
            interval.tick().await;
            if tx.is_closed() {
                break;
            }
            if let Ok(current_state) = query_unix_ifaddrs(&filters) {
                diff_and_emit_unix_events(&last_state, &current_state, &tx);
                last_state = current_state;
            }
        }
    }))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
type UnixIfaddrsMap = std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn query_unix_ifaddrs(
    filters: &[String],
) -> std::io::Result<UnixIfaddrsMap> {
    let mut state = std::collections::HashMap::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut curr = ifap;
    while !curr.is_null() {
        unsafe {
            let ifa = &*curr;
            if !ifa.ifa_name.is_null() {
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                    .to_string_lossy()
                    .into_owned();
                let should_include = filters.is_empty() || filters.iter().any(|f| &name == f);

                if should_include {
                    let ifindex = libc::if_nametoindex(ifa.ifa_name);
                    let is_up = (ifa.ifa_flags & libc::IFF_UP as libc::c_uint) != 0;

                    let entry = state
                        .entry(name)
                        .or_insert_with(|| (ifindex, is_up, Vec::new()));
                    entry.1 = is_up;

                    if !ifa.ifa_addr.is_null() {
                        let addr_family = (*ifa.ifa_addr).sa_family as libc::c_int;
                        if (addr_family == libc::AF_INET || addr_family == libc::AF_INET6)
                            && let Some(ip) = parse_sockaddr(ifa.ifa_addr)
                                && !is_apipa(&ip) {
                                    entry.2.push(ip);
                                }
                    }
                }
            }
            curr = ifa.ifa_next;
        }
    }

    unsafe {
        libc::freeifaddrs(ifap);
    }
    Ok(state)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_sockaddr(sa: *const libc::sockaddr) -> Option<IpAddr> {
    unsafe {
        match (*sa).sa_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(sa as *const libc::sockaddr_in);
                let bytes = sin.sin_addr.s_addr.to_ne_bytes();
                Some(IpAddr::V4(std::net::Ipv4Addr::from(bytes)))
            }
            libc::AF_INET6 => {
                let sin6 = &*(sa as *const libc::sockaddr_in6);
                let bytes = sin6.sin6_addr.s6_addr;
                Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
            }
            _ => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn diff_and_emit_unix_events(
    old_state: &std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>,
    new_state: &std::collections::HashMap<String, (u32, bool, Vec<IpAddr>)>,
    tx: &mpsc::Sender<IfaceEvent>,
) {
    for (name, (new_ifindex, new_is_up, new_ips)) in new_state {
        if let Some((old_ifindex, old_is_up, old_ips)) = old_state.get(name) {
            if new_ifindex != old_ifindex {
                let _ = tx.try_send(IfaceEvent::InterfaceIndexChanged {
                    iface: name.clone(),
                    old_ifindex: *old_ifindex,
                    new_ifindex: *new_ifindex,
                });
            }
            if new_is_up != old_is_up {
                let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                    iface: name.clone(),
                    ifindex: *new_ifindex,
                    is_up: *new_is_up,
                });
            }
            for ip in new_ips {
                if !old_ips.contains(ip) {
                    let _ = tx.try_send(IfaceEvent::AddressAdded {
                        iface: name.clone(),
                        iface_label: None,
                        ifindex: *new_ifindex,
                        addr: *ip,
                        is_deprecated: false,
                    });
                }
            }
            for ip in old_ips {
                if !new_ips.contains(ip) {
                    let _ = tx.try_send(IfaceEvent::AddressRemoved {
                        iface: name.clone(),
                        iface_label: None,
                        ifindex: *old_ifindex,
                        addr: *ip,
                    });
                }
            }
        } else {
            let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                iface: name.clone(),
                ifindex: *new_ifindex,
                is_up: *new_is_up,
            });
            for ip in new_ips {
                let _ = tx.try_send(IfaceEvent::AddressAdded {
                    iface: name.clone(),
                    iface_label: None,
                    ifindex: *new_ifindex,
                    addr: *ip,
                    is_deprecated: false,
                });
            }
        }
    }

    for (name, (old_ifindex, old_is_up, old_ips)) in old_state {
        if !new_state.contains_key(name) {
            if *old_is_up {
                let _ = tx.try_send(IfaceEvent::InterfaceStateChanged {
                    iface: name.clone(),
                    ifindex: *old_ifindex,
                    is_up: false,
                });
            }
            for ip in old_ips {
                let _ = tx.try_send(IfaceEvent::AddressRemoved {
                    iface: name.clone(),
                    iface_label: None,
                    ifindex: *old_ifindex,
                    addr: *ip,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_diff_and_emit_unix_events() {
        let (tx, mut rx) = mpsc::channel(64);

        let mut old_state = HashMap::new();
        old_state.insert(
            "eth0".to_string(),
            (1, true, vec!["192.168.1.1".parse::<IpAddr>().unwrap()]),
        );

        let mut new_state = HashMap::new();
        // eth0 updated: IP changed to 192.168.1.2, state to down, ifindex to 2
        new_state.insert(
            "eth0".to_string(),
            (2, false, vec!["192.168.1.2".parse::<IpAddr>().unwrap()]),
        );
        // eth1 added
        new_state.insert(
            "eth1".to_string(),
            (3, true, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]),
        );

        diff_and_emit_unix_events(&old_state, &new_state, &tx);

        let mut events = Vec::new();
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }

        assert!(events.contains(&IfaceEvent::InterfaceIndexChanged {
            iface: "eth0".to_string(),
            old_ifindex: 1,
            new_ifindex: 2,
        }));
        assert!(events.contains(&IfaceEvent::InterfaceStateChanged {
            iface: "eth0".to_string(),
            ifindex: 2,
            is_up: false,
        }));
        assert!(events.contains(&IfaceEvent::AddressAdded {
            iface: "eth0".to_string(),
            iface_label: None,
            ifindex: 2,
            addr: "192.168.1.2".parse().unwrap(),
            is_deprecated: false,
        }));
        assert!(events.contains(&IfaceEvent::AddressRemoved {
            iface: "eth0".to_string(),
            iface_label: None,
            ifindex: 1,
            addr: "192.168.1.1".parse().unwrap(),
        }));
        assert!(events.contains(&IfaceEvent::InterfaceStateChanged {
            iface: "eth1".to_string(),
            ifindex: 3,
            is_up: true,
        }));
        assert!(events.contains(&IfaceEvent::AddressAdded {
            iface: "eth1".to_string(),
            iface_label: None,
            ifindex: 3,
            addr: "10.0.0.1".parse().unwrap(),
            is_deprecated: false,
        }));
        assert_eq!(events.len(), 6);
    }

    #[tokio::test]
    async fn test_iface_watcher_abort_on_drop() {
        let mut watcher = IfaceWatcher::new(vec![]).unwrap();
        let mut rx = watcher.rx.take().unwrap();
        drop(watcher);
        let res = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());
    }

    #[test]
    fn test_bounded_channel_backpressure_drop() {
        let (tx, _rx) = mpsc::channel(2);
        let event = IfaceEvent::ResyncRequired;
        assert!(tx.try_send(event.clone()).is_ok());
        assert!(tx.try_send(event.clone()).is_ok());
        // Channel is now full (capacity 2); try_send should return Full error without panicking
        assert!(tx.try_send(event).is_err());
    }
}
