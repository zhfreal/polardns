//! General string, parsing, and socket configuration utilities

use crate::listener_manager::SocketKey;
use socket2::Socket;
use std::io;
use std::net::IpAddr;

/// Generic port parser
pub fn parse_port(s: &str) -> Option<u16> {
    s.parse::<u16>().ok()
}

/// Get all IP addresses (IPv4 and IPv6) for a given interface name
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_interface_addrs(iface: &str) -> Vec<IpAddr> {
    let mut addrs = Vec::new();
    let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` allocates a linked list of OS interface address structures.
    let res = unsafe { libc::getifaddrs(&mut ifaddrs_ptr) };
    if res != 0 || ifaddrs_ptr.is_null() {
        return addrs;
    }

    let mut next = ifaddrs_ptr;
    while !next.is_null() {
        // SAFETY: `next` is guaranteed to be a non-null pointer during iteration.
        let ifaddr = unsafe { &*next };
        if !ifaddr.ifa_name.is_null() {
            // SAFETY: `ifa_name` points to a valid null-terminated OS string.
            let name = unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) };
            if name.to_bytes() == iface.as_bytes() && !ifaddr.ifa_addr.is_null() {
                let family = unsafe { (*ifaddr.ifa_addr).sa_family } as libc::c_int;
                if family == libc::AF_INET {
                    let sa = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in) };
                    let ipv4 = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    if !ipv4.is_link_local() {
                        addrs.push(IpAddr::V4(ipv4));
                    }
                } else if family == libc::AF_INET6 {
                    let sa = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_in6) };
                    let ipv6 = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                    addrs.push(IpAddr::V6(ipv6)); // Stopped discarding link-local
                }
            }
        }
        next = ifaddr.ifa_next;
    }

    // SAFETY: `ifaddrs_ptr` allocated by `libc::getifaddrs` is freed here.
    unsafe { libc::freeifaddrs(ifaddrs_ptr) };
    addrs
}

#[cfg(target_os = "windows")]
pub fn get_interface_addrs(iface: &str) -> Vec<IpAddr> {
    if let Ok(state) = crate::iface_watcher::query_windows_adapters(&[iface.to_string()]) {
        if let Some((_, _, ips)) = state.get(iface) {
            return ips.clone();
        }
    }
    Vec::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_interface_addrs(_iface: &str) -> Vec<IpAddr> {
    Vec::new()
}


/// Resolve interface index from interface name
pub fn resolve_scope_id(iface: &str) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let c_iface = std::ffi::CString::new(iface).ok()?;
        // SAFETY: `c_iface` is a valid null-terminated C string.
        let idx = unsafe { libc::if_nametoindex(c_iface.as_ptr()) };
        if idx > 0 {
            Some(idx)
        } else {
            None
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Query adapters via GetAdaptersAddresses to map friendly interface name/alias to adapter IfIndex
        if let Ok(state) = crate::iface_watcher::query_windows_adapters(&[iface.to_string()]) {
            if let Some((ifindex, _, _)) = state.get(iface) {
                return Some(*ifindex);
            }
        }
        if let Some(rest) = iface.strip_prefix("ifindex_") {
            if let Ok(idx) = rest.parse::<u32>() {
                return Some(idx);
            }
        }
        if let Ok(idx) = iface.parse::<u32>() {
            return Some(idx);
        }
        None
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = iface;
        None
    }
}

/// Helper function to check if socket key targets loopback
pub fn is_loopback_target(key: &SocketKey) -> bool {
    key.addr.ip().is_loopback()
}

/// Check if error is Address Not Available (EADDRNOTAVAIL / WSAEADDRNOTAVAIL)
pub fn is_addr_not_available(err: &io::Error) -> bool {
    if let Some(code) = err.raw_os_error() {
        #[cfg(unix)]
        {
            code == libc::EADDRNOTAVAIL
        }
        #[cfg(windows)]
        {
            code == 10049 // WSAEADDRNOTAVAIL
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = code;
            false
        }
    } else {
        false
    }
}

/// Check if error is Address In Use (EADDRINUSE / WSAEADDRINUSE)
pub fn is_addr_in_use(err: &io::Error) -> bool {
    if let Some(code) = err.raw_os_error() {
        #[cfg(unix)]
        {
            code == libc::EADDRINUSE
        }
        #[cfg(windows)]
        {
            code == 10048 // WSAEADDRINUSE
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = code;
            false
        }
    } else {
        false
    }
}

/// Configure listener socket with cross-platform options and interface constraints
pub fn configure_listener_socket(socket: &Socket, key: &SocketKey, bind_interfaces: bool) -> io::Result<()> {
    // 1. Always set REUSEADDR
    socket.set_reuse_address(true)?;

    // 2. Set REUSEPORT where supported
    #[cfg(all(unix, not(target_os = "solaris")))]
    {
        let _ = socket.set_reuse_port(true);
    }

    // 3. Configure IPV6_V6ONLY for IPv6 sockets to keep v4 and v6 clean and explicit
    if key.addr.is_ipv6() {
        let _ = socket.set_only_v6(true);
    }

    // 4. Linux IP_FREEBIND / IPV6_FREEBIND optimization where applicable
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = 1;
        if key.addr.is_ipv4() {
            // SAFETY: `fd` is a valid socket file descriptor and `val` is a local integer option.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_FREEBIND,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
            }
        } else {
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    78, // IPV6_FREEBIND
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
            }
        }
    }

    // 5. Interface binding constraint
    if bind_interfaces && let Some(ref iface) = key.iface {
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::io::AsRawFd;
                let c_iface = std::ffi::CString::new(iface.as_str()).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, e)
                })?;
                let res = unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        c_iface.as_ptr() as *const libc::c_void,
                        c_iface.as_bytes_with_nul().len() as libc::socklen_t,
                    )
                };
                if res < 0 {
                    let err = io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
                        tracing::warn!(
                            iface = %iface,
                            "SO_BINDTODEVICE returned EPERM (missing CAP_NET_RAW). Falling back to IP-address constraint emulation."
                        );
                    } else {
                        return Err(err);
                    }
                }
            }

            #[cfg(target_os = "macos")]
            {
                use std::os::unix::io::AsRawFd;
                if let Some(ifindex) = resolve_scope_id(iface) {
                    let fd = socket.as_raw_fd();
                    if key.addr.is_ipv4() {
                        const IP_BOUND_IF: libc::c_int = 25;
                        let val = ifindex as libc::c_int;
                        unsafe {
                            libc::setsockopt(
                                fd,
                                libc::IPPROTO_IP,
                                IP_BOUND_IF,
                                &val as *const _ as *const libc::c_void,
                                std::mem::size_of_val(&val) as libc::socklen_t,
                            );
                        }
                    } else {
                        const IPV6_BOUND_IF: libc::c_int = 125;
                        let val = ifindex as libc::c_int;
                        unsafe {
                            libc::setsockopt(
                                fd,
                                libc::IPPROTO_IPV6,
                                IPV6_BOUND_IF,
                                &val as *const _ as *const libc::c_void,
                                std::mem::size_of_val(&val) as libc::socklen_t,
                            );
                        }
                    }
                }
            }

            #[cfg(target_os = "windows")]
            {
                use std::os::windows::io::AsRawSocket;
                if let Some(ifindex) = resolve_scope_id(iface) {
                    let sock = socket.as_raw_socket();
                    if key.addr.is_ipv4() {
                        const IP_UNICAST_IF: i32 = 31;
                        // Windows IP_UNICAST_IF requires network byte order (htonl) for IPv4 ifindex
                        let net_ifindex = ifindex.to_be();
                        unsafe {
                            let ret = windows_sys::Win32::Networking::WinSock::setsockopt(
                                sock as usize,
                                windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                                IP_UNICAST_IF,
                                &net_ifindex as *const _ as *const u8,
                                std::mem::size_of_val(&net_ifindex) as i32,
                            );
                            if ret != 0 {
                                tracing::warn!(
                                    iface = %iface,
                                    ifindex = %ifindex,
                                    "Failed to set IP_UNICAST_IF on Windows socket: {}",
                                    io::Error::last_os_error()
                                );
                            }
                        }
                    } else {
                        const IPV6_UNICAST_IF: i32 = 31;
                        // Windows IPV6_UNICAST_IF requires host byte order
                        unsafe {
                            let ret = windows_sys::Win32::Networking::WinSock::setsockopt(
                                sock as usize,
                                windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
                                IPV6_UNICAST_IF,
                                &ifindex as *const _ as *const u8,
                                std::mem::size_of_val(&ifindex) as i32,
                            );
                            if ret != 0 {
                                tracing::warn!(
                                    iface = %iface,
                                    ifindex = %ifindex,
                                    "Failed to set IPV6_UNICAST_IF on Windows socket: {}",
                                    io::Error::last_os_error()
                                );
                            }
                        }
                    }
                } else {
                    tracing::warn!(
                        iface = %iface,
                        "Could not resolve Windows interface name to adapter index for socket binding"
                    );
                }
            }
    }

    // 6. Support IP_PKTINFO / IPV6_RECVPKTINFO for wildcard sockets
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if (key.protocol == crate::listener_manager::ProtocolKind::PlainUdp
            || key.protocol == crate::listener_manager::ProtocolKind::DoQ
            || key.protocol == crate::listener_manager::ProtocolKind::DoH3)
            && key.addr.ip().is_unspecified()
        {
            if key.addr.is_ipv4() {
                let opt: libc::c_int = 1;
                // SAFETY: `socket` is a valid file descriptor; opt is local c_int.
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_PKTINFO,
                        &opt as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&opt) as libc::socklen_t,
                    );
                }
            } else if key.addr.is_ipv6() {
                let opt: libc::c_int = 1;
                // SAFETY: `socket` is a valid file descriptor; opt is local c_int.
                unsafe {
                    libc::setsockopt(
                        socket.as_raw_fd(),
                        libc::IPPROTO_IPV6,
                        libc::IPV6_RECVPKTINFO,
                        &opt as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&opt) as libc::socklen_t,
                    );
                }
            }
        }
    }

    Ok(())
}

/// Get all active interfaces, their IP addresses, and optional IPv6 scope IDs (excluding IPv4 APIPA 169.254.x.x)
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn get_all_interfaces() -> Vec<(String, IpAddr, Option<u32>)> {
    let mut interfaces = Vec::new();
    let mut ifaddrs_ptr: *mut libc::ifaddrs = std::ptr::null_mut();

    unsafe {
        if libc::getifaddrs(&mut ifaddrs_ptr) != 0 {
            return interfaces;
        }

        let mut next = ifaddrs_ptr;
        while !next.is_null() {
            let ifaddr = &*next;
            if !ifaddr.ifa_name.is_null() && !ifaddr.ifa_addr.is_null() {
                let name = std::ffi::CStr::from_ptr(ifaddr.ifa_name).to_string_lossy().into_owned();
                let family = (*ifaddr.ifa_addr).sa_family as libc::c_int;
                if family == libc::AF_INET {
                    let sa = &*(ifaddr.ifa_addr as *const libc::sockaddr_in);
                    let ipv4 = std::net::Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    if !ipv4.is_link_local() {
                        interfaces.push((name, IpAddr::V4(ipv4), None));
                    }
                } else if family == libc::AF_INET6 {
                    let sa = &*(ifaddr.ifa_addr as *const libc::sockaddr_in6);
                    let ipv6 = std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr);
                    let scope_id = if sa.sin6_scope_id != 0 {
                        Some(sa.sin6_scope_id)
                    } else {
                        let c_name = std::ffi::CStr::from_ptr(ifaddr.ifa_name);
                        let idx = libc::if_nametoindex(c_name.as_ptr());
                        if idx != 0 { Some(idx) } else { None }
                    };
                    interfaces.push((name, IpAddr::V6(ipv6), scope_id));
                }
            }
            next = ifaddr.ifa_next;
        }

        libc::freeifaddrs(ifaddrs_ptr);
    }
    interfaces
}

#[cfg(target_os = "windows")]
pub fn get_all_interfaces() -> Vec<(String, IpAddr, Option<u32>)> {
    let mut interfaces = Vec::new();
    if let Ok(state) = crate::iface_watcher::query_windows_adapters(&[]) {
        for (name, (ifindex, _, ips)) in state {
            for ip in ips {
                let scope_id = if ip.is_ipv6() { Some(ifindex) } else { None };
                interfaces.push((name.clone(), ip, scope_id));
            }
        }
    }
    interfaces
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn get_all_interfaces() -> Vec<(String, IpAddr, Option<u32>)> {
    Vec::new()
}

/// Match interface name against pattern (supporting '*' wildcard and trailing asterisk prefix wildcards)
pub fn match_interface(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

/// Check if interface name is excluded by any of the patterns
pub fn is_interface_excluded(name: &str, except_list: &[String]) -> bool {
    except_list.iter().any(|pattern| match_interface(pattern, name))
}

/// Check if interface name matches any of the allowed interface patterns
pub fn is_interface_allowed(name: &str, interface_list: &[String]) -> bool {
    if interface_list.is_empty() {
        return true;
    }
    interface_list.iter().any(|pattern| match_interface(pattern, name))
}

#[cfg(feature = "jemalloc")]
pub fn purge_jemalloc() {
    let _ = tikv_jemalloc_ctl::epoch::advance();
    // SAFETY: mallctl arena.4096.purge purges dirty extents across all arenas
    unsafe {
        let _ = tikv_jemalloc_ctl::raw::write(b"arena.4096.purge\0", ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_matching() {
        assert!(match_interface("*", "eth0"));
        assert!(match_interface("eth*", "eth0"));
        assert!(match_interface("eth*", "eth1"));
        assert!(!match_interface("eth*", "wlan0"));
        assert!(match_interface("wlan0", "wlan0"));
        assert!(!match_interface("wlan0", "wlan1"));

        let except_list = vec!["eth*".to_string(), "lo".to_string()];
        assert!(is_interface_excluded("eth0", &except_list));
        assert!(is_interface_excluded("lo", &except_list));
        assert!(!is_interface_excluded("wlan0", &except_list));

        let allowed_list = vec!["wlan*".to_string()];
        assert!(is_interface_allowed("wlan0", &allowed_list));
        assert!(!is_interface_allowed("eth0", &allowed_list));
    }

    #[test]
    fn test_configure_listener_socket_bind_interfaces_toggle() {
        use socket2::{Domain, Type, Socket};
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).unwrap();
        let key = crate::listener_manager::SocketKey::new(
            "127.0.0.1:53".parse().unwrap(),
            crate::listener_manager::ProtocolKind::PlainUdp,
            Some("lo".to_string())
        );

        // When bind_interfaces = false, socket configuration should succeed without needing root SO_BINDTODEVICE
        assert!(configure_listener_socket(&socket, &key, false).is_ok());
    }

    #[test]
    fn test_parse_port() {
        assert_eq!(parse_port("53"), Some(53));
        assert_eq!(parse_port("65535"), Some(65535));
        assert_eq!(parse_port("65536"), None);
    }

    #[test]
    fn test_is_apipa() {
        use crate::iface_watcher::is_apipa;
        assert!(is_apipa(&"169.254.1.1".parse().unwrap()));
        assert!(!is_apipa(&"192.168.1.1".parse().unwrap()));
        assert!(!is_apipa(&"::1".parse().unwrap()));
    }
}
