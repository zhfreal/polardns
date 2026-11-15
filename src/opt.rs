use clap::Parser;

pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u32 = 1000;
pub const DEFAULT_TCP_IDLE_TIMEOUT_MS: u32 = 10000;
pub const DEFAULT_QUIC_IDLE_TIMEOUT_MS: u32 = 30000;
pub const DEFAULT_QUEUE_TIMEOUT_MS: u32 = 2000;
pub const DEFAULT_RTT_PROBE_INTERVAL_SECS: u64 = 15;
pub const DEFAULT_RTT_PROBE_TIMEOUT_MS: u64 = 2000;
pub const DEFAULT_CACHE_CLEANUP_INTERVAL_SECS: u32 = 600;
pub const DEFAULT_MAX_CONCURRENT_QUERIES: usize = 1000;
pub const DEFAULT_MAX_CLIENT_CONNECTIONS: usize = 1024;

/// Next Generation DNS Proxy (Rust Rewrite)
#[derive(Parser, Debug, Clone, Default)]
#[command(
    author,
    version = crate::build_info::VERSION,
    about = "Next Generation DNS Proxy (Rust Rewrite)",
    long_about = None,
    help_template = "{name} {version}\n{about}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}"
)]
pub struct Opt {
    /// Config file path
    #[arg(short = 'C', long = "config")]
    pub config: Option<String>,

    #[arg(skip)]
    pub web_rules: Vec<crate::config::WebRule>,

    /// Workspace base directory for resolving relative paths
    #[arg(short = 'w', long = "workspace")]
    pub workspace: Option<String>,

    /// Custom User-Agent header string for HTTP requests (DoH, DoH3, Web rules)
    #[arg(long = "user-agent", alias = "user_agent", default_value = crate::http_client::DEFAULT_USER_AGENT)]
    pub user_agent: String,

    /// Bind addresses (e.g. 127.0.0.1, ::1, unix:/run/dns.sock, unixgram:/run/dns.sock)
    #[arg(
        short = 'b',
        long = "bind-addr",
        aliases = ["bind-address", "listen-address"],
        visible_short_aliases = ['a'],
        default_value = "127.0.0.1",
        value_delimiter = ','
    )]
    pub bind_addr: Vec<String>,

    /// Listen on specific address and port (e.g. 127.0.0.1:53, unix:/run/dns.sock)
    #[arg(short = 'L', long = "listen", value_delimiter = ',')]
    pub listen: Vec<String>,

    /// Bind to specific interfaces (dnsmasq style)
    #[arg(short = 'i', long = "interface", value_delimiter = ',')]
    pub interface: Vec<String>,

    /// Do not listen on specific interfaces (dnsmasq style)
    #[arg(short = 'I', long = "except-interface", value_delimiter = ',')]
    pub except_interface: Vec<String>,

    /// Bind only to specified interfaces statically using SO_BINDTODEVICE (Linux) or IP_BOUND_IF (macOS)
    #[arg(short = 'z', long = "bind-interfaces")]
    pub bind_interfaces: bool,

    /// Bind to specific interface IPs dynamically without SO_BINDTODEVICE
    #[arg(long = "bind-dynamic", alias = "bind")]
    pub bind_dynamic: bool,

    /// Standard DNS (UDP/TCP) listener ports (comma-separated)
    #[arg(
        short = 'p',
        long = "port",
        aliases = ["bind-port", "dns-port"],
        visible_short_aliases = ['l'],
        default_value = "53",
        value_delimiter = ','
    )]
    pub bind_port: Vec<u16>,

    /// Flag to enable DoT listener
    #[arg(long = "enable-dot")]
    pub enable_dot: bool,

    /// DoT listener ports (comma-separated)
    #[arg(long = "dot-port", aliases = ["tls-port"], default_value = "853", value_delimiter = ',')]
    pub dot_port: Vec<u16>,

    /// Flag to enable DoH listener
    #[arg(long = "enable-doh")]
    pub enable_doh: bool,

    /// DoH listener ports (comma-separated)
    #[arg(long = "doh-port", default_value = "443", value_delimiter = ',')]
    pub doh_port: Vec<u16>,

    /// Flag to enable DoH over HTTP/3 (QUIC). Requires --enable-doh.
    #[arg(long = "enable-doh3")]
    pub enable_doh3: bool,

    /// DoH3 listener ports (comma-separated)
    #[arg(long = "doh3-port", default_value = "443", value_delimiter = ',')]
    pub doh3_port: Vec<u16>,

    /// Flag to enable DNS-over-QUIC (DoQ) listener (RFC 9250).
    #[arg(long = "enable-doq")]
    pub enable_doq: bool,

    /// DoQ listener ports (comma-separated)
    #[arg(long = "doq-port", default_value = "853", value_delimiter = ',')]
    pub doq_port: Vec<u16>,

    /// Allow TLS 1.2 for local DoT/DoH TCP listeners. Requires build feature tls12.
    #[cfg(feature = "tls12")]
    #[arg(long = "enable-tls12")]
    pub enable_tls12: bool,

    /// Path to TLS certificate chain file (PEM)
    #[arg(long = "cert-file")]
    pub cert_file: Option<String>,

    /// Path to TLS private key file (PEM)
    #[arg(long = "key-file")]
    pub key_file: Option<String>,

    /// Additional TLS certificate/key pair for local DoT/DoH listeners.
    /// One pair is cert,key or a combined PEM. Repeat for multiple pairs,
    /// or pass a quoted ';'-separated list of pairs in one value.
    #[arg(long = "cert-pair")]
    pub cert_pair: Vec<String>,

    /// Reject local TLS handshakes without a matching DNS SNI name.
    #[arg(long = "strict-sni")]
    pub strict_sni: bool,

    /// Bind TLS listeners to specific interfaces (independent of plain DNS)
    #[arg(long = "tls-interface", value_delimiter = ',')]
    pub tls_interface: Vec<String>,

    /// Do not listen on specific interfaces for TLS listeners (independent of plain DNS)
    #[arg(long = "tls-except-interface", value_delimiter = ',')]
    pub tls_except_interface: Vec<String>,

    /// Bind TLS listeners to specific addresses (independent of plain DNS)
    #[arg(
        long = "tls-bind-addr",
        aliases = ["tls-bind-address", "tls-listen-address"],
        value_delimiter = ','
    )]
    pub tls_bind_addr: Vec<String>,

    /// Bind TLS listeners to specific interfaces statically via SO_BINDTODEVICE
    #[arg(long = "tls-bind-interfaces")]
    pub tls_bind_interfaces: bool,

    /// Bind TLS listeners to specific interface IPs dynamically via Netlink
    #[arg(long = "tls-bind-dynamic", alias = "tls-bind")]
    pub tls_bind_dynamic: bool,

    /// Disable binding to IPv6 Link-Local (fe80::/10) addresses globally
    #[arg(long = "no-ipv6-link-local")]
    pub no_ipv6_link_local: bool,

    /// Disable binding to IPv6 Link-Local (fe80::/10) addresses for TLS listeners
    #[arg(long = "no-tls-ipv6-link-local")]
    pub no_tls_ipv6_link_local: bool,

    /// Path for DoH requests
    #[arg(long = "doh-path", default_value = "/dns-query")]
    pub doh_path: String,

    /// Listen on UDP only
    #[arg(long = "udp-only")]
    pub udp_only: bool,

    /// Direct DNS servers (e.g. 114.114.114.114, 223.5.5.5) [alias: --polar-dns]
    #[arg(short = 'c', long = "direct-dns", alias = "polar-dns")]
    pub direct_dns: Option<String>,

    /// Send queries to all configured direct-dns servers simultaneously [alias: --polar-dns-all]
    #[arg(long = "direct-dns-all", alias = "polar-dns-all")]
    pub direct_dns_all: bool,

    /// Trusted Upstream DNS (e.g. 8.8.8.8, tls://1.1.1.1, https://1.1.1.1/dns-query) [alias: --trust-dns]
    #[arg(short = 't', long = "proxy-dns", alias = "trust-dns")]
    pub proxy_dns: Option<String>,

    /// Send queries to all configured proxy-dns servers simultaneously [alias: --trust-dns-all]
    #[arg(long = "proxy-dns-all", alias = "trust-dns-all")]
    pub proxy_dns_all: bool,

    /// Bootstrap DNS for resolving DoT/DoH hostnames; supports IP literals, udp://IP, or tcp://IP only
    #[arg(long = "fallback-dns")]
    pub fallback_dns: Option<String>,

    /// Send queries to all configured fallback-dns servers simultaneously
    #[arg(long = "fallback-dns-all")]
    pub fallback_dns_all: bool,

    /// Adblock Domain list file(s)
    #[arg(short = 'B', long = "adblock")]
    pub adblock_file: Vec<String>,

    /// [DEPRECATED] Direct Domain list file(s) [alias: --polarlist-file, --chnlist-file]
    #[arg(short = 'm', long = "directlist-file", alias = "polarlist-file", alias = "chnlist-file")]
    pub chnlist_file: Vec<String>,

    /// [DEPRECATED] GFW Domain list file(s)
    #[arg(short = 'g', long = "gfwlist-file")]
    pub gfwlist_file: Vec<String>,

    /// [DEPRECATED] Match directlist before gfwlist [alias: --polarlist-first, --chnlist-first]
    #[arg(short = 'M', long = "directlist-first", alias = "polarlist-first", alias = "chnlist-first")]
    pub chnlist_first: bool,

    /// Default tag for unmatched domains (e.g. direct, proxy)
    #[arg(short = 'd', long = "default-tag", default_value = "direct")]
    pub default_tag: String,

    /// [DEPRECATED] Add the ip of name-tag:direct to ipset/nftset (set4,set6). Use --direct-sets instead.
    #[arg(long = "add-tagdirect-ip", alias = "add-tagpolar-ip", alias = "add-tagchn-ip", value_name = "set4,set6")]
    pub add_tagchn_ip: Option<String>,

    /// [DEPRECATED] Add the ip of name-tag:proxy to ipset/nftset (set4,set6). Use --proxy-sets instead.
    #[arg(short = 'A', long = "add-taggfw-ip", value_name = "set4,set6")]
    pub add_taggfw_ip: Option<String>,

    /// Add the ip of name-tag:direct to ipset/nftset (comma-separated list of sets) [alias: --polar-sets, --chn-sets]
    #[arg(long = "direct-sets", alias = "polar-sets", alias = "chn-sets", value_delimiter = ',')]
    pub direct_sets: Vec<String>,

    /// Add the ip of name-tag:proxy to ipset/nftset (comma-separated list of sets) [alias: --gfw-sets]
    #[arg(long = "proxy-sets", alias = "gfw-sets", value_delimiter = ',')]
    pub proxy_sets: Vec<String>,

    /// Custom Group definitions
    #[arg(long = "group")]
    pub group: Vec<String>,

    /// [DEPRECATED] Custom Group Domain Name List
    #[arg(long = "group-dnl")]
    pub group_dnl: Vec<String>,

    /// Custom Group Upstream Servers
    #[arg(long = "group-upstream")]
    pub group_upstream: Vec<String>,

    /// [DEPRECATED] Custom Group IPSet assignments. Use --group-sets instead.
    #[arg(long = "group-ipset")]
    pub group_ipset: Vec<String>,

    /// Custom Group IPSet/NFTSet assignments
    #[arg(long = "group-sets")]
    pub group_sets: Vec<String>,

    /// Upstream Rule file
    #[arg(long = "upstream-rule")]
    pub upstream_rule: Vec<String>,

    /// Log DNS match results to a file (format: domain,Tag)
    #[arg(long = "log-dns-match")]
    pub log_dns_match: Option<String>,

    /// Set socket mark (SO_MARK) on outgoing packets (Linux only)
    #[arg(long = "out-mark")]
    pub out_mark: Option<u32>,

    /// Send queries to all configured group-upstream servers simultaneously
    #[arg(long = "group-upstream-all")]
    pub group_upstream_all: bool,

    /// Filter IPv6 rules (e.g. tag:name, direct...)
    #[arg(short = 'N', long = "no-ipv6")]
    pub no_ipv6: Option<String>,

    /// Filter queries with the given qtype
    #[arg(long = "filter-qtype")]
    pub filter_qtype: Vec<u16>,

    /// DNS Cache Size (0 to disable)
    #[arg(long = "cache", default_value_t = 0)]
    pub cache_size: usize,

    /// Stale Cache limits (seconds)
    #[arg(
        long = "cache-stale",
        default_value_t = 0,
        long_help = "Serve stale cache entries for this many seconds after their TTL expires. When a stale entry is served, a background query is automatically dispatched to refresh it."
    )]
    pub cache_stale: i32,

    /// Cache refresh threshold (percentage)
    #[arg(
        long = "cache-refresh",
        long_help = "Trigger a background refresh when a record's elapsed time in cache exceeds this percentage of its bounded TTL. Ensures hot records are proactively refreshed before expiring."
    )]
    pub cache_refresh: Option<u8>,

    /// TTL of the NODATA response
    #[arg(long = "cache-nodata-ttl", default_value_t = 60)]
    pub cache_nodata_ttl: u32,

    /// Minimum cache TTL override
    #[arg(
        long = "cache-min-ttl",
        long_help = "Force incoming records to have at least this TTL before they are saved to the cache. Prevents upstream servers from forcing too-frequent refreshes."
    )]
    pub cache_min_ttl: Option<u32>,

    /// Maximum cache TTL override
    #[arg(
        long = "cache-max-ttl",
        long_help = "Cap incoming records to this TTL before they are saved to the cache. Prevents routing staleness when upstream servers provide excessively long TTLs."
    )]
    pub cache_max_ttl: Option<u32>,

    /// Ignore dns cache for specific domains (suffix)
    #[arg(long = "cache-ignore")]
    pub cache_ignore: Vec<String>,

    /// Background cache cleanup interval (seconds, 0 to disable)
    #[arg(long = "cache-cleanup-interval", default_value_t = DEFAULT_CACHE_CLEANUP_INTERVAL_SECS)]
    pub cache_cleanup_interval: u32,

    /// Cache database persistence path
    #[arg(long = "cache-db")]
    pub cache_db: Option<String>,

    /// Enable verdict caching for tag:none domains
    #[arg(long = "verdict-cache")]
    pub verdict_cache_size: Option<usize>,

    /// Verdict Cache persistence path
    #[arg(long = "verdict-cache-db")]
    pub verdict_cache_db: Option<String>,

    /// Load hosts file
    #[arg(long = "hosts")]
    pub hosts: Option<String>,

    /// Add custom local resource records: --dns-rr-ip <names>=<ips>
    #[arg(long = "dns-rr-ip")]
    pub dns_rr_ip: Vec<String>,

    /// Enable SSL certificate validation
    #[arg(long = "cert-verify")]
    pub cert_verify: bool,

    /// CA certs path for SSL validation
    #[arg(long = "ca-certs")]
    pub ca_certs: Option<String>,

    /// Do not enable built-in ip blacklist for add-ip
    #[arg(long = "no-ipset-blacklist")]
    pub no_ipset_blacklist: bool,

    /// [DEPRECATED] Timeout for upstream servers (seconds)
    #[arg(short = 'o', long = "timeout-sec")]
    pub timeout_sec: Option<u16>,

    /// Timeout for upstream servers in milliseconds (overrides timeout-sec)
    #[arg(long = "timeout-ms", default_value_t = DEFAULT_UPSTREAM_TIMEOUT_MS)]
    pub timeout_ms: u32,

    /// Timeout for idle TCP client connections in milliseconds
    #[arg(long = "tcp-idle-timeout-ms", default_value_t = DEFAULT_TCP_IDLE_TIMEOUT_MS)]
    pub tcp_idle_timeout_ms: u32,

    /// Timeout for idle QUIC (DoH3 and DoQ) connections in milliseconds
    #[arg(long = "quic-idle-timeout-ms", default_value_t = DEFAULT_QUIC_IDLE_TIMEOUT_MS)]
    pub quic_idle_timeout_ms: u32,

    /// Timeout in milliseconds for waiting to acquire an internal query queue permit before dropping
    #[arg(long = "queue-timeout-ms", alias = "queue-timeout", default_value_t = DEFAULT_QUEUE_TIMEOUT_MS)]
    pub queue_timeout_ms: u32,

    /// Maximum number of concurrent queries the server will process globally
    #[arg(long = "max-concurrent-queries", default_value_t = DEFAULT_MAX_CONCURRENT_QUERIES)]
    pub max_concurrent_queries: usize,

    /// Number of Tokio worker threads (default: available CPU cores, or 1 on single-core / low-end)
    #[arg(long = "worker-threads", alias = "threads", value_name = "COUNT")]
    pub worker_threads: Option<usize>,

    /// Tokio worker thread stack size in bytes (default: 512KB for low-end / embedded, saves RAM)
    #[arg(long = "thread-stack-size", value_name = "BYTES")]
    pub thread_stack_size: Option<usize>,

    /// Maximum number of accepted TCP/DoT/DoH/DoH3 client connections
    #[arg(long = "max-client-connections", default_value_t = DEFAULT_MAX_CLIENT_CONNECTIONS)]
    pub max_client_connections: usize,

    /// HTTP/3 & QUIC performance profile: 'low', 'balanced', or 'high' [default: balanced]
    /// 
    /// Controls internal QUIC flow control windows, packet recycling pools, and task buffer sizes:
    ///   - low:      Optimized for resource-constrained devices (OpenWrt, 32MB-64MB RAM). Total H3 memory < 2MB.
    ///   - balanced: Standard default for home routers, NAS, and small VPS instances (128MB+ RAM).
    ///   - high:     High-throughput setting for dedicated servers and cloud deployments (512MB+ RAM).
    #[arg(long = "h3-profile", value_name = "PROFILE")]
    pub h3_profile: Option<String>,

    /// Enable ultra-low memory mode for HTTP/3 and QUIC (shortcut for --h3-profile low).
    /// Recommended for OpenWrt routers with 32MB-64MB RAM to keep total memory under 2MB RSS.
    #[arg(long = "h3-low-memory")]
    pub h3_low_memory: bool,

    /// Maximum number of cache refresh queries running in the background
    #[arg(long = "max-background-refreshes", default_value_t = 256)]
    pub max_background_refreshes: usize,

    /// Maximum number of active connections per TCP/DoT/DoH upstream
    #[arg(long = "max-upstream-conns", default_value_t = 16)]
    pub max_upstream_conns: usize,

    /// Number of packets to trustdns
    #[arg(long = "repeat-times", default_value_t = 1)]
    pub repeat_times: u8,

    /// Allow no-ip reply from polardns (tag:none)
    #[arg(short = 'n', long = "noip-as-directip", alias = "noip-as-polarip", alias = "noip-as-chnip")]
    pub noip_as_chnip: bool,

    /// Legacy option, deprecated (only fair mode now)
    #[arg(short = 'f', long = "fair-mode")]
    pub fair_mode: bool,

    /// Enable SO_REUSEPORT
    #[arg(short = 'r', long = "reuse-port")]
    pub reuse_port: bool,

    /// UDP socket send/receive buffer size in bytes (0 leaves OS defaults)
    #[arg(long = "socket-buffer-size", default_value_t = 1_048_576)]
    pub socket_buffer_size: usize,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// File to write standard tracing logs to
    #[arg(long = "log-file")]
    pub log_file: Option<String>,

    /// Directory to write rolling logs to
    #[arg(long = "log-dir")]
    pub log_dir: Option<String>,

    /// Global log level (TRACE, DEBUG, INFO, WARN, ERROR)
    #[arg(long = "log-level")]
    pub log_level: Option<String>,

    /// Log rotation period (minutely, hourly, daily, never)
    #[arg(long = "log-rotation-period", default_value = "never")]
    pub log_rotation_period: String,

    /// Log rotation size threshold (e.g. 10M, 1G)
    #[arg(long = "log-rotation-size")]
    pub log_rotation_size: Option<String>,

    /// Maximum number of rolled log files to retain
    #[arg(long = "log-max-files")]
    pub log_max_files: Option<usize>,

    /// File path to write DNS query resolution result logs (CSV format)
    #[arg(long = "log-dns-result")]
    pub log_dns_result: Option<String>,

    /// Number of RTT samples to use for EMA smoothing factor calculation (alpha = 2 / (N + 1))
    #[arg(long = "rtt-samples", default_value_t = 9)]
    pub rtt_samples: usize,

    /// Penalty in milliseconds added to RTT when an upstream fails or times out
    #[arg(long = "rtt-failure-penalty", default_value_t = 1000)]
    pub rtt_failure_penalty: u64,

    /// Frequency in seconds for sending background RTT active probes (0 to disable)
    #[arg(long = "rtt-probe-interval", default_value_t = DEFAULT_RTT_PROBE_INTERVAL_SECS)]
    pub rtt_probe_interval: u64,

    /// Timeout in milliseconds for background active RTT probe queries
    #[arg(long = "rtt-probe-timeout-ms", alias = "rtt-probe-timeout", default_value_t = DEFAULT_RTT_PROBE_TIMEOUT_MS)]
    pub rtt_probe_timeout_ms: u64,

    /// Skip field in command line parsing - stores group-specific no-ipv6 status
    #[arg(skip)]
    pub tag_to_no_ipv6: std::collections::HashMap<crate::tag::Tag, bool>,

    /// Skip field in command line parsing - stores group-specific query type filtering
    #[arg(skip)]
    pub tag_to_filter_qtype: std::collections::HashMap<crate::tag::Tag, Vec<u16>>,

    /// Skip field in command line parsing - stores group-specific concurrency (all) configuration
    #[arg(skip)]
    pub tag_to_all: std::collections::HashMap<crate::tag::Tag, bool>,
}

fn matches_short_flag(arg: &str, flag_char: char, takes_value: bool) -> bool {
    if !arg.starts_with('-') || arg.starts_with("--") {
        return false;
    }
    if takes_value {
        arg == format!("-{}", flag_char)
            || arg.starts_with(&format!("-{}=", flag_char))
            || (arg.starts_with(&format!("-{}", flag_char)) && arg.len() > 2)
            || (arg.ends_with(flag_char) && arg[1..arg.len()-1].chars().all(|c| c.is_ascii_alphabetic()))
    } else {
        let chars = &arg[1..];
        chars.contains(flag_char) && chars.chars().all(|c| c.is_ascii_alphabetic())
    }
}

impl Opt {
    pub fn validate(&self) -> Result<(), String> {
        if self.bind_interfaces && self.bind_dynamic {
            return Err("--bind-interfaces (-z) and --bind-dynamic / --bind are mutually exclusive".to_string());
        }
        if self.tls_bind_interfaces && self.tls_bind_dynamic {
            return Err("--tls-bind-interfaces and --tls-bind-dynamic / --tls-bind are mutually exclusive".to_string());
        }
        Ok(())
    }

    /// Loads configuration exactly fulfilling legacy initialization logic
    pub fn init() -> Self {
        Self::init_from(std::env::args().collect())
    }

    pub fn init_from(cli_args: Vec<String>) -> Self {
        let mut config_file = None;
        let mut workspace_cli = None;

        for i in 0..cli_args.len() {
            if cli_args[i] == "-C" || cli_args[i] == "--config" {
                if i + 1 < cli_args.len() {
                    config_file = Some(cli_args[i + 1].clone());
                }
            } else if (cli_args[i].starts_with("-C=") || cli_args[i].starts_with("--config="))
                && let Some(val) = cli_args[i].split('=').nth(1)
            {
                config_file = Some(val.to_string());
            } else if cli_args[i] == "-w" || cli_args[i] == "--workspace" {
                if i + 1 < cli_args.len() {
                    workspace_cli = Some(cli_args[i + 1].clone());
                }
            } else if (cli_args[i].starts_with("-w=") || cli_args[i].starts_with("--workspace="))
                && let Some(val) = cli_args[i].split('=').nth(1)
            {
                workspace_cli = Some(val.to_string());
            } else if cli_args[i].starts_with("-w") && cli_args[i].len() > 2 && !cli_args[i].contains('=') {
                workspace_cli = Some(cli_args[i][2..].to_string());
            }
        }
        let workspace_env = std::env::var("POLARDNS_WORKSPACE").ok();
        let workspace_opt = workspace_cli.clone().or(workspace_env.clone());

        let mut final_args = vec![cli_args[0].clone()];
        let mut parsed_structured_config: Option<crate::config::ConfigFile> = None;

        if let Some(path) = config_file {
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error: Failed to read config file '{}': {}", path, e);
                    std::process::exit(1);
                }
            };

            let config_dir = std::path::Path::new(&path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."));

            // Robust check to see if a configuration item is overridden on CLI
            let is_overridden = |aliases: &[&str]| {
                cli_args.iter().any(|arg| {
                    for alias in aliases {
                        if alias.starts_with("--") {
                            if arg == *alias || arg.starts_with(&format!("{}=", alias)) {
                                return true;
                            }
                        } else if alias.starts_with('-') && alias.len() == 2 {
                            let char_opt = alias.chars().nth(1).unwrap();
                            let takes_value = !matches!(char_opt, 'r' | 'v' | 'n' | 'f' | 'M');
                            if matches_short_flag(arg, char_opt, takes_value) {
                                return true;
                            }
                        }
                    }
                    false
                })
            };

            if path.ends_with(".toml") {
                let mut config: crate::config::ConfigFile = toml::from_str(&content).unwrap_or_else(|e| {
                    eprintln!("Error: Failed to parse TOML config '{}': {}", path, e);
                    std::process::exit(1);
                });
                let final_workspace = workspace_opt.clone().or(config.workspace.clone());
                let base_dir = if let Some(ws) = &final_workspace {
                    let ws_path = std::path::Path::new(ws);
                    if ws_path.is_relative() {
                        if workspace_cli.is_some() || workspace_env.is_some() {
                            std::fs::canonicalize(ws_path).unwrap_or_else(|_| ws_path.to_path_buf())
                        } else {
                            std::fs::canonicalize(config_dir.join(ws_path)).unwrap_or_else(|_| config_dir.join(ws_path))
                        }
                    } else {
                        ws_path.to_path_buf()
                    }
                } else {
                    config_dir.to_path_buf()
                };
                config.resolve_all_paths(&base_dir);
                if final_workspace.is_some() {
                    config.workspace = Some(base_dir.to_string_lossy().to_string());
                }
                final_args.extend(config.clone().into_cli_args(is_overridden));
                parsed_structured_config = Some(config);
            } else if path.ends_with(".yaml") || path.ends_with(".yml") {
                #[cfg(feature = "yaml")]
                {
                    let mut config: crate::config::ConfigFile = serde_yml::from_str(&content).unwrap_or_else(|e| {
                        eprintln!("Error: Failed to parse YAML config '{}': {}", path, e);
                        std::process::exit(1);
                    });
                    let final_workspace = workspace_opt.clone().or(config.workspace.clone());
                    let base_dir = if let Some(ws) = &final_workspace {
                        let ws_path = std::path::Path::new(ws);
                        if ws_path.is_relative() {
                            if workspace_cli.is_some() || workspace_env.is_some() {
                                std::fs::canonicalize(ws_path).unwrap_or_else(|_| ws_path.to_path_buf())
                            } else {
                                std::fs::canonicalize(config_dir.join(ws_path)).unwrap_or_else(|_| config_dir.join(ws_path))
                            }
                        } else {
                            ws_path.to_path_buf()
                        }
                    } else {
                        config_dir.to_path_buf()
                    };
                    config.resolve_all_paths(&base_dir);
                    if final_workspace.is_some() {
                        config.workspace = Some(base_dir.to_string_lossy().to_string());
                    }
                    final_args.extend(config.clone().into_cli_args(is_overridden));
                    parsed_structured_config = Some(config);
                }
                #[cfg(not(feature = "yaml"))]
                {
                    eprintln!("Error: Failed to parse '{}': YAML support was disabled at compile time. Please recompile with '--features yaml' or convert config to TOML.", path);
                    std::process::exit(1);
                }
            } else {
                if path.ends_with(".conf") {
                    tracing::warn!("DEPRECATION WARNING: Line-based .conf formats are deprecated. Please migrate to .toml or .yaml.");
                }
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let line_no_comment = if let Some((before_hash, _)) = line.split_once('#') {
                        before_hash.trim()
                    } else {
                        line
                    };

                    if line_no_comment.is_empty() {
                        continue;
                    }

                    let (parts_key, parts_val) = if let Some((k, v)) = line_no_comment.split_once(|c: char| c.is_whitespace()) {
                        (k.trim(), Some(v.trim()))
                    } else if let Some((k, v)) = line_no_comment.split_once('=') {
                        (k.trim(), Some(v.trim()))
                    } else {
                        (line_no_comment, None)
                    };

                    let mut key = format!("--{}", parts_key);
                    match key.as_str() {
                        "--bind-address" | "--listen-address" => key = "--bind-addr".to_string(),
                        "--bind" => key = "--bind-dynamic".to_string(),
                        "--tls-bind-address" | "--tls-listen-address" => key = "--tls-bind-addr".to_string(),
                        "--tls-bind" => key = "--tls-bind-dynamic".to_string(),
                        "--user_agent" => key = "--user-agent".to_string(),
                        _ => {}
                    }

                    let legacy_is_overridden = cli_args.iter().any(|arg| {
                        if arg == &key || arg.starts_with(&format!("{}=", key)) {
                            return true;
                        }
                        match key.as_str() {
                            "--user-agent" => arg == "--user-agent" || arg == "--user_agent",
                            "--bind-addr" => {
                                matches_short_flag(arg, 'b', true)
                                    || matches_short_flag(arg, 'a', true)
                                    || arg == "--bind-addr"
                                    || arg == "--bind-address"
                                    || arg == "--listen-address"
                            }
                            "--except-interface" => {
                                matches_short_flag(arg, 'I', true)
                                    || arg == "--except-interface"
                            }
                            "--bind-interfaces" => {
                                matches_short_flag(arg, 'z', true)
                                    || arg == "--bind-interfaces"
                            }
                            "--bind-dynamic" => {
                                arg == "--bind-dynamic"
                                    || arg == "--bind"
                            }
                            "--tls-except-interface" => arg == "--tls-except-interface",
                            "--tls-bind-interfaces" => arg == "--tls-bind-interfaces",
                            "--tls-bind-dynamic" => arg == "--tls-bind-dynamic" || arg == "--tls-bind",
                            "--doh3-port" => arg == "--doh3-port",
                            "--interface" => matches_short_flag(arg, 'i', true) || arg == "--interface",
                            "--bind-port" | "--dns-port" | "--port" => {
                                matches_short_flag(arg, 'l', true)
                                    || matches_short_flag(arg, 'p', true)
                                    || arg == "--bind-port"
                                    || arg == "--dns-port"
                                    || arg == "--port"
                            }
                            "--enable-dot" => arg == "--enable-dot",
                            "--dot-port" | "--tls-port" => {
                                arg == "--dot-port"
                                    || arg == "--tls-port"
                            }
                            "--enable-doh" => arg == "--enable-doh",
                            "--doh-port" => arg == "--doh-port",
                            "--enable-doh3" => arg == "--enable-doh3",
                            "--enable-doq" => arg == "--enable-doq",
                            "--doq-port" => arg == "--doq-port",
                            #[cfg(feature = "tls12")]
                            "--enable-tls12" => arg == "--enable-tls12",
                            "--cert-file" => arg == "--cert-file",
                            "--key-file" => arg == "--key-file",
                            "--cert-pair" => arg == "--cert-pair",
                            "--strict-sni" => arg == "--strict-sni",
                            "--doh-path" => arg == "--doh-path",
                            "--udp-only" => arg == "--udp-only",
                            "--tls-interface" => arg == "--tls-interface",
                            "--tls-bind-addr" => arg == "--tls-bind-addr",
                            "--no-ipv6-link-local" => arg == "--no-ipv6-link-local",
                            "--no-tls-ipv6-link-local" => arg == "--no-tls-ipv6-link-local",
                            "--polar-dns" | "--direct-dns" => {
                                matches_short_flag(arg, 'c', true)
                                    || arg == "--polar-dns"
                                    || arg == "--direct-dns"
                            }
                            "--polar-dns-all" | "--direct-dns-all" => {
                                arg == "--polar-dns-all" || arg == "--direct-dns-all"
                            }
                            "--trust-dns" | "--proxy-dns" => {
                                matches_short_flag(arg, 't', true)
                                    || arg == "--trust-dns"
                                    || arg == "--proxy-dns"
                            }
                            "--trust-dns-all" | "--proxy-dns-all" => {
                                arg == "--trust-dns-all" || arg == "--proxy-dns-all"
                            }
                            "--fallback-dns" => arg == "--fallback-dns",
                            "--fallback-dns-all" => arg == "--fallback-dns-all",
                            "--upstream-rule" => arg == "--upstream-rule",
                            "--log-dns-match" => arg == "--log-dns-match",
                            "--group-upstream-all" => arg == "--group-upstream-all",
                            "--directlist-file" | "--polarlist-file" | "--chnlist-file" => {
                                matches_short_flag(arg, 'm', true)
                                    || arg == "--directlist-file"
                                    || arg == "--polarlist-file"
                                    || arg == "--chnlist-file"
                            }
                            "--gfwlist-file" => {
                                matches_short_flag(arg, 'g', true) || arg == "--gfwlist-file"
                            }
                            "--directlist-first" | "--polarlist-first" | "--chnlist-first" => {
                                matches_short_flag(arg, 'M', false)
                                    || arg == "--directlist-first"
                                    || arg == "--polarlist-first"
                                    || arg == "--chnlist-first"
                            }
                            "--add-tagdirect-ip" | "--add-tagpolar-ip" | "--add-tagchn-ip" => {
                                arg == "--add-tagdirect-ip"
                                    || arg == "--add-tagpolar-ip"
                                    || arg == "--add-tagchn-ip"
                                    || arg == "--polar-sets"
                                    || arg == "--chn-sets"
                                    || arg == "--direct-sets"
                            }
                            "--add-taggfw-ip" => {
                                matches_short_flag(arg, 'A', true)
                                    || arg == "--add-taggfw-ip"
                                    || arg == "--gfw-sets"
                                    || arg == "--proxy-sets"
                            }
                            "--polar-sets" | "--chn-sets" | "--direct-sets" => {
                                arg == "--polar-sets"
                                    || arg == "--chn-sets"
                                    || arg == "--direct-sets"
                                    || arg == "--add-tagdirect-ip"
                                    || arg == "--add-tagpolar-ip"
                                    || arg == "--add-tagchn-ip"
                            }
                            "--gfw-sets" | "--proxy-sets" => {
                                arg == "--gfw-sets"
                                    || arg == "--proxy-sets"
                                    || matches_short_flag(arg, 'A', true)
                                    || arg == "--add-taggfw-ip"
                            }
                            "--group-ipset" => arg == "--group-ipset" || arg == "--group-sets",
                            "--group-sets" => arg == "--group-sets" || arg == "--group-ipset",
                            "--no-ipv6" => matches_short_flag(arg, 'N', true) || arg == "--no-ipv6",
                            "--timeout-sec" => matches_short_flag(arg, 'o', true),
                            "--timeout-ms" => arg == "--timeout-ms",
                            "--tcp-idle-timeout-ms" => arg == "--tcp-idle-timeout-ms",
                            "--quic-idle-timeout-ms" => arg == "--quic-idle-timeout-ms",
                            "--queue-timeout-ms" => arg == "--queue-timeout-ms" || arg == "--queue-timeout",
                            "--rtt-probe-interval" => arg == "--rtt-probe-interval",
                            "--rtt-probe-timeout-ms" => arg == "--rtt-probe-timeout-ms" || arg == "--rtt-probe-timeout",
                            "--max-concurrent-queries" => arg == "--max-concurrent-queries",
                            "--max-client-connections" => arg == "--max-client-connections",
                            "--max-background-refreshes" => arg == "--max-background-refreshes",
                            "--max-upstream-conns" => arg == "--max-upstream-conns",
                            "--repeat-times" => arg == "--repeat-times",
                            "--noip-as-directip" | "--noip-as-polarip" | "--noip-as-chnip" => {
                                matches_short_flag(arg, 'n', false)
                                    || arg == "--noip-as-directip"
                                    || arg == "--noip-as-polarip"
                                    || arg == "--noip-as-chnip"
                            },
                            "--fair-mode" => matches_short_flag(arg, 'f', false),
                            "--reuse-port" => matches_short_flag(arg, 'r', false),
                            "--socket-buffer-size" => arg == "--socket-buffer-size",
                            "--verbose" => matches_short_flag(arg, 'v', false),
                            "--listen" => {
                                matches_short_flag(arg, 'L', true) || arg == "--listen"
                            }
                            "--out-mark" => arg == "--out-mark",
                            "--workspace" => matches_short_flag(arg, 'w', true) || arg == "--workspace",
                            _ => false,
                        }
                    });

                    if !legacy_is_overridden {
                        final_args.push(key);
                        if let Some(val) = parts_val {
                            final_args.push(val.to_string());
                        }
                    }
                }
            }
        }

        final_args.extend(cli_args.into_iter().skip(1));
        let mut opt = Opt::parse_from(final_args);

        if let Err(e) = opt.validate() {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }

        if opt.default_tag == "chn" || opt.default_tag == "polar" {
            opt.default_tag = "direct".to_string();
        } else if opt.default_tag == "gfw" {
            opt.default_tag = "proxy".to_string();
        }

        // --- Post-Processing: Dynamic Registration, Validation and Memory Fields ---
        if let Some(config) = parsed_structured_config {
            // Validation: Both bind_addr+bind_port and listen are empty
            let mut listeners_empty = true;
            if let Some(ref listeners) = config.listeners
                && (listeners.listen.as_ref().map(|l| !l.is_empty()).unwrap_or(false)
                    || listeners.bind_addr.as_ref().map(|b| !b.is_empty()).unwrap_or(false)
                    || listeners.bind_port.as_ref().map(|p| !p.is_empty()).unwrap_or(false)
                    || listeners.tls.as_ref().map(|t| t.enable_dot.unwrap_or(false) || t.enable_doh.unwrap_or(false) || t.enable_doq.unwrap_or(false)).unwrap_or(false))
            {
                listeners_empty = false;
            }
            if listeners_empty {
                eprintln!("Error: No listener configured. Set bind_addr+bind_port or listen.");
                std::process::exit(1);
            }

            // Validation: Neither direct nor proxy upstreams defined
            let mut upstreams_defined = false;
            if let Some(ref upstreams) = config.upstreams
                && (upstreams.direct.as_ref().and_then(|d| d.servers.as_ref()).map(|s| !s.is_empty()).unwrap_or(false)
                    || upstreams.proxy.as_ref().and_then(|p| p.servers.as_ref()).map(|s| !s.is_empty()).unwrap_or(false))
            {
                upstreams_defined = true;
            }
            if !upstreams_defined {
                eprintln!("Error: At least one of upstreams.direct or upstreams.proxy must be configured");
                std::process::exit(1);
            }

            // Validation: at most one type = "default" rule is allowed
            let mut default_rule_count = 0;
            if let Some(ref rules) = config.rules {
                for rule in rules {
                    if let crate::config::RuleConfig::Default { tag } = rule {
                        default_rule_count += 1;
                        if tag == "adblock" {
                            eprintln!("Error: 'adblock' cannot be used as default tag");
                            std::process::exit(1);
                        }
                    }
                }
            }
            if default_rule_count > 1 {
                eprintln!("Error: Multiple type = 'default' rules are not allowed. Only one default tag can be defined in config.");
                std::process::exit(1);
            }

            if let Some(upstreams) = config.upstreams {
                use crate::tag::Tag;

                if let Some(direct) = upstreams.direct {
                    if direct.no_ipv6.unwrap_or(false) {
                        opt.tag_to_no_ipv6.insert(Tag::Direct, true);
                    }
                    if let Some(ref qtypes) = direct.filter_qtype {
                        opt.tag_to_filter_qtype.insert(Tag::Direct, qtypes.clone());
                    }
                }

                if let Some(proxy) = upstreams.proxy {
                    if proxy.no_ipv6.unwrap_or(false) {
                        opt.tag_to_no_ipv6.insert(Tag::Proxy, true);
                    }
                    if let Some(ref qtypes) = proxy.filter_qtype {
                        opt.tag_to_filter_qtype.insert(Tag::Proxy, qtypes.clone());
                    }
                }

                // Check custom group names reserved & duplicate/limits
                let mut registered_groups = std::collections::HashSet::new();
                if let Some(groups) = upstreams.groups {
                    for (name, group) in groups {
                        if name == "chn"
                            || name == "polar"
                            || name == "gfw"
                            || name == "direct"
                            || name == "proxy"
                            || name == "adblock"
                            || name == "block"
                            || name == "none"
                            || name == "hosts"
                        {
                            eprintln!("Error: Custom group name '{}' is reserved", name);
                            std::process::exit(1);
                        }
                        registered_groups.insert(name.clone());

                        match Tag::register(&name) {
                            Ok(tag) => {
                                if group.no_ipv6.unwrap_or(false) {
                                    opt.tag_to_no_ipv6.insert(tag, true);
                                }
                                if let Some(ref qtypes) = group.filter_qtype {
                                    opt.tag_to_filter_qtype.insert(tag, qtypes.clone());
                                }
                                if let Some(all) = group.all {
                                    opt.tag_to_all.insert(tag, all);
                                }
                            }
                            Err(_) => {
                                eprintln!("Error: Too many custom groups (max 253). Cannot register '{}'", name);
                                std::process::exit(1);
                            }
                        }
                    }
                }

                // Validate rules: type = "upstream" references undefined group, or custom group with no servers
                if let Some(ref rules) = config.rules {
                    for rule in rules {
                        if let crate::config::RuleConfig::Upstream { tag, path, url, refresh, .. } = rule {
                            if tag != "direct" && tag != "proxy" && !registered_groups.contains(tag) {
                                eprintln!("Error: Tag '{}' in rules must be a defined upstream group", tag);
                                std::process::exit(1);
                            }
                            if let Some(u) = url {
                                if let Some(p) = path {
                                    opt.web_rules.push(crate::config::WebRule {
                                        tag: tag.clone(),
                                        url: u.clone(),
                                        path: p.clone(),
                                        refresh: refresh.unwrap_or(86400),
                                    });
                                } else {
                                    eprintln!("Error: Upstream rule referencing URL '{}' must specify a local path", u);
                                    std::process::exit(1);
                                }
                            }
                            // Check rule file path does not exist after resolution (only if url is None)
                            if let Some(p) = path
                                && !std::path::Path::new(p).exists() && !p.starts_with("inline:base64:") && url.is_none() {
                                    eprintln!("Error: Rule file not found: '{}' (from config field: '{}')", p, p);
                                    std::process::exit(1);
                                }
                        }
                    }
                }
            }

            if let Some(ref adblock) = config.adblock {
                for entry in adblock {
                    match entry {
                        crate::config::AdblockConfig::Path(path) => {
                            if !opt.adblock_file.contains(path) {
                                opt.adblock_file.push(path.clone());
                            }
                            if !std::path::Path::new(path).exists() && !path.starts_with("inline:base64:") {
                                eprintln!("Error: Adblock rule file not found: '{}'", path);
                                std::process::exit(1);
                            }
                        }
                        crate::config::AdblockConfig::Web { url, path, refresh, .. } => {
                            opt.web_rules.push(crate::config::WebRule {
                                tag: "adblock".to_string(),
                                url: url.clone(),
                                path: path.clone(),
                                refresh: refresh.unwrap_or(86400),
                            });
                            if !opt.adblock_file.contains(path) {
                                opt.adblock_file.push(path.clone());
                            }
                        }
                    }
                }
            }

            if let Some(ref qtypes) = config.filter_qtype {
                opt.filter_qtype.extend(qtypes);
            }
            if let Some(ref no_ipv6) = config.no_ipv6
                && opt.no_ipv6.is_none() {
                    opt.no_ipv6 = Some(no_ipv6.clone());
                }
        }

        // --- Bridge CLI --no-ipv6 flag into tag_to_no_ipv6 ---
        if let Some(ref no_ipv6_str) = opt.no_ipv6 {
            for tag_name in no_ipv6_str.split(',') {
                let tag_name = tag_name.trim();
                if tag_name.is_empty() { continue; }
                if let Some(tag) = crate::tag::Tag::from_name(tag_name) {
                    opt.tag_to_no_ipv6.insert(tag, true);
                } else {
                    eprintln!("Warning: --no-ipv6 references unknown tag '{}', ignoring", tag_name);
                }
            }
        }

        opt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_dnsmasq_style_listen_flags() {
        let opt1 = Opt::parse_from(["polardns", "-a", "10.0.0.1", "--listen-address", "10.0.0.2", "--bind-address", "10.0.0.3"]);
        assert_eq!(opt1.bind_addr, vec!["10.0.0.1".to_string(), "10.0.0.2".to_string(), "10.0.0.3".to_string()]);

        let opt2 = Opt::parse_from(["polardns", "-p", "1053", "--port", "1054", "--dns-port", "1055"]);
        assert_eq!(opt2.bind_port, vec![1053, 1054, 1055]);

        let opt3 = Opt::parse_from(["polardns", "--tls-port", "8853"]);
        assert_eq!(opt3.dot_port, vec![8853]);

        let opt4 = Opt::parse_from(["polardns", "-I", "eth0", "--except-interface", "wlan*"]);
        assert_eq!(opt4.except_interface, vec!["eth0".to_string(), "wlan*".to_string()]);

        let opt5 = Opt::parse_from(["polardns", "-z", "--tls-bind-interfaces"]);
        assert!(opt5.bind_interfaces);
        assert!(opt5.tls_bind_interfaces);

        let opt6 = Opt::parse_from(["polardns", "--bind-dynamic", "--tls-bind-dynamic"]);
        assert!(opt6.bind_dynamic);
        assert!(opt6.tls_bind_dynamic);
        
        let opt7 = Opt::parse_from(["polardns", "--bind", "--tls-bind"]);
        assert!(opt7.bind_dynamic);
        assert!(opt7.tls_bind_dynamic);
    }

    #[test]
    fn test_bind_interfaces_and_dynamic_mutually_exclusive() {
        let opt_both = Opt::try_parse_from(["polardns", "-z", "--bind-dynamic"]).unwrap();
        assert!(opt_both.validate().is_err());
    }

    #[test]
    fn test_matches_short_flag() {
        // Flags taking values
        assert!(matches_short_flag("-b", 'b', true));
        assert!(matches_short_flag("-b127.0.0.1", 'b', true));
        assert!(matches_short_flag("-b=127.0.0.1", 'b', true));
        assert!(!matches_short_flag("-b", 'c', true));
        assert!(!matches_short_flag("--bind-addr", 'b', true));

        // Boolean flags (can be combined)
        assert!(matches_short_flag("-v", 'v', false));
        assert!(matches_short_flag("-vr", 'v', false));
        assert!(matches_short_flag("-vr", 'r', false));
        assert!(matches_short_flag("-rv", 'v', false));
        assert!(matches_short_flag("-rv", 'r', false));
        assert!(!matches_short_flag("-v", 'r', false));
        assert!(!matches_short_flag("-1", 'v', false));
    }

    #[test]
    fn test_strict_sni_parse() {
        let opt = Opt::parse_from(["polardns", "--strict-sni"]);
        assert!(opt.strict_sni);
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn test_enable_tls12_parse_when_feature_enabled() {
        let opt = Opt::parse_from(["polardns", "--enable-tls12"]);
        assert!(opt.enable_tls12);
    }

    #[cfg(not(feature = "tls12"))]
    #[test]
    fn test_enable_tls12_rejected_without_feature() {
        assert!(Opt::try_parse_from(["polardns", "--enable-tls12"]).is_err());
    }

    #[test]
    fn test_help_includes_version_and_commit() {
        let help = Opt::command().render_help().to_string();

        assert!(help.contains(env!("CARGO_PKG_VERSION")));
        assert!(help.contains(crate::build_info::GIT_COMMIT));
        assert!(help.contains(crate::build_info::ENABLED_FEATURES));
    }

    #[test]
    fn test_cli_override_config() {
        use std::io::Write;
        let mut tmp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write!(tmp_file, r#"
            [listeners]
            bind_port = [65353]
            bind_addr = ["127.0.0.1"]
            [upstreams.direct]
            servers = ["223.5.5.5"]
        "#).unwrap();
        
        let path = tmp_file.path().to_string_lossy().to_string();
        
        let args = vec![
            "polardns".to_string(),
            "-C".to_string(),
            path,
            "-l1054".to_string(),
        ];
        
        let opt = Opt::init_from(args);
        assert_eq!(opt.bind_port, vec![1054]);
        assert_eq!(opt.bind_addr, vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn test_cli_override_config_grouped() {
        use std::io::Write;
        let mut tmp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write!(tmp_file, r#"
            [listeners]
            bind_port = [65353]
            verbose = false
            [upstreams.direct]
            servers = ["223.5.5.5"]
        "#).unwrap();
        
        let path = tmp_file.path().to_string_lossy().to_string();
        
        let args = vec![
            "polardns".to_string(),
            "-C".to_string(),
            path,
            "-vl".to_string(),
            "1054".to_string(),
        ];
        
        let opt = Opt::init_from(args);
        assert_eq!(opt.bind_port, vec![1054]);
        assert!(opt.verbose);
    }

    #[test]
    fn test_tag_limit_expansion() {
        crate::tag::reset_custom_tags();
        // Register custom tags until we hit the registry limit (253 custom tags).
        // Since Tag::register checks current tags length against TAG_MAX,
        // it will eventually fail.
        let mut registered_count = 0;
        for i in 0..300 {
            let name = format!("limit_test_g{}", i);
            if crate::tag::Tag::register(&name).is_err() {
                registered_count = i;
                break;
            }
        }
        // Total custom tags registered should be bounded.
        assert!(registered_count > 0 && registered_count <= 253);
        crate::tag::reset_custom_tags();
    }

    #[test]
    fn test_adblock_config_toml_loading() {
        use std::io::Write;
        let mut adblock_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(adblock_file, "blocked.com").unwrap();
        let adblock_path = adblock_file.path().to_str().unwrap();

        let mut tmp_file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write!(tmp_file, r#"
            adblock = ["{}"]
            [listeners]
            bind_port = [1054]
            [upstreams.direct]
            servers = ["223.5.5.5"]
        "#, adblock_path).unwrap();
        
        let path = tmp_file.path().to_string_lossy().to_string();
        let args = vec![
            "polardns".to_string(),
            "-C".to_string(),
            path,
        ];
        
        let opt = Opt::init_from(args);
        assert_eq!(opt.adblock_file, vec![adblock_path.to_string()]);
    }

    #[test]
    fn test_tls_standalone_options_parsing() {
        let opt = Opt::parse_from([
            "polardns",
            "--tls-interface",
            "ppp0,wg0",
            "--tls-bind-addr",
            "fe80::1%ppp0,::1",
            "--no-ipv6-link-local",
            "--no-tls-ipv6-link-local",
        ]);
        assert_eq!(opt.tls_interface, vec!["ppp0".to_string(), "wg0".to_string()]);
        assert_eq!(opt.tls_bind_addr, vec!["fe80::1%ppp0".to_string(), "::1".to_string()]);
        assert!(opt.no_ipv6_link_local);
        assert!(opt.no_tls_ipv6_link_local);
    }

    #[test]
    fn test_worker_threads_and_stack_size_parsing() {
        let opt = Opt::parse_from([
            "polardns",
            "--worker-threads",
            "2",
            "--thread-stack-size",
            "262144",
        ]);
        assert_eq!(opt.worker_threads, Some(2));
        assert_eq!(opt.thread_stack_size, Some(262144));
    }

    #[test]
    fn test_timeout_and_interval_options_parsing() {
        let opt = Opt::parse_from([
            "polardns",
            "--queue-timeout-ms",
            "3500",
            "--rtt-probe-interval",
            "25",
            "--rtt-probe-timeout-ms",
            "1500",
        ]);
        assert_eq!(opt.queue_timeout_ms, 3500);
        assert_eq!(opt.rtt_probe_interval, 25);
        assert_eq!(opt.rtt_probe_timeout_ms, 1500);
    }
}

