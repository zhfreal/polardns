use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct ConfigFile {
    pub workspace: Option<String>,
    #[serde(alias = "user-agent")]
    pub user_agent: Option<String>,
    pub listeners: Option<ListenersConfig>,
    pub upstreams: Option<UpstreamsConfig>,
    pub rules: Option<Vec<RuleConfig>>,
    pub hosts: Option<HostsConfig>,
    pub cache: Option<CacheConfig>,
    pub ssl: Option<SslConfig>,
    pub ipset: Option<IpsetConfig>,
    pub limits: Option<LimitsConfig>,
    pub logging: Option<LoggingConfig>,
    pub adblock: Option<Vec<AdblockConfig>>,
    pub filter_qtype: Option<Vec<u16>>,
    #[serde(alias = "no-ipv6")]
    pub no_ipv6: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum AdblockConfig {
    Path(String),
    Web {
        url: String,
        path: String,
        refresh: Option<u64>,
        domains: Option<Vec<String>>,
    },
}

#[derive(Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum RuleConfig {
    #[serde(rename = "upstream")]
    Upstream {
        path: Option<String>,
        url: Option<String>,
        refresh: Option<u64>,
        domains: Option<Vec<String>>,
        tag: String,
    },
    #[serde(rename = "default")]
    Default {
        tag: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebRule {
    pub tag: String,
    pub url: String,
    pub path: String,
    pub refresh: u64,
}

fn resolve_single_path(path: &mut String, config_dir: &Path) {
    let p = Path::new(path);
    if p.is_relative() {
        let absolute_p = config_dir.join(p);
        *path = absolute_p.to_string_lossy().into_owned();
    }
}

fn resolve_opt_path(opt_path: &mut Option<String>, config_dir: &Path) {
    if let Some(path) = opt_path {
        resolve_single_path(path, config_dir);
    }
}

impl ConfigFile {
    /// Resolves all relative paths in the configuration relative to config_dir
    pub fn resolve_all_paths(&mut self, config_dir: &Path) {
        if let Some(rules) = &mut self.rules {
            for rule in rules {
                match rule {
                    RuleConfig::Upstream { path, .. } => {
                        resolve_opt_path(path, config_dir);
                    }
                    RuleConfig::Default { .. } => {}
                }
            }
        }

        if let Some(ref mut adblock) = self.adblock {
            for entry in adblock {
                match entry {
                    AdblockConfig::Path(path) => {
                        resolve_single_path(path, config_dir);
                    }
                    AdblockConfig::Web { path, .. } => {
                        resolve_single_path(path, config_dir);
                    }
                }
            }
        }

        if let Some(ref mut logging) = self.logging {
            resolve_opt_path(&mut logging.log_file, config_dir);
            resolve_opt_path(&mut logging.log_dir, config_dir);
            resolve_opt_path(&mut logging.log_dns_match, config_dir);
            resolve_opt_path(&mut logging.log_dns_result, config_dir);
        }

        if let Some(ref mut hosts) = self.hosts {
            resolve_opt_path(&mut hosts.hosts_file, config_dir);
        }

        if let Some(ref mut listeners) = self.listeners
            && let Some(ref mut tls) = listeners.tls
        {
            resolve_opt_path(&mut tls.cert_file, config_dir);
                resolve_opt_path(&mut tls.key_file, config_dir);
                if let Some(ref mut cert_pairs) = tls.cert_pairs {
                    for pair in cert_pairs {
                        resolve_single_path(&mut pair.cert, config_dir);
                        resolve_opt_path(&mut pair.key, config_dir);
                    }
                }
        }

        if let Some(ref mut ssl) = self.ssl {
            resolve_opt_path(&mut ssl.ca_certs, config_dir);
        }

        if let Some(ref mut cache) = self.cache {
            resolve_opt_path(&mut cache.db_path, config_dir);
        }

        if let Some(ref mut logging) = self.logging {
            resolve_opt_path(&mut logging.log_dns_match, config_dir);
        }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct UpstreamsConfig {
    pub direct: Option<UpstreamGroupExtended>,
    pub proxy: Option<UpstreamGroupExtended>,
    /// Fallback is a bootstrap resolver for DoT/DoH hostname resolution.
    /// It is NOT a routing tag — no filtering (no_ipv6, filter_qtype) applies.
    pub fallback: Option<FallbackConfig>,
    pub tuning: Option<UpstreamTuningConfig>,
    /// Must use IndexMap (not HashMap) for deterministic Tag::Custom(id) assignment order.
    pub groups: Option<indexmap::IndexMap<String, UpstreamGroupExtended>>,
}

/// Bootstrap resolver configuration. Minimal — only servers and all_mode.
/// No filtering fields because fallback is not a routing tag.
#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct FallbackConfig {
    pub servers: Option<Vec<String>>,
    pub all: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct UpstreamGroupExtended {
    pub servers: Option<Vec<String>>,
    pub all: Option<bool>,
    pub sets: Option<Vec<String>>,
    #[serde(alias = "no-ipv6")]
    pub no_ipv6: Option<bool>,
    #[serde(alias = "filter-qtype")]
    pub filter_qtype: Option<Vec<u16>>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct UpstreamTuningConfig {
    #[serde(alias = "repeat-times")]
    pub repeat_times: Option<u8>,
    #[serde(alias = "out-mark")]
    pub out_mark: Option<u32>,
    #[serde(alias = "group-upstream-all")]
    pub group_upstream_all: Option<bool>,
    #[serde(alias = "rtt-samples")]
    pub rtt_samples: Option<usize>,
    #[serde(alias = "rtt-failure-penalty")]
    pub rtt_failure_penalty: Option<u64>,
    #[serde(alias = "rtt-probe-interval")]
    pub rtt_probe_interval: Option<u64>,
    #[serde(alias = "rtt-probe-timeout-ms", alias = "rtt_probe_timeout_ms", alias = "rtt-probe-timeout")]
    pub rtt_probe_timeout_ms: Option<u64>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct ListenersConfig {
    #[serde(alias = "bind_port", alias = "port", deserialize_with = "deserialize_flex_u16_vec", default)]
    pub bind_port: Option<Vec<u16>>,
    #[serde(alias = "bind_addr", alias = "bind_address", alias = "listen_address", alias = "bind-addr", alias = "bind-address", alias = "listen-address")]
    pub bind_addr: Option<Vec<String>>,
    #[serde(alias = "except_interface", alias = "except-interface")]
    pub except_interface: Option<Vec<String>>,
    #[serde(alias = "bind_interfaces", alias = "bind-interfaces")]
    pub bind_interfaces: Option<bool>,
    #[serde(alias = "bind_dynamic", alias = "bind-dynamic", alias = "bind")]
    pub bind_dynamic: Option<bool>,
    pub listen: Option<Vec<String>>,
    pub interface: Option<Vec<String>>,
    #[serde(alias = "udp-only")]
    pub udp_only: Option<bool>,
    #[serde(alias = "no-ipv6-link-local")]
    pub no_ipv6_link_local: Option<bool>,
    pub tls: Option<TlsConfig>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct TlsConfig {
    #[serde(alias = "enable-dot")]
    pub enable_dot: Option<bool>,
    #[serde(alias = "dot_port", alias = "tls_port", alias = "port", deserialize_with = "deserialize_flex_u16_vec", default)]
    pub dot_port: Option<Vec<u16>>,
    #[serde(alias = "enable-doh")]
    pub enable_doh: Option<bool>,
    #[serde(alias = "doh-port", alias = "doh_port", deserialize_with = "deserialize_flex_u16_vec", default)]
    pub doh_port: Option<Vec<u16>>,
    #[serde(alias = "doh-path")]
    pub doh_path: Option<String>,
    #[serde(alias = "enable-doh3")]
    pub enable_doh3: Option<bool>,
    #[serde(alias = "doh3-port", alias = "doh3_port", deserialize_with = "deserialize_flex_u16_vec", default)]
    pub doh3_port: Option<Vec<u16>>,
    #[serde(alias = "enable-doq")]
    pub enable_doq: Option<bool>,
    #[serde(alias = "doq-port", alias = "doq_port", deserialize_with = "deserialize_flex_u16_vec", default)]
    pub doq_port: Option<Vec<u16>>,
    #[serde(alias = "quic-idle-timeout-ms")]
    pub quic_idle_timeout_ms: Option<u32>,
    #[serde(alias = "cert-file")]
    pub cert_file: Option<String>,
    #[serde(alias = "key-file")]
    pub key_file: Option<String>,
    #[serde(alias = "cert-pairs")]
    pub cert_pairs: Option<Vec<CertPairConfig>>,
    #[serde(alias = "strict-sni")]
    pub strict_sni: Option<bool>,
    #[serde(alias = "enable-tls12")]
    pub enable_tls12: Option<bool>,
    pub interface: Option<Vec<String>>,
    #[serde(alias = "except_interface", alias = "except-interface")]
    pub except_interface: Option<Vec<String>>,
    #[serde(alias = "bind_addr", alias = "bind_address", alias = "listen_address", alias = "bind-addr", alias = "bind-address", alias = "listen-address")]
    pub bind_addr: Option<Vec<String>>,
    #[serde(alias = "bind_interfaces", alias = "bind-interfaces")]
    pub bind_interfaces: Option<bool>,
    #[serde(alias = "bind_dynamic", alias = "bind-dynamic", alias = "bind")]
    pub bind_dynamic: Option<bool>,
    #[serde(alias = "no-ipv6-link-local")]
    pub no_ipv6_link_local: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct CertPairConfig {
    pub cert: String,
    pub key: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct HostsConfig {
    #[serde(alias = "hosts-file")]
    pub hosts_file: Option<String>,
    #[serde(alias = "rr-records")]
    pub rr_records: Option<HashMap<String, Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct CacheConfig {
    pub size: Option<usize>,
    pub stale: Option<i32>,
    pub refresh: Option<u8>,
    #[serde(alias = "nodata-ttl")]
    pub nodata_ttl: Option<u32>,
    #[serde(alias = "min-ttl")]
    pub min_ttl: Option<u32>,
    #[serde(alias = "max-ttl")]
    pub max_ttl: Option<u32>,
    #[serde(alias = "cache-ignore")]
    pub cache_ignore: Option<Vec<String>>,
    #[serde(alias = "cleanup-interval")]
    pub cleanup_interval: Option<u32>,
    #[serde(alias = "db-path")]
    pub db_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct SslConfig {
    #[serde(alias = "cert-verify")]
    pub cert_verify: Option<bool>,
    #[serde(alias = "ca-certs")]
    pub ca_certs: Option<String>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct IpsetConfig {
    #[serde(alias = "no-ipset-blacklist")]
    pub no_ipset_blacklist: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct LimitsConfig {
    #[serde(alias = "timeout-ms")]
    pub timeout_ms: Option<u32>,
    #[serde(alias = "tcp-idle-timeout-ms")]
    pub tcp_idle_timeout_ms: Option<u32>,
    #[serde(alias = "queue-timeout-ms", alias = "queue_timeout_ms", alias = "queue-timeout")]
    pub queue_timeout_ms: Option<u32>,
    #[serde(alias = "rtt-probe-timeout-ms", alias = "rtt_probe_timeout_ms", alias = "rtt-probe-timeout")]
    pub rtt_probe_timeout_ms: Option<u64>,
    #[serde(alias = "rtt-probe-interval", alias = "rtt_probe_interval")]
    pub rtt_probe_interval: Option<u64>,
    #[serde(alias = "max-concurrent-queries")]
    pub max_concurrent_queries: Option<usize>,
    #[serde(alias = "worker-threads", alias = "threads")]
    pub worker_threads: Option<usize>,
    #[serde(alias = "thread-stack-size")]
    pub thread_stack_size: Option<usize>,
    #[serde(alias = "max-client-connections")]
    pub max_client_connections: Option<usize>,
    #[serde(alias = "max-background-refreshes")]
    pub max_background_refreshes: Option<usize>,
    #[serde(alias = "max-upstream-conns")]
    pub max_upstream_conns: Option<usize>,
    #[serde(alias = "socket-buffer-size")]
    pub socket_buffer_size: Option<usize>,
    #[serde(alias = "reuse-port")]
    pub reuse_port: Option<bool>,
    
    // HTTP/3 Macro Performance Profiles
    #[serde(alias = "h3-profile")]
    pub h3_profile: Option<String>,
    #[serde(alias = "h3-low-memory")]
    pub h3_low_memory: Option<bool>,
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct LoggingConfig {
    #[serde(alias = "log-file")]
    pub log_file: Option<String>,
    #[serde(alias = "log-dir")]
    pub log_dir: Option<String>,
    #[serde(alias = "log-level")]
    pub log_level: Option<String>,
    #[serde(alias = "log-rotation-period")]
    pub log_rotation_period: Option<String>,
    #[serde(alias = "log-rotation-size")]
    pub log_rotation_size: Option<String>,
    #[serde(alias = "log-max-files")]
    pub log_max_files: Option<usize>,
    #[serde(alias = "log-dns-match")]
    pub log_dns_match: Option<String>,
    #[serde(alias = "log-dns-result")]
    pub log_dns_result: Option<String>,
    pub verbose: Option<bool>,
}

impl ConfigFile {
    /// Translates the structured configuration into an intermediate flat command line arguments vector 
    /// compatible with clap parser, skipping keys that are already overridden by the user manually.
    pub fn into_cli_args<F>(self, is_overridden: F) -> Vec<String>
    where
        F: Fn(&[&str]) -> bool,
    {
        let mut args = Vec::new();
        
        macro_rules! add_arg {
            ($flag:expr, $aliases:expr, $value:expr) => {
                if !is_overridden($aliases) {
                    args.push($flag.to_string());
                    args.push($value);
                }
            };
        }

        macro_rules! add_flag {
            ($flag:expr, $aliases:expr, $value:expr) => {
                if $value && !is_overridden($aliases) {
                    args.push($flag.to_string());
                }
            };
        }

        // 0. Workspace & User-Agent
        if let Some(ref ws) = self.workspace {
            add_arg!("--workspace", &["-w", "--workspace"], ws.clone());
        }
        if let Some(ref ua) = self.user_agent {
            add_arg!("--user-agent", &["--user-agent", "--user_agent"], ua.clone());
        }

        // 1. Listeners
        if let Some(listeners) = self.listeners {
            if let Some(bind_addr) = listeners.bind_addr {
                add_arg!("--bind-addr", &["--bind-addr", "-b"], bind_addr.join(","));
            }
            if let Some(bind_port) = listeners.bind_port {
                let port_strs: Vec<String> = bind_port.iter().map(|p| p.to_string()).collect();
                add_arg!("--bind-port", &["--bind-port", "-l", "--dns-port"], port_strs.join(","));
            }
            if let Some(listen) = listeners.listen {
                add_arg!("--listen", &["--listen", "-L"], listen.join(","));
            }
            if let Some(interface) = listeners.interface {
                add_arg!("--interface", &["--interface", "-i"], interface.join(","));
            }
            if let Some(except_interface) = listeners.except_interface {
                add_arg!("--except-interface", &["--except-interface", "-I"], except_interface.join(","));
            }
            add_flag!("--bind-interfaces", &["--bind-interfaces", "-z"], listeners.bind_interfaces.unwrap_or(false));
            add_flag!("--bind-dynamic", &["--bind-dynamic", "--bind"], listeners.bind_dynamic.unwrap_or(false));
            add_flag!("--udp-only", &["--udp-only"], listeners.udp_only.unwrap_or(false));
            add_flag!("--no-ipv6-link-local", &["--no-ipv6-link-local"], listeners.no_ipv6_link_local.unwrap_or(false));

            if let Some(tls) = listeners.tls {
                add_flag!("--enable-dot", &["--enable-dot"], tls.enable_dot.unwrap_or(false));
                if let Some(dot_port) = tls.dot_port {
                    let port_strs: Vec<String> = dot_port.iter().map(|p| p.to_string()).collect();
                    add_arg!("--dot-port", &["--dot-port"], port_strs.join(","));
                }
                add_flag!("--enable-doh", &["--enable-doh"], tls.enable_doh.unwrap_or(false));
                if let Some(doh_port) = tls.doh_port {
                    let port_strs: Vec<String> = doh_port.iter().map(|p| p.to_string()).collect();
                    add_arg!("--doh-port", &["--doh-port"], port_strs.join(","));
                }
                if let Some(doh_path) = tls.doh_path {
                    add_arg!("--doh-path", &["--doh-path"], doh_path);
                }
                add_flag!("--enable-doh3", &["--enable-doh3"], tls.enable_doh3.unwrap_or(false));
                if let Some(doh3_port) = tls.doh3_port {
                    let port_strs: Vec<String> = doh3_port.iter().map(|p| p.to_string()).collect();
                    add_arg!("--doh3-port", &["--doh3-port"], port_strs.join(","));
                }
                add_flag!("--enable-doq", &["--enable-doq"], tls.enable_doq.unwrap_or(false));
                if let Some(doq_ports) = tls.doq_port {
                    let ports_str = doq_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
                    add_arg!("--doq-port", &["--doq-port"], ports_str);
                }
                if let Some(quic_timeout) = tls.quic_idle_timeout_ms {
                    add_arg!("--quic-idle-timeout-ms", &["--quic-idle-timeout-ms"], quic_timeout.to_string());
                }
                if let Some(cert_file) = tls.cert_file {
                    add_arg!("--cert-file", &["--cert-file"], cert_file);
                }
                if let Some(key_file) = tls.key_file {
                    add_arg!("--key-file", &["--key-file"], key_file);
                }
                if let Some(cert_pairs) = tls.cert_pairs {
                    for pair in cert_pairs {
                        if let Some(ref key) = pair.key {
                            add_arg!("--cert-pair", &["--cert-pair"], format!("{},{}", pair.cert, key));
                        } else {
                            add_arg!("--cert-pair", &["--cert-pair"], pair.cert.clone());
                        }
                    }
                }
                add_flag!("--strict-sni", &["--strict-sni"], tls.strict_sni.unwrap_or(false));
                #[cfg(feature = "tls12")]
                if let Some(enable_tls12) = tls.enable_tls12 {
                    add_flag!("--enable-tls12", &["--enable-tls12"], enable_tls12);
                }
                if let Some(interface) = tls.interface {
                    add_arg!("--tls-interface", &["--tls-interface"], interface.join(","));
                }
                if let Some(except_interface) = tls.except_interface {
                    add_arg!("--tls-except-interface", &["--tls-except-interface"], except_interface.join(","));
                }
                if let Some(bind_addr) = tls.bind_addr {
                    add_arg!("--tls-bind-addr", &["--tls-bind-addr"], bind_addr.join(","));
                }
                add_flag!("--tls-bind-interfaces", &["--tls-bind-interfaces"], tls.bind_interfaces.unwrap_or(false));
                add_flag!("--tls-bind-dynamic", &["--tls-bind-dynamic", "--tls-bind"], tls.bind_dynamic.unwrap_or(false));
                add_flag!("--no-tls-ipv6-link-local", &["--no-tls-ipv6-link-local"], tls.no_ipv6_link_local.unwrap_or(false));
            }
        }

        // 2. Upstreams
        if let Some(upstreams) = self.upstreams {
            if let Some(direct) = upstreams.direct {
                if let Some(servers) = direct.servers {
                    add_arg!("--direct-dns", &["--direct-dns", "-c", "--china-dns"], servers.join(","));
                }
                add_flag!("--direct-dns-all", &["--direct-dns-all", "--china-dns-all"], direct.all.unwrap_or(false));
                if let Some(sets) = direct.sets {
                    add_arg!("--direct-sets", &["--direct-sets", "--chn-sets"], sets.join(","));
                }
            }
            if let Some(proxy) = upstreams.proxy {
                if let Some(servers) = proxy.servers {
                    add_arg!("--proxy-dns", &["--proxy-dns", "-t", "--trust-dns"], servers.join(","));
                }
                add_flag!("--proxy-dns-all", &["--proxy-dns-all", "--trust-dns-all"], proxy.all.unwrap_or(false));
                if let Some(sets) = proxy.sets {
                    add_arg!("--proxy-sets", &["--proxy-sets", "--gfw-sets"], sets.join(","));
                }
            }
            if let Some(fallback) = upstreams.fallback {
                if let Some(servers) = fallback.servers {
                    add_arg!("--fallback-dns", &["--fallback-dns"], servers.join(","));
                }
                add_flag!("--fallback-dns-all", &["--fallback-dns-all"], fallback.all.unwrap_or(false));
            }
            if let Some(tuning) = upstreams.tuning {
                if let Some(repeat_times) = tuning.repeat_times {
                    add_arg!("--repeat-times", &["--repeat-times"], repeat_times.to_string());
                }
                if let Some(out_mark) = tuning.out_mark {
                    add_arg!("--out-mark", &["--out-mark"], out_mark.to_string());
                }
                if let Some(group_upstream_all) = tuning.group_upstream_all {
                    add_flag!("--group-upstream-all", &["--group-upstream-all"], group_upstream_all);
                }
                if let Some(rtt_samples) = tuning.rtt_samples {
                    add_arg!("--rtt-samples", &["--rtt-samples"], rtt_samples.to_string());
                }
                if let Some(rtt_failure_penalty) = tuning.rtt_failure_penalty {
                    add_arg!("--rtt-failure-penalty", &["--rtt-failure-penalty"], rtt_failure_penalty.to_string());
                }
                if let Some(rtt_probe_interval) = tuning.rtt_probe_interval {
                    add_arg!("--rtt-probe-interval", &["--rtt-probe-interval"], rtt_probe_interval.to_string());
                }
                if let Some(rtt_probe_timeout_ms) = tuning.rtt_probe_timeout_ms {
                    add_arg!("--rtt-probe-timeout-ms", &["--rtt-probe-timeout-ms", "--rtt-probe-timeout"], rtt_probe_timeout_ms.to_string());
                }
            }

            // Custom groups — ALWAYS emit, not subject to override.
            // These are multi-value accumulative flags; both CLI and config groups
            // should be registered. Suppressing via is_overridden would incorrectly
            // hide config groups if ANY --group is passed on CLI.
            if let Some(groups) = upstreams.groups {
                for (name, group) in groups {
                    args.push("--group".to_string());
                    args.push(name.clone());
                    if let Some(servers) = group.servers {
                        args.push("--group-upstream".to_string());
                        args.push(format!("{}:{}", name, servers.join(",")));
                    }
                    if let Some(sets) = group.sets {
                        args.push("--group-sets".to_string());
                        args.push(format!("{}:{}", name, sets.join(",")));
                    }
                }
            }
        }

        // 3. Global Adblock List (prioritized first)
        // NOTE: --adblock does NOT have value_delimiter=',' — it expects one --adblock per file.
        // We must emit separate --adblock invocations, not comma-join them.
        if let Some(adblock) = self.adblock
            && !is_overridden(&["--adblock", "-B"])
        {
            for entry in adblock {
                match entry {
                    AdblockConfig::Path(path) => {
                        args.push("--adblock".to_string());
                        args.push(path);
                    }
                    AdblockConfig::Web { path, .. } => {
                        args.push("--adblock".to_string());
                        args.push(path);
                    }
                }
            }
        }

        // 4. Rules
        if let Some(rules) = self.rules {
            for rule in rules {
                match rule {
                    RuleConfig::Upstream { path, domains, tag, .. } => {
                        if let Some(ref path_str) = path {
                            add_arg!("--upstream-rule", &["--upstream-rule"], format!("{}@{}", path_str, tag));
                        }
                        if let Some(ref domains_list) = domains {
                            use base64::prelude::*;
                            let encoded = BASE64_STANDARD.encode(domains_list.join("\n").as_bytes());
                            add_arg!("--upstream-rule", &["--upstream-rule"], format!("inline:base64:{}@{}", encoded, tag));
                        }
                    }
                    RuleConfig::Default { tag } => {
                        add_arg!("--default-tag", &["--default-tag", "-d"], tag);
                    }
                }
            }
        }

        // 5. Hosts
        if let Some(hosts) = self.hosts {
            if let Some(hosts_file) = hosts.hosts_file {
                add_arg!("--hosts", &["--hosts"], hosts_file);
            }
            if let Some(rr_records) = hosts.rr_records {
                for (name, ips) in rr_records {
                    add_arg!("--dns-rr-ip", &["--dns-rr-ip"], format!("{}={}", name, ips.join(",")));
                }
            }
        }

        // 6. Cache
        if let Some(cache) = self.cache {
            if let Some(size) = cache.size {
                add_arg!("--cache", &["--cache"], size.to_string());
            }
            if let Some(stale) = cache.stale {
                add_arg!("--cache-stale", &["--cache-stale"], stale.to_string());
            }
            if let Some(refresh) = cache.refresh {
                add_arg!("--cache-refresh", &["--cache-refresh"], refresh.to_string());
            }
            if let Some(nodata_ttl) = cache.nodata_ttl {
                add_arg!("--cache-nodata-ttl", &["--cache-nodata-ttl"], nodata_ttl.to_string());
            }
            if let Some(min_ttl) = cache.min_ttl {
                add_arg!("--cache-min-ttl", &["--cache-min-ttl"], min_ttl.to_string());
            }
            if let Some(max_ttl) = cache.max_ttl {
                add_arg!("--cache-max-ttl", &["--cache-max-ttl"], max_ttl.to_string());
            }
            if let Some(cache_ignore) = cache.cache_ignore {
                for domain in cache_ignore {
                    add_arg!("--cache-ignore", &["--cache-ignore"], domain);
                }
            }
            if let Some(cleanup_interval) = cache.cleanup_interval {
                add_arg!("--cache-cleanup-interval", &["--cache-cleanup-interval"], cleanup_interval.to_string());
            }
            if let Some(db_path) = cache.db_path {
                add_arg!("--cache-db", &["--cache-db"], db_path);
            }
        }

        // 7. SSL
        if let Some(ssl) = self.ssl {
            add_flag!("--cert-verify", &["--cert-verify"], ssl.cert_verify.unwrap_or(false));
            if let Some(ca_certs) = ssl.ca_certs {
                add_arg!("--ca-certs", &["--ca-certs"], ca_certs);
            }
        }

        // 8. IPSet
        if let Some(ipset) = self.ipset {
            add_flag!("--no-ipset-blacklist", &["--no-ipset-blacklist"], ipset.no_ipset_blacklist.unwrap_or(false));
        }

        // 9. Limits
        if let Some(limits) = self.limits {
            if let Some(timeout_ms) = limits.timeout_ms {
                add_arg!("--timeout-ms", &["--timeout-ms"], timeout_ms.to_string());
            }
            if let Some(tcp_idle_timeout_ms) = limits.tcp_idle_timeout_ms {
                add_arg!("--tcp-idle-timeout-ms", &["--tcp-idle-timeout-ms"], tcp_idle_timeout_ms.to_string());
            }
            if let Some(queue_timeout_ms) = limits.queue_timeout_ms {
                add_arg!("--queue-timeout-ms", &["--queue-timeout-ms", "--queue-timeout"], queue_timeout_ms.to_string());
            }
            if let Some(rtt_probe_timeout_ms) = limits.rtt_probe_timeout_ms {
                add_arg!("--rtt-probe-timeout-ms", &["--rtt-probe-timeout-ms", "--rtt-probe-timeout"], rtt_probe_timeout_ms.to_string());
            }
            if let Some(rtt_probe_interval) = limits.rtt_probe_interval {
                add_arg!("--rtt-probe-interval", &["--rtt-probe-interval"], rtt_probe_interval.to_string());
            }
            if let Some(max_concurrent_queries) = limits.max_concurrent_queries {
                add_arg!("--max-concurrent-queries", &["--max-concurrent-queries"], max_concurrent_queries.to_string());
            }
            if let Some(worker_threads) = limits.worker_threads {
                add_arg!("--worker-threads", &["--worker-threads", "--threads"], worker_threads.to_string());
            }
            if let Some(thread_stack_size) = limits.thread_stack_size {
                add_arg!("--thread-stack-size", &["--thread-stack-size"], thread_stack_size.to_string());
            }
            if let Some(max_client_connections) = limits.max_client_connections {
                add_arg!("--max-client-connections", &["--max-client-connections"], max_client_connections.to_string());
            }
            if let Some(max_background_refreshes) = limits.max_background_refreshes {
                add_arg!("--max-background-refreshes", &["--max-background-refreshes"], max_background_refreshes.to_string());
            }
            if let Some(max_upstream_conns) = limits.max_upstream_conns {
                add_arg!("--max-upstream-conns", &["--max-upstream-conns"], max_upstream_conns.to_string());
            }
            if let Some(socket_buffer_size) = limits.socket_buffer_size {
                add_arg!("--socket-buffer-size", &["--socket-buffer-size"], socket_buffer_size.to_string());
            }
            add_flag!("--reuse-port", &["--reuse-port"], limits.reuse_port.unwrap_or(false));
            if let Some(h3_profile) = limits.h3_profile {
                add_arg!("--h3-profile", &["--h3-profile"], h3_profile);
            }
            add_flag!("--h3-low-memory", &["--h3-low-memory"], limits.h3_low_memory.unwrap_or(false));
        }

        // 10. Logging
        if let Some(logging) = self.logging {
            if let Some(log_file) = logging.log_file {
                add_arg!("--log-file", &["--log-file"], log_file);
            }
            if let Some(log_dir) = logging.log_dir {
                add_arg!("--log-dir", &["--log-dir"], log_dir);
            }
            if let Some(log_level) = logging.log_level {
                add_arg!("--log-level", &["--log-level"], log_level);
            }
            if let Some(log_rotation_period) = logging.log_rotation_period {
                add_arg!("--log-rotation-period", &["--log-rotation-period"], log_rotation_period);
            }
            if let Some(log_rotation_size) = logging.log_rotation_size {
                add_arg!("--log-rotation-size", &["--log-rotation-size"], log_rotation_size);
            }
            if let Some(log_max_files) = logging.log_max_files {
                add_arg!("--log-max-files", &["--log-max-files"], log_max_files.to_string());
            }
            if let Some(log_dns_match) = logging.log_dns_match {
                add_arg!("--log-dns-match", &["--log-dns-match"], log_dns_match);
            }
            if let Some(log_dns_result) = logging.log_dns_result {
                add_arg!("--log-dns-result", &["--log-dns-result"], log_dns_result);
            }
            add_flag!("--verbose", &["--verbose", "-v"], logging.verbose.unwrap_or(false));
        }

        args
    }
}

fn deserialize_flex_u16_vec<'de, D>(deserializer: D) -> Result<Option<Vec<u16>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct FlexVisitor;
    impl<'de> Visitor<'de> for FlexVisitor {
        type Value = Option<Vec<u16>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a port, array of ports, or comma-separated ports")
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u16::try_from(v)
                .map(|p| Some(vec![p]))
                .map_err(de::Error::custom)
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            u16::try_from(v)
                .map(|p| Some(vec![p]))
                .map_err(de::Error::custom)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let res: Result<Vec<u16>, _> = v.split(',')
                .map(|s| s.trim().parse::<u16>())
                .collect();
            res.map(Some).map_err(de::Error::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            #[derive(serde::Deserialize)]
            #[serde(untagged)]
            enum StringOrU16 {
                String(String),
                U16(u16),
            }
            let mut res = Vec::new();
            while let Some(elem) = seq.next_element::<StringOrU16>()? {
                match elem {
                    StringOrU16::U16(p) => res.push(p),
                    StringOrU16::String(s) => {
                        for part in s.split(',') {
                            let part = part.trim();
                            if !part.is_empty() {
                                let p = part.parse::<u16>().map_err(de::Error::custom)?;
                                res.push(p);
                            }
                        }
                    }
                }
            }
            Ok(Some(res))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(self)
        }
    }

    deserializer.deserialize_any(FlexVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_deserialize_flex_u16_vec() {
        let toml_content = r#"
            [listeners]
            bind_port = 53
            bind_addr = ["127.0.0.1"]
        "#;
        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        assert_eq!(config.listeners.unwrap().bind_port.unwrap(), vec![53]);

        let toml_content_str = r#"
            [listeners]
            bind_port = "53,54"
        "#;
        let config_str: ConfigFile = toml::from_str(toml_content_str).unwrap();
        assert_eq!(config_str.listeners.unwrap().bind_port.unwrap(), vec![53, 54]);

        let toml_content_arr = r#"
            [listeners]
            bind_port = [53, "54, 55", 56]
        "#;
        let config_arr: ConfigFile = toml::from_str(toml_content_arr).unwrap();
        assert_eq!(config_arr.listeners.unwrap().bind_port.unwrap(), vec![53, 54, 55, 56]);
    }

    #[test]
    fn test_parse_toml_config() {
        let toml_content = r#"
            [listeners]
            bind_addr = ["127.0.0.1", "::1"]
            bind_port = [1054]
            udp_only = true

            [upstreams.direct]
            servers = ["223.5.5.5"]
            sets = ["direct"]

            [upstreams.proxy]
            servers = ["8.8.8.8"]
            no_ipv6 = true
            filter_qtype = [28]

            [upstreams.groups.streaming]
            servers = ["1.1.1.1"]
            all = true

            [[rules]]
            type = "upstream"
            path = "rules/direct.list"
            tag = "direct"

            [[rules]]
            type = "default"
            tag = "direct"
        "#;

        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        
        let listeners = config.listeners.as_ref().unwrap();
        assert_eq!(listeners.bind_addr.as_ref().unwrap(), &vec!["127.0.0.1".to_string(), "::1".to_string()]);
        assert_eq!(listeners.bind_port.as_ref().unwrap(), &vec![1054]);
        assert!(listeners.udp_only.unwrap_or(false));

        let upstreams = config.upstreams.as_ref().unwrap();
        let direct = upstreams.direct.as_ref().unwrap();
        assert_eq!(direct.servers.as_ref().unwrap(), &vec!["223.5.5.5".to_string()]);
        
        let proxy = upstreams.proxy.as_ref().unwrap();
        assert_eq!(proxy.servers.as_ref().unwrap(), &vec!["8.8.8.8".to_string()]);
        assert!(proxy.no_ipv6.unwrap_or(false));
        assert_eq!(proxy.filter_qtype.as_ref().unwrap(), &vec![28]);

        let groups = upstreams.groups.as_ref().unwrap();
        let streaming = groups.get("streaming").unwrap();
        assert_eq!(streaming.servers.as_ref().unwrap(), &vec!["1.1.1.1".to_string()]);
        assert!(streaming.all.unwrap_or(false));

        let rules = config.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 2);
        match &rules[0] {
            RuleConfig::Upstream { path, tag, .. } => {
                assert_eq!(path.as_ref().unwrap(), "rules/direct.list");
                assert_eq!(tag, "direct");
            }
            _ => panic!("Expected RuleConfig::Upstream"),
        }
    }

    #[test]
    fn test_parse_example_config_toml() {
        let content = std::fs::read_to_string("examples/config.toml").unwrap();
        let config: ConfigFile = toml::from_str(&content).unwrap();
        assert!(config.adblock.is_some());
        assert_eq!(config.adblock.as_ref().unwrap().len(), 1);
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_parse_example_config_yaml() {
        let content = std::fs::read_to_string("examples/config.yaml").unwrap();
        let config: ConfigFile = serde_yml::from_str(&content).unwrap();
        assert!(config.adblock.is_some());
        assert_eq!(config.adblock.as_ref().unwrap().len(), 1);
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_parse_yaml_config() {
        let yaml_content = r#"
            listeners:
              bind_addr:
                - "127.0.0.1"
              bind_port: [1054]
            upstreams:
              direct:
                servers:
                  - "223.5.5.5"
        "#;
        let config: ConfigFile = serde_yml::from_str(yaml_content).unwrap();
        let listeners = config.listeners.as_ref().unwrap();
        assert_eq!(listeners.bind_addr.as_ref().unwrap(), &vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn test_kebab_and_snake_case_aliases() {
        let toml_content = r#"
            [listeners]
            bind-addr = ["127.0.0.1"]
            bind-port = [1054]
        "#;
        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        let listeners = config.listeners.as_ref().unwrap();
        assert_eq!(listeners.bind_addr.as_ref().unwrap(), &vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn test_relative_path_resolution() {
        let mut config = ConfigFile {
            hosts: Some(HostsConfig {
                hosts_file: Some("hosts.txt".to_string()),
                ..Default::default()
            }),
            cache: Some(CacheConfig {
                db_path: Some("cache.db".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        config.resolve_all_paths(Path::new("/tmp/test_dir"));
        assert_eq!(config.hosts.unwrap().hosts_file.unwrap(), "/tmp/test_dir/hosts.txt");
        assert_eq!(config.cache.unwrap().db_path.unwrap(), "/tmp/test_dir/cache.db");
    }

    #[test]
    fn test_parse_toml_config_with_url() {
        let toml_content = r#"
            [[rules]]
            type = "upstream"
            path = "rules/gfw-remote.txt"
            url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
            refresh = 86400
            tag = "proxy"
        "#;
        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        let rules = config.rules.as_ref().unwrap();
        assert_eq!(rules.len(), 1);
        match &rules[0] {
            RuleConfig::Upstream { path, url, refresh, tag, .. } => {
                assert_eq!(path.as_ref().unwrap(), "rules/gfw-remote.txt");
                assert_eq!(url.as_ref().unwrap(), "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt");
                assert_eq!(refresh.unwrap(), 86400);
                assert_eq!(tag, "proxy");
            }
            _ => panic!("Expected RuleConfig::Upstream"),
        }
    }

    #[test]
    #[cfg(feature = "yaml")]
    fn test_parse_yaml_config_with_url() {
        let yaml_content = r#"
            adblock:
              - rules/adblock-local.txt
              - url: https://easylist.to/easylist/easylist.txt
                path: rules/adblock-remote.txt
                refresh: 3600
        "#;
        let config: ConfigFile = serde_yml::from_str(yaml_content).unwrap();
        let adblock = config.adblock.as_ref().unwrap();
        assert_eq!(adblock.len(), 2);
        match &adblock[0] {
            AdblockConfig::Path(path) => assert_eq!(path, "rules/adblock-local.txt"),
            _ => panic!("Expected AdblockConfig::Path"),
        }
        match &adblock[1] {
            AdblockConfig::Web { url, path, refresh, .. } => {
                assert_eq!(path, "rules/adblock-remote.txt");
                assert_eq!(url, "https://easylist.to/easylist/easylist.txt");
                assert_eq!(refresh.unwrap(), 3600);
            }
            _ => panic!("Expected AdblockConfig::Web"),
        }
    }

    #[test]
    fn test_tls_standalone_and_link_local_config() {
        let toml_content = r#"
            [listeners]
            bind_addr = ["127.0.0.1"]
            bind_port = [53]
            no_ipv6_link_local = true

            [listeners.tls]
            enable_dot = true
            interface = ["ppp0"]
            bind_addr = ["fe80::1%ppp0"]
            no_ipv6_link_local = true
        "#;
        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        let listeners = config.listeners.as_ref().unwrap();
        assert!(listeners.no_ipv6_link_local.unwrap());
        
        let tls = listeners.tls.as_ref().unwrap();
        assert_eq!(tls.interface.as_ref().unwrap(), &vec!["ppp0".to_string()]);
        assert_eq!(tls.bind_addr.as_ref().unwrap(), &vec!["fe80::1%ppp0".to_string()]);
        assert!(tls.no_ipv6_link_local.unwrap());

        // Test into_cli_args serialization
        let args = config.into_cli_args(|_| false);
        assert!(args.contains(&"--no-ipv6-link-local".to_string()));
        assert!(args.contains(&"--tls-interface".to_string()));
        assert!(args.contains(&"ppp0".to_string()));
        assert!(args.contains(&"--tls-bind-addr".to_string()));
        assert!(args.contains(&"fe80::1%ppp0".to_string()));
        assert!(args.contains(&"--no-tls-ipv6-link-local".to_string()));
    }

    #[test]
    fn test_user_agent_config_and_cli_serialization() {
        let toml_content = r#"
            user_agent = "CustomUserAgent/2.0"
            [listeners]
            bind_port = [53]
        "#;
        let config: ConfigFile = toml::from_str(toml_content).unwrap();
        assert_eq!(config.user_agent.as_deref(), Some("CustomUserAgent/2.0"));

        let args = config.into_cli_args(|_| false);
        assert!(args.contains(&"--user-agent".to_string()));
        assert!(args.contains(&"CustomUserAgent/2.0".to_string()));

        #[cfg(feature = "yaml")]
        {
            let yaml_content = r#"
user-agent: "CustomUserAgent/3.0"
listeners:
  bind_port: [53]
"#;
            let yaml_config: ConfigFile = serde_yml::from_str(yaml_content).unwrap();
            assert_eq!(yaml_config.user_agent.as_deref(), Some("CustomUserAgent/3.0"));
        }
    }
}
