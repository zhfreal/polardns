#[cfg(all(feature = "quiche", feature = "original"))]
compile_error!("Features 'quiche' and 'original' are mutually exclusive and cannot be enabled at the same time.");

#[cfg(all(feature = "quiche", feature = "original-h3-server"))]
compile_error!("Features 'quiche' and 'original-h3-server' are mutually exclusive and cannot be enabled at the same time.");

#[cfg(all(feature = "quiche", feature = "upstream-h3"))]
compile_error!("Features 'quiche' and 'upstream-h3' are mutually exclusive and cannot be enabled at the same time.");

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use tracing::{Level, info};


pub mod build_info;
pub mod cache;
pub mod config;
pub mod dnl;
pub mod dns;
pub mod hosts;
pub mod iface_watcher;
pub mod ipset;
pub mod listener_manager;
pub mod opt;
#[cfg(feature = "quiche")]
pub mod quiche_client;
#[cfg(feature = "quiche")]
pub mod quiche_server;
pub mod request_id;
pub mod server;
pub mod tag;
pub mod upstream;
pub mod utils;
pub mod web_rule;
pub mod http_client;

fn resolve_rule_path(file: &str, workspace: &Option<String>, fallback_dir: &std::path::Path) -> String {
    if file.starts_with("inline:base64:") {
        return file.to_string();
    }
    let p = std::path::Path::new(file);
    if p.is_relative() {
        let full_path = if let Some(ws) = workspace {
            std::path::Path::new(ws).join(p)
        } else {
            fallback_dir.join(p)
        };
        full_path.into_os_string().into_string().unwrap_or_else(|os| os.to_string_lossy().into_owned())
    } else {
        file.to_string()
    }
}

#[cfg(feature = "jemalloc")]
#[repr(transparent)]
pub struct ConstCharPtr(pub *const std::ffi::c_char);
#[cfg(feature = "jemalloc")]
unsafe impl Sync for ConstCharPtr {}

#[cfg(feature = "jemalloc")]
#[unsafe(no_mangle)]
pub static _rjem_malloc_conf: ConstCharPtr =
    ConstCharPtr(c"thp:never,background_thread:true,dirty_decay_ms:0,muzzy_decay_ms:0,narenas:1".as_ptr());

#[cfg(feature = "jemalloc")]
#[unsafe(no_mangle)]
pub static malloc_conf: ConstCharPtr =
    ConstCharPtr(c"thp:never,background_thread:true,dirty_decay_ms:0,muzzy_decay_ms:0,narenas:1".as_ptr());

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_THP_DISABLE, 1, 0, 0, 0);
    }
    #[cfg(feature = "jemalloc")]
    {
        let _ = tikv_jemalloc_ctl::epoch::advance();
        let _ = tikv_jemalloc_ctl::background_thread::write(true);
        // SAFETY: update arena decay intervals for all arenas
        unsafe {
            let _ = tikv_jemalloc_ctl::raw::update(b"arenas.dirty_decay_ms\0", 0isize);
            let _ = tikv_jemalloc_ctl::raw::update(b"arenas.muzzy_decay_ms\0", 0isize);
        }
    }

    #[cfg(feature = "rustls-stack")]
    let _ = rustls::crypto::ring::default_provider().install_default();

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    boring::init();

    let options = opt::Opt::init();

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(workers) = options.worker_threads {
        builder.worker_threads(workers.max(1));
    }
    // Default thread stack size 512KB for low memory / embedded devices (default in glibc is 8MB!)
    let stack_size = options.thread_stack_size.unwrap_or(512 * 1024);
    builder.thread_stack_size(stack_size);

    let runtime = builder.build()?;
    runtime.block_on(async_main(options))
}

async fn async_main(options: opt::Opt) -> anyhow::Result<()> {

    // Initialize standard logging (with non-blocking console & rolling file writers)
    let (_console_guard, _file_guard) = init_logging(&options);

    info!("Starting polardns {}...", build_info::VERSION);

    // Set verbose trace level if requested
    if options.verbose {
        info!("Verbose logging enabled");
    }

    // Warn about parsed but currently unimplemented flags
    if let Some(hosts_file) = &options.hosts {
        hosts::init(hosts_file);
    }
    if !options.dns_rr_ip.is_empty() {
        hosts::init_from_args(&options.dns_rr_ip);
    }
    #[cfg(feature = "ipset")]
    if options.no_ipset_blacklist {
        ipset::disable_blacklist();
    }
    #[cfg(not(feature = "ipset"))]
    if options.no_ipset_blacklist {
        tracing::warn!("--no-ipset-blacklist was specified, but ipset feature is disabled");
    }

    // Deprecation warnings
    if !options.chnlist_file.is_empty() {
        tracing::warn!("--chnlist-file is deprecated. Please use --upstream-rule instead.");
    }

    if !options.cache_ignore.is_empty() {
        tracing::warn!("--cache-ignore is parsed but currently ignored in this version.");
    }
    if options.repeat_times != 1 {
        tracing::warn!("--repeat-times is parsed but currently ignored in this version.");
    }
    if options.noip_as_chnip {
        tracing::warn!("--noip-as-chnip is parsed but currently ignored in this version.");
    }
    if options.fair_mode {
        tracing::warn!("--fair-mode is parsed but currently ignored in this version.");
    }
    if !options.gfwlist_file.is_empty() {
        tracing::warn!("--gfwlist-file is deprecated. Please use --upstream-rule instead.");
    }
    if !options.group_dnl.is_empty() {
        tracing::warn!("--group-dnl is deprecated. Please use --upstream-rule instead.");
    }
    if options.chnlist_first {
        tracing::warn!(
            "--chnlist-first is deprecated. It will be ignored if --upstream-rule is provided."
        );
    }
    if options.timeout_sec.is_some() {
        tracing::warn!("--timeout-sec is deprecated. Please use --timeout-ms instead.");
    }
    if options.verdict_cache_size.is_some() || options.verdict_cache_db.is_some() {
        tracing::warn!(
            "--verdict-cache and --verdict-cache-db are deprecated and ignored because verdict-based routing has been discarded."
        );
    }

    // Custom groups registration
    for gname in &options.group {
        if gname == "chn"
            || gname == "polar"
            || gname == "gfw"
            || gname == "direct"
            || gname == "proxy"
            || gname == "adblock"
            || gname == "block"
            || gname == "none"
            || gname == "hosts"
        {
            eprintln!("Error: Custom group name '{}' is reserved", gname);
            std::process::exit(1);
        }
        if tag::Tag::register(gname).is_err() {
            eprintln!(
                "Error: Too many custom groups (max 250). Cannot register '{}'",
                gname
            );
            std::process::exit(1);
        }
    }

    // Validate default-tag
    if let Some(t) = tag::Tag::from_name(&options.default_tag) {
        if t == tag::Tag::Adblock {
            eprintln!("Error: 'adblock' cannot be used as --default-tag");
            std::process::exit(1);
        }
        if t == tag::Tag::Hosts {
            eprintln!("Error: 'hosts' cannot be used as --default-tag");
            std::process::exit(1);
        }
        if let tag::Tag::Custom(_) = t {
            let has_upstream = options.group_upstream.iter().any(|u| {
                if let Some((tag_name, _)) = u.split_once(':') {
                    tag_name.trim() == options.default_tag
                } else {
                    false
                }
            });
            if !has_upstream {
                eprintln!(
                    "Error: Default tag '{}' is a custom group and must have upstream servers defined via --group-upstream",
                    options.default_tag
                );
                std::process::exit(1);
            }
        }
    } else {
        eprintln!(
            "Error: --default-tag '{}' must be 'direct', 'proxy' (or 'polar', legacy 'chn', 'gfw'), or a custom group name defined in --group",
            options.default_tag
        );
        std::process::exit(1);
    }

    let mut rules: Vec<(String, tag::Tag)> = Vec::new();
    let mut adblock_rules: Vec<String> = Vec::new();

    // 1. Gather adblock lists
    for raw_f in &options.adblock_file {
        for f in raw_f.split(',') {
            let f_trim = f.trim();
            if !f_trim.is_empty() {
                adblock_rules.push(f_trim.to_string());
            }
        }
    }

    // 2. Load upstream rules
    if !options.upstream_rule.is_empty() {
        let mut used_custom_tags = rustc_hash::FxHashSet::default();
        let default_control_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));

        for rule_entry in &options.upstream_rule {
            if let Some((file, tag_name)) = parse_rule_line(rule_entry) {
                // Direct rule mapping (e.g. from CLI or resolved by config.rs)
                let resolved_file = resolve_rule_path(&file, &options.workspace, &default_control_dir);
                let t = tag::Tag::from_name(&tag_name);
                match t {
                    Some(tag::Tag::Direct)
                    | Some(tag::Tag::Proxy)
                    | Some(tag::Tag::Adblock) => {
                        rules.push((resolved_file, t.unwrap()));
                    }
                    Some(tag::Tag::Custom(_)) => {
                        rules.push((resolved_file, t.unwrap()));
                        used_custom_tags.insert(tag_name);
                    }
                    _ => {
                        eprintln!(
                            "Error: Tag '{}' in upstream-rule must be defined in --group",
                            tag_name
                        );
                        std::process::exit(1);
                    }
                }
            } else {
                // Separate rules file path (compatibility mode)
                let resolved_rule_entry = resolve_rule_path(rule_entry, &options.workspace, &default_control_dir);
                match std::fs::read_to_string(&resolved_rule_entry) {
                    Ok(content) => {
                        let control_dir = std::path::Path::new(&resolved_rule_entry)
                            .parent()
                            .unwrap_or(std::path::Path::new("."));

                        for line in content.lines() {
                            if let Some((file, tag_name)) = parse_rule_line(line) {
                                let resolved_file = resolve_rule_path(&file, &options.workspace, control_dir);
                                let t = tag::Tag::from_name(&tag_name);
                                match t {
                                    Some(tag::Tag::Direct)
                                    | Some(tag::Tag::Proxy)
                                    | Some(tag::Tag::Adblock) => {
                                        rules.push((resolved_file, t.unwrap()));
                                    }
                                    Some(tag::Tag::Custom(_)) => {
                                        rules.push((resolved_file, t.unwrap()));
                                        used_custom_tags.insert(tag_name);
                                    }
                                    _ => {
                                        eprintln!(
                                            "Error: Tag '{}' in upstream-rule must be defined in --group",
                                            tag_name
                                        );
                                        std::process::exit(1);
                                    }
                                }
                            } else if !line.trim().is_empty() && !line.trim().starts_with('#') {
                                tracing::warn!("Invalid line in upstream-rule file '{}': {}", resolved_rule_entry, line);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Error: Failed to read upstream-rule file or rule pattern '{}': {}",
                            resolved_rule_entry, e
                        );
                        std::process::exit(1);
                    }
                }
            }
        }

        // Validate that used custom tags have upstreams
        for tag_name in used_custom_tags {
            let has_upstream = options
                .group_upstream
                .iter()
                .any(|u| u.starts_with(&format!("{}:", tag_name)));
            if !has_upstream {
                eprintln!(
                    "Error: Tag '{}' used in upstream-rule must have upstream servers defined via --group-upstream",
                    tag_name
                );
                std::process::exit(1);
            }
        }
    } else {
        // Legacy priority
        for dnl_arg in &options.group_dnl {
            if let Some((tag_name, file_raw)) = dnl_arg.split_once(':')
                && let Some(t) = tag::Tag::from_name(tag_name)
            {
                for f in file_raw.split(',') {
                    let f_trim = f.trim();
                    if !f_trim.is_empty() {
                        rules.push((f_trim.to_string(), t));
                    }
                }
            }
        }

        let mut gfw_rules = Vec::new();
        for file in &options.gfwlist_file {
            for f in file.split(',') {
                let f_trim = f.trim();
                if !f_trim.is_empty() {
                    gfw_rules.push((f_trim.to_string(), tag::Tag::Proxy));
                }
            }
        }

        let mut chn_rules = Vec::new();
        for file in &options.chnlist_file {
            for f in file.split(',') {
                let f_trim = f.trim();
                if !f_trim.is_empty() {
                    chn_rules.push((f_trim.to_string(), tag::Tag::Direct));
                }
            }
        }

        if options.chnlist_first {
            rules.extend(chn_rules);
            rules.extend(gfw_rules);
        } else {
            rules.extend(gfw_rules);
            rules.extend(chn_rules);
        }
    }

    // Initialize DNS match logging if requested
    if let Some(ref log_path) = options.log_dns_match
        && let Err(e) = dnl::init_match_logging(log_path)
    {
        eprintln!(
            "Error: Failed to initialize match logging at '{}': {}",
            log_path, e
        );
        std::process::exit(1);
    }

    // Initialize DNS result logging if requested
    if let Some(ref log_path) = options.log_dns_result
        && let Err(e) = server::init_result_logging(log_path)
    {
        eprintln!(
            "Error: Failed to initialize result logging at '{}': {}",
            log_path, e
        );
        std::process::exit(1);
    }

    // Initialize web rules (fetches missing/stale rule files before DNL initialization)
    web_rule::init_and_spawn(options.web_rules.clone(), &options.user_agent).await;

    // Initialize domain list cache
    dnl::init_adblock(adblock_rules);
    dnl::init(rules);

    // Spawn background task for DNL zero-downtime hot reloading
    dnl::start_hot_reload_watcher();

    server::run_server(std::sync::Arc::new(options)).await?;

    Ok(())
}

fn parse_rule_line(line: &str) -> Option<(String, String)> {
    let line_no_comment = match line.split_once('#') {
        Some((before, _)) => before,
        None => line,
    };
    let line = line_no_comment.trim();
    if line.is_empty() {
        return None;
    }
    if let Some((file, tag_name)) = line.rsplit_once('@') {
        Some((file.trim().to_string(), tag_name.trim().to_string()))
    } else if let Some((file, tag_name)) = line.rsplit_once(',') {
        Some((file.trim().to_string(), tag_name.trim().to_string()))
    } else {
        None
    }
}

fn init_logging(options: &opt::Opt) -> (tracing_appender::non_blocking::WorkerGuard, Option<tracing_appender::non_blocking::WorkerGuard>) {
    let level = if let Some(ref l) = options.log_level {
        match l.to_uppercase().as_str() {
            "TRACE" => Level::TRACE,
            "DEBUG" => Level::DEBUG,
            "INFO" => Level::INFO,
            "WARN" => Level::WARN,
            "ERROR" => Level::ERROR,
            _ => if options.verbose { Level::DEBUG } else { Level::INFO },
        }
    } else if options.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    use tracing_subscriber::prelude::*;
    use tracing_subscriber::EnvFilter;

    let (console_writer, console_guard) = tracing_appender::non_blocking(std::io::stdout());
    let console_layer = tracing_subscriber::fmt::layer()
        .with_writer(console_writer)
        .with_ansi(true);

    let mut file_layer = None;
    let mut file_guard = None;

    if let Some(ref log_file) = options.log_file {
        if let Some(parent) = std::path::Path::new(log_file).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new().create(true).append(true).open(log_file) {
            Ok(f) => {
                let (non_blocking_file, guard) = tracing_appender::non_blocking(f);
                file_guard = Some(guard);
                file_layer = Some(tracing_subscriber::fmt::layer().with_writer(non_blocking_file).with_ansi(false));
            }
            Err(e) => {
                eprintln!("Error: Failed to open log file '{}': {}", log_file, e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref log_dir) = options.log_dir {
        #[cfg(feature = "file-log")]
        {
            let _ = std::fs::create_dir_all(log_dir);
            let max_bytes = if let Some(ref size_str) = options.log_rotation_size {
                let size_str = size_str.trim().to_uppercase();
                if size_str.ends_with('M') {
                    size_str[..size_str.len()-1].parse::<u64>().unwrap_or(10) * 1024 * 1024
                } else if size_str.ends_with('G') {
                    size_str[..size_str.len()-1].parse::<u64>().unwrap_or(1) * 1024 * 1024 * 1024
                } else if size_str.ends_with('K') {
                    size_str[..size_str.len()-1].parse::<u64>().unwrap_or(100) * 1024
                } else {
                    size_str.parse::<u64>().unwrap_or(10 * 1024 * 1024)
                }
            } else {
                10 * 1024 * 1024
            };

            let mut condition = tracing_rolling_file::RollingConditionBase::new();
            condition = match options.log_rotation_period.as_str() {
                "minutely" => condition.minutely(),
                "hourly" => condition.hourly(),
                "daily" => condition.daily(),
                _ => condition.daily(),
            };
            condition = condition.max_size(max_bytes);

            let file_appender = tracing_rolling_file::RollingFileAppender::new(
                log_dir,
                condition,
                options.log_max_files.unwrap_or(10),
            );

            match file_appender {
                Ok(appender) => {
                    let (non_blocking_file, guard) = tracing_appender::non_blocking(appender);
                    file_guard = Some(guard);
                    file_layer = Some(tracing_subscriber::fmt::layer().with_writer(non_blocking_file).with_ansi(false));
                }
                Err(e) => {
                    eprintln!("Error: Failed to initialize rolling file appender in '{}': {}", log_dir, e);
                    std::process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "file-log"))]
        {
            eprintln!("Warning: Rolling log file support was disabled at compile time. Ignoring log_dir '{}'.", log_dir);
        }
    }

    let filter = EnvFilter::from_default_env().add_directive(level.into());
    let registry = tracing_subscriber::registry().with(filter).with(console_layer);

    if let Some(fl) = file_layer {
        tracing::subscriber::set_global_default(registry.with(fl)).expect("setting default subscriber failed");
    } else {
        tracing::subscriber::set_global_default(registry).expect("setting default subscriber failed");
    }

    (console_guard, file_guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_line_delim() {
        // Standard '@' delimiter
        assert_eq!(
            parse_rule_line("domain.list@direct"),
            Some(("domain.list".to_string(), "direct".to_string()))
        );
        assert_eq!(
            parse_rule_line(" domain.list  @   proxy "),
            Some(("domain.list".to_string(), "proxy".to_string()))
        );

        // Comma ',' delimiter
        assert_eq!(
            parse_rule_line("adblock.list,block"),
            Some(("adblock.list".to_string(), "block".to_string()))
        );
        assert_eq!(
            parse_rule_line(" adblock.list  ,   adblock "),
            Some(("adblock.list".to_string(), "adblock".to_string()))
        );

        // Comments and empty lines
        assert_eq!(parse_rule_line(""), None);
        assert_eq!(parse_rule_line("  "), None);
        assert_eq!(parse_rule_line("# comment"), None);
        assert_eq!(parse_rule_line("  # comment with space"), None);

        // Trailing comments
        assert_eq!(
            parse_rule_line("domain.list@direct # inline comment"),
            Some(("domain.list".to_string(), "direct".to_string()))
        );
        assert_eq!(
            parse_rule_line("adblock.list,block#inline"),
            Some(("adblock.list".to_string(), "block".to_string()))
        );

        // Invalid format (no delimiter)
        assert_eq!(parse_rule_line("invalid_line"), None);
    }
}
