use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::sync::RwLock;

use rustc_hash::FxHashMap;

use crate::tag::Tag;

const DNS_NAME_MAXLEN: usize = 253;
const DNS_NAME_LABEL_MAXLEN: usize = 63;
pub const MATCH_LOGGER_FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
pub const HOT_RELOAD_WATCH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

type RuleId = u32;

#[inline]
pub fn hash_domain(domain: &str) -> u64 {
    let mut hasher = FxHasher::default();
    domain.hash(&mut hasher);
    hasher.finish()
}

#[inline]
pub fn hash_domain_ascii_lower(domain: &str) -> u64 {
    if !domain.bytes().any(|b| b.is_ascii_uppercase()) {
        return hash_domain(domain);
    }

    let mut lower_buf = [0u8; 255];
    if domain.len() <= lower_buf.len() {
        let domain_bytes = domain.as_bytes();
        lower_buf[..domain_bytes.len()].copy_from_slice(domain_bytes);
        lower_buf[..domain_bytes.len()].make_ascii_lowercase();
        // SAFETY: input was valid UTF-8 and ASCII lowercasing preserves validity.
        return hash_domain(unsafe {
            std::str::from_utf8_unchecked(&lower_buf[..domain_bytes.len()])
        });
    }

    hash_domain(&domain.to_ascii_lowercase())
}

struct ProviderWildcardRule {
    rule_id: RuleId,
    labels: Box<[Box<[u8]>]>,
}

struct ClassicalGlobRule {
    rule_id: RuleId,
    pattern: Box<[u8]>,
}

struct KeywordRule {
    rule_id: RuleId,
    needle: Box<[u8]>,
}

pub struct DnlCache {
    rules: Vec<Tag>,
    pub patterns: Box<[compact_str::CompactString]>,
    exact: FxHashMap<u64, RuleId>,
    suffix: FxHashMap<u64, RuleId>,
    subdomain: FxHashMap<u64, RuleId>,
    provider_wildcards: Vec<ProviderWildcardRule>,
    wildcard_buckets: FxHashMap<u64, Vec<usize>>,
    wildcard_fallback: Vec<usize>,
    classical_wildcards: Vec<ClassicalGlobRule>,
    keywords: Vec<KeywordRule>,
    #[cfg(feature = "aho-corasick")]
    keyword_automaton: Option<aho_corasick::AhoCorasick>,
    #[cfg(feature = "aho-corasick")]
    keyword_rule_ids: Box<[RuleId]>,
    #[cfg(feature = "regex")]
    regex_set: Option<regex::RegexSet>,
    #[cfg(feature = "regex")]
    regex_rule_ids: Vec<RuleId>,
}

/// Global Domain Name List registry
static DNL_ADBLOCK: RwLock<Option<DnlCache>> = RwLock::new(None);
static DNL_ROUTING: RwLock<Option<DnlCache>> = RwLock::new(None);
static ADBLOCK_CONFIG: RwLock<Vec<String>> = RwLock::new(Vec::new());
static ROUTING_CONFIG: RwLock<Vec<(String, Tag)>> = RwLock::new(Vec::new());
static MATCH_LOGGER: RwLock<Option<tokio::sync::mpsc::Sender<(compact_str::CompactString, Tag, compact_str::CompactString)>>> = RwLock::new(None);
static REOPEN_TRIGGER: RwLock<Option<tokio::sync::mpsc::Sender<()>>> = RwLock::new(None);

pub fn is_match_logging_enabled() -> bool {
    MATCH_LOGGER.read().map(|lock| lock.is_some()).unwrap_or(false)
}

fn normalize_domain<'a>(mut name: &'a str) -> Option<std::borrow::Cow<'a, str>> {
    name = name.trim();
    if name.is_empty() || name.starts_with('#') {
        return None;
    }

    if name.ends_with('.') && name.len() > 1 {
        name = &name[..name.len() - 1];
    }

    if name.starts_with('.') || name.ends_with('.') {
        return None;
    }

    if name.len() > DNS_NAME_MAXLEN {
        return None;
    }

    for label in name.split('.') {
        if label.is_empty() || label.len() > DNS_NAME_LABEL_MAXLEN {
            return None;
        }
    }

    if !name.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(std::borrow::Cow::Borrowed(name))
    } else {
        Some(std::borrow::Cow::Owned(name.to_ascii_lowercase()))
    }
}

fn normalize_pattern<'a>(mut pattern: &'a str) -> Option<std::borrow::Cow<'a, str>> {
    pattern = pattern.trim();
    if pattern.is_empty() || pattern.starts_with('#') {
        return None;
    }

    if pattern.ends_with('.') && pattern.len() > 1 {
        pattern = &pattern[..pattern.len() - 1];
    }

    if pattern.starts_with('.') || pattern.ends_with('.') || pattern.len() > DNS_NAME_MAXLEN {
        return None;
    }

    for label in pattern.split('.') {
        if label.is_empty() || label.len() > DNS_NAME_LABEL_MAXLEN {
            return None;
        }
    }

    if !pattern.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(std::borrow::Cow::Borrowed(pattern))
    } else {
        Some(std::borrow::Cow::Owned(pattern.to_ascii_lowercase()))
    }
}

fn strip_surrounding_quotes(value: &str) -> &str {
    let value = value.trim();
    if value.len() >= 2
        && ((value.starts_with('\'') && value.ends_with('\''))
            || (value.starts_with('"') && value.ends_with('"')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn strip_comment(line: &str) -> &str {
    if contains_ignore_ascii_case(line.as_bytes(), b"DOMAIN-REGEX,") {
        line
    } else {
        line.split_once('#').map_or(line, |(before, _)| before)
    }
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn first_rule_field(value: &str) -> &str {
    value.split(',').next().unwrap_or(value).trim()
}

#[cfg(feature = "regex")]
fn is_target_token(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(feature = "regex")]
fn strip_trailing_target(value: &str) -> &str {
    if let Some(last_comma) = value.rfind(',') {
        let target = value[last_comma + 1..].trim();
        if is_target_token(target) {
            return value[..last_comma].trim();
        }
    }
    value.trim()
}

#[inline]
fn consider_rule(best: &mut Option<RuleId>, rule_id: RuleId) {
    if best.is_none_or(|current| rule_id < current) {
        *best = Some(rule_id);
    }
}

#[inline]
fn contains_wildcard(value: &str) -> bool {
    value.bytes().any(|b| b == b'*' || b == b'?')
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
    if pattern == b"*" {
        return true;
    }

    let (mut p_idx, mut v_idx) = (0usize, 0usize);
    let mut star_idx = None;
    let mut star_value_idx = 0usize;

    while v_idx < value.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == value[v_idx] || pattern[p_idx] == b'?') {
            p_idx += 1;
            v_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == b'*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            star_value_idx = v_idx;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            star_value_idx += 1;
            v_idx = star_value_idx;
        } else {
            return false;
        }
    }

    pattern[p_idx..].iter().all(|&b| b == b'*')
}

fn provider_wildcard_matches(rule: &ProviderWildcardRule, domain: &str) -> bool {
    let mut labels = domain.split('.');
    for pattern in rule.labels.iter() {
        let Some(label) = labels.next() else {
            return false;
        };
        if !glob_match(pattern, label.as_bytes()) {
            return false;
        }
    }
    labels.next().is_none()
}

struct DnlBuilder {
    rules: Vec<Tag>,
    patterns: Vec<compact_str::CompactString>,
    exact: FxHashMap<u64, RuleId>,
    suffix: FxHashMap<u64, RuleId>,
    subdomain: FxHashMap<u64, RuleId>,
    provider_wildcards: Vec<ProviderWildcardRule>,
    wildcard_buckets: FxHashMap<u64, Vec<usize>>,
    wildcard_fallback: Vec<usize>,
    classical_wildcards: Vec<ClassicalGlobRule>,
    keywords: Vec<KeywordRule>,
    #[cfg(feature = "regex")]
    regex_strings: Vec<String>,
    #[cfg(feature = "regex")]
    regex_rule_ids: Vec<RuleId>,
}

impl DnlBuilder {
    fn new() -> Self {
        Self {
            rules: Vec::new(),
            patterns: Vec::new(),
            exact: FxHashMap::default(),
            suffix: FxHashMap::default(),
            subdomain: FxHashMap::default(),
            provider_wildcards: Vec::new(),
            wildcard_buckets: FxHashMap::default(),
            wildcard_fallback: Vec::new(),
            classical_wildcards: Vec::new(),
            keywords: Vec::new(),
            #[cfg(feature = "regex")]
            regex_strings: Vec::new(),
            #[cfg(feature = "regex")]
            regex_rule_ids: Vec::new(),
        }
    }

    #[inline]
    fn push_rule_lazy(&mut self, tag: Tag, pattern_gen: impl FnOnce() -> String) -> RuleId {
        let id = self.rules.len() as RuleId;
        self.rules.push(tag);
        if cfg!(test) || is_match_logging_enabled() {
            self.patterns.push(compact_str::CompactString::from(pattern_gen()));
        }
        id
    }

    #[inline]
    fn push_rule(&mut self, tag: Tag, pattern: String) -> RuleId {
        self.push_rule_lazy(tag, || pattern)
    }

    fn add_exact(&mut self, domain: &str, tag: Tag) {
        if let Some(domain) = normalize_domain(domain) {
            let hash = hash_domain(&domain);
            if !self.exact.contains_key(&hash) {
                let rule_id = self.push_rule_lazy(tag, || domain.to_string());
                self.exact.insert(hash, rule_id);
            }
        }
    }

    fn add_suffix(&mut self, domain: &str, tag: Tag) {
        if let Some(domain) = normalize_domain(domain) {
            let hash = hash_domain(&domain);
            if !self.suffix.contains_key(&hash) {
                let rule_id = self.push_rule_lazy(tag, || format!("+.{}", domain));
                self.suffix.insert(hash, rule_id);
            }
        }
    }

    fn add_subdomain_only(&mut self, domain: &str, tag: Tag) {
        if let Some(domain) = normalize_domain(domain) {
            let hash = hash_domain(&domain);
            if !self.subdomain.contains_key(&hash) {
                let rule_id = self.push_rule_lazy(tag, || format!(".{}", domain));
                self.subdomain.insert(hash, rule_id);
            }
        }
    }

    fn add_provider_wildcard(&mut self, pattern: &str, tag: Tag) {
        let Some(pattern) = normalize_pattern(pattern) else {
            return;
        };
        if !contains_wildcard(&pattern) {
            self.add_exact(&pattern, tag);
            return;
        }

        let rule_id = self.push_rule_lazy(tag, || pattern.to_string());
        let labels: Vec<Box<[u8]>> = pattern
            .split('.')
            .map(|label| label.as_bytes().to_vec().into_boxed_slice())
            .collect();
        let bucket_suffix = fixed_wildcard_suffix(&pattern);
        let wildcard_idx = self.provider_wildcards.len();
        self.provider_wildcards.push(ProviderWildcardRule {
            rule_id,
            labels: labels.into_boxed_slice(),
        });

        if let Some(suffix) = bucket_suffix {
            self.wildcard_buckets
                .entry(hash_domain(&suffix))
                .or_default()
                .push(wildcard_idx);
        } else {
            self.wildcard_fallback.push(wildcard_idx);
        }
    }

    fn add_classical_wildcard(&mut self, pattern: &str, tag: Tag) {
        let pattern_lower = first_rule_field(pattern).to_ascii_lowercase();
        if pattern_lower.is_empty() {
            return;
        }
        let rule_id = self.push_rule(tag, pattern.to_string());
        self.classical_wildcards.push(ClassicalGlobRule {
            rule_id,
            pattern: pattern_lower.into_bytes().into_boxed_slice(),
        });
    }

    fn add_keyword(&mut self, keyword: &str, tag: Tag) {
        let keyword_lower = first_rule_field(keyword).to_ascii_lowercase();
        if keyword_lower.is_empty() {
            return;
        }
        let rule_id = self.push_rule(tag, keyword.to_string());
        self.keywords.push(KeywordRule {
            rule_id,
            needle: keyword_lower.into_bytes().into_boxed_slice(),
        });
    }

    fn add_regex(&mut self, regex: &str, tag: Tag) {
        #[cfg(feature = "regex")]
        {
            let regex_clean = strip_trailing_target(regex);
            if regex_clean.is_empty() {
                return;
            }
            let rule_id = self.push_rule(tag, regex.to_string());
            self.regex_strings.push(format!("(?i){}", regex_clean));
            self.regex_rule_ids.push(rule_id);
        }
        #[cfg(not(feature = "regex"))]
        {
            let _ = (regex, tag);
            tracing::warn!("Regex rules are not supported in this build (feature 'regex' disabled)");
        }
    }

    fn finish(mut self) -> Result<(DnlCache, usize), String> {
        self.rules.shrink_to_fit();
        self.patterns.shrink_to_fit();
        self.exact.shrink_to_fit();
        self.suffix.shrink_to_fit();
        self.subdomain.shrink_to_fit();
        self.provider_wildcards.shrink_to_fit();
        self.wildcard_buckets.shrink_to_fit();
        for bucket in self.wildcard_buckets.values_mut() {
            bucket.shrink_to_fit();
        }
        self.wildcard_fallback.shrink_to_fit();
        self.classical_wildcards.shrink_to_fit();
        self.keywords.shrink_to_fit();

        #[cfg(feature = "aho-corasick")]
        let (keyword_automaton, keyword_rule_ids) = if !self.keywords.is_empty() {
            let needles: Vec<&[u8]> = self.keywords.iter().map(|k| &k.needle[..]).collect();
            let rule_ids: Vec<RuleId> = self.keywords.iter().map(|k| k.rule_id).collect();
            match aho_corasick::AhoCorasick::new(&needles) {
                Ok(ac) => (Some(ac), rule_ids.into_boxed_slice()),
                Err(e) => {
                    tracing::warn!("Failed to compile Aho-Corasick automaton: {}", e);
                    (None, rule_ids.into_boxed_slice())
                }
            }
        } else {
            (None, Box::new([]) as Box<[RuleId]>)
        };

        #[cfg(feature = "regex")]
        let regex_set = if !self.regex_strings.is_empty() {
            match regex::RegexSet::new(&self.regex_strings) {
                Ok(set) => Some(set),
                Err(e) => {
                    tracing::warn!("Failed to compile RegexSet: {}", e);
                    return Err(format!("Regex compile error: {}", e));
                }
            }
        } else {
            None
        };

        let count = self.rules.len();
        Ok((
            DnlCache {
                rules: self.rules,
                patterns: self.patterns.into_boxed_slice(),
                exact: self.exact,
                suffix: self.suffix,
                subdomain: self.subdomain,
                provider_wildcards: self.provider_wildcards,
                wildcard_buckets: self.wildcard_buckets,
                wildcard_fallback: self.wildcard_fallback,
                classical_wildcards: self.classical_wildcards,
                keywords: self.keywords,
                #[cfg(feature = "aho-corasick")]
                keyword_automaton,
                #[cfg(feature = "aho-corasick")]
                keyword_rule_ids,
                #[cfg(feature = "regex")]
                regex_set,
                #[cfg(feature = "regex")]
                regex_rule_ids: self.regex_rule_ids,
            },
            count,
        ))
    }
}

fn fixed_wildcard_suffix(pattern: &str) -> Option<String> {
    let labels: Vec<&str> = pattern.split('.').collect();
    let last_wildcard = labels
        .iter()
        .rposition(|label| label.bytes().any(|b| b == b'*' || b == b'?'))?;
    if last_wildcard + 1 >= labels.len() {
        return None;
    }
    Some(labels[last_wildcard + 1..].join("."))
}

/// Helper method to load domains from a file (or "-" for stdin) and append them to a temporary vector.
fn load_list(filename: &str, tag: Tag, builder: &mut DnlBuilder) -> io::Result<()> {
    let mut reader: Box<dyn BufRead> = if let Some(b64_str) = filename.strip_prefix("inline:base64:") {
        use base64::prelude::*;
        let decoded = BASE64_STANDARD.decode(b64_str.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Box::new(BufReader::new(std::io::Cursor::new(decoded)))
    } else if filename == "-" {
        Box::new(BufReader::new(io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(filename)?))
    };

    let is_yaml = filename.ends_with(".yaml") || filename.ends_with(".yml");
    let mut in_rule_array = false;
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line_no_comment = strip_comment(&line);
        let line_trimmed = line_no_comment.trim();
        if line_trimmed.is_empty() || line_trimmed.starts_with("//") {
            continue;
        }

        if is_yaml {
            if line_trimmed == "payload:" || line_trimmed == "rules:" {
                in_rule_array = true;
                continue;
            }

            if in_rule_array && line_trimmed.starts_with('-') {
                let item = strip_surrounding_quotes(line_trimmed[1..].trim());
                parse_rule_item(item, tag, builder);
            }
        } else {
            parse_rule_item(line_trimmed, tag, builder);
        }
    }

    Ok(())
}

fn parse_single_rule_token(item: &str, tag: Tag, builder: &mut DnlBuilder) {
    if item.is_empty() {
        return;
    }

    if let Some(domain) = item.strip_prefix("+.") {
        builder.add_suffix(domain, tag);
    } else if let Some(domain) = item.strip_prefix('.') {
        builder.add_subdomain_only(domain, tag);
    } else if contains_wildcard(item) {
        builder.add_provider_wildcard(item, tag);
    } else {
        builder.add_exact(item, tag);
    }
}

fn parse_rule_item(raw: &str, tag: Tag, builder: &mut DnlBuilder) {
    let raw = strip_surrounding_quotes(raw.trim());
    if raw.is_empty() || raw.starts_with('#') || raw.starts_with("//") {
        return;
    }

    if let Some((rule_type, rest)) = raw.split_once(',') {
        match rule_type.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" => {
                builder.add_exact(first_rule_field(rest), tag);
                return;
            }
            "DOMAIN-SUFFIX" => {
                builder.add_suffix(first_rule_field(rest), tag);
                return;
            }
            "DOMAIN-KEYWORD" => {
                builder.add_keyword(rest, tag);
                return;
            }
            "DOMAIN-WILDCARD" => {
                builder.add_classical_wildcard(rest, tag);
                return;
            }
            "DOMAIN-REGEX" => {
                builder.add_regex(rest, tag);
                return;
            }
            // Non-domain Clash/Surge/Mihomo rule types: skip so they do not pollute domain sets
            "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "GEOIP"
            | "IP-ASN"
            | "PROCESS-NAME"
            | "PROCESS-PATH"
            | "DST-PORT"
            | "SRC-PORT"
            | "IN-PORT"
            | "IN-TYPE"
            | "IN-NAME"
            | "NETWORK"
            | "RULE-SET"
            | "AND"
            | "OR"
            | "NOT"
            | "SUB-RULE"
            | "MATCH"
            | "PAYLOAD" => {
                return;
            }
            _ => {}
        }
    }

    let field = first_rule_field(raw);
    let mut tokens = field.split_whitespace();
    if let Some(first) = tokens.next() {
        // Skip standalone IP CIDR blocks (e.g. 10.0.0.0/8 or 2001:db8::/32)
        if first.contains('/') {
            return;
        }
        if first.parse::<std::net::IpAddr>().is_ok() {
            for domain in tokens {
                parse_single_rule_token(domain, tag, builder);
            }
            return;
        }
        parse_single_rule_token(first, tag, builder);
    }
}

pub fn init_adblock(adblock_rules: Vec<String>) {
    let mut adblock_rules_mapped = Vec::new();
    for path in adblock_rules {
        adblock_rules_mapped.push((path, Tag::Adblock));
    }
    match build_map(&adblock_rules_mapped) {
        Ok((cache, count)) => {
            *DNL_ADBLOCK.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
            let paths: Vec<String> = adblock_rules_mapped.iter().map(|(p, _)| p.clone()).collect();
            *ADBLOCK_CONFIG.write().unwrap_or_else(|e| e.into_inner()) = paths;
            #[cfg(feature = "jemalloc")]
            crate::utils::purge_jemalloc();
            tracing::info!(
                "DNL Adblock initialization complete. Total unique domains added: {}",
                count
            );
        }
        Err(e) => {
            eprintln!("Error: DNL Adblock initialization failed: {}", e);
            std::process::exit(1);
        }
    }
}

pub fn init(routing_rules: Vec<(String, Tag)>) {
    match build_map(&routing_rules) {
        Ok((cache, count)) => {
            *DNL_ROUTING.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
            *ROUTING_CONFIG.write().unwrap_or_else(|e| e.into_inner()) = routing_rules;
            #[cfg(feature = "jemalloc")]
            crate::utils::purge_jemalloc();
            tracing::info!(
                "DNL Routing initialization complete. Total unique domains added: {}",
                count
            );
        }
        Err(e) => {
            eprintln!("Error: DNL Routing initialization failed: {}", e);
            std::process::exit(1);
        }
    }
}

pub fn init_match_logging(path: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::{BufWriter, Write};
    use tokio::sync::mpsc;

    let file = OpenOptions::new().create(true).append(true).open(path)?;

    let (tx, mut rx) = mpsc::channel::<(compact_str::CompactString, Tag, compact_str::CompactString)>(4096);
    *MATCH_LOGGER.write().unwrap_or_else(|e| e.into_inner()) = Some(tx);

    let (reopen_tx, mut reopen_rx) = mpsc::channel::<()>(1);
    *REOPEN_TRIGGER.write().unwrap_or_else(|e| e.into_inner()) = Some(reopen_tx);

    let path_clone = path.to_string();
    tokio::spawn(async move {
        let mut writer = BufWriter::new(file);
        let mut interval = tokio::time::interval(MATCH_LOGGER_FLUSH_INTERVAL);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Some((domain, tag, rule)) => {
                            let _ = writeln!(writer, "{},{},{}", domain, tag.name(), rule);
                        }
                        None => break,
                    }
                }
                _ = reopen_rx.recv() => {
                    let _ = writer.flush();
                    match OpenOptions::new().create(true).append(true).open(&path_clone) {
                        Ok(new_file) => {
                            writer = BufWriter::new(new_file);
                            tracing::info!("Reopened DNS match log file at '{}'", path_clone);
                        }
                        Err(e) => {
                            tracing::error!("Failed to reopen DNS match log file at '{}': {}", path_clone, e);
                        }
                    }
                }
                _ = interval.tick() => {
                    let _ = writer.flush();
                }
            }
        }
    });

    Ok(())
}

pub fn reopen_match_log() {
    if let Ok(lock) = REOPEN_TRIGGER.read()
        && let Some(sender) = &*lock
    {
        let _ = sender.try_send(());
    }
}

fn build_map(rules: &[(String, Tag)]) -> Result<(DnlCache, usize), String> {
    let mut builder = DnlBuilder::new();

    for (file, tag) in rules {
        if let Err(e) = load_list(file, *tag, &mut builder) {
            tracing::warn!("failed to open '{}': {}", file, e);
            return Err(format!("failed to open '{}': {}", file, e));
        }
    }

    builder.finish()
}

pub fn start_hot_reload_watcher() {
    #[cfg(feature = "hot-reload")]
    {
        use notify::Watcher;
        tokio::spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<notify::Result<notify::Event>>(100);
            let mut watcher = match notify::recommended_watcher(move |res| {
                let _ = tx.try_send(res);
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Failed to create notify watcher: {}", e);
                    return;
                }
            };

            let mut watched_paths = rustc_hash::FxHashSet::default();
            let watch_files = |w: &mut notify::RecommendedWatcher, wp: &mut rustc_hash::FxHashSet<std::path::PathBuf>| {
                if let Ok(adblock_lock) = ADBLOCK_CONFIG.read() {
                    for file in adblock_lock.iter() {
                        if file.starts_with("inline:base64:") || file == "-" {
                            continue;
                        }
                        let path = std::path::Path::new(file);
                        if path.exists() {
                            let _ = w.unwatch(path);
                            if w.watch(path, notify::RecursiveMode::NonRecursive).is_ok() {
                                wp.insert(path.to_path_buf());
                            }
                        }
                    }
                }
                if let Ok(routing_lock) = ROUTING_CONFIG.read() {
                    for (file, _) in routing_lock.iter() {
                        if file.starts_with("inline:base64:") || file == "-" {
                            continue;
                        }
                        let path = std::path::Path::new(file);
                        if path.exists() {
                            let _ = w.unwatch(path);
                            if w.watch(path, notify::RecursiveMode::NonRecursive).is_ok() {
                                wp.insert(path.to_path_buf());
                            }
                        }
                    }
                }
            };

            watch_files(&mut watcher, &mut watched_paths);

            let mut _watcher_guard = watcher;
            let mut ticker = tokio::time::interval(HOT_RELOAD_WATCH_INTERVAL);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        watch_files(&mut _watcher_guard, &mut watched_paths);
                    }
                    res = rx.recv() => {
                        match res {
                            Some(Ok(event)) => {
                                if event.kind.is_modify() || event.kind.is_create() {
                                    let mut reload_adblock = false;
                                    let mut reload_routing = false;
                                    for path in event.paths {
                                        let canonical_path = path.canonicalize().ok();
                                        if let Ok(adblock_lock) = ADBLOCK_CONFIG.read()
                                            && adblock_lock.iter().any(|f| {
                                                if let Ok(p) = std::path::Path::new(f).canonicalize()
                                                    && let Some(cp) = &canonical_path {
                                                        return p == *cp;
                                                    }
                                                f == &path.to_string_lossy().to_string()
                                            }) {
                                                reload_adblock = true;
                                            }
                                        if let Ok(routing_lock) = ROUTING_CONFIG.read()
                                            && routing_lock.iter().any(|(f, _)| {
                                                if let Ok(p) = std::path::Path::new(f).canonicalize()
                                                    && let Some(cp) = &canonical_path {
                                                        return p == *cp;
                                                    }
                                                f == &path.to_string_lossy().to_string()
                                            }) {
                                                reload_routing = true;
                                            }
                                    }

                                    if reload_adblock {
                                        tracing::info!("Adblock rules changed. Rebuilding adblock matcher...");
                                        let adblock_rules = {
                                            let lock = ADBLOCK_CONFIG.read().unwrap();
                                            lock.clone()
                                        };
                                        let mut adblock_rules_mapped = Vec::new();
                                        for path in adblock_rules {
                                            adblock_rules_mapped.push((path, Tag::Adblock));
                                        }
                                        match build_map(&adblock_rules_mapped) {
                                            Ok((cache, count)) => {
                                                *DNL_ADBLOCK.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
                                                #[cfg(feature = "jemalloc")]
                                                crate::utils::purge_jemalloc();
                                                tracing::info!("DNL Adblock hot-swap complete. Total unique domains: {}", count);
                                            }
                                            Err(e) => {
                                                tracing::error!("DNL Adblock hot-swap failed: {}", e);
                                            }
                                        }
                                    }

                                    if reload_routing {
                                        tracing::info!("Routing rules changed. Rebuilding routing matcher...");
                                        let routing_rules = {
                                            let lock = ROUTING_CONFIG.read().unwrap();
                                            lock.clone()
                                        };
                                        match build_map(&routing_rules) {
                                            Ok((cache, count)) => {
                                                *DNL_ROUTING.write().unwrap_or_else(|e| e.into_inner()) = Some(cache);
                                                #[cfg(feature = "jemalloc")]
                                                crate::utils::purge_jemalloc();
                                                tracing::info!("DNL Routing hot-swap complete. Total unique domains: {}", count);
                                            }
                                            Err(e) => {
                                                tracing::error!("DNL Routing hot-swap failed: {}", e);
                                            }
                                        }
                                    }

                                    if reload_adblock || reload_routing {
                                        watch_files(&mut _watcher_guard, &mut watched_paths);
                                    }
                                }
                            }
                            Some(Err(e)) => {
                                tracing::warn!("Hot-reload watcher encountered error: {}", e);
                            }
                            None => {
                                tracing::warn!("Hot-reload watcher channel closed, stopping watcher.");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
    #[cfg(not(feature = "hot-reload"))]
    {
        tracing::debug!("Domain list hot-reload watcher disabled at compile time");
    }
}

pub fn is_empty() -> bool {
    DNL_ROUTING.read().unwrap_or_else(|e| e.into_inner()).is_none() &&
    DNL_ADBLOCK.read().unwrap_or_else(|e| e.into_inner()).is_none()
}

pub fn check_adblock(name: &str) -> Option<compact_str::CompactString> {
    let need_rule = match MATCH_LOGGER.read() {
        Ok(lock) => lock.is_some(),
        Err(_) => false,
    };
    let (tag, matched_rule) = get_tag_with_rule_inner(name, Tag::Direct, &DNL_ADBLOCK, need_rule);
    if tag == Tag::Adblock {
        if let Ok(lock) = MATCH_LOGGER.read()
            && let Some(sender) = &*lock
        {
            let rule_str = matched_rule.clone().unwrap_or_else(|| compact_str::CompactString::new("adblock"));
            let _ = sender.try_send((compact_str::CompactString::new(name), Tag::Adblock, rule_str));
        }
        Some(matched_rule.unwrap_or_else(|| compact_str::CompactString::new("adblock")))
    } else {
        None
    }
}

pub fn get_tag(name: &str, default_tag: Tag) -> Tag {
    let need_rule = match MATCH_LOGGER.read() {
        Ok(lock) => lock.is_some(),
        Err(_) => false,
    };
    let (matched_tag, matched_rule) = get_tag_with_rule_inner(name, default_tag, &DNL_ROUTING, need_rule);
    if let Ok(lock) = MATCH_LOGGER.read()
        && let Some(sender) = &*lock
    {
        let rule_str = matched_rule.unwrap_or_else(|| compact_str::CompactString::new("none"));
        let _ = sender.try_send((compact_str::CompactString::new(name), matched_tag, rule_str));
    }
    matched_tag
}

pub fn log_match(domain: &str, tag: Tag, rule: &str) {
    if let Ok(lock) = MATCH_LOGGER.read()
        && let Some(sender) = &*lock
    {
        let _ = sender.try_send((compact_str::CompactString::new(domain), tag, compact_str::CompactString::new(rule)));
    }
}

fn get_tag_with_rule_inner(
    name: &str,
    default_tag: Tag,
    rules_lock: &RwLock<Option<DnlCache>>,
    need_rule_pattern: bool,
) -> (Tag, Option<compact_str::CompactString>) {
    let lock = rules_lock.read().unwrap_or_else(|e| e.into_inner());
    let cache = match lock.as_ref() {
        Some(c) => c,
        None => return (default_tag, None),
    };

    let name_trimmed = name.strip_suffix('.').unwrap_or(name);
    if name_trimmed.is_empty()
        || name_trimmed.len() > DNS_NAME_MAXLEN
        || name_trimmed.starts_with('.')
        || name_trimmed.ends_with('.')
    {
        return (default_tag, None);
    }

    let mut lower_buf = [0u8; 255];
    let queried_name_storage;
    let name_to_match = if name_trimmed.len() <= lower_buf.len()
        && name_trimmed.bytes().any(|b| b.is_ascii_uppercase())
    {
        let name_bytes = name_trimmed.as_bytes();
        lower_buf[..name_bytes.len()].copy_from_slice(name_bytes);
        lower_buf[..name_bytes.len()].make_ascii_lowercase();
        // SAFETY: `lower_buf` contains a valid UTF-8 slice copied from `name_trimmed` (&str),
        // where `make_ascii_lowercase()` only modified ASCII bytes (0x41..=0x5A to 0x61..=0x7A), preserving UTF-8 validity.
        unsafe { std::str::from_utf8_unchecked(&lower_buf[..name_bytes.len()]) }
    } else if name_trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        queried_name_storage = name_trimmed.to_ascii_lowercase();
        queried_name_storage.as_str()
    } else {
        name_trimmed
    };

    let mut best = None;

    if let Some(&rule_id) = cache.exact.get(&hash_domain(name_to_match)) {
        consider_rule(&mut best, rule_id);
    }

    if best != Some(0) {
        let has_subdomain = !cache.subdomain.is_empty();
        let has_wildcard_buckets = !cache.wildcard_buckets.is_empty();
        let mut suffix = name_to_match;
        let mut is_subdomain_suffix = false;
        loop {
            let suffix_hash = hash_domain(suffix);
            if let Some(&rule_id) = cache.suffix.get(&suffix_hash) {
                consider_rule(&mut best, rule_id);
                if best == Some(0) {
                    break;
                }
            }
            if is_subdomain_suffix && has_subdomain && let Some(&rule_id) = cache.subdomain.get(&suffix_hash) {
                consider_rule(&mut best, rule_id);
                if best == Some(0) {
                    break;
                }
            }
            if has_wildcard_buckets && let Some(bucket) = cache.wildcard_buckets.get(&suffix_hash) {
                for &idx in bucket {
                    let rule = &cache.provider_wildcards[idx];
                    if best.is_none_or(|current| rule.rule_id < current)
                        && provider_wildcard_matches(rule, name_to_match)
                    {
                        consider_rule(&mut best, rule.rule_id);
                        if best == Some(0) {
                            break;
                        }
                    }
                }
            }
            if best == Some(0) {
                break;
            }
            let Some(dot_idx) = suffix.find('.') else {
                break;
            };
            suffix = &suffix[dot_idx + 1..];
            is_subdomain_suffix = true;
        }
    }

    if best == Some(0) {
        let pat = if need_rule_pattern && !cache.patterns.is_empty() {
            Some(cache.patterns[0].clone())
        } else {
            None
        };
        return (cache.rules[0], pat);
    }

    if !cache.wildcard_fallback.is_empty() {
        for &idx in &cache.wildcard_fallback {
            let rule = &cache.provider_wildcards[idx];
            if best.is_none_or(|current| rule.rule_id < current)
                && provider_wildcard_matches(rule, name_to_match)
            {
                consider_rule(&mut best, rule.rule_id);
            }
        }
    }

    if !cache.classical_wildcards.is_empty() {
        for rule in &cache.classical_wildcards {
            if best.is_none_or(|current| rule.rule_id < current)
                && glob_match(&rule.pattern, name_to_match.as_bytes())
            {
                consider_rule(&mut best, rule.rule_id);
            }
        }
    }

    #[cfg(feature = "aho-corasick")]
    if let Some(ac) = &cache.keyword_automaton {
        if best.is_none_or(|current| !cache.keyword_rule_ids.is_empty() && cache.keyword_rule_ids[0] < current) {
            for mat in ac.find_overlapping_iter(name_to_match.as_bytes()) {
                let rule_id = cache.keyword_rule_ids[mat.pattern().as_usize()];
                consider_rule(&mut best, rule_id);
                if best == Some(0) {
                    break;
                }
            }
        }
    } else if !cache.keywords.is_empty() {
        for rule in &cache.keywords {
            if best.is_none_or(|current| rule.rule_id < current)
                && contains_bytes(name_to_match.as_bytes(), &rule.needle)
            {
                consider_rule(&mut best, rule.rule_id);
            }
        }
    }
    #[cfg(not(feature = "aho-corasick"))]
    // Fallback: O(n*m) linear keyword scan; enable 'aho-corasick' feature for Aho–Corasick automaton
    if !cache.keywords.is_empty() {
        for rule in &cache.keywords {
            if best.is_none_or(|current| rule.rule_id < current)
                && contains_bytes(name_to_match.as_bytes(), &rule.needle)
            {
                consider_rule(&mut best, rule.rule_id);
            }
        }
    }

    #[cfg(feature = "regex")]
    if let Some(regex_set) = &cache.regex_set
        && best.is_none_or(|current| !cache.regex_rule_ids.is_empty() && cache.regex_rule_ids[0] < current) {
            let matches = regex_set.matches(name_to_match);
            if let Some(first_match) = matches.into_iter().next() {
                consider_rule(&mut best, cache.regex_rule_ids[first_match]);
            }
    }

    match best {
        Some(rule_id) => {
            let pat = if need_rule_pattern && !cache.patterns.is_empty() {
                Some(cache.patterns[rule_id as usize].clone())
            } else {
                None
            };
            (cache.rules[rule_id as usize], pat)
        }
        None => (default_tag, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::Write;
    use tempfile::NamedTempFile;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(feature = "rustls-stack")]
    static INIT: std::sync::Once = std::sync::Once::new();
    fn init_rustls() {
        #[cfg(feature = "rustls-stack")]
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    #[test]
    fn test_dnl_flat_map() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut chn = NamedTempFile::new().unwrap();
        writeln!(
            chn,
            "baidu.com # this is an inline comment\n+.cn\n# comment with multiple words"
        )
        .unwrap();

        let mut gfw = NamedTempFile::new().unwrap();
        writeln!(
            gfw,
            "+.google.com\n*.twitter.com\n.example.com\n* # global proxy"
        )
        .unwrap();

        let rules = vec![
            (chn.path().to_str().unwrap().to_string(), Tag::Direct),
            (gfw.path().to_str().unwrap().to_string(), Tag::Proxy),
        ];

        init(rules);

        // Exact match testing
        assert_eq!(get_tag("baidu.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("www.baidu.com", Tag::Direct), Tag::Direct); // no prefix means EXACT, fallback to default

        // Verify comments are stripped and not parsed as domains
        assert_ne!(get_tag("inline", Tag::Proxy), Tag::Direct);
        assert_ne!(get_tag("comment", Tag::Proxy), Tag::Direct);
        assert_ne!(get_tag("words", Tag::Proxy), Tag::Direct);

        // PLUS (+) matching
        assert_eq!(get_tag("cn", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("www.cn", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("google.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("www.google.com", Tag::Direct), Tag::Proxy);

        // STAR (*) matching
        assert_eq!(get_tag("api.twitter.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("twitter.com", Tag::Direct), Tag::Direct); // doesn't match root
        assert_eq!(get_tag("v1.api.twitter.com", Tag::Direct), Tag::Direct); // doesn't match >1 level

        // DOT (.) matching
        assert_eq!(get_tag("www.example.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("api.v1.example.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("example.com", Tag::Direct), Tag::Direct); // doesn't match root

        // GLOBAL STAR matching
        assert_eq!(get_tag("localhost", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("apple", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("apple.com", Tag::Direct), Tag::Direct); // multiple levels don't match
    }

    #[test]
    fn test_yaml_dnl_parsing() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut yaml_file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        writeln!(yaml_file, "payload:").unwrap();
        writeln!(yaml_file, "  - '+.000webhost.com' # comment on domain").unwrap();
        writeln!(yaml_file, "  # a comment line in middle").unwrap();
        writeln!(yaml_file, "  - \"+.0rz.tw\"").unwrap();
        writeln!(yaml_file, "  - +.1-apple.com.tw").unwrap();
        writeln!(yaml_file, "  - '1000giri.net'").unwrap();
        writeln!(yaml_file, "rules:").unwrap();
        writeln!(yaml_file, "  - DOMAIN-SUFFIX,rules-array.test").unwrap();

        let rules = vec![(yaml_file.path().to_str().unwrap().to_string(), Tag::Direct)];
        init(rules);

        // Verify comments are stripped and not parsed as domains
        assert_ne!(get_tag("middle", Tag::Proxy), Tag::Direct);
        assert_ne!(get_tag("domain", Tag::Proxy), Tag::Direct);

        // PLUS matching
        assert_eq!(get_tag("000webhost.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("www.000webhost.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("0rz.tw", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("1-apple.com.tw", Tag::Direct), Tag::Direct);

        // EXACT matching
        assert_eq!(get_tag("1000giri.net", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("www.1000giri.net", Tag::Direct), Tag::Direct);

        // rules: arrays are accepted too
        assert_eq!(get_tag("rules-array.test", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("www.rules-array.test", Tag::Proxy), Tag::Direct);
    }

    #[test]
    #[cfg(feature = "regex")]
    fn test_advanced_rules() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "DOMAIN,exact.com").unwrap();
        writeln!(f, "DOMAIN-SUFFIX,suffix.com").unwrap();
        writeln!(f, "DOMAIN-KEYWORD,badword").unwrap();
        writeln!(f, "DOMAIN-WILDCARD,*.wildcard.org").unwrap();
        writeln!(f, "DOMAIN-REGEX,^abc.*xyz\\.com$").unwrap();
        writeln!(f, "DOMAIN-KEYWORD,CamelCaseWord").unwrap();
        writeln!(f, "DOMAIN-WILDCARD,*.WildCardCamel.Org").unwrap();
        writeln!(f, "DOMAIN-REGEX,^abc#123.*\\.xyz$").unwrap();
        writeln!(f, "DOMAIN,1.2.3.4.5.6.7.8.9.com").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        // DOMAIN
        assert_eq!(get_tag("exact.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("www.exact.com", Tag::Direct), Tag::Direct);

        // DOMAIN-SUFFIX
        assert_eq!(get_tag("suffix.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("api.suffix.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("not-suffix.com", Tag::Direct), Tag::Direct);

        // DOMAIN-KEYWORD
        assert_eq!(get_tag("some-badword-domain.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("goodword.com", Tag::Direct), Tag::Direct);
        assert_eq!(
            get_tag("some-camelcaseword-domain.com", Tag::Direct),
            Tag::Proxy
        );

        // DOMAIN-WILDCARD: * crosses dot boundaries (Mihomo glob semantics)
        assert_eq!(get_tag("api.wildcard.org", Tag::Direct), Tag::Proxy); // 1-level sub: matches
        assert_eq!(get_tag("wildcard.org", Tag::Direct), Tag::Direct); // bare domain: no match
        assert_eq!(get_tag("api.wildcardcamel.org", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("a.b.wildcard.org", Tag::Direct), Tag::Proxy); // multi-level: must match

        // DOMAIN-REGEX
        assert_eq!(get_tag("abc123xyz.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("abxyz.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("abc#123xyz.xyz", Tag::Direct), Tag::Proxy);

        // Long exact domains are not truncated to their last 8 labels.
        assert_eq!(get_tag("1.2.3.4.5.6.7.8.9.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("x.2.3.4.5.6.7.8.9.com", Tag::Direct), Tag::Direct);
    }

    #[test]
    #[cfg(feature = "regex")]
    fn test_classical_rules_parsing() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();

        writeln!(f, "DOMAIN,exact.com,PROXY").unwrap();
        writeln!(f, "DOMAIN-SUFFIX,suffix.com,PROXY").unwrap();
        writeln!(f, "DOMAIN-KEYWORD,keyword,PROXY").unwrap();
        writeln!(f, "DOMAIN-WILDCARD,*.wildcard.org,PROXY").unwrap();
        writeln!(f, "DOMAIN-REGEX,^regex.*\\.xyz$,PROXY").unwrap();
        writeln!(f, "bare.com,PROXY").unwrap();
        writeln!(f, "+.plus.com,PROXY").unwrap();
        writeln!(f, "*.star.com,PROXY").unwrap();
        writeln!(f, ".dot.com,PROXY").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        assert_eq!(get_tag("exact.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("sub.suffix.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("has-keyword.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("sub.wildcard.org", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("regex.xyz", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("bare.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("sub.plus.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("sub.star.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("a.b.star.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("sub.dot.com", Tag::Direct), Tag::Proxy);
    }

    #[test]
    fn test_mihomo_provider_wildcards() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "*.example.com").unwrap();
        writeln!(f, "s3-ap-*.amazonaws.com").unwrap();
        writeln!(f, "*.*.microsoft.com").unwrap();
        writeln!(f, "xbox.*.microsoft.com").unwrap();
        writeln!(f, "api?.wild.example").unwrap();
        writeln!(f, "// premium-style comment").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        assert_eq!(get_tag("www.example.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("a.b.example.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("example.com", Tag::Direct), Tag::Direct);

        assert_eq!(
            get_tag("s3-ap-east-1.amazonaws.com", Tag::Direct),
            Tag::Proxy
        );
        assert_eq!(get_tag("s3.amazonaws.com", Tag::Direct), Tag::Direct);

        assert_eq!(get_tag("a.b.microsoft.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("a.microsoft.com", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("xbox.live.microsoft.com", Tag::Direct), Tag::Proxy);

        assert_eq!(get_tag("api1.wild.example", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("api12.wild.example", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("premium-style", Tag::Direct), Tag::Direct);
    }

    #[test]
    fn test_global_priority_across_rule_kinds() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut keyword_file = NamedTempFile::new().unwrap();
        writeln!(keyword_file, "DOMAIN-KEYWORD,priority").unwrap();

        let mut exact_file = NamedTempFile::new().unwrap();
        writeln!(exact_file, "priority.example.com").unwrap();

        let rules1 = vec![
            (
                keyword_file.path().to_str().unwrap().to_string(),
                Tag::Proxy,
            ),
            (exact_file.path().to_str().unwrap().to_string(), Tag::Direct),
        ];
        init(rules1);
        assert_eq!(get_tag("priority.example.com", Tag::Direct), Tag::Proxy);

        let rules2 = vec![
            (exact_file.path().to_str().unwrap().to_string(), Tag::Direct),
            (
                keyword_file.path().to_str().unwrap().to_string(),
                Tag::Proxy,
            ),
        ];
        init(rules2);
        assert_eq!(get_tag("priority.example.com", Tag::Proxy), Tag::Direct);

        let mut wildcard_file = NamedTempFile::new().unwrap();
        writeln!(wildcard_file, "DOMAIN-WILDCARD,*.ordered.test").unwrap();

        let mut suffix_file = NamedTempFile::new().unwrap();
        writeln!(suffix_file, "+.ordered.test").unwrap();

        let rules3 = vec![
            (
                wildcard_file.path().to_str().unwrap().to_string(),
                Tag::Proxy,
            ),
            (
                suffix_file.path().to_str().unwrap().to_string(),
                Tag::Direct,
            ),
        ];
        init(rules3);
        assert_eq!(get_tag("a.b.ordered.test", Tag::Direct), Tag::Proxy);
    }

    #[test]
    fn test_prioritized_rules() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f1 = NamedTempFile::new().unwrap();
        writeln!(f1, "example.com").unwrap();

        let mut f2 = NamedTempFile::new().unwrap();
        writeln!(f2, "+.example.com").unwrap();

        let tag_custom = Tag::register("custom_test").unwrap();

        // Case 1: f1 before f2
        // example.com matched by f1 (Tag::Direct)
        // www.example.com matched by f2 (Tag::Custom)
        let rules1 = vec![
            (f1.path().to_str().unwrap().to_string(), Tag::Direct),
            (f2.path().to_str().unwrap().to_string(), tag_custom),
        ];
        init(rules1);
        assert_eq!(get_tag("example.com", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("www.example.com", Tag::Proxy), tag_custom);

        // Case 2: f2 before f1
        // example.com matched by f2 (Tag::Custom)
        // www.example.com matched by f2 (Tag::Custom)
        let rules2 = vec![
            (f2.path().to_str().unwrap().to_string(), tag_custom),
            (f1.path().to_str().unwrap().to_string(), Tag::Direct),
        ];
        init(rules2);
        assert_eq!(get_tag("example.com", Tag::Proxy), tag_custom);
        assert_eq!(get_tag("www.example.com", Tag::Proxy), tag_custom);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_process_query_hosts_and_adblock() {
        init_rustls();
        let _guard = TEST_MUTEX.lock().unwrap();

        // 1. Initialize hosts file
        let mut hosts_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(hosts_file, "1.2.3.4 example.com").unwrap();
        writeln!(hosts_file, "::5 example.com").unwrap();
        crate::hosts::init(hosts_file.path().to_str().unwrap());

        // 2. Initialize DNL rules for adblock testing
        let mut adblock_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(adblock_file, "blocked.com").unwrap();

        let rules = vec![(
            adblock_file.path().to_str().unwrap().to_string(),
            Tag::Adblock,
        )];
        init(rules);

        // 3. Mock ServerState using Opt parsed from vector
        let opt = std::sync::Arc::new(crate::opt::Opt::parse_from(vec![
            "chinadns-rs",
            "--hosts",
            hosts_file.path().to_str().unwrap(),
        ]));

        let state = std::sync::Arc::new(crate::server::ServerState {
            opt: opt.clone(),
            default_tag: Tag::from_name(&opt.default_tag).unwrap(),
            tag_to_upstreams: rustc_hash::FxHashMap::default(),
            #[cfg(feature = "ipset")]
            tag_to_sets: rustc_hash::FxHashMap::default(),
            fallback_upstreams: std::sync::Arc::from(
                Vec::<crate::upstream::UpstreamProtocol>::new(),
            ),
            cache: std::sync::Arc::new(crate::cache::DnsCache::new(0, 0, None)),
            tls_config: None,
            tls_config_by_ca: rustc_hash::FxHashMap::default(),
            http_client: None,
            http_clients_by_ca: rustc_hash::FxHashMap::default(),
            #[cfg(feature = "rustls-stack")]
            http3_client: None,
            #[cfg(feature = "rustls-stack")]
            http3_clients_by_ca: rustc_hash::FxHashMap::default(),
            conn_pool: std::sync::Arc::new(crate::upstream::ConnectionPool::new(16, std::sync::Arc::new(crate::opt::Opt::default()))),
            timeout_duration: std::time::Duration::from_secs(1),
            query_count: std::sync::atomic::AtomicU64::new(0),
            refresh_inflight: std::sync::Mutex::new(rustc_hash::FxHashSet::default()),
            global_query_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1000)),
            client_conn_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1024)),
            background_refresh_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            rtt_tracker: std::sync::Arc::new(crate::upstream::RttTracker::new()),
        });

        let client_addr = "127.0.0.1:5353".parse().unwrap();

        // --- Test Hosts Match (A record) ---
        let query_a = crate::dns::build_query("example.com", 1);
        let resp_a =
            crate::server::process_query(&query_a, &state, client_addr, true, None, crate::request_id::RequestId::new())
                .await
                .unwrap();
        let msg_a = crate::dns::DnsMessage::parse(&resp_a).unwrap();
        assert_eq!(msg_a.get_rcode(), 0); // NOERROR
        // Collect resolved IPs
        let mut ips = Vec::new();
        msg_a.for_each_ip(|ip| {
            ips.push(ip);
            false
        });
        assert_eq!(
            ips,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))]
        );

        // --- Test Hosts Match (AAAA record) ---
        let query_aaaa = crate::dns::build_query("example.com", 28);
        let resp_aaaa =
            crate::server::process_query(&query_aaaa, &state, client_addr, true, None, crate::request_id::RequestId::new())
                .await
                .unwrap();
        let msg_aaaa = crate::dns::DnsMessage::parse(&resp_aaaa).unwrap();
        assert_eq!(msg_aaaa.get_rcode(), 0); // NOERROR
        let mut ips_v6 = Vec::new();
        msg_aaaa.for_each_ip(|ip| {
            ips_v6.push(ip);
            false
        });
        assert_eq!(
            ips_v6,
            vec![std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                0, 0, 0, 0, 0, 0, 0, 5
            ))]
        );

        // --- Test Adblock Match (NXDOMAIN response) ---
        let query_blocked = crate::dns::build_query("blocked.com", 1);
        let resp_blocked =
            crate::server::process_query(&query_blocked, &state, client_addr, true, None, crate::request_id::RequestId::new())
                .await
                .unwrap();
        let msg_blocked = crate::dns::DnsMessage::parse(&resp_blocked).unwrap();
        assert_eq!(msg_blocked.get_rcode(), 3); // NXDOMAIN
    }

    #[tokio::test]
    async fn test_system_config_integration() {
        let _guard = TEST_MUTEX.lock().unwrap();

        // 1. Read actual system config or fallback to sample
        let config_path = "/etc/chinadns-ng/config.conf";
        let config_content = match std::fs::read_to_string(config_path) {
            Ok(c) => c,
            Err(_) => return, // Skip test if system config is not readable (e.g. non-existent on non-test system)
        };

        // Parse upstream-rule entries from config
        let mut upstream_rule_entries = Vec::new();
        for line in config_content.lines() {
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

            let (parts_key, parts_val) = if let Some((k, v)) = line_no_comment.split_once('=') {
                (k.trim(), Some(v.trim()))
            } else if let Some((k, v)) = line_no_comment.split_once(|c: char| c.is_whitespace())
            {
                (k.trim(), Some(v.trim()))
            } else {
                (line_no_comment, None)
            };

            if parts_key == "upstream-rule"
                && let Some(val) = parts_val {
                    upstream_rule_entries.push(val.to_string());
                }
        }

        let mut rules = Vec::new();
        for entry in upstream_rule_entries {
            if let Some((file, tag_name)) = crate::parse_rule_line(&entry) {
                if let Some(t) = Tag::from_name(&tag_name) {
                    if !std::path::Path::new(&file).exists() {
                        return;
                    }
                    rules.push((file, t));
                }
            } else {
                let rules_content = match std::fs::read_to_string(&entry) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                for line in rules_content.lines() {
                    if let Some((file, tag_name)) = crate::parse_rule_line(line)
                        && let Some(t) = Tag::from_name(&tag_name) {
                            if !std::path::Path::new(&file).exists() {
                                return;
                            }
                            rules.push((file, t));
                        }
                }
            }
        }

        if rules.is_empty() {
            return;
        }

        // 3. Initialize DNL cache using real rules
        init(rules);

        // 4. Verification with real domains from parsed files
        // We know from /var/lib/mihomo/provider/rule-set/ custom-domain-proxy.list has googlevideo.com
        // custom-domain-direct.list has vc52.cn
        // adblock-domain.list has unioncom.cc

        // Block tag matching
        assert_eq!(get_tag("unioncom.cc", Tag::Direct), Tag::Adblock);

        // Direct tag matching
        assert_eq!(get_tag("vc52.cn", Tag::Proxy), Tag::Direct);

        // Proxy tag matching
        assert_eq!(get_tag("googlevideo.com", Tag::Direct), Tag::Proxy);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_cache_ttl_normalization() {
        init_rustls();
        let _guard = TEST_MUTEX.lock().unwrap();

        // 1. Mock ServerState with cache configurations
        let opt = std::sync::Arc::new(crate::opt::Opt::parse_from(vec![
            "chinadns-rs",
            "--cache",
            "10",
            "--cache-max-ttl",
            "10", // Max TTL override
        ]));

        // Bind mock DNS upstream server
        let mock_server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_server.local_addr().unwrap();

        // Mock upstream that replies with TTL = 100
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_len, client_addr)) = mock_server.recv_from(&mut buf).await {
                let id = u16::from_be_bytes([buf[0], buf[1]]);

                // Build a response for "cache-ttl-test.com"
                let mut resp_msg = crate::dns::build_query("cache-ttl-test.com", 1);
                // Set QR bit (response) and ID
                resp_msg[2] |= 0x80;
                resp_msg[0] = (id >> 8) as u8;
                resp_msg[1] = (id & 0xFF) as u8;
                // Add Answer with TTL = 100
                resp_msg[6] = 0;
                resp_msg[7] = 1; // ANCOUNT = 1
                resp_msg.push(0xC0);
                resp_msg.push(0x0C);
                resp_msg.extend_from_slice(&[0x00, 0x01]); // Type A
                resp_msg.extend_from_slice(&[0x00, 0x01]); // Class IN
                resp_msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x64]); // TTL = 100
                resp_msg.extend_from_slice(&[0x00, 0x04]); // RDLEN = 4
                resp_msg.extend_from_slice(&[1, 1, 1, 1]);

                let _ = mock_server.send_to(&resp_msg, client_addr).await;
            }
        });

        let mut tag_to_upstreams = rustc_hash::FxHashMap::default();
        tag_to_upstreams.insert(
            Tag::Direct,
            std::sync::Arc::from(vec![crate::upstream::UpstreamProtocol::Udp(mock_addr, Default::default())]),
        );

        let state = std::sync::Arc::new(crate::server::ServerState {
            opt: opt.clone(),
            default_tag: Tag::from_name(&opt.default_tag).unwrap(),
            tag_to_upstreams,
            #[cfg(feature = "ipset")]
            tag_to_sets: rustc_hash::FxHashMap::default(),
            fallback_upstreams: std::sync::Arc::from(
                Vec::<crate::upstream::UpstreamProtocol>::new(),
            ),
            cache: std::sync::Arc::new(crate::cache::DnsCache::new(10, 0, None)),
            tls_config: None,
            tls_config_by_ca: rustc_hash::FxHashMap::default(),
            http_client: None,
            http_clients_by_ca: rustc_hash::FxHashMap::default(),
            #[cfg(feature = "rustls-stack")]
            http3_client: None,
            #[cfg(feature = "rustls-stack")]
            http3_clients_by_ca: rustc_hash::FxHashMap::default(),
            conn_pool: std::sync::Arc::new(crate::upstream::ConnectionPool::new(16, std::sync::Arc::new(crate::opt::Opt::default()))),
            timeout_duration: std::time::Duration::from_millis(1000),
            query_count: std::sync::atomic::AtomicU64::new(0),
            refresh_inflight: std::sync::Mutex::new(rustc_hash::FxHashSet::default()),
            global_query_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1000)),
            client_conn_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(1024)),
            background_refresh_queue: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            rtt_tracker: std::sync::Arc::new(crate::upstream::RttTracker::new()),
        });

        let client_addr = "127.0.0.1:5353".parse().unwrap();
        let query = crate::dns::build_query("cache-ttl-test.com", 1);

        // Resolve. It should query upstream, get response (with TTL=100), but cache and return with normalized TTL (max_ttl=10).
        let resp = crate::server::process_query(&query, &state, client_addr, true, None, crate::request_id::RequestId::new())
            .await
            .unwrap();
        let msg = crate::dns::DnsMessage::parse(&resp).unwrap();

        assert_eq!(msg.get_min_ttl(), 10); // Capped at max-ttl!
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_match_logging_functionality() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let log_file = NamedTempFile::new().unwrap();
        let log_path = log_file.path().to_str().unwrap().to_string();

        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "+.example.com").unwrap();
        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        // Initialize logging
        init_match_logging(&log_path).unwrap();

        // Perform matches (original casing should be logged)
        assert_eq!(get_tag("WWW.Example.Com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("apple.com", Tag::Direct), Tag::Direct);

        // Wait for buffer flush
        tokio::time::sleep(tokio::time::Duration::from_millis(600)).await;

        // Read log file content
        let logs = std::fs::read_to_string(&log_path).unwrap();
        assert!(logs.contains("WWW.Example.Com,proxy,+.example.com\n"));
        assert!(logs.contains("apple.com,direct,none\n"));
    }
    #[tokio::test]
    async fn test_production_rules_comprehensive() {
        let _guard = TEST_MUTEX.lock().unwrap();

        let rules_path = "/etc/chinadns-ng/upstream.rules";
        let rules_content = match std::fs::read_to_string(rules_path) {
            Ok(c) => c,
            Err(_) => return, // Skip on non-production systems
        };

        let mut rules = Vec::new();
        for line in rules_content.lines() {
            if let Some((file, tag_name)) = crate::parse_rule_line(line)
                && let Some(t) = Tag::from_name(&tag_name)
            {
                if !std::path::Path::new(&file).exists() {
                    return;
                }
                rules.push((file, t));
            }
        }

        if rules.is_empty() {
            return;
        }

        init(rules);

        // --- TLD matching ---
        // +.alibaba in cn-domain.list → direct
        assert_eq!(get_tag("alibaba", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("foo.alibaba", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("foo.bar.alibaba", Tag::Proxy), Tag::Direct);

        // --- Punycode ---
        // +.xn--zfr164b in cn-domain.list → direct
        assert_eq!(get_tag("xn--zfr164b", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("foo.xn--zfr164b", Tag::Proxy), Tag::Direct);

        // --- Adblock exact match ---
        // pinggai0.caixin.com (bare) in adblock-domain.list → block
        assert_eq!(get_tag("pinggai0.caixin.com", Tag::Direct), Tag::Adblock);
        // www.pinggai0.caixin.com should NOT match (bare = EXACT only)
        assert_ne!(
            get_tag("www.pinggai0.caixin.com", Tag::Direct),
            Tag::Adblock
        );

        // --- Adblock plus match ---
        // +.pubmatic.com in adblock-domain.list → block
        assert_eq!(get_tag("pubmatic.com", Tag::Direct), Tag::Adblock);
        assert_eq!(get_tag("www.pubmatic.com", Tag::Direct), Tag::Adblock);
        assert_eq!(get_tag("a.b.pubmatic.com", Tag::Direct), Tag::Adblock);

        // --- Proxy bare exact ---
        // clients1.google.com (bare) in google-domain.list → proxy
        assert_eq!(get_tag("clients1.google.com", Tag::Direct), Tag::Proxy);
        // www.clients1.google.com also matches proxy via +.google.com in the same file
        assert_eq!(get_tag("www.clients1.google.com", Tag::Direct), Tag::Proxy);

        // --- Direct plus ---
        // +.vc52.cn in custom-domain-direct.list → direct
        assert_eq!(get_tag("vc52.cn", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("www.vc52.cn", Tag::Proxy), Tag::Direct);

        // --- TLD private ---
        // +.local in private-domain.list → direct
        assert_eq!(get_tag("local", Tag::Proxy), Tag::Direct);
        assert_eq!(get_tag("myhost.local", Tag::Proxy), Tag::Direct);

        // --- Case insensitivity ---
        assert_eq!(get_tag("PUBMATIC.COM", Tag::Direct), Tag::Adblock);
        assert_eq!(get_tag("Clients1.Google.Com", Tag::Direct), Tag::Proxy);
    }

    #[test]
    fn test_split_whitespace_single_token() {
        let _guard = TEST_MUTEX.lock().unwrap();
        // Simulate a classical-format rule with extra whitespace tokens
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "example.com  PROXY  extra-stuff").unwrap();
        writeln!(f, "+.suffix.com").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        // example.com should be matched
        assert_eq!(get_tag("example.com", Tag::Direct), Tag::Proxy);
        // "PROXY" and "extra-stuff" must NOT be inserted as domains
        assert_eq!(get_tag("proxy", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("extra-stuff", Tag::Direct), Tag::Direct);
        // +.suffix.com should still work
        assert_eq!(get_tag("suffix.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("www.suffix.com", Tag::Direct), Tag::Proxy);
    }

    #[test]
    #[ignore = "manual large-rule stress check"]
    fn test_large_suffix_rule_stress() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        for i in 0..100_000 {
            writeln!(f, "+.stress-{i}.example").unwrap();
        }

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        for i in 0..100_000 {
            let domain = format!("www.stress-{i}.example");
            assert_eq!(get_tag(&domain, Tag::Direct), Tag::Proxy);
        }
    }

    #[test]
    fn test_non_domain_rule_filtering() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "IP-CIDR,10.0.0.0/8,DIRECT").unwrap();
        writeln!(f, "IP-CIDR6,2001:db8::/32,PROXY").unwrap();
        writeln!(f, "GEOIP,CN,DIRECT").unwrap();
        writeln!(f, "PROCESS-NAME,curl,DIRECT").unwrap();
        writeln!(f, "192.168.0.0/16").unwrap();
        writeln!(f, "DOMAIN,real-domain.com,PROXY").unwrap();
        writeln!(f, "bare-domain.org,PROXY").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        // Real domains must match
        assert_eq!(get_tag("real-domain.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("bare-domain.org", Tag::Direct), Tag::Proxy);

        // Non-domain rule types must NOT be inserted into domain cache
        assert_eq!(get_tag("ip-cidr", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("ip-cidr6", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("geoip", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("process-name", Tag::Direct), Tag::Direct);
        assert_eq!(get_tag("192.168.0.0/16", Tag::Direct), Tag::Direct);
    }

    #[test]
    fn test_aho_corasick_keyword_matching() {
        let _guard = TEST_MUTEX.lock().unwrap();
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "DOMAIN-KEYWORD,google").unwrap();
        writeln!(f, "DOMAIN-KEYWORD,youtube").unwrap();
        writeln!(f, "DOMAIN-KEYWORD,fb").unwrap();

        let rules = vec![(f.path().to_str().unwrap().to_string(), Tag::Proxy)];
        init(rules);

        assert_eq!(get_tag("some-google-service.com", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("my-youtube-cdn.net", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("login.fb.me", Tag::Direct), Tag::Proxy);
        assert_eq!(get_tag("unrelated.com", Tag::Direct), Tag::Direct);
    }
}
