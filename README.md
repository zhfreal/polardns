# PolarDNS

**PolarDNS** is a modern, high-performance rule-based DNS proxy and router designed for smart traffic splitting, privacy protection, and adblocking. It allows you to route DNS queries intelligently to different upstream resolvers (such as direct domestic DNS, secure encrypted DNS, or custom internal resolvers) based on flexible domain matching rules.

PolarDNS runs efficiently on everything from low-resource embedded home routers (such as OpenWrt) to high-concurrency cloud servers.

---

## 🌟 Key Features

* 🎯 **Smart Rule-Based Routing**: Route domains to specific upstream servers (e.g. `direct`, `proxy`, or custom groups) using widely-adopted Mihomo/Clash provider-domain and classical rule formats (`DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `+.example.com`, wildcards, and regex).
* 🔒 **All-in-One Encrypted DNS (Client & Server)**:
  * **Local Server**: Serve local network clients over DNS-over-HTTPS (DoH), DNS-over-HTTP/3 (DoH3), DNS-over-QUIC (DoQ, RFC 9250), DNS-over-TLS (DoT), and standard UDP/TCP.
  * **Upstreams**: Query remote upstreams via DoH (`https://`), DoH3 (`h3://`), DoQ (`doq://`), DoT (`tls://`), and standard UDP/TCP. Supports custom root CA certificate pinning (`|ca=/path/to/ca.pem`).
* 🛡️ **Built-in Adblocking**: Load one or more adblocking domain lists. Queries matching ad or tracker domains immediately receive `NXDOMAIN`, preventing unwanted connections before they reach your upstreams.
* ⚡ **Fastest Server Auto-Selection & Instant Failover**: Continuous background latency tracking automatically routes queries to the lowest-latency upstream server, applying immediate failover penalties if a server becomes slow or unreachable.
* 🔄 **Web-Fetched Rules & Zero-Downtime Hot Reload**: Fetch domain lists directly from remote URLs with configurable auto-refresh intervals. Updated rule files on disk are hot-reloaded seamlessly into memory without dropping client connections or restarting the daemon.
* 🧱 **Automatic Firewall Integration (ipset & nftables)**: Automatically add resolved IP addresses into Linux `ipset` or `nftables` sets for transparent proxying, traffic bypass, and policy routing.
* 📝 **Local Hosts & Custom Records**: Easily define local static DNS mappings or import existing system hosts files (`/etc/hosts`).
* 🪶 **Lightweight & Router-Friendly**: Designed with minimal CPU and memory footprints. Features specialized low-memory profiles optimized for OpenWrt and embedded routers (< 14 MB RAM usage).
* ⚙️ **User-Friendly Configuration**: Structured, easy-to-read TOML and YAML configuration files, alongside full CLI flag support.

---

## 🚀 Quick Start

### 1. Download or Build

Build a release binary with the Rust toolchain:

```bash
cargo build --release
```

The compiled binary will be located at `target/release/polardns`.

### 2. Basic Command Line Usage

Run PolarDNS to split traffic between a local direct DNS and an encrypted upstream:

```bash
polardns \
    --bind-addr 127.0.0.1 \
    --bind-port 1054 \
    --direct-dns 223.5.5.5 \
    --proxy-dns https://1.1.1.1/dns-query \
    --upstream-rule /etc/polardns/rules/direct.yaml@direct \
    --upstream-rule /etc/polardns/rules/proxy.rules@proxy \
    --default-tag direct
```

---

## 💡 How It Works

Every DNS request received by PolarDNS is processed in a clean, predictable order:

1. **Local Overrides**: Checks local custom domain records and `/etc/hosts`.
2. **Adblock**: Checks configured adblocking domain lists. If matched, returns `NXDOMAIN` immediately.
3. **Local Cache**: Returns the cached response if available.
4. **Rule Matching**: Matches the requested domain against your configured rule lists from top to bottom. The first matching rule assigns the query to a target group (e.g., `direct`, `proxy`, or a custom group). If no rule matches, the `default-tag` is used.
5. **Upstream Resolution**: Routes the query to the fastest available upstream server configured for that tag.

---

## 📋 Configuration Guide

PolarDNS supports **TOML** (recommended) and **YAML** configuration files, automatically detected by file extension.

### Example Configuration (`config.toml`)

```toml
# Base working directory for resolving relative rule and certificate paths
workspace = "/etc/polardns"

# ==============================================================================
# Listeners (Where PolarDNS accepts queries)
# ==============================================================================
[listeners]
# Listen on local IPv4 and IPv6 loopback on port 1054
bind_addr = ["127.0.0.1", "::1"]
bind_port = [1054]

# Optional: Enable local encrypted DNS listeners
[listeners.tls]
enable_dot = false
dot_port = [853]

enable_doh = false
doh_port = [443]
doh_path = "/dns-query"
enable_doh3 = false   # HTTP/3 over QUIC

enable_doq = false   # DNS-over-QUIC (RFC 9250)
doq_port = [853]

cert_file = "/etc/polardns/tls/default.crt"
key_file = "/etc/polardns/tls/default.key"

# ==============================================================================
# Upstream Resolvers
# ==============================================================================
[upstreams.direct]
# Direct resolvers for local domains
servers = ["223.5.5.5", "119.29.29.29"]
# Add resolved IPs to firewall sets for direct routing
sets = ["direct_v4", "direct_v6"]

[upstreams.proxy]
# Encrypted resolvers for proxied domains
servers = [
    "tls://1.1.1.1:853",
    "https://1.1.1.1/dns-query",
    "h3://dns.google/dns-query"
]
# Add resolved IPs to firewall sets for proxy routing
sets = ["proxy_v4", "proxy_v6"]

# Bootstrap resolver used to resolve DoH/DoT upstream domain names
[upstreams.fallback]
servers = ["223.5.5.5"]

# Optional: Custom routing groups (e.g., for streaming or corporate networks)
[upstreams.groups.streaming]
servers = ["https://dns.example/dns-query"]
sets = ["streaming_v4"]

# ==============================================================================
# Built-in Adblocking
# ==============================================================================
adblock = [
    "/etc/polardns/rules/adblock.list"
]

# ==============================================================================
# Rule-Based Routing
# ==============================================================================
# Rules are evaluated in top-to-bottom order. First match wins.

# Example 1: Web-fetched remote rule list with 24-hour auto-refresh
# [[rules]]
# type = "upstream"
# path = "rules/remote-proxy.txt"
# url = "https://example.com/rules/proxy-domains.txt"
# refresh = 86400
# tag = "proxy"

# Example 2: Explicit inline domain list
[[rules]]
type = "upstream"
domains = [
    "DOMAIN-SUFFIX,google.com",
    "DOMAIN-KEYWORD,github",
    "*.wikipedia.org"
]
tag = "proxy"

# Example 3: Rule files
[[rules]]
type = "upstream"
path = "rules/direct-domains.yaml"
tag = "direct"

[[rules]]
type = "upstream"
path = "rules/proxy-domains.rules"
tag = "proxy"

[[rules]]
type = "upstream"
path = "rules/streaming.yaml"
tag = "streaming"

# Default fallback tag for unmatched queries
[[rules]]
type = "default"
tag = "direct"

# ==============================================================================
# DNS Caching
# ==============================================================================
[cache]
size = 4096              # Number of cached records (0 to disable)
stale = 86400            # Serve stale entries on network errors (in seconds)
db_path = "/var/cache/polardns/cache.db" # Persistent cache across restarts

# ==============================================================================
# Local Overrides & Hosts
# ==============================================================================
[hosts]
hosts_file = "/etc/hosts"

[hosts.rr_records]
"router.local" = ["192.168.1.1"]
"nas.local" = ["192.168.1.100"]

# ==============================================================================
# Logging
# ==============================================================================
[logging]
log_level = "info"
log_dns_match = "/var/log/polardns/match.log"   # Logs domain routing decisions
```

---

## 📂 Rule Formats & Syntax

PolarDNS supports standard rule formats used across modern network tools:

### Provider Domain Syntax (`.yaml` / `.list`)
```yaml
payload:
  - example.com          # Exact match only
  - '+.example.net'      # example.net and all subdomains (Recommended suffix match)
  - '.internal.example'  # Subdomains only
  - '*.cdn.example'      # Wildcard match
  - 'api?.example.org'   # Single character wildcard
```

### Classical Rule Syntax (`.rules`)
```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.net
DOMAIN-KEYWORD,google
DOMAIN-WILDCARD,*.video.example
DOMAIN-REGEX,^(.+\.)?service\.org$
```

---

## 🔀 Upstream Protocols & Routing Modifiers

PolarDNS supports flexible upstream URL definitions:

| Protocol | Syntax Example | Notes |
| :--- | :--- | :--- |
| **UDP / TCP** | `1.1.1.1:53` or `1.1.1.1` | Tries UDP first, falls back to TCP on truncation |
| **UDP Only** | `udp://1.1.1.1:1053` | Standard UDP transport on custom port |
| **TCP Only** | `tcp://1.1.1.1:1053` | Standard TCP transport on custom port |
| **DNS-over-TLS (DoT)** | `tls://1.1.1.1:853` | Encrypted TLS transport |
| **DNS-over-HTTPS (DoH)** | `https://1.1.1.1/dns-query` | Encrypted HTTP/2 or HTTP/1.1 transport |
| **DNS-over-HTTP/3 (DoH3)** | `h3://1.1.1.1/dns-query` | Encrypted QUIC / HTTP/3 transport |
| **DNS-over-QUIC (DoQ)** | `doq://dns.adguard-dns.com:853` | RFC 9250 QUIC transport |

### Per-Upstream Attributes
You can customize upstream behavior by appending modifiers to the URL:
* **Custom CA Pinning**: `https://dns.internal/dns-query|ca=/etc/polardns/internal-ca.pem`
* **Linux Socket Mark (SO_MARK)**: `tls://1.1.1.1:853|mark=100`

---

## 🚦 Firewall Integration (ipset & nftables)

PolarDNS can dynamically add resolved IPv4 and IPv6 addresses into kernel firewall sets, enabling seamless policy routing and traffic splitting:

```bash
# Add resolved IPs for direct and proxy domains to ipset or nftables
polardns \
    --direct-sets direct_v4,direct_v6 \
    --proxy-sets proxy_v4,nft:inet:fw4:proxy_set
```

* **ipset**: Specify the set name directly (e.g. `direct_v4`).
* **nftables**: Use the format `nft:<family>:<table>:<set>` (e.g. `nft:inet:fw4:proxy_set`).

---

## 🛠️ Building & Installation

### Build Requirements
* Modern Rust toolchain (Rust 1.85+, Edition 2024).

```bash
# Build standard release
cargo build --release
```

### Router / Low-Memory Build (`quiche` Engine)
For resource-constrained devices like OpenWrt routers with 32MB–64MB RAM, build with the `quiche` engine for a tiny ~14 MB RAM footprint:

```bash
cargo build --release --no-default-features --features jemalloc,quiche,tls12
```

Use `--h3-low-memory` or `--h3-profile low` at runtime for ultra-low memory operation.

---

## 📦 Systemd Service Deployment

A sample systemd service file is provided at [`examples/polardns.service`](examples/polardns.service).

### Quick Setup

```bash
# 1. Install binary
sudo install -Dm755 target/release/polardns /usr/local/bin/polardns

# 2. Setup configuration directory
sudo install -d /etc/polardns /var/cache/polardns /var/log/polardns
sudo install -Dm644 examples/config.toml /etc/polardns/config.toml
sudo install -Dm644 examples/upstreams.rules /etc/polardns/upstreams.rules

# 3. Install systemd service
sudo install -Dm644 examples/polardns.service /etc/systemd/system/polardns.service

# 4. Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now polardns
```

To run with non-root security privileges, PolarDNS requests `CAP_NET_BIND_SERVICE` (to bind low ports), `CAP_NET_ADMIN` (for firewall set sync), and `CAP_NET_RAW` (for interface binding).

---

## ⚖️ License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE) for details.
