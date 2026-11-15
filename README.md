# PolarDNS

PolarDNS is a next-generation high-performance rule-based DNS proxy and router engineered for modern network environments. Written 100% in native Rust, it is designed from the ground up for maximum throughput, memory safety, and flexible policy-based traffic routing.

Featuring unmatched **Memory Safety** and lightning-fast **tokio-based Concurrency**, PolarDNS delivers extreme performance across cloud servers, home gateways, and resource-constrained embedded routers without sacrificing deployment speed or flexibility!

## 🚀 Key Features & Capabilities

### 💎 User-Facing Features (Native Rust Engine)

* **Local DoT, DoH, DoH3 & DoQ Server Listeners**: Serves local DNS clients over TLS (DoT), HTTPS (DoH), HTTP/3 (DoH3/QUIC), and DNS-over-QUIC (DoQ, RFC 9250) with SNI-based certificate selection (`--cert-pair`), TLS 1.3/1.2 control, and strict SNI mode.
* **Flexible Rule-Based Routing**: Use `--upstream-rule` to bind multiple Clash/Mihomo-style domain list files to custom routing tags/groups with globally consistent priority order, replacing the rigid legacy lists.
* **Mihomo (Clash) Rule Compatibility**: Full support for Mihomo/Clash provider-domain syntax (e.g., `+.example.com`, `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`, and `DOMAIN-REGEX` rules).
* **Zero-Downtime Hot Reload**: Monitored domain list files are dynamically rebuilt and swapped in-memory at runtime. No daemon restarts are required for daily rule updates.
* **Web-Fetched Rules & Automatic Background Refresh**: Automatically download rules from HTTP/HTTPS URLs to local files (`path`), with configurable background auto-refresh intervals (`refresh` in seconds). Works seamlessly with hot-reloading!
* **Encrypted Upstreams (DoH, DoH3 & DoQ)**: Supports querying upstreams over DoH (`https://`), DoH3 (`h3://`), and DoQ (`doq://` / `quic://`) in addition to UDP, TCP, and DoT, with per-upstream CA pinning support (`|ca=/path/to/ca.pem`).
* **RTT-Based Smart Routing**: Active probing of all configured upstreams every 15 seconds (configurable via `--rtt-probe-interval`, with timeout `--rtt-probe-timeout-ms`) measures pure network latency, keeping upstreams sorted. Fast fail-over instantly applies penalties to dead or saturated servers. Automatically avoids background probing when only 1 upstream is configured or when disabled (`0`).
* **Asynchronous Match Tracing**: Buffered, non-blocking logs of domain-to-tag matches via `--log-dns-match` for precise debugging without impacting query path performance.
* **Millisecond-Precision Timeouts & Intervals**: Added `--timeout-ms` for granular control, `--queue-timeout-ms` for queue saturation shed timeout, `--rtt-probe-interval` for background probe scheduling, and `--rtt-probe-timeout-ms` for active probe query timeouts.
* **Embedded & Low-End Device Support**: Configure worker thread count via `--worker-threads` / `--threads` and thread stack size via `--thread-stack-size` (defaults to 512KB for embedded targets, reducing virtual and resident memory significantly vs the glibc 8MB default). Automatic jemalloc dirty/muzzy page purging minimizes resident set size on low-memory routers.
* **Comprehensive CLI Aliases**: Flexible argument handling including `-a` (`--bind-address`), `-p` / `-l` (`--bind-port`, `--dns-port`), `--tls-port`, `--bind` (alias for `--bind-dynamic`), and `--tls-bind`.
* **Advanced Interface Binding (dnsmasq-style)**: Support for `-z / --bind-interfaces` (strict static binding) and `--bind-dynamic` (smart per-IP interface binding) with `-I / --except-interface` blacklisting support.

### ⚡ Architectural & Performance Upgrades

* **Dual Crypto & HTTP/3 Engine Architecture**: Complete native Rust architecture with zero legacy C wrappers, offering two selectable engines: a 100% Pure Rust engine (`original`, zero C/CMake dependencies) and an enterprise-grade `quiche` engine (Cloudflare quiche + Google BoringSSL + Hyper) optimized for minimal memory footprint (~14 MB RSS) and full DoQ/DoH3 client and server support.
* **Zero-Allocation DNS Parser**: A custom-engineered DNS parser parses incoming packets directly from raw byte slices with zero allocations, offering safety against memory overflows and extreme throughput.
* **Native Netlink bindings via Rustix**: Integrates with the Linux kernel via `AF_NETLINK` using zero-allocation packed structures to dynamically sync DNS results to `ipset` and `nftables` without spawning sub-shells.
* **Standard Async I/O (Tokio)**: Modern, highly optimized `tokio` multi-threading multiplexers.
* **Resilient Connection Pooling**: Advanced semaphore-controlled client lease pool with TCP Keepalive probes to handle heavy multi-threaded throughput.
* **DoS & Slowloris Protection**: Built-in global query rate limiting and socket idle timeouts (`--tcp-idle-timeout-ms`).
* **Adaptive Cache RAM Management (Smart Shrink)**: Automatically releases unused RAM back to the OS during periods of low DNS caching activity.

## 🧠 Core Mechanics & Routing Logic

`polardns` employs a high-performance matching and routing engine engineered for speed and memory efficiency.

### 1. Match Order (Fast Path First)
Every incoming DNS request follows a fixed routing order. Exact domains and suffix rules use allocation-free fast indexes; wildcard, keyword, and regex rules are evaluated only when present:
1.  **Hosts**: Checked against local hosts file (`--hosts`) or manual entries (`--dns-rr-ip`). Supports **multiple IPv4 and IPv6 addresses** per domain.
2.  **Adblock**: Checked against adblock lists (`--adblock`). Matches return `NXDOMAIN` immediately.
3.  **DNS Cache**: High-performance O(1) cache lookup.
4.  **Upstream Servers**: Routed based on the domain's **Tag** (matched via `--upstream-rule` or legacy priority) or the `--default-tag`.

### 2. Upstream Routing Rules
- **Advanced Mode (Recommended)**: Uses `--upstream-rule <file>`. Define an ordered list of `<dnl file>@<tag>` where the first matching DNL rule wins and routes the query to that tag.
- **Legacy Mode (Deprecated)**: Uses `--directlist-file` (or legacy `--chnlist-file`) and `--gfwlist-file`. Priority is determined by `--directlist-first` (or legacy `--chnlist-first`).
- **Supported Tags**: `direct` (with aliases `polar`, `chn`), `proxy` (with legacy alias `gfw`), or any custom group name defined via `--group`.
- **Mihomo-Compatible Domains**: Rule files support provider-domain syntax (`example.com`, `+.example.com`, `.example.com`, `*.example.com`, embedded `*`/`?` wildcards) and classical `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `DOMAIN-WILDCARD`, and `DOMAIN-REGEX` entries.
- **Priority**: First match wins across all rule kinds, not just within exact/suffix rules.
- **Rule-Based DNL Matching**: Domain-name-list matching is a first-class routing feature. You can bind multiple Clash/Mihomo-style DNL files to different upstream tags, including custom groups, instead of relying on only one direct list and one proxy list.
- **Hot Reload**: DNL files referenced by `upstreams.rules` are watched at runtime. When one of those files changes, `polardns` rebuilds and hot-swaps the DNL cache without restarting the daemon; if the rebuild fails, the previous working cache stays active and the watcher retries later.
- **Note**: The legacy `none` tag and verdict-based routing have been discarded for better predictability.

`--upstream-rule` can be specified multiple times and accepts either a path to a control file (backward compatibility mode) or inline rule mapping directly.

When mapping inline rules directly or writing them in the control file, each rule maps one DNL rule file to one routing tag:

```text
# Recommended separator
/etc/polardns/rules/direct-provider.yaml@direct
/etc/polardns/rules/proxy-classical.rules@proxy
/etc/polardns/rules/adblock-provider.yaml@adblock

# Comma is also accepted for compatibility
/etc/polardns/rules/private-cdn.list,cdn
```

When specifying rules directly or via a control file, paths are read exactly as written. Use absolute paths in service or Docker configs, or configure a `workspace` directory.

#### Workspace Path Resolution
If a `workspace` is configured (via the config file, `POLARDNS_WORKSPACE` environment variable, or the `-w` / `--workspace` CLI flag), all relative paths (including rule files, certificates, and databases) will automatically resolve relative to this directory. Relative DNL file paths referenced inside an `upstreams.rules` control file will also dynamically resolve against the workspace base directory.

#### Method 1: Using Inline Rules in Command Line or Config File (Recommended)
You can define rules directly without an intermediate `upstreams.rules` file:

```bash
polardns \
    --direct-dns 223.5.5.5 \
    --proxy-dns https://1.1.1.1/dns-query \
    --group cdn \
    --group-upstream cdn:https://dns-cdn.example/dns-query \
    --upstream-rule /etc/polardns/rules/direct-provider.yaml@direct \
    --upstream-rule /etc/polardns/rules/proxy-classical.rules@proxy \
    --upstream-rule /etc/polardns/rules/private-cdn.list,cdn
```

Or inside the TOML configuration file (`config.toml`):
```toml
[[rules]]
type = "upstream"
path = "/etc/polardns/rules/direct-provider.yaml"
tag = "direct"

[[rules]]
type = "upstream"
path = "/etc/polardns/rules/proxy-classical.rules"
tag = "proxy"

[[rules]]
type = "upstream"
path = "rules/private-cdn.list"
tag = "cdn"

# You can also embed domain list rules directly in TOML/YAML:
[[rules]]
type = "upstream"
domains = [
    "DOMAIN,example.com",
    "DOMAIN-SUFFIX,google.com",
    "github.com",
    "*.bing.com"
]
tag = "proxy"
```

#### Web-Fetched Rules (TOML/YAML only)
You can automatically fetch rules from a remote HTTP/HTTPS URL on startup and keep them updated in the background:
```toml
[[rules]]
type = "upstream"
path = "rules/remote-rules.txt"    # Local path to store the fetched rules
url = "https://example.com/rules"  # URL to fetch from
refresh = 86400                    # Background refresh interval in seconds (default: 86400 / 24h)
tag = "proxy"
```

#### Method 2: Pointing to a Separate Rule File (Legacy/Compatible Mode)
You can still point `--upstream-rule` to a separate file (e.g. `/etc/polardns/upstreams.rules`) containing the rules:

```bash
polardns \
    --direct-dns 223.5.5.5 \
    --proxy-dns https://1.1.1.1/dns-query \
    --group cdn \
    --group-upstream cdn:https://dns-cdn.example/dns-query \
    --upstream-rule /etc/polardns/upstreams.rules
```

#### Upstream Server URL Schemes

Upstreams specified in `--direct-dns`, `--proxy-dns`, and `--group-upstream` support various transport protocols and custom ports:

- **UDP and TCP** (default): `127.0.0.1:53` or `127.0.0.1` (defaults to port 53). Sends queries over UDP first, and automatically falls back to TCP if the UDP response is truncated.
- **UDP Only**: `udp://127.0.0.1:1053` or `udp://127.0.0.1`.
- **TCP Only**: `tcp://127.0.0.1:1053` or `tcp://127.0.0.1`.
- **DNS-over-TLS (DoT)**: `tls://1.1.1.1:853` or `tls://dns.google`.
- **DNS-over-HTTPS (DoH)**: `https://1.1.1.1/dns-query` or `https://dns.google/dns-query`.
- **DNS-over-HTTP/3 (DoH3)**: `h3://1.1.1.1/dns-query` or `h3://dns.google/dns-query` (requires binary built with `quiche` or `upstream-h3` feature).
- **DNS-over-QUIC (DoQ, RFC 9250)**: `doq://dns.adguard-dns.com:853` or `quic://1.1.1.1:853` (defaults to port 853 if port omitted; requires binary built with `quiche` or `original-h3-server` feature).

#### DNL Rule File Syntax

Files referenced by `upstreams.rules` may use Mihomo/Clash provider-domain syntax:

```yaml
payload:
  - example.com          # exact match only
  - '+.example.net'      # example.net and every subdomain
  - '.internal.example'  # subdomains only, not internal.example itself
  - '*.cdn.example'      # provider wildcard, label-aware * and ?
  - 'api?.example.org'
```

Plain `.list` files use the same item syntax, one rule per line:

```text
example.com
+.example.net
.internal.example
*.cdn.example
api?.example.org
```

Classical Clash/Mihomo rule-provider entries are also accepted:

```text
DOMAIN,example.com
DOMAIN-SUFFIX,example.net
DOMAIN-KEYWORD,example
DOMAIN-WILDCARD,*.cdn.example
DOMAIN-REGEX,^(.+\.)?githubusercontent\.com$
```

Classical lines may include a trailing target token such as `,DIRECT` or `,PROXY` for compatibility:

```text
DOMAIN-SUFFIX,example.net,PROXY
```

That trailing token is ignored by `polardns`; routing comes from the tag assigned to the whole file in `upstreams.rules`. This keeps rule priority deterministic across files and rule kinds.

The domain-list files referenced by `upstreams.rules` are hot-reloaded. This is useful when a Mihomo provider file, generated domain list, or adblock list is updated by another process: `polardns` detects the changed file, rebuilds the matcher, and swaps the new DNL cache into service without dropping listeners. Changing the `upstreams.rules` control file itself still requires restarting or reloading the process so the file-to-tag mapping is read again.

### 3. Simultaneous vs Sequential Upstream Querying
- **Sequential (RTT-Sorted Fallback)**: Leverages a high-performance **RTT (Round-Trip Time) State Tracker** to prioritize queries. 
  * **Active Probing**: A background task probes all configured upstreams every 15 seconds using a lightweight `.` (root) NS query. This query is answered directly from the upstream resolver's memory (root hints), measuring pure network + protocol transit times fairly without recursive domain lookup bias.
  * **RTT-Sorted Fallback**: The fallback list is stably sorted by tracked RTT (with randomized tie-breaking for equal latencies), ensuring queries are always routed to the fastest available upstream first.
  * **Fast Fail-Over**: If an upstream fails (connection refused, pool saturated, or timeout), a $+1000\text{ ms}$ penalty (up to a max of $5000\text{ ms}$) is immediately applied to its tracked RTT. This instantly deprioritizes the failing server for subsequent client queries without waiting for the next background probe.
- **Simultaneous (`--proxy-dns-all`, `--direct-dns-all`, `--group-upstream-all`)**: Blasts the query to *all* configured servers in a group at once, accepting the fastest valid response. (Supported aliases: `--trust-dns-all`, `--polar-dns-all`). Pending queries to other upstreams are canceled immediately upon receiving a response.

### 4. Protocol-Aware Multi-Set Management
Resolved IPs can be automatically injected into Linux kernel firewall sets (ipset and nftables) for dynamic routing. `polardns` features a protocol-aware routing engine that automatically maps IPv4/IPv6 results to the correct destination sets.

*   **Mixed Protocol Support**: Mix `ipset` and `nftables` sets for a single tag.
*   **Automatic Family Detection**: Only routes IPv4 addresses to IPv4 sets and IPv6 to IPv6 sets (dual-stack sets receive both).
*   **Native Netlink Implementation**: Zero-dependency interaction with the kernel (no external `ipset` or `nft` binaries required).

**Config Examples:**
```bash
# Mix ipset and nftables for the 'direct' tag
polardns --direct-sets direct_v4,direct_v6,nft:inet:fw4:bypass_set
```

**Supported Formats:**
- **Ipset**: `<set_name>` (e.g., `direct_v4`)
- **Nftables**: `nft:<family>:<table>:<set>` (e.g., `nft:ip6:fw4:blocked_v6`)
  - *Families:* `ip` (IPv4), `ip6` (IPv6), `inet` (Both).

## 🛠️ Build from Source

`polardns` provides **two distinct, mutually exclusive cryptographic, QUIC, and HTTP/3 engine implementations**:
1. **Original Engine (`original` / `rustls-stack`)** [Default]: A 100% Native Pure-Rust stack powered by `rustls`, `ring`, `quinn`, `h3`, and `reqwest`. Zero C dependencies and zero CMake/compiler toolchain requirements.
2. **Quiche Engine (`quiche`)**: An enterprise-grade, high-performance engine powered by Cloudflare's `quiche` (RFC 9000 QUIC, RFC 9114 HTTP/3, and RFC 9250 DoQ), Google `BoringSSL` (`boring` / `tokio-boring`), and native `Hyper 1.x`. Engineered for ultra-low memory footprints (~14 MB RSS on embedded routers) with complete decoupling from Rustls/Ring.

> [!IMPORTANT]
> **Mutual Exclusivity**: The `original` (Rustls) and `quiche` (BoringSSL) engines are strictly mutually exclusive. **Never build with `--all-features`**, as enabling both engines simultaneously causes a compile-time error.

### 📊 Engine Comparison Matrix

| Feature / Component | `original` Engine (Default) | `quiche` Engine |
| :--- | :--- | :--- |
| **TLS / SSL Implementation** | `rustls` (v0.23) + `tokio-rustls` | `boring` (v4.0) + `tokio-boring` (BoringSSL) |
| **Cryptographic Provider** | `ring` (Pure Rust / ASM) | BoringSSL (C-static archive via `boring-sys`) |
| **QUIC & HTTP/3 Server (DoH3)** | `quinn` (v0.11) + `h3` + `h3-quinn` | Cloudflare `quiche` (v0.29) native H3 |
| **Upstream DoH3 Client (`h3://`)** | `reqwest` (requires `--cfg reqwest_unstable`) | Cloudflare `quiche` connection pool (`quiche_client`) |
| **DNS-over-QUIC (DoQ, RFC 9250)** | Local DoQ server listener only | Full DoQ Server Listener + Upstream DoQ Client (`doq://`) |
| **Upstream DoH Client (`https://`)** | `reqwest` (with `rustls-tls`) | Custom `hyper` 1.x `HttpClient` + `tokio-boring` |
| **Policy Routing (`SO_MARK`) on H3/DoQ**| Not supported natively (requires cgroups) | Fully supported via native socket marking in `quiche_pool` |
| **External Build Dependencies** | Standard Rust toolchain only | Rust toolchain, CMake (3.12+), Go, and C/C++ compiler |
| **Embedded Router RAM Footprint** | ~35 MB RSS | **~14 MB RSS** (60% memory reduction) |
| **Default Cargo Profile** | Yes (`default = [...]`) | No (requires `--features quiche`) |

---

### 📦 Install Build Dependencies

#### 1. Rust Toolchain (Required for Both Engines)
`polardns` requires a modern stable Rust toolchain supporting **Rust Edition 2024** (Rust 1.85+).

For official installation instructions and platform-specific guides, see:
- [Official Rust Installation Guide](https://www.rust-lang.org/tools/install)
- [rustup.rs (The Rust toolchain installer)](https://rustup.rs/)

Quick installation via `rustup`:
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

If you already have `rustup` installed, ensure your toolchain is up to date:
```bash
rustup update stable
```

#### 2. System Packages & Build Tools

- **For the Original Engine (`original` / Rustls)**:
  Requires standard C build essentials (for `tikv-jemalloc-sys`):
  - **Debian / Ubuntu**: `sudo apt update && sudo apt install -y build-essential`
  - **RHEL / Fedora / CentOS**: `sudo dnf install -y gcc gcc-c++ make`
  - **Alpine Linux**: `apk add build-base`
  - **macOS**: `xcode-select --install`

- **For the Quiche Engine (`quiche` / BoringSSL)**:
  Because Google BoringSSL is compiled from source via `boring-sys`, the build host additionally requires **CMake** (>= 3.12), **Go** (Golang, for generating assembly code), and **Perl**:
  - **Debian / Ubuntu**:
    ```bash
    sudo apt update && sudo apt install -y build-essential cmake golang perl
    ```
  - **RHEL / Fedora / CentOS**:
    ```bash
    sudo dnf install -y gcc gcc-c++ make cmake golang perl
    ```
  - **Alpine Linux**:
    ```bash
    apk add build-base cmake go perl
    ```
  - **macOS** (Homebrew):
    ```bash
    brew install cmake go perl
    ```

#### 3. Zig & cargo-zigbuild (Optional, for Cross-Compilation & Static MUSL)
For building statically linked musl binaries (e.g., for Alpine Linux or OpenWrt routers) or cross-compiling without complex GCC toolchains, `cargo-zigbuild` and Zig serve as the cross C/C++ compiler and linker.

Official installation and setup references:
- **Zig Compiler**:
  - [Zig Official Downloads & Prebuilt Binaries](https://ziglang.org/download/)
  - [Zig Official Getting Started Guide](https://ziglang.org/learn/getting-started/)
  - Package manager options: `brew install zig` (macOS), `snap install zig --classic` (Ubuntu/Debian), or download tarballs directly from [ziglang.org/download](https://ziglang.org/download/).
- **cargo-zigbuild**:
  - [cargo-zigbuild Repository & Documentation](https://github.com/rust-cross/cargo-zigbuild)
  - Installation:
    ```bash
    cargo install --locked cargo-zigbuild
    ```

---

### Option A: Building the Original Engine (Pure Rust / Rustls)

The `original` engine is enabled by default and compiles with zero external C toolchain dependencies.

#### 1. Standard Release Build (Default)
Builds the binary with `jemalloc`, local DoH3 server listener (`original-h3-server`), and optional TLS 1.2 compatibility:
```bash
cargo build --release
```

#### 2. With Upstream `h3://` Support
Upstream HTTP/3 queries in the `original` stack rely on `reqwest`'s HTTP/3 client, which requires passing the unstable cfg flag:
```bash
RUSTFLAGS="--cfg reqwest_unstable" cargo build --release --features upstream-h3
```

#### 3. Using System Allocator (No Jemalloc)
For small embedded devices without `jemalloc`:
```bash
cargo build --release --no-default-features --features original-h3-server,tls12
```

The output binary is written to:
```text
target/release/polardns
```

---

### Option B: Building the Quiche Engine (BoringSSL / Quiche)

The `quiche` engine integrates Cloudflare's `quiche` and Google BoringSSL for maximal throughput, full DoQ upstream support, socket marking on QUIC, and minimal memory usage on low-end hardware.

#### Build Prerequisites
Ensure the required build dependencies (`cmake`, `golang`, `perl`, and a C/C++ compiler) are installed as shown in the [Install Build Dependencies](#-install-build-dependencies) section above.

#### 1. Standard Quiche Release Build
Build with `jemalloc`, `quiche`, and `tls12`:
```bash
cargo build --release --no-default-features --features jemalloc,quiche,tls12
```

#### 2. Quiche Build with System Allocator
```bash
cargo build --release --no-default-features --features quiche,tls12
```

The output binary is written to:
```text
target/release/polardns
```

---

### 🌐 Cross-Compilation

For cross builds, keep linker configuration local to your machine instead of committing `.cargo/config.toml`:

#### 1. GNU libc Target (`aarch64-unknown-linux-gnu`)

- **Original Engine**:
  ```bash
  rustup target add aarch64-unknown-linux-gnu
  RUSTFLAGS="--cfg reqwest_unstable" \
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu --features upstream-h3
  ```

- **Quiche Engine**:
  ```bash
  rustup target add aarch64-unknown-linux-gnu
  CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --release --target aarch64-unknown-linux-gnu --no-default-features --features jemalloc,quiche,tls12
  ```

#### 2. Musl Static Target (`aarch64-unknown-linux-musl`)
Fully static binaries (ideal for OpenWrt and Alpine) can be built using `cargo-zigbuild`:

- **Original Engine**:
  ```bash
  cargo zigbuild --release --target aarch64-unknown-linux-musl
  ```

- **Quiche Engine**:
  ```bash
  cargo zigbuild --release --target aarch64-unknown-linux-musl --no-default-features --features jemalloc,quiche,tls12
  ```

Cross-build artifacts are written to:
```text
target/<target-triple>/release/polardns
```

## ⚙️ Configuration & Usage

`polardns` supports multiple bind addresses, interfaces, ports, Unix Domain Sockets (UDS), and specific listener endpoints. You can specify them multiple times in the CLI or configuration file.

- **IP Addresses**: Bind to IPv4/IPv6 addresses (e.g. `-b 127.0.0.1 -b ::1`). They will be bound to all ports defined in `--bind-port`.
- **Unix Domain Sockets (UDS)**: Bind to Unix sockets using `unix:/path/to/socket` (for stream/TCP-like queries) or `unixgram:/path/to/socket` (for datagram/UDP-like queries). Sockets bypass ports and will automatically delete/unlink any stale socket file on startup.
- **Specific Listeners**: Bind to specific address and port combinations using `--listen` / `-L` (e.g. `-L 127.0.0.1:1053` or `-L unix:/tmp/dns.sock`). Unlike `-b`, they do not cross-multiply with ports.

```bash
# Listen on both standard loopback and a Unix Domain Socket
polardns -b 127.0.0.1 -b unix:/tmp/dns.sock -l 1054 \
    -c 114.114.114.114 \
    -t https://1.1.1.1/dns-query \
    --upstream-rule /etc/polardns/upstreams.rules
```

### DNS over TLS (DoT) & DNS over HTTPS (DoH) Listeners
`polardns` can serve local clients as a DNS over TLS and DNS over HTTPS server. DoH serves HTTP/1.1 and HTTP/2 by default; HTTP/3 (QUIC) is available as an explicit opt-in. This local encrypted listener is independent from upstream transport selection, so clients can query `polardns` over UDP/TCP/DoT/DoH while `polardns` routes each request to direct, proxy, adblock, or custom upstream groups.

```bash
polardns \
    --enable-dot --dot-port 853 \
    --enable-doh --doh-port 443 --doh-path /dns-query \
    --cert-file /path/to/server.crt \
    --key-file /path/to/server.key
```
- **HTTP/3**: Add `--enable-doh3` to also bind DoH over QUIC on the configured DoH port.
- **Multiple Ports**: `--dot-port` and `--doh-port` can be specified multiple times, aligning with standard listener port logic.
- **Multiple Listener Certificates**: Keep `--cert-file` and `--key-file` as the default certificate, and add repeatable `--cert-pair` entries for SNI-based selection. Inside one pair, use `cert.pem,key.pem`; use a combined PEM path when the file contains both the certificate chain and private key. To put multiple pairs in one value, quote the value and separate pairs with `;`.
```bash
polardns \
    --enable-dot --enable-doh \
    --cert-file /etc/polardns/default.crt \
    --key-file /etc/polardns/default.key \
    --cert-pair /etc/polardns/dns-example.crt,/etc/polardns/dns-example.key \
    --cert-pair /etc/polardns/combined-anycast.pem \
    --cert-pair '/etc/polardns/alt.crt,/etc/polardns/alt.key;/etc/polardns/combined-alt.pem'
```
  Certificate DNS SANs are extracted automatically, with CN used only as a fallback when no DNS SAN is present. Exact SANs and single-label wildcards such as `*.example.com` are used for SNI matching. If the client sends no matching SNI, the default `--cert-file/--key-file` certificate is used; if no default pair is configured, the first `--cert-pair` entry is used as the fallback.
- **Strict SNI**: Add `--strict-sni` to reject local TLS handshakes that do not send a DNS SNI name matching any configured certificate SAN/CN. This is useful for public multi-domain listeners, but IP-only clients that cannot send SNI will fail.
- **TLS Versions**: Local DoT/DoH TCP listeners are TLS 1.3-only by default. If the binary is built with `--features tls12`, add `--enable-tls12` to allow TLS 1.2 as well. DoH3 always uses TLS 1.3 because HTTP/3 runs over QUIC.
- **SSL Certificate Verification**: By default, SSL certificate verification for encrypted upstreams (DoT/DoH/DoH3) is disabled, meaning self-signed or unverified certificates are accepted (useful for private/testing upstreams). To enable validation, pass `--cert-verify`.
- **Custom Upstream Authorities**: When `--cert-verify` is enabled, the daemon validates certificates against the system's root certificates. To validate against a specific root CA bundle globally, add `--ca-certs /path/to/ca.pem`. To bind a different CA to only one encrypted upstream, append `|ca=/path/to/ca.pem` to that upstream. `h3://` upstreams require a binary built with `--features quiche` or `RUSTFLAGS="--cfg reqwest_unstable" --features upstream-h3`:
```bash
polardns \
    --cert-verify \
    --proxy-dns 'tls://dns1.example.com:853|ca=/etc/polardns/ca-dns1.pem,https://dns2.example.com/dns-query|ca=/etc/polardns/ca-dns2.pem,h3://dns3.example.com/dns-query|ca=/etc/polardns/ca-dns3.pem'
```
  Per-upstream `ca=` is supported on `tls://`, `https://`, and `h3://` upstreams. It implies strict verification for that upstream and uses only the specified CA bundle. Quote CLI values containing `|` so the shell does not treat it as a pipe.
- **Bind Port Aliases**: The standard listener port flag `--bind-port` now supports `--dns-port` as a more descriptive alias.

### HTTP/3 Memory Profiles & Low-Memory Tuning
When compiled with feature `quiche`, `polardns` includes a high-performance HTTP/3 engine with zero-allocation packet recycling pools and automatic memory scaling via `--h3-profile`:

| Profile | CLI Flag / Config Option | Target Environment | Flow Window (Conn / Stream) | Target Total RSS |
| :--- | :--- | :--- | :--- | :--- |
| **`low`** | `--h3-profile low` or `--h3-low-memory` | OpenWrt / Embedded (32MB–64MB RAM) | 256 KB / 16 KB | **< 2 MB** |
| **`balanced`** | `--h3-profile balanced` (Default) | Home Routers / NAS / VPS (128MB+ RAM) | 1 MB / 64 KB | ~5–10 MB |
| **`high`** | `--h3-profile high` | Dedicated Cloud Servers (512MB+ RAM) | 8 MB / 256 KB | High Throughput |

```bash
# OpenWrt low-memory mode example (<2MB RSS total memory)
polardns --h3-low-memory --proxy-dns h3://1.1.1.1/dns-query ...
```
- **Bootstrap Resolver**: `--fallback-dns` is used only to resolve hostnames inside DoT/DoH upstream URLs. Keep it non-recursive: use an IP literal, `udp://IP`, or `tcp://IP`, not another hostname-based DoT/DoH resolver.

### TOML / YAML Configuration (Default & Recommended)
`polardns` uses TOML as its primary and default configuration format (YAML is also natively supported). The format is auto-detected based on the file extension (`.toml`, `.yaml`, `.yml`).

To run with a TOML/YAML config:
```bash
polardns -C /etc/polardns/config.toml
polardns --config /etc/polardns/config.yaml
```

A comprehensive, deployment-oriented reference configuration is available at [`examples/config.toml`](examples/config.toml) (YAML equivalent at [`examples/config.yaml`](examples/config.yaml)). A matching non-root systemd service sample is available at [`examples/polardns.service`](examples/polardns.service).

### Legacy Configuration Format (Deprecated)
The legacy line-based `.conf` configuration files continue to be supported as a fallback:

**Config file example (`/etc/polardns/config.conf`):**
```conf
# Standard format
bind-addr 0.0.0.0
bind-addr ::

# '=' format with whitespace around is also supported
interface = lo

# Comma-separated values are supported for list fields
bind-port 1054,65353

# Listen only on UDP (disables the default TCP listener)
udp-only
```

Legacy config sample is available at [`examples/config.conf`](examples/config.conf). The systemd service assumes the binary is installed at `/usr/local/bin/polardns`; adjust `ExecStart=` if your install path differs. It grants `CAP_NET_BIND_SERVICE` for low ports, `CAP_NET_ADMIN` for ipset/nft set sync, and `CAP_NET_RAW` for device interface binding (`SO_BINDTODEVICE`); remove `CAP_NET_ADMIN` or `CAP_NET_RAW` if not using these features.

If you run the binary directly under a non-privileged user without systemd, you can grant the necessary capabilities to the binary using `setcap`:

```bash
sudo setcap 'cap_net_bind_service,cap_net_admin=+ep' /usr/local/bin/polardns
```

Typical service deployment layout:

```bash
install -Dm755 target/release/polardns /usr/local/bin/polardns
# Optional: set capabilities directly on the binary if not running via systemd service
sudo setcap 'cap_net_bind_service,cap_net_admin=+ep' /usr/local/bin/polardns

install -Dm644 examples/config.toml /etc/polardns/config.toml
install -Dm644 examples/upstreams.rules /etc/polardns/upstreams.rules
install -Dm644 examples/polardns.service /etc/systemd/system/polardns.service
```

When copying `examples/upstreams.rules` into `/etc/polardns`, update its DNL file paths to point at your real rule files, preferably with absolute paths.

### Notable Features
- **Efficient DNL Matching**: Uses hash indexes for exact domains, a compact reversed-label trie for suffix rules, and linear byte glob matching for Mihomo wildcards. Explicit `DOMAIN-REGEX` remains regex-backed.
- **Rule-Based DNL Routing**: `--upstream-rule` maps multiple Clash/Mihomo-style DNL files to upstream tags, including custom groups. First-match priority is preserved globally across exact, suffix, wildcard, keyword, and regex rules.
- **DNL Hot Reload**: Domain-list files referenced by `upstreams.rules` are monitored and hot-swapped into the running matcher after changes, avoiding daemon restarts for routine provider/list updates.
- **Local DoT/DoH/DoQ Server**: Serves local encrypted DNS clients over DoT, DoH, DoH3, and DoQ, with HTTP/1.1+HTTP/2 DoH enabled by `--enable-doh`, DoH3 via `--enable-doh3`, and DoQ (RFC 9250) via `--enable-doq` and `--doq-port`.
- **Millisecond Timeouts & Intervals**: High-precision control with `--timeout-ms` (defaults to 1000ms), `--queue-timeout-ms` (defaults to 2000ms for query queue saturation shed), `--rtt-probe-interval` (defaults to 15s, 0 to disable), and `--rtt-probe-timeout-ms` (defaults to 2000ms).
- **TCP & UDP Dual-Stack**: Listens on both UDP and TCP by default for all addresses/interfaces (use `--udp-only` to disable TCP).
- **Interface Binding**: Directly bind to network interfaces via `--interface` (e.g., `-i lo,eth0`) or specify independent interfaces and bind addresses for encrypted DNS listeners via `--tls-interface` and `--tls-bind-addr`. Disable binding to IPv6 Link-Local addresses globally with `--no-ipv6-link-local` or for TLS listeners only with `--no-tls-ipv6-link-local`.
- **Adaptive Socket & Network Event Watcher**: Real-time event-driven tracking of kernel network interface state changes, link UP/DOWN transitions, and IP address assignment via kernel Netlink (`NETLINK_ROUTE`), macOS BSD route sockets (`PF_ROUTE`), and Windows IP Helper notifications. Features automatic 200ms grace debouncing, exponential port recovery backoff (`EADDRINUSE`), IPv6 DAD checks, and zero-downtime socket handoff.
- **Flexible Config**: Configuration files support `key value`, `key=value`, and comma-separated lists for maximum compatibility.
- **Compact Memory**: Keeps common exact and `+.` suffix rules in compact indexes, uses inline storage for single-rule buckets, and avoids regex expansion for wildcard rules.
- **Granular DNS Caching**: `--cache`, `--cache-min-ttl`, `--cache-max-ttl`, `--cache-cleanup-interval`, and persistence via `--cache-db`. Features adaptive memory management (Smart Shrink) to release RAM back to the OS during periods of low usage.
- **UDP Memory Control**: `--socket-buffer-size` controls per-socket UDP send/receive buffers. The default is 1 MiB; set it higher for very high packet-rate deployments or `0` to leave OS defaults.
- **Linux Routing**: Directly syncs DNS resolutions to `ipset`/`nftables` via `--direct-sets` and `--proxy-sets` (with aliases `--polar-sets`, `--chn-sets`, and `--gfw-sets`).
- **Local Overrides**: Support for multiple IPs per domain in hosts and CLI records.
- **TLS Security**: Full DoT/DoH support with optional strict cert validation (`--cert-verify`).
- **Slowloris & Rate Limit Protection**: Defends against slow-client attacks using socket read timeout limits (`--tcp-idle-timeout-ms`, default 10s), queue permit wait timeout (`--queue-timeout-ms`, default 2000ms), and global query queueing limits (`--max-concurrent-queries`, default 1000).
- **Embedded & Low-End Device Tuning**: Explicit worker thread tuning via `--worker-threads` (or `--threads`) and thread stack size via `--thread-stack-size` (default: 512 KiB vs OS default 8 MiB), drastically reducing memory on small routers (32MB–128MB RAM). Zero-allocation domain parsing and background jemalloc purging release inactive memory back to the kernel.
- **Upstream Resilience**: Integrates per-upstream connection limits (`--max-upstream-conns`, default 16) with a fail-fast design that bypasses saturated servers immediately, using socket TCP Keepalive probes (60s idle, 10s interval) to prune dead upstream connections dynamically. Features an active-probing **RTT State Tracker** to dynamically prioritize and route traffic to the lowest-latency upstreams.
- **Match Tracing**: Supports high-performance asynchronous tracing via `--log-dns-match <log file>`. Matches are logged asynchronously (e.g. `domain,tag_name`) to a buffered background writer to avoid blocking the hot query resolution path.

*(You can run `polardns --help` to see all options parsed and validated natively.)*

## 🔀 Policy Routing & Socket Marking (SO_MARK)

`polardns` supports setting socket marks (`SO_MARK`) on outgoing sockets to enable policy-based routing on Linux:

- **Global Mark**: Use `--out-mark <mark>` (or `out-mark <mark>` in the config) to apply a socket mark to all outgoing UDP, TCP, and DoT queries.
- **Per-Upstream Mark**: Append `|mark=<mark>` directly to upstream server definitions to route queries for specific servers differently (e.g. `direct-dns 223.5.5.5|mark=100`, `proxy-dns tls://1.1.1.1:853|mark=200`).

### DoH/DoH3 Client Limitations & Cgroups Workaround

> [!NOTE]
> Under the **Quiche engine** (`--features quiche`), socket marks (`|mark=<mark>`) are natively supported on QUIC/DoH3 (`h3://`) and DoQ (`doq://`) upstreams directly via native UDP socket marking. Under the **Original engine** (`reqwest`), HTTP socket creation is abstracted, so programmatic socket marking cannot be applied directly to DoH/DoH3 queries.

Because the internal HTTP client library (`reqwest`) in the Original engine handles socket creation and connection pooling at a high abstraction level, programmatic socket marking (`|mark=val`) cannot be applied to DoH (`https://`) and DoH3 (`h3://`) upstreams.

To mark and route all outbound DoH/DoH3 queries, you can run `polardns` inside a dedicated Linux **cgroup** and use `nftables`/`iptables` to apply marks on all packets originating from that cgroup.

**Example using nftables:**
```bash
# 1. Start the service inside the 'polardns' cgroup
systemd-run --slice=polardns.slice ./target/debug/polardns ...

# 2. Add an nftables rule to mark all packets from that cgroup
nft add rule ip filter output socket cgroup "polardns" meta mark set 100
```

## ⚖️ License
Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See the [LICENSE](LICENSE) file for the full license text.
