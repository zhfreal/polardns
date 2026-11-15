#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use std::pin::Pin;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use std::task::{Context, Poll};
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use std::time::Duration;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use bytes::Bytes;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use http_body_util::{BodyExt, Full, Limited};
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use hyper_util::client::legacy::Client as HyperClient;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use tower_service::Service;

pub const DEFAULT_USER_AGENT: &str = concat!("chinadns-rs/", env!("CARGO_PKG_VERSION"));
pub const MAX_DOH_RESPONSE_SIZE: u64 = 64 * 1024;        // 64 KiB
pub const MAX_RULE_DOWNLOAD_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub const HTTP_TCP_KEEPALIVE_TIME: Duration = Duration::from_secs(30);
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub const HTTP_TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
pub struct BoringStream {
    pub io: TokioIo<tokio_boring::SslStream<tokio::net::TcpStream>>,
    pub is_h2: bool,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl hyper::rt::Read for BoringStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl hyper::rt::Write for BoringStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl Connection for BoringStream {
    fn connected(&self) -> Connected {
        let connected = Connected::new();
        if self.is_h2 {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
#[derive(Clone)]
pub struct BoringConnector {
    http: HttpConnector,
    connector: boring::ssl::SslConnector,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl BoringConnector {
    pub fn new(ssl_connector: boring::ssl::SslConnector) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        Self { http, connector: ssl_connector }
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
#[derive(Clone)]
pub struct HttpClient {
    inner: HyperClient<BoringConnector, Full<Bytes>>,
    timeout: Duration,
    user_agent: String,
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
fn get_proxy_from_env(uri: &http::Uri) -> Option<http::Uri> {
    let scheme = uri.scheme_str().unwrap_or("http");
    if scheme == "https" {
        std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok()
            .and_then(|s| s.parse::<http::Uri>().ok())
    } else {
        std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok()
            .and_then(|s| s.parse::<http::Uri>().ok())
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl Service<http::Uri> for BoringConnector {
    type Response = BoringStream;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(|e| e.into())
    }

    fn call(&mut self, req: http::Uri) -> Self::Future {
        let mut http = self.http.clone();
        let connector = self.connector.clone();
        Box::pin(async move {
            let host = req.host().ok_or_else(|| anyhow::anyhow!("missing host in URI"))?.to_string();
            
            // Handle HTTP CONNECT proxy tunneling if a proxy is configured in the environment
            let proxy_uri = get_proxy_from_env(&req);
            let tcp_stream = if let Some(ref proxy) = proxy_uri {
                let proxy_host = proxy.host().ok_or_else(|| anyhow::anyhow!("missing host in proxy URI"))?;
                let proxy_port = proxy.port_u16().unwrap_or(80);
                let connect_uri = http::Uri::builder()
                    .scheme(proxy.scheme_str().unwrap_or("http"))
                    .authority(format!("{}:{}", proxy_host, proxy_port))
                    .path_and_query("/")
                    .build()?;
                let io_stream = http.call(connect_uri).await.map_err(|e| anyhow::anyhow!("TCP connect to proxy failed: {}", e))?;
                let mut stream = io_stream.into_inner();
                
                let port = req.port_u16().unwrap_or(443);
                let connect_req = format!(
                    "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
                    host, port, host, port
                );
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream.write_all(connect_req.as_bytes()).await?;
                stream.flush().await?;
                
                let mut resp_buf = [0u8; 4096];
                let mut pos = 0;
                while pos < resp_buf.len() {
                    let n = stream.read(&mut resp_buf[pos..]).await?;
                    if n == 0 {
                        anyhow::bail!("Proxy closed connection unexpectedly during CONNECT handshake");
                    }
                    pos += n;
                    if resp_buf[..pos].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                
                let resp_str = String::from_utf8_lossy(&resp_buf[..pos]);
                if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
                    anyhow::bail!("Proxy CONNECT handshake failed: {}", resp_str.split("\r\n").next().unwrap_or(""));
                }
                stream
            } else {
                http.call(req).await.map_err(|e| anyhow::anyhow!("TCP connect failed: {}", e))?.into_inner()
            };

            let _ = tcp_stream.set_nodelay(true);
            
            // Enable TCP keep-alive on outgoing socket
            let sock_ref = socket2::SockRef::from(&tcp_stream);
            let mut keepalive = socket2::TcpKeepalive::new();
            keepalive = keepalive.with_time(HTTP_TCP_KEEPALIVE_TIME);
            keepalive = keepalive.with_interval(HTTP_TCP_KEEPALIVE_INTERVAL);
            let _ = sock_ref.set_tcp_keepalive(&keepalive);

            let clean_host = host.trim_matches('[').trim_matches(']');
            let ssl_stream = if let Ok(ip) = clean_host.parse::<std::net::IpAddr>() {
                let mut ssl_config = connector.configure()?;
                ssl_config.param_mut().set_ip(ip)?;
                ssl_config.set_use_server_name_indication(false);
                let ssl_stream_fut = tokio_boring::connect(ssl_config, "", tcp_stream);
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, ssl_stream_fut)
                    .await
                    .map_err(|_| anyhow::anyhow!("BoringSSL TLS handshake timed out"))?
            } else {
                let domain_host = host.trim_end_matches('.');
                let ascii_host = idna::domain_to_ascii(domain_host).unwrap_or_else(|_| domain_host.to_string());
                let mut ssl_config = connector.configure()?;
                ssl_config.set_hostname(&ascii_host)?;
                let ssl_stream_fut = tokio_boring::connect(ssl_config, &ascii_host, tcp_stream);
                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, ssl_stream_fut)
                    .await
                    .map_err(|_| anyhow::anyhow!("BoringSSL TLS handshake timed out"))?
            }.map_err(|e| {
                let _ = boring::error::ErrorStack::get();
                anyhow::anyhow!("BoringSSL handshake failed: {}", e)
            })?;
                
            let is_h2 = ssl_stream.ssl().selected_alpn_protocol() == Some(b"h2");
            Ok(BoringStream {
                io: TokioIo::new(ssl_stream),
                is_h2,
            })
        })
    }
}

pub fn format_http_host_header(uri: &http::Uri) -> anyhow::Result<String> {
    let host = uri.host().ok_or_else(|| anyhow::anyhow!("URI missing host"))?;
    let formatted_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };

    match uri.port_u16() {
        Some(port) if port != 80 && port != 443 => Ok(format!("{}:{}", formatted_host, port)),
        _ => Ok(formatted_host),
    }
}

#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
impl HttpClient {
    pub fn new(timeout: Duration, cert_verify: bool, ca_path: Option<&str>, user_agent: String) -> anyhow::Result<Self> {
        let mut ssl_builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
        ssl_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
        if !cert_verify {
            ssl_builder.set_verify(boring::ssl::SslVerifyMode::NONE);
        } else if let Some(path) = ca_path {
            ssl_builder.set_ca_file(path)?;
        } else {
            crate::upstream::configure_ca_store_with_fallbacks(&mut ssl_builder)?;
        }
        let connector = BoringConnector::new(ssl_builder.build());
        let client = HyperClient::builder(TokioExecutor::new())
            .http2_initial_stream_window_size(1024 * 1024)
            .http2_initial_connection_window_size(2 * 1024 * 1024)
            .http2_adaptive_window(true)
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8) // RAM optimization for embedded routers
            .build(connector);
        Ok(Self { inner: client, timeout, user_agent })
    }

    pub async fn get(&self, url: &str) -> anyhow::Result<Bytes> {
        let uri: http::Uri = url.parse()?;
        let host_header = format_http_host_header(&uri)?;
        let req = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("host", &host_header)
            .header("user-agent", &self.user_agent)
            .body(Full::new(Bytes::new()))?;

        let resp = tokio::time::timeout(self.timeout, self.inner.request(req)).await??;
        if !resp.status().is_success() {
            anyhow::bail!("GET request failed: HTTP {}", resp.status());
        }
        let limited = Limited::new(resp.into_body(), MAX_RULE_DOWNLOAD_SIZE as usize);
        let response_bytes = limited.collect().await.map_err(|_| anyhow::anyhow!("Download size exceeded limit"))?.to_bytes();
        Ok(response_bytes)
    }

    pub async fn get_to_file(&self, url: &str, file_path: &str) -> anyhow::Result<()> {
        use http_body_util::BodyExt;
        use tokio::io::AsyncWriteExt;
        let uri: http::Uri = url.parse()?;
        let host_header = format_http_host_header(&uri)?;
        let req = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("host", &host_header)
            .header("user-agent", &self.user_agent)
            .body(Full::new(Bytes::new()))?;

        let resp = tokio::time::timeout(self.timeout, self.inner.request(req)).await??;
        if !resp.status().is_success() {
            anyhow::bail!("GET request failed: HTTP {}", resp.status());
        }
        let mut file = tokio::fs::File::create(file_path).await?;
        let mut body = resp.into_body();
        let mut downloaded: usize = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(chunk) = frame.data_ref() {
                downloaded += chunk.len();
                if downloaded > MAX_RULE_DOWNLOAD_SIZE as usize {
                    anyhow::bail!("Download size exceeded limit");
                }
                file.write_all(chunk).await?;
            }
        }
        file.flush().await?;
        Ok(())
    }

    pub async fn post_dns_wire(&self, url: &str, body: Bytes) -> anyhow::Result<Bytes> {
        if body.len() < 2 {
            anyhow::bail!("DNS query payload is too short for transaction ID validation");
        }
        let uri: http::Uri = url.parse()?;
        let host_header = format_http_host_header(&uri)?;
        let mut retries = 0;
        loop {
            let req = http::Request::builder()
                .method("POST")
                .uri(url)
                .header("host", &host_header)
                .header("user-agent", &self.user_agent)
                .header("content-type", "application/dns-message")
                .header("accept", "application/dns-message")
                .header("content-length", body.len().to_string())
                .body(Full::new(body.clone()))?;
                
            match tokio::time::timeout(self.timeout, self.inner.request(req)).await {
                Ok(Ok(resp)) => {
                    if !resp.status().is_success() {
                        anyhow::bail!("DoH POST query failed with HTTP status: {}", resp.status());
                    }
                    if let Some(ct) = resp.headers().get("content-type") {
                        if !ct.to_str().unwrap_or("").starts_with("application/dns-message") {
                            anyhow::bail!("invalid DoH response content-type: {:?}", ct);
                        }
                    }
                    let limited = Limited::new(resp.into_body(), MAX_DOH_RESPONSE_SIZE as usize);
                    let response_bytes = limited.collect().await.map_err(|_| anyhow::anyhow!("DoH response body exceeded limit"))?.to_bytes();

                    if response_bytes.len() < 2 {
                        anyhow::bail!("DNS response payload is too short for transaction ID validation");
                    }

                    // Transaction ID validation
                    let req_txid = u16::from_be_bytes([body[0], body[1]]);
                    let resp_txid = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
                    if req_txid != resp_txid {
                        anyhow::bail!("DNS Transaction ID mismatch");
                    }

                    return Ok(response_bytes);
                }
                Ok(Err(_e)) if retries < 1 => {
                    retries += 1;
                    continue;
                }
                Ok(Err(e)) => anyhow::bail!("DoH POST query failed: {}", e),
                Err(_) => anyhow::bail!("DoH POST query timed out"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    #[tokio::test]
    async fn test_http_client_new() {
        let client = HttpClient::new(Duration::from_secs(5), false, None, DEFAULT_USER_AGENT.to_string());
        assert!(client.is_ok());
    }

    #[test]
    fn test_format_http_host_header() {
        assert_eq!(format_http_host_header(&"http://example.com".parse().unwrap()).unwrap(), "example.com");
        assert_eq!(format_http_host_header(&"https://127.0.0.1:853".parse().unwrap()).unwrap(), "127.0.0.1:853");
        assert_eq!(format_http_host_header(&"https://[::1]:853".parse().unwrap()).unwrap(), "[::1]:853");
    }
}
