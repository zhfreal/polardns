use std::time::Duration;
use tracing::{info, warn, error};
use crate::config::WebRule;

#[cfg(feature = "rustls-stack")]
use reqwest::Client;
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
use crate::http_client::HttpClient as Client;

struct TempFileGuard {
    path: String,
    active: bool,
}

impl TempFileGuard {
    fn new(path: String) -> Self {
        Self { path, active: true }
    }
    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn atomic_replace(tmp_path: &str, path: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        let mut last_err = None;
        for i in 0..5 {
            match std::fs::rename(tmp_path, path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(50 * (1 << i))).await;
                }
            }
        }
        // Fallback: copy over target and remove temp file
        if std::fs::copy(tmp_path, path).is_ok() {
            let _ = std::fs::remove_file(tmp_path);
            return Ok(());
        }
        Err(last_err.map(|e| e.to_string()).unwrap_or_else(|| "rename failed".to_string()))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::fs::rename(tmp_path, path).map_err(|e| e.to_string())
    }
}

/// Fetch a single rule URL and write atomically to path using a temp file.
#[cfg(feature = "rustls-stack")]
async fn fetch_rule(client: &Client, url: &str, path: &str) -> Result<(), String> {
    use futures::StreamExt;
    use std::io::Write;
    let res = client.get(url).send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("HTTP status {}", res.status()));
    }
    
    let tmp_path = format!("{}.tmp", path);
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    let mut guard = TempFileGuard::new(tmp_path.clone());
    let mut file = std::fs::File::create(&tmp_path).map_err(|e| e.to_string())?;
    
    let mut stream = res.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| e.to_string())?;
        file.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    file.flush().map_err(|e| e.to_string())?;
    drop(file);
    
    atomic_replace(&tmp_path, path).await?;
    guard.disarm();
    Ok(())
}

/// Fetch a single rule URL and write atomically to path using a temp file.
#[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
async fn fetch_rule(client: &Client, url: &str, path: &str) -> Result<(), String> {
    let tmp_path = format!("{}.tmp", path);
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    
    let mut guard = TempFileGuard::new(tmp_path.clone());
    client.get_to_file(url, &tmp_path).await.map_err(|e| e.to_string())?;
    
    atomic_replace(&tmp_path, path).await?;
    guard.disarm();
    Ok(())
}

/// Initialize web rules. Performs initial fetch if file is missing or stale, then spawns background tasks.
pub async fn init_and_spawn(rules: Vec<WebRule>, user_agent: &str) {
    if rules.is_empty() {
        return;
    }

    #[cfg(feature = "rustls-stack")]
    let client = Client::builder()
        .user_agent(user_agent)
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default();

    #[cfg(all(feature = "boring", not(feature = "rustls-stack")))]
    let client = Client::new(Duration::from_secs(30), true, None, user_agent.to_string())
        .map_err(|e| e.to_string())
        .unwrap();

    for rule in &rules {
        let path_exists = std::path::Path::new(&rule.path).exists();
        
        let should_fetch = if !path_exists {
            true
        } else {
            if let Ok(metadata) = std::fs::metadata(&rule.path) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        elapsed.as_secs() >= rule.refresh
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        };

        if should_fetch {
            info!("Fetching initial/stale rule file from '{}' to '{}'...", rule.url, rule.path);
            if let Err(e) = fetch_rule(&client, &rule.url, &rule.path).await {
                if !path_exists {
                    error!(
                        "Failed to fetch initial rules from '{}': {}. Creating an empty rule file to allow startup.",
                        rule.url, e
                    );
                    if let Some(parent) = std::path::Path::new(&rule.path).parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    let _ = std::fs::write(&rule.path, b"");
                } else {
                    warn!(
                        "Failed to fetch fresh rules from '{}': {}. Falling back to cached local rules.",
                        rule.url, e
                    );
                }
            }
        }
    }

    // Spawn background tasks for periodic refreshes
    for rule in rules {
        let client = client.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(rule.refresh));
            // Skip immediate tick because we already executed startup fetch
            interval.tick().await;

            loop {
                interval.tick().await;
                info!("Scheduled background refresh of rule from '{}' to '{}'", rule.url, rule.path);
                if let Err(e) = fetch_rule(&client, &rule.url, &rule.path).await {
                    error!("Failed to refresh rules from '{}': {}", rule.url, e);
                } else {
                    info!("Successfully refreshed rules from '{}'", rule.url);
                }
            }
        });
    }
}
