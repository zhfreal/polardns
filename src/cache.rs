use compact_str::CompactString;
use rustc_hash::FxHashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::info;

pub const SHARD_CLEANUP_WARN_THRESHOLD: Duration = Duration::from_millis(5);
pub const CACHE_SHRINK_MIN_CAPACITY: usize = 64;
pub const CACHE_SHRINK_TRIGGER_CAPACITY: usize = 32;

pub enum CacheStatus {
    Hit { data: Arc<[u8]>, elapsed: u32 },
    Stale { data: Arc<[u8]>, original_ttl: u32 },
    Refresh { data: Arc<[u8]>, elapsed: u32 },
    Miss,
}

pub struct CleanupStats {
    pub total_removed: usize,
    pub total_active: usize,
    pub duration_us: u128,
}

pub struct CacheEntry {
    pub data: Arc<[u8]>,
    pub expires_at: Instant,
    pub original_ttl: u32,
}

struct CacheShard {
    entries: RwLock<FxHashMap<CompactString, CacheEntry>>,
}

pub struct DnsCache {
    shards: Vec<CacheShard>,
    shard_mask: usize,
    max_size: usize,
    shard_max_size: usize,
    stale_sec: i32,
    refresh_pct: Option<u8>,
    pub hits: AtomicUsize,
    pub misses: AtomicUsize,
}

impl DnsCache {
    pub fn new(max_size: usize, stale_sec: i32, refresh_pct: Option<u8>) -> Self {
        let num_shards = if max_size > 0 && max_size < 64 {
            max_size.next_power_of_two().clamp(1, 64)
        } else {
            64
        };
        let shard_mask = num_shards - 1;
        let mut shards = Vec::with_capacity(num_shards);
        let shard_max_size = if max_size > 0 {
            max_size.div_ceil(num_shards)
        } else {
            0
        };

        for _ in 0..num_shards {
            let mut map = FxHashMap::default();
            if shard_max_size > 0 {
                map.reserve(shard_max_size.min(256));
            }
            shards.push(CacheShard {
                entries: RwLock::new(map),
            });
        }

        Self {
            shards,
            shard_mask,
            max_size,
            shard_max_size,
            stale_sec,
            refresh_pct,
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
        }
    }

    fn get_shard_index(&self, key: &str) -> usize {
        let mut s = rustc_hash::FxHasher::default();
        key.hash(&mut s);
        (s.finish() as usize) & self.shard_mask
    }

    pub fn get(&self, key: &str) -> CacheStatus {
        let now = Instant::now();
        let idx = self.get_shard_index(key);
        let shard = &self.shards[idx];

        let entries = shard.entries.read().unwrap_or_else(|poison_err| {
            tracing::warn!("Cache shard read lock was poisoned during get. Recovering.");
            poison_err.into_inner()
        });
        if let Some(entry) = entries.get(key) {
            let inserted_at = entry
                .expires_at
                .checked_sub(Duration::from_secs(entry.original_ttl as u64))
                .unwrap_or(entry.expires_at);
            let elapsed = if now > inserted_at {
                now.duration_since(inserted_at).as_secs() as u32
            } else {
                0
            };
            if entry.expires_at > now {
                let data = entry.data.clone();
                self.hits.fetch_add(1, Ordering::Relaxed);
                if elapsed > 0
                    && let Some(pct) = self.refresh_pct
                    && elapsed * 100 > entry.original_ttl * (pct as u32)
                {
                    return CacheStatus::Refresh { data, elapsed };
                }
                return CacheStatus::Hit { data, elapsed };
            } else if self.stale_sec > 0 {
                let stale_until = entry.expires_at + Duration::from_secs(self.stale_sec as u64);
                if stale_until > now {
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return CacheStatus::Stale {
                        data: entry.data.clone(),
                        original_ttl: entry.original_ttl,
                    };
                }
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        CacheStatus::Miss
    }

    pub fn insert(&self, key: &str, data: Arc<[u8]>, ttl: u32) {
        if self.max_size == 0 {
            return;
        }

        let now = Instant::now();
        let expires_at = now + Duration::from_secs(ttl as u64);

        let idx = self.get_shard_index(key);
        let shard = &self.shards[idx];
        let mut entries = shard.entries.write().unwrap_or_else(|poison_err| {
            tracing::warn!("Cache shard write lock was poisoned during insert. Recovering.");
            poison_err.into_inner()
        });

        if entries.len() >= self.shard_max_size && !entries.contains_key(key) {
            Self::evict(&mut entries, self.shard_max_size, now, self.stale_sec);
        }

        entries.insert(
            CompactString::new(key),
            CacheEntry {
                data,
                expires_at,
                original_ttl: ttl,
            },
        );
    }

    fn evict(entries: &mut FxHashMap<CompactString, CacheEntry>, max_size: usize, now: Instant, stale_sec: i32) {
        entries.retain(|_, entry| {
            let stale_until = if stale_sec > 0 {
                entry.expires_at + Duration::from_secs(stale_sec as u64)
            } else {
                entry.expires_at
            };
            stale_until > now
        });

        if entries.len() >= max_size {
            let target = max_size * 3 / 4;
            let to_remove = entries.len().saturating_sub(target);
            if to_remove > 0 {
                let mut items: Vec<(&CompactString, Instant)> = entries
                    .iter()
                    .map(|(k, v)| {
                        let stale_until = if stale_sec > 0 {
                            v.expires_at + Duration::from_secs(stale_sec as u64)
                        } else {
                            v.expires_at
                        };
                        (k, stale_until)
                    })
                    .collect();
                items.select_nth_unstable_by_key(to_remove - 1, |item| item.1);
                let keys_to_remove: Vec<CompactString> = items[..to_remove]
                    .iter()
                    .map(|(k, _)| (*k).clone())
                    .collect();
                for k in keys_to_remove {
                    entries.remove(&k);
                }
            }
        }

        let current_len = entries.len();
        let current_cap = entries.capacity();
        if current_len == 0 && current_cap > 0 {
            entries.shrink_to(0);
        } else if current_cap > current_len * 2 && current_cap > CACHE_SHRINK_MIN_CAPACITY {
            let target_capacity = (current_len + current_len / 4).max(CACHE_SHRINK_TRIGGER_CAPACITY);
            entries.shrink_to(target_capacity);
        }
    }

    pub fn cleanup(&self) -> CleanupStats {
        let start_time = Instant::now();
        let now = Instant::now();
        let mut total_removed = 0;
        let mut total_active = 0;

        for (i, shard) in self.shards.iter().enumerate() {
            let shard_start = Instant::now();
            let (has_expired, active_count) = {
                let entries = match shard.entries.read() {
                    Ok(e) => e,
                    Err(poison_err) => {
                        tracing::warn!(
                            "Cache shard read lock was poisoned during cleanup. Recovering."
                        );
                        poison_err.into_inner()
                    }
                };
                if entries.is_empty() {
                    continue;
                }
                let expired = entries.values().any(|entry| {
                    let stale_until = if self.stale_sec > 0 {
                        entry.expires_at + Duration::from_secs(self.stale_sec as u64)
                    } else {
                        entry.expires_at
                    };
                    stale_until <= now
                });
                (expired, entries.len())
            };

            if has_expired {
                let mut entries = match shard.entries.write() {
                    Ok(e) => e,
                    Err(poison_err) => poison_err.into_inner(),
                };
                let prev_len = entries.len();
                Self::evict(&mut entries, usize::MAX, now, self.stale_sec);
                let removed = prev_len - entries.len();
                total_removed += removed;
                total_active += entries.len();
                let shard_dur = shard_start.elapsed();
                if shard_dur > SHARD_CLEANUP_WARN_THRESHOLD {
                    tracing::debug!(
                        "Cache cleanup on shard {} took {:?}",
                        i,
                        shard_dur
                    );
                }
            } else {
                total_active += active_count;
            }
        }

        #[cfg(feature = "jemalloc")]
        if total_removed > 0 {
            crate::utils::purge_jemalloc();
        }

        CleanupStats {
            total_removed,
            total_active,
            duration_us: start_time.elapsed().as_micros(),
        }
    }

    pub fn load_from_db(&self, path: &str) {
        if self.max_size == 0 {
            return;
        }

        use std::io::Read;
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(_) => return, // If file doesn't exist, just return silently
        };
        let mut file = std::io::BufReader::new(file);

        let mut magic = [0u8; 8];
        if file.read_exact(&mut magic).is_err() || &magic != b"CDNSCACH" {
            tracing::warn!("Invalid cache database magic bytes in '{}'", path);
            return;
        }

        let mut version_buf = [0u8; 4];
        if file.read_exact(&mut version_buf).is_err() {
            return;
        }
        let version = u32::from_be_bytes(version_buf);
        if version != 1 {
            tracing::warn!(
                "Unsupported cache database version {} in '{}'",
                version,
                path
            );
            return;
        }

        let mut count_buf = [0u8; 4];
        if file.read_exact(&mut count_buf).is_err() {
            return;
        }
        let count = u32::from_be_bytes(count_buf) as usize;

        let now = Instant::now();
        let mut loaded_count = 0;
        let mut key_bytes = Vec::with_capacity(256);
        let mut data_bytes = Vec::with_capacity(4096);

        for _ in 0..count {
            let mut klen_buf = [0u8; 4];
            if file.read_exact(&mut klen_buf).is_err() {
                break;
            }
            let klen = u32::from_be_bytes(klen_buf) as usize;
            if klen > 1024 {
                tracing::warn!("Corrupted cache database: key length {} exceeds limit 1024", klen);
                break;
            }

            key_bytes.resize(klen, 0);
            if file.read_exact(&mut key_bytes).is_err() {
                break;
            }
            let key_str_opt = std::str::from_utf8(&key_bytes).ok();

            let mut dlen_buf = [0u8; 4];
            if file.read_exact(&mut dlen_buf).is_err() {
                break;
            }
            let dlen = u32::from_be_bytes(dlen_buf) as usize;
            if dlen > 65535 {
                tracing::warn!("Corrupted cache database: data length {} exceeds limit 65535", dlen);
                break;
            }

            data_bytes.resize(dlen, 0);
            if file.read_exact(&mut data_bytes).is_err() {
                break;
            }

            let mut original_ttl_buf = [0u8; 4];
            if file.read_exact(&mut original_ttl_buf).is_err() {
                break;
            }
            let original_ttl = u32::from_be_bytes(original_ttl_buf);

            let mut rem_ttl_buf = [0u8; 8];
            if file.read_exact(&mut rem_ttl_buf).is_err() {
                break;
            }
            let rem_ttl = i64::from_be_bytes(rem_ttl_buf);

            let mut rem_stale_buf = [0u8; 8];
            if file.read_exact(&mut rem_stale_buf).is_err() {
                break;
            }
            let rem_stale = i64::from_be_bytes(rem_stale_buf);

            let key_str = match key_str_opt {
                Some(s) => s,
                None => {
                    tracing::warn!("Skipping cache database entry with invalid UTF-8 key");
                    continue;
                }
            };

            if rem_stale <= 0 {
                continue; // Already expired (even with stale margin)
            }

            let expires_at = now + Duration::from_secs(rem_ttl.max(0) as u64);

            let idx = self.get_shard_index(key_str);
            let shard = &self.shards[idx];
            let mut entries = shard.entries.write().unwrap_or_else(|poison_err| {
                tracing::warn!(
                    "Cache shard write lock was poisoned during load_from_db. Recovering."
                );
                poison_err.into_inner()
            });

            if entries.len() >= self.shard_max_size && !entries.contains_key(key_str) {
                Self::evict(&mut entries, self.shard_max_size, now, self.stale_sec);
            }

            entries.insert(
                CompactString::new(key_str),
                CacheEntry {
                    data: Arc::from(&data_bytes[..dlen]),
                    expires_at,
                    original_ttl,
                },
            );
            loaded_count += 1;
        }

        info!("Loaded {} cached entries from DB '{}'", loaded_count, path);
    }

    pub fn save_to_db(&self, path: &str) {
        use std::io::{Write, Seek, SeekFrom, BufWriter};

        let now = Instant::now();
        let temp_path = format!("{}.tmp", path);

        let file = match std::fs::File::create(&temp_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Failed to create temp cache DB file '{}': {}", temp_path, e);
                return;
            }
        };
        let mut writer = BufWriter::new(file);

        if writer.write_all(b"CDNSCACH").is_err()
            || writer.write_all(&1u32.to_be_bytes()).is_err()
            || writer.write_all(&0u32.to_be_bytes()).is_err()
        {
            tracing::error!("Failed to write header to temp cache DB file '{}'", temp_path);
            let _ = std::fs::remove_file(&temp_path);
            return;
        }

        let mut count = 0u32;
        for shard in &self.shards {
            let entries = shard.entries.read().unwrap_or_else(|poison_err| {
                tracing::warn!("Cache shard read lock was poisoned during save_to_db. Recovering.");
                poison_err.into_inner()
            });

            for (key, entry) in entries.iter() {
                let stale_until = if self.stale_sec > 0 {
                    entry.expires_at + Duration::from_secs(self.stale_sec as u64)
                } else {
                    entry.expires_at
                };
                if stale_until > now {
                    let rem_ttl = if entry.expires_at > now {
                        entry.expires_at.duration_since(now).as_secs() as i64
                    } else {
                        -(now.duration_since(entry.expires_at).as_secs() as i64)
                    };
                    let rem_stale = stale_until.duration_since(now).as_secs() as i64;
                    let kbytes = key.as_bytes();
                    let res = writer
                        .write_all(&(kbytes.len() as u32).to_be_bytes())
                        .and_then(|_| writer.write_all(kbytes))
                        .and_then(|_| writer.write_all(&(entry.data.len() as u32).to_be_bytes()))
                        .and_then(|_| writer.write_all(&entry.data))
                        .and_then(|_| writer.write_all(&entry.original_ttl.to_be_bytes()))
                        .and_then(|_| writer.write_all(&rem_ttl.to_be_bytes()))
                        .and_then(|_| writer.write_all(&rem_stale.to_be_bytes()));

                    if res.is_err() {
                        tracing::error!(
                            "Failed to write entry to temp cache DB file '{}'",
                            temp_path
                        );
                        let _ = std::fs::remove_file(&temp_path);
                        return;
                    }
                    count += 1;
                }
            }
        }

        if writer.seek(SeekFrom::Start(12)).is_ok() {
            let _ = writer.write_all(&count.to_be_bytes());
        }

        if let Err(e) = writer.flush() {
            tracing::error!("Failed to flush temp cache DB file '{}': {}", temp_path, e);
            let _ = std::fs::remove_file(&temp_path);
            return;
        }
        drop(writer);

        if let Err(e) = std::fs::rename(&temp_path, path) {
            tracing::error!("Failed to rename temp cache DB file to '{}': {}", path, e);
            let _ = std::fs::remove_file(&temp_path);
        } else {
            tracing::debug!("Saved {} cached entries to DB '{}'", count, path);
        }
    }

    pub fn stats(&self) -> CacheStats {
        let mut size = 0;
        let mut capacity = 0;
        for shard in &self.shards {
            if let Ok(entries) = shard.entries.read() {
                size += entries.len();
                capacity += entries.capacity();
            }
        }
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };
        CacheStats {
            size,
            capacity,
            hits,
            misses,
            hit_rate,
        }
    }
}

pub struct CacheStats {
    pub size: usize,
    pub capacity: usize,
    pub hits: usize,
    pub misses: usize,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_cache_db_persistence() {
        let cache = DnsCache::new(10, 60, Some(50));
        let key1 = "baidu.com:1";
        let query1 = crate::dns::build_query("baidu.com", 1);
        cache.insert(key1, Arc::from(query1.as_slice()), 100);

        let key2 = "google.com:28";
        let query2 = crate::dns::build_query("google.com", 28);
        cache.insert(key2, Arc::from(query2.as_slice()), 200);

        let temp_file = NamedTempFile::new().unwrap();
        let db_path = temp_file.path().to_str().unwrap();

        // Save
        cache.save_to_db(db_path);

        // Create new cache instance to load from db
        let cache2 = DnsCache::new(10, 60, Some(50));
        cache2.load_from_db(db_path);

        // Verify keys and data exist
        match cache2.get(key1) {
            CacheStatus::Hit { data, .. } => assert_eq!(&*data, query1.as_slice()),
            _ => panic!("Expected Hit for key1"),
        }

        match cache2.get(key2) {
            CacheStatus::Hit { data, .. } => assert_eq!(&*data, query2.as_slice()),
            _ => panic!("Expected Hit for key2"),
        }
    }

    #[test]
    fn test_cache_evict_identical_timestamps() {
        let cache = DnsCache::new(64, 60, Some(50));
        let mut key1 = String::new();
        let mut key2 = String::new();
        for i in 0..1000 {
            let k = format!("k{}", i);
            if cache.get_shard_index(&k) == 0 {
                if key1.is_empty() {
                    key1 = k;
                } else if key2.is_empty() {
                    key2 = k;
                    break;
                }
            }
        }
        assert!(!key1.is_empty() && !key2.is_empty());
        let query1 = vec![1, 2, 3];
        let query2 = vec![4, 5, 6];
        cache.insert(&key1, Arc::from(query1.as_slice()), 100);
        cache.insert(&key2, Arc::from(query2.as_slice()), 100);
        let stats = cache.stats();
        assert_eq!(stats.size, 1);
    }

    #[test]
    fn test_cache_scaled_shards_small_size() {
        let cache_small = DnsCache::new(10, 60, Some(50));
        assert_eq!(cache_small.shards.len(), 16);
        assert_eq!(cache_small.shard_max_size, 1);

        let cache_one = DnsCache::new(1, 60, Some(50));
        assert_eq!(cache_one.shards.len(), 1);
        assert_eq!(cache_one.shard_max_size, 1);

        let cache_normal = DnsCache::new(100, 60, Some(50));
        assert_eq!(cache_normal.shards.len(), 64);
        assert_eq!(cache_normal.shard_max_size, 2);
    }
}
