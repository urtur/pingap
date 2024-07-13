// Copyright 2024 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::http_cache::{CacheObject, HttpCacheStorage};
use super::{Error, Result};
use crate::util;
use async_trait::async_trait;
use std::path::Path;
use tinyufo::TinyUfo;
use tokio::fs;
use tracing::info;

pub struct FileCache {
    directory: String,
    cache: TinyUfo<String, CacheObject>,
}

/// Create a file cache and use tinyufo for hotspot data caching
pub fn new_file_cache(dir: &str) -> Result<FileCache> {
    let dir = util::resolve_path(dir);
    let path = Path::new(&dir);
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| Error::Io { source: e })?;
    }
    info!(dir, "new file cache");

    Ok(FileCache {
        directory: dir,
        cache: TinyUfo::new(100, 100),
    })
}

#[async_trait]
impl HttpCacheStorage for FileCache {
    /// Get cache object from tinyufo,
    /// if not exists, then get from the file.
    async fn get(&self, key: &str) -> Option<CacheObject> {
        if let Some(obj) = self.cache.get(&key.to_string()) {
            return Some(obj);
        }
        let file = Path::new(&self.directory).join(key);
        let Ok(buf) = fs::read(file).await else {
            return None;
        };
        if buf.len() < 8 {
            None
        } else {
            Some(CacheObject::from(buf))
        }
    }
    /// Put cache object to tinyufo and file.
    async fn put(
        &self,
        key: String,
        data: CacheObject,
        weight: u16,
    ) -> Result<()> {
        self.cache.put(key.clone(), data.clone(), weight);
        let buf: Vec<u8> = data.into();
        let file = Path::new(&self.directory).join(key);
        fs::write(file, buf)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(())
    }
    /// Remove cache object from file, tinyufo doesn't support remove now.
    async fn remove(&self, key: &str) -> Result<Option<CacheObject>> {
        // TODO remove from tinyufo
        let file = Path::new(&self.directory).join(key);
        fs::remove_file(file)
            .await
            .map_err(|e| Error::Io { source: e })?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::new_file_cache;
    use crate::cache::http_cache::{CacheObject, HttpCacheStorage};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_cache() {
        let dir = TempDir::new().unwrap();
        let dir = dir.into_path().to_string_lossy().to_string();
        let cache = new_file_cache(&dir).unwrap();
        let key = "key".to_string();
        let obj = CacheObject {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: b"Hello World!".to_vec(),
        };
        let result = cache.get(&key).await;
        assert_eq!(true, result.is_none());
        cache.put(key.clone(), obj.clone(), 1).await.unwrap();
        let result = cache.get(&key).await.unwrap();
        assert_eq!(obj, result);

        // empty tinyufo, get from file
        let cache = new_file_cache(&dir).unwrap();
        let result = cache.get(&key).await.unwrap();
        assert_eq!(obj, result);

        cache.remove(&key).await.unwrap();
        let result = cache.get(&key).await;
        assert_eq!(true, result.is_none());
    }
}
