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

use super::{Error, Result};
use async_trait::async_trait;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use pingora::cache::key::CacheHashKey;
use pingora::cache::key::CompactCacheKey;
use pingora::cache::storage::{HandleHit, HandleMiss};
use pingora::cache::trace::SpanHandle;
use pingora::cache::{
    CacheKey, CacheMeta, HitHandler, MissHandler, PurgeType, Storage,
};
use std::any::Any;
use std::sync::Arc;

type BinaryMeta = (Vec<u8>, Vec<u8>);

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CacheObject {
    pub meta: BinaryMeta,
    pub body: Vec<u8>,
}

/// Create a cache object from bytes.
impl From<Vec<u8>> for CacheObject {
    fn from(value: Vec<u8>) -> Self {
        let size_byte = 8;
        // 8 bytes
        if value.len() < size_byte {
            return Self::default();
        }
        let meta0_size =
            u32::from_be_bytes(value[0..4].try_into().unwrap()) as usize;
        let meta1_size =
            u32::from_be_bytes(value[4..8].try_into().unwrap()) as usize;
        let mut start = size_byte;
        let mut end = start + meta0_size;
        let meta0 = value[start..end].to_vec();

        start = end;
        end += meta1_size;
        let meta1 = value[start..end].to_vec();

        start = end;
        let body = value[start..value.len()].to_vec();
        Self {
            meta: (meta0, meta1),
            body,
        }
    }
}
/// Convert cache object to bytes.
impl From<CacheObject> for Vec<u8> {
    fn from(value: CacheObject) -> Self {
        let mut buf = BytesMut::with_capacity(value.body.len() + 1024);
        let meta0_size = value.meta.0.len() as u32;
        let meta1_size = value.meta.1.len() as u32;
        buf.put_u32(meta0_size);
        buf.put_u32(meta1_size);
        buf.extend(value.meta.0);
        buf.extend(value.meta.1);
        buf.extend(value.body.iter());

        buf.to_vec()
    }
}

#[async_trait]
pub trait HttpCacheStorage: Sync + Send {
    async fn get(&self, key: &str) -> Option<CacheObject>;
    async fn put(
        &self,
        key: String,
        data: CacheObject,
        weight: u16,
    ) -> Result<()>;
    async fn remove(&self, _key: &str) -> Result<Option<CacheObject>> {
        Ok(None)
    }
}

pub struct HttpCache {
    pub(crate) cached: Arc<dyn HttpCacheStorage>,
}

pub struct CompleteHit {
    body: Vec<u8>,
    done: bool,
    range_start: usize,
    range_end: usize,
}

impl CompleteHit {
    fn get(&mut self) -> Option<Bytes> {
        if self.done {
            None
        } else {
            self.done = true;
            Some(Bytes::copy_from_slice(
                &self.body.as_slice()[self.range_start..self.range_end],
            ))
        }
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        if start >= self.body.len() {
            return Err(Error::Invalid {
                message: format!(
                    "seek start out of range {start} >= {}",
                    self.body.len()
                ),
            });
        }
        self.range_start = start;
        if let Some(end) = end {
            // end over the actual last byte is allowed, we just need to return the actual bytes
            self.range_end = std::cmp::min(self.body.len(), end);
        }
        // seek resets read so that one handler can be used for multiple ranges
        self.done = false;
        Ok(())
    }
}

#[async_trait]
impl HandleHit for CompleteHit {
    async fn read_body(&mut self) -> pingora::Result<Option<Bytes>> {
        Ok(self.get())
    }
    async fn finish(
        self: Box<Self>, // because self is always used as a trait object
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<()> {
        Ok(())
    }

    fn can_seek(&self) -> bool {
        true
    }

    fn seek(
        &mut self,
        start: usize,
        end: Option<usize>,
    ) -> pingora::Result<()> {
        self.seek(start, end)?;
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

pub struct ObjectMissHandler {
    meta: BinaryMeta,
    body: BytesMut,
    // these are used only in finish() to data from temp to cache
    key: String,
    cache: Arc<dyn HttpCacheStorage>,
}

#[async_trait]
impl HandleMiss for ObjectMissHandler {
    async fn write_body(
        &mut self,
        data: bytes::Bytes,
        _eof: bool,
    ) -> pingora::Result<()> {
        self.body.extend(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> pingora::Result<usize> {
        let size = self.body.len(); // FIXME: this just body size, also track meta size
        let _ = self
            .cache
            .put(
                self.key.clone(),
                CacheObject {
                    meta: self.meta,
                    body: self.body.to_vec(),
                },
                get_wegith(size),
            )
            .await?;

        Ok(size)
    }
}

fn get_wegith(size: usize) -> u16 {
    if size < 50 * 1024 {
        return 4;
    }
    if size < 500 * 1024 {
        return 2;
    }
    1
}

#[async_trait]
impl Storage for HttpCache {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> pingora::Result<Option<(CacheMeta, HitHandler)>> {
        let hash = key.combined();
        if let Some(obj) = self.cached.get(&hash).await {
            let meta = CacheMeta::deserialize(&obj.meta.0, &obj.meta.1)?;
            let size = obj.body.len();
            let hit_handler = CompleteHit {
                body: obj.body,
                done: false,
                range_start: 0,
                range_end: size,
            };
            Ok(Some((meta, Box::new(hit_handler))))
        } else {
            Ok(None)
        }
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<MissHandler> {
        // TODO: support multiple concurrent writes or panic if the is already a writer
        let capacity = 5 * 1024;
        let size = if let Some(content_length) =
            meta.headers().get(http::header::CONTENT_LENGTH)
        {
            content_length
                .to_str()
                .unwrap_or_default()
                .parse::<usize>()
                .unwrap_or(capacity)
        } else {
            capacity
        };
        let hash = key.combined();
        let meta = meta.serialize()?;
        let miss_handler = ObjectMissHandler {
            meta,
            key: hash.clone(),
            cache: self.cached.clone(),
            body: BytesMut::with_capacity(size),
        };
        Ok(Box::new(miss_handler))
    }

    async fn purge(
        &'static self,
        key: &CompactCacheKey,
        _type: PurgeType,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        // This usually purges the primary key because, without a lookup,
        // the variance key is usually empty
        let hash = key.combined();
        let cache_removed = if let Ok(result) = self.cached.remove(&hash).await
        {
            result.is_some()
        } else {
            false
        };
        Ok(cache_removed)
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> pingora::Result<bool> {
        let hash = key.combined();
        if let Some(mut obj) = self.cached.get(&hash).await {
            obj.meta = meta.serialize()?;
            let size = obj.body.len();
            let _ = self.cached.put(hash, obj, get_wegith(size)).await?;
            Ok(true)
        } else {
            Err(Error::Invalid {
                message: "no meta found".to_string(),
            }
            .into())
        }
    }

    fn support_streaming_partial_write(&self) -> bool {
        false
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{CompleteHit, HttpCacheStorage, ObjectMissHandler};
    use crate::cache::tiny::new_tiny_ufo_cache;
    use bytes::{Bytes, BytesMut};
    use pingora::cache::storage::{HitHandler, MissHandler};
    use pretty_assertions::assert_eq;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_complete_hit() {
        let body = b"Hello World!".to_vec();
        let size = body.len();
        let hit = CompleteHit {
            body,
            done: false,
            range_start: 0,
            range_end: size,
        };
        let mut handle: HitHandler = Box::new(hit);
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"Hello World!", body.unwrap().as_ref());

        handle.seek(1, Some(size - 1)).unwrap();
        let body = handle.read_body().await.unwrap();
        assert_eq!(true, body.is_some());
        assert_eq!(b"ello World", body.unwrap().as_ref());
    }

    #[tokio::test]
    async fn test_object_miss_handler() {
        let key = "key";

        let cache = Arc::new(new_tiny_ufo_cache(10, 10));
        let obj = ObjectMissHandler {
            meta: (b"Hello".to_vec(), b"World".to_vec()),
            body: BytesMut::new(),
            key: key.to_string(),
            cache: cache.clone(),
        };
        let mut handle: MissHandler = Box::new(obj);

        handle
            .write_body(Bytes::from_static(b"Hello World!"), true)
            .await
            .unwrap();
        handle.finish().await.unwrap();

        let data = cache.get(key).await.unwrap();
        assert_eq!("Hello World!", std::str::from_utf8(&data.body).unwrap());
    }
}
