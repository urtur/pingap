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

use super::ProxyPlugin;
use super::{Error, Result};
use crate::config::{ProxyPluginCategory, ProxyPluginStep};
use crate::state::State;
use crate::util;
use async_trait::async_trait;
use pingora::proxy::Session;
use pingora_limits::inflight::Inflight;
use substring::Substring;

#[derive(PartialEq, Debug)]
pub enum LimitTag {
    Ip,
    RequestHeader,
    Cookie,
    Query,
}

pub struct Limiter {
    tag: LimitTag,
    max: isize,
    value: String,
    inflight: Inflight,
    proxy_step: ProxyPluginStep,
}

impl Limiter {
    pub fn new(value: &str, proxy_step: ProxyPluginStep) -> Result<Self> {
        let (key, max) = value.split_once(' ').ok_or(Error::Invalid {
            message: value.to_string(),
        })?;
        let max = max
            .parse::<u32>()
            .map_err(|e| Error::ParseInt { source: e })?;
        if key.len() < 2 {
            return Err(Error::Invalid {
                message: key.to_string(),
            });
        }
        let ch = key.substring(0, 1);
        let value = key.substring(1, key.len());
        let tag = match ch {
            "~" => LimitTag::Cookie,
            ">" => LimitTag::RequestHeader,
            "?" => LimitTag::Query,
            _ => LimitTag::Ip,
        };

        Ok(Self {
            tag,
            proxy_step,
            max: max as isize,
            value: value.to_string(),
            inflight: Inflight::new(),
        })
    }
    /// Increment `key` by 1. If value gt max, an error will be return.
    /// Otherwise returns a Guard. It may set the client ip to context.
    pub fn incr(&self, session: &Session, ctx: &mut State) -> Result<()> {
        let key = match self.tag {
            LimitTag::Query => util::get_query_value(session.req_header(), &self.value)
                .unwrap_or_default()
                .to_string(),
            LimitTag::RequestHeader => {
                util::get_req_header_value(session.req_header(), &self.value)
                    .unwrap_or_default()
                    .to_string()
            }
            LimitTag::Cookie => util::get_cookie_value(session.req_header(), &self.value)
                .unwrap_or_default()
                .to_string(),
            _ => {
                let client_ip = util::get_client_ip(session);
                ctx.client_ip = Some(client_ip.clone());
                client_ip
            }
        };
        if key.is_empty() {
            return Ok(());
        }
        let (guard, value) = self.inflight.incr(key, 1);
        if value > self.max {
            return Err(Error::Exceed {
                max: self.max,
                value,
            });
        }
        ctx.guard = Some(guard);
        Ok(())
    }
}
#[async_trait]
impl ProxyPlugin for Limiter {
    #[inline]
    fn step(&self) -> ProxyPluginStep {
        self.proxy_step
    }
    #[inline]
    fn category(&self) -> ProxyPluginCategory {
        ProxyPluginCategory::Limit
    }
    #[inline]
    async fn handle(&self, session: &mut Session, ctx: &mut State) -> pingora::Result<bool> {
        let _ = self
            .incr(session, ctx)
            .map_err(|e| util::new_internal_error(429, e.to_string()))?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::state::State;

    use super::{LimitTag, Limiter};
    use pingora::proxy::Session;
    use pretty_assertions::assert_eq;
    use tokio_test::io::Builder;
    async fn new_session() -> Session {
        let headers = vec![
            "Host: github.com",
            "Referer: https://github.com/",
            "User-Agent: pingap/0.1.1",
            "Cookie: deviceId=abc",
            "Accept: application/json",
            "X-Uuid: 138q71",
            "X-Forwarded-For: 1.1.1.1, 192.168.1.2",
        ]
        .join("\r\n");
        let input_header = format!("GET /vicanso/pingap?key=1 HTTP/1.1\r\n{headers}\r\n\r\n");
        let mock_io = Builder::new().read(&input_header.as_bytes()).build();
        let mut session = Session::new_h1(Box::new(mock_io));
        session.read_request().await.unwrap();
        session
    }
    #[tokio::test]
    async fn test_new_cookie_limiter() {
        let limiter = Limiter::new("~deviceId 10").unwrap();
        assert_eq!(LimitTag::Cookie, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_req_header_limiter() {
        let limiter = Limiter::new(">X-Uuid 10").unwrap();
        assert_eq!(LimitTag::RequestHeader, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_query_limiter() {
        let limiter = Limiter::new("?key 10").unwrap();
        assert_eq!(LimitTag::Query, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
    #[tokio::test]
    async fn test_new_ip_limiter() {
        let limiter = Limiter::new("ip 10").unwrap();
        assert_eq!(LimitTag::Ip, limiter.tag);
        let mut ctx = State {
            ..Default::default()
        };
        let session = new_session().await;

        limiter.incr(&session, &mut ctx).unwrap();
        assert_eq!(true, ctx.guard.is_some());
    }
}
