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

use super::logger::Parser;
use super::{Location, Upstream};
use crate::config::{LocationConf, PingapConf, UpstreamConf};
use crate::http_extra::{HttpResponse, HTTP_HEADER_CONTENT_JSON, HTTP_HEADER_WWW_AUTHENTICATE};
use crate::plugin::ProxyPlugin;
use crate::serve::ADMIN_SERVE;
use crate::state::{get_hostname, State};
use crate::util;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use bytesize::ByteSize;
use http::StatusCode;
use log::{error, info};
use memory_stats::memory_stats;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::listeners::TlsSettings;
use pingora::protocols::http::error_resp;
use pingora::protocols::Digest;
use pingora::proxy::{http_proxy_service, HttpProxy};
use pingora::server::configuration;
use pingora::services::background::GenBackgroundService;
use pingora::services::listening::Service;
use pingora::services::Service as IService;
use pingora::upstreams::peer::Peer;
use pingora::{
    proxy::{ProxyHttp, Session},
    upstreams::peer::HttpPeer,
};
use serde::Serialize;
use snafu::{ResultExt, Snafu};
use std::fs;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use substring::Substring;

static ERROR_TEMPLATE: &str = include_str!("../../error.html");

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Toml de error {}, {content}", source.to_string()))]
    TomlDe {
        source: toml::de::Error,
        content: String,
    },
    #[snafu(display("Error {category} {message}"))]
    Common { category: String, message: String },
    #[snafu(display("Io {source}"))]
    Io { source: std::io::Error },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Default)]
pub struct ServerConf {
    pub name: String,
    pub addr: String,
    pub admin: bool,
    pub stats_path: Option<String>,
    pub admin_path: Option<String>,
    pub access_log: Option<String>,
    pub authorization: Option<String>,
    pub upstreams: Vec<(String, UpstreamConf)>,
    pub locations: Vec<(String, LocationConf)>,
    pub tls_cert: Option<Vec<u8>>,
    pub tls_key: Option<Vec<u8>>,
    pub threads: Option<usize>,
    pub error_template: String,
}

impl From<PingapConf> for Vec<ServerConf> {
    fn from(conf: PingapConf) -> Self {
        let mut upstreams = vec![];
        for (name, item) in conf.upstreams {
            upstreams.push((name, item));
        }
        let mut locations = vec![];
        for (name, item) in conf.locations {
            locations.push((name, item));
        }
        // sort location by weight
        locations.sort_by_key(|b| std::cmp::Reverse(b.1.get_weight()));
        let mut servers = vec![];
        for (name, item) in conf.servers {
            let valid_locations = item.locations.unwrap_or_default();
            let mut valid_upstreams = vec![];
            // filter location of server
            let mut filter_locations = vec![];
            for item in locations.iter() {
                if valid_locations.contains(&item.0) {
                    valid_upstreams.push(item.1.upstream.clone());
                    filter_locations.push(item.clone())
                }
            }
            // filter upstream of server locations
            let mut filter_upstreams = vec![];
            for item in upstreams.iter() {
                if valid_upstreams.contains(&item.0) {
                    filter_upstreams.push(item.clone())
                }
            }
            let mut tls_cert = None;
            let mut tls_key = None;
            // load config validate base64
            // so ignore error
            if let Some(value) = &item.tls_cert {
                let buf = STANDARD.decode(value).unwrap_or_default();
                tls_cert = Some(buf);
            }
            if let Some(value) = &item.tls_key {
                let buf = STANDARD.decode(value).unwrap_or_default();
                tls_key = Some(buf);
            }

            let error_template = if conf.error_template.is_empty() {
                ERROR_TEMPLATE.to_string()
            } else {
                conf.error_template.clone()
            };

            servers.push(ServerConf {
                name,
                tls_cert,
                tls_key,
                admin: false,
                authorization: item.authorization,
                stats_path: item.stats_path,
                admin_path: item.admin_path,
                addr: item.addr,
                access_log: item.access_log,
                upstreams: filter_upstreams,
                locations: filter_locations,
                threads: item.threads,
                error_template,
            });
        }

        servers
    }
}

impl ServerConf {
    pub fn validate(&self) -> Result<()> {
        // TODO validate
        Ok(())
    }
}

pub struct Server {
    admin: bool,
    addr: String,
    accepted: AtomicU64,
    processing: AtomicI32,
    locations: Vec<Location>,
    log_parser: Option<Parser>,
    authorization: Option<String>,
    error_template: String,
    stats_path: Option<String>,
    admin_path: Option<String>,
    threads: Option<usize>,
    tls_cert: Option<Vec<u8>>,
    tls_key: Option<Vec<u8>>,
}

#[derive(Serialize)]
struct ServerStats {
    processing: i32,
    accepted: u64,
    hostname: String,
    physical_mem_mb: usize,
    physical_mem: String,
}

pub struct ServerServices {
    pub lb: Service<HttpProxy<Server>>,
    pub bg_services: Vec<Box<dyn IService>>,
}

impl Server {
    pub fn new(conf: ServerConf) -> Result<Self> {
        let mut upstreams = vec![];
        let in_used_upstreams: Vec<_> = conf
            .locations
            .iter()
            .map(|item| item.1.upstream.clone())
            .collect();
        for item in conf.upstreams.iter() {
            // ignore not in used
            if !in_used_upstreams.contains(&item.0) {
                continue;
            }
            let up = Upstream::new(&item.0, &item.1).map_err(|err| Error::Common {
                category: "upstream".to_string(),
                message: err.to_string(),
            })?;
            upstreams.push(Arc::new(up));
        }
        let mut locations = vec![];
        for item in conf.locations.iter() {
            locations.push(
                Location::new(&item.0, &item.1, upstreams.clone()).map_err(|err| {
                    Error::Common {
                        category: "location".to_string(),
                        message: err.to_string(),
                    }
                })?,
            );
        }
        let mut p = None;
        if let Some(access_log) = conf.access_log {
            p = Some(Parser::from(access_log.as_str()));
        }

        Ok(Server {
            admin: conf.admin,
            accepted: AtomicU64::new(0),
            processing: AtomicI32::new(0),
            stats_path: conf.stats_path,
            admin_path: conf.admin_path,
            authorization: conf.authorization,
            addr: conf.addr,
            log_parser: p,
            locations,
            error_template: conf.error_template,
            tls_key: conf.tls_key,
            tls_cert: conf.tls_cert,
            threads: conf.threads,
        })
    }
    pub fn run(self, conf: &Arc<configuration::ServerConf>) -> Result<ServerServices> {
        let addr = self.addr.clone();
        let mut bg_services: Vec<Box<dyn IService>> = vec![];
        for item in self.locations.iter() {
            let name = format!("BG {}", item.upstream.name);
            if let Some(up) = item.upstream.as_round_robind() {
                bg_services.push(Box::new(GenBackgroundService::new(name.clone(), up)));
            }
            if let Some(up) = item.upstream.as_consistent() {
                bg_services.push(Box::new(GenBackgroundService::new(name, up)));
            }
        }
        // tls
        let tls_cert = self.tls_cert.clone();
        let tls_key = self.tls_key.clone();

        let threads = self.threads;
        let mut lb = http_proxy_service(conf, self);
        lb.threads = threads;
        // add tls
        if tls_cert.is_some() {
            let dir = tempfile::tempdir().context(IoSnafu)?;
            let cert_path = dir.path().join("tls-cert");
            let key_path = dir.path().join("tls-key");
            fs::write(cert_path.clone(), tls_cert.unwrap_or_default()).context(IoSnafu)?;
            fs::write(key_path.clone(), tls_key.unwrap_or_default()).context(IoSnafu)?;
            let mut tls_settings = TlsSettings::intermediate(
                cert_path.to_str().ok_or(Error::Common {
                    category: "tmpdir".to_string(),
                    message: cert_path.to_string_lossy().to_string(),
                })?,
                key_path.to_str().ok_or(Error::Common {
                    category: "tmpdir".to_string(),
                    message: key_path.to_string_lossy().to_string(),
                })?,
            )
            .map_err(|err| Error::Common {
                category: "tls".to_string(),
                message: err.to_string(),
            })?;
            tls_settings.enable_h2();
            lb.add_tls_with_settings(&addr, None, tls_settings);
        } else {
            lb.add_tcp(&addr);
        }
        Ok(ServerServices { lb, bg_services })
    }
    async fn send_stats_response(&self, session: &mut Session, ctx: &mut State) {
        let mut physical_mem = 0;
        if let Some(value) = memory_stats() {
            physical_mem = value.physical_mem;
        }

        let buf = serde_json::to_vec(&ServerStats {
            accepted: self.accepted.load(Ordering::Relaxed),
            processing: self.processing.load(Ordering::Relaxed),
            hostname: get_hostname(),
            physical_mem: ByteSize(physical_mem as u64).to_string_as(true),
            physical_mem_mb: physical_mem / (1024 * 1024),
        })
        .unwrap_or_default();

        let size = HttpResponse {
            status: StatusCode::OK,
            body: Bytes::from(buf),
            headers: Some(vec![HTTP_HEADER_CONTENT_JSON.clone()]),
            ..Default::default()
        }
        .send(session)
        .await
        .unwrap_or_else(|e| {
            // ingore error for stats
            error!("failed to send error response to downstream: {e}");
            0
        });
        ctx.status = Some(StatusCode::OK);
        ctx.response_body_size = size;
    }
    fn auth_validate(&self, req_header: &RequestHeader) -> bool {
        if let Some(authorization) = &self.authorization {
            let value = util::get_req_header_value(req_header, "Authorization").unwrap_or_default();
            if value.is_empty() {
                return false;
            }
            if value != format!("Basic {authorization}") {
                return false;
            }
        }
        true
    }
    async fn serve_admin(
        &self,
        admin_path: &str,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<bool> {
        if !self.auth_validate(session.req_header()) {
            let _ = HttpResponse {
                status: StatusCode::UNAUTHORIZED,
                headers: Some(vec![HTTP_HEADER_WWW_AUTHENTICATE.clone()]),
                ..Default::default()
            }
            .send(session)
            .await?;
            return Ok(true);
        }

        let header = session.req_header_mut();
        let path = header.uri.path();
        let mut new_path = path.substring(admin_path.len(), path.len()).to_string();
        if let Some(query) = header.uri.query() {
            new_path = format!("{new_path}?{query}");
        }
        // TODO parse error
        if let Ok(uri) = new_path.parse::<http::Uri>() {
            header.set_uri(uri);
        }
        ADMIN_SERVE.handle(session, ctx).await
    }
    async fn serve_stats_admin(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<bool> {
        let path = session.req_header().uri.path();
        // stats path
        if let Some(stats_path) = &self.stats_path {
            if stats_path == path {
                self.send_stats_response(session, ctx).await;
                return Ok(true);
            }
        }

        // admin server
        if self.admin {
            let result = ADMIN_SERVE.handle(session, ctx).await?;
            return Ok(result);
        }

        // admin path
        if let Some(admin_path) = &self.admin_path {
            if path.starts_with(admin_path) {
                let result = self.serve_admin(admin_path, session, ctx).await?;
                return Ok(result);
            }
        }
        Ok(false)
    }
}

#[async_trait]
impl ProxyHttp for Server {
    type CTX = State;
    fn new_ctx(&self) -> Self::CTX {
        State::default()
    }
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        ctx.processing = self.processing.fetch_add(1, Ordering::Relaxed);
        self.accepted.fetch_add(1, Ordering::Relaxed);
        // session.cache.enable(storage, eviction, predictor, cache_lock)

        // serve stats or admin
        let served = self.serve_stats_admin(session, ctx).await?;
        if served {
            return Ok(true);
        }

        let header = session.req_header_mut();
        let path = header.uri.path();
        let host = header.uri.host().unwrap_or_default();

        let (location_index, lo) = self
            .locations
            .iter()
            .enumerate()
            .find(|(_, item)| item.matched(host, path))
            .ok_or_else(|| {
                util::new_internal_error(
                    500,
                    format!("Location not found, host:{host} path:{path}"),
                )
            })?;
        if let Some(mut new_path) = lo.rewrite(path) {
            if let Some(query) = header.uri.query() {
                new_path = format!("{new_path}?{query}");
            }
            // TODO parse error
            let _ = new_path.parse::<http::Uri>().map(|uri| header.set_uri(uri));
        }
        // TODO find a way for compressing for static file
        if let Some(level) = lo.modify_accept_encoding(header) {
            session.downstream_compression.adjust_decompression(true);
            session.downstream_compression.adjust_level(level);
        }

        let done = lo.exec_proxy_plugins(session, ctx).await?;
        if done {
            return Ok(true);
        }

        ctx.location_index = Some(location_index);

        // TODO get response from cache
        // check location support cache

        Ok(false)
    }
    async fn proxy_upstream_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        let lo = &self.locations[ctx.location_index.unwrap_or_default()];
        if let Some(dir) = lo.upstream.as_directory() {
            let result = dir.handle(session, ctx).await?;
            return Ok(!result);
        }
        if let Some(mock) = lo.upstream.as_mock() {
            let result = mock.handle(session, ctx).await?;
            return Ok(!result);
        }
        Ok(true)
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut State,
    ) -> pingora::Result<Box<HttpPeer>> {
        let lo = &self.locations[ctx.location_index.unwrap_or_default()];
        let peer = lo.upstream.new_http_peer(ctx, session).ok_or_else(|| {
            util::new_internal_error(503, format!("No available upstream({})", lo.upstream_name))
        })?;

        Ok(Box::new(peer))
    }
    async fn connected_to_upstream(
        &self,
        _session: &mut Session,
        reused: bool,
        peer: &HttpPeer,
        _fd: std::os::unix::io::RawFd,
        _digest: Option<&Digest>,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        ctx.reused = reused;
        ctx.upstream_address = peer.address().to_string();
        Ok(())
    }
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        header: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // add x-forwarded-for
        if let Some(addr) = util::get_remote_addr(session) {
            let value = if let Some(value) =
                session.get_header(util::HTTP_HEADER_X_FORWARDED_FOR.clone())
            {
                format!("{}, {}", value.to_str().unwrap_or_default(), addr)
            } else {
                addr.to_string()
            };
            let _ = header.insert_header(util::HTTP_HEADER_X_FORWARDED_FOR.clone(), value);
        }

        if let Some(index) = ctx.location_index {
            if let Some(lo) = self.locations.get(index) {
                lo.insert_proxy_headers(header);
            }
        }

        Ok(())
    }
    fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) {
        if ctx.status.is_none() {
            ctx.status = Some(upstream_response.status);
        }
        if let Some(index) = ctx.location_index {
            if let Some(lo) = self.locations.get(index) {
                lo.insert_headers(upstream_response)
            }
        }
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) {
        if let Some(body) = body {
            ctx.response_body_size += body.len();
        }
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> u16
    where
        Self::CTX: Send + Sync,
    {
        let server_session = session.as_mut();

        let code = match e.etype() {
            pingora::HTTPStatus(code) => *code,
            _ => match e.esource() {
                pingora::ErrorSource::Upstream => 502,
                pingora::ErrorSource::Downstream => match e.etype() {
                    pingora::ErrorType::WriteError | pingora::ErrorType::ReadError => 500,
                    // client close the connection
                    pingora::ErrorType::ConnectionClosed => 499,
                    _ => 400,
                },
                pingora::ErrorSource::Internal | pingora::ErrorSource::Unset => 500,
            },
        };
        // TODO better error handler(e.g. json response)
        let mut resp = match code {
            502 => error_resp::HTTP_502_RESPONSE.clone(),
            400 => error_resp::HTTP_400_RESPONSE.clone(),
            _ => error_resp::gen_error_response(code),
        };

        let content = self
            .error_template
            .replace("{{version}}", util::get_pkg_version())
            .replace("{{content}}", &e.to_string());
        let buf = Bytes::from(content);
        ctx.status = Some(StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
        ctx.response_body_size = buf.len();
        let _ = resp.insert_header(http::header::CONTENT_TYPE, "text/html; charset=utf-8");
        let _ = resp.insert_header(http::header::CONTENT_LENGTH, buf.len().to_string());

        // TODO: we shouldn't be closing downstream connections on internally generated errors
        // and possibly other upstream connect() errors (connection refused, timeout, etc)
        //
        // This change is only here because we DO NOT re-use downstream connections
        // today on these errors and we should signal to the client that pingora is dropping it
        // rather than a misleading the client with 'keep-alive'
        server_session.set_keepalive(None);

        server_session
            .write_response_header(Box::new(resp))
            .await
            .unwrap_or_else(|e| {
                error!("failed to send error response to downstream: {e}");
            });

        let _ = server_session.write_response_body(buf).await;
        code
    }
    async fn logging(&self, session: &mut Session, _e: Option<&pingora::Error>, ctx: &mut Self::CTX)
    where
        Self::CTX: Send + Sync,
    {
        self.processing.fetch_add(-1, Ordering::Relaxed);
        if ctx.status.is_none() {
            if let Some(header) = session.response_written() {
                ctx.status = Some(header.status);
            }
        }

        if let Some(p) = &self.log_parser {
            info!("{}", p.format(session, ctx));
        }
    }
}
