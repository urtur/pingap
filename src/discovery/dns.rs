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

use crate::webhook;

use super::{format_addrs, Addr, Error, Result};
use async_trait::async_trait;
use hickory_resolver::lookup_ip::LookupIp;
use hickory_resolver::{AsyncResolver, Resolver};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends};
use pingora::protocols::l4::socket::SocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::net::ToSocketAddrs;
use tokio::runtime::Handle;
use tracing::{debug, error};

struct Dns {
    ipv4_only: bool,
    hosts: Vec<Addr>,
}

impl Dns {
    fn new(addrs: &[String], tls: bool, ipv4_only: bool) -> Result<Self> {
        let hosts = format_addrs(addrs, tls);
        Ok(Self { hosts, ipv4_only })
    }
    fn lookup_ip(&self) -> Result<Vec<LookupIp>> {
        let mut ip_list = vec![];
        let resolver = Resolver::from_system_conf().map_err(|e| Error::Io {
            source: e,
            content: "new resolover fail".to_string(),
        })?;
        for (host, _, _) in self.hosts.iter() {
            let ip = resolver
                .lookup_ip(host)
                .map_err(|e| Error::Resolve { source: e })?;
            ip_list.push(ip);
        }
        Ok(ip_list)
    }
    async fn tokio_lookup_ip(&self) -> Result<Vec<LookupIp>> {
        let mut ip_list = vec![];
        let resolver = AsyncResolver::tokio_from_system_conf()
            .map_err(|e| Error::Resolve { source: e })?;
        for (host, _, _) in self.hosts.iter() {
            let ip = resolver
                .lookup_ip(host)
                .await
                .map_err(|e| Error::Resolve { source: e })?;
            ip_list.push(ip);
        }
        Ok(ip_list)
    }
    async fn run_discover(
        &self,
    ) -> Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        let tokio_runtime = Handle::try_current().is_ok();
        let mut upstreams = BTreeSet::new();
        let mut backends = vec![];
        debug!(
            hosts = format!("{:?}", self.hosts),
            "dns discover is running"
        );
        let lookup_ip_list = if tokio_runtime {
            self.tokio_lookup_ip().await?
        } else {
            self.lookup_ip()?
        };
        for (index, (_, port, weight)) in self.hosts.iter().enumerate() {
            let lookup_ip =
                lookup_ip_list.get(index).ok_or(Error::Invalid {
                    message: "lookup ip fail".to_string(),
                })?;
            for item in lookup_ip.iter() {
                if self.ipv4_only && !item.is_ipv4() {
                    continue;
                }
                let mut addr = item.to_string();
                if !port.is_empty() {
                    addr += &format!(":{port}");
                }
                for socket_addr in
                    addr.to_socket_addrs().map_err(|e| Error::Io {
                        source: e,
                        content: format!("{addr} to socket addr fail"),
                    })?
                {
                    backends.push(Backend {
                        addr: SocketAddr::Inet(socket_addr),
                        weight: weight.to_owned(),
                    });
                }
            }
        }
        upstreams.extend(backends);
        // no readiness
        let health = HashMap::new();
        Ok((upstreams, health))
    }
}

#[async_trait]
impl ServiceDiscovery for Dns {
    async fn discover(
        &self,
    ) -> pingora::Result<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        match self.run_discover().await {
            Ok(data) => return Ok(data),
            Err(e) => {
                error!(
                    error = e.to_string(),
                    hosts = format!("{:?}", self.hosts),
                    "dns discover fail"
                );
                webhook::send(webhook::SendNotificationParams {
                    category:
                        webhook::NotificationCategory::ServiceDiscoverFail,
                    level: webhook::NotificationLevel::Warn,
                    msg: format!("{:?}, error: {e}", self.hosts),
                });
                return Err(e.into());
            },
        }
    }
}

/// Create a dns discovery, scheduled execution execute DNS resolve,
/// and update the latest IP address list.
pub fn new_dns_discover_backends(
    addrs: &[String],
    tls: bool,
    ipv4_only: bool,
) -> Result<Backends> {
    let dns = Dns::new(addrs, tls, ipv4_only)?;
    let backends = Backends::new(Box::new(dns));
    Ok(backends)
}

#[cfg(test)]
mod tests {
    use super::Dns;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_dns_discover() {
        let dns = Dns::new(&["github.com".to_string()], true, true).unwrap();
        let ip_list = dns.tokio_lookup_ip().await.unwrap();
        assert_eq!(true, !ip_list.is_empty());

        let (backends, _) = dns.run_discover().await.unwrap();
        assert_eq!(true, !backends.is_empty());
    }
}
