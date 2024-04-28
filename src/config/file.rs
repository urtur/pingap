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

use super::PingapConf;
use super::{ConfigStorage, Error, Result};
use crate::util;
use async_trait::async_trait;
use glob::glob;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use toml::{map::Map, Value};

#[derive(Deserialize, Debug, Serialize)]
struct TomlConfig {
    name: Option<String>,
    servers: Option<Map<String, Value>>,
    upstreams: Option<Map<String, Value>>,
    locations: Option<Map<String, Value>>,
    proxy_plugins: Option<Map<String, Value>>,
    error_template: Option<String>,
    pid_file: Option<String>,
    upgrade_sock: Option<String>,
    user: Option<String>,
    group: Option<String>,
    threads: Option<usize>,
    work_stealing: Option<bool>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub grace_period: Option<Duration>,
    #[serde(default)]
    #[serde(with = "humantime_serde")]
    pub graceful_shutdown_timeout: Option<Duration>,
    pub upstream_keepalive_pool_size: Option<usize>,
    pub webhook: Option<String>,
    pub webhook_type: Option<String>,
    pub log_level: Option<String>,
    pub sentry: Option<String>,
    pub pyroscope: Option<String>,
}

pub struct FileStorage {
    path: String,
}
impl FileStorage {
    pub fn new(path: &str) -> Result<Self> {
        let filepath = util::resolve_path(path);
        if filepath.is_empty() {
            return Err(Error::Invalid {
                message: "Config path is empty".to_string(),
            });
        }

        Ok(Self { path: filepath })
    }
}

#[async_trait]
impl ConfigStorage for FileStorage {
    async fn load_config(&self, admin: bool) -> Result<PingapConf> {
        let filepath = self.path.clone();
        if admin && !Path::new(&filepath).exists() {
            return Ok(PingapConf::default());
        }

        let mut data = vec![];
        if Path::new(&filepath).is_dir() {
            for entry in glob(&format!("{filepath}/**/*.toml")).map_err(|e| Error::Pattern {
                source: e,
                path: filepath,
            })? {
                let f = entry.map_err(|e| Error::Glob { source: e })?;
                let mut buf = fs::read(&f).await.map_err(|e| Error::Io {
                    source: e,
                    file: f.to_string_lossy().to_string(),
                })?;
                data.append(&mut buf);
                data.push(0x0a);
            }
        } else {
            let mut buf = fs::read(&filepath).await.map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })?;
            data.append(&mut buf);
        }
        PingapConf::try_from(data)
    }
    async fn save_config(&self, conf: &PingapConf, category: &str) -> Result<()> {
        let filepath = self.path.clone();
        conf.validate()?;
        if Path::new(&filepath).is_file() {
            let ping_conf = toml::to_string_pretty(&conf).map_err(|e| Error::Ser { source: e })?;
            return fs::write(&filepath, ping_conf)
                .await
                .map_err(|e| Error::Io {
                    source: e,
                    file: filepath,
                });
        }

        let (path, toml_value) = conf.get_toml(category)?;
        let filepath = format!("{filepath}{path}");
        fs::write(&filepath, toml_value)
            .await
            .map_err(|e| Error::Io {
                source: e,
                file: filepath,
            })
    }
}