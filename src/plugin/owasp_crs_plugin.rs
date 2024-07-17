use super::{get_step_conf, get_str_conf, Error, Plugin, Result};
use crate::config::{PluginCategory, PluginConf, PluginStep};
use crate::http_extra::HttpResponse;
use crate::state::State;
use async_trait::async_trait;
use bytes::Bytes;
use http::StatusCode;
use pingora::proxy::Session;
use tracing::{debug, info};

pub struct OwaspCrsPlugin {
    plugin_step: PluginStep,
    forbidden_resp: HttpResponse,
}

impl TryFrom<&PluginConf> for OwaspCrsPlugin {
    type Error = Error;
    fn try_from(value: &PluginConf) -> Result<Self> {
        let step = get_step_conf(value);

        let mut message = get_str_conf(value, "message");
        if message.is_empty() {
            message = "Ha ha ha... Request is forbidden".to_string();
        }
        let params = Self {
            plugin_step: step,
            forbidden_resp: HttpResponse {
                status: StatusCode::FORBIDDEN,
                body: Bytes::from(message),
                ..Default::default()
            },
        };
        if ![PluginStep::Request, PluginStep::ProxyUpstream]
            .contains(&params.plugin_step)
        {
            return Err(Error::Invalid {
                category: PluginCategory::OwaspCrsPlugin.to_string(),
                message: "Referer restriction plugin should be executed at request or proxy upstream step".to_string(),
            });
        }

        Ok(params)
    }
}

impl OwaspCrsPlugin {
    pub fn new(params: &PluginConf) -> Result<Self> {
        debug!(params = params.to_string(), "new OWASP CRS WAF plugin");
        Self::try_from(params)
    }
}

#[async_trait]
impl Plugin for OwaspCrsPlugin {
    #[inline]
    fn step(&self) -> String {
        self.plugin_step.to_string()
    }
    #[inline]
    fn category(&self) -> PluginCategory {
        PluginCategory::OwaspCrsPlugin
    }
    #[inline]
    async fn handle_request(
        &self,
        step: PluginStep,
        session: &mut Session,
        _ctx: &mut State,
    ) -> pingora::Result<Option<HttpResponse>> {
        if step != self.plugin_step {
            return Ok(None);
        }

        let req_header = session.req_header();
        let headers = &req_header.headers;
        let mut message = String::from("");
        message.push_str("<html><head></head><body>");
        message.push_str("<h1>Rezquest Headers</h1>");
        message.push_str("0. uri = ");
        message.push_str(&req_header.uri.to_string());
        message.push_str("<br>");
        for (i, n) in headers.into_iter().enumerate() {
            let hn = &n.0.as_str();
            let hv = &n.1.to_str().unwrap();
            message.push_str(&(i+1).to_string());
            message.push_str(". ");
            message.push_str(hn);
            message.push_str(" = ");
            message.push_str(hv);
            message.push_str("<br>");
            info!("{hn} {hv}");
        }
        message.push_str("</body></html>");

        let mut forbidden_resp = self.forbidden_resp.clone();
        forbidden_resp.body = message.into();

        let allow = false;
        if !allow {
            return Ok(Some(forbidden_resp));
        }
        return Ok(None);
    }
}
